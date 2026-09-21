"""A timeline event: something that happened (or a file that changed) at a UTC instant."""

from __future__ import annotations

from typing import Any, Mapping, Self

from pydantic import BaseModel, ConfigDict, model_validator

from android_forensics.models.enums import ArtifactStatus, ArtifactType, Confidence, TimelineEventKind
from android_forensics.models.types import NonBlankStr, UtcIso


class TimelineEvent(BaseModel):
    """Artifact events carry the artifact's status so recovered events can be told from active ones.

    File events are filesystem metadata, not evidence of user activity, and therefore carry no artifact status.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int | None = None
    run_id: int | None = None
    timestamp: UtcIso
    timestamp_raw: str | None = None
    time_basis: str | None = None
    kind: TimelineEventKind
    artifact_type: ArtifactType | None = None
    event: NonBlankStr
    source: str | None = None
    status: ArtifactStatus | None = None
    confidence: Confidence | None = None
    artifact_id: int | None = None
    evidence_file_id: int | None = None

    @model_validator(mode="after")
    def _kind_shapes_the_event(self) -> Self:
        if self.kind is TimelineEventKind.ARTIFACT:
            if self.artifact_type is None or self.status is None or self.artifact_id is None:
                raise ValueError("an artifact event needs artifact_type, status and artifact_id")
        else:
            if self.evidence_file_id is None:
                raise ValueError("a file event needs the evidence_file_id it describes")
            if self.status is not None or self.artifact_id is not None or self.artifact_type is not None:
                raise ValueError("a file event is filesystem metadata: it has no artifact status, type or id")
        return self

    @property
    def is_recovered(self) -> bool:
        return self.status is not None and self.status.is_recovery_state

    @property
    def is_file_event(self) -> bool:
        return self.kind is not TimelineEventKind.ARTIFACT

    def to_record(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "ts_utc": self.timestamp, "ts_raw": self.timestamp_raw, "time_basis": self.time_basis,
            "event_kind": self.kind.value, "artifact_type": self.artifact_type.value if self.artifact_type else None,
            "event": self.event, "source": self.source, "status": self.status.value if self.status else None,
            "confidence": self.confidence.value if self.confidence else None, "artifact_id": self.artifact_id,
            "evidence_file_id": self.evidence_file_id,
        }

    @classmethod
    def from_record(cls, r: Mapping[str, Any]) -> Self:
        return cls(
            id=r["id"], run_id=r["run_id"], timestamp=r["ts_utc"], timestamp_raw=r["ts_raw"], time_basis=r["time_basis"],
            kind=r["event_kind"], artifact_type=r["artifact_type"], event=r["event"], source=r["source"],
            status=r["status"], confidence=r["confidence"], artifact_id=r["artifact_id"],
            evidence_file_id=r["evidence_file_id"],
        )
