"""An analysis run: one execution of one pipeline stage, recorded for reproducibility."""

from __future__ import annotations

import json
from typing import Any, Mapping, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from android_forensics.models.enums import RunStatus
from android_forensics.models.types import CaseId, NonBlankStr, UtcIso, parse_utc


class AnalysisRun(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int | None = None
    case_id: CaseId
    stage: NonBlankStr
    started_at: UtcIso
    finished_at: UtcIso | None = None
    status: RunStatus = RunStatus.RUNNING
    tool_version: NonBlankStr
    params: dict[str, Any] = Field(default_factory=dict)
    stats: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None

    @model_validator(mode="after")
    def _lifecycle(self) -> Self:
        if self.status is RunStatus.RUNNING:
            if self.finished_at is not None or self.error is not None:
                raise ValueError("a RUNNING run has no finish time and no error")
        else:
            if self.finished_at is None:
                raise ValueError(f"a {self.status.value} run must have a finish time")
            if self.finished_at < self.started_at:  # canonical UTC strings sort chronologically
                raise ValueError("a run cannot finish before it started")
            if self.status is RunStatus.FAILED and not self.error:
                raise ValueError("a FAILED run must record its error")
            if self.status is RunStatus.COMPLETED and self.error is not None:
                raise ValueError("a COMPLETED run cannot carry an error")
        return self

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (parse_utc(self.finished_at) - parse_utc(self.started_at)).total_seconds()

    def finished(self, status: RunStatus, finished_at: str, stats: dict[str, Any] | None = None, error: str | None = None) -> Self:
        """Return the completed/failed version of this run (runs are immutable)."""
        return type(self).model_validate(
            {**self.model_dump(), "status": status, "finished_at": finished_at, "stats": stats or {}, "error": error}
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id, "stage": self.stage, "started_at": self.started_at, "finished_at": self.finished_at,
            "status": self.status.value, "tool_version": self.tool_version,
            "params_json": json.dumps(self.params, default=str), "stats_json": json.dumps(self.stats, default=str),
            "error": self.error,
        }

    @classmethod
    def from_record(cls, r: Mapping[str, Any]) -> Self:
        return cls(
            id=r["id"], case_id=r["case_id"], stage=r["stage"], started_at=r["started_at"], finished_at=r["finished_at"],
            status=r["status"], tool_version=r["tool_version"], params=json.loads(r["params_json"] or "{}"),
            stats=json.loads(r["stats_json"] or "{}"), error=r["error"],
        )
