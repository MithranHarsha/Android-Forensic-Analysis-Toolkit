"""A validation result: one check, one target, one outcome — and always the reason."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

from android_forensics.models.enums import ValidationCheck, ValidationStatus, ValidationTarget
from android_forensics.models.types import NonBlankStr, UtcIso


class ValidationResult(BaseModel):
    """Failed and partial results are kept, never discarded; ``detail`` explains every outcome (even VALID)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: int | None = None
    run_id: int | None = None
    target_type: ValidationTarget
    target_id: int | None = None
    target_label: NonBlankStr
    check: ValidationCheck
    status: ValidationStatus
    detail: NonBlankStr
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: UtcIso | None = None

    @classmethod
    def of(
        cls,
        target_type: ValidationTarget | str,
        target_id: int | None,
        target_label: str,
        check: ValidationCheck | str,
        status: ValidationStatus,
        detail: str,
        evidence: dict[str, Any] | None = None,
    ) -> Self:
        return cls(
            target_type=target_type, target_id=target_id, target_label=target_label, check=check, status=status,  # type: ignore[arg-type]
            detail=detail, evidence=evidence or {},
        )

    @property
    def passed(self) -> bool:
        return self.status is ValidationStatus.VALID

    @property
    def failed(self) -> bool:
        return self.status is ValidationStatus.INVALID

    def to_record(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "target_type": self.target_type.value, "target_id": self.target_id,
            "target_label": self.target_label, "check_name": self.check.value, "status": self.status.value,
            "detail": self.detail, "evidence_json": json.dumps(self.evidence, default=str) if self.evidence else None,
            "created_at": self.created_at,
        }

    @classmethod
    def from_record(cls, r: Mapping[str, Any] | sqlite3.Row) -> Self:
        return cls(
            id=r["id"], run_id=r["run_id"], target_type=r["target_type"], target_id=r["target_id"],
            target_label=r["target_label"], check=r["check_name"], status=r["status"], detail=r["detail"],
            evidence=json.loads(r["evidence_json"]) if r["evidence_json"] else {}, created_at=r["created_at"],
        )
