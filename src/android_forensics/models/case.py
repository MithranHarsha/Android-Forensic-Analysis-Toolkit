"""The case: the unit of work that owns evidence, runs, artifacts and reports."""

from __future__ import annotations

import json
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

from android_forensics.models.types import CaseId, NonBlankStr, UtcIso


class SourceLayout(BaseModel):
    """The Android directory layout detected for one evidence source, with the evidence supporting it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    layout: NonBlankStr
    prefix: str = ""
    detail: str = ""


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: CaseId
    name: NonBlankStr
    examiner: str | None = None
    description: str | None = None
    created_at: UtcIso
    tool_version: NonBlankStr
    layout: str | None = None  # overall layout across sources, once scanned
    layouts: dict[int, SourceLayout] = Field(default_factory=dict)  # keyed by evidence source id

    def to_record(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "examiner": self.examiner,
            "description": self.description,
            "created_at": self.created_at,
            "tool_version": self.tool_version,
            "layout": self.layout,
            "layout_detail": json.dumps({str(k): v.model_dump() for k, v in self.layouts.items()}),
        }

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "Case":
        return cls(
            id=record["id"],
            name=record["name"],
            examiner=record["examiner"],
            description=record["description"],
            created_at=record["created_at"],
            tool_version=record["tool_version"],
            layout=record["layout"],
            layouts=json.loads(record["layout_detail"] or "{}"),
        )
