"""A timestamp as stored and as interpreted — never one without the other."""

from __future__ import annotations

from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, model_validator

from android_forensics.models.enums import TimestampFormat
from android_forensics.models.types import UtcIso, parse_utc


class TimestampInfo(BaseModel):
    """``raw`` is exactly what the source stored; ``utc`` is the interpretation under ``format``.

    ``utc`` is ``None`` when the raw value is NULL, zero/negative (unset), non-numeric or out of range — the reason is
    in ``note``. ``plausible`` says whether the interpretation falls inside the Android-era window; an implausible
    value is kept and flagged, never dropped.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    raw: int | float | str | None = None
    format: TimestampFormat
    utc: UtcIso | None = None
    plausible: bool | None = None
    note: str | None = None

    @model_validator(mode="after")
    def _plausibility_needs_an_interpretation(self) -> Self:
        if self.utc is None and self.plausible is True:
            raise ValueError("a timestamp with no UTC interpretation cannot be plausible")
        return self

    @property
    def as_datetime(self) -> datetime | None:
        return parse_utc(self.utc) if self.utc else None
