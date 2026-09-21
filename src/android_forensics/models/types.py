"""Constrained scalar types shared by every model.

Hashes, timestamps and labels are validated at the model boundary so a malformed value can never be
persisted or reported as evidence.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator, StringConstraints

from android_forensics.util import iso_utc

Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Sha1Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
Md5Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
HexBytes = Annotated[str, StringConstraints(pattern=r"^([0-9a-f]{2})*$")]


def _not_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


# Rejects empty/whitespace-only text but never alters it: evidence paths and names must survive byte-for-byte.
NonBlankStr = Annotated[str, AfterValidator(_not_blank)]
CaseId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]

_CANONICAL_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
# Canonical timestamp form used everywhere: millisecond precision, UTC, lexicographically sortable.
UtcIso = Annotated[str, StringConstraints(pattern=_CANONICAL_UTC.pattern)]


def normalize_iso_utc(value: object) -> object:
    """Accept any timezone-aware ISO 8601 string and return the canonical UTC form.

    A timestamp without a timezone is rejected: an examiner-supplied time that could be local or UTC is
    ambiguous, and ambiguity must not be silently resolved.
    """
    if not isinstance(value, str):
        return value
    text = value.strip()
    if _CANONICAL_UTC.match(text):
        return text
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"not an ISO 8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp {value!r} has no timezone; use 'Z' for UTC or an explicit offset")
    return iso_utc(parsed)


# Lenient input, canonical storage: for fields a human may supply (e.g. acquisition time).
IsoInput = Annotated[UtcIso, BeforeValidator(normalize_iso_utc)]


def parse_utc(value: str) -> datetime:
    """Parse a canonical UtcIso string into an aware datetime."""
    return datetime.fromisoformat(value)


def canonical_json(value: Any) -> str:
    """Deterministic JSON used for digests: sorted keys, no whitespace, unicode preserved."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
