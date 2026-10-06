"""Small shared helpers."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime


def iso_utc(dt: datetime) -> str:
    """Sortable millisecond-precision UTC timestamp, e.g. 2024-05-01T10:11:12.345Z."""
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def iso_from_epoch(seconds: float) -> str | None:
    try:
        return iso_utc(datetime.fromtimestamp(seconds, tz=UTC))
    except (OverflowError, OSError, ValueError):
        return None


def now_iso() -> str:
    return iso_utc(datetime.now(UTC))


def safe_text(s: str) -> str:
    """Make a path/text value storable in SQLite even if it carries undecodable bytes."""
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        return os.fsencode(s).decode("utf-8", "backslashreplace")


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def safe_basename(name: str, limit: int = 100) -> str:
    return _SAFE_NAME.sub("_", name)[:limit] or "_"
