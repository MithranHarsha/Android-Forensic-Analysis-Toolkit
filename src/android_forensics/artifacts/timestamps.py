"""Timestamp interpretation.

The storage format is *declared by the parser* from knowledge of the source schema — it is never
guessed from the value. Every conversion keeps the raw value next to the UTC interpretation and a
plausibility verdict. Value ``0`` (or negative) means "unset" and yields no timestamp.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from android_forensics.config import PLAUSIBLE_FUTURE_SLACK_DAYS, PLAUSIBLE_MIN
from android_forensics.models import TimestampFormat, TimestampInfo
from android_forensics.util import iso_utc

_UNIX = datetime(1970, 1, 1, tzinfo=UTC)
_WEBKIT = datetime(1601, 1, 1, tzinfo=UTC)
_COCOA = datetime(2001, 1, 1, tzinfo=UTC)

FORMATS = {
    TimestampFormat.UNIX_S: (_UNIX, "seconds"),
    TimestampFormat.UNIX_MS: (_UNIX, "milliseconds"),
    TimestampFormat.UNIX_US: (_UNIX, "microseconds"),
    TimestampFormat.WEBKIT_US: (_WEBKIT, "microseconds"),
    TimestampFormat.COCOA_S: (_COCOA, "seconds"),
}


def to_datetime(value: int | float, fmt: TimestampFormat | str) -> datetime | None:
    epoch, unit = FORMATS[TimestampFormat(fmt)]
    try:
        return epoch + timedelta(**{unit: value})
    except (OverflowError, ValueError):
        return None


def is_plausible(dt: datetime, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    return PLAUSIBLE_MIN <= dt <= now + timedelta(days=PLAUSIBLE_FUTURE_SLACK_DAYS)


def convert(raw: object, fmt: TimestampFormat | str, now: datetime | None = None) -> TimestampInfo:
    """Interpret ``raw`` as ``fmt``. Never invents a value: unparseable input gives ``utc=None``."""
    fmt = TimestampFormat(fmt)
    if raw is None:
        return TimestampInfo(raw=None, format=fmt, note="NULL")
    value: int | float
    if isinstance(raw, bool):
        return TimestampInfo(raw=int(raw), format=fmt, note="boolean is not a timestamp")
    if isinstance(raw, (int, float)):
        value = raw
    elif isinstance(raw, str) and raw.strip().lstrip("-").isdigit():
        value = int(raw.strip())
    else:
        return TimestampInfo(raw=raw if isinstance(raw, str) else None, format=fmt, plausible=False, note="non-numeric value")
    if value <= 0:
        return TimestampInfo(raw=value, format=fmt, note="zero/negative value: treated as unset")
    dt = to_datetime(value, fmt)
    if dt is None:
        return TimestampInfo(raw=value, format=fmt, plausible=False, note="value outside representable range")
    return TimestampInfo(raw=value, utc=iso_utc(dt), format=fmt, plausible=is_plausible(dt, now))


def plausible_formats(value: object, now: datetime | None = None) -> list[str]:
    """Which storage formats would render ``value`` as a plausible date (for generic column hints only)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return []
    out = []
    for fmt in FORMATS:
        dt = to_datetime(value, fmt)
        if dt is not None and is_plausible(dt, now):
            out.append(fmt)
    return out
