"""What an artifact says that another artifact could say too (Phase 7): its phone numbers, names, URLs, e-mail addresses,
message text and timestamp, read from the typed payload. Nothing here is guessed: a field the artifact does not carry is absent."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from android_forensics.models import (
    Artifact,
    BrowserDownload,
    BrowserHistoryEntry,
    CallRecord,
    CallType,
    Contact,
    MessageDirection,
    SMSMessage,
)

_INCOMING_CALLS = {CallType.INCOMING, CallType.MISSED, CallType.REJECTED, CallType.BLOCKED, CallType.VOICEMAIL}


@dataclass(frozen=True)
class Facts:
    role: str  # message | call | contact | browser | other
    phones: tuple[str, ...] = ()  # phone keys (normalization.phone_key)
    names: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()  # normalised
    emails: tuple[str, ...] = ()  # lower case
    texts: tuple[str, ...] = ()  # message bodies, whitespace-normalised
    moment: str | None = None  # the artifact's timestamp as UTC to the second (``2024-03-01T08:00:00``)
    moment_valid: bool | None = None  # plausible? None: no timestamp to judge
    direction: str | None = None  # in | out | None (unknown or not applicable)


def normalise_url(url: str | None) -> str | None:
    """Lower-case scheme and host, no fragment, no trailing slash on the path -- so two spellings of one address compare equal."""
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    path = parts.path.rstrip("/") if parts.path != "/" else ""
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def normalise_text(text: str | None) -> str | None:
    return " ".join(text.split()) if text and text.strip() else None


def _moment(a: Artifact) -> tuple[str | None, bool | None]:
    ts = a.timestamp
    if ts is None or not ts.utc:
        return None, None
    return ts.utc[:19], ts.plausible


def facts_of(a: Artifact) -> Facts:
    moment, valid = _moment(a)
    if isinstance(a, SMSMessage):
        direction = "in" if a.direction is MessageDirection.RECEIVED else "out" if a.direction is MessageDirection.SENT else None
        text = normalise_text(a.body)
        return Facts("message", phones=(a.phone_key,) if a.phone_key else (), texts=(text,) if text else (), moment=moment,
                     moment_valid=valid, direction=direction)
    if isinstance(a, CallRecord):
        direction = "in" if a.call_type in _INCOMING_CALLS else "out" if a.call_type is CallType.OUTGOING else None
        return Facts("call", phones=(a.phone_key,) if a.phone_key else (), names=(a.cached_name,) if a.cached_name else (),
                     moment=moment, moment_valid=valid, direction=direction)
    if isinstance(a, Contact):
        phones = tuple(dict.fromkeys(p.phone_key for p in a.phones if p.phone_key))
        emails = tuple(dict.fromkeys(e.address.strip().lower() for e in a.emails if e.address.strip()))
        return Facts("contact", phones=phones, names=(a.display_name,) if a.display_name else (), emails=emails,
                     moment=moment, moment_valid=valid)
    if isinstance(a, BrowserHistoryEntry):
        url = normalise_url(a.url)
        return Facts("browser", urls=(url,) if url else (), moment=moment, moment_valid=valid)
    if isinstance(a, BrowserDownload):
        urls = tuple(dict.fromkeys(u for u in (normalise_url(a.tab_url), normalise_url(a.referrer)) if u))
        return Facts("browser", urls=urls, moment=moment, moment_valid=valid)
    return Facts("other", moment=moment, moment_valid=valid)
