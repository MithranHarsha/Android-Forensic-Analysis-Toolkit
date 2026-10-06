"""Pattern rules for raw carving (Phase 6).

A rule is a regular expression over ASCII bytes plus a validator. The regular expression finds the *shape*; the validator
decides whether the value is plausible (a phone number of a legal length, a date inside the Android era, a host with a real
top-level domain). A shape that does not validate is not reported: a candidate that fails its own checks would only be noise.

The same rules run over UTF-16LE text (the encoding Java strings and UTF-16 SQLite databases use), applied to the decoded
ASCII characters of each run.

Deliberate limits, stated so nobody mistakes silence for absence:

* a bare run of digits is never called a phone number (timestamps, ids and sizes look the same) -- only ``+`` numbers in
  E.164 form and formatted North-American numbers are;
* international numbers written with spaces or dashes are not recognised;
* a timestamp stored as a binary integer is not carved (a random 6-byte value lands in the plausible range about 0.3% of
  the time); binary integers are handled where their type is known, by the SQLite-record carver;
* dates without a year (logcat's ``03-01 08:00:00``) cannot be checked for plausibility and are not carved.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from android_forensics.artifacts.timestamps import is_plausible, to_datetime
from android_forensics.models import CarveKind, TimestampFormat

Validator = Callable[[str, "datetime | None"], bool]
_UTC = UTC


@dataclass(frozen=True)
class Rule:
    name: str
    kind: CarveKind
    regex: re.Pattern[bytes]
    validate: Validator
    description: str
    trim: Callable[[str], str] | None = None  # punctuation that surrounds a token but is not part of it


# ------------------------------------------------------------------ phone numbers


def _nanp_ok(area: str, exchange: str) -> bool:
    """North-American numbering plan: area code and exchange start with 2-9 and are not N11 service codes."""
    return area[0] in "23456789" and exchange[0] in "23456789" and area[1:] != "11" and exchange[1:] != "11"


def valid_e164(text: str, now: datetime | None) -> bool:
    digits = text[1:]
    if not 8 <= len(digits) <= 15:
        return False
    if digits[0] == "1":  # country code 1 (NANP): exactly ten digits follow, in a legal plan
        return len(digits) == 11 and _nanp_ok(digits[1:4], digits[4:7])
    return True


def valid_nanp(text: str, now: datetime | None) -> bool:
    digits = re.sub(r"\D", "", text)
    if len(digits) == 11:
        if digits[0] != "1":
            return False
        digits = digits[1:]
    return len(digits) == 10 and _nanp_ok(digits[:3], digits[3:6])


# ------------------------------------------------------------------ URLs and e-mail addresses

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_AUTHORITY = re.compile(r"^(?:[^/@?#]*@)?(\[[0-9A-Fa-f:.]+\]|[^/:?#@]+)(?::(\d{1,5}))?(?:[/?#]|$)")


def trim_url(text: str) -> str:
    """Drop punctuation that wraps a URL in running text; keep a closing bracket only if its opening one is inside."""
    while text:
        last = text[-1]
        if last in ".,;:!?'\"":
            text = text[:-1]
        elif last in ")]}" and text.count(last) > text.count({")": "(", "]": "[", "}": "{"}[last]):
            text = text[:-1]
        else:
            break
    return text


def valid_http_url(text: str, now: datetime | None) -> bool:
    m = _AUTHORITY.match(text.split("://", 1)[1]) if "://" in text else None
    if not m:
        return False
    host, port = m.group(1), m.group(2)
    if port is not None and not 0 < int(port) < 65536:
        return False
    if host.startswith("["):
        return True
    ip = _IPV4.match(host)
    if ip:
        return all(int(g) <= 255 for g in ip.groups())
    if host.lower() == "localhost":
        return True
    if not _HOST.match(host):
        return False
    labels = host.split(".")
    return len(labels) >= 2 and labels[-1].isalpha() and 2 <= len(labels[-1]) <= 24


def valid_android_uri(text: str, now: datetime | None) -> bool:
    scheme, _, rest = text.partition("://")
    scheme = scheme.lower()
    if scheme == "file":
        return rest.startswith("/") and len(rest) > 1
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if scheme == "content":
        return bool(re.fullmatch(r"(?:[0-9]+@)?[A-Za-z][A-Za-z0-9_.-]*", authority)) and "." in authority
    if scheme == "market":
        return bool(re.fullmatch(r"(?:details|search)\?.+", rest))
    return bool(authority)  # intent://


def valid_email(text: str, now: datetime | None) -> bool:
    local, _, domain = text.rpartition("@")
    if not local or not domain or len(text) > 254 or len(local) > 64:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local or ".." in domain:
        return False
    labels = domain.split(".")
    return (len(labels) >= 2 and all(re.fullmatch(_LABEL, x) for x in labels) and labels[-1].isalpha() and 2 <= len(labels[-1]) <= 24)


# ------------------------------------------------------------------ timestamps


def _numeric_timestamp(fmt: TimestampFormat) -> Validator:
    def check(text: str, now: datetime | None) -> bool:
        if not text.isdigit():
            return False
        dt = to_datetime(int(text), fmt)
        return dt is not None and is_plausible(dt, now)

    return check


_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def _moment(year: int, month: int, day: int, hour: int, minute: int, second: int, offset: timedelta | None = None) -> datetime | None:
    """The UTC instant, or None for a date that does not exist (30 February, hour 24 ...)."""
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=_UTC) - (offset or timedelta(0))
    except (ValueError, OverflowError):
        return None


_ISO = re.compile(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.\d{1,9})?(Z|[+-]\d\d:?\d\d)?")
_MEDIUM = re.compile(r"([A-Z][a-z]{2}) (\d{1,2}), (\d{4}),? (\d{1,2}):(\d\d)(?::(\d\d))? ?([AP]M)")


def parse_iso8601(text: str) -> datetime | None:
    """``2024-03-01 08:00:00`` / ``2024-03-01T08:00:00.123+05:30`` as a UTC instant (no zone means UTC), or None."""
    m = _ISO.fullmatch(text)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    tz = m.group(7)
    offset = None
    if tz and tz != "Z":
        sign = -1 if tz[0] == "-" else 1
        digits = tz[1:].replace(":", "")
        offset = sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return _moment(y, mo, d, h, mi, s, offset)


def parse_medium_date(text: str) -> datetime | None:
    """Java's ``DateFormat.MEDIUM`` in the US locale (``Mar 1, 2024 8:00:00 AM``), as some Android apps and exports write it."""
    m = _MEDIUM.fullmatch(text)
    if not m or m.group(1) not in _MONTHS:
        return None
    hour = int(m.group(4))
    if not 1 <= hour <= 12:
        return None
    hour = hour % 12 + (12 if m.group(7) == "PM" else 0)
    return _moment(int(m.group(3)), _MONTHS[m.group(1)], int(m.group(2)), hour, int(m.group(5)), int(m.group(6) or 0))


def _plausible_parse(parse: Callable[[str], datetime | None]) -> Validator:
    def check(text: str, now: datetime | None) -> bool:
        moment = parse(text)
        return moment is not None and is_plausible(moment, now)

    return check


valid_iso8601 = _plausible_parse(parse_iso8601)
valid_medium_date = _plausible_parse(parse_medium_date)

_NUMERIC_FORMAT = {
    CarveKind.TIMESTAMP_UNIX_SECONDS: TimestampFormat.UNIX_S,
    CarveKind.TIMESTAMP_UNIX_MILLIS: TimestampFormat.UNIX_MS,
    CarveKind.TIMESTAMP_WEBKIT_MICROS: TimestampFormat.WEBKIT_US,
}


def carved_timestamp(kind: CarveKind, text: str) -> datetime | None:
    """The UTC instant a carved timestamp hit stands for (the same reading the validator used), or None."""
    if kind in _NUMERIC_FORMAT:
        return to_datetime(int(text), _NUMERIC_FORMAT[kind]) if text.isdigit() else None
    if kind is CarveKind.TIMESTAMP_TEXT:
        return parse_iso8601(text) or parse_medium_date(text)
    return None


# ------------------------------------------------------------------ the rule table

_URL_BODY = rb"[^\s\"'<>\\^`{|}\x00-\x1f\x7f-\xff]"

RULES: tuple[Rule, ...] = (
    Rule("phone_e164", CarveKind.PHONE_NUMBER, re.compile(rb"(?<![0-9])\+[1-9][0-9]{7,14}(?![0-9])"), valid_e164,
         "+ followed by 8-15 digits (E.164); country code 1 must be a legal ten-digit North-American number"),
    Rule("phone_nanp_formatted", CarveKind.PHONE_NUMBER,
         re.compile(rb"(?<![0-9])(?:\+?1[ .-])?(?:\([2-9][0-9]{2}\) ?|[2-9][0-9]{2}[ .-])[2-9][0-9]{2}[ .-][0-9]{4}(?![0-9])"), valid_nanp,
         "(202) 555-0101, 202-555-0101, 202.555.0101 or 1-202-555-0101"),
    Rule("url_http", CarveKind.URL, re.compile(rb"(?i)https?://" + _URL_BODY + rb"{3,2048}"), valid_http_url,
         "http(s) URL whose host is a domain name, an IPv4 address, an IPv6 literal or localhost", trim_url),
    Rule("url_android", CarveKind.URL, re.compile(rb"(?i)(?:content|file|intent|market)://" + _URL_BODY + rb"{2,2048}"), valid_android_uri,
         "Android URI: content://authority/..., file:///path, market://details?id=..., intent://...", trim_url),
    Rule("email", CarveKind.EMAIL,
         re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}"), valid_email,
         "local-part@domain with a real-looking top-level domain"),
    Rule("timestamp_unix_seconds", CarveKind.TIMESTAMP_UNIX_SECONDS, re.compile(rb"(?<![0-9+])[0-9]{10}(?![0-9])"),
         _numeric_timestamp(TimestampFormat.UNIX_S), "ten decimal digits that read as a date inside the Android era"),
    Rule("timestamp_unix_millis", CarveKind.TIMESTAMP_UNIX_MILLIS, re.compile(rb"(?<![0-9+])[0-9]{13}(?![0-9])"),
         _numeric_timestamp(TimestampFormat.UNIX_MS), "thirteen decimal digits that read as a date inside the Android era"),
    Rule("timestamp_webkit_micros", CarveKind.TIMESTAMP_WEBKIT_MICROS, re.compile(rb"(?<![0-9+])[0-9]{17}(?![0-9])"),
         _numeric_timestamp(TimestampFormat.WEBKIT_US), "seventeen decimal digits that read, as Chromium stores them, inside the Android era"),
    Rule("timestamp_iso8601", CarveKind.TIMESTAMP_TEXT,
         re.compile(rb"(?<![0-9])(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])[T ](?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
                    rb"(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):?[0-5][0-9])?"), valid_iso8601,
         "yyyy-MM-dd[T ]HH:mm:ss with optional fraction and zone (SQLite datetime(), ISO 8601)"),
    Rule("timestamp_medium_date", CarveKind.TIMESTAMP_TEXT,
         re.compile(rb"(?<![A-Za-z])(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-3]?[0-9], (?:19|20)[0-9]{2},? [01]?[0-9]:[0-5][0-9]"
                    rb"(?::[0-5][0-9])? ?[AP]M"), valid_medium_date,
         "Mar 1, 2024 8:00:00 AM (Java DateFormat.MEDIUM, US locale)"),
)

RULES_BY_NAME = {r.name: r for r in RULES}
