"""SMS-like text (Phase 6): runs of text that read like a text message, found in raw bytes.

Nothing about a run of text says it is an SMS, so a run is reported only when something *around* it supports the reading. The
supports, from strongest to weakest (a run gets the strongest it has, the rest are listed in the candidate's notes):

``sms_backup_xml``
    an ``<sms ... address="..." body="...">`` element, the format of the common "SMS Backup & Restore" apps: the body attribute
    is the message, ``address`` and ``date`` sit beside it.
``sms_body_near_address``
    a printable run of at least four words with a phone number within 96 bytes of it (in a SQLite ``sms`` cell the address
    text, some binary integers and then the body lie within that distance of each other) -- or touching it.
``sms_otp_text``
    a run that says it is a one-time / verification / security code and carries a four to eight digit code.
``sms_body_near_timestamp``
    a printable run of at least four words with a 13-digit millisecond timestamp within 96 bytes of it.

Text in a language that does not separate words with spaces is not recognised by the word-count rule.
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field

NEAR = 96
MAX_RUN = 600

# printable ASCII and *exactly* the well-formed UTF-8 sequences (no overlong forms, no surrogates), so a run always decodes
_UTF8_CHAR = (rb"[\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]"
              rb"|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2}")
_RUN = re.compile(rb"(?:" + _UTF8_CHAR + rb"){20,%d}" % MAX_RUN)
_WORD = re.compile(r"[^\W\d_]{2,}")
_OTP = re.compile(
    r"(?i)\b(?:otp|one[- ]time (?:password|code|pin)|verification code|security code|login code|passcode|pin|code)\b[^0-9]{0,40}\b[0-9]{4,8}\b"
    r"|\b[0-9]{4,8}\b[^0-9]{0,40}\b(?:is your|otp|code|pin)\b")
_SMS_TAG = re.compile(rb"<sms\b[^>]{0,2000}>")
_ATTR = re.compile(r'(\w+)="([^"]*)"')


@dataclass(frozen=True)
class SmsHit:
    start: int
    end: int
    text: str
    pattern: str
    notes: tuple[str, ...] = field(default=())


def _reads_like_prose(text: str) -> bool:
    words = _WORD.findall(text)
    letters = sum(c.isalpha() for c in text)
    return len(words) >= 4 and letters >= 0.5 * len(text) and max(len(w) for w in words) <= 40 and not text.startswith(("http://", "https://"))


class _Spans:
    """Byte spans sorted by start, answering "is there a span near ``[start, end]``?" in O(log n) instead of scanning them all.

    Near means: ends no earlier than ``NEAR`` bytes before ``start``, starts no later than ``NEAR`` bytes after ``end``, and is not
    strictly inside the run itself. (A linear scan per run made carving quadratic: 100,000 messages took 25 s of pure Python.)"""

    def __init__(self, spans: list[tuple[int, int]]):
        self.spans = sorted(spans)
        self.starts = [s for s, _ in self.spans]
        self.longest = max((e - s for s, e in self.spans), default=0)

    def near(self, start: int, end: int) -> bool:
        lo = bisect_left(self.starts, start - NEAR - self.longest)
        hi = bisect_right(self.starts, end + NEAR)
        return any(e >= start - NEAR and s <= end + NEAR and not (start < s and e < end) for s, e in self.spans[lo:hi])


def find_sms_like(data: bytes, lo: int, hi: int, phone_spans: list[tuple[int, int]], millis_spans: list[tuple[int, int]]) -> list[SmsHit]:
    """SMS-like text whose start is in ``[lo, hi)``. ``phone_spans`` / ``millis_spans`` are the (start, end) byte spans of the phone
    numbers and millisecond timestamps already found in ``data``."""
    hits: list[SmsHit] = []
    tags: list[tuple[int, int]] = []
    phones, millis = _Spans(phone_spans), _Spans(millis_spans)
    for m in _SMS_TAG.finditer(data):
        if not lo <= m.start() < hi:
            continue
        attrs = dict(_ATTR.findall(m.group().decode("utf-8", "replace")))
        if "body" in attrs and "address" in attrs and attrs["body"]:
            notes = (f"address={attrs['address']}",) + ((f"date={attrs['date']}",) if "date" in attrs else ())
            body_at = m.group().find(b'body="') + len('body="')
            hits.append(SmsHit(m.start() + body_at, m.start() + body_at + len(attrs["body"].encode("utf-8")), attrs["body"], "sms_backup_xml", notes))
            tags.append((m.start(), m.end()))
    tag_starts = [a for a, _ in tags]
    for m in _RUN.finditer(data):
        s, e = m.start(), m.end()
        if not lo <= s < hi:
            continue
        k = bisect_right(tag_starts, s) - 1          # tags are found in file order and do not overlap
        if k >= 0 and s < tags[k][1]:
            continue
        try:
            text = m.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        found: list[str] = []
        if phones.near(s, e):
            found.append("sms_body_near_address")
        if _OTP.search(text):
            found.append("sms_otp_text")
        if millis.near(s, e):
            found.append("sms_body_near_timestamp")
        prose = _reads_like_prose(text)
        # an OTP message is short and formulaic; the other two supports need the run to read like prose
        usable = [p for p in found if p == "sms_otp_text" or prose]
        if not usable:
            continue
        hits.append(SmsHit(s, e, text, usable[0], tuple(f"also supported by {p}" for p in usable[1:])))
    hits.sort(key=lambda h: (h.start, h.pattern))
    return hits
