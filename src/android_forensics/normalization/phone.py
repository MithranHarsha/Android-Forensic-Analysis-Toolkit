"""Phone-number normalisation for cross-artifact matching.

This is deliberately *not* E.164 parsing (no country-plan database is bundled). ``phone_key`` is a
conservative matching key — the trailing ten digits of a genuine phone number — so that
"+1 (202) 555-0123", "202-555-0123" and "12025550123" compare equal. Short codes and alphanumeric
sender IDs get no key: they must never be "correlated" as if they were subscriber numbers.
"""

from __future__ import annotations

import re

from android_forensics.models import AddressKind

_STRIP = re.compile(r"[\s().\-]")
_PHONE = re.compile(r"^\+?\d{7,15}$")
_SHORT = re.compile(r"^\d{3,6}$")


def classify_address(raw: str | None) -> AddressKind:
    if raw is None or not raw.strip():
        return AddressKind.EMPTY
    s = _STRIP.sub("", raw)
    if _PHONE.match(s):
        return AddressKind.PHONE
    if _SHORT.match(s):
        return AddressKind.SHORTCODE
    if re.search(r"[A-Za-z]", s):
        return AddressKind.ALPHANUMERIC
    return AddressKind.UNKNOWN


def normalize_number(raw: str | None) -> str | None:
    if classify_address(raw) is not AddressKind.PHONE:
        return None
    return _STRIP.sub("", raw or "")


def phone_key(raw: str | None) -> str | None:
    n = normalize_number(raw)
    if n is None:
        return None
    digits = n.lstrip("+")
    return digits[-10:]


def snippet(text: str | None, limit: int = 80) -> str:
    if not text:
        return ""
    one = " ".join(text.split())
    return one if len(one) <= limit else one[: limit - 1] + "…"
