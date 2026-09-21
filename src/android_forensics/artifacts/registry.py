"""Parser registry. Adding a new artifact parser = subclass ArtifactParser and decorate with @register."""

from __future__ import annotations

from android_forensics.artifacts.base import ArtifactParser

_PARSERS: list[ArtifactParser] = []


def register(cls: type[ArtifactParser]) -> type[ArtifactParser]:
    if not any(type(p) is cls for p in _PARSERS):
        _PARSERS.append(cls())
    return cls


def get_parsers() -> list[ArtifactParser]:
    from android_forensics.artifacts import browser, calls, contacts, sms  # noqa: F401  (register on import)

    return list(_PARSERS)
