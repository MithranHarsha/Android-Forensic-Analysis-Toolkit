"""UI-agnostic progress reporting. The engine reports; the CLI decides how to draw it."""

from __future__ import annotations

from typing import Protocol


class Progress(Protocol):
    def start(self, description: str, total: int | None = None) -> None: ...
    def advance(self, n: int = 1) -> None: ...
    def stop(self) -> None: ...


class NullProgress:
    def start(self, description: str, total: int | None = None) -> None:
        pass

    def advance(self, n: int = 1) -> None:
        pass

    def stop(self) -> None:
        pass
