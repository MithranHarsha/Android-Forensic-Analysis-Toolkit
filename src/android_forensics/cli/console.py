"""Rich helpers shared by CLI commands."""

from __future__ import annotations

import re
from collections.abc import Iterable

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from rich.progress import Progress as RichProgressBar
from rich.segment import Segment
from rich.table import Table
from rich.text import Text

__all__ = ["RichProgress", "SafeConsole", "SafeTable", "console", "err_console", "escape", "plain_panel", "sanitize", "stats_panel", "styled"]

# Evidence is untrusted text: a file named "x\x1b[2J" or "\x1b]0;title\x07" would clear the examiner's screen or retitle
# their terminal, and a right-to-left override (U+202E) makes "evil\u202egpj.exe" display as "evilexe.jpg". Every string rendered
# by these consoles passes through ``sanitize`` first; control characters are shown as visible \xNN / \uNNNN escapes.
_UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def sanitize(text: str) -> str:
    return _UNSAFE.sub(lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100 else f"\\u{ord(m.group()):04x}", text)


class SafeConsole(Console):
    """A Console that neutralises control characters in *content* while leaving its own styling codes alone.

    Rich assembles output from ``Segment`` objects: ``control`` segments are its cursor/title codes, all other segments are
    text that may come from evidence. Only the latter are sanitised. (tests/security covers this against the installed Rich.)"""

    def _render_buffer(self, buffer: Iterable[Segment]) -> str:
        return super()._render_buffer(
            s if s.control else Segment(sanitize(s.text), s.style, s.control) for s in buffer
        )


console = SafeConsole()
err_console = SafeConsole(stderr=True)

STATUS_STYLE = {
    "VALID": "green", "PARTIAL": "yellow", "INVALID": "bold red", "UNVERIFIED": "cyan",
    "ACTIVE": "green", "RECOVERED": "bold magenta", "CORRUPTED": "red", "UNRECOVERABLE": "dim red",
}


class SafeTable(Table):
    """A table that shows string cells exactly as given.

    Evidence text (file names, package names, message bodies, error details) is untrusted. Rich would read ``[backup]`` in it
    as a style tag and drop it — showing the examiner a path that does not exist — and a stray ``[/]`` would raise. Only
    ``Text`` cells (see ``styled``) carry styling; every ``str`` cell is plain text.
    """

    def add_row(self, *renderables, **kwargs):
        return super().add_row(*(Text(r) if isinstance(r, str) else r for r in renderables), **kwargs)


def plain_panel(content: str, title: str) -> Panel:
    """A panel around untrusted text, shown verbatim."""
    return Panel(Text(content), title=title)


def styled(status: str | None) -> Text:
    if not status:
        return Text("-")
    return Text(status, style=STATUS_STYLE.get(status, "white"))


class RichProgress:
    """Adapts the engine's UI-agnostic Progress protocol to Rich."""

    def __init__(self) -> None:
        self._bar: RichProgressBar | None = None
        self._task: TaskID | None = None

    def start(self, description: str, total: int | None = None) -> None:
        self.stop()
        self._bar = RichProgressBar(
            SpinnerColumn(), TextColumn("[bold]{task.description}"), BarColumn(),
            MofNCompleteColumn(), TimeElapsedColumn(), console=console, transient=True,
        )
        self._bar.start()
        self._task = self._bar.add_task(escape(description), total=total)  # descriptions can carry evidence names

    def advance(self, n: int = 1) -> None:
        if self._bar is not None and self._task is not None:
            self._bar.advance(self._task, n)

    def stop(self) -> None:
        if self._bar is not None:
            self._bar.stop()
            self._bar = None


def stats_panel(title: str, rows: list[tuple[str, object]]) -> Panel:
    t = SafeTable.grid(padding=(0, 2))
    t.add_column(style="bold cyan", justify="right")
    t.add_column(overflow="fold")
    for k, v in rows:
        t.add_row(k + ":", v if isinstance(v, Text) else f"{v:,}" if isinstance(v, int) and not isinstance(v, bool) else str(v))
    return Panel(t, title=Text(title, style="bold"), border_style="blue", expand=False)
