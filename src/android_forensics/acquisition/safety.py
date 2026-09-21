"""Archive path safety and extraction budgets."""

from __future__ import annotations

import posixpath
import re

from android_forensics.config import MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_TOTAL_BYTES, MAX_MEMBER_BYTES


class UnsafePathError(ValueError):
    pass


class BudgetExceeded(RuntimeError):
    pass


_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def normalize_member_path(name: str) -> str:
    """Return a safe, relative POSIX path for an archive member or raise UnsafePathError.

    Leading slashes are stripped (Android acquisitions are often packed with absolute
    paths such as ``/data/data/...``); traversal (``..``), NULs and drive prefixes are rejected.
    """
    if "\x00" in name:
        raise UnsafePathError("NUL byte in path")
    p = name.replace("\\", "/")
    if _DRIVE_RE.match(p):
        raise UnsafePathError("drive-letter prefix")
    parts: list[str] = []
    for comp in p.split("/"):
        if comp in ("", "."):
            continue
        if comp == "..":
            raise UnsafePathError("path traversal component '..'")
        parts.append(comp)
    if not parts:
        raise UnsafePathError("empty path")
    out = posixpath.join(*parts)
    if len(out) > 4096:
        raise UnsafePathError("path too long")
    return out


class ExtractionBudget:
    def __init__(
        self,
        max_entries: int = MAX_ARCHIVE_ENTRIES,
        max_total_bytes: int = MAX_ARCHIVE_TOTAL_BYTES,
        max_member_bytes: int = MAX_MEMBER_BYTES,
    ) -> None:
        self.max_entries = max_entries
        self.max_total_bytes = max_total_bytes
        self.max_member_bytes = max_member_bytes
        self.entries = 0
        self.total = 0

    def charge_entry(self) -> None:
        self.entries += 1
        if self.entries > self.max_entries:
            raise BudgetExceeded(f"entry limit {self.max_entries} exceeded")

    def charge_bytes(self, n: int, member_total: int) -> None:
        self.total += n
        if member_total > self.max_member_bytes:
            raise BudgetExceeded(f"member exceeds {self.max_member_bytes} bytes")
        if self.total > self.max_total_bytes:
            raise BudgetExceeded(f"total size limit {self.max_total_bytes} exceeded")
