"""Read-only access to original evidence.

Evidence is opened with ``os.open(O_RDONLY)`` — never a mode that could write — plus, where the platform allows:

* ``O_NOFOLLOW`` so a path that turns into a symlink between enumeration and open (a race) is refused, not followed;
* ``O_NOATIME`` (Linux, and only when the process owns the file) so reading does not update the access time.

Other platforms may still update access times when a file is read: mount evidence read-only or use a write blocker.
"""

from __future__ import annotations

import os
from typing import BinaryIO

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NOATIME = getattr(os, "O_NOATIME", 0)
_BINARY = getattr(os, "O_BINARY", 0)


def open_readonly(path: str | os.PathLike[str], *, follow_symlinks: bool = False) -> BinaryIO:
    """Open ``path`` for reading only. Symlinks are refused unless ``follow_symlinks`` is set (never for evidence)."""
    flags = os.O_RDONLY | _BINARY | (0 if follow_symlinks else _NOFOLLOW)
    if _NOATIME:
        try:
            fd = os.open(path, flags | _NOATIME)
        except PermissionError:  # O_NOATIME needs file ownership; fall back to a plain read-only open
            fd = os.open(path, flags)
    else:
        fd = os.open(path, flags)
    return os.fdopen(fd, "rb")


def fingerprint(st: os.stat_result) -> tuple[int, int, int]:
    """Identity of a file's content state: size, modification time (ns) and inode."""
    return (st.st_size, st.st_mtime_ns, st.st_ino)


__all__ = ["fingerprint", "open_readonly"]
