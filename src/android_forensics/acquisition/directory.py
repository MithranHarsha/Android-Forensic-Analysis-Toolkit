"""Directory acquirer: read-only walk of an extracted filesystem dump."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from android_forensics.acquisition.base import AcquireContext, AcquiredFile, AcquisitionIssue, read_local_file
from android_forensics.acquisition.safety import BudgetExceeded
from android_forensics.models import FileTimes, SourceType
from android_forensics.util import iso_from_epoch, safe_text


class DirectoryAcquirer:
    source_type = SourceType.DIRECTORY

    def __init__(self, root: Path):
        self.root = root

    def acquire(self, ctx: AcquireContext) -> Iterator[AcquiredFile | AcquisitionIssue]:
        ordinal = 0
        stack: list[Path] = [self.root]
        while stack:
            current = stack.pop()
            rel_dir = safe_text(current.relative_to(self.root).as_posix()) if current != self.root else "."
            try:
                with os.scandir(current) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError as exc:
                yield AcquisitionIssue(rel_dir, "unreadable_directory", f"{type(exc).__name__}: {exc}")
                continue

            subdirs: list[Path] = []
            for entry in entries:
                rel = safe_text(Path(entry.path).relative_to(self.root).as_posix())
                try:
                    if entry.is_symlink():
                        target = os.readlink(entry.path)
                        yield AcquisitionIssue(
                            rel, "symlink_skipped", f"symlink -> {safe_text(target)} (not followed)"
                        )
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        subdirs.append(Path(entry.path))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        yield AcquisitionIssue(rel, "special_file_skipped", "socket/device/fifo not read")
                        continue
                    st = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    yield AcquisitionIssue(rel, "stat_error", f"{type(exc).__name__}: {exc}")
                    continue

                times = FileTimes(
                    mtime=iso_from_epoch(st.st_mtime),
                    atime=iso_from_epoch(st.st_atime),
                    ctime=iso_from_epoch(st.st_ctime),
                    basis="fs_stat (ctime = inode change time on POSIX)",
                )
                try:
                    acquired, issues = read_local_file(ctx, ordinal, rel, entry.path, st, times)
                except BudgetExceeded as exc:
                    yield AcquisitionIssue(rel, "budget_exceeded", str(exc), incomplete=True)
                    return
                yield from issues
                if acquired is not None:
                    ordinal += 1
                    yield acquired
            stack.extend(reversed(subdirs))
