"""Single-file acquirer, used for laboratory database inputs.

Adjacent SQLite sidecars (-wal, -shm, -journal) are ingested with the database so the
active view and the Review 2 recovery engine see the same state the phone had.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from android_forensics.acquisition.base import AcquireContext, AcquiredFile, AcquisitionIssue, read_local_file
from android_forensics.acquisition.safety import BudgetExceeded
from android_forensics.models import FileTimes, SourceType
from android_forensics.util import iso_from_epoch, safe_text

SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class SingleFileAcquirer:
    source_type = SourceType.SINGLE_FILE

    def __init__(self, path: Path):
        self.path = path

    def acquire(self, ctx: AcquireContext) -> Iterator[AcquiredFile | AcquisitionIssue]:
        candidates = [self.path] + [
            self.path.with_name(self.path.name + s)
            for s in SIDECAR_SUFFIXES
            if self.path.with_name(self.path.name + s).is_file()
        ]
        ordinal = 0
        for p in candidates:
            rel = safe_text(p.name)
            try:
                st = p.stat()
                times = FileTimes(
                    mtime=iso_from_epoch(st.st_mtime),
                    atime=iso_from_epoch(st.st_atime),
                    ctime=iso_from_epoch(st.st_ctime),
                    basis="fs_stat (ctime = inode change time on POSIX)",
                )
                acquired, issues = read_local_file(ctx, ordinal, rel, p, st, times)
            except BudgetExceeded as exc:
                yield AcquisitionIssue(rel, "budget_exceeded", str(exc), incomplete=True)
                return
            except OSError as exc:
                yield AcquisitionIssue(rel, "read_error", f"{type(exc).__name__}: {exc}")
                continue
            yield from issues
            if acquired is not None:
                ordinal += 1
                yield acquired
