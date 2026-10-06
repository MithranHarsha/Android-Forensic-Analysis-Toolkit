"""ZIP and TAR(.gz/.bz2/.xz) acquirers with zip-slip, symlink and budget protection."""

from __future__ import annotations

import stat
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from android_forensics.acquisition.base import AcquireContext, AcquiredFile, AcquisitionIssue, ingest_stream
from android_forensics.acquisition.safety import BudgetExceeded, UnsafePathError, normalize_member_path
from android_forensics.models import FileTimes, SourceType
from android_forensics.util import iso_from_epoch, iso_utc, safe_text

_UT_EXTRA_ID = 0x5455  # Info-ZIP "extended timestamp": UTC epoch seconds, unlike the timezone-less DOS time


def _zip_times(info: zipfile.ZipInfo) -> FileTimes:
    """Prefer the Info-ZIP UT field (UTC) over the DOS time (local time of unknown zone, 2 s resolution)."""
    extra, i = info.extra, 0
    while i + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4 : i + 4 + size]
        if header_id == _UT_EXTRA_ID and len(body) >= 5 and body[0] & 1:
            (mtime,) = struct.unpack_from("<l", body, 1)
            return FileTimes(mtime=iso_from_epoch(mtime), basis="zip_extra_field_UT (UTC epoch, Info-ZIP extended timestamp)")
        i += 4 + size
    try:
        mtime_iso = iso_utc(datetime(*info.date_time, tzinfo=UTC))
    except ValueError:
        mtime_iso = None
    return FileTimes(mtime=mtime_iso, basis="zip_dos_time (timezone unspecified; shown as UTC)")


def _tar_times(member: tarfile.TarInfo) -> FileTimes:
    """mtime always; atime/ctime only when the archive carries PAX extended headers."""
    extras = {}
    for key in ("atime", "ctime"):
        try:
            extras[key] = iso_from_epoch(float(member.pax_headers[key]))
        except (KeyError, ValueError):
            extras[key] = None
    basis = "tar_header_mtime (UTC epoch)" + ("; atime/ctime from PAX header" if any(extras.values()) else "")
    return FileTimes(mtime=iso_from_epoch(member.mtime), atime=extras["atime"], ctime=extras["ctime"], basis=basis)


class ZipAcquirer:
    source_type = SourceType.ZIP

    def __init__(self, path: Path):
        self.path = path

    def acquire(self, ctx: AcquireContext) -> Iterator[AcquiredFile | AcquisitionIssue]:
        try:
            zf = zipfile.ZipFile(self.path)
        except (zipfile.BadZipFile, OSError) as exc:
            yield AcquisitionIssue(self.path.name, "archive_unreadable", str(exc), incomplete=True)
            return
        ordinal = 0
        seen: set[str] = set()
        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                label = safe_text(info.filename)
                try:
                    ctx.budget.charge_entry()
                    rel = normalize_member_path(info.filename)
                except UnsafePathError as exc:
                    yield AcquisitionIssue(label, "unsafe_path_skipped", str(exc))
                    continue
                except BudgetExceeded as exc:
                    yield AcquisitionIssue(label, "budget_exceeded", str(exc), incomplete=True)
                    return
                rel = safe_text(rel)
                if stat.S_ISLNK(info.external_attr >> 16):
                    yield AcquisitionIssue(rel, "symlink_skipped", "symlink entry not followed")
                    continue
                if info.flag_bits & 0x1:
                    yield AcquisitionIssue(rel, "encrypted_member", "password-protected zip member; not opened")
                    continue
                if rel in seen:
                    yield AcquisitionIssue(rel, "duplicate_member", "duplicate path in archive; both kept")
                seen.add(rel)
                times = _zip_times(info)
                try:
                    with zf.open(info) as fh:
                        acquired = ingest_stream(ctx, ordinal, rel, fh, info.file_size, times)
                except BudgetExceeded as exc:
                    yield AcquisitionIssue(rel, "budget_exceeded", str(exc), incomplete=True)
                    return
                except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error, EOFError, OSError) as exc:
                    yield AcquisitionIssue(rel, "member_read_error", f"{type(exc).__name__}: {exc}")
                    continue
                ordinal += 1
                yield acquired


class TarAcquirer:
    source_type = SourceType.TAR

    def __init__(self, path: Path):
        self.path = path

    def acquire(self, ctx: AcquireContext) -> Iterator[AcquiredFile | AcquisitionIssue]:
        try:
            tf = tarfile.open(self.path, "r:*")
        except (tarfile.TarError, OSError, EOFError) as exc:
            yield AcquisitionIssue(self.path.name, "archive_unreadable", str(exc), incomplete=True)
            return
        ordinal = 0
        with tf:
            iterator = iter(tf)
            while True:
                try:
                    member = next(iterator)
                except StopIteration:
                    break
                except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
                    yield AcquisitionIssue(
                        self.path.name, "archive_truncated", f"{type(exc).__name__}: {exc}", incomplete=True
                    )
                    return
                if member.isdir():
                    continue
                label = safe_text(member.name)
                try:
                    ctx.budget.charge_entry()
                    rel = safe_text(normalize_member_path(member.name))
                except UnsafePathError as exc:
                    yield AcquisitionIssue(label, "unsafe_path_skipped", str(exc))
                    continue
                except BudgetExceeded as exc:
                    yield AcquisitionIssue(label, "budget_exceeded", str(exc), incomplete=True)
                    return
                if member.issym() or member.islnk():
                    yield AcquisitionIssue(rel, "symlink_skipped", f"link -> {safe_text(member.linkname)} (not followed)")
                    continue
                if not member.isreg():
                    yield AcquisitionIssue(rel, "special_file_skipped", "device/fifo entry not read")
                    continue
                fh = tf.extractfile(member)
                if fh is None:
                    yield AcquisitionIssue(rel, "member_read_error", "cannot open member")
                    continue
                times = _tar_times(member)
                try:
                    acquired = ingest_stream(ctx, ordinal, rel, fh, member.size, times)
                except BudgetExceeded as exc:
                    yield AcquisitionIssue(rel, "budget_exceeded", str(exc), incomplete=True)
                    return
                except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
                    yield AcquisitionIssue(rel, "member_read_error", f"{type(exc).__name__}: {exc}", incomplete=True)
                    return
                ordinal += 1
                yield acquired
