"""Acquire a disk image: enumerate its file systems and ingest every regular file exactly like a directory dump."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

from android_forensics.acquisition.base import AcquireContext, AcquiredFile, AcquisitionIssue, ingest_stream
from android_forensics.acquisition.image.ext4 import ROOT_INODE, Ext4Error, Ext4FileSystem, WalkIssue, looks_like_ext
from android_forensics.acquisition.image.f2fs import F2fsError, F2fsFileSystem
from android_forensics.acquisition.image.partitions import FsLocation, find_filesystems
from android_forensics.acquisition.image.source import EWF_MAGIC, SPARSE_MAGIC, ImageError, ImageSource, open_image
from android_forensics.acquisition.safety import BudgetExceeded, UnsafePathError, normalize_member_path
from android_forensics.models import FileTimes, SourceType
from android_forensics.readonly import open_readonly
from android_forensics.util import iso_from_epoch, safe_text

# top-level names of an Android /data partition; a root containing "data" plus another of these is the userdata root
_USERDATA_MARKERS = {"app", "misc", "system", "user", "user_de", "media", "local", "dalvik-cache", "property"}


def is_disk_image(path: Path) -> bool:
    """True if ``path`` is a sparse/E01 image or a raw image holding a recognisable file system or partition table."""
    try:
        with open_readonly(path, follow_symlinks=True) as fh:
            head = fh.read(8)
    except OSError:
        return False
    if len(head) >= 4 and struct.unpack("<I", head[:4])[0] == SPARSE_MAGIC:
        return True
    if head == EWF_MAGIC:
        return True
    try:
        with open_image(path) as src:
            return bool(find_filesystems(src))
    except (ImageError, OSError):
        return False


def _times(ino, fs_name: str) -> FileTimes:  # noqa: ANN001 - Ext4Inode | F2fsInode (same time attributes)
    crtime = f"; crtime={iso_from_epoch(ino.crtime)}" if ino.crtime else ""
    return FileTimes(
        mtime=iso_from_epoch(ino.mtime) if ino.mtime is not None else None,
        atime=iso_from_epoch(ino.atime) if ino.atime is not None else None,
        ctime=iso_from_epoch(ino.ctime) if ino.ctime is not None else None,
        basis=f"{fs_name}_inode (UTC epoch seconds; ctime = inode change time{crtime})",
    )


class ImageAcquirer:
    source_type = SourceType.DISK_IMAGE

    def __init__(self, path: Path, mount_point: str | None = None):
        self.path = path
        self.mount_point = mount_point.strip("/") if mount_point else None

    def acquire(self, ctx: AcquireContext) -> Iterator[AcquiredFile | AcquisitionIssue]:
        try:
            src = open_image(self.path)
        except (ImageError, OSError) as exc:
            yield AcquisitionIssue(self.path.name, "image_unreadable", f"{type(exc).__name__}: {exc}", incomplete=True)
            return
        with src:
            yield AcquisitionIssue(self.path.name, "image_format", src.describe())
            for note in getattr(src, "notes", []):
                yield AcquisitionIssue(self.path.name, "image_incomplete", note, incomplete=True)
            verdict = getattr(src, "verify", None)
            if callable(verdict):
                ok, detail = verdict()
                yield AcquisitionIssue(self.path.name, "image_hash_verified" if ok else "image_hash_mismatch", detail, incomplete=not ok)
            locations = find_filesystems(src)
            if not locations:
                yield AcquisitionIssue(self.path.name, "no_filesystem_found", "no ext2/3/4 or f2fs file system and no partition table recognised", incomplete=True)
                return
            ordinal = 0
            for loc in locations:
                label = f"partition {loc.index}" + (f" '{loc.name}'" if loc.name else "") if loc.index else "image"
                if loc.note:
                    yield AcquisitionIssue(label, "partition_note", loc.note)
                if loc.fstype in ("ext", "f2fs"):
                    ordinal = yield from self._acquire_fs(ctx, src, loc, label, ordinal)
                else:
                    yield AcquisitionIssue(label, "filesystem_not_recognised",
                                           f"{loc.length:,} bytes at offset {loc.offset:,}: neither ext nor f2fs (encrypted, FAT, raw or another format); not read")

    # ------------------------------------------------------------------ helpers shared with other file systems
    def prefix_for(self, loc: FsLocation, root_names: set[str]) -> str:
        if self.mount_point is not None:
            return self.mount_point
        if "data" in root_names and root_names & _USERDATA_MARKERS:
            return "data"          # the image is an Android /data partition: its 'data' dir is /data/data
        if loc.name:
            return "".join(c if c.isalnum() or c in "._-" else "_" for c in loc.name)
        return f"partition{loc.index}" if loc.index else ""

    # ------------------------------------------------------------------ ext2/3/4 and f2fs
    def _acquire_fs(self, ctx: AcquireContext, src: ImageSource, loc: FsLocation, label: str, ordinal: int):
        name = "ext4" if loc.fstype == "ext" else "f2fs"
        try:
            fs: Ext4FileSystem | F2fsFileSystem
            if loc.fstype == "ext":
                ext = fs = Ext4FileSystem(src, loc.offset, loc.length)
                sb = ext.sb
                desc = (f"ext2/3/4, block size {sb.block_size}, {sb.blocks_count:,} blocks, label '{safe_text(sb.label)}', "
                        f"uuid {sb.uuid}, last mounted at '{safe_text(sb.last_mounted)}'")
                root_names = self._ext_root_names(ext)
            else:
                f2 = fs = F2fsFileSystem(src, loc.offset, loc.length)
                desc = (f"f2fs {safe_text(f2.sb.version)}, {f2.sb.block_count:,} blocks, label '{safe_text(f2.sb.label)}', "
                        f"uuid {f2.sb.uuid}, checkpoint version {f2.cp_ver}")
                root_names = f2.root_names()
        except ImageError as exc:
            yield AcquisitionIssue(label, "filesystem_unreadable", f"{name}: {exc}", incomplete=True)
            return ordinal
        yield AcquisitionIssue(label, "filesystem_found", desc)
        for note in fs.notes:
            yield AcquisitionIssue(label, "filesystem_note", note)
        prefix = self.prefix_for(loc, root_names)
        walk_issues: list[WalkIssue] = []
        for entry in fs.walk(walk_issues):
            while walk_issues:
                w = walk_issues.pop(0)
                yield AcquisitionIssue(self._join(prefix, w.path), w.issue_type, w.detail)
            ino = entry.inode
            rel_raw = self._join(prefix, entry.path)
            try:
                ctx.budget.charge_entry()
                rel = safe_text(normalize_member_path(rel_raw))
            except UnsafePathError as exc:
                yield AcquisitionIssue(safe_text(rel_raw), "unsafe_path_skipped", str(exc))
                continue
            except BudgetExceeded as exc:
                yield AcquisitionIssue(safe_text(rel_raw), "budget_exceeded", str(exc), incomplete=True)
                return ordinal
            if ino.is_symlink:
                yield AcquisitionIssue(rel, "symlink_skipped", "symlink inode not followed")
                continue
            if not ino.is_file:
                yield AcquisitionIssue(rel, "special_file_skipped", "device/fifo/socket inode not read")
                continue
            if ino.encrypted:
                yield AcquisitionIssue(rel, "file_based_encryption_detected", "inode carries the fscrypt flag; contents are ciphertext and were not read")
                continue
            try:
                reader = fs.open_file(ino)  # type: ignore[arg-type]
                acquired = ingest_stream(ctx, ordinal, rel, reader, ino.size, _times(ino, name))  # type: ignore[arg-type]
            except BudgetExceeded as exc:
                yield AcquisitionIssue(rel, "budget_exceeded", str(exc), incomplete=True)
                return ordinal
            except (Ext4Error, F2fsError, ImageError, OSError, struct.error) as exc:
                yield AcquisitionIssue(rel, "member_read_error", f"{type(exc).__name__}: {exc}")
                continue
            ordinal += 1
            yield acquired
        while walk_issues:
            w = walk_issues.pop(0)
            yield AcquisitionIssue(self._join(prefix, w.path), w.issue_type, w.detail)
        return ordinal

    @staticmethod
    def _ext_root_names(fs: Ext4FileSystem) -> set[str]:
        try:
            return {e.name.decode("utf-8", "replace") for e in fs.entries(fs.inode(ROOT_INODE))}
        except ImageError:
            return set()

    @staticmethod
    def _join(prefix: str, path: str) -> str:
        path = path.strip("/")
        return f"{prefix}/{path}" if prefix and path else (prefix or path)


__all__ = ["ImageAcquirer", "is_disk_image", "looks_like_ext"]
