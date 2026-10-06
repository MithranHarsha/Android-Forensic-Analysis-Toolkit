"""Locate file systems inside a disk image: a bare partition image, an MBR disk or a GPT disk (Android devices use GPT)."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from android_forensics.acquisition.image.ext4 import EXT_MAGIC
from android_forensics.acquisition.image.source import ImageSource

F2FS_MAGIC = 0xF2F52010
MAX_GPT_ENTRIES = 1024


@dataclass(frozen=True)
class FsLocation:
    index: int            # 0 for a bare file system, else 1-based partition number
    offset: int
    length: int
    fstype: str           # "ext" | "f2fs" | "unknown"
    name: str | None = None   # GPT partition name, e.g. "userdata"
    note: str | None = None


def fs_type_at(src: ImageSource, offset: int) -> str:
    raw = src.read_at(offset + 1024, 64)
    if len(raw) >= 58 and struct.unpack_from("<H", raw, 56)[0] == EXT_MAGIC:
        return "ext"
    if len(raw) >= 4 and struct.unpack_from("<I", raw, 0)[0] == F2FS_MAGIC:
        return "f2fs"
    return "unknown"


def _gpt(src: ImageSource, sector: int) -> list[FsLocation] | None:
    hdr = src.read_at(sector, 92)
    if len(hdr) < 92 or hdr[:8] != b"EFI PART":
        return None
    entries_lba, count, size = struct.unpack_from("<QII", hdr, 72)
    if count == 0 or count > MAX_GPT_ENTRIES or size < 128 or size > 512 or size & (size - 1):
        return []
    out: list[FsLocation] = []
    table = src.read_at(entries_lba * sector, count * size)
    for i in range(min(count, len(table) // size)):
        e = table[i * size:(i + 1) * size]
        if e[:16] == bytes(16):
            continue
        first, last = struct.unpack_from("<QQ", e, 32)
        if last < first or (last + 1) * sector > src.size:
            continue
        name = e[56:128].decode("utf-16le", "replace").split("\0")[0] or None
        off, length = first * sector, (last - first + 1) * sector
        out.append(FsLocation(i + 1, off, length, fs_type_at(src, off), name))
    return out


def _mbr(src: ImageSource) -> list[FsLocation] | None:
    sec = src.read_at(0, 512)
    if len(sec) < 512 or sec[510:512] != b"\x55\xaa":
        return None
    out: list[FsLocation] = []
    for i in range(4):
        e = sec[446 + 16 * i:462 + 16 * i]
        ptype, = struct.unpack_from("<B", e, 4)
        start, count = struct.unpack_from("<II", e, 8)
        if ptype == 0 or count == 0:
            continue
        if ptype == 0xEE:
            return None  # protective MBR: use the GPT
        off, length = start * 512, count * 512
        if off + 1024 > src.size:
            continue
        note = "extended partition not followed" if ptype in (0x05, 0x0F, 0x85) else None
        out.append(FsLocation(i + 1, off, min(length, src.size - off), fs_type_at(src, off), None, note))
    return out or None


def find_filesystems(src: ImageSource) -> list[FsLocation]:
    """File systems found in the image, in disk order. An image that is itself a file system yields one entry at offset 0."""
    bare = fs_type_at(src, 0)
    if bare != "unknown":
        return [FsLocation(0, 0, src.size, bare)]
    for sector in (512, 4096):
        gpt = _gpt(src, sector)
        if gpt is not None:
            return gpt
    mbr = _mbr(src)
    return mbr or []


def looks_like_disk_image(src: ImageSource) -> bool:
    return bool(find_filesystems(src))
