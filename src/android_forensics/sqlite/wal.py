"""The write-ahead log: header, frames, checksum validation and page versions (Phase 4C).

Reference: https://www.sqlite.org/walformat.html. All integers are big-endian.

**WAL header** (32 bytes)::

    [0..3]  magic 0x377f0682 (little-endian checksums) or 0x377f0683 (big-endian checksums)
    [4..7]  file format version (3007000)     [8..11] page size      [12..15] checkpoint sequence
    [16..19] salt-1      [20..23] salt-2      [24..27] checksum-1    [28..31] checksum-2

**Frame** (24-byte header + one page)::

    [0..3] page number    [4..7] database size in pages after commit (non-zero only on a commit frame)
    [8..11] salt-1        [12..15] salt-2      [16..19] checksum-1    [20..23] checksum-2

The **checksum** treats its input as 8-byte units of two 32-bit words (byte order from the magic number) and runs
``s0 += x0 + s1; s1 += x1 + s0`` (mod 2³²). The header checksum covers header bytes 0-23. A frame's checksum covers its
header bytes 0-7 and then its whole page, and is *cumulative*: it starts from the previous frame's stored checksums (frame 1
starts from the header's).

A frame is **valid** if both salts equal the header's and its checksum matches; the first invalid frame ends the valid run.
Valid frames up to the last commit frame are **committed** (visible to readers); later valid frames are an uncommitted tail.
When the WAL is reset for reuse, SQLite writes new salts and overwrites frames from the start — it does not shorten the file
— so frames beyond the new end are **stale**: they carry an older generation's salts and are the WAL's history of pages
that have since been superseded. Stale frames cannot be checked against their own header (it is gone), but consecutive stale
frames are checked against *each other* (each frame's checksum must follow from its predecessor's).
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path

from android_forensics import config
from android_forensics.readonly import open_readonly

WAL_HEADER = 32
FRAME_HEADER = 24
MAGIC_LE = 0x377F0682  # checksums use little-endian words
MAGIC_BE = 0x377F0683


class WalError(ValueError):
    pass


def wal_checksum(data: bytes, s0: int = 0, s1: int = 0, *, big_endian: bool) -> tuple[int, int]:
    """SQLite's WAL checksum over ``data`` (length a multiple of 8), continuing from ``(s0, s1)``."""
    if len(data) % 8:
        raise WalError("checksum input must be a multiple of 8 bytes")
    fmt = ">" if big_endian else "<"
    words = struct.unpack(f"{fmt}{len(data) // 4}I", data)
    for i in range(0, len(words), 2):
        s0 = (s0 + words[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + words[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


@dataclass(frozen=True)
class WalHeader:
    magic: int
    version: int
    page_size: int
    checkpoint_sequence: int
    salt1: int
    salt2: int
    checksum1: int
    checksum2: int
    checksum_valid: bool

    @property
    def big_endian(self) -> bool:
        return self.magic == MAGIC_BE


# frame statuses
COMMITTED = "committed"  # valid, and at or before the last commit frame: visible to readers
UNCOMMITTED = "uncommitted"  # valid but after the last commit frame
STALE = "stale_generation"  # salts from an earlier WAL generation: a superseded page version
STALE_UNVERIFIED = "stale_unverified"  # older-generation salts and nothing to check its checksum against
CORRUPT = "corrupt"  # current salts but the checksum does not follow
EMPTY = "empty"


@dataclass(frozen=True)
class WalFrame:
    index: int  # 1-based position in the file
    offset: int  # of the frame header
    page_number: int
    commit_size: int
    salt1: int
    salt2: int
    checksum1: int
    checksum2: int
    status: str

    @property
    def page_offset(self) -> int:
        return self.offset + FRAME_HEADER

    @property
    def is_commit(self) -> bool:
        return self.commit_size != 0


@dataclass
class WalInfo:
    path: str
    size: int
    header: WalHeader | None
    frames: list[WalFrame] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    data: bytes = field(default=b"", repr=False)

    @property
    def page_size(self) -> int:
        return self.header.page_size if self.header else 0

    def count(self, status: str) -> int:
        return sum(1 for f in self.frames if f.status == status)

    def page(self, frame: WalFrame) -> bytes:
        return self.data[frame.page_offset: frame.page_offset + self.page_size]

    def summary(self) -> dict[str, int]:
        return {s: self.count(s) for s in (COMMITTED, UNCOMMITTED, STALE, STALE_UNVERIFIED, CORRUPT, EMPTY)}


def parse_wal(path: str | Path, *, expected_page_size: int | None = None) -> WalInfo:
    """Parse a ``-wal`` file. A WAL with a damaged header still yields its frames if ``expected_page_size`` is supplied
    (the page size then comes from the database)."""
    path = Path(path)
    with open_readonly(path) as fh:
        size = os.fstat(fh.fileno()).st_size
        if size > config.MAX_SIDECAR_BYTES:
            return WalInfo(str(path), size, None, problems=[
                f"WAL is {size:,} bytes, over the {config.MAX_SIDECAR_BYTES:,}-byte limit for sidecars: not parsed (raise config.MAX_SIDECAR_BYTES to analyse it)"])
        data = fh.read()
    info = WalInfo(str(path), len(data), None, data=data)
    if len(data) < WAL_HEADER:
        info.problems.append("WAL shorter than its 32-byte header")
        return info
    magic, version, page_size, seq, salt1, salt2, c1, c2 = struct.unpack(">8I", data[:WAL_HEADER])
    big = magic == MAGIC_BE
    header_ok = magic in (MAGIC_LE, MAGIC_BE)
    page_size = 65536 if page_size == 1 else page_size
    if header_ok:
        info.header = WalHeader(magic, version, page_size, seq, salt1, salt2, c1, c2,
                                checksum_valid=wal_checksum(data[:24], big_endian=big) == (c1, c2))
        if not info.header.checksum_valid:
            info.problems.append("WAL header checksum does not match: header may be damaged")
        if page_size < 512 or page_size & (page_size - 1):
            info.problems.append(f"WAL header page size {page_size} is invalid")
            info.header = None
    else:
        info.problems.append("WAL header magic invalid")
    ps = info.header.page_size if info.header else (expected_page_size or 0)
    if not ps:
        return info
    if info.header is None:  # frames of a WAL whose header is gone: classify every non-empty frame as unverifiable
        info.header = WalHeader(0, 0, ps, 0, 0, 0, 0, 0, False)
    _classify_frames(info, ps, valid_header=header_ok and info.header.checksum_valid)
    return info


def _classify_frames(info: WalInfo, ps: int, *, valid_header: bool) -> None:
    data, header = info.data, info.header
    assert header is not None
    slot = FRAME_HEADER + ps
    count = (len(data) - WAL_HEADER) // slot
    trailing = (len(data) - WAL_HEADER) % slot
    if trailing:
        info.problems.append(f"{trailing} trailing bytes after the last whole frame (an incomplete frame write)")
    big = header.big_endian
    s0, s1 = header.checksum1, header.checksum2
    chain_alive = valid_header
    prev_stale: tuple[int, int] | None = None
    frames: list[WalFrame] = []
    for i in range(count):
        off = WAL_HEADER + i * slot
        raw = data[off: off + FRAME_HEADER]
        page_number, commit, sa, sb, ca, cb = struct.unpack(">6I", raw)
        if page_number == 0 and sa == 0 and sb == 0 and ca == 0 and cb == 0:
            frames.append(WalFrame(i + 1, off, 0, 0, 0, 0, 0, 0, EMPTY))
            continue
        current = (sa, sb) == (header.salt1, header.salt2) and valid_header
        status: str
        if current and chain_alive:
            page = data[off + FRAME_HEADER: off + slot]
            n0, n1 = wal_checksum(raw[:8], s0, s1, big_endian=big)
            n0, n1 = wal_checksum(page, n0, n1, big_endian=big)
            if (n0, n1) == (ca, cb):
                s0, s1 = n0, n1
                status = COMMITTED  # provisional: frames after the last commit are re-labelled below
            else:
                chain_alive = False
                status = CORRUPT
        elif current:
            status = CORRUPT  # follows a broken frame, so cannot be trusted
        else:
            page = data[off + FRAME_HEADER: off + slot]
            if prev_stale is not None:
                n0, n1 = wal_checksum(raw[:8], *prev_stale, big_endian=big)
                n0, n1 = wal_checksum(page, n0, n1, big_endian=big)
                status = STALE if (n0, n1) == (ca, cb) else STALE_UNVERIFIED
            else:
                status = STALE_UNVERIFIED
            prev_stale = (ca, cb)
        frames.append(WalFrame(i + 1, off, page_number, commit, sa, sb, ca, cb, status))
    last_commit = max((f.index for f in frames if f.status == COMMITTED and f.is_commit), default=0)
    info.frames = [
        WalFrame(f.index, f.offset, f.page_number, f.commit_size, f.salt1, f.salt2, f.checksum1, f.checksum2,
                 UNCOMMITTED if f.status == COMMITTED and f.index > last_commit else f.status)
        for f in frames
    ]
