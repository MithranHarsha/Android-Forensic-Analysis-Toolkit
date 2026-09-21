"""Header-level facts about WAL, shared-memory and rollback-journal sidecar files.

Review 1 records *that* these files exist and what their headers claim. It does not
interpret frames or journalled pages — that is Review 2's job. Numbers reported here
are indicators of recovery potential, not findings.
"""

from __future__ import annotations

import struct
from pathlib import Path

from pydantic import BaseModel

from android_forensics.filesystem.classifier import JOURNAL_MAGIC, WAL_MAGICS
from android_forensics.readonly import open_readonly

WAL_HEADER = 32
WAL_FRAME_HEADER = 24
JOURNAL_HEADER = 28


class WalFacts(BaseModel):
    size: int
    magic_valid: bool = False
    checksum_endianness: str | None = None
    format_version: int | None = None
    page_size: int | None = None
    checkpoint_sequence: int | None = None
    salt1: int | None = None
    salt2: int | None = None
    frame_slots: int | None = None
    trailing_bytes: int | None = None
    matches_db_page_size: bool | None = None
    note: str = ""


class JournalFacts(BaseModel):
    size: int
    magic_valid: bool = False
    header_zeroed: bool = False
    page_count_field: int | None = None
    initial_db_pages: int | None = None
    sector_size: int | None = None
    page_size: int | None = None
    matches_db_page_size: bool | None = None
    note: str = ""


class ShmFacts(BaseModel):
    size: int
    format_version: int | None = None
    max_frame: int | None = None
    page_size: int | None = None
    note: str = ""


def inspect_wal(path: Path, db_page_size: int | None) -> WalFacts:
    size = path.stat().st_size
    if size == 0:
        return WalFacts(size=0, note="empty: all frames checkpointed into the main database, or WAL truncated")
    with open_readonly(path) as fh:
        head = fh.read(WAL_HEADER)
    if len(head) < WAL_HEADER or head[:4] not in WAL_MAGICS:
        return WalFacts(size=size, note="WAL header magic invalid — file corrupt or overwritten")
    _magic, version, page_size, seq, salt1, salt2, _c1, _c2 = struct.unpack(">8I", head)
    ps = 65536 if page_size == 1 else page_size
    slot = ps + WAL_FRAME_HEADER
    body = size - WAL_HEADER
    return WalFacts(
        size=size,
        magic_valid=True,
        checksum_endianness="big" if head[:4] == WAL_MAGICS[1] else "little",
        format_version=version,
        page_size=ps,
        checkpoint_sequence=seq,
        salt1=salt1,
        salt2=salt2,
        frame_slots=body // slot if slot else None,
        trailing_bytes=body % slot if slot else None,
        matches_db_page_size=(ps == db_page_size) if db_page_size else None,
        note="frame_slots is an upper bound: salt/checksum validity of each frame is examined in Review 2",
    )


def inspect_journal(path: Path, db_page_size: int | None) -> JournalFacts:
    size = path.stat().st_size
    if size == 0:
        return JournalFacts(size=0, note="empty journal")
    with open_readonly(path) as fh:
        head = fh.read(JOURNAL_HEADER)
    if head[:8] == bytes(8):
        return JournalFacts(size=size, header_zeroed=True, note="header zeroed: journal_mode=PERSIST after a commit (stale pages may remain), or a transaction whose journal was never synced; SQLite does not treat it as hot")
    if len(head) < JOURNAL_HEADER or head[:8] != JOURNAL_MAGIC:
        return JournalFacts(size=size, note="journal header magic invalid — corrupt or non-standard")
    _m, count, _nonce, init_pages, sector, page_size = struct.unpack(">8sIIIII", head)
    return JournalFacts(
        size=size,
        magic_valid=True,
        page_count_field=count,
        initial_db_pages=init_pages,
        sector_size=sector,
        page_size=page_size,
        matches_db_page_size=(page_size == db_page_size) if db_page_size else None,
        note="valid-magic journal: an interrupted write transaction; SQLite rolls it back on next open. The header page count reflects the last sync only — journal records may extend beyond it (examined in Review 2)"
        if size > JOURNAL_HEADER
        else "journal header only",
    )


def inspect_shm(path: Path) -> ShmFacts:
    size = path.stat().st_size
    with open_readonly(path) as fh:
        head = fh.read(48)
    if len(head) < 48:
        return ShmFacts(size=size, note="wal-index shorter than one header")
    for endian in ("<", ">"):
        version, _unused, _change, _init, _big, page_size, max_frame, _npage = struct.unpack(f"{endian}IIIBBHII", head[:24])
        if version == 3007000:
            return ShmFacts(
                size=size,
                format_version=version,
                max_frame=max_frame,
                page_size=65536 if page_size == 1 else page_size,
                note="wal-index header; max_frame = last valid WAL frame recorded by the writer",
            )
    return ShmFacts(size=size, note="wal-index header not recognised (stale or corrupt)")
