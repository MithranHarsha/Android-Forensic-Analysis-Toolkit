"""Carving inside SQLite files: what is already accounted for, and what is free space (Phase 6).

A database is mostly *structured evidence*: live cells that the parsers turn into artifacts, and rows recovery has already
reported. Carving them again would only re-find those values, so the carver is told to skip:

* the 100-byte database header, every b-tree page header and cell-pointer array, and a freelist trunk's bookkeeping;
* the extent of every live cell of every page image *that is the current version of its page* -- the main file's pages the WAL
  has not replaced, and the last committed WAL frame of each page. A replaced page, an older frame, an uncommitted or stale
  frame and every journal page are history: their cells hold values the database no longer shows, so they are carved;
* overflow, pointer-map and lock-byte pages, which hold live payload continuation or nothing;
* the raw bytes of each record the recovery engine reported (``recovered`` ranges).

What is left is the unallocated gap of each page, freeblocks nobody could turn into a row, released pages the schema cannot
describe, and slack -- the places where bytes outlive their structure. A hit there is reported with
``container="sqlite_free_space"``: it lies inside a parsed database, which the scorer counts as a (small) point in its favour.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable

from android_forensics.carving.carver import CarveResult, CarveSource, Exclusions, carve_file
from android_forensics.sqlite.journal import JournalInfo
from android_forensics.sqlite.pages import PageError, parse_btree_page
from android_forensics.sqlite.parser import PageRole, SQLiteDatabase
from android_forensics.sqlite.recovery import live_extents
from android_forensics.sqlite.wal import COMMITTED, FRAME_HEADER, WAL_HEADER, WalInfo

DB_HEADER = 100


def page_image_exclusions(number: int, data: bytes, usable: int, base: int, *, cells: bool = True) -> list[tuple[int, int]]:
    """Ranges of one page image (which starts at file offset ``base``) that must not be carved: the database header (page 1),
    the b-tree page header and cell-pointer array, and -- when ``cells`` -- the live cells."""
    out: list[tuple[int, int]] = []
    if number == 1:
        out.append((base, base + min(DB_HEADER, len(data))))
    try:
        page = parse_btree_page(number, data)
    except PageError:
        return out  # not a b-tree page (or unreadable): none of it is known structure
    out.append((base + page.header_offset, base + max(page.pointer_array_end, page.header_offset)))
    if cells:
        out.extend((base + a, base + b) for a, b in live_extents(page, usable))
    return out


def _last_committed(wal: WalInfo | None) -> dict[int, int]:
    """page number -> index of the newest committed frame carrying it (that frame *is* the page as the active view sees it)."""
    latest: dict[int, int] = {}
    for frame in (wal.frames if wal else ()):
        if frame.status == COMMITTED and frame.page_number:
            latest[frame.page_number] = frame.index
    return latest


def main_file_exclusions(db: SQLiteDatabase, wal: WalInfo | None = None, recovered: Iterable[tuple[int, int]] = ()) -> list[tuple[int, int]]:
    """Ranges of the main file that are structure, live data or already-recovered rows. ``recovered`` is ``(file_offset, length)``;
    ``wal`` (if there is one) tells which pages of the main file it has replaced."""
    roles = db.page_map()
    ps = db.page_size
    replaced = set(_last_committed(wal))
    ranges: list[tuple[int, int]] = [(o, o + n) for o, n in recovered]
    for number in range(1, db.file_page_count + 1):
        base = (number - 1) * ps
        info = roles[number]
        if info.role in (PageRole.OVERFLOW, PageRole.POINTER_MAP, PageRole.LOCK_BYTE):
            ranges.append((base, base + ps))
            continue
        data = db.read_page(number)
        if info.role == PageRole.FREELIST_TRUNK:
            leaves = struct.unpack_from(">I", data, 4)[0]
            ranges.append((base, base + min(ps, 8 + 4 * leaves)))
            continue
        # a current b-tree page's cells are live data; a released page's or a replaced page's cells are history (what recovery
        # looks at, and what it reports is excluded through ``recovered``), so only their header and pointer array are structure
        current = info.role == PageRole.BTREE and number not in replaced
        ranges += page_image_exclusions(number, data, db.usable_size, base, cells=current)
    return ranges


def wal_exclusions(wal: WalInfo, db: SQLiteDatabase, recovered: Iterable[tuple[int, int]] = ()) -> list[tuple[int, int]]:
    latest = _last_committed(wal)
    ranges: list[tuple[int, int]] = [(o, o + n) for o, n in recovered] + [(0, min(WAL_HEADER, wal.size))]
    for frame in wal.frames:
        ranges.append((frame.offset, frame.offset + FRAME_HEADER))
        if frame.page_number:
            current = latest.get(frame.page_number) == frame.index
            ranges += page_image_exclusions(frame.page_number, wal.page(frame), db.usable_size, frame.page_offset, cells=current)
    return ranges


def journal_exclusions(journal: JournalInfo, db: SQLiteDatabase, recovered: Iterable[tuple[int, int]] = ()) -> list[tuple[int, int]]:
    first = journal.records[0].offset if journal.records else journal.size
    ranges: list[tuple[int, int]] = [(o, o + n) for o, n in recovered] + [(0, first)]
    for r in journal.records:
        ranges.append((r.offset, r.offset + 4))
        ranges.append((r.page_offset() + journal.page_size, r.page_offset() + journal.page_size + 4))
        ranges += page_image_exclusions(r.page_number, journal.page(r), db.usable_size, r.page_offset(), cells=False)  # history
    return ranges


def carve_database_file(path: str | Path, source: CarveSource, exclusions: Iterable[tuple[int, int]], **options) -> CarveResult:
    """Carve one file of a database (main, ``-wal`` or ``-journal``), skipping ``exclusions``; hits are tagged as free space."""
    tagged = CarveSource(source.evidence_file_id, source.source_file, source.source_sha256, container="sqlite_free_space")
    return carve_file(path, tagged, exclude=Exclusions(exclusions), **options)
