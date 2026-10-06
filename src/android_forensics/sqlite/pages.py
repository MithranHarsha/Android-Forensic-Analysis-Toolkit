"""SQLite pages: b-tree page headers, cell-pointer arrays, freeblock chains, cells and overflow chains.

Reference: https://www.sqlite.org/fileformat2.html §1.6 ("B-tree Pages"). Every offset used here, relative to the start of
the page (page 1 begins with the 100-byte database header, so its b-tree header starts at byte 100):

======  =====  ==================================================================================================
offset  bytes  field
======  =====  ==================================================================================================
0       1      page type: 0x02 index interior · 0x05 table interior · 0x0A index leaf · 0x0D table leaf
1       2      offset of the first **freeblock** on the page, or 0
3       2      number of cells
5       2      start of the **cell content area** (0 means 65536); cells grow downwards from the end of the page
7       1      number of **fragmented free bytes** (free gaps of 1–3 bytes, which no freeblock records)
8       4      right-most child pointer (interior pages only)
8/12    2×n    the **cell pointer array**: ``n`` big-endian offsets, one per cell, in key order
======  =====  ==================================================================================================

Free space on a b-tree page is one of: the **unallocated gap** between the end of the cell-pointer array and the start of the
cell content area; a **freeblock** (a chain in increasing offset order, each block starting ``[next:2][size:2]`` and covering
``size`` bytes); or a fragment. Deleting a cell turns its bytes into a freeblock (overwriting its first four bytes with the
freeblock header) — or, when it was the cell nearest the gap, just grows the gap and leaves the cell intact.

Cell layouts (``varint`` as in ``records.py``):

* table leaf     ``[payload size: varint][rowid: varint][payload][overflow page: 4 bytes, if spilled]``
* table interior ``[left child page: 4 bytes][rowid: varint]``
* index leaf     ``[payload size: varint][payload][overflow page: 4]``
* index interior ``[left child page: 4][payload size: varint][payload][overflow page: 4]``

A payload that does not fit locally continues in a chain of **overflow pages**: ``[next page: 4 bytes][content: U-4 bytes]``.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from android_forensics.readonly import open_readonly
from android_forensics.sqlite.records import RecordError, local_payload_size, read_varint, to_signed64

MAX_PAGE_SIZE = 65536
MIN_PAGE_SIZE = 512
DB_HEADER_SIZE = 100


class PageError(RecordError):
    """A page that cannot be read or is structurally impossible."""


class PageType(StrEnum):
    TABLE_LEAF = "table_leaf"
    TABLE_INTERIOR = "table_interior"
    INDEX_LEAF = "index_leaf"
    INDEX_INTERIOR = "index_interior"
    FREELIST_TRUNK = "freelist_trunk"
    FREELIST_LEAF = "freelist_leaf"
    OVERFLOW = "overflow"
    POINTER_MAP = "pointer_map"
    LOCK_BYTE = "lock_byte"
    UNKNOWN = "unknown"

    @property
    def is_btree(self) -> bool:
        return self in (PageType.TABLE_LEAF, PageType.TABLE_INTERIOR, PageType.INDEX_LEAF, PageType.INDEX_INTERIOR)

    @property
    def is_leaf(self) -> bool:
        return self in (PageType.TABLE_LEAF, PageType.INDEX_LEAF)

    @property
    def is_index(self) -> bool:
        return self in (PageType.INDEX_LEAF, PageType.INDEX_INTERIOR)


_BTREE_BY_BYTE = {
    0x0D: PageType.TABLE_LEAF, 0x05: PageType.TABLE_INTERIOR, 0x0A: PageType.INDEX_LEAF, 0x02: PageType.INDEX_INTERIOR,
}


# ------------------------------------------------------------------ page sources


class PageSource(Protocol):
    """Anything that yields fixed-size pages by 1-based page number: the database file, a WAL frame set, a journal."""

    page_size: int

    @property
    def page_count(self) -> int: ...

    def read_page(self, number: int) -> bytes: ...


class FilePageSource:
    """Pages of a file on disk, read on demand through the read-only opener. Use as a context manager (or call ``close``)."""

    def __init__(self, path: str | Path, page_size: int):
        if page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE or page_size & (page_size - 1):
            raise PageError(f"invalid page size {page_size}")
        self.path = Path(path)
        self.page_size = page_size
        self._fh = open_readonly(self.path)
        self._size = os.fstat(self._fh.fileno()).st_size

    @property
    def size(self) -> int:
        return self._size

    @property
    def page_count(self) -> int:
        return self._size // self.page_size

    def read_page(self, number: int) -> bytes:
        if number < 1:
            raise PageError(f"page numbers start at 1, not {number}")
        offset = (number - 1) * self.page_size
        if offset + self.page_size > self._size:
            raise PageError(f"page {number} lies beyond the end of the file ({self._size} bytes)")
        self._fh.seek(offset)
        data = self._fh.read(self.page_size)
        if len(data) != self.page_size:
            raise PageError(f"short read for page {number}")
        return data

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> FilePageSource:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class BytesPageSource:
    """Pages held in memory (tests, journal images, WAL page versions)."""

    def __init__(self, data: bytes, page_size: int):
        self.page_size = page_size
        self._data = data

    @property
    def page_count(self) -> int:
        return len(self._data) // self.page_size

    def read_page(self, number: int) -> bytes:
        if number < 1 or number > self.page_count:
            raise PageError(f"page {number} is outside 1..{self.page_count}")
        return self._data[(number - 1) * self.page_size: number * self.page_size]


# ------------------------------------------------------------------ b-tree pages


@dataclass(frozen=True)
class Freeblock:
    offset: int
    size: int
    next_offset: int

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class BTreePage:
    """A parsed b-tree page. ``data`` is the whole page; every offset is within it."""

    number: int
    data: bytes
    type: PageType
    header_offset: int
    first_freeblock: int
    cell_count: int
    content_start: int
    fragmented_bytes: int
    right_pointer: int | None
    pointer_array_start: int
    cell_offsets: tuple[int, ...]
    freeblocks: tuple[Freeblock, ...]
    problems: tuple[str, ...] = field(default=())

    @property
    def pointer_array_end(self) -> int:
        return self.pointer_array_start + 2 * self.cell_count

    @property
    def unallocated(self) -> tuple[int, int]:
        """The gap between the cell-pointer array and the cell content area (may be empty: ``start == end``)."""
        return self.pointer_array_end, max(self.content_start, self.pointer_array_end)

    @property
    def is_valid(self) -> bool:
        return not self.problems


def page_header_offset(page_number: int) -> int:
    return DB_HEADER_SIZE if page_number == 1 else 0


def classify_btree_byte(byte: int) -> PageType | None:
    return _BTREE_BY_BYTE.get(byte)


def parse_btree_page(number: int, data: bytes) -> BTreePage:
    """Parse the b-tree header, cell-pointer array and freeblock chain of a page. Structural problems are collected in
    ``problems`` (the parse continues as far as it safely can); a page that is not a b-tree page raises ``PageError``."""
    page_size = len(data)
    ho = page_header_offset(number)
    if page_size < ho + 8:
        raise PageError("page too small for a b-tree header")
    ptype = _BTREE_BY_BYTE.get(data[ho])
    if ptype is None:
        raise PageError(f"page {number}: byte 0x{data[ho]:02x} at offset {ho} is not a b-tree page type")
    header_size = 8 if ptype.is_leaf else 12
    first_free, cell_count, content_raw = struct.unpack_from(">HHH", data, ho + 1)
    fragmented = data[ho + 7]
    right = struct.unpack_from(">I", data, ho + 8)[0] if not ptype.is_leaf else None
    content_start = 65536 if content_raw == 0 else content_raw
    array_start = ho + header_size
    problems: list[str] = []
    if array_start + 2 * cell_count > page_size:
        problems.append(f"cell pointer array ({cell_count} cells) runs past the end of the page")
        cell_count = max(0, (page_size - array_start) // 2)
    offsets = tuple(struct.unpack_from(">H", data, array_start + 2 * i)[0] for i in range(cell_count))
    if content_start > page_size:
        problems.append(f"cell content area starts at {content_start}, beyond the page ({page_size})")
    elif content_start < array_start + 2 * cell_count:
        problems.append("cell content area overlaps the cell pointer array")
    bad = [o for o in offsets if o < array_start + 2 * cell_count or o >= page_size]
    if bad:
        problems.append(f"{len(bad)} cell pointer(s) point outside the cell content area")

    blocks: list[Freeblock] = []
    pos = first_free
    seen = 0
    while pos:
        seen += 1
        if seen > page_size // 4 + 1:
            problems.append("freeblock chain does not terminate")
            break
        if pos + 4 > page_size or pos < array_start:
            problems.append(f"freeblock offset {pos} is outside the page")
            break
        nxt, size = struct.unpack_from(">HH", data, pos)
        if size < 4 or pos + size > page_size:
            problems.append(f"freeblock at {pos} has impossible size {size}")
            break
        blocks.append(Freeblock(pos, size, nxt))
        if nxt and nxt <= pos:
            problems.append(f"freeblock chain goes backwards ({pos} -> {nxt})")
            break
        pos = nxt
    return BTreePage(
        number=number, data=data, type=ptype, header_offset=ho, first_freeblock=first_free, cell_count=cell_count,
        content_start=content_start, fragmented_bytes=fragmented, right_pointer=right, pointer_array_start=array_start,
        cell_offsets=offsets, freeblocks=tuple(blocks), problems=tuple(problems),
    )


# ------------------------------------------------------------------ cells


@dataclass(frozen=True)
class Cell:
    """One cell of a b-tree page, located and sized (its payload is read with ``read_cell_payload``)."""

    page: int
    index: int  # position in the cell-pointer array
    offset: int  # within the page
    type: PageType
    rowid: int | None
    left_child: int | None
    payload_size: int | None
    payload_offset: int | None  # within the page
    local_size: int  # payload bytes on this page
    overflow_page: int | None
    size: int  # bytes the cell occupies on the page, overflow pointer included

    @property
    def end(self) -> int:
        return self.offset + self.size


def read_cell(page: BTreePage, index: int, usable_size: int) -> Cell:
    """Decode the ``index``-th cell of ``page`` (locating its payload, not reading spilled bytes)."""
    offset = page.cell_offsets[index]
    data = page.data
    ptype = page.type
    if offset >= len(data):
        raise PageError(f"page {page.number}: cell {index} starts at {offset}, past the page")
    pos = offset
    left = rowid = payload_size = None
    if not ptype.is_leaf:
        if pos + 4 > len(data):
            raise PageError("interior cell truncated")
        left = struct.unpack_from(">I", data, pos)[0]
        pos += 4
    if ptype is PageType.TABLE_INTERIOR:
        rowid_raw, n = read_varint(data, pos)
        return Cell(page.number, index, offset, ptype, to_signed64(rowid_raw), left, None, None, 0, None, pos + n - offset)
    payload_size, n = read_varint(data, pos)
    pos += n
    if ptype is PageType.TABLE_LEAF:
        rowid_raw, n = read_varint(data, pos)
        rowid = to_signed64(rowid_raw)
        pos += n
    local = local_payload_size(payload_size, usable_size, index=ptype.is_index)
    if pos + local > len(data):
        raise PageError(f"page {page.number}: cell {index} payload ({local} local bytes) runs past the page")
    overflow = None
    size = pos - offset + local
    if local < payload_size:
        if pos + local + 4 > len(data):
            raise PageError(f"page {page.number}: cell {index} overflow pointer runs past the page")
        overflow = struct.unpack_from(">I", data, pos + local)[0]
        size += 4
    return Cell(page.number, index, offset, ptype, rowid, left, payload_size, pos, local, overflow, size)


def read_cell_payload(page: BTreePage, cell: Cell, source: PageSource, usable_size: int) -> bytes:
    """The complete payload of a cell: the local part, then the overflow chain (loop- and range-checked)."""
    if cell.payload_size is None or cell.payload_offset is None:
        raise PageError("interior table cells carry no payload")
    payload = bytearray(page.data[cell.payload_offset: cell.payload_offset + cell.local_size])
    remaining = cell.payload_size - cell.local_size
    nxt = cell.overflow_page
    visited: set[int] = set()
    while remaining > 0:
        if not nxt or nxt in visited or nxt > source.page_count:
            raise PageError(f"page {page.number}: overflow chain of cell {cell.index} is broken at page {nxt}")
        visited.add(nxt)
        chunk = source.read_page(nxt)
        following = struct.unpack_from(">I", chunk, 0)[0]
        take = min(remaining, usable_size - 4)
        payload += chunk[4:4 + take]
        remaining -= take
        nxt = following
    return bytes(payload)
