"""Deleted-record recovery from raw pages (Phase 4B).

**Why ``SELECT *`` cannot see deleted rows, and what remains.** SQLite deletes a row by marking its cell's bytes free; it does
not erase them (unless ``secure_delete`` is on). Depending on where the cell sat, what is left is:

============================  ========================================================================================
cell sat …                    what remains
============================  ========================================================================================
next to the unallocated gap   the whole cell, untouched: payload size, rowid, record          -> **RECOVERED**
elsewhere on a leaf page      a *freeblock*: SQLite overwrote the cell's first four bytes with ``[next:2][size:2]`` —
                              those held the payload size, the rowid and, when both are short, the record's header size
                              and first serial type. The rest is intact                       -> **PARTIAL**
on a page that was released   the page, untouched, on the freelist (a leaf page keeps its header, pointer array, cells)
in a stale page image         a WAL frame or rollback-journal page holding an older version of the page
============================  ========================================================================================

**Method.** Every page image is scanned for byte sequences that parse as a record *exactly* under some table's schema
(``ddl.py``): the right number of serial types, ``header size + body sizes == payload size``, a NULL in the rowid-alias
column, plausible types. Two hypotheses are tested at every offset:

``full``       ``[payload size][rowid][record]`` starts here: an untouched cell.
``clobbered``  a freeblock starts here. The cell's first four bytes are gone, so the surviving bytes are read under each
               plausible layout of the lost prefix (payload-size and rowid varints of 1–2 and 1–5 bytes give the record
               header a start of 2, 3, 4 … bytes into the cell). A hypothesis is accepted only if the record it implies
               *fills the freeblock exactly*, its stated header size (when it survives) matches, the payload size it implies
               fits the assumed varint length, and — for a lost first serial type — the type size it forces is legal and,
               for a rowid alias, zero.

**What is never done.** A field the bytes do not determine is ``UNKNOWN`` (the rowid of a freeblock cell always is). A cell
whose payload spilled to overflow pages is not attempted. Nothing is inferred from neighbouring rows.

**Statuses.** ``RECOVERED``: an untouched cell — every field and the rowid. ``PARTIAL``: a freeblock cell — every surviving
field, no rowid (and possibly one field inferred from its length and declared affinity, flagged). ``CORRUPTED``: the record
structure fits exactly but a value fails validation (text that is not valid UTF-8): the values cannot be trusted.

Records equal to a row of the active view are not deleted data and are dropped (``ActiveIndex``); the same row found in
several places is reported once, with the other locations noted.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from android_forensics.models.enums import ArtifactStatus, ExtractionMethod
from android_forensics.models.unknown import UNKNOWN
from android_forensics.sqlite.ddl import ColumnDef, TableSql
from android_forensics.sqlite.pages import BTreePage, PageError, parse_btree_page
from android_forensics.sqlite.parser import PageRole, SQLiteDatabase
from android_forensics.sqlite.records import (
    RecordError,
    decode_value,
    read_varint,
    serial_type_class,
    serial_type_size,
    to_signed64,
    varint_length,
)

MIN_CELL = 4
MIN_SCAN_WIDTH = 3  # a table with fewer columns carries too little structure to recognise in free space (any 1-2 values "fit")
MAX_ROWID_BYTES = 6  # a rowid needing more than 6 varint bytes (>= 2^42) is not plausible for a phone's tables
MAX_LOST_PREFIX = 12
_STRONG, _WEAK = 1.0, 0.5
MIN_FIT = 0.75


# ------------------------------------------------------------------ table models


@dataclass(frozen=True)
class TableModel:
    """What recovery needs to know about a table: its stored columns in record order and which one is the rowid alias."""

    name: str
    columns: tuple[ColumnDef, ...]
    alias_index: int | None

    @property
    def width(self) -> int:
        return len(self.columns)

    @property
    def scannable(self) -> bool:
        """Only models with enough columns to be recognised by structure alone are searched for in free space."""
        return self.width >= MIN_SCAN_WIDTH

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.columns)

    @classmethod
    def from_sql(cls, table: TableSql) -> TableModel | None:
        """None for tables recovery does not attempt: virtual, WITHOUT ROWID (index-format cells) and column-less."""
        if table.virtual or table.without_rowid or not table.stored_columns or table.name.lower().startswith("sqlite_"):
            return None
        stored = table.stored_columns
        alias = next((i for i, c in enumerate(stored) if c.is_rowid_alias), None)
        return cls(table.name, stored, alias)


# ------------------------------------------------------------------ candidates


@dataclass
class Candidate:
    """A byte sequence that parses as a record of ``table``. Offsets are within the page image it was found in."""

    table: str
    kind: str  # "full" | "clobbered"
    offset: int
    length: int
    rowid: int | None
    values: list[Any]  # one per stored column; UNKNOWN where the bytes do not determine it
    fit: float
    issues: list[str] = field(default_factory=list)
    corrupted: bool = False
    from_pointer_array: bool = False
    cell_index: int | None = None

    @property
    def end(self) -> int:
        return self.offset + self.length

    def unknown_columns(self, model: TableModel) -> list[str]:
        return [c.name for c, v in zip(model.columns, self.values) if v is UNKNOWN]


def _affinity_score(column: ColumnDef, serial_type: int) -> float:
    cls = serial_type_class(serial_type)
    aff = column.affinity.value
    if cls == "null":
        return _STRONG
    if aff == "BLOB":
        return _STRONG
    if aff == "INTEGER" or aff == "NUMERIC":
        return _STRONG if cls in ("integer", "real") and (aff == "NUMERIC" or cls == "integer") else (_WEAK if cls in ("real", "text") else 0.0)
    if aff == "REAL":
        return _STRONG if cls in ("real", "integer") else (_WEAK if cls == "text" else 0.0)
    if aff == "TEXT":
        return _STRONG if cls == "text" else (_WEAK if cls in ("integer", "real") else 0.0)
    return _WEAK


def _fit_and_decode(
    model: TableModel, types: Sequence[int | None], body: memoryview, encoding: str, unknown_body: int = 0
) -> tuple[list[Any], float, list[str], bool]:
    """Decode ``body`` under ``types``. A ``None`` type marks a column whose type could not be determined: its value is
    UNKNOWN and its ``unknown_body`` bytes are skipped. Returns (values, fit score, issues, structure-fits-but-a-value-is-invalid)."""
    values: list[Any] = []
    scores: list[float] = []
    issues: list[str] = []
    corrupted = False
    pos = 0
    for col, t in zip(model.columns, types):
        if t is None:
            values.append(UNKNOWN)
            scores.append(_WEAK)
            pos += unknown_body
            continue
        size = serial_type_size(t)
        if col.is_rowid_alias:
            if t != 0:
                return [], 0.0, ["rowid alias column holds a value"], False
            values.append(UNKNOWN)  # filled from the rowid by the caller when it is known
            scores.append(_STRONG)
            continue
        try:
            values.append(decode_value(t, body[pos:pos + size], encoding))
        except RecordError as exc:
            values.append(UNKNOWN)
            issues.append(f"{col.name}: {exc}")
            corrupted = True
        scores.append(_affinity_score(col, t))
        pos += size
    return values, (sum(scores) / len(scores) if scores else 0.0), issues, corrupted


def schema_consistent(model: TableModel, values: Sequence[Any]) -> bool:
    """Could ``values`` be a row of ``model``? A stored NULL in a NOT NULL column cannot occur (SQLite refuses the insert), and a
    record whose every column is NULL says nothing: it is what structure bytes followed by zeros look like, not a row.
    Undetermined columns (UNKNOWN) and the rowid alias (always stored NULL) are not judged."""
    informative = False
    for col, v in zip(model.columns, values):
        if col.is_rowid_alias or v is UNKNOWN:
            continue
        if v is None:
            if col.not_null:
                return False
        else:
            informative = True
    return informative


class CellHeader(NamedTuple):
    """The model-independent part of reading ``[payload size][rowid][record]`` at one offset: where the record lies and its serial types."""

    start: int
    plen: int
    rowid_raw: int
    pos: int  # start of the record (its header-size varint)
    end: int
    header_size: int
    types: list[int]


def cell_header(data: bytes | memoryview, start: int, limit: int) -> CellHeader | None:
    """Parse the cell framing at ``start`` once, whatever table it might belong to. None unless a well-formed record header of
    exactly ``plen`` bytes (header + the bodies its serial types declare) fits before ``limit``.

    Scanning a page tries *every* byte offset against *every* table of the database; a real handset database has dozens of tables
    and most offsets fail on the first varint or two, so doing this once per offset (and only then dispatching on the number of
    columns) instead of once per offset *per table* is what keeps recovery tractable on real evidence."""
    try:
        plen, n1 = read_varint(data, start)
        if plen < 1 or start + n1 + plen > limit:
            return None
        rowid_raw, n2 = read_varint(data, start + n1)
        if n2 > MAX_ROWID_BYTES:
            return None
        pos = start + n1 + n2
        end = pos + plen
        if end > limit:
            return None  # the payload starts after the rowid: check the whole cell against the limit
        header_size, hn = read_varint(data, pos)
        if header_size < 2 or header_size > plen:
            return None
        types: list[int] = []
        p = pos + hn
        stop = pos + header_size
        body = 0
        while p < stop:
            t, tn = read_varint(data, p)
            if p + tn > stop:
                return None
            body += serial_type_size(t)
            types.append(t)
            p += tn
        if header_size + body != plen:
            return None
    except RecordError:
        return None
    return CellHeader(start, plen, rowid_raw, pos, end, header_size, types)


def full_from_header(data: bytes | memoryview, h: CellHeader, model: TableModel, encoding: str) -> Candidate | None:
    """``h`` read as a row of ``model`` (None unless its column count, types and values fit the model)."""
    if len(h.types) != model.width or h.header_size < 1 + model.width:
        return None
    values, fit, issues, corrupted = _fit_and_decode(model, h.types, memoryview(data)[h.pos + h.header_size:h.end], encoding)
    if not values or fit < MIN_FIT or not schema_consistent(model, values):
        return None
    rowid = to_signed64(h.rowid_raw)
    if model.alias_index is not None:
        values[model.alias_index] = rowid
    return Candidate(model.name, "full", h.start, h.end - h.start, rowid, values, fit, issues, corrupted)


def try_full(data: bytes | memoryview, start: int, limit: int, model: TableModel, encoding: str) -> Candidate | None:
    """``[payload size][rowid][record]`` at ``start``, ending no later than ``limit``, and *exactly* filling its payload size."""
    h = cell_header(data, start, limit)
    return None if h is None else full_from_header(data, h, model, encoding)


def _end_ok(data: bytes | memoryview, at: int, block_end: int, boundaries: frozenset[int], models: Sequence[TableModel], encoding: str) -> bool:
    """Can a freed cell end at ``at`` inside a freeblock that ends at ``block_end``? Yes if that is the block's end, an interior
    freeblock-header boundary (SQLite leaves one at every cell boundary of a merged block), or the start of an untouched cell."""
    if at == block_end or at in boundaries:
        return True
    if at > block_end:
        return False
    if block_end - at < MIN_CELL:
        return True  # fewer than 4 bytes left: no cell fits, so they are fragment bytes SQLite folded into the freeblock
    h = cell_header(data, at, block_end)
    return h is not None and any(full_from_header(data, h, m, encoding) is not None for m in models)


def try_clobbered(
    data: bytes | memoryview, start: int, block_end: int, boundaries: frozenset[int], model: TableModel, encoding: str,
    models: Sequence[TableModel] | None = None,
) -> Candidate | None:
    """A freed cell whose first four bytes (``start .. start+4``) were overwritten by a freeblock header. ``block_end`` is where
    its freeblock ends and ``boundaries`` the interior header offsets of a merged block, so the cell ends at one of those (or at
    the start of an untouched cell). Tries each layout of the lost prefix and returns the best consistent reading, or None."""
    models = models or [model]
    if block_end - start < 8 or block_end > len(data):
        return None
    surv = bytes(data[start + 4:block_end])
    width = model.width
    ends = sorted({block_end, *(b for b in boundaries if start + 8 <= b <= block_end)})
    best: Candidate | None = None
    for h0 in range(2, MAX_LOST_PREFIX):  # the record header begins h0 bytes into the cell: payload-size varint + rowid varint
        lost_types = max(0, 3 - h0)  # serial-type bytes overwritten: only h0 == 2 loses one (with the header-size byte)
        types_idx = max(0, h0 - 3)  # index into ``surv`` where the surviving serial types begin
        need = width - lost_types
        if need < 1:
            continue
        try:
            types: list[int | None] = [None] * lost_types
            p = types_idx
            for _ in range(need):
                t, tn = read_varint(surv, p)
                serial_type_size(t)
                types.append(t)
                p += tn
        except RecordError:
            continue
        type_bytes = p - types_idx
        known_body = sum(serial_type_size(t) for t in types if t is not None)
        header_size = 1 + lost_types + type_bytes
        if h0 >= 4 and surv[h0 - 4] != header_size:  # the header-size byte survived: it must agree with what follows
            continue
        base = h0 + 1 + lost_types + type_bytes + known_body  # cell bytes accounted for, without the lost column's own body
        body = memoryview(surv)[types_idx + type_bytes:]
        # candidate (cell end, size of the lost first column's body)
        options: list[tuple[int, int]] = []
        if not lost_types:
            options = [(base, 0)]
        elif model.alias_index == 0:
            options = [(base, 0)]  # a rowid alias is stored as NULL: no body
        else:
            options = [(t - start, t - start - base) for t in ends if t - start >= base]
        viable = []
        for length, d0 in options:
            if not _end_ok(data, start + length, block_end, frozenset(boundaries), models, encoding):
                continue
            plen = header_size + known_body + d0
            rowid_len = h0 - varint_length(plen)
            if not 1 <= rowid_len <= MAX_ROWID_BYTES:
                continue
            viable.append((length, d0))
        if lost_types and model.alias_index != 0:
            if len(viable) != 1:
                continue  # the first column's size is not determined unambiguously: do not guess
        for length, d0 in viable[:1]:
            inferred = None
            if lost_types:
                if model.alias_index == 0:
                    types[0] = 0
                else:
                    types[0] = _infer_first_type(model.columns[0], d0)
                    if types[0] is not None:
                        inferred = f"{model.columns[0].name}: type inferred from its length ({d0} bytes) and declared affinity"
            values, fit, issues, corrupted = _fit_and_decode(model, types, body, encoding, d0)
            if not values or fit < MIN_FIT or not schema_consistent(model, values):
                continue
            if inferred:
                issues.append(inferred)
            if model.alias_index is not None:
                values[model.alias_index] = UNKNOWN
            exact = start + length == block_end
            cand = Candidate(model.name, "clobbered", start, length, None, values, fit - (0.0 if exact else 0.001), issues, corrupted)
            if best is None or (cand.fit, cand.length) > (best.fit, best.length):
                best = cand
    return best


def _infer_first_type(column: ColumnDef, size: int) -> int | None:
    """The serial type of a lost first column, from how many body bytes it must occupy and its declared affinity.

    Only unambiguous cases are inferred: an INTEGER / NUMERIC column of 1, 2, 3, 4 or 6 bytes is an integer (floats are always
    8 bytes); a TEXT column is text; a column *declared* BLOB is a blob. Zero bytes (NULL, 0 or 1), 8 bytes (int64 or float)
    and an untyped column could each be several things, so the value stays UNKNOWN rather than being guessed."""
    aff = column.affinity.value
    if size == 0:
        return None
    if aff in ("INTEGER", "NUMERIC") and size in (1, 2, 3, 4, 6):
        return {1: 1, 2: 2, 3: 3, 4: 4, 6: 5}[size]
    if aff == "TEXT":
        return 13 + 2 * size
    if aff == "BLOB" and "BLOB" in column.declared_type.upper():
        return 12 + 2 * size
    return None


# ------------------------------------------------------------------ scanning a page image


def scan_page(
    number: int, data: bytes, models: Sequence[TableModel], encoding: str, *, owner_hint: str | None = None, usable_size: int | None = None
) -> tuple[list[Candidate], BTreePage | None]:
    kept, page, _ = scan_page_detailed(number, data, models, encoding, owner_hint=owner_hint, usable_size=usable_size)
    return kept, page


def scan_page_detailed(
    number: int, data: bytes, models: Sequence[TableModel], encoding: str, *, owner_hint: str | None = None, usable_size: int | None = None
) -> tuple[list[Candidate], BTreePage | None, list[tuple[int, int]]]:
    """Find every record-shaped byte sequence in one page image: the cells of its pointer array (if it is a b-tree page) and
    whatever the free space holds. Returns non-overlapping candidates, best fit first at any overlap."""
    page: BTreePage | None
    try:
        page = parse_btree_page(number, data)
    except PageError:
        page = None
    candidates: list[Candidate] = []
    live: list[tuple[int, int]] = []
    heads: dict[int, tuple[int, frozenset[int]]] = {}  # freeblock-header offset -> (end of its freeblock, interior boundaries)
    scan_from = 0
    if page is not None and page.type.name in ("TABLE_LEAF", "TABLE_INTERIOR"):
        scan_from = page.pointer_array_end
        for f in page.freeblocks:
            # Freeing cells one after another merges them into one freeblock but leaves each earlier freeblock header in place,
            # at the boundary between two cells; its size field is exactly the distance from there to the end of the block.
            interior = frozenset(s for s in range(f.offset + 4, f.end - 7) if struct.unpack_from(">H", data, s + 2)[0] == f.end - s)
            for h in {f.offset, *interior}:
                heads[h] = (f.end, interior)
        if page.type.name == "TABLE_LEAF":
            candidates += _pointer_array_cells(page, models, encoding, owner_hint)
        live = live_extents(page, usable_size or len(data))
    elif page is not None:
        return [], page, []  # index pages hold index cells, which this engine does not read
    limit = len(data)
    ordered = _models_for(models, owner_hint)
    scan_models = [m for m in ordered if m.scannable]
    by_width: dict[int, list[TableModel]] = {}
    for m in scan_models:
        by_width.setdefault(m.width, []).append(m)
    covered = bytearray(limit)
    for a, b in live:
        covered[a:b] = b"\x01" * (b - a)  # bytes that belong to a live cell are not free space
    for s in range(max(scan_from, 0), limit - MIN_CELL):
        if covered[s]:
            continue
        if data[s] != 0:  # an untouched cell starts with its payload size, which is never 0
            hdr = cell_header(data, s, limit)
            if hdr is not None:
                for model in by_width.get(len(hdr.types), ()):  # same models, same order as before: only those with this column count can fit
                    c = full_from_header(data, hdr, model, encoding)
                    if c is not None:
                        candidates.append(c)
        head = heads.get(s)
        if head is None and s + 8 <= limit:
            # A stale freeblock header: when a freed cell borders the unallocated gap SQLite drops it from the chain but leaves its
            # ``[next:2][size:2]`` bytes behind, and ``size`` is then exactly the cell's length.
            nxt, size = struct.unpack_from(">HH", data, s)
            if MIN_CELL * 2 <= size <= limit - s and (nxt == 0 or s + MIN_CELL <= nxt < limit):
                end = s + size  # the cells stacked below it leave stale headers of their own, each ``size == end - here``
                head = (end, frozenset(b for b in range(s + 4, end - 7) if struct.unpack_from(">H", data, b + 2)[0] == end - b))
        if head:
            block_end, interior = head
            for model in scan_models:
                c = try_clobbered(data, s, block_end, interior, model, encoding, scan_models)
                if c is not None:
                    candidates.append(c)
    kept = _non_overlapping([c for c in candidates if c.from_pointer_array or not any(c.offset < b and a < c.end for a, b in live)])
    unparsed = [(f.offset, f.size) for f in (page.freeblocks if page is not None else ()) if f.size >= 8
                and not any(c.offset < f.end and f.offset < c.end for c in kept)]
    return kept, page, unparsed


def live_extents(page: BTreePage, usable_size: int) -> list[tuple[int, int]]:
    """Byte ranges of the page occupied by its live cells (per its own pointer array)."""
    from android_forensics.sqlite.pages import read_cell

    out = []
    for i in range(len(page.cell_offsets)):
        try:
            cell = read_cell(page, i, usable_size)
        except (PageError, RecordError):
            continue
        out.append((cell.offset, min(cell.end, len(page.data))))
    return out


def _models_for(models: Sequence[TableModel], owner: str | None) -> list[TableModel]:
    if owner is None:
        return list(models)
    return sorted(models, key=lambda m: m.name != owner)


def _pointer_array_cells(page: BTreePage, models: Sequence[TableModel], encoding: str, owner: str | None) -> list[Candidate]:
    out = []
    for i, off in enumerate(page.cell_offsets):
        if off >= len(page.data):
            continue
        for model in _models_for(models, owner):
            c = try_full(page.data, off, len(page.data), model, encoding)
            if c is not None:
                c.from_pointer_array = True
                c.cell_index = i
                out.append(c)
                break
    return out


def _non_overlapping(candidates: list[Candidate]) -> list[Candidate]:
    """Greedy: keep the best-fitting candidate wherever several overlap (a full cell beats a clobbered reading of the same bytes)."""
    ranked = sorted(candidates, key=lambda c: (-(c.kind == "full"), -c.fit, -c.length, c.offset))
    kept: list[Candidate] = []
    taken: list[tuple[int, int]] = []
    for c in ranked:
        if any(c.offset < e and s < c.end for s, e in taken):
            continue
        kept.append(c)
        taken.append((c.offset, c.end))
    return sorted(kept, key=lambda c: c.offset)


# ------------------------------------------------------------------ comparing with the active view


class ActiveIndex:
    """The rows of the active view, for telling deleted data from data that is still there."""

    def __init__(self, models: dict[str, TableModel], rows: dict[str, list[tuple]]):
        self._models = models
        self._rows = rows  # table -> list of value tuples in stored-column order (the alias column holds the rowid)
        self._by_positions: dict[tuple[str, tuple[int, ...]], set[tuple]] = {}

    def contains(self, model: TableModel, values: Sequence[Any], rowid: int | None) -> bool:
        """True if an active row carries every value the candidate knows (an UNKNOWN value matches anything)."""
        positions = tuple(i for i, v in enumerate(values) if v is not UNKNOWN and i != model.alias_index)
        if len(positions) < 2:
            return False  # too little known to say "this is that row"
        key = (model.name, positions)
        index = self._by_positions.get(key)
        if index is None:
            index = {tuple(row[i] for i in positions) for row in self._rows.get(model.name, ())}
            self._by_positions[key] = index
        return tuple(values[i] for i in positions) in index


def _normalise(v: Any) -> Any:
    return float(v) if isinstance(v, float) and v.is_integer() else v


# ------------------------------------------------------------------ results


@dataclass
class RecoveredRow:
    """A deleted (or superseded) record, with everything needed to trace it back to bytes."""

    table: str
    values: dict[str, Any]  # column -> value, UNKNOWN where undetermined
    rowid: int | None
    status: ArtifactStatus
    method: ExtractionMethod
    source: str  # "main" | "wal" | "journal"
    source_path: str
    page_number: int
    page_offset: int  # within the page image
    file_offset: int  # absolute, in ``source_path``
    length: int
    raw: bytes
    page_type: str | None
    region: str
    cell_index: int | None
    fit: float
    issues: list[str] = field(default_factory=list)
    unknown_columns: list[str] = field(default_factory=list)
    also_found_at: list[str] = field(default_factory=list)
    frame: int | None = None

    @property
    def location(self) -> str:
        return f"{self.source}:page {self.page_number}@{self.page_offset}"


@dataclass(frozen=True)
class PageImage:
    """One page image to scan, and where it came from."""

    number: int  # the *database* page number it represents
    data: bytes
    source: str  # "main" | "wal" | "journal"
    source_path: str
    file_offset: int  # of the start of ``data`` in ``source_path``
    role: str  # btree | freelist_leaf | freelist_trunk | orphan | historical
    owner: str | None = None
    frame: int | None = None


def _method_and_region(image: PageImage, cand: Candidate, page: BTreePage | None) -> tuple[ExtractionMethod, str, list[str]]:
    notes: list[str] = []
    if image.source == "wal":
        return ExtractionMethod.WAL_FRAME, f"wal_frame_{image.frame}" if image.frame else "wal_frame", notes
    if image.source == "journal":
        return ExtractionMethod.JOURNAL_PAGE, "journal_page", notes
    if image.role in ("freelist_leaf", "freelist_trunk"):
        return ExtractionMethod.FREELIST_PAGE, image.role, notes
    if image.role == "orphan":
        return ExtractionMethod.RAW_PAGE_SCAN, "orphan_page", notes
    if cand.from_pointer_array:
        notes.append("a live cell of the main file that the active view (with the WAL applied) no longer contains")
        return ExtractionMethod.RAW_PAGE_SCAN, "main_page_cell_superseded", notes
    if page is not None and any(f.offset <= cand.offset < f.end for f in page.freeblocks):
        return ExtractionMethod.FREEBLOCK, "freeblock", notes
    return ExtractionMethod.UNALLOCATED_SPACE, "unallocated", notes


def recover_from_images(
    images: Iterable[PageImage], models: Sequence[TableModel], encoding: str, active: ActiveIndex | None = None
) -> tuple[list[RecoveredRow], dict[str, int]]:
    """Scan page images and return de-duplicated recovered rows plus counters (``examined``, ``dropped_active``, ``merged``)."""
    by_name = {m.name: m for m in models}
    found: list[RecoveredRow] = []
    stats = {"pages_examined": 0, "candidates": 0, "dropped_active": 0, "merged": 0}
    for image in images:
        stats["pages_examined"] += 1
        candidates, page = scan_page(image.number, image.data, models, encoding, owner_hint=image.owner)
        for c in candidates:
            stats["candidates"] += 1
            model = by_name[c.table]
            if active is not None and active.contains(model, c.values, c.rowid):
                stats["dropped_active"] += 1
                continue
            method, region, notes = _method_and_region(image, c, page)
            status = ArtifactStatus.CORRUPTED if c.corrupted else (ArtifactStatus.RECOVERED if c.kind == "full" else ArtifactStatus.PARTIAL)
            unknown = c.unknown_columns(model)
            issues = list(c.issues) + notes
            if c.kind == "clobbered":
                issues.append("the first bytes of the cell (payload size, rowid) were overwritten by SQLite's freeblock header: the rowid is unknown")
            raw = image.data[c.offset:c.end]
            found.append(RecoveredRow(
                table=c.table, values={col.name: v for col, v in zip(model.columns, c.values)}, rowid=c.rowid, status=status, method=method,
                source=image.source, source_path=image.source_path, page_number=image.number, page_offset=c.offset,
                file_offset=image.file_offset + c.offset, length=c.length, raw=raw, page_type=page.type.value if page else None,
                region=region, cell_index=c.cell_index, fit=c.fit, issues=issues, unknown_columns=unknown, frame=image.frame,
            ))
    merged = _merge_duplicates(found, {m.name: (m.columns[m.alias_index].name if m.alias_index is not None else None) for m in models})
    stats["merged"] = len(found) - len(merged)
    return merged, stats


_RANK = {ArtifactStatus.RECOVERED: 3, ArtifactStatus.PARTIAL: 2, ArtifactStatus.CORRUPTED: 1}


def _hashable(v: Any) -> Any:
    return ("blob", bytes(v)) if isinstance(v, (bytes, bytearray)) else _normalise(v)


def _subsumes(kept: RecoveredRow, other: RecoveredRow, alias: str | None) -> bool:
    """``other`` is the same record as ``kept`` if every value ``other`` knows (the rowid alias aside) is what ``kept`` holds."""
    if kept.table != other.table:
        return False
    known = [(k, v) for k, v in other.values.items() if v is not UNKNOWN and k != alias]
    if len(known) < 2:
        return False
    return all(kept.values.get(k, UNKNOWN) is not UNKNOWN and _hashable(kept.values[k]) == _hashable(v) for k, v in known)


def _merge_duplicates(rows: list[RecoveredRow], aliases: dict[str, str | None] | None = None) -> list[RecoveredRow]:
    """The same row in several places is one deleted record: keep the most complete instance and list the other locations.
    A partial row merges into a more complete one when everything it knows agrees with it."""
    aliases = aliases or {}
    ordered = sorted(rows, key=lambda r: (-_RANK[r.status], -sum(v is not UNKNOWN for v in r.values.values()), -r.fit,
                                         r.source != "main", r.page_number, r.page_offset))
    kept: list[RecoveredRow] = []
    for r in ordered:
        home = next((k for k in kept if _subsumes(k, r, aliases.get(r.table)) or (k.values == r.values and k.table == r.table)), None)
        if home is None:
            kept.append(r)
            continue
        if r.location not in home.also_found_at:
            home.also_found_at.append(r.location)
        if r.rowid is not None and home.rowid is None:
            home.also_found_at.append(f"rowid {r.rowid} known from {r.location}")
    return sorted(kept, key=lambda r: (r.table, r.source, r.page_number, r.page_offset))


def field_types_valid(model: TableModel, values: dict[str, Any]) -> list[str]:
    """Phase 4D field validation: every recovered value against its column's declared type. Returns human-readable problems."""
    problems = []
    for col in model.columns:
        v = values.get(col.name, UNKNOWN)
        if v is UNKNOWN or v is None:
            continue
        aff = col.affinity.value
        if aff == "TEXT" and not isinstance(v, str):
            problems.append(f"{col.name}: {type(v).__name__} in a TEXT column")
        elif aff == "INTEGER" and not (isinstance(v, int) and not isinstance(v, bool)):
            problems.append(f"{col.name}: {type(v).__name__} in an INTEGER column")
        elif aff == "REAL" and not isinstance(v, (int, float)):
            problems.append(f"{col.name}: {type(v).__name__} in a REAL column")
        elif aff == "NUMERIC" and not isinstance(v, (int, float)):
            problems.append(f"{col.name}: {type(v).__name__} in a NUMERIC column")
    return problems


# ------------------------------------------------------------------ driving the engine over a database


def build_models(db: SQLiteDatabase) -> list[TableModel]:
    """Table models from the schema text in page 1 (works on databases SQLite will not open)."""
    models = []
    for row in db.schema():
        table = row.table_sql()
        if table is None or row.root_page <= 0:
            continue
        model = TableModel.from_sql(table)
        if model is not None:
            models.append(model)
    return models


def main_file_images(db: SQLiteDatabase) -> Iterable[PageImage]:
    """Every page of the main file that can hold record remnants, with its role."""
    roles = db.page_map()
    for n in range(1, db.file_page_count + 1):
        info = roles[n]
        if info.role in (PageRole.OVERFLOW, PageRole.POINTER_MAP, PageRole.LOCK_BYTE):
            continue
        role = {PageRole.BTREE: "btree", PageRole.FREELIST_LEAF: "freelist_leaf", PageRole.FREELIST_TRUNK: "freelist_trunk",
                PageRole.ORPHAN: "orphan"}[info.role]
        data = db.read_page(n)
        if role == "freelist_trunk":
            data = _blank_trunk_header(data)
        yield PageImage(n, data, "main", str(db.path), (n - 1) * db.page_size, role, info.owner if role == "btree" else None)


def _blank_trunk_header(data: bytes) -> bytes:
    """A trunk page's first ``8 + 4L`` bytes are freelist bookkeeping, not record remnants: zero them so they are not scanned."""
    leaf_count = struct.unpack_from(">I", data, 4)[0]
    cut = min(len(data), 8 + 4 * leaf_count)
    return bytes(cut) + data[cut:]


def active_index_from_rows(models: Sequence[TableModel], rows_by_table: dict[str, list[dict[str, Any]]]) -> ActiveIndex:
    by_name = {m.name: m for m in models}
    rows: dict[str, list[tuple]] = {}
    for name, dict_rows in rows_by_table.items():
        m = by_name.get(name)
        if m is None:
            continue
        rows[name] = [tuple(_normalise(r.get(c.name)) for c in m.columns) for r in dict_rows]
    return ActiveIndex(by_name, rows)


def active_index_from_sqlite(path, sidecars: dict[str, Any] | None, models: Sequence[TableModel], scratch) -> ActiveIndex:
    """The active view exactly as SQLite presents it (the WAL applied, a hot journal rolled back), read on a scratch copy."""
    from pathlib import Path

    from android_forensics.sqlite.reader import SQLiteSession

    rows: dict[str, list[dict[str, Any]]] = {}
    with SQLiteSession(Path(path), {k: Path(v) for k, v in (sidecars or {}).items()}, Path(scratch)) as session:
        for m in models:
            try:
                rows[m.name] = [raw for _rowid, raw in session.iter_rows(m.name)]
            except Exception:  # a table SQLite cannot read contributes no active rows: everything found is then reported
                rows[m.name] = []
    return active_index_from_rows(models, rows)


# ------------------------------------------------------------------ evidence that a record existed but its content is gone


@dataclass
class UnrecoveredRegion:
    """Freed space that proves a record (or a page of them) was released, but whose bytes hold no recoverable record."""

    page_number: int
    page_offset: int
    file_offset: int
    length: int
    source: str
    source_path: str
    reason: str  # "zero-filled" | "no record structure fits"
    raw: bytes
    region: str
    frame: int | None = None


def _unrecovered(image: PageImage, offset: int, length: int, region: str) -> UnrecoveredRegion:
    raw = image.data[offset:offset + length]
    reason = "zero-filled: the content was erased (secure_delete, or overwritten with zeros)" if not any(raw[4:] if region == "freeblock" else raw) \
        else "the bytes are not a record of any known table (partly overwritten, or another structure)"
    return UnrecoveredRegion(image.number, offset, image.file_offset + offset, length, image.source, image.source_path, reason, raw, region, image.frame)


def recover_all(
    images: Iterable[PageImage], models: Sequence[TableModel], encoding: str, active: ActiveIndex | None = None
) -> tuple[list[RecoveredRow], list[UnrecoveredRegion], dict[str, int]]:
    """``recover_from_images`` plus the regions where a release left nothing to recover."""
    images = list(images)
    rows, stats = recover_from_images(images, models, encoding, active)
    unrecovered: list[UnrecoveredRegion] = []
    for image in images:
        candidates, page, unparsed = scan_page_detailed(image.number, image.data, models, encoding, owner_hint=image.owner)
        for offset, size in unparsed:
            unrecovered.append(_unrecovered(image, offset, size, "freeblock"))
        if image.role in ("freelist_leaf", "orphan") and not candidates and (page is None or page.type.name.startswith("TABLE")):
            if any(image.data) or image.role == "freelist_leaf":
                unrecovered.append(_unrecovered(image, 0, len(image.data), image.role))
    stats["unrecovered_regions"] = len(unrecovered)
    return rows, unrecovered, stats
