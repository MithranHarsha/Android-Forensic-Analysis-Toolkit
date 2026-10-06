"""``SQLiteDatabase``: a page-level reader that needs nothing from the SQLite library.

It reads the 100-byte header (``header.py``), then the schema from page 1 (the ``sqlite_master`` table b-tree), then any
table by walking its b-tree — interior pages in key order, leaf cells, overflow chains — and decodes every cell with
``records.py``. Because it never asks SQLite to open the file it works on truncated and damaged databases, and because it
sees pages rather than rows it is the foundation of the recovery engine (``recovery.py``): the same reader that yields the
live rows also knows which pages are live, free, overflow or orphaned.

Rows come out with their physical location (page, cell index, byte offset in the file) and the raw cell bytes.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from android_forensics.readonly import open_readonly
from android_forensics.sqlite.ddl import DdlError, TableSql, parse_create_table
from android_forensics.sqlite.freelist import FreelistInfo, walk_freelist
from android_forensics.sqlite.header import HEADER_SIZE, SQLiteHeader, parse_header
from android_forensics.sqlite.pages import (
    BTreePage,
    Cell,
    FilePageSource,
    PageError,
    PageType,
    parse_btree_page,
    read_cell,
    read_cell_payload,
)
from android_forensics.sqlite.records import RecordError, parse_record

MAX_DEPTH = 64


@dataclass(frozen=True)
class SchemaRow:
    """A row of ``sqlite_master``, decoded from page 1."""

    rowid: int
    type: str
    name: str
    tbl_name: str
    root_page: int
    sql: str | None

    def table_sql(self) -> TableSql | None:
        if self.type != "table" or not self.sql:
            return None
        try:
            return parse_create_table(self.sql)
        except DdlError:
            return None


@dataclass(frozen=True)
class LiveRow:
    """A row present in a table's b-tree, with where its cell sits."""

    table: str
    rowid: int | None  # None for WITHOUT ROWID tables
    stored: tuple[Any, ...]  # the record's values in stored order (a rowid alias is NULL here)
    serial_types: tuple[int, ...]
    page: int
    cell_index: int
    file_offset: int  # absolute offset of the cell in the file
    raw: bytes  # the cell's bytes on its page (overflow pages excluded)


class PageRole:
    """Why a page is where it is."""

    BTREE = "btree"  # reachable from a root (owner in ``PageInfo.owner``)
    OVERFLOW = "overflow"
    FREELIST_TRUNK = "freelist_trunk"
    FREELIST_LEAF = "freelist_leaf"
    POINTER_MAP = "pointer_map"
    LOCK_BYTE = "lock_byte"
    ORPHAN = "orphan"  # not reachable from anything: released b-tree pages whose bytes remain


@dataclass(frozen=True)
class PageInfo:
    number: int
    role: str
    owner: str | None = None
    page_type: PageType | None = None


@dataclass
class SQLiteDatabase:
    path: Path
    header: SQLiteHeader
    source: FilePageSource
    problems: list[str] = field(default_factory=list)
    _schema: list[SchemaRow] | None = field(default=None, repr=False)

    # ------------------------------------------------------------------ opening
    @classmethod
    def open(cls, path: str | Path) -> SQLiteDatabase:
        path = Path(path)
        with open_readonly(path) as fh:
            header = parse_header(fh.read(HEADER_SIZE))
        if not header.valid or not header.page_size:
            raise PageError(f"{path.name}: not a database this reader can parse ({'; '.join(header.fatal) or 'no valid header'})")
        return cls(path=path, header=header, source=FilePageSource(path, header.page_size))

    def close(self) -> None:
        self.source.close()

    def __enter__(self) -> SQLiteDatabase:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ geometry
    @property
    def page_size(self) -> int:
        return self.header.page_size or 0

    @property
    def usable_size(self) -> int:
        return self.page_size - (self.header.reserved_bytes or 0)

    @property
    def encoding(self) -> str:
        return self.header.text_encoding or "UTF-8"

    @property
    def file_page_count(self) -> int:
        return self.source.page_count

    @property
    def page_count(self) -> int:
        """Pages in the database: the header's count when it is trustworthy (version-valid-for equals the change counter),
        otherwise the number of whole pages in the file."""
        h = self.header
        if h.page_count and h.version_valid_for == h.file_change_counter:
            return min(h.page_count, self.file_page_count) if self.file_page_count else h.page_count
        return self.file_page_count

    def read_page(self, number: int) -> bytes:
        return self.source.read_page(number)

    def btree(self, number: int) -> BTreePage:
        return parse_btree_page(number, self.read_page(number))

    # ------------------------------------------------------------------ schema
    def schema(self) -> list[SchemaRow]:
        if self._schema is None:
            rows: list[SchemaRow] = []
            for page, cell in self.walk(1):
                if page.type is not PageType.TABLE_LEAF:
                    continue
                try:
                    rec = parse_record(read_cell_payload(page, cell, self.source, self.usable_size), 0, encoding=self.encoding)
                except (PageError, RecordError) as exc:
                    self.problems.append(f"sqlite_master cell on page {page.number}: {exc}")
                    continue
                v = rec.values + (None,) * (5 - len(rec.values))
                rows.append(SchemaRow(cell.rowid or 0, str(v[0]), str(v[1]), str(v[2]), int(v[3] or 0), v[4] if isinstance(v[4], str) else None))
            self._schema = rows
        return self._schema

    def tables(self) -> dict[str, SchemaRow]:
        """Real (b-tree backed) tables by name."""
        return {r.name: r for r in self.schema() if r.type == "table" and r.root_page > 0}

    # ------------------------------------------------------------------ b-tree traversal
    def walk(self, root: int) -> Iterator[tuple[BTreePage, Cell]]:
        """Every cell of the b-tree at ``root`` in key order (interior index cells are entries too). A damaged or looping
        page is recorded in ``problems`` and skipped; the rest of the tree is still walked."""
        visited: set[int] = set()

        def visit(number: int, depth: int) -> Iterator[tuple[BTreePage, Cell]]:
            if depth > MAX_DEPTH or number in visited or not 1 <= number <= self.file_page_count:
                self.problems.append(f"b-tree walk skipped page {number} (depth {depth}): loop, depth limit or out of range")
                return
            visited.add(number)
            try:
                page = self.btree(number)
            except PageError as exc:
                self.problems.append(str(exc))
                return
            if page.problems:
                self.problems.extend(f"page {number}: {p}" for p in page.problems)
            for i in range(len(page.cell_offsets)):
                try:
                    cell = read_cell(page, i, self.usable_size)
                except (PageError, RecordError) as exc:
                    self.problems.append(f"page {number} cell {i}: {exc}")
                    continue
                if page.type in (PageType.TABLE_INTERIOR, PageType.INDEX_INTERIOR):
                    if cell.left_child:
                        yield from visit(cell.left_child, depth + 1)
                    if page.type is PageType.INDEX_INTERIOR:
                        yield page, cell
                else:
                    yield page, cell
            if page.right_pointer:
                yield from visit(page.right_pointer, depth + 1)

        yield from visit(root, 1)

    def live_rows(self, entry: SchemaRow) -> Iterator[LiveRow]:
        """Decode every row of a table from its b-tree (main file only: WAL frames are not applied here)."""
        for page, cell in self.walk(entry.root_page):
            if page.type not in (PageType.TABLE_LEAF, PageType.INDEX_LEAF, PageType.INDEX_INTERIOR):
                continue
            try:
                payload = read_cell_payload(page, cell, self.source, self.usable_size)
                rec = parse_record(payload, 0, encoding=self.encoding)
            except (PageError, RecordError) as exc:
                self.problems.append(f"{entry.name}: page {page.number} cell {cell.index}: {exc}")
                continue
            offset = (page.number - 1) * self.page_size + cell.offset
            yield LiveRow(entry.name, cell.rowid, rec.values, rec.serial_types, page.number, cell.index, offset,
                          page.data[cell.offset:cell.offset + cell.size])

    # ------------------------------------------------------------------ page inventory
    def freelist(self) -> FreelistInfo:
        h = self.header
        return walk_freelist(self.source, h.first_freelist_trunk or 0, h.freelist_page_count or 0, self.file_page_count, self.usable_size)

    def page_map(self) -> dict[int, PageInfo]:
        """Classify every page of the file: b-tree (with its owner), overflow, freelist trunk/leaf, pointer map, lock byte —
        and, for what remains, *orphans*: b-tree pages nothing points to any more (released, but their bytes remain)."""
        roles: dict[int, PageInfo] = {}
        for row in self.schema():
            if row.root_page <= 0 or row.type not in ("table", "index"):
                continue
            for page, cell in self.walk(row.root_page):
                roles.setdefault(page.number, PageInfo(page.number, PageRole.BTREE, row.name, page.type))
                nxt, seen = cell.overflow_page, set()
                while nxt and nxt not in seen and 1 <= nxt <= self.file_page_count:
                    seen.add(nxt)
                    roles.setdefault(nxt, PageInfo(nxt, PageRole.OVERFLOW, row.name))
                    nxt = int.from_bytes(self.read_page(nxt)[:4], "big")
            # interior pages are visited by ``walk`` but only yield cells for leaves: mark them too
            self._mark_interiors(row, roles)
        roles.setdefault(1, PageInfo(1, PageRole.BTREE, "sqlite_master", PageType.TABLE_LEAF))
        fl = self.freelist()
        for n in fl.trunks:
            roles.setdefault(n, PageInfo(n, PageRole.FREELIST_TRUNK))
        for n in fl.leaves:
            roles.setdefault(n, PageInfo(n, PageRole.FREELIST_LEAF))
        lock = (1 << 30) // self.page_size + 1 if self.page_size else 0
        auto_vacuum = bool(self.header.largest_root_page)
        stride = self.usable_size // 5 + 1
        for n in range(1, self.file_page_count + 1):
            if n in roles:
                continue
            if n == lock and n <= self.file_page_count:
                roles[n] = PageInfo(n, PageRole.LOCK_BYTE)
            elif auto_vacuum and n >= 2 and (n - 2) % stride == 0:
                roles[n] = PageInfo(n, PageRole.POINTER_MAP)
            else:
                roles[n] = PageInfo(n, PageRole.ORPHAN, None, self._btree_type_or_none(n))
        return roles

    def _btree_type_or_none(self, number: int) -> PageType | None:
        try:
            return parse_btree_page(number, self.read_page(number)).type
        except PageError:
            return None

    def _mark_interiors(self, row: SchemaRow, roles: dict[int, PageInfo]) -> None:
        visited: set[int] = set()
        stack = [row.root_page]
        while stack:
            n = stack.pop()
            if n in visited or not 1 <= n <= self.file_page_count:
                continue
            visited.add(n)
            try:
                page = self.btree(n)
            except PageError:
                continue
            roles.setdefault(n, PageInfo(n, PageRole.BTREE, row.name, page.type))
            if not page.type.is_leaf:
                for i in range(len(page.cell_offsets)):
                    try:
                        child = read_cell(page, i, self.usable_size).left_child
                    except (PageError, RecordError):
                        continue
                    if child:
                        stack.append(child)
                if page.right_pointer:
                    stack.append(page.right_pointer)


def logical_row(table: TableSql, row: LiveRow) -> dict[str, Any]:
    """A live row as ``{column: value}`` for the table's *stored* columns, with the rowid alias filled from the rowid and a
    WITHOUT ROWID record (primary-key columns first) put back into declared order."""
    columns = table.stored_columns
    if table.without_rowid:
        pk = [c for c in sorted((c for c in columns if c.primary_key_position), key=lambda c: c.primary_key_position)]
        order = pk + [c for c in columns if not c.primary_key_position]
    else:
        order = list(columns)
    values = dict(zip((c.name for c in order), row.stored))
    for c in order[len(row.stored):]:
        values[c.name] = None  # a record written before ALTER TABLE ADD COLUMN: the column reads as its default (NULL if none)
    alias = table.rowid_alias
    if alias is not None and row.rowid is not None:
        values[alias.name] = row.rowid
    return {c.name: values[c.name] for c in columns}
