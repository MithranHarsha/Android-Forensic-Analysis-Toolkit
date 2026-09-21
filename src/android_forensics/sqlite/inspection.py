"""Typed results of *normal* SQLite inspection: what a database contains as SQLite itself presents it.

This is the "active view" — the tables, columns, indexes and rows a query returns, with the header, sidecar and engine
facts that give them context. Nothing here is recovered data: rows that were deleted are simply absent (Review 2 reads
the bytes that remain). The models live beside ``header`` and ``sidecars`` because they embed those facts.

Everything is immutable and validated, round-trips through JSON without loss, and keeps what a bare ``SELECT *`` would
throw away: the database path and hash, the schema text as stored, declared type *and* actual storage class of every
value, rowids, and the header / version / sidecar / engine metadata of the file.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterator, Literal, Self, Sequence, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

from android_forensics.models.discovery import Sidecar
from android_forensics.models.enums import OpenStatus, SqliteStatus, StorageClass, TableKind, TypeAffinity
from android_forensics.models.types import HexBytes, NonBlankStr, Sha256Hex, UtcIso
from android_forensics.sqlite.header import SQLiteHeader
from android_forensics.sqlite.sidecars import JournalFacts, ShmFacts, WalFacts

BLOB_HEAD_BYTES = 32  # bytes of a BLOB always kept in ``hex_head`` (same convention as the artifact raw references)

_FROZEN = ConfigDict(extra="forbid", frozen=True)


# ------------------------------------------------------------------ values


class BlobValue(BaseModel):
    """A BLOB cell: its length and SHA-256 always, its first bytes always, its complete bytes when small enough to inline.

    The digest binds the summary to the original bytes, so a large value that is not inlined can still be checked
    against the evidence file later."""

    model_config = _FROZEN

    kind: Literal["blob"] = "blob"
    length: int = Field(ge=0)
    sha256: Sha256Hex
    hex_head: HexBytes
    hex: HexBytes | None = None  # the complete value (present when it fits the inline limit)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(self.hex_head) // 2 != min(self.length, BLOB_HEAD_BYTES):
            raise ValueError("hex_head must hold the first min(length, 32) bytes")
        if self.hex is not None:
            if len(self.hex) != 2 * self.length:
                raise ValueError("inline hex does not match the declared length")
            if not self.hex.startswith(self.hex_head):
                raise ValueError("hex_head is not the start of the inline value")
            if hashlib.sha256(bytes.fromhex(self.hex)).hexdigest() != self.sha256:
                raise ValueError("inline value does not match its SHA-256")
        return self

    @property
    def data(self) -> bytes | None:
        return bytes.fromhex(self.hex) if self.hex is not None else None


class SpecialFloat(BaseModel):
    """A REAL that JSON cannot carry: SQLite stores +Inf and -Inf (NaN it converts to NULL). Never silently altered."""

    model_config = _FROZEN

    kind: Literal["float"] = "float"
    value: Literal["inf", "-inf", "nan"]


RecordValue = Union[None, int, float, str, BlobValue, SpecialFloat]


def storage_class_of(value: RecordValue) -> StorageClass:
    if value is None:
        return StorageClass.NULL
    if isinstance(value, BlobValue):
        return StorageClass.BLOB
    if isinstance(value, (float, SpecialFloat)):
        return StorageClass.REAL
    if isinstance(value, int):
        return StorageClass.INTEGER
    return StorageClass.TEXT


class ActiveRecord(BaseModel):
    """One row as the normal view returns it. ``state`` is always ``ACTIVE``: recovered rows are a Review 2 type."""

    model_config = _FROZEN

    state: Literal["ACTIVE"] = "ACTIVE"
    table: str
    rowid: int | None  # None: WITHOUT ROWID table (its identity is its primary key) or a rowid no name can reach
    ordinal: int = Field(ge=0)  # 0-based position in this enumeration (rowid order for rowid tables)
    values: list[RecordValue]  # aligned with the table's ``data_columns``; every value exactly as stored, never coerced
    undecodable_text: dict[str, HexBytes] = Field(default_factory=dict)  # column → the original bytes of TEXT that is not valid UTF-8

    @property
    def storage_classes(self) -> list[StorageClass]:
        return [storage_class_of(v) for v in self.values]

    def as_dict(self, columns: Sequence[str]) -> dict[str, RecordValue]:
        if len(columns) != len(self.values):
            raise ValueError(f"{len(columns)} column names for {len(self.values)} values")
        return dict(zip(columns, self.values))


# ------------------------------------------------------------------ schema


class ColumnSchema(BaseModel):
    """One column as ``PRAGMA table_xinfo`` reports it, plus what follows from it."""

    model_config = _FROZEN

    cid: int
    name: str
    declared_type: str  # verbatim; "" when the column declares none
    affinity: TypeAffinity  # derived from the declared type — the type a *value* has is its storage class
    not_null: bool
    default: str | None = None  # the DEFAULT expression as SQL text
    primary_key_position: int = Field(ge=0)  # 0: not in the primary key; 1..n: position within it
    hidden: int = Field(ge=0, le=3)  # 0 normal · 1 hidden virtual-table column · 2 generated (virtual) · 3 generated (stored)
    is_rowid_alias: bool = False  # INTEGER PRIMARY KEY: the column *is* the rowid

    @property
    def is_primary_key(self) -> bool:
        return self.primary_key_position > 0

    @property
    def is_generated(self) -> bool:
        return self.hidden in (2, 3)


class IndexColumn(BaseModel):
    model_config = _FROZEN

    position: int = Field(ge=0)
    cid: int  # column id in the table; -1: the rowid; -2: an expression
    name: str | None  # None for expressions
    descending: bool = False
    collation: str | None = None


class IndexSchema(BaseModel):
    model_config = _FROZEN

    name: str
    table: str
    unique: bool
    origin: str  # "c": CREATE INDEX · "u": UNIQUE constraint · "pk": PRIMARY KEY constraint
    partial: bool
    columns: list[IndexColumn]  # key columns only
    sql: str | None = None  # None for indexes SQLite creates for constraints
    root_page: int | None = None  # None where the table's own b-tree is the index (WITHOUT ROWID primary key)


class ForeignKey(BaseModel):
    model_config = _FROZEN

    id: int
    referenced_table: str
    columns: list[str]
    referenced_columns: list[str | None]  # None: the referenced table's primary key
    on_update: str
    on_delete: str
    match: str


class TableInspection(BaseModel):
    """A table: its complete schema, its row count, and (when requested) its active records."""

    model_config = _FROZEN

    name: str
    kind: TableKind
    internal: bool  # SQLite housekeeping (``sqlite_sequence``, ``sqlite_stat1`` …)
    sql: str | None = None  # the CREATE statement exactly as stored
    root_page: int | None = None
    without_rowid: bool = False
    strict: bool = False
    autoincrement: bool = False
    columns: list[ColumnSchema] = Field(default_factory=list)
    primary_key: list[str] = Field(default_factory=list)  # in key order; empty when the table has none
    rowid_alias: str | None = None
    indexes: list[IndexSchema] = Field(default_factory=list)
    foreign_keys: list[ForeignKey] = Field(default_factory=list)
    row_count: int | None = None  # COUNT(*) over the active view; None if it could not be counted
    records: list[ActiveRecord] = Field(default_factory=list)
    records_truncated: bool = False  # a per-table cap (or a read error) left rows out of ``records``
    read_error: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        names = [c.name for c in self.columns]
        pk = [c.name for c in sorted((c for c in self.columns if c.primary_key_position), key=lambda c: c.primary_key_position)]
        if self.primary_key != pk:
            raise ValueError(f"primary_key {self.primary_key} disagrees with the columns' key positions {pk}")
        if self.rowid_alias is not None:
            if self.without_rowid:
                raise ValueError("a WITHOUT ROWID table has no rowid alias")
            if self.rowid_alias not in names:
                raise ValueError("rowid_alias must name a column")
        width = len(self.data_columns)
        for r in self.records:
            if len(r.values) != width:
                raise ValueError(f"record {r.ordinal} has {len(r.values)} values for {width} columns")
        return self

    @property
    def data_columns(self) -> list[str]:
        """The columns a row holds (``*``): hidden virtual-table columns are not part of a row."""
        return [c.name for c in self.columns if c.hidden != 1]

    @property
    def records_read(self) -> int:
        return len(self.records)

    def record_dicts(self) -> list[dict[str, RecordValue]]:
        cols = self.data_columns
        return [r.as_dict(cols) for r in self.records]


class SchemaEntry(BaseModel):
    """A row of ``sqlite_master`` verbatim: tables, indexes, views and triggers, in creation order."""

    model_config = _FROZEN

    rowid: int | None = None
    type: str  # table · index · view · trigger
    name: str
    table: str  # tbl_name
    root_page: int | None = None
    sql: str | None = None


# ------------------------------------------------------------------ metadata


class FileFacts(BaseModel):
    model_config = _FROZEN

    path: NonBlankStr  # absolute, as inspected
    name: NonBlankStr
    size: int = Field(ge=0)
    sha256: Sha256Hex | None = None  # of the exact bytes SQLite was given (or of the file, if it was never opened)
    mtime: UtcIso | None = None  # file-system modification time


class SizeCheck(BaseModel):
    model_config = _FROZEN

    actual_size: int = Field(ge=0)
    expected_size: int | None = None  # from the header's page count (when trustworthy) or a whole number of pages
    consistent: bool | None = None


class VersionInfo(BaseModel):
    """Version facts: what the file says about who last wrote it, what format it needs, and what read it now."""

    model_config = _FROZEN

    last_writer_version_number: int | None = None  # header bytes 96-99 (SQLITE_VERSION_NUMBER of the last writer)
    last_writer_version: str | None = None  # e.g. "3.39.4"
    version_valid_for: int | None = None  # header bytes 92-95
    file_change_counter: int | None = None
    last_writer_version_reliable: bool | None = None  # only when version_valid_for == the file change counter
    write_format: str | None = None  # "rollback journal" | "WAL"
    read_format: str | None = None
    schema_format: int | None = None
    schema_format_min_version: str | None = None  # oldest SQLite that can read this schema format
    inspecting_library_version: str  # the SQLite library that opened the scratch copy
    notes: list[str] = Field(default_factory=list)


class InspectedSidecar(Sidecar):
    """A WAL / SHM / journal file next to the database, with what its header says and whether it shaped the active view."""

    wal: WalFacts | None = None
    shm: ShmFacts | None = None
    journal: JournalFacts | None = None
    applied: bool = False  # copied into the scratch session, so SQLite saw it


class IntegrityResult(BaseModel):
    """``PRAGMA integrity_check`` on the working copy.

    ``ok`` · ``failed`` (includes a check SQLite had to abort on a malformed file) · ``not_run`` · ``partial``: the b-tree
    structure verified (``quick_check``) but the index-to-table comparison cannot be trusted because an index orders its keys
    with an Android collation this tool can only approximate — never reported as ``ok``, and never as a failure."""

    model_config = _FROZEN

    status: Literal["ok", "partial", "failed", "not_run"]
    messages: list[str] = Field(default_factory=list)  # what SQLite reported
    caveats: list[str] = Field(default_factory=list)  # why a result is only partial


class EngineInfo(BaseModel):
    """What SQLite itself did with the scratch copy — separate from what the bytes say."""

    model_config = _FROZEN

    open_status: OpenStatus
    open_error: str | None = None
    sqlite_library_version: str
    view_includes_wal: bool | None = None  # committed WAL frames are part of the rows below
    wal_frames_valid: int | None = Field(default=None, ge=0)  # frames SQLite validated when it opened the working copy (None: no wal-index)
    applied_sidecars: list[str] = Field(default_factory=list)  # "wal" / "shm" / "journal"
    pragmas: dict[str, int | str | None] = Field(default_factory=dict)  # as the engine reports them
    decode_errors: int = Field(default=0, ge=0)  # TEXT values that were not valid UTF-8
    notes: list[str] = Field(default_factory=list)


class InspectionIssue(BaseModel):
    """A problem met while inspecting; the inspection carries on and reports what it could."""

    model_config = _FROZEN

    kind: NonBlankStr
    detail: str = ""
    table: str | None = None


class DatabaseInspection(BaseModel):
    """Everything normal inspection can say about one SQLite database."""

    model_config = _FROZEN

    inspected_at: UtcIso
    tool_version: NonBlankStr
    file: FileFacts
    status: SqliteStatus
    status_detail: str = ""
    header: SQLiteHeader
    size: SizeCheck
    version: VersionInfo
    sidecars: list[InspectedSidecar] = Field(default_factory=list)
    engine: EngineInfo
    integrity: IntegrityResult
    schema_entries: list[SchemaEntry] = Field(default_factory=list)
    tables: list[TableInspection] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    issues: list[InspectionIssue] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        names = [t.name for t in self.tables]
        if len(set(names)) != len(names):
            raise ValueError("duplicate table names")
        if len({s.kind for s in self.sidecars}) != len(self.sidecars):
            raise ValueError("at most one sidecar per kind")
        if self.engine.open_status is not OpenStatus.OK and (self.tables or self.schema_entries):
            raise ValueError("a database SQLite did not open has no schema or tables to report")
        declared = {e.name for e in self.schema_entries if e.type == "table"}
        if self.engine.open_status is OpenStatus.OK and declared != set(names):
            raise ValueError("tables must match the table entries of the schema")
        return self

    # ---- convenience
    @property
    def path(self) -> str:
        return self.file.path

    @property
    def is_readable_by_sqlite(self) -> bool:
        return self.engine.open_status is OpenStatus.OK

    @property
    def views(self) -> list[SchemaEntry]:
        return [e for e in self.schema_entries if e.type == "view"]

    @property
    def triggers(self) -> list[SchemaEntry]:
        return [e for e in self.schema_entries if e.type == "trigger"]

    @property
    def indexes(self) -> list[IndexSchema]:
        return [i for t in self.tables for i in t.indexes]

    @property
    def record_count(self) -> int:
        """Active records included in this result (not the same as the tables' row counts when a cap applied)."""
        return sum(len(t.records) for t in self.tables)

    def table(self, name: str) -> TableInspection | None:
        return next((t for t in self.tables if t.name == name), None)

    def sidecar(self, kind: str) -> InspectedSidecar | None:
        return next((s for s in self.sidecars if s.kind.value == kind), None)

    def iter_records(self) -> Iterator[dict[str, Any]]:
        """Records with their full provenance — database, table, rowid, ordinal — ready for JSON-lines export."""
        for t in self.tables:
            cols = t.data_columns
            for r in t.records:
                yield {
                    "database": self.path, "sha256": self.file.sha256, "table": t.name, "rowid": r.rowid,
                    "ordinal": r.ordinal, "state": r.state, "values": r.as_dict(cols),
                }


# ------------------------------------------------------------------ pure helpers


def affinity_of(declared_type: str | None) -> TypeAffinity:
    """SQLite's five rules for column affinity, applied in order (https://www.sqlite.org/datatype3.html#determination_of_column_affinity)."""
    t = (declared_type or "").upper()
    if "INT" in t:
        return TypeAffinity.INTEGER
    if "CHAR" in t or "CLOB" in t or "TEXT" in t:
        return TypeAffinity.TEXT
    if "BLOB" in t or not t.strip():
        return TypeAffinity.BLOB
    if "REAL" in t or "FLOA" in t or "DOUB" in t:
        return TypeAffinity.REAL
    return TypeAffinity.NUMERIC


def decode_version_number(number: int) -> str:
    """``3039004`` → ``"3.39.4"`` (SQLITE_VERSION_NUMBER = major·10⁶ + minor·10³ + release)."""
    return f"{number // 1_000_000}.{(number // 1000) % 1000}.{number % 1000}"


# Oldest SQLite that reads each schema format number (https://www.sqlite.org/fileformat2.html#schema_format_number).
SCHEMA_FORMAT_MIN_VERSION = {1: "3.0.0", 2: "3.1.3", 3: "3.1.4", 4: "3.3.0"}
_FORMAT_NAMES = {1: "rollback journal", 2: "WAL"}


def version_info(header: SQLiteHeader, library_version: str) -> VersionInfo:
    """Version facts from the header alone (works on files SQLite cannot open)."""
    notes: list[str] = []
    number = header.sqlite_version_number if header.valid else None
    reliable = None
    if number is not None:
        reliable = header.version_valid_for == header.file_change_counter
        if number == 0:
            notes.append("the last writer recorded no version number (written by SQLite older than 3.7.0, or never stamped)")
            number, reliable = None, None
        elif not reliable:
            notes.append(
                "version-valid-for differs from the change counter: the file was modified since the version number was "
                "stored (normal for WAL-mode databases between checkpoints), so it may not name the latest writer"
            )
    write, read = header.write_version, header.read_version
    return VersionInfo(
        last_writer_version_number=number,
        last_writer_version=decode_version_number(number) if number else None,
        version_valid_for=header.version_valid_for,
        file_change_counter=header.file_change_counter,
        last_writer_version_reliable=reliable,
        write_format=None if write is None else _FORMAT_NAMES.get(write, f"unknown ({write})"),
        read_format=None if read is None else _FORMAT_NAMES.get(read, f"unknown ({read})"),
        schema_format=header.schema_format,
        schema_format_min_version=SCHEMA_FORMAT_MIN_VERSION.get(header.schema_format) if header.schema_format else None,
        inspecting_library_version=library_version,
        notes=notes,
    )
