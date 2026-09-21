"""``SQLiteInspector`` — normal inspection of one SQLite database, returning structured forensic information.

    from android_forensics.sqlite.inspector import SQLiteInspector

    result = SQLiteInspector.inspect("mmssms.db")            # -> DatabaseInspection
    result.header.page_size, result.version.last_writer_version
    for table in result.tables:                              # schema, primary keys, indexes, row counts …
        for record in table.records:                         # … and every active row with its rowid and storage classes
            ...

"Normal" means the *active view*: the rows a query returns, exactly as SQLite on the phone would present them (main file
plus committed WAL frames, a hot journal rolled back). Rows that were deleted are simply absent — this module does not
look for them; recovering them is Review 2's page-level work.

How the evidence stays untouched: the database and its sidecars are opened through the read-only opener, copied once
into a private scratch directory (hashing the exact bytes as they go), and SQLite only ever opens that copy. Even a
"read-only" SQLite connection can create ``-shm`` files, replay a WAL or roll back a hot journal; those effects land on
the copy, which is deleted afterwards.

A damaged, truncated, encrypted or non-SQLite file is not an error: it is inspected as far as its bytes allow and the
result says how far that was. Only a path that is missing, a directory, or an unsafe scratch location raises
``InspectionError``.
"""

from __future__ import annotations

import hashlib
import math
import re
import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterator, Mapping

from android_forensics import __version__
from android_forensics.acquisition.hashing import sha256_of
from android_forensics.errors import InspectionError
from android_forensics.filesystem.analysis import STATUS_ISSUE, FileObservation, detect_sqlite_status
from android_forensics.filesystem.classifier import ENTROPY_ENCRYPTED_THRESHOLD, Classification, classify, shannon_entropy
from android_forensics.filesystem.sidecars import SIDECAR_SUFFIX
from android_forensics.models.enums import FileKind, OpenStatus, SidecarKind, SqliteStatus, TableKind
from android_forensics.readonly import open_readonly
from android_forensics.sqlite.header import HeaderReport, inspect_database_file, parse_header
from android_forensics.sqlite.inspection import (
    ActiveRecord,
    BlobValue,
    ColumnSchema,
    DatabaseInspection,
    EngineInfo,
    FileFacts,
    ForeignKey,
    IndexColumn,
    IndexSchema,
    InspectedSidecar,
    InspectionIssue,
    IntegrityResult,
    RecordValue,
    SchemaEntry,
    SizeCheck,
    SpecialFloat,
    TableInspection,
    affinity_of,
    version_info,
)
from android_forensics.sqlite.reader import (
    APPROXIMATED_COLLATIONS,
    SQLiteOpenError,
    SQLiteSession,
    UndecodableText,
    q,
    rowid_expression,
)
from android_forensics.sqlite.sidecars import inspect_journal, inspect_shm, inspect_wal
from android_forensics.util import iso_from_epoch, now_iso

__all__ = ["InspectionOptions", "SQLiteInspector", "inspect_database"]

MIN_SQLITE_VERSION = (3, 26, 0)  # PRAGMA table_xinfo (an unknown PRAGMA is silently ignored, which would give empty schemas)
_SUFFIX_TO_KIND = {suffix: kind for kind, suffix in SIDECAR_SUFFIX.items()}
_SUFFIX_NAME = {suffix: kind.value for suffix, kind in _SUFFIX_TO_KIND.items()}
_AUTO_VACUUM = {0: "none", 1: "full", 2: "incremental"}
_NOISE = re.compile(r"""'(?:[^']|'')*'|"(?:[^"]|"")*"|`(?:[^`]|``)*`|\[[^\]]*\]|--[^\n]*|/\*.*?\*/""", re.S)
_VIRTUAL_SQL = re.compile(r"^\s*CREATE\s+VIRTUAL\s+TABLE\b", re.I)
_AUTOINCREMENT = re.compile(r"\bAUTOINCREMENT\b", re.I)


# ------------------------------------------------------------------ options


@dataclass(frozen=True)
class InspectionOptions:
    """How much to read. The defaults give the fullest picture; the caps exist for very large databases."""

    include_records: bool = True  # read the active rows (False: schema, metadata and row counts only)
    max_records_per_table: int | None = None  # cap on rows kept per table (row counts are always exact)
    tables: tuple[str, ...] | None = None  # read records only for these tables (case-insensitive); schema is always complete
    blob_inline_limit: int = 256  # BLOBs up to this many bytes are kept whole; larger ones as length + SHA-256 + head
    apply_sidecars: bool = True  # include the WAL / hot journal in the view (what the phone would show); False: main file only
    integrity_check: bool = True  # run PRAGMA integrity_check on the scratch copy
    hash_files: bool = True  # SHA-256 the database and its sidecars
    sidecars: Mapping[str, Path] | None = None  # explicit {"-wal": path, "-shm": …, "-journal": …}; default: files beside the database
    scratch_dir: Path | None = None  # where the private working copy is made; default: a fresh temporary directory

    def __post_init__(self) -> None:
        if self.max_records_per_table is not None and self.max_records_per_table < 0:
            raise ValueError("max_records_per_table must be >= 0")
        if self.blob_inline_limit < 0:
            raise ValueError("blob_inline_limit must be >= 0")
        for suffix in self.sidecars or {}:
            if suffix not in _SUFFIX_TO_KIND:
                raise ValueError(f"unknown sidecar suffix {suffix!r} (expected one of {sorted(_SUFFIX_TO_KIND)})")


# ------------------------------------------------------------------ public API


class SQLiteInspector:
    """Stateless entry points; every call opens its own private working copy."""

    @classmethod
    def inspect(cls, database_path: str | Path, options: InspectionOptions | None = None, **overrides: Any) -> DatabaseInspection:
        """Inspect one database. ``overrides`` are ``InspectionOptions`` fields: ``inspect(p, include_records=False)``."""
        opts = replace(options or InspectionOptions(), **overrides)
        _require_supported_sqlite()
        return _inspect(_resolve(database_path), opts)

    @classmethod
    def iter_records(
        cls, database_path: str | Path, table: str, options: InspectionOptions | None = None, **overrides: Any
    ) -> Iterator[ActiveRecord]:
        """Stream one table's active records without holding them all in memory (for tables too big for ``inspect``).

        The working copy lives until the iterator is exhausted or closed. Raises ``InspectionError`` up front if the path
        is unusable and on first use if SQLite cannot open the database or has no such table."""
        opts = replace(options or InspectionOptions(), **overrides)
        _require_supported_sqlite()
        return _stream(_resolve(database_path), table, opts)


def inspect_database(database_path: str | Path, **options: Any) -> DatabaseInspection:
    """Shorthand for ``SQLiteInspector.inspect``."""
    return SQLiteInspector.inspect(database_path, **options)


# ------------------------------------------------------------------ orchestration


def _require_supported_sqlite() -> None:
    if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
        raise InspectionError(
            f"The SQLite inspector needs SQLite {'.'.join(map(str, MIN_SQLITE_VERSION))} or newer; this Python is linked with {sqlite3.sqlite_version}"
        )


def _resolve(database_path: str | Path) -> Path:
    path = Path(database_path).expanduser()
    if not path.exists():
        raise InspectionError(f"Database does not exist: {path}")
    if path.is_dir():
        raise InspectionError(f"{path} is a directory, not a database file (use 'discover' to survey a directory)")
    path = path.resolve()
    if not path.is_file():
        raise InspectionError(f"{path} is not a regular file")
    return path


@contextmanager
def _scratch(opts: InspectionOptions, database: Path) -> Iterator[Path]:
    if opts.scratch_dir is None:
        root = Path(tempfile.mkdtemp(prefix="afinspect_"))
        try:
            yield root
        finally:
            shutil.rmtree(root, ignore_errors=True)
        return
    root = Path(opts.scratch_dir).expanduser().resolve()
    if root == database.parent or database.parent in root.parents:
        raise InspectionError(f"Scratch directory {root} is inside the evidence directory {database.parent}; refusing to write there")
    yield root


def _classify_for_inspection(name: str, head: bytes, size: int) -> Classification:
    """The caller asked us to treat this file as a database, so anything without a SQLite header is a *failed* database."""
    c = classify(name, head, size)
    if c.kind is FileKind.SQLITE_DB or c.kind.is_database_candidate:
        return c
    if size == 0:
        return Classification(FileKind.DB_UNRECOGNISED, "zero-length file")
    if len(head) >= 1024 and shannon_entropy(head) >= ENTROPY_ENCRYPTED_THRESHOLD:
        return Classification(FileKind.ENCRYPTED_SUSPECT, f"no SQLite header and high entropy ({shannon_entropy(head):.2f} bits/byte) — likely encrypted, not attempted")
    return Classification(FileKind.DB_UNRECOGNISED, f"not a SQLite database (looks like {c.kind.value}: {c.detail})")


def _inspect(path: Path, opts: InspectionOptions) -> DatabaseInspection:
    issues: list[InspectionIssue] = []
    notes: list[str] = []
    st = path.stat()
    mtime = iso_from_epoch(st.st_mtime)

    try:
        with open_readonly(path) as fh:
            head = fh.read(4096)
        report = inspect_database_file(path)
    except OSError as exc:
        return _unreadable(path, st.st_size, mtime, exc)

    classification = _classify_for_inspection(path.name, head, st.st_size)
    status, status_detail = detect_sqlite_status(FileObservation(
        path=path.name, size=st.st_size, kind=classification.kind, kind_detail=classification.detail,
        header=report if classification.kind is FileKind.SQLITE_DB else None,
    ))
    header = report.header
    notes += header.fatal + header.warnings + report.notes
    if status in STATUS_ISSUE:
        issues.append(InspectionIssue(kind=STATUS_ISSUE[status], detail=status_detail))

    sidecar_files = _find_sidecars(path, opts, issues)
    sidecars, sidecar_paths = _sidecar_reports(sidecar_files, header.page_size, opts, issues)

    sha256: str | None = None
    schema_entries: list[SchemaEntry] = []
    tables: list[TableInspection] = []
    pragmas: dict[str, int | str | None] = {}
    engine_notes: list[str] = []
    decode_errors = 0
    integrity = IntegrityResult(status="not_run")
    open_error: str | None = None
    applied: list[str] = []
    wal_frames: int | None = None

    if status in (SqliteStatus.VALID, SqliteStatus.TRUNCATED):
        open_status = OpenStatus.OK
        session_sidecars = sidecar_paths if opts.apply_sidecars else {}
        try:
            with _scratch(opts, path) as scratch_root:
                session = SQLiteSession(path, session_sidecars, scratch_root, track_undecodable=True, follow_symlinks=True)
                try:
                    with session:
                        sha256 = session.db_sha256
                        conn = session.conn
                        assert conn is not None
                        schema_entries, catalogue_error = _read_schema_entries(conn)
                        if catalogue_error:
                            issues.append(InspectionIssue(kind="schema_read_error", detail=catalogue_error))
                        tables = _read_catalogue(conn, schema_entries, issues)
                        pragmas = _engine_pragmas(conn)
                        if opts.integrity_check:
                            integrity = _integrity(session, tables, issues)
                        if opts.include_records:
                            tables = [_with_records(session, t, opts, issues) for t in tables]
                        engine_notes += session.notes
                        decode_errors = session.decode_errors
                        applied = [_SUFFIX_NAME[s] for s in session_sidecars]
                        index = session.wal_index()
                        wal_frames = index.max_frame if index is not None else None
                except SQLiteOpenError as exc:
                    open_status, open_error = OpenStatus.UNOPENABLE, str(exc)
                    sha256 = session.db_sha256
                    engine_notes += session.notes
                    issues.append(InspectionIssue(kind="database_unopenable", detail=f"SQLite refused to open it: {exc}"))
        except OSError as exc:
            return _unreadable(path, st.st_size, mtime, exc)
    else:
        open_status = {
            SqliteStatus.ENCRYPTED_SUSPECT: OpenStatus.ENCRYPTED_SUSPECT,
            SqliteStatus.CORRUPT_HEADER: OpenStatus.HEADER_INVALID,
        }.get(status, OpenStatus.NOT_SQLITE)
        open_error = status_detail
        engine_notes.append("SQLite was not asked to open this file: " + status_detail)

    if status not in (SqliteStatus.VALID, SqliteStatus.TRUNCATED) or open_status is OpenStatus.UNOPENABLE:
        try:
            sha256 = sha256 or (sha256_of(path) if opts.hash_files else None)
        except OSError:
            sha256 = None
    if not opts.hash_files:
        sha256 = None

    sidecars = [s.model_copy(update={"applied": s.kind.value in applied}) for s in sidecars]
    wal = next((s for s in sidecars if s.kind is SidecarKind.WAL), None)
    includes_wal = None
    if open_status is OpenStatus.OK:
        if wal_frames is not None:  # SQLite's own count of the frames it validated
            includes_wal = wal_frames > 0
        else:  # no wal-index to read: fall back on what the WAL file itself says
            includes_wal = bool(wal is not None and wal.applied and wal.wal is not None and wal.wal.size > 32 and wal.wal.magic_valid)
        if wal is not None and wal.wal is not None and wal.wal.size > 0 and header.journal_mode != "wal":
            engine_notes.append(
                "a WAL file is present but the database header is not in WAL mode: SQLite opens any WAL that exists and "
                "validates its frames itself, so the file may still have contributed rows (see wal_frames_valid)"
            )
        if wal is not None and not opts.apply_sidecars:
            engine_notes.append("sidecars were not applied (apply_sidecars=False): rows are those of the main file alone")
        journal = next((s for s in sidecars if s.kind is SidecarKind.JOURNAL), None)
        if journal is not None and journal.applied and journal.journal is not None and journal.journal.magic_valid and journal.journal.size > 28:
            engine_notes.append(
                "a rollback journal with a valid header was applied to the scratch copy: if it was hot (an interrupted "
                "transaction) SQLite rolled it back, so the rows are those from before that transaction"
            )

    return DatabaseInspection(
        inspected_at=now_iso(), tool_version=__version__,
        file=FileFacts(path=str(path), name=path.name, size=st.st_size, sha256=sha256, mtime=mtime),
        status=status, status_detail=status_detail, header=header,
        size=SizeCheck(actual_size=report.actual_size, expected_size=report.expected_size, consistent=report.size_consistent),
        version=version_info(header, sqlite3.sqlite_version), sidecars=sidecars,
        engine=EngineInfo(
            open_status=open_status, open_error=open_error, sqlite_library_version=sqlite3.sqlite_version, view_includes_wal=includes_wal,
            wal_frames_valid=wal_frames, applied_sidecars=applied, pragmas=pragmas, decode_errors=decode_errors, notes=engine_notes,
        ),
        integrity=integrity, schema_entries=schema_entries, tables=tables, notes=notes, issues=issues,
    )



def _unreadable(path: Path, size: int, mtime: str | None, exc: OSError) -> DatabaseInspection:
    detail = f"{type(exc).__name__}: {exc}"
    return DatabaseInspection(
        inspected_at=now_iso(), tool_version=__version__,
        file=FileFacts(path=str(path), name=path.name, size=size, sha256=None, mtime=mtime),
        status=SqliteStatus.UNREADABLE, status_detail="the file could not be read", header=parse_header(b""),
        size=SizeCheck(actual_size=size), version=version_info(parse_header(b""), sqlite3.sqlite_version),
        engine=EngineInfo(open_status=OpenStatus.UNREADABLE, open_error=detail, sqlite_library_version=sqlite3.sqlite_version),
        integrity=IntegrityResult(status="not_run"),
        issues=[InspectionIssue(kind=STATUS_ISSUE[SqliteStatus.UNREADABLE], detail=detail)],
    )


# ------------------------------------------------------------------ sidecars


def _find_sidecars(path: Path, opts: InspectionOptions, issues: list[InspectionIssue]) -> dict[SidecarKind, Path]:
    if opts.sidecars is not None:
        return {_SUFFIX_TO_KIND[suffix]: Path(p) for suffix, p in opts.sidecars.items()}
    found: dict[SidecarKind, Path] = {}
    for kind, suffix in SIDECAR_SUFFIX.items():
        candidate = path.with_name(path.name + suffix)
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            issues.append(InspectionIssue(kind="sidecar_unreadable", detail=f"{candidate.name}: {type(exc).__name__}: {exc}"))
            continue
        if candidate.is_symlink():
            issues.append(InspectionIssue(kind="sidecar_symlink_skipped", detail=f"{candidate.name} is a symlink; not followed"))
        elif not candidate.is_file():
            issues.append(InspectionIssue(kind="sidecar_not_a_file", detail=f"{candidate.name} is not a regular file"))
        else:
            found[kind] = candidate
    return found


def _sidecar_reports(
    files: dict[SidecarKind, Path], page_size: int | None, opts: InspectionOptions, issues: list[InspectionIssue]
) -> tuple[list[InspectedSidecar], dict[str, Path]]:
    """Facts for every sidecar found, and the {suffix: path} of those that can be copied into the working session."""
    reports: list[InspectedSidecar] = []
    readable: dict[str, Path] = {}
    for kind, path in files.items():
        try:
            size = path.stat().st_size
            sha = sha256_of(path) if opts.hash_files else None
            if kind is SidecarKind.WAL:
                wal = inspect_wal(path, page_size)
                rep = InspectedSidecar(kind=kind, path=str(path), size=size, sha256=sha, wal=wal, note=wal.note,
                                       header_valid=wal.magic_valid if size else None)
            elif kind is SidecarKind.JOURNAL:
                journal = inspect_journal(path, page_size)
                rep = InspectedSidecar(kind=kind, path=str(path), size=size, sha256=sha, journal=journal, note=journal.note,
                                       header_valid=journal.magic_valid if size and not journal.header_zeroed else None)
            else:
                shm = inspect_shm(path)
                rep = InspectedSidecar(kind=kind, path=str(path), size=size, sha256=sha, shm=shm, note=shm.note)
        except OSError as exc:
            issues.append(InspectionIssue(kind="sidecar_unreadable", detail=f"{path.name}: {type(exc).__name__}: {exc}"))
            continue
        reports.append(rep)
        readable[SIDECAR_SUFFIX[kind]] = path
    reports.sort(key=lambda r: list(SIDECAR_SUFFIX).index(r.kind))
    return reports, readable


# ------------------------------------------------------------------ catalogue


def _strip_sql_noise(sql: str) -> str:
    return _NOISE.sub(" ", sql)


def _table_options(stripped_sql: str) -> set[str]:
    """The words after a CREATE TABLE's closing parenthesis: ``WITHOUT ROWID``, ``STRICT`` (used only without table_list)."""
    depth, last = 0, -1
    for i, ch in enumerate(stripped_sql):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                last = i
    tail = stripped_sql[last + 1:] if last >= 0 else ""
    return {" ".join(part.split()).upper() for part in tail.split(",") if part.strip()}


def _table_list(conn: sqlite3.Connection) -> dict[str, tuple[str, bool, bool]] | None:
    """``PRAGMA table_list`` (SQLite 3.37+): {name: (type, without_rowid, strict)}. None where the library predates it —
    an unknown PRAGMA is silently ignored and returns no rows, whereas a real database always lists at least its schema table."""
    try:
        rows = conn.execute("PRAGMA table_list").fetchall()
    except sqlite3.DatabaseError:
        return None
    if not rows or len(rows[0]) < 6:
        return None
    return {r[1]: (r[2], bool(r[4]), bool(r[5])) for r in rows if r[0] == "main"}


def _read_schema_entries(conn: sqlite3.Connection) -> tuple[list[SchemaEntry], str | None]:
    entries: list[SchemaEntry] = []
    try:
        cur = conn.execute("SELECT rowid, type, name, tbl_name, rootpage, sql FROM sqlite_master ORDER BY rowid")
        while (row := cur.fetchone()) is not None:  # row by row: entries before a damaged page are kept
            entries.append(SchemaEntry(rowid=row[0], type=row[1], name=row[2], table=row[3], root_page=row[4] or None, sql=row[5]))
    except sqlite3.DatabaseError as exc:
        return entries, f"sqlite_master could only be read up to entry {len(entries)}: {type(exc).__name__}: {exc}"
    return entries, None


def _read_catalogue(conn: sqlite3.Connection, entries: list[SchemaEntry], issues: list[InspectionIssue]) -> list[TableInspection]:
    listing = _table_list(conn)
    index_entries = {e.name: e for e in entries if e.type == "index"}
    return [_read_table(conn, e, listing, index_entries, issues) for e in entries if e.type == "table"]


def _read_table(
    conn: sqlite3.Connection, entry: SchemaEntry, listing: dict[str, tuple[str, bool, bool]] | None,
    index_entries: dict[str, SchemaEntry], issues: list[InspectionIssue],
) -> TableInspection:
    sql = entry.sql or ""
    stripped = _strip_sql_noise(sql)
    if listing is not None and entry.name in listing:
        type_, without_rowid, strict = listing[entry.name]
        kind = {"virtual": TableKind.VIRTUAL, "shadow": TableKind.SHADOW}.get(type_, TableKind.TABLE)
    else:  # library without PRAGMA table_list: read the CREATE statement
        options = _table_options(stripped)
        kind = TableKind.VIRTUAL if _VIRTUAL_SQL.match(sql) else TableKind.TABLE
        without_rowid, strict = "WITHOUT ROWID" in options, "STRICT" in options
    if kind is TableKind.VIRTUAL:
        without_rowid = False
    base = dict(
        name=entry.name, kind=kind, internal=entry.name.lower().startswith("sqlite_"), sql=entry.sql, root_page=entry.root_page,
        without_rowid=without_rowid, strict=strict, autoincrement=bool(_AUTOINCREMENT.search(stripped)),
    )
    try:
        raw_columns = conn.execute(f"PRAGMA table_xinfo({q(entry.name)})").fetchall()
        indexes = _read_indexes(conn, entry.name, index_entries)
        foreign_keys = _read_foreign_keys(conn, entry.name)
    except sqlite3.DatabaseError as exc:
        detail = f"{type(exc).__name__}: {exc}"
        issues.append(InspectionIssue(kind="schema_read_error", table=entry.name, detail=detail))
        return TableInspection(**base, read_error=f"schema: {detail}")

    pk_columns = [c for c in raw_columns if c[5]]
    alias = None
    if (
        kind is not TableKind.VIRTUAL and not without_rowid and len(pk_columns) == 1
        and (pk_columns[0][2] or "").strip().upper() == "INTEGER" and not any(ix.origin == "pk" for ix in indexes)
    ):
        alias = pk_columns[0][1]  # INTEGER PRIMARY KEY creates no index of its own: the column *is* the rowid
    columns = [
        ColumnSchema(
            cid=c[0], name=c[1], declared_type=c[2] or "", affinity=affinity_of(c[2]), not_null=bool(c[3]), default=c[4],
            primary_key_position=c[5], hidden=c[6], is_rowid_alias=(c[1] == alias),
        )
        for c in raw_columns
    ]
    primary_key = [c.name for c in sorted((c for c in columns if c.primary_key_position), key=lambda c: c.primary_key_position)]
    try:
        row_count: int | None = conn.execute(f"SELECT COUNT(*) FROM {q(entry.name)}").fetchone()[0]
        read_error = None
    except sqlite3.DatabaseError as exc:
        row_count, read_error = None, f"count: {type(exc).__name__}: {exc}"
        issues.append(InspectionIssue(kind="table_read_error", table=entry.name, detail=read_error))
    return TableInspection(
        **base, columns=columns, primary_key=primary_key, rowid_alias=alias, indexes=indexes, foreign_keys=foreign_keys,
        row_count=row_count, read_error=read_error,
    )


def _read_indexes(conn: sqlite3.Connection, table: str, index_entries: dict[str, SchemaEntry]) -> list[IndexSchema]:
    out: list[IndexSchema] = []
    for _seq, name, unique, origin, partial in conn.execute(f"PRAGMA index_list({q(table)})").fetchall():
        columns = [
            IndexColumn(position=r[0], cid=r[1], name=r[2], descending=bool(r[3]), collation=r[4])
            for r in conn.execute(f"PRAGMA index_xinfo({q(name)})").fetchall() if r[5]  # key columns; the rest is the rowid / PK suffix
        ]
        entry = index_entries.get(name)
        out.append(IndexSchema(
            name=name, table=table, unique=bool(unique), origin=origin, partial=bool(partial), columns=columns,
            sql=entry.sql if entry else None, root_page=entry.root_page if entry else None,
        ))
    return out


def _read_foreign_keys(conn: sqlite3.Connection, table: str) -> list[ForeignKey]:
    grouped: dict[int, dict[str, Any]] = {}
    for fk_id, _seq, ref_table, from_col, to_col, on_update, on_delete, match in conn.execute(f"PRAGMA foreign_key_list({q(table)})").fetchall():
        g = grouped.setdefault(fk_id, dict(id=fk_id, referenced_table=ref_table, columns=[], referenced_columns=[],
                                           on_update=on_update, on_delete=on_delete, match=match))
        g["columns"].append(from_col)
        g["referenced_columns"].append(to_col)
    return [ForeignKey(**g) for _, g in sorted(grouped.items())]


def _engine_pragmas(conn: sqlite3.Connection) -> dict[str, int | str | None]:
    """What the engine reports for the working copy (a cross-check on the header, not a replacement for it)."""
    out: dict[str, int | str | None] = {}
    for name in ("page_size", "page_count", "freelist_count", "encoding", "user_version", "application_id", "schema_version", "auto_vacuum", "journal_mode"):
        try:
            value = conn.execute(f"PRAGMA {name}").fetchone()[0]
        except (sqlite3.DatabaseError, TypeError):
            value = None
        out[name] = _AUTO_VACUUM.get(value, value) if name == "auto_vacuum" else value
    return out


_INTEGRITY_SHORT = 20  # messages kept in a result, and the cheap first pass
_INTEGRITY_FULL = 200_000  # the second pass, used only to see *every* message about indexes we cannot verify


def _integrity(session: SQLiteSession, tables: list[TableInspection], issues: list[InspectionIssue]) -> IntegrityResult:
    """``integrity_check``, read with care for indexes whose collation this tool can only approximate.

    A healthy database whose index orders keys with Android's ``LOCALIZED`` (say) collation fails ``integrity_check`` here with
    "row N missing from index X", because our stand-in collation orders differently from the phone's. When *every* message is of
    that kind, the b-tree structure is checked with ``quick_check`` and the result is ``partial`` with a caveat. Anything else
    — any message that does not concern such an index, or so many messages that they may have been cut off — is a real failure."""
    messages = session.integrity(_INTEGRITY_SHORT)  # a check SQLite has to abort ("database disk image is malformed") is a failed check
    if messages == ["ok"]:
        return IntegrityResult(status="ok", messages=messages)
    approximated = sorted({
        i.name for t in tables for i in t.indexes if any((c.collation or "").upper() in APPROXIMATED_COLLATIONS for c in i.columns)
    })
    if approximated:
        every = session.integrity(_INTEGRITY_FULL)  # the short pass may have stopped inside the noise from these indexes
        concerning = [m for m in every if any(f"index {name}" in m for name in approximated)]
        if concerning and len(concerning) == len(every) < _INTEGRITY_FULL:
            quick = session.quick_check()
            if quick == ["ok"]:
                caveat = (
                    f"index-to-table consistency could not be verified for {', '.join(approximated)}: they order keys with a collation "
                    f"({'/'.join(APPROXIMATED_COLLATIONS)}) that Android supplies and this tool can only approximate "
                    f"({len(every):,} message(s), all about those indexes); PRAGMA quick_check confirms the b-tree structure is sound"
                )
                issues.append(InspectionIssue(kind="integrity_partial", detail=caveat))
                return IntegrityResult(status="partial", messages=every[:_INTEGRITY_SHORT], caveats=[caveat])
            messages = quick
        else:
            messages = [m for m in every if m not in concerning][:_INTEGRITY_SHORT] or messages  # the messages that are *not* excusable
    issues.append(InspectionIssue(kind="database_integrity_failure", detail="; ".join(messages)[:300]))
    return IntegrityResult(status="failed", messages=messages)


# ------------------------------------------------------------------ records


def _convert(value: Any, inline_limit: int) -> RecordValue:
    """A cell exactly as SQLite stored it. Nothing is coerced: an INTEGER stays an int, a numeric-looking TEXT stays text."""
    if value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return SpecialFloat(value="nan" if math.isnan(value) else ("inf" if value > 0 else "-inf"))
    data = bytes(value)
    return BlobValue(
        length=len(data), sha256=hashlib.sha256(data).hexdigest(), hex_head=data[:32].hex(),
        hex=data.hex() if len(data) <= inline_limit else None,
    )


def _select_for(table: TableInspection) -> tuple[str, list[ColumnSchema]]:
    data_columns = [c for c in table.columns if c.hidden != 1]
    rowid = None if table.without_rowid else rowid_expression(c.name for c in table.columns)
    order = f" ORDER BY {rowid}" if rowid and table.kind is not TableKind.VIRTUAL else ""
    select = ", ".join(q(c.name) for c in data_columns)
    return f"SELECT {rowid or 'NULL'} AS __rowid__, {select} FROM {q(table.name)}{order}", data_columns


def _iter_table(session: SQLiteSession, table: TableInspection, inline_limit: int, cap: int | None) -> Iterator[tuple[ActiveRecord | None, str | None]]:
    """Yield (record, None) for each row, then possibly (None, error). Rows are fetched one at a time so that when a page in
    the middle of a table is damaged, every row before it has already been handed over."""
    assert session.conn is not None
    sql, data_columns = _select_for(table)
    if cap is not None:
        sql += f" LIMIT {int(cap)}"
    try:
        cur = session.conn.execute(sql)
    except sqlite3.DatabaseError as exc:
        yield None, f"{type(exc).__name__}: {exc}"
        return
    ordinal = 0
    while True:
        try:
            row = cur.fetchone()
        except sqlite3.DatabaseError as exc:
            yield None, f"{type(exc).__name__}: {exc}"
            return
        if row is None:
            return
        values: list[RecordValue] = []
        undecodable: dict[str, str] = {}
        for column, raw in zip(data_columns, row[1:]):
            if isinstance(raw, UndecodableText):
                undecodable[column.name] = raw.raw.hex()
                raw = str(raw)
            values.append(_convert(raw, inline_limit))
        yield ActiveRecord(table=table.name, rowid=row[0], ordinal=ordinal, values=values, undecodable_text=undecodable), None
        ordinal += 1


def _with_records(session: SQLiteSession, table: TableInspection, opts: InspectionOptions, issues: list[InspectionIssue]) -> TableInspection:
    if table.read_error and not table.columns:
        return table  # its schema could not be read, so neither can its rows
    if opts.tables is not None and table.name.lower() not in {t.lower() for t in opts.tables}:
        return table
    records: list[ActiveRecord] = []
    error: str | None = None
    for record, err in _iter_table(session, table, opts.blob_inline_limit, opts.max_records_per_table):
        if err is not None:
            error = err
        else:
            records.append(record)  # type: ignore[arg-type]
    read_error = table.read_error
    if error is not None:
        rows_error = f"rows: {error} — {len(records)} rows read before it were kept"
        issues.append(InspectionIssue(kind="table_read_error", table=table.name, detail=rows_error))
        read_error = "; ".join(e for e in (read_error, rows_error) if e)  # keep an earlier count failure too
    lossy = sum(len(r.undecodable_text) for r in records)
    if lossy:
        issues.append(InspectionIssue(kind="undecodable_text", table=table.name, detail=f"{lossy} TEXT value(s) are not valid UTF-8; the bytes are kept beside a lossy decoding"))
    if table.rowid_alias is None and not table.without_rowid and table.columns and rowid_expression(c.name for c in table.columns) is None:
        issues.append(InspectionIssue(kind="rowid_unavailable", table=table.name, detail="columns named rowid, oid and _rowid_ shadow the row identity"))
    truncated = error is not None or (table.row_count is not None and len(records) < table.row_count)
    return table.model_copy(update={"records": records, "records_truncated": truncated, "read_error": read_error})


def _stream(path: Path, table_name: str, opts: InspectionOptions) -> Iterator[ActiveRecord]:
    issues: list[InspectionIssue] = []
    report: HeaderReport = inspect_database_file(path)
    if not report.header.valid:
        raise InspectionError(f"{path.name} does not have a valid SQLite header: {'; '.join(report.header.fatal)}")
    sidecar_files = _find_sidecars(path, opts, issues)
    _, sidecar_paths = _sidecar_reports(sidecar_files, report.header.page_size, replace(opts, hash_files=False), issues)

    def generate() -> Iterator[ActiveRecord]:
        with _scratch(opts, path) as scratch_root:
            session = SQLiteSession(path, sidecar_paths if opts.apply_sidecars else {}, scratch_root, track_undecodable=True, follow_symlinks=True)
            try:
                with session:
                    assert session.conn is not None
                    entries, error = _read_schema_entries(session.conn)
                    entry = next((e for e in entries if e.type == "table" and e.name.lower() == table_name.lower()), None)
                    if entry is None:
                        raise InspectionError(f"{path.name} has no table named {table_name!r}" + (f" ({error})" if error else ""))
                    table = _read_table(session.conn, entry, _table_list(session.conn), {e.name: e for e in entries if e.type == "index"}, issues)
                    if table.read_error and not table.columns:
                        raise InspectionError(f"The schema of {table.name!r} could not be read: {table.read_error}")
                    delivered = 0
                    for record, err in _iter_table(session, table, opts.blob_inline_limit, opts.max_records_per_table):
                        if err is not None:
                            raise InspectionError(f"Reading {table.name!r} failed after {delivered} rows: {err}")
                        delivered += 1
                        yield record  # type: ignore[misc]
            except SQLiteOpenError as exc:
                raise InspectionError(f"SQLite could not open {path.name}: {exc}") from exc

    return generate()
