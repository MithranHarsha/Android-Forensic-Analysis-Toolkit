"""Read-only SQLite session over a *scratch copy* of a preserved database.

Why a scratch copy: even ``mode=ro`` connections can create ``-shm`` files, replay a WAL, or
roll back a hot journal. Those side effects must never touch the preserved evidence copy, so
each session works on a disposable copy that is deleted afterwards. The resulting "active
view" is exactly what the phone's own SQLite would present on next open: main file + committed
WAL frames, with any hot journal rolled back.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import sqlite3
import tempfile
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from android_forensics.config import CHUNK_SIZE
from android_forensics.readonly import open_readonly
from android_forensics.sqlite.sidecars import ShmFacts, inspect_shm

# Android registers these collations itself (ICU-based); they are not in SQLite. Registering a plain binary comparison lets a
# table or index that names one be read, but it is only an approximation of the phone's ordering.
APPROXIMATED_COLLATIONS = ("LOCALIZED", "PHONEBOOK", "UNICODE", "LOCALE")
_ANDROID_COLLATIONS = APPROXIMATED_COLLATIONS
_WITHOUT_ROWID = re.compile(r"\bWITHOUT\s+ROWID\b", re.I)
_VIRTUAL = re.compile(r"^\s*CREATE\s+VIRTUAL\s+TABLE", re.I)


# ---------------------------------------------------------------- hostile-database hardening
# A database from a compromised device is attacker-controlled *code* as well as data: views, triggers, CHECK constraints,
# generated columns and DEFAULTs can call SQL functions, and a crafted query plan can burn unbounded CPU or memory. The
# session therefore (1) distrusts the schema (PRAGMA trusted_schema=OFF: schema-embedded SQL may not call "unsafe" functions),
# (2) installs an authorizer that permits reading and nothing else, (3) caps the heap, and (4) aborts any statement that runs
# past a deadline.
_ALLOWED_PRAGMAS = frozenset({
    "table_info", "table_xinfo", "table_list", "index_list", "index_info", "index_xinfo", "foreign_key_list", "integrity_check",
    "quick_check", "query_only", "page_size", "page_count", "freelist_count", "encoding", "user_version", "application_id",
    "schema_version", "data_version", "auto_vacuum", "journal_mode", "trusted_schema", "hard_heap_limit", "soft_heap_limit", "collation_list",
})
_DENIED_FUNCTIONS = frozenset({"load_extension", "fts3_tokenizer", "readfile", "writefile", "edit", "zipfile", "sqlar_compress"})
_READ_ACTIONS = frozenset({sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_RECURSIVE, sqlite3.SQLITE_TRANSACTION,
                           sqlite3.SQLITE_SAVEPOINT})
DEFAULT_STATEMENT_SECONDS = 300.0
HEAP_LIMIT_BYTES = 1 << 30


def _read_only_authorizer(action: int, arg1: str | None, arg2: str | None, db_name: str | None, trigger: str | None) -> int:
    if action in _READ_ACTIONS:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION:
        return sqlite3.SQLITE_DENY if (arg2 or "").lower() in _DENIED_FUNCTIONS else sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA:
        return sqlite3.SQLITE_OK if (arg1 or "").lower() in _ALLOWED_PRAGMAS else sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY  # INSERT/UPDATE/DELETE/CREATE/DROP/ALTER/ATTACH/DETACH/ANALYZE/REINDEX/... all refused


def q(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def rowid_expression(column_names: Iterable[str]) -> str | None:
    """A name that reaches a table's real rowid: ``rowid``, ``oid`` or ``_rowid_`` — whichever no column shadows.

    A column called ``rowid`` makes the bare word mean that column, not the row's identity. None if all three are taken."""
    taken = {n.lower() for n in column_names}
    return next((alias for alias in ("rowid", "oid", "_rowid_") if alias not in taken), None)


class UndecodableText(str):
    """TEXT that is not valid UTF-8. The string holds a lossy decoding; ``raw`` keeps the bytes exactly as stored."""

    raw: bytes

    def __new__(cls, text: str, raw: bytes) -> UndecodableText:
        obj = super().__new__(cls, text)
        obj.raw = raw
        return obj


def _copy_readonly(src: Path, dst: Path, follow_symlinks: bool) -> tuple[str, int]:
    """Copy ``src`` (opened read-only) to ``dst`` and return the SHA-256 and size of the exact bytes copied."""
    digest, size = hashlib.sha256(), 0
    with open_readonly(src, follow_symlinks=follow_symlinks) as fin, open(dst, "wb") as fout:
        while chunk := fin.read(CHUNK_SIZE):
            digest.update(chunk)
            fout.write(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


@dataclass(frozen=True)
class ColumnInfo:
    name: str
    type: str
    notnull: bool
    pk: int


@dataclass
class SchemaObject:
    obj_type: str
    name: str
    tbl_name: str
    root_page: int | None
    sql: str | None
    columns: list[ColumnInfo] = field(default_factory=list)
    rowid_table: bool = True
    is_virtual: bool = False
    row_count: int | None = None
    read_error: str | None = None


class SQLiteOpenError(RuntimeError):
    pass


class SQLiteSession:
    """``track_undecodable`` makes non-UTF-8 TEXT come back as ``UndecodableText`` (a ``str`` that keeps its raw bytes).
    ``follow_symlinks`` lets an explicitly named database be a symlink; sidecars never are followed unless it is set.

    After entering, ``db_sha256`` / ``db_size`` describe the exact bytes SQLite was given (the copy was hashed as it was made)."""

    def __init__(
        self, db_path: Path, sidecars: dict[str, Path] | None, scratch_root: Path,
        *, track_undecodable: bool = False, follow_symlinks: bool = False, statement_seconds: float = DEFAULT_STATEMENT_SECONDS,
    ):
        self.db_path = db_path
        self.sidecars = sidecars or {}
        self.scratch_root = scratch_root
        self.track_undecodable = track_undecodable
        self.follow_symlinks = follow_symlinks
        self.statement_seconds = statement_seconds
        self._deadline = float("inf")
        self.decode_errors = 0
        self.notes: list[str] = []
        self.db_sha256: str | None = None
        self.db_size: int | None = None
        self.sidecar_sha256: dict[str, str] = {}
        self._tmp: Path | None = None
        self.conn: sqlite3.Connection | None = None

    def _decode(self, raw: bytes) -> str:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            self.decode_errors += 1
            text = raw.decode("utf-8", "replace")
            return UndecodableText(text, raw) if self.track_undecodable else text

    def __enter__(self) -> SQLiteSession:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self._tmp = Path(tempfile.mkdtemp(prefix="sess_", dir=self.scratch_root))
        work = self._tmp / "work.db"
        try:
            self.db_sha256, self.db_size = _copy_readonly(self.db_path, work, self.follow_symlinks)
            for suffix, src in self.sidecars.items():
                self.sidecar_sha256[suffix], _ = _copy_readonly(src, self._tmp / f"work.db{suffix}", False)
        except BaseException:
            self.close()  # never leave a scratch directory behind, whatever went wrong
            raise
        uri = f"file:{quote(str(work))}"
        try:
            try:
                self.conn = sqlite3.connect(f"{uri}?mode=ro", uri=True)
                self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            except sqlite3.OperationalError as exc:
                if "readonly" not in str(exc).lower() and "unable to open" not in str(exc).lower():
                    raise
                if self.conn:
                    self.conn.close()
                self.notes.append("read-only open refused (hot journal / WAL recovery); reopened on scratch copy read-write")
                self.conn = sqlite3.connect(f"{uri}?mode=rw", uri=True)
                self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            self.conn.text_factory = self._decode
            for name in _ANDROID_COLLATIONS:
                self.conn.create_collation(name, lambda a, b: (a > b) - (a < b))
            self.conn.execute("PRAGMA query_only=ON")
            self._harden()
        except sqlite3.DatabaseError as exc:
            self.close()
            raise SQLiteOpenError(f"{type(exc).__name__}: {exc}") from exc
        return self

    def _harden(self) -> None:
        assert self.conn is not None
        self.conn.execute("PRAGMA trusted_schema=OFF")
        try:
            self.conn.execute(f"PRAGMA hard_heap_limit={HEAP_LIMIT_BYTES}")
        except sqlite3.DatabaseError:  # pragma: no cover - SQLite < 3.31
            pass
        self.conn.set_authorizer(_read_only_authorizer)
        self.arm()
        self.conn.set_progress_handler(lambda: 1 if time.monotonic() > self._deadline else 0, 10_000)

    def arm(self) -> None:
        """Restart the statement clock; a statement that runs longer than ``statement_seconds`` is aborted."""
        self._deadline = time.monotonic() + self.statement_seconds

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            finally:
                self.conn = None
        if self._tmp is not None:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None

    def __exit__(self, *exc: object) -> None:
        self.close()

    def schema(self) -> list[SchemaObject]:
        assert self.conn is not None
        self.arm()
        objs: list[SchemaObject] = []
        for row in self.conn.execute("SELECT type, name, tbl_name, rootpage, sql FROM sqlite_master ORDER BY rowid"):
            obj = SchemaObject(row[0], row[1], row[2], row[3], row[4])
            if obj.obj_type == "table":
                obj.is_virtual = bool(obj.sql and _VIRTUAL.match(obj.sql))
                obj.rowid_table = not (obj.sql and _WITHOUT_ROWID.search(obj.sql))
                try:
                    obj.columns = [
                        ColumnInfo(c[1], c[2] or "", bool(c[3]), c[5])
                        for c in self.conn.execute(f"PRAGMA table_xinfo({q(obj.name)})")
                    ]
                except sqlite3.DatabaseError as exc:
                    obj.read_error = f"schema: {exc}"
                if not obj.is_virtual and not obj.read_error:
                    try:
                        obj.row_count = self.conn.execute(f"SELECT COUNT(*) FROM {q(obj.name)}").fetchone()[0]
                    except sqlite3.DatabaseError as exc:
                        obj.read_error = f"count: {exc}"
            objs.append(obj)
        return objs

    def iter_rows(
        self, table: SchemaObject | str, columns: list[str] | None = None
    ) -> Iterator[tuple[int | None, dict[str, Any]]]:
        """Yield (rowid, {column: value}); rowid is None for WITHOUT ROWID tables.

        Rows are streamed one at a time on purpose: if a page in the middle of the table is damaged,
        every row before it has already been yielded to the caller, and only the failing step raises.
        """
        assert self.conn is not None
        rowid_name: str | None
        if isinstance(table, str):
            name, has_rowid, rowid_name = table, True, "rowid"
        else:
            name, has_rowid = table.name, table.rowid_table
            rowid_name = rowid_expression(c.name for c in table.columns) if table.columns else "rowid"
        cols = "*" if not columns else ", ".join(q(c) for c in columns)
        rid = rowid_name if (has_rowid and rowid_name) else "NULL"
        self.arm()
        cur = self.conn.execute(f"SELECT {rid} AS __rowid__, {cols} FROM {q(name)}")
        names = [d[0] for d in cur.description][1:]
        for r in cur:
            self.arm()
            yield r[0], dict(zip(names, r[1:]))

    def wal_index(self) -> ShmFacts | None:
        """The wal-index header SQLite keeps beside the working copy once it has opened it: ``max_frame`` is the number of WAL
        frames SQLite itself validated (salts and checksums) and therefore the number that contribute to what queries see.
        SQLite opens a WAL whenever the file exists, whatever the database header says. None if there is no wal-index."""
        if self._tmp is None or not (self._tmp / "work.db-shm").is_file():
            return None
        try:
            return inspect_shm(self._tmp / "work.db-shm")
        except OSError:
            return None

    def integrity(self, limit: int = 20) -> list[str]:
        assert self.conn is not None
        try:
            self.arm()
            return [r[0] for r in self.conn.execute(f"PRAGMA integrity_check({int(limit)})")]
        except sqlite3.DatabaseError as exc:
            return [f"integrity_check aborted: {exc}"]

    def quick_check(self, limit: int = 20) -> list[str]:
        """Like ``integrity``, but without comparing index contents to table contents (b-tree structure only)."""
        assert self.conn is not None
        try:
            self.arm()
            return [r[0] for r in self.conn.execute(f"PRAGMA quick_check({int(limit)})")]
        except sqlite3.DatabaseError as exc:
            return [f"quick_check aborted: {exc}"]
