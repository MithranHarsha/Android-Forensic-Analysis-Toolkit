"""Recover deleted data from one database and its sidecars: the orchestration of Phase 4B (main file) and 4C (WAL, journal)."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from android_forensics.sqlite.ddl import DdlError, parse_create_table
from android_forensics.sqlite.journal import JournalInfo, parse_journal
from android_forensics.sqlite.pages import PageError, PageType, parse_btree_page, read_cell
from android_forensics.sqlite.parser import SQLiteDatabase, logical_row
from android_forensics.sqlite.reader import SQLiteOpenError, SQLiteSession
from android_forensics.sqlite.records import RecordError, parse_record
from android_forensics.sqlite.recovery import (
    ActiveIndex,
    PageImage,
    RecoveredRow,
    TableModel,
    UnrecoveredRegion,
    active_index_from_rows,
    active_index_from_sqlite,
    main_file_images,
    recover_all,
)
from android_forensics.sqlite.wal import COMMITTED, STALE, STALE_UNVERIFIED, UNCOMMITTED, WalInfo, parse_wal

_FRAME_NOTES = {
    COMMITTED: "a committed WAL frame (a page version that readers have seen)",
    UNCOMMITTED: "a valid WAL frame after the last commit (an uncommitted transaction)",
    STALE: "a stale WAL frame from an earlier WAL generation (a superseded page version); checksum chain verified",
    STALE_UNVERIFIED: "a stale WAL frame from an earlier WAL generation (a superseded page version); not verifiable",
}


@dataclass
class RecoveryReport:
    database: str
    rows: list[RecoveredRow] = field(default_factory=list)
    unrecovered: list[UnrecoveredRegion] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    tables_attempted: list[str] = field(default_factory=list)
    tables_skipped: list[str] = field(default_factory=list)
    freelist_pages: int = 0
    wal: dict[str, Any] | None = None
    journal: dict[str, Any] | None = None
    active_source: str = ""
    models: list[TableModel] = field(default_factory=list)  # the table definitions the scan used
    wal_frame_status: dict[int, str] = field(default_factory=dict)  # WAL frame index -> its verification status
    journal_checksum_ok: dict[int, bool] = field(default_factory=dict)  # journal record index -> its checksum verified


def _schema_from_page1(data: bytes, encoding: str) -> list[tuple[str, str]]:
    """(name, CREATE TABLE text) for the tables listed on a page-1 image (used for WAL / journal images of page 1)."""
    out: list[tuple[str, str]] = []
    try:
        page = parse_btree_page(1, data)
    except PageError:
        return out
    if page.type is not PageType.TABLE_LEAF:
        return out
    for i in range(len(page.cell_offsets)):
        try:
            cell = read_cell(page, i, len(data))
            if cell.overflow_page or cell.payload_offset is None:
                continue
            rec = parse_record(data[cell.payload_offset: cell.payload_offset + cell.local_size], 0, encoding=encoding)
        except (PageError, RecordError):
            continue
        v = rec.values
        if len(v) >= 5 and v[0] == "table" and isinstance(v[4], str):
            out.append((str(v[1]), v[4]))
    return out


def _model_for(sql: str) -> TableModel | None:
    try:
        return TableModel.from_sql(parse_create_table(sql))
    except DdlError:
        return None


def _wal_images(wal: WalInfo, db_page_count: int) -> Iterator[PageImage]:
    for f in wal.frames:
        if f.status not in _FRAME_NOTES or f.page_number < 1 or f.page_number > max(db_page_count, 1) * 4 + 1024:
            continue
        yield PageImage(f.page_number, wal.page(f), "wal", wal.path, f.page_offset, "historical", None, f.index)


def _journal_images(journal: JournalInfo) -> Iterator[PageImage]:
    for r in journal.records:
        yield PageImage(r.page_number, journal.page(r), "journal", journal.path, r.page_offset(), "historical", None, r.index)


def recover_database(main: str | Path, sidecars: dict[str, Path | str] | None = None, scratch: Path | None = None) -> RecoveryReport:
    """Recover deleted / superseded records from ``main`` and its ``-wal`` / ``-journal`` (``{"-wal": path, ...}``).

    Nothing is written next to the evidence: SQLite (used only to obtain the *active view* the findings are compared with)
    works on a scratch copy."""
    main = Path(main)
    sidecars = {k: Path(v) for k, v in (sidecars or {}).items()}
    report = RecoveryReport(str(main))
    try:
        db = SQLiteDatabase.open(main)
    except PageError as exc:
        report.notes.append(f"the main file has no usable header ({exc}): recovery from it was not attempted")
        return report
    own_scratch = scratch is None
    scratch_dir = Path(tempfile.mkdtemp(prefix="afrecover_")) if own_scratch else Path(scratch)
    try:
        with db:
            report.freelist_pages = len(db.freelist().pages)
            wal = parse_wal(sidecars["-wal"], expected_page_size=db.page_size) if sidecars.get("-wal") and sidecars["-wal"].stat().st_size else None
            journal = parse_journal(sidecars["-journal"], db_page_size=db.page_size, db_page_count=db.page_count) \
                if sidecars.get("-journal") and sidecars["-journal"].stat().st_size else None
            if wal:
                report.wal = {"frames": len(wal.frames), **wal.summary(), "problems": wal.problems}
                report.wal_frame_status = {f.index: f.status for f in wal.frames}
            if journal:
                report.journal = {"kind": journal.kind, "records": len(journal.records), "problems": journal.problems}
                report.journal_checksum_ok = {r.index: r.checksum_ok for r in journal.records}

            models, skipped = _collect_models(db, wal, journal, main, sidecars, scratch_dir, report)
            report.models = models
            report.tables_attempted = sorted(m.name for m in models)
            report.tables_skipped = skipped
            if not models:
                report.notes.append("no table schema could be read from the main file, the WAL, the journal or SQLite: nothing to attempt")
                return report
            active = _active_index(db, models, main, sidecars, scratch_dir, report)

            images = list(main_file_images(db))
            if wal:
                images += list(_wal_images(wal, db.page_count))
            if journal:
                images += list(_journal_images(journal))
            rows, unrecovered, stats = recover_all(images, models, db.encoding, active)
            for r in rows:
                if r.source == "wal" and r.frame:
                    frame = next((f for f in wal.frames if f.index == r.frame), None) if wal else None
                    if frame is not None:
                        r.issues.append(_FRAME_NOTES[frame.status])
                elif r.source == "journal":
                    r.issues.append("a page image from the rollback journal: the page as it was before the transaction the journal belongs to")
            report.rows, report.unrecovered, report.stats = rows, unrecovered, stats
    finally:
        if own_scratch:
            import shutil

            shutil.rmtree(scratch_dir, ignore_errors=True)
    return report


def _collect_models(db, wal, journal, main, sidecars, scratch, report) -> tuple[list[TableModel], list[str]]:
    """The union of table definitions from every source: the main file's page 1, SQLite's own view, WAL and journal page-1 images."""
    sql_by_name: dict[str, str] = {}
    for row in db.schema():
        if row.type == "table" and row.sql:
            sql_by_name[row.name] = row.sql
    try:
        with SQLiteSession(main, {k: v for k, v in sidecars.items()}, scratch) as session:
            for obj in session.schema():
                if obj.obj_type == "table" and obj.sql:
                    sql_by_name[obj.name] = obj.sql
    except (SQLiteOpenError, OSError):
        report.notes.append("SQLite could not open the database (with its sidecars): the schema and the active view come from the page-level reader")
    if wal:
        for f in reversed(wal.frames):  # the newest committed version of page 1 wins
            if f.page_number == 1 and f.status in _FRAME_NOTES:
                for name, sql in _schema_from_page1(wal.page(f), db.encoding):
                    sql_by_name.setdefault(name, sql)
    if journal:
        for r in journal.records:
            if r.page_number == 1:
                for name, sql in _schema_from_page1(journal.page(r), db.encoding):
                    sql_by_name.setdefault(name, sql)
    models: list[TableModel] = []
    skipped: list[str] = []
    for name, sql in sorted(sql_by_name.items()):
        m = _model_for(sql)
        if m is None:
            skipped.append(name)
        else:
            models.append(m)
    return models, skipped


def _active_index(db, models, main, sidecars, scratch, report) -> ActiveIndex:
    try:
        idx = active_index_from_sqlite(main, sidecars, models, scratch)
        report.active_source = "sqlite (the active view: WAL applied, hot journal rolled back)"
        return idx
    except (SQLiteOpenError, OSError):
        rows: dict[str, list[dict[str, Any]]] = {}
        for row in db.schema():
            table = row.table_sql()
            if table is None or row.root_page <= 0:
                continue
            rows[row.name] = [logical_row(table, r) for r in db.live_rows(row)]
        report.active_source = "page-level reader (main file only: SQLite could not open the database)"
        return active_index_from_rows(models, rows)
