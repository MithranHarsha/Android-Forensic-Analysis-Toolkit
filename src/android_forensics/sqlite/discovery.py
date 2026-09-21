"""SQLite discovery (case pipeline): run the inspector over every ingested database and persist what it finds.

The inspection itself — header, version, sidecars, schema, integrity — is ``SQLiteInspector``'s; this stage feeds it the
preserved working copies (and their preserved sidecars) and stores the result in the case database. The byte-level
detection status (``VALID``, ``TRUNCATED`` …) is decided exactly as the filesystem scan decides it, from the file's kind at
ingestion and its header, so the scan and this stage always agree; the engine-level outcome (did SQLite open it?) is stored
separately as ``open_status``.

Active records are *not* read here: extraction does that, table by table, through the artifact parsers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from android_forensics.filesystem.analysis import FileObservation, detect_sqlite_status
from android_forensics.filesystem.sidecars import SIDECAR_SUFFIX, sidecar_paths as expected_sidecar_paths
from android_forensics.models import FileKind
from android_forensics.models.enums import OpenStatus, TableKind
from android_forensics.progress import NullProgress, Progress
from android_forensics.sqlite.header import HeaderReport
from android_forensics.sqlite.inspection import DatabaseInspection
from android_forensics.sqlite.inspector import InspectionOptions, SQLiteInspector
from android_forensics.storage.case_store import CaseStore, utcnow

_DB_KINDS = tuple(k.value for k in FileKind if k.is_database_candidate)
_NOT_SQLITE_MESSAGE = "SQLite magic absent (corrupt, overwritten or different format)"


@dataclass
class DiscoveryStats:
    databases: int = 0
    readable: int = 0
    encrypted_suspects: int = 0
    unreadable: int = 0
    tables: int = 0
    with_wal: int = 0
    with_journal: int = 0


def preserved_path(store: CaseStore, row) -> Path | None:
    if not row["preserved_copy"]:
        return None
    return store.evidence_dir / f"s{row['source_id']}" / row["preserved_copy"]


def sidecar_rows(store: CaseStore, db_row) -> dict[str, object]:
    """The sidecar files ingested for a database, keyed by suffix ("-wal", "-shm", "-journal")."""
    found = {}
    for kind, sidecar_path in expected_sidecar_paths(db_row["path"]).items():
        r = store.one("SELECT * FROM evidence_files WHERE source_id=? AND path=?", (db_row["source_id"], sidecar_path))
        if r is not None:
            found[SIDECAR_SUFFIX[kind]] = r
    return found


def _blank_record(evidence_file_id: int, actual_size: int) -> dict:
    return {
        "evidence_file_id": evidence_file_id, "header_valid": 0, "header_json": None, "page_size": None,
        "page_count_header": None, "expected_size": None, "actual_size": actual_size, "size_consistent": None,
        "text_encoding": None, "journal_mode": None, "freelist_page_count": None, "schema_cookie": None,
        "user_version": None, "application_id": None, "has_wal": 0, "has_shm": 0, "has_journal": 0,
        "sidecars_json": "{}", "view_includes_wal": None, "sqlite_status": "UNVERIFIED", "sqlite_status_detail": None,
        "open_status": "not_sqlite", "open_error": None, "integrity_status": "UNVERIFIED", "integrity_detail": None,
        "table_count": 0, "warnings_json": "[]", "version_json": None, "engine_json": None,
    }


def _apply_inspection(rec: dict, insp: DatabaseInspection, warnings: list[str], stats: DiscoveryStats) -> None:
    """Copy an inspection into the ``databases`` row, keeping the meaning (and wording) later stages rely on."""
    h = insp.header
    rec.update(
        header_valid=int(h.valid), header_json=h.model_dump_json(), page_size=h.page_size, page_count_header=h.page_count,
        expected_size=insp.size.expected_size, size_consistent=None if insp.size.consistent is None else int(insp.size.consistent),
        text_encoding=h.text_encoding, journal_mode=h.journal_mode, freelist_page_count=h.freelist_page_count,
        schema_cookie=h.schema_cookie, user_version=h.user_version, application_id=h.application_id,
        version_json=insp.version.model_dump_json(), engine_json=insp.engine.model_dump_json(),
    )
    warnings += insp.notes + insp.engine.notes

    facts = {}
    for s in insp.sidecars:
        facts[s.kind.value] = (s.wal or s.shm or s.journal).model_dump()
        rec[f"has_{s.kind.value}"] = 1
    stats.with_wal += "wal" in facts
    stats.with_journal += "journal" in facts
    rec["sidecars_json"] = json.dumps(facts)
    rec["view_includes_wal"] = None if insp.engine.view_includes_wal is None else int(insp.engine.view_includes_wal)

    status = insp.engine.open_status
    rec["open_status"] = status.value
    if status is OpenStatus.OK:
        rec["integrity_status"] = {"ok": "VALID", "partial": "PARTIAL", "failed": "INVALID"}.get(insp.integrity.status, "UNVERIFIED")
        detail = "; ".join(insp.integrity.messages)
        if insp.integrity.caveats:
            detail = "; ".join(insp.integrity.caveats) + f" (integrity_check said: {detail})"
        rec["integrity_detail"] = detail[:2000] if insp.integrity.status != "not_run" else None
        stats.readable += 1
        return
    stats.unreadable += 1
    if status is OpenStatus.NOT_SQLITE:
        rec["open_error"] = _NOT_SQLITE_MESSAGE
    elif status is OpenStatus.HEADER_INVALID:
        rec["open_error"] = "; ".join(h.fatal)
    else:  # unopenable / unreadable
        rec["open_error"] = insp.engine.open_error
        if status is OpenStatus.UNOPENABLE:
            rec["integrity_detail"] = "database could not be opened by SQLite"


def _table_rows(database_id: int, insp: DatabaseInspection) -> list[tuple]:
    """One ``db_tables`` row per ``sqlite_master`` entry (tables, indexes, views, triggers), with the full schema as JSON."""
    tables = {t.name: t for t in insp.tables}
    indexes = {i.name: i for i in insp.indexes}
    rows = []
    for e in insp.schema_entries:
        t = tables.get(e.name) if e.type == "table" else None
        if t is not None:
            columns = [[c.name, c.declared_type, c.not_null, c.primary_key_position] for c in t.columns]
            details = t.model_dump_json(exclude={"records"})
            rows.append((database_id, e.name, e.type, e.root_page, e.sql, int(not t.without_rowid), int(t.kind is TableKind.VIRTUAL),
                         t.row_count, json.dumps(columns), t.read_error, details))
        else:
            index = indexes.get(e.name) if e.type == "index" else None
            rows.append((database_id, e.name, e.type, e.root_page, e.sql, 1, 0, None, "[]", None,
                         index.model_dump_json() if index is not None else None))
    return rows


def discover_databases(store: CaseStore, progress: Progress | None = None) -> DiscoveryStats:
    progress = progress or NullProgress()
    stats = DiscoveryStats()
    rows = store.q(
        f"SELECT * FROM evidence_files WHERE kind IN ({','.join('?' * len(_DB_KINDS))}) ORDER BY id", _DB_KINDS
    )
    progress.start("Discovering SQLite databases", len(rows))
    for f in rows:
        stats.databases += 1
        path = preserved_path(store, f)
        rec = _blank_record(f["id"], f["size"])
        warnings: list[str] = []
        insp: DatabaseInspection | None = None

        if f["kind"] == "encrypted_suspect":
            rec["open_status"] = "encrypted_suspect"
            rec["open_error"] = f["kind_detail"]
            rec["integrity_detail"] = "not attempted: no SQLite header, content appears encrypted"
            stats.encrypted_suspects += 1
        elif path is None:
            rec["open_status"] = "not_preserved"
            rec["open_error"] = "no working copy: the evidence was ingested without preserving this file (--preserve none)"
            rec["integrity_detail"] = "not attempted: no working copy to open"
            stats.unreadable += 1
        else:
            sidecar_files = {s: p for s, r in sidecar_rows(store, f).items() if (p := preserved_path(store, r)) is not None}
            insp = SQLiteInspector.inspect(path, InspectionOptions(
                include_records=False, hash_files=False, sidecars=sidecar_files, scratch_dir=store.scratch_dir,
            ))
            _apply_inspection(rec, insp, warnings, stats)

        # the byte-level status is decided exactly as the filesystem scan decides it (ingestion kind + header)
        header_report = None
        if insp is not None and f["kind"] == FileKind.SQLITE_DB.value:
            header_report = HeaderReport(
                header=insp.header, actual_size=insp.size.actual_size, expected_size=insp.size.expected_size,
                size_consistent=insp.size.consistent,
            )
        status, status_detail = detect_sqlite_status(FileObservation(
            path=f["path"], size=f["size"], kind=FileKind(f["kind"]), kind_detail=f["kind_detail"], header=header_report,
        ))
        rec["sqlite_status"], rec["sqlite_status_detail"] = status.value, status_detail
        rec["table_count"] = len(insp.tables) if insp is not None else 0
        rec["warnings_json"] = json.dumps(warnings)

        cols = list(rec)
        with store.transaction():
            cur = store.conn.execute(
                f"INSERT INTO databases({','.join(cols)}) VALUES({','.join('?' * len(cols))})", [rec[c] for c in cols]
            )
            db_id = int(cur.lastrowid)
            if insp is not None:
                store.conn.executemany(
                    "INSERT INTO db_tables(database_id,name,obj_type,root_page,sql,rowid_table,is_virtual,row_count,"
                    "columns_json,read_error,details_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    _table_rows(db_id, insp),
                )
        stats.tables += rec["table_count"]

        issue = None
        if rec["open_status"] == "unopenable":  # byte-level problems (empty, truncated, corrupt header…) are reported by the scan
            issue = ("database_unopenable", f"SQLite refused to open it: {rec['open_error']}")
        elif rec["integrity_status"] == "INVALID":
            issue = ("database_integrity_failure", (rec["integrity_detail"] or "")[:300])
        if issue:
            with store.transaction():
                store.conn.execute(
                    "INSERT INTO scan_issues(source_id,path,issue_type,detail,stage,created_at) VALUES(?,?,?,?,'scan',?)",
                    (f["source_id"], f["path"], issue[0], issue[1], utcnow()),
                )
        progress.advance()
    progress.stop()
    return stats
