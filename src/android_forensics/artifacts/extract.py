"""Extraction stage: identify artifacts by schema, extract ACTIVE records, normalise, persist."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from android_forensics.artifacts.base import DbContext
from android_forensics.artifacts.generic import build_app_summaries, column_hints
from android_forensics.artifacts.registry import get_parsers
from android_forensics.plugins import is_builtin
from android_forensics.progress import NullProgress, Progress
from android_forensics.sqlite.discovery import preserved_path, sidecar_rows
from android_forensics.sqlite.reader import SQLiteOpenError, SQLiteSession
from android_forensics.storage.artifact_writer import insert_artifacts
from android_forensics.storage.case_store import CaseStore, utcnow
from android_forensics.util import require

_BATCH = 1000


@dataclass
class ExtractionStats:
    databases: int = 0
    tables_matched: int = 0
    artifacts: Counter = field(default_factory=Counter)
    generic_tables: int = 0
    errors: int = 0
    app_summaries: int = 0

    @property
    def total(self) -> int:
        return sum(self.artifacts.values())


def _plugin_issue(store: CaseStore, d, parser, detail: str) -> None:  # noqa: ANN001
    with store.transaction():
        store.conn.execute(
            "INSERT INTO scan_issues(source_id,path,issue_type,detail,stage,created_at) VALUES(?,?,?,?,?,?)",
            (d["src_id"], d["fpath"], "parser_plugin_error", f"{parser.name} {parser.version}: {detail}", "extract", utcnow()))


def run_extraction(store: CaseStore, run_id: int, progress: Progress | None = None, now: datetime | None = None) -> ExtractionStats:
    progress = progress or NullProgress()
    stats = ExtractionStats()
    parsers = get_parsers()
    dbs = store.q(
        "SELECT d.*, f.path AS fpath, f.sha256 AS fsha, f.package AS pkg, f.source_id AS src_id, f.preserved_copy AS pc, "
        "f.id AS fid FROM databases d JOIN evidence_files f ON f.id=d.evidence_file_id "
        "WHERE d.open_status='ok' ORDER BY d.id"
    )
    progress.start("Extracting active artifacts", len(dbs))
    for d in dbs:
        stats.databases += 1
        frow = store.one("SELECT * FROM evidence_files WHERE id=?", (d["fid"],))
        sidecars = {s: p for s, r in sidecar_rows(store, frow).items() if (p := preserved_path(store, r)) is not None}
        try:
            session_cm = SQLiteSession(require(preserved_path(store, frow), "preserved copy"), sidecars, store.scratch_dir)
            with session_cm as session:
                objects = session.schema()
                ctx = DbContext(
                    database_id=d["id"], evidence_file_id=d["fid"], source_path=d["fpath"], sha256=d["fsha"],
                    application=d["pkg"], view_includes_wal=bool(d["view_includes_wal"]),
                    tables={o.name: o for o in objects if o.obj_type == "table"}, now=now,
                )
                matched_tables: set[str] = set()
                for parser in parsers:
                    try:
                        matches = parser.identify(objects, ctx)
                    except Exception as exc:  # noqa: BLE001
                        if is_builtin(parser):
                            raise
                        stats.errors += 1
                        _plugin_issue(store, d, parser, f"identify() failed: {type(exc).__name__}: {exc}")
                        continue
                    for match in matches:
                        buffer = []
                        err = None
                        try:
                            for art in parser.extract(session, match, ctx):
                                buffer.append(art)
                                stats.artifacts[art.artifact_type.value] += 1
                                if len(buffer) >= _BATCH:
                                    insert_artifacts(store, run_id, d["id"], buffer)
                                    buffer.clear()
                        except sqlite3.DatabaseError as exc:
                            err = f"{type(exc).__name__}: {exc}"
                            stats.errors += 1
                        except Exception as exc:  # noqa: BLE001 - a third-party parser must never abort the case
                            if is_builtin(parser):
                                raise
                            err = f"plugin parser raised {type(exc).__name__}: {exc}"
                            stats.errors += 1
                        insert_artifacts(store, run_id, d["id"], buffer)
                        for role in match.roles.values():
                            matched_tables.add(role.table)
                            with store.transaction():
                                store.conn.execute(
                                    "UPDATE db_tables SET parsed_by=?, schema_variant=?, schema_score=?, read_error=COALESCE(?,read_error)"
                                    " WHERE database_id=? AND name=? AND obj_type='table'",
                                    (parser.name, match.variant, role.score, err, d["id"], role.table),
                                )
                        if err:
                            with store.transaction():
                                store.conn.execute(
                                    "INSERT INTO scan_issues(source_id,path,issue_type,detail,stage,created_at) VALUES(?,?,?,?,?,?)",
                                    (d["src_id"], d["fpath"], "extraction_error",
                                     f"{parser.name}/{match.primary.table}: {err} — rows read before the error were kept", "extract", utcnow()),
                                )
                        stats.tables_matched += len(match.roles)

                for obj in objects:
                    if obj.obj_type != "table" or obj.is_virtual or obj.name in matched_tables or obj.read_error:
                        continue
                    try:
                        hints = column_hints(session, obj, now)
                        herr = None
                    except sqlite3.DatabaseError as exc:
                        hints, herr = None, f"{type(exc).__name__}: {exc}"
                    with store.transaction():
                        store.conn.execute(
                            "UPDATE db_tables SET hints_json=?, read_error=COALESCE(?,read_error) "
                            "WHERE database_id=? AND name=? AND obj_type='table'",
                            (json.dumps(hints) if hints else None, herr, d["id"], obj.name),
                        )
                    stats.generic_tables += 1
                with store.transaction():
                    store.conn.execute("UPDATE databases SET decode_errors=? WHERE id=?", (session.decode_errors, d["id"]))
        except SQLiteOpenError as exc:
            stats.errors += 1
            with store.transaction():
                store.conn.execute(
                    "INSERT INTO scan_issues(source_id,path,issue_type,detail,stage,created_at) VALUES(?,?,?,?,?,?)",
                    (d["src_id"], d["fpath"], "extraction_error", f"could not reopen database: {exc}", "extract", utcnow()),
                )
        progress.advance()
    progress.stop()

    summaries, skipped = build_app_summaries(store, run_id)
    insert_artifacts(store, run_id, None, summaries)
    stats.app_summaries = len(summaries)
    stats.artifacts["app_summary"] += len(summaries)
    if skipped:
        with store.transaction():
            store.conn.executemany(
                "INSERT INTO scan_issues(source_id,path,issue_type,detail,stage,created_at) VALUES(NULL,?,?,?,?,?)",
                [(p, "xml_skipped", reason, "extract", utcnow()) for p, reason in skipped],
            )
    return stats
