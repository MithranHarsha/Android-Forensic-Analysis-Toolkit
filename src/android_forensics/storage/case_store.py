"""Per-case SQLite store: schema, typed access to the core models, runs and a hash-chained custody log."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from android_forensics import TOOL_NAME, __version__
from android_forensics.errors import CaseError
from android_forensics.models import (
    AnalysisRun,
    Artifact,
    Case,
    EvidenceFile,
    EvidenceSource,
    RunStatus,
    SourceLayout,
    TimelineEvent,
    ValidationResult,
)
from android_forensics.storage.schema import MIGRATIONS
from android_forensics.util import now_iso
from android_forensics.workspace import Workspace

GENESIS_HASH = "0" * 64


def utcnow() -> str:
    return now_iso()


class CaseStore:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir.resolve()
        self.workspace = Workspace(self.case_dir)
        self.db_path = self.case_dir / "case.db"
        if not self.db_path.is_file():
            raise CaseError(f"Not a case directory (case.db missing): {case_dir}")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    @property
    def manifest_path(self) -> Path:
        return self.workspace.manifest_path

    @property
    def evidence_dir(self) -> Path:
        return self.workspace.evidence_dir

    @property
    def scratch_dir(self) -> Path:
        return self.workspace.scratch_dir

    @property
    def reports_dir(self) -> Path:
        return self.workspace.reports_dir

    @classmethod
    def create(
        cls,
        case_dir: Path,
        name: str,
        examiner: str | None = None,
        description: str | None = None,
    ) -> CaseStore:
        case_dir = case_dir.resolve()
        if (case_dir / "case.db").exists():
            raise CaseError(f"A case already exists at {case_dir}")
        Workspace(case_dir).create()
        boot = sqlite3.connect(case_dir / "case.db")
        boot.close()
        store = cls(case_dir)
        case = Case(id=uuid.uuid4().hex, name=name, examiner=examiner, description=description,
                    created_at=utcnow(), tool_version=__version__)
        with store.transaction():
            store.insert("cases", case.to_record())
        store.log("case_created", name, {"examiner": examiner, "description": description})
        return store

    @classmethod
    def open(cls, case_dir: Path) -> CaseStore:
        return cls(case_dir)

    @staticmethod
    def is_case_dir(path: Path) -> bool:
        return (path / "case.db").is_file()

    def close(self) -> None:
        self.conn.close()

    def _migrate(self) -> None:
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations("
            "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL, description TEXT)"
        )
        applied = {r[0] for r in self.conn.execute("SELECT version FROM schema_migrations")}
        for version, description, sql in MIGRATIONS:
            if version in applied:
                continue
            self.conn.executescript("BEGIN;\n" + sql + "\nCOMMIT;")
            self.conn.execute(
                "INSERT INTO schema_migrations VALUES(?,?,?)", (version, utcnow(), description)
            )
            self.conn.commit()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.conn
        except BaseException:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    # ------------------------------------------------------------------ raw access

    def q(self, sql: str, params: Sequence[Any] | Mapping[str, Any] = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: Sequence[Any] | Mapping[str, Any] = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: Sequence[Any] | Mapping[str, Any] = ()) -> Any:
        row = self.conn.execute(sql, params).fetchone()
        return row[0] if row else None

    def insert(self, table: str, record: Mapping[str, Any]) -> int:
        """INSERT one flat record (as produced by a model's ``to_record``). Table/column names are internal constants."""
        cols = ", ".join(record)
        marks = ", ".join(f":{c}" for c in record)
        return int(self.conn.execute(f"INSERT INTO {table}({cols}) VALUES({marks})", dict(record)).lastrowid or 0)

    def insert_many(self, table: str, records: Sequence[Mapping[str, Any]]) -> None:
        if not records:
            return
        cols = ", ".join(records[0])
        marks = ", ".join(f":{c}" for c in records[0])
        self.conn.executemany(f"INSERT INTO {table}({cols}) VALUES({marks})", [dict(r) for r in records])

    # ------------------------------------------------------------------ case

    def case(self) -> Case:
        row = self.one("SELECT * FROM cases LIMIT 1")
        if row is None:
            raise CaseError("Case record missing")
        return Case.from_record(row)

    @property
    def case_id(self) -> str:
        return self.case().id

    def set_layouts(self, overall: str, layouts: Mapping[int, SourceLayout]) -> None:
        detail = json.dumps({str(k): v.model_dump() for k, v in layouts.items()})
        with self.transaction():
            self.conn.execute("UPDATE cases SET layout=?, layout_detail=?", (overall, detail))

    # ------------------------------------------------------------------ evidence

    def add_source(self, source: EvidenceSource) -> int:
        with self.transaction():
            return self.insert("evidence_sources", source.to_record())

    def update_source_totals(self, source_id: int, file_count: int, total_bytes: int, complete: bool) -> None:
        with self.transaction():
            self.conn.execute(
                "UPDATE evidence_sources SET file_count=?, total_bytes=?, complete=? WHERE id=?",
                (file_count, total_bytes, int(complete), source_id),
            )

    def sources(self) -> list[EvidenceSource]:
        return [EvidenceSource.from_record(r) for r in self.q("SELECT * FROM evidence_sources ORDER BY id")]

    def add_files(self, files: Sequence[EvidenceFile]) -> None:
        with self.transaction():
            self.insert_many("evidence_files", [f.to_record() for f in files])

    def evidence_files(self, source_id: int | None = None) -> Iterator[EvidenceFile]:
        sql = "SELECT * FROM evidence_files" + (" WHERE source_id=?" if source_id is not None else "") + " ORDER BY source_id, ordinal"
        cur = self.conn.execute(sql, () if source_id is None else (source_id,))
        for row in cur:
            yield EvidenceFile.from_record(row)

    def get_file(self, file_id: int) -> EvidenceFile:
        row = self.one("SELECT * FROM evidence_files WHERE id=?", (file_id,))
        if row is None:
            raise CaseError(f"No evidence file {file_id}")
        return EvidenceFile.from_record(row)

    # ------------------------------------------------------------------ runs

    def start_run(self, stage: str, params: dict[str, Any] | None = None) -> int:
        run = AnalysisRun(case_id=self.case_id, stage=stage, started_at=utcnow(), tool_version=__version__, params=params or {})
        with self.transaction():
            return self.insert("analysis_runs", run.to_record())

    def get_run(self, run_id: int) -> AnalysisRun:
        row = self.one("SELECT * FROM analysis_runs WHERE id=?", (run_id,))
        if row is None:
            raise CaseError(f"No analysis run {run_id}")
        return AnalysisRun.from_record(row)

    def finish_run(
        self, run_id: int, status: str | RunStatus, stats: dict[str, Any] | None = None, error: str | None = None
    ) -> AnalysisRun:
        done = self.get_run(run_id).finished(RunStatus(status), utcnow(), stats, error)
        record = done.to_record()
        with self.transaction():
            self.conn.execute(
                "UPDATE analysis_runs SET finished_at=?, status=?, stats_json=?, error=? WHERE id=?",
                (record["finished_at"], record["status"], record["stats_json"], record["error"], run_id),
            )
        return done

    def runs(self) -> list[AnalysisRun]:
        return [AnalysisRun.from_record(r) for r in self.q("SELECT * FROM analysis_runs ORDER BY id")]

    def last_run(self, stage: str) -> AnalysisRun | None:
        row = self.one(
            "SELECT * FROM analysis_runs WHERE stage=? AND status='COMPLETED' ORDER BY id DESC LIMIT 1", (stage,)
        )
        return None if row is None else AnalysisRun.from_record(row)

    # ------------------------------------------------------------------ results

    def add_validation_results(self, run_id: int, results: Iterable[ValidationResult]) -> int:
        now = utcnow()
        records = [r.model_copy(update={"run_id": run_id, "created_at": r.created_at or now}).to_record() for r in results]
        with self.transaction():
            self.insert_many("validation_results", records)
        return len(records)

    def add_timeline_events(self, run_id: int, events: Iterable[TimelineEvent]) -> int:
        records = [e.model_copy(update={"run_id": run_id}).to_record() for e in events]
        with self.transaction():
            self.insert_many("timeline_events", records)
        return len(records)

    def get_artifact(self, artifact_id: int) -> Artifact:
        row = self.one("SELECT * FROM artifacts WHERE id=?", (artifact_id,))
        if row is None:
            raise CaseError(f"No artifact {artifact_id}")
        return Artifact.from_record(row)

    # ------------------------------------------------------------------ custody

    def log(self, action: str, target: str | None = None, detail: dict[str, Any] | None = None) -> None:
        """Append a hash-chained chain-of-custody entry (each entry commits to the previous one)."""
        prev = self.scalar("SELECT entry_hash FROM custody_log ORDER BY id DESC LIMIT 1") or GENESIS_HASH
        ts = utcnow()
        actor = f"{TOOL_NAME} {__version__}"
        detail_json = json.dumps(detail or {}, sort_keys=True, default=str)
        material = "|".join([prev, ts, actor, action, target or "", detail_json])
        entry_hash = hashlib.sha256(material.encode()).hexdigest()
        with self.transaction():
            self.conn.execute(
                "INSERT INTO custody_log(ts,actor,action,target,detail_json,prev_hash,entry_hash) "
                "VALUES(?,?,?,?,?,?,?)",
                (ts, actor, action, target, detail_json, prev, entry_hash),
            )

    DETAIL_KEY = re.compile(r"^[a-z][a-z0-9_]{0,40}$")

    def set_detail(self, key: str, value: str) -> None:
        """Record a case detail (case number, agency, examiner credentials …). Every change is written to the custody log."""
        if not self.DETAIL_KEY.match(key):
            raise CaseError(f"invalid detail name {key!r}: use lowercase letters, digits and '_' (max 41 characters)")
        if len(value) > 4000:
            raise CaseError(f"detail {key!r} is longer than 4000 characters")
        old = self.scalar("SELECT value FROM case_details WHERE key=?", (key,))
        with self.transaction():
            self.conn.execute("INSERT INTO case_details(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                              "updated_at=excluded.updated_at", (key, value, utcnow()))
        self.log("case_detail_set", key, {"previous": old, "new": value})

    def details(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self.q("SELECT key, value FROM case_details ORDER BY key")}

    def verify_custody_chain(self) -> tuple[bool, str]:
        prev = GENESIS_HASH
        for row in self.q("SELECT * FROM custody_log ORDER BY id"):
            material = "|".join(
                [prev, row["ts"], row["actor"], row["action"], row["target"] or "", row["detail_json"] or "{}"]
            )
            if row["prev_hash"] != prev or hashlib.sha256(material.encode()).hexdigest() != row["entry_hash"]:
                return False, f"custody chain broken at entry {row['id']}"
            prev = row["entry_hash"]
        return True, "custody chain intact"

    def clear_tables(self, *tables: str) -> None:
        """Delete rows of derived-data tables (evidence tables are never passed here)."""
        with self.transaction():
            for t in tables:
                self.conn.execute(f"DELETE FROM {t}")

    def counts(self) -> dict[str, int]:
        def n(sql: str) -> int:
            return int(self.scalar(sql) or 0)

        return {
            "sources": n("SELECT COUNT(*) FROM evidence_sources"),
            "files": n("SELECT COUNT(*) FROM evidence_files"),
            "bytes": n("SELECT COALESCE(SUM(size),0) FROM evidence_files"),
            "databases": n("SELECT COUNT(*) FROM databases"),
            "sqlite_readable": n("SELECT COUNT(*) FROM databases WHERE open_status='ok'"),
            "artifacts": n("SELECT COUNT(*) FROM artifacts"),
            "active_artifacts": n("SELECT COUNT(*) FROM artifacts WHERE status='ACTIVE'"),
            "timeline_events": n("SELECT COUNT(*) FROM timeline_events"),
            "validation_results": n("SELECT COUNT(*) FROM validation_results"),
            "scan_issues": n("SELECT COUNT(*) FROM scan_issues"),
            "recovered_records": n("SELECT COUNT(*) FROM recovered_records"),
            "recovered_artifacts": n("SELECT COUNT(*) FROM artifacts WHERE status IN ('RECOVERED','PARTIAL','CORRUPTED')"),
            "carved_candidates": n("SELECT COUNT(*) FROM carved_candidates"),
            "correlation_edges": n("SELECT COUNT(*) FROM correlations"),
        }
