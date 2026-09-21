"""Stage runner.

Each stage declares what it depends on and how to clear its own derived data, so re-running a stage
is idempotent and automatically invalidates only what was built on top of it. Review 2 adds its
``recover`` / ``correlate`` stages here without touching the CLI.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from android_forensics.artifacts.extract import run_extraction
from android_forensics.filesystem.scanner import scan_filesystem
from android_forensics.progress import NullProgress, Progress
from android_forensics.sqlite.discovery import discover_databases
from android_forensics.storage.case_store import CaseError, CaseStore
from android_forensics.timeline.builder import build_timeline
from android_forensics.validation.runner import run_validation


@dataclass
class StageOptions:
    progress: Progress = field(default_factory=NullProgress)
    rehash_originals: bool = True
    timeline_files: str = "key"
    now: datetime | None = None


@dataclass(frozen=True)
class Stage:
    name: str
    description: str
    run: Callable[[CaseStore, int, StageOptions], dict[str, Any]]
    reset: Callable[[CaseStore], None]
    requires: tuple[str, ...] = ()


def _scan(store: CaseStore, run_id: int, o: StageOptions) -> dict[str, Any]:
    if not store.scalar("SELECT COUNT(*) FROM evidence_sources"):
        raise CaseError("Nothing to scan: ingest evidence first (android-forensics ingest CASE PATH)")
    fs = scan_filesystem(store, o.progress)
    ds = discover_databases(store, o.progress)
    return {
        "files": fs.files, "layout": fs.layout, "kinds": fs.kinds, "categories": fs.categories, "packages": fs.packages,
        "app_directories": fs.app_directories,
        "databases": ds.databases, "readable": ds.readable, "encrypted_suspects": ds.encrypted_suspects,
        "unreadable": ds.unreadable, "tables": ds.tables, "with_wal": ds.with_wal, "with_journal": ds.with_journal,
    }


def _extract(store: CaseStore, run_id: int, o: StageOptions) -> dict[str, Any]:
    ex = run_extraction(store, run_id, o.progress, o.now)
    return {"databases": ex.databases, "tables_matched": ex.tables_matched, "artifacts": dict(ex.artifacts),
            "total": ex.total, "generic_tables": ex.generic_tables, "errors": ex.errors}


def _validate(store: CaseStore, run_id: int, o: StageOptions) -> dict[str, Any]:
    v = run_validation(store, run_id, o.progress, o.rehash_originals)
    return {"total": v.total, "by_status": dict(v.by_status)}


def _timeline(store: CaseStore, run_id: int, o: StageOptions) -> dict[str, Any]:
    t = build_timeline(store, run_id, o.timeline_files)
    return {"artifact_events": t.artifact_events, "file_events": t.file_events, "total": t.total}


def _reset_scan(store: CaseStore) -> None:
    store.clear_tables("db_tables", "databases", "app_directories")
    with store.transaction():
        store.conn.execute("DELETE FROM scan_issues WHERE stage='scan'")


def _reset_extract(store: CaseStore) -> None:
    store.clear_tables("messages", "calls", "contacts", "browser_history", "artifacts")
    with store.transaction():
        store.conn.execute("UPDATE db_tables SET parsed_by=NULL, schema_variant=NULL, schema_score=NULL, hints_json=NULL")
        store.conn.execute("DELETE FROM scan_issues WHERE stage='extract'")


PIPELINE: list[Stage] = [
    Stage("scan", "Filesystem analysis and SQLite discovery", _scan, _reset_scan),
    Stage("extract", "Active artifact extraction and normalisation", _extract, _reset_extract, requires=("scan",)),
    Stage("validate", "Automated validation", _validate, lambda s: s.clear_tables("validation_results"), requires=("extract",)),
    Stage("timeline", "Unified timeline", _timeline, lambda s: s.clear_tables("timeline_events"), requires=("extract",)),
]
BY_NAME = {s.name: s for s in PIPELINE}


def _dependents(name: str) -> list[str]:
    out = [name]
    changed = True
    while changed:
        changed = False
        for s in PIPELINE:
            if s.name not in out and any(r in out for r in s.requires):
                out.append(s.name)
                changed = True
    return out


def run_stage(store: CaseStore, name: str, options: StageOptions | None = None) -> dict[str, Any]:
    if name not in BY_NAME:
        raise CaseError(f"unknown stage '{name}' (available: {', '.join(BY_NAME)})")
    stage = BY_NAME[name]
    options = options or StageOptions()
    for req in stage.requires:
        if store.last_run(req) is None:
            raise CaseError(f"stage '{name}' requires '{req}' to have completed — run it first")
    for dep in reversed(_dependents(name)):
        BY_NAME[dep].reset(store)
    run_id = store.start_run(name, {"timeline_files": options.timeline_files, "rehash_originals": options.rehash_originals})
    t0 = time.monotonic()
    try:
        stats = stage.run(store, run_id, options)
    except BaseException as exc:
        store.finish_run(run_id, "FAILED", error=f"{type(exc).__name__}: {exc}")
        raise
    stats["seconds"] = round(time.monotonic() - t0, 3)
    store.finish_run(run_id, "COMPLETED", stats)
    store.log(f"stage_{name}_completed", None, {k: v for k, v in stats.items() if not isinstance(v, (dict, list))})
    return stats


def run_pipeline(store: CaseStore, names: list[str] | None = None, options: StageOptions | None = None,
                 on_stage: Callable[[str, dict[str, Any]], None] | None = None) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for name in names or [s.name for s in PIPELINE]:
        results[name] = run_stage(store, name, options)
        if on_stage:
            on_stage(name, results[name])
    return results
