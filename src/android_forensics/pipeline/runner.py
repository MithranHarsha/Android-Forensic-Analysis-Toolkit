"""Stage runner.

Each stage declares what it depends on and how to clear its own derived data, so re-running a stage is idempotent and
automatically invalidates only what was built on top of it. Review 2's four stages (``recover``, ``carve``, ``correlate``,
``reconstruct``; see ``pipeline.recovery_stages``) are registered here and can be run by name, but are not part of the
default pipeline: ``run_pipeline(store)`` with no ``names`` still runs exactly Review 1's ``scan`` / ``extract`` / ``validate``
/ ``timeline``, so nothing about Review 1's behaviour changes unless recovery is asked for by name (``FULL_PIPELINE_NAMES``).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from android_forensics.artifacts.extract import run_extraction
from android_forensics.filesystem.scanner import scan_filesystem
from android_forensics.pipeline.recovery_stages import (
    _carve,
    _correlate,
    _reconstruct,
    _recover,
    _reset_carve,
    _reset_correlate,
    _reset_reconstruct,
    _reset_recover,
)
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
    workers: int | str = 1  # processes for the per-database recovery / carving stages; results are identical to a serial run


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


ALL_STAGES: list[Stage] = [
    Stage("scan", "Filesystem analysis and SQLite discovery", _scan, _reset_scan),
    Stage("extract", "Active artifact extraction and normalisation", _extract, _reset_extract, requires=("scan",)),
    Stage("recover", "Deleted / superseded SQLite record recovery", _recover, _reset_recover, requires=("scan",)),
    Stage("carve", "Raw pattern carving outside structured records", _carve, _reset_carve, requires=("recover",)),
    Stage("correlate", "Evidence graph and corroboration for recovery/carving", _correlate, _reset_correlate,
         requires=("extract", "carve")),
    Stage("reconstruct", "Recovered records -> scored artifacts; final evidence graph", _reconstruct, _reset_reconstruct,
         requires=("correlate",)),
    Stage("validate", "Automated validation", _validate, lambda s: s.clear_tables("validation_results"), requires=("extract",)),
    Stage("timeline", "Unified timeline", _timeline, lambda s: s.clear_tables("timeline_events"), requires=("extract",)),
]
BY_NAME = {s.name: s for s in ALL_STAGES}

# The default pipeline (``run_pipeline`` with no explicit ``names``) is exactly Review 1's four stages: recovery is opt-in,
# requested by name (``run_stage(store, "recover")``) or via an explicit stage list (the CLI's ``analyze`` uses one that
# includes ``recover``/``carve``/``correlate``/``reconstruct`` unless ``--no-recover`` is given). This is what keeps every
# Review 1 result unchanged when nothing asks for recovery (D-007).
PIPELINE: list[Stage] = [s for s in ALL_STAGES if s.name in ("scan", "extract", "validate", "timeline")]
RECOVERY_STAGE_NAMES: tuple[str, ...] = ("recover", "carve", "correlate", "reconstruct")
FULL_PIPELINE_NAMES: tuple[str, ...] = ("scan", "extract", "recover", "carve", "correlate", "reconstruct", "validate", "timeline")


def _dependents(name: str) -> list[str]:
    """Every stage that (transitively) requires ``name``, across *all* registered stages -- not just the default pipeline --
    so resetting a stage correctly invalidates recovery stages too, whether or not they are part of this run."""
    out = [name]
    changed = True
    while changed:
        changed = False
        for s in ALL_STAGES:
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
    log = logging.getLogger("android_forensics.pipeline")
    log.info("stage started", extra={"fields": {"stage": name, "case": store.case_id, "run_id": run_id}})
    try:
        stats = stage.run(store, run_id, options)
    except BaseException as exc:
        store.finish_run(run_id, "FAILED", error=f"{type(exc).__name__}: {exc}")
        log.error("stage failed", extra={"fields": {"stage": name, "case": store.case_id, "error": f"{type(exc).__name__}: {exc}"}})
        raise
    stats["seconds"] = round(time.monotonic() - t0, 3)
    log.info("stage completed", extra={"fields": {"stage": name, "case": store.case_id, "seconds": stats["seconds"],
                                                  **{k: v for k, v in stats.items() if isinstance(v, (int, float, str))}}})
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
