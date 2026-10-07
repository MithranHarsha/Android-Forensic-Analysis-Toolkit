"""Review 2 pipeline stages: recover, carve, correlate, reconstruct (Phase 9).

Each stage reads only what an earlier stage persisted to the case database -- never another stage's in-memory state -- so any
stage can be re-run by itself and the runner's dependency-aware reset (``pipeline.runner``) stays correct. In order:

``recover``
    scans every readable database's main file (and its ``-wal`` / ``-journal`` if preserved) for deleted and superseded
    records, and persists them as ``recovered_records`` / ``unrecovered_regions``, plus the ``wal_frames`` and
    ``freelist_pages`` tables the report and dashboard read from.
``carve``
    finds pattern candidates in the free space of every database (excluding structure, live cells and rows ``recover`` already
    reported) and in every other preserved file, and persists them as ``carved_candidates`` -- unscored, status
    ``CARVED CANDIDATE``.
``correlate``
    builds the evidence graph over active artifacts, *draft* reconstructions of the not-yet-scored recovered records, and the
    carved candidates; writes each recovered record's corroboration sentences (for the scorer) and scores every carved
    candidate (which never becomes an artifact, so this is also where its confidence is decided).
``reconstruct``
    turns each recovered record into its typed artifact (or a ``GenericRecord``), scored with the sentences ``correlate``
    wrote; then runs correlation a second time over the now-complete set of stored artifacts and carved candidates, and
    persists the final graph to ``correlations``.

Neither ``validate`` nor ``timeline`` requires these stages: a Review 1 pipeline (``scan``, ``extract``, ``validate``,
``timeline``) runs exactly as before and reports no recovery, matching the tool's Review 1 behaviour (D-007). The full
pipeline runs recovery between ``extract`` and ``validate`` so validation and the timeline see recovered artifacts too.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from android_forensics.artifacts.recovered import DatabaseContext, reconstruct, record_from_row
from android_forensics.carving import (
    CarveSource,
    carve_database_file,
    carve_file,
    journal_exclusions,
    main_file_exclusions,
    wal_exclusions,
)
from android_forensics.confidence.scorer import CarveEvidence, score_carved
from android_forensics.correlation import FileInfo, Subject, build_correlation, database_of
from android_forensics.models import CarvedCandidate, EvidenceFile
from android_forensics.models import UnrecoveredRegion as StoredUnrecoveredRegion
from android_forensics.pipeline.parallel import ordered_map, resolve_workers
from android_forensics.sqlite.discovery import preserved_path, sidecar_rows
from android_forensics.sqlite.journal import parse_journal
from android_forensics.sqlite.parser import SQLiteDatabase
from android_forensics.sqlite.recover_db import recover_database
from android_forensics.sqlite.recovery import build_models
from android_forensics.sqlite.wal import parse_wal
from android_forensics.storage.artifact_writer import insert_artifact_uncommitted
from android_forensics.storage.case_store import CaseStore, utcnow
from android_forensics.storage.recovery_store import (
    insert_carved,
    insert_edges,
    insert_recovered,
    insert_unrecovered,
    link_artifact,
    load_carved,
    load_recovered,
    update_carved_scoring,
)
from android_forensics.util import require

_SIDECAR_SUFFIXES = ("-wal", "-journal")


def _issue(store: CaseStore, source_id: int | None, path: str, issue_type: str, detail: str, stage: str) -> None:
    with store.transaction():
        store.conn.execute(
            "INSERT INTO scan_issues(source_id,path,issue_type,detail,stage,created_at) VALUES(?,?,?,?,?,?)",
            (source_id, path, issue_type, detail, stage, utcnow()),
        )


def _preserved(store: CaseStore, f: EvidenceFile) -> Path | None:
    return None if f.preserved_copy is None else store.evidence_dir / f"s{f.source_id}" / f.preserved_copy


def _open_databases(store: CaseStore):
    return store.q(
        "SELECT d.*, f.path AS fpath, f.sha256 AS fsha, f.source_id AS src_id, f.id AS fid FROM databases d "
        "JOIN evidence_files f ON f.id=d.evidence_file_id WHERE d.header_valid=1 ORDER BY d.id"
    )


# ------------------------------------------------------------------ recover


def _task_size(task) -> float:
    """Scheduling hint: bigger files first. Never affects results or their order."""
    try:
        return float(task[0].stat().st_size)
    except OSError:
        return 0.0


def _recover_worker(task: tuple[Path, dict[str, Path], Path]):
    """Runs in a worker process: recovery of one database. Returns the report, or the error text (never raises)."""
    main_path, sidecar_paths, scratch = task
    try:
        return recover_database(main_path, sidecar_paths, scratch=scratch), None
    except Exception as exc:  # one damaged database must not stop the run
        return None, f"{type(exc).__name__}: {exc}"


def _recover(store: CaseStore, run_id: int, o) -> dict[str, Any]:
    stats: Counter = Counter()
    dbs = _open_databases(store)
    o.progress.start("Recovering deleted records", len(dbs))
    prepared: list[tuple[Any, Any, Path | None, dict[str, Path], dict[str, Any]]] = []
    for d in dbs:
        frow = store.one("SELECT * FROM evidence_files WHERE id=?", (d["fid"],))
        main_path = preserved_path(store, frow)
        sidecar_recs = sidecar_rows(store, frow) if main_path is not None else {}
        sidecar_paths = {suf: p for suf in _SIDECAR_SUFFIXES if suf in sidecar_recs
                         and (p := preserved_path(store, sidecar_recs[suf])) is not None}
        prepared.append((d, frow, main_path, sidecar_paths, sidecar_recs))
    tasks = [(mp, sp, store.scratch_dir) for _d, _f, mp, sp, _r in prepared if mp is not None]
    results = ordered_map(_recover_worker, tasks, resolve_workers(getattr(o, "workers", 1)), cost=_task_size)
    for d, frow, main_path, sidecar_paths, sidecar_recs in prepared:
        if main_path is None:
            stats["skipped_no_working_copy"] += 1
            _issue(store, d["src_id"], d["fpath"], "recovery_skipped",
                  "no working copy preserved: recovery reads raw file bytes and cannot run on hashes alone", "recover")
            o.progress.advance()
            continue
        report, error = next(results)
        if report is None:
            stats["errors"] += 1
            _issue(store, d["src_id"], d["fpath"], "recovery_error", error or "unknown error", "recover")
            o.progress.advance()
            continue
        file_for_source = {"main": (d["fid"], d["fsha"])}
        for suf, key in (("-wal", "wal"), ("-journal", "journal")):
            if suf in sidecar_recs:
                file_for_source[key] = (sidecar_recs[suf]["id"], sidecar_recs[suf]["sha256"])
        records = [
            record_from_row(row, database_file_id=d["fid"], source_file_id=fid, source_sha256=sha, database_id=d["id"])
            for row in report.rows
            if (loc := file_for_source.get(row.source)) is not None
            for fid, sha in (loc,)
        ]
        insert_recovered(store, run_id, records)
        for r in records:
            stats[f"recovered_{r.status.value.lower()}"] += 1
        regions = [
            StoredUnrecoveredRegion(database_id=d["id"], source=u.source, source_path=u.source_path, page_number=u.page_number,
                                    page_offset=u.page_offset, file_offset=u.file_offset, length=u.length, region=u.region,
                                    reason=u.reason, raw_sha256=hashlib.sha256(u.raw).hexdigest(), frame=u.frame)
            for u in report.unrecovered if file_for_source.get(u.source) is not None
        ]
        insert_unrecovered(store, run_id, regions)
        stats["unrecovered_regions"] += len(regions)
        if "-wal" in sidecar_paths:
            wal_info = parse_wal(sidecar_paths["-wal"], expected_page_size=d["page_size"])
            with store.transaction():
                for f in wal_info.frames:
                    store.insert("wal_frames", {"run_id": run_id, "database_id": d["id"], "frame_index": f.index,
                                                "file_offset": f.offset, "page_number": f.page_number,
                                                "commit_size": f.commit_size, "status": f.status})
        with SQLiteDatabase.open(main_path) as db:
            fl = db.freelist()
        with store.transaction():
            for role, pages in (("trunk", fl.trunks), ("leaf", fl.leaves)):
                for page_no in pages:
                    store.insert("freelist_pages", {"run_id": run_id, "database_id": d["id"], "page_number": page_no, "role": role})
        stats["databases_attempted"] += 1
        o.progress.advance()
    o.progress.stop()
    return dict(stats)


def _reset_recover(store: CaseStore) -> None:
    store.clear_tables("recovered_records", "unrecovered_regions", "wal_frames", "freelist_pages")
    with store.transaction():
        store.conn.execute("DELETE FROM scan_issues WHERE stage='recover'")


# ------------------------------------------------------------------ carve

_CARVE_SKIP_KINDS = {"image", "video", "audio", "apk", "archive", "encrypted_suspect", "empty"}


def _persist(store: CaseStore, run_id: int, candidates: list[CarvedCandidate]) -> None:
    if candidates:
        insert_carved(store, run_id, candidates)


def _carve_worker(task):
    """Runs in a worker process: carve one preserved file with its exclusions. Returns (candidates, None) or (None, error text)."""
    path, source, exclusions, now, is_database = task
    try:
        result = carve_database_file(path, source, exclusions, now=now) if is_database else carve_file(path, source, now=now)
        return result.candidates, None
    except Exception as exc:  # noqa: BLE001 - one unreadable file must not stop the stage
        return None, f"{type(exc).__name__}: {exc}"


def _carve(store: CaseStore, run_id: int, o) -> dict[str, Any]:
    stats: Counter = Counter()
    dbs = _open_databases(store)
    handled: set[int] = set()
    o.progress.start("Preparing carving", len(dbs))
    # Phase 1 (one process, needs the case database): decide *what* to carve and *what to leave out*, in a fixed order.
    units: list[dict[str, Any]] = []
    for d in dbs:
        frow = store.one("SELECT * FROM evidence_files WHERE id=?", (d["fid"],))
        main_path = preserved_path(store, frow)
        handled.add(d["fid"])
        if main_path is None:
            stats["skipped_no_working_copy"] += 1
            o.progress.advance()
            continue
        sidecar_recs = sidecar_rows(store, frow)
        handled.update(sidecar_recs[s_]["id"] for s_ in ("-wal", "-journal", "-shm") if s_ in sidecar_recs)
        recovered_main = [(r["file_offset"], r["length"]) for r in store.q(
            "SELECT file_offset, length FROM recovered_records WHERE database_file_id=? AND source='main'", (d["fid"],))]
        try:
            wal_path = preserved_path(store, sidecar_recs["-wal"]) if "-wal" in sidecar_recs else None
            wal_info = parse_wal(wal_path, expected_page_size=d["page_size"]) if wal_path and wal_path.stat().st_size else None
            with SQLiteDatabase.open(main_path) as db:
                ex = main_file_exclusions(db, wal_info, recovered_main)
        except Exception as exc:
            stats["errors"] += 1
            _issue(store, d["src_id"], d["fpath"], "carve_error", f"{type(exc).__name__}: {exc}", "carve")
            o.progress.advance()
            continue
        units.append({"path": main_path, "source": CarveSource(d["fid"], d["fpath"], require(frow, "evidence file row")["sha256"]), "ex": ex, "db": True,
                      "count": "databases_carved", "error": None})
        if wal_info is not None:
            wr = sidecar_recs["-wal"]
            wal_ranges = [(r["file_offset"], r["length"]) for r in store.q(
                "SELECT file_offset, length FROM recovered_records WHERE source_file_id=? AND source='wal'", (wr["id"],))]
            with SQLiteDatabase.open(main_path) as db:
                wex = wal_exclusions(wal_info, db, wal_ranges)
            units.append({"path": wal_path, "source": CarveSource(wr["id"], wr["path"], wr["sha256"]), "ex": wex, "db": True,
                          "count": None, "error": None})
        if "-journal" in sidecar_recs:
            jr = sidecar_recs["-journal"]
            journal_path = preserved_path(store, jr)
            if journal_path and journal_path.stat().st_size:
                try:
                    journal_info = parse_journal(journal_path, db_page_size=d["page_size"])
                    j_ranges = [(r["file_offset"], r["length"]) for r in store.q(
                        "SELECT file_offset, length FROM recovered_records WHERE source_file_id=? AND source='journal'", (jr["id"],))]
                    with SQLiteDatabase.open(main_path) as db:
                        jex = journal_exclusions(journal_info, db, j_ranges)
                    units.append({"path": journal_path, "source": CarveSource(jr["id"], jr["path"], jr["sha256"]), "ex": jex, "db": True,
                                  "count": None, "error": (d["src_id"], jr["path"])})
                except Exception as exc:
                    stats["errors"] += 1
                    _issue(store, d["src_id"], jr["path"], "carve_error", f"{type(exc).__name__}: {exc}", "carve")
        o.progress.advance()
    o.progress.stop()

    others = [f for f in store.evidence_files() if f.id not in handled and f.kind.value not in _CARVE_SKIP_KINDS and f.is_preserved]
    for f in others:
        units.append({"path": _preserved(store, f), "source": CarveSource(require(f.id, "evidence file id"), f.path, f.hashes.sha256), "ex": None, "db": False,
                      "count": "files_carved", "error": None})

    # Phase 2: the byte scanning, spread over worker processes; Phase 3: results written back in the original order.
    o.progress.start("Carving", len(units))
    tasks = [(u["path"], u["source"], u["ex"], o.now, u["db"]) for u in units]
    for unit, (candidates, error) in zip(units, ordered_map(_carve_worker, tasks, resolve_workers(getattr(o, "workers", 1)), cost=_task_size)):
        if candidates is None:
            stats["errors"] += 1
            src = unit["error"] or (None, unit["source"].source_file)
            _issue(store, src[0], src[1], "carve_error", error or "unknown error", "carve")
        else:
            _persist(store, run_id, candidates)
            stats["candidates"] += len(candidates)
            if unit["count"]:
                stats[unit["count"]] += 1
        o.progress.advance()
    o.progress.stop()
    return dict(stats)


def _reset_carve(store: CaseStore) -> None:
    store.clear_tables("carved_candidates")
    with store.transaction():
        store.conn.execute("DELETE FROM scan_issues WHERE stage='carve'")


# ------------------------------------------------------------------ shared: the graph's file map and a recovered record's context


def _file_infos(store: CaseStore) -> dict[int, FileInfo]:
    rows = store.q("SELECT f.id AS fid, f.path AS fpath, f.package AS pkg, d.id AS did FROM evidence_files f "
                   "LEFT JOIN databases d ON d.evidence_file_id=f.id")
    out: dict[int, FileInfo] = {r["fid"]: FileInfo(r["fid"], r["fpath"], "database" if r["did"] is not None else "file", r["pkg"])
                                for r in rows}
    db_paths = {v.path for v in out.values() if v.kind == "database"}
    for fid, info in list(out.items()):
        if info.kind == "file" and info.path != database_of(info.path) and database_of(info.path) in db_paths:
            out[fid] = FileInfo(fid, info.path, "sidecar", info.application)
    return out


def _database_context(store: CaseStore, database_file_id: int) -> DatabaseContext | None:
    d = store.one("SELECT id, page_size FROM databases WHERE evidence_file_id=?", (database_file_id,))
    frow = store.one("SELECT * FROM evidence_files WHERE id=?", (database_file_id,))
    if d is None or frow is None:
        return None
    main_path = preserved_path(store, frow)
    if main_path is None:
        return None
    with SQLiteDatabase.open(main_path) as db:
        models = build_models(db)
    wal_status = {r["frame_index"]: r["status"] for r in store.q(
        "SELECT frame_index, status FROM wal_frames WHERE database_id=?", (d["id"],))}
    return DatabaseContext(database_file_id, frow["path"], frow["sha256"], frow["package"], models, wal_frame_status=wal_status)


def _load_active_subjects(store: CaseStore) -> list[Subject]:
    subjects = []
    for row in store.q("SELECT id FROM artifacts WHERE artifact_type != 'app_summary' ORDER BY id"):
        art = store.get_artifact(row["id"])
        # keep only what correlation reads: at a million artifacts the parsed models alone would need ~15 GB
        subjects.append(Subject.slim(f"artifact:{row['id']}", art, "active",
                                     art.provenance.source_database or art.provenance.source_file, art.provenance.evidence_file_id))
    return subjects


def _recovered_drafts(store: CaseStore) -> tuple[list[Subject], dict[str, int]]:
    """Draft artifacts (unscored, never persisted) of every recovered record not yet reconstructed, for correlation only."""
    subjects: list[Subject] = []
    record_id_by_ref: dict[str, int] = {}
    contexts: dict[int, DatabaseContext | None] = {}
    for record in load_recovered(store, "artifact_id IS NULL"):
        ctx = contexts.setdefault(record.database_file_id, _database_context(store, record.database_file_id))
        if ctx is None:
            continue
        draft = reconstruct(record, ctx)
        ref = f"recovered:{record.id}"
        subjects.append(Subject.slim(ref, draft, "recovered", ctx.database_path, record.database_file_id, record.source_file_id))
        record_id_by_ref[ref] = require(record.id, "recovered record id")
    return subjects, record_id_by_ref


# ------------------------------------------------------------------ correlate


def _correlate(store: CaseStore, run_id: int, o) -> dict[str, Any]:
    files = _file_infos(store)
    active = _load_active_subjects(store)
    drafts, record_id_by_ref = _recovered_drafts(store)
    carved = list(load_carved(store))
    corr = build_correlation(active + drafts, carved, files)

    with store.transaction():
        for ref, record_id in record_id_by_ref.items():
            store.conn.execute("UPDATE recovered_records SET corroboration_json=? WHERE id=?",
                              (json.dumps(list(corr.for_ref(ref).sources)), record_id))
        for c in carved:
            corrb = corr.for_ref(f"carved:{c.id}")
            evidence = CarveEvidence(kind=c.kind.value, context_valid=c.context_valid, value_valid=True,
                                     corroborations=corrb.sources, inside_known_structure=c.container == "sqlite_free_space")
            assessment = score_carved(evidence)
            artifact_ids = sorted({int(t.split(":", 1)[1]) for t in corrb.targets if t.startswith("artifact:")})
            scored = CarvedCandidate(**{**c.model_dump(), "confidence": assessment.level, "confidence_factors": assessment.factors,
                                        "explanation": assessment.explanation, "corroborated_by": artifact_ids,
                                        "notes": list(corrb.notes)})
            update_carved_scoring(store, require(c.id, "carved candidate id"), scored)
    return {
        "recovered_drafts": len(drafts), "carved_scored": len(carved), "active_subjects": len(active),
        "recovered_corroborated": sum(1 for ref in record_id_by_ref if corr.for_ref(ref).corroborated),
        "carved_corroborated": sum(1 for c in carved if corr.for_ref(f"carved:{c.id}").corroborated),
    }


def _reset_correlate(store: CaseStore) -> None:
    with store.transaction():
        store.conn.execute("UPDATE recovered_records SET corroboration_json='[]'")
        store.conn.execute(
            "UPDATE carved_candidates SET confidence=NULL, confidence_factors_json='[]', explanation='', "
            "corroborated_by_json='[]', notes_json='[]'"
        )


# ------------------------------------------------------------------ reconstruct


def _reconstruct(store: CaseStore, run_id: int, o) -> dict[str, Any]:
    stats: Counter = Counter()
    contexts: dict[int, DatabaseContext | None] = {}
    now, pending = utcnow(), 0
    for record in list(load_recovered(store, "artifact_id IS NULL")):
        ctx = contexts.setdefault(record.database_file_id, _database_context(store, record.database_file_id))
        if ctx is None:
            stats["skipped_no_context"] += 1
            continue
        sources = tuple(json.loads(store.scalar("SELECT corroboration_json FROM recovered_records WHERE id=?", (record.id,)) or "[]"))
        artifact = reconstruct(record, ctx, sources)
        link_artifact(store, require(record.id, "recovered record id"), insert_artifact_uncommitted(store, run_id, record.database_id, artifact, now))
        stats[f"reconstructed_{artifact.status.value.lower()}"] += 1
        pending += 1
        if pending >= 500:   # a commit (an fsync) per record was the slowest thing in the whole pipeline on some platforms
            store.conn.commit()
            pending = 0
    store.conn.commit()

    files = _file_infos(store)
    active = _load_active_subjects(store)
    carved = list(load_carved(store))
    corr = build_correlation(active, carved, files)
    stats["correlation_edges"] = insert_edges(store, run_id, corr.graph.iter_edges())
    return dict(stats)


def _reset_reconstruct(store: CaseStore) -> None:
    with store.transaction():
        store.conn.execute("UPDATE recovered_records SET artifact_id=NULL")  # drop every reference before the artifact goes
        ids = [r[0] for r in store.q("SELECT id FROM artifacts WHERE status IN ('RECOVERED','PARTIAL','CORRUPTED')")]
        if ids:
            placeholders = ",".join("?" * len(ids))
            for table in ("messages", "calls", "contacts", "browser_history"):
                store.conn.execute(f"DELETE FROM {table} WHERE artifact_id IN ({placeholders})", ids)
            store.conn.execute(f"DELETE FROM timeline_events WHERE artifact_id IN ({placeholders})", ids)
            store.conn.execute(f"DELETE FROM artifacts WHERE id IN ({placeholders})", ids)
        store.conn.execute("DELETE FROM correlations")


__all__ = [
    "_carve", "_correlate", "_reconstruct", "_recover",
    "_reset_carve", "_reset_correlate", "_reset_reconstruct", "_reset_recover",
]
