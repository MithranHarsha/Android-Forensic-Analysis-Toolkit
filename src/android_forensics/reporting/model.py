"""Assemble the report model from the case store. Every artifact row carries its provenance."""

from __future__ import annotations

import json
import platform
import sqlite3
import sys
from collections import Counter
from typing import Any

from pydantic import BaseModel, Field

from android_forensics import TOOL_NAME, __version__
from android_forensics.config import HTML_ROW_CAP
from android_forensics.filesystem.android_paths import KNOWN_APPS
from android_forensics.plugins import LOADED as _LOADED_PLUGINS
from android_forensics.reporting import text
from android_forensics.storage.case_store import CaseStore, utcnow


class ReportModel(BaseModel):
    meta: dict[str, Any]
    at_a_glance: list[dict[str, Any]]
    sources: list[dict[str, Any]]
    acquisition: dict[str, Any]
    evidence_files: list[dict[str, Any]]
    artifact_summary: dict[str, Any]
    databases: list[dict[str, Any]]
    app_directories: list[dict[str, Any]]
    recovery: dict[str, Any]
    active: dict[str, dict[str, Any]]
    timeline: list[dict[str, Any]]
    validation: dict[str, Any]
    scan_issues: list[dict[str, Any]]
    table_catalog: list[dict[str, Any]]
    custody: dict[str, Any]
    provenance: dict[str, Any] = Field(default_factory=dict)
    details: dict[str, str] = Field(default_factory=dict)
    runs: list[dict[str, Any]]
    methodology: list[tuple[str, str]]
    limitations: list[str]
    disclaimer: str
    status_glossary: list[tuple[str, str]]
    html_row_cap: int = HTML_ROW_CAP
    truncation: dict[str, list[int]] = Field(default_factory=dict)


_CONF_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _short(sha: str | None) -> str:
    return (sha or "")[:16] + "…" if sha else ""


def _prov(r) -> dict[str, Any]:
    return {
        "file": r["source_file"], "sha256": r["source_sha256"], "table": r["source_table"], "rowid": r["source_rowid"],
        "wal": {1: "view: db+WAL", 0: "view: db only", None: "n/a"}[r["view_includes_wal"]],
        "page": r["page_number"], "offset": r["byte_offset"], "method": r["extraction_method"],
        "parser": f"{r['parser']} {r['parser_version']}", "variant": r["schema_variant"], "score": r["schema_match_score"],
    }


def _recovered_rows(store: CaseStore, status: str) -> list[dict[str, Any]]:
    rows = []
    for r in store.q(
        "SELECT rr.*, a.confidence AS a_confidence, a.validation_notes_json AS a_notes, a.summary AS a_summary "
        "FROM recovered_records rr LEFT JOIN artifacts a ON a.id = rr.artifact_id WHERE rr.status=? ORDER BY rr.id", (status,)
    ):
        notes = json.loads(r["a_notes"] or "[]")
        rows.append({
            "id": r["id"], "status": r["status"], "table": r["table_name"], "rowid": r["rowid_value"], "method": r["method"],
            "source": r["source"], "source_path": r["source_path"], "page": r["page_number"], "offset": r["file_offset"],
            "region": r["region"], "fit": r["fit"], "summary": r["a_summary"],
            "values": json.loads(r["values_json"]), "unknown_columns": json.loads(r["unknown_columns_json"] or "[]"),
            "issues": json.loads(r["issues_json"] or "[]"), "also_found_at": json.loads(r["also_found_at_json"] or "[]"),
            "corroboration": json.loads(r["corroboration_json"] or "[]"),
            "confidence": r["a_confidence"], "explanation": notes[-1] if notes else "",
        })
    return rows


def _carved_rows(store: CaseStore) -> list[dict[str, Any]]:
    rows = []
    for r in store.q("SELECT * FROM carved_candidates ORDER BY id"):
        rows.append({
            "id": r["id"], "status": r["status"], "kind": r["kind"], "pattern": r["pattern"], "matched": r["matched"],
            "encoding": r["encoding"], "container": r["container"], "offset": r["byte_offset"], "length": r["length"],
            "source_file": r["source_file"], "confidence": r["confidence"], "explanation": r["explanation"],
            "corroborated_by": json.loads(r["corroborated_by_json"] or "[]"), "notes": json.loads(r["notes_json"] or "[]"),
        })
    return rows


def _correlation_rows(store: CaseStore) -> list[dict[str, Any]]:
    return [
        {"source": f"{r['source_kind']}:{r['source_ref']}", "relation": r["relation"],
         "target": f"{r['target_kind']}:{r['target_ref']}", "strength": r["strength"], "explanation": r["explanation"]}
        for r in store.q("SELECT * FROM correlations ORDER BY id")
    ]


def _unrecovered_rows(store: CaseStore) -> list[dict[str, Any]]:
    return [dict(r) for r in store.q("SELECT source_path, region, reason FROM unrecovered_regions ORDER BY id")]


def _active_section(store: CaseStore) -> dict[str, dict[str, Any]]:
    layouts = {
        "sms": ("SMS messages", ["ID", "Time (UTC)", "Direction", "Address", "Body", "Read", "Thread"]),
        "call": ("Call log", ["ID", "Time (UTC)", "Type", "Number", "Duration (s)", "Cached name", "Presentation"]),
        "contact": ("Contacts", ["ID", "Last updated (UTC)", "Name", "Phones", "Emails", "Account", "Application flag"]),
        "browser_visit": ("Browser visits", ["ID", "Time (UTC)", "Title", "URL", "Transition", "Visits"]),
        "browser_download": ("Browser downloads", ["ID", "Time (UTC)", "File", "Source page", "Bytes", "State"]),
        "app_summary": ("Application summary", ["ID", "Package", "Application", "Files", "Databases", "Last file change (UTC)", "Preference keys"]),
    }
    out: dict[str, dict[str, Any]] = {}
    for atype, (title, cols) in layouts.items():
        total = store.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type=? AND status='ACTIVE'", (atype,)) or 0
        rows = []
        for r in store.q("SELECT * FROM artifacts WHERE artifact_type=? AND status='ACTIVE' ORDER BY COALESCE(ts_utc,'9999'), id", (atype,)):
            f = json.loads(r["fields_json"])
            ts = r["ts_utc"] or ""
            if atype == "sms":
                cells = [r["id"], ts, f.get("direction"), f.get("address"), f.get("body"), f.get("read"), f.get("thread_id")]
            elif atype == "call":
                cells = [r["id"], ts, f.get("call_type"), f.get("number") or "(private/unknown)", f.get("duration_seconds"), f.get("cached_name"), f.get("presentation")]
            elif atype == "contact":
                cells = [r["id"], ts, f.get("display_name"), ", ".join(p["number"] for p in f.get("phones", [])),
                         ", ".join(e["address"] for e in f.get("emails", [])), f.get("account_name"),
                         "FLAGGED DELETED (still in database)" if r["marked_deleted"] else ""]
            elif atype == "browser_visit":
                cells = [r["id"], ts, f.get("title"), f.get("url"), f.get("transition") or ("url-level record" if f.get("url_level_only") else ""), f.get("visit_count")]
            elif atype == "browser_download":
                cells = [r["id"], ts, (f.get("target_path") or "").rsplit("/", 1)[-1], f.get("tab_url"), f.get("total_bytes"), f.get("download_state")]
            else:
                cells = [r["id"], f["package"], f.get("known_app") or "", f["file_count"], f["database_count"], ts,
                         sum(len(v) for v in f.get("shared_pref_keys", {}).values())]
            rows.append({"cells": cells, "prov": _prov(r), "flags": json.loads(r["flags_json"] or "[]"),
                         "marked_deleted": bool(r["marked_deleted"]), "unknown": json.loads(r["unknown_fields_json"] or "[]")})
        out[atype] = {"title": title, "columns": cols, "rows": rows, "total": total}
    return out


def build_report_model(store: CaseStore, html_row_cap: int | None = None) -> ReportModel:
    cap = HTML_ROW_CAP if html_row_cap is None else html_row_cap
    case = store.case()
    counts = store.counts()
    files = [dict(r) for r in store.q(
        "SELECT f.id, s.original_name AS source, f.path, f.logical_path, f.package, f.kind, f.size, f.md5, f.sha1, f.sha256, "
        "f.mtime, f.time_basis, f.preserved_copy FROM evidence_files f JOIN evidence_sources s ON s.id=f.source_id ORDER BY f.source_id, f.ordinal")]
    kinds = Counter(f["kind"] for f in files)
    issues = [dict(r) for r in store.q("SELECT source_id, path, issue_type, detail, stage FROM scan_issues ORDER BY id")]
    sources = [dict(r) for r in store.q("SELECT * FROM evidence_sources ORDER BY id")]
    layout = {sid: lay.model_dump() for sid, lay in case.layouts.items()}

    by_type = {r["artifact_type"]: r["n"] for r in store.q("SELECT artifact_type, COUNT(*) n FROM artifacts GROUP BY 1")}
    artifact_status = {r["status"]: r["n"] for r in store.q("SELECT status, COUNT(*) n FROM artifacts GROUP BY 1")}
    apps: dict[str, dict[str, Any]] = {}
    for r in store.q("SELECT COALESCE(application,'(unattributed)') a, artifact_type t, COUNT(*) n FROM artifacts WHERE artifact_type!='app_summary' GROUP BY 1,2"):
        apps.setdefault(r["a"], {"application": r["a"], "name": KNOWN_APPS.get(r["a"], ""), "counts": {}})["counts"][r["t"]] = r["n"]

    databases: list[dict[str, Any]] = []
    for d in store.q(
        "SELECT d.*, f.path, f.package, f.sha256, f.size, (SELECT COUNT(*) FROM artifacts a WHERE a.database_id=d.id) AS parsed "
        "FROM databases d JOIN evidence_files f ON f.id=d.evidence_file_id ORDER BY f.path"):
        side = json.loads(d["sidecars_json"] or "{}")
        hdr = json.loads(d["header_json"] or "{}")
        version = json.loads(d["version_json"] or "null") or {}
        engine = json.loads(d["engine_json"] or "null") or {}
        databases.append({
            "auto_vacuum": hdr.get("auto_vacuum"),
            "sqlite_version": version.get("last_writer_version"), "sqlite_version_reliable": version.get("last_writer_version_reliable"),
            "schema_format": version.get("schema_format"), "user_version": hdr.get("user_version"), "application_id": hdr.get("application_id"),
            "wal_frames_valid": engine.get("wal_frames_valid"),
            "id": d["id"], "path": d["path"], "package": d["package"], "sha256": d["sha256"], "size": d["size"],
            "sqlite_status": d["sqlite_status"], "sqlite_status_detail": d["sqlite_status_detail"],
            "open_status": d["open_status"], "open_error": d["open_error"], "integrity": d["integrity_status"],
            "integrity_detail": d["integrity_detail"], "page_size": d["page_size"], "page_count": d["page_count_header"],
            "encoding": d["text_encoding"], "journal_mode": d["journal_mode"], "tables": d["table_count"],
            "artifacts": d["parsed"], "view_includes_wal": d["view_includes_wal"],
            "freelist_pages": d["freelist_page_count"], "wal": side.get("wal"), "journal": side.get("journal"), "shm": side.get("shm"),
            "warnings": json.loads(d["warnings_json"] or "[]"),
        })
    app_directories = []
    for a in store.q("SELECT * FROM app_directories ORDER BY path"):
        entry = dict(a)
        entry["subdirectories"] = json.loads(entry.pop("subdirectories_json") or "[]")
        entry["kind_counts"] = json.loads(entry.pop("kind_counts_json") or "{}")
        app_directories.append(entry)
    indicators = []
    for info in databases:
        if info["open_status"] in ("encrypted_suspect", "not_preserved"):
            continue
        wal = info["wal"] or {}
        jr = info["journal"] or {}
        notes = []
        if info["auto_vacuum"] in ("full", "incremental"):
            notes.append(f"auto-vacuum ({info['auto_vacuum']}) enabled — freed pages are reclaimed, so freelist-based recovery potential is reduced")
        if info["freelist_pages"]:
            notes.append(f"{info['freelist_pages']} freelist page(s) declared in the header — deleted rows may persist there")
        if wal.get("size", 0) > 32:
            notes.append(f"WAL present ({wal.get('frame_slots', '?')} frame slot(s)) — may hold superseded page images")
        if jr.get("magic_valid"):
            notes.append("valid-magic rollback journal — holds pre-transaction page images")
        elif jr.get("size", 0) > 0:
            notes.append("journal file present but header not valid/zeroed — stale pages may remain")
        if info["open_status"] != "ok":
            notes.append("database not readable by SQLite — a candidate for Review 2 salvage")
        indicators.append({"path": info["path"], "freelist_pages": info["freelist_pages"], "page_count": info["page_count"],
                           "wal_frame_slots": wal.get("frame_slots") if wal else None, "journal_bytes": jr.get("size") if jr else None,
                           "notes": notes or ["no indicator present in header or sidecars (this does not prove nothing was deleted)"]})

    val_rows = [dict(r) for r in store.q("SELECT target_type, target_id, target_label, check_name, status, detail FROM validation_results ORDER BY CASE status WHEN 'INVALID' THEN 0 WHEN 'PARTIAL' THEN 1 WHEN 'UNVERIFIED' THEN 2 ELSE 3 END, check_name, id")]
    by_status = Counter(r["status"] for r in val_rows)
    by_check: dict[str, dict[str, int]] = {}
    for vr in val_rows:
        by_check.setdefault(vr["check_name"], {}).setdefault(vr["status"], 0)
        by_check[vr["check_name"]][vr["status"]] += 1

    tl = [dict(r) for r in store.q(
        "SELECT ts_utc, time_basis, event_kind, artifact_type, event, source, status, confidence, artifact_id FROM timeline_events ORDER BY ts_utc, id")]
    table_catalog = [dict(r) for r in store.q(
        "SELECT f.path AS database, t.name, t.obj_type, t.row_count, t.parsed_by, t.schema_variant, t.schema_score, t.columns_json, t.read_error, t.details_json "
        "FROM db_tables t JOIN databases d ON d.id=t.database_id JOIN evidence_files f ON f.id=d.evidence_file_id "
        "WHERE t.obj_type='table' ORDER BY f.path, t.name")]
    for t in table_catalog:
        t["columns"] = [c[0] for c in json.loads(t.pop("columns_json") or "[]")]
        details = json.loads(t.pop("details_json") or "null") or {}
        t["primary_key"] = details.get("primary_key", [])
        t["indexes"] = [
            {"name": i["name"], "unique": i["unique"], "origin": i["origin"], "partial": i["partial"],
             "columns": [c["name"] if c["name"] is not None else "(expression)" for c in i["columns"]]}
            for i in details.get("indexes", [])
        ]
        t["foreign_keys"] = [{"columns": f["columns"], "references": f["referenced_table"]} for f in details.get("foreign_keys", [])]
        t["flags"] = [label for label, on in (
            ("WITHOUT ROWID", details.get("without_rowid")), ("AUTOINCREMENT", details.get("autoincrement")), ("STRICT", details.get("strict")),
            ("virtual table", details.get("kind") == "virtual"), ("shadow table", details.get("kind") == "shadow"),
        ) if on]

    ok, msg = store.verify_custody_chain()
    custody = {"intact": ok, "message": msg, "entries": [dict(r) for r in store.q("SELECT id, ts, actor, action, target, detail_json, entry_hash FROM custody_log ORDER BY id")]}
    runs = [dict(r) for r in store.q("SELECT id, stage, status, started_at, finished_at, tool_version, stats_json FROM analysis_runs ORDER BY id")]

    active = _active_section(store)

    stages_run = {stage: store.last_run(stage) is not None for stage in ("recover", "carve", "correlate", "reconstruct")}
    recovery_performed = stages_run["recover"]
    recovered_rows, corrupted_rows, partial_rows = (_recovered_rows(store, s) for s in ("RECOVERED", "CORRUPTED", "PARTIAL"))
    carved_rows = _carved_rows(store) if stages_run["carve"] else []
    correlation_rows = _correlation_rows(store) if stages_run["correlate"] else []
    unrecovered_rows = _unrecovered_rows(store) if recovery_performed else []
    def top(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """What the HTML shows when there are too many rows: highest confidence first, original order within a level."""
        return sorted(rows, key=lambda r: _CONF_RANK.get(str(r.get("confidence")), 9))[:cap] if len(rows) > cap else rows

    def summary(rows: list[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
        tally = Counter(tuple(str(r.get(k)) for k in keys) for r in rows)
        return [dict(zip(keys, k, strict=True), count=n) for k, n in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))]

    recovery = {
        "recovered_top": top(recovered_rows + corrupted_rows), "partial_top": top(partial_rows), "carved_top": top(carved_rows),
        "correlations_top": correlation_rows[:cap], "unrecoverable_top": unrecovered_rows[:cap],
        "carved_summary": summary(carved_rows, "kind", "confidence"),
        "recovered_summary": summary(recovered_rows + corrupted_rows + partial_rows, "status", "method", "confidence"),
        "performed": recovery_performed, "stages_run": stages_run, "messages": text.NOT_PERFORMED,
        "indicators": indicators, "recovered": recovered_rows, "corrupted": corrupted_rows, "partial": partial_rows,
        "carved": carved_rows, "correlations": correlation_rows, "unrecoverable": unrecovered_rows,
        "counts": {"recovered": len(recovered_rows), "corrupted": len(corrupted_rows), "partial": len(partial_rows),
                  "carved": len(carved_rows), "correlation_edges": len(correlation_rows), "unrecoverable": len(unrecovered_rows)},
    }

    at_a_glance: list[dict[str, Any]] = [
        {"label": "ACTIVE DATA", "value": counts["active_artifacts"], "note": "records present in live databases", "state": "ok"},
        {"label": "RECOVERED DELETED DATA", "value": (len(recovered_rows) + len(corrupted_rows)) if recovery_performed else "not performed",
         "note": (f"{len(corrupted_rows)} corrupted" if corrupted_rows else "reconstructed with a confidence explanation") if recovery_performed else "Review 2",
         "state": "ok" if recovery_performed else "na"},
        {"label": "PARTIAL RECOVERIES", "value": len(partial_rows) if recovery_performed else "not performed",
         "note": "reconstructed; missing fields are UNKNOWN, never guessed" if recovery_performed else "Review 2",
         "state": "ok" if recovery_performed else "na"},
        {"label": "CARVED CANDIDATES", "value": len(carved_rows) if stages_run["carve"] else "not performed",
         "note": "unconfirmed pattern hits, never ACTIVE" if stages_run["carve"] else "Review 2", "state": "ok" if stages_run["carve"] else "na"},
        {"label": "UNRECOVERABLE DATA", "value": len(unrecovered_rows) if recovery_performed else "not classified",
         "note": "proven deleted, content lost" if recovery_performed else "Review 2", "state": "ok" if recovery_performed else "na"},
    ]
    methodology = list(text.METHODOLOGY)
    limitations = list(text.LIMITATIONS)
    if recovery_performed:
        methodology[-1] = ("Recovery, carving and correlation (this review)", text.RECOVERY_PERFORMED_METHODOLOGY)
        limitations[0] = text.RECOVERY_PERFORMED_LIMITATION
    model = ReportModel(
        meta={
            "case_id": case.id, "case_name": case.name, "examiner": case.examiner, "description": case.description,
            "created_at": case.created_at, "generated_at": utcnow(), "tool_name": TOOL_NAME, "tool_version": __version__,
            "python": sys.version.split()[0], "sqlite_library": sqlite3.sqlite_version, "platform": platform.platform(),
            "review_scope": text.REVIEW2_SCOPE if recovery_performed else text.REVIEW_SCOPE,
        },
        at_a_glance=at_a_glance,
        sources=sources,
        acquisition={
            "files": len(files), "bytes": sum(f["size"] for f in files), "kinds": dict(kinds.most_common()),
            "layout": case.layout, "layout_detail": layout, "issue_counts": dict(Counter(i["issue_type"] for i in issues)),
            "preserved_copies": sum(1 for f in files if f["preserved_copy"]), "all_complete": all(s["complete"] for s in sources),
        },
        evidence_files=files,
        artifact_summary={"by_type": by_type, "by_status": artifact_status, "by_application": sorted(apps.values(), key=lambda a: a["application"]), "total": counts["artifacts"]},
        databases=databases,
        app_directories=app_directories,
        recovery=recovery,
        active=active,
        timeline=tl,
        validation={"total": len(val_rows), "by_status": dict(by_status), "by_check": by_check, "results": val_rows},
        scan_issues=issues,
        table_catalog=table_catalog,
        custody=custody,
        runs=runs,
        methodology=methodology,
        limitations=limitations,
        disclaimer=text.DISCLAIMER,
        status_glossary=text.STATUS_GLOSSARY,
    )
    model.html_row_cap = cap
    model.details = store.details()
    from android_forensics.custody.audit import AUDIT_FILENAME, AuditLog
    from android_forensics.custody.stamp import tool_stamp

    audit = AuditLog(store.case_dir / AUDIT_FILENAME).verify()
    model.provenance = {
        "tool_stamp": tool_stamp(), "plugins": [p.as_dict() for p in _LOADED_PLUGINS],
        "audit": {"present": audit.entries > 0, "entries": audit.entries, "intact": audit.ok, "head": audit.head,
                  "problem": audit.reason or None},
    }
    model.truncation = {
        "evidence_files": [min(len(files), cap), len(files)], "timeline": [min(len(tl), cap), len(tl)],
        **{k: [min(len(v["rows"]), cap), len(v["rows"])] for k, v in active.items()},
        "validation": [min(len(val_rows), cap), len(val_rows)],
        "recovered": [min(len(recovered_rows) + len(corrupted_rows), cap), len(recovered_rows) + len(corrupted_rows)],
        "partial": [min(len(partial_rows), cap), len(partial_rows)], "carved": [min(len(carved_rows), cap), len(carved_rows)],
        "correlations": [min(len(correlation_rows), cap), len(correlation_rows)],
        "unrecoverable": [min(len(unrecovered_rows), cap), len(unrecovered_rows)],
    }
    return model
