"""FastAPI dashboard (Phase 11): a read-only REST API and a static single-page frontend over one case.

The dashboard never runs a pipeline stage and never writes to the case database: it is a viewer for what `analyze` /
`recover` already produced (`android-forensics recover CASE` first if you want recovered data reflected here). Every
endpoint returns only what the case database holds; nothing is invented for a nicer-looking page. A recovered record's
confidence is always shown with its explanation, and a carved candidate is always shown as ``CARVED CANDIDATE`` with its
own list of what would need to corroborate it -- the frontend has no code path that could relabel either as confirmed.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from android_forensics import __version__
from android_forensics.dashboard.security import SecurityHeadersMiddleware
from android_forensics.errors import CaseError
from android_forensics.storage.case_store import CaseStore

WEB_DIR = Path(__file__).resolve().parent / "web"


def _row(r) -> dict[str, Any]:
    return dict(r)


def _artifact_row(store: CaseStore, r) -> dict[str, Any]:
    d = _row(r)
    d["confidence_factors"] = json.loads(d.pop("confidence_factors_json") or "[]")
    d["validation_notes"] = json.loads(d.pop("validation_notes_json") or "[]")
    d["fields"] = json.loads(d.pop("fields_json") or "{}")
    d["unknown_fields"] = json.loads(d.pop("unknown_fields_json") or "[]")
    d["flags"] = json.loads(d.pop("flags_json") or "[]")
    d.pop("raw_row_json", None)
    return d


def build_router(store_dep: Callable[..., Iterator[CaseStore]]) -> APIRouter:
    """The read-only case API, for whichever case ``store_dep`` yields.

    Mounted at ``/api`` by the single-case dashboard and at ``/api/cases/{case_id}`` by the multi-case server
    (``android_forensics.server``), so both expose exactly the same endpoints and the same guarantees."""
    router = APIRouter()

    @router.get("/summary")
    def summary(s: CaseStore = Depends(store_dep)) -> dict[str, Any]:
        c = s.case()
        counts = s.counts()
        runs = [r.model_dump(mode="json") for r in s.runs()]
        return {"case": c.model_dump(mode="json"), "counts": counts, "runs": runs}

    @router.get("/artifacts")
    def artifacts(
        type: str | None = None, status: str | None = None, db: str | None = None, app_: str | None = Query(None, alias="app"),
        q: str | None = None, limit: int = 50, offset: int = 0, s: CaseStore = Depends(store_dep),
    ) -> dict[str, Any]:
        limit = max(1, min(limit, 500))
        where, params = ["1=1"], []
        for col, val in (("artifact_type", type), ("status", status), ("application", app_)):
            if val:
                where.append(f"{col}=?")
                params.append(val)
        if db:
            where.append("source_database LIKE ?")
            params.append(f"%{db}%")
        if q:
            where.append("summary LIKE ?")
            params.append(f"%{q}%")
        clause = " AND ".join(where)
        total = s.scalar(f"SELECT COUNT(*) FROM artifacts WHERE {clause}", params) or 0
        rows = s.q(f"SELECT * FROM artifacts WHERE {clause} ORDER BY id LIMIT ? OFFSET ?", [*params, limit, offset])
        return {"total": total, "limit": limit, "offset": offset, "artifacts": [_artifact_row(s, r) for r in rows]}

    @router.get("/artifacts/{artifact_id}")
    def artifact_detail(artifact_id: int, s: CaseStore = Depends(store_dep)) -> dict[str, Any]:
        row = s.one("SELECT * FROM artifacts WHERE id=?", (artifact_id,))
        if row is None:
            raise HTTPException(404, f"No artifact {artifact_id}")
        detail = _artifact_row(s, row)
        rec = s.one("SELECT id, artifact_id, status, region, page_number, page_offset, corroboration_json FROM recovered_records "
                    "WHERE artifact_id=?", (artifact_id,))
        if rec is not None:
            detail["recovered_record"] = {**_row(rec), "corroboration": json.loads(rec["corroboration_json"] or "[]")}
        detail["correlations"] = [_row(r) for r in s.q(
            "SELECT * FROM correlations WHERE source_ref=? OR target_ref=? ORDER BY id", (f"artifact:{artifact_id}",) * 2)]
        return detail

    @router.get("/recovery")
    def recovery(s: CaseStore = Depends(store_dep)) -> dict[str, Any]:
        by_status = {r["status"]: r["n"] for r in s.q("SELECT status, COUNT(*) n FROM recovered_records GROUP BY status")}
        by_method = {r["method"]: r["n"] for r in s.q("SELECT method, COUNT(*) n FROM recovered_records GROUP BY method")}
        corroborated = s.scalar("SELECT COUNT(*) FROM recovered_records WHERE corroboration_json != '[]'") or 0
        unrecovered = s.scalar("SELECT COUNT(*) FROM unrecovered_regions") or 0
        last = {stage: (r.model_dump(mode="json") if r else None) for stage in ("recover", "carve", "correlate", "reconstruct")
                for r in [s.last_run(stage)]}
        return {"by_status": by_status, "by_method": by_method, "corroborated": corroborated, "unrecovered_regions": unrecovered,
                "last_runs": last}

    @router.get("/recovered")
    def recovered_records(status: str | None = None, limit: int = 50, offset: int = 0, s: CaseStore = Depends(store_dep)) -> dict[str, Any]:
        limit = max(1, min(limit, 500))
        where, params = ["1=1"], []
        if status:
            where.append("status=?")
            params.append(status)
        clause = " AND ".join(where)
        total = s.scalar(f"SELECT COUNT(*) FROM recovered_records WHERE {clause}", params) or 0
        rows = s.q(f"SELECT * FROM recovered_records WHERE {clause} ORDER BY id LIMIT ? OFFSET ?", [*params, limit, offset])
        out = []
        for r in rows:
            d = _row(r)
            for key in ("values_json", "unknown_columns_json", "issues_json", "also_found_at_json", "corroboration_json"):
                d[key[:-5]] = json.loads(d.pop(key) or ("[]" if key != "values_json" else "{}"))
            out.append(d)
        return {"total": total, "limit": limit, "offset": offset, "records": out}

    @router.get("/carved")
    def carved(kind: str | None = None, limit: int = 50, offset: int = 0, s: CaseStore = Depends(store_dep)) -> dict[str, Any]:
        limit = max(1, min(limit, 500))
        where, params = ["1=1"], []
        if kind:
            where.append("kind=?")
            params.append(kind)
        clause = " AND ".join(where)
        total = s.scalar(f"SELECT COUNT(*) FROM carved_candidates WHERE {clause}", params) or 0
        rows = s.q(f"SELECT * FROM carved_candidates WHERE {clause} ORDER BY id LIMIT ? OFFSET ?", [*params, limit, offset])
        out = []
        for r in rows:
            d = _row(r)
            d["confidence_factors"] = json.loads(d.pop("confidence_factors_json") or "[]")
            d["corroborated_by"] = json.loads(d.pop("corroborated_by_json") or "[]")
            d["notes"] = json.loads(d.pop("notes_json") or "[]")
            out.append(d)
        return {"total": total, "limit": limit, "offset": offset, "candidates": out}

    @router.get("/correlations")
    def correlations(
        entity_kind: str | None = None, entity_ref: str | None = None, relation: str | None = None,
        limit: int = 200, s: CaseStore = Depends(store_dep),
    ) -> dict[str, Any]:
        limit = max(1, min(limit, 2000))
        where, params = ["1=1"], []
        if entity_ref:
            where.append("(source_ref=? OR target_ref=?)")
            params += [entity_ref, entity_ref]
        if entity_kind:
            where.append("(source_kind=? OR target_kind=?)")
            params += [entity_kind, entity_kind]
        if relation:
            where.append("relation=?")
            params.append(relation)
        clause = " AND ".join(where)
        total = s.scalar(f"SELECT COUNT(*) FROM correlations WHERE {clause}", params) or 0
        rows = s.q(f"SELECT * FROM correlations WHERE {clause} ORDER BY id LIMIT ?", [*params, limit])
        edges = [{**_row(r), "evidence": json.loads(r["evidence_json"] or "{}")} for r in rows]
        nodes = {}
        for e in edges:
            for kind, ref in ((e["source_kind"], e["source_ref"]), (e["target_kind"], e["target_ref"])):
                nodes.setdefault(f"{kind}:{ref}", {"kind": kind, "ref": ref})
        for e in edges:
            e.pop("evidence_json", None)
        return {"total": total, "nodes": list(nodes.values()), "edges": edges}

    @router.get("/validation")
    def validation(status: str | None = None, limit: int = 100, offset: int = 0, s: CaseStore = Depends(store_dep)) -> dict[str, Any]:
        limit = max(1, min(limit, 1000))
        where, params = ["1=1"], []
        if status:
            where.append("status=?")
            params.append(status)
        clause = " AND ".join(where)
        by_status = {r["status"]: r["n"] for r in s.q("SELECT status, COUNT(*) n FROM validation_results GROUP BY status")}
        total = s.scalar(f"SELECT COUNT(*) FROM validation_results WHERE {clause}", params) or 0
        rows = s.q(f"SELECT * FROM validation_results WHERE {clause} ORDER BY id LIMIT ? OFFSET ?", [*params, limit, offset])
        results = [{**_row(r), "evidence": json.loads(r["evidence_json"] or "{}")} for r in rows]
        for r in results:
            r.pop("evidence_json", None)
        return {"total": total, "by_status": by_status, "limit": limit, "offset": offset, "results": results}

    @router.get("/timeline")
    def timeline(
        kind: str | None = None, artifact_type: str | None = None, since: str | None = None, until: str | None = None,
        limit: int = 100, offset: int = 0, s: CaseStore = Depends(store_dep),
    ) -> dict[str, Any]:
        limit = max(1, min(limit, 1000))
        where, params = ["1=1"], []
        if kind:
            where.append("event_kind=?")
            params.append(kind)
        if artifact_type:
            where.append("artifact_type=?")
            params.append(artifact_type)
        if since:
            where.append("ts_utc>=?")
            params.append(since)
        if until:
            where.append("ts_utc<=?")
            params.append(until)
        clause = " AND ".join(where)
        total = s.scalar(f"SELECT COUNT(*) FROM timeline_events WHERE {clause}", params) or 0
        rows = s.q(f"SELECT * FROM timeline_events WHERE {clause} ORDER BY ts_utc LIMIT ? OFFSET ?", [*params, limit, offset])
        return {"total": total, "limit": limit, "offset": offset, "events": [_row(r) for r in rows]}

    return router


def create_app(case_dir: Path) -> FastAPI:
    """The dashboard for the case at ``case_dir``. Each request opens its own connection (SQLite, one case file)."""
    case_dir = Path(case_dir)
    if not CaseStore.is_case_dir(case_dir):
        raise CaseError(f"Not a case directory (case.db missing): {case_dir}")

    app = FastAPI(title="Android Forensics Dashboard", version=__version__)
    app.add_middleware(SecurityHeadersMiddleware)

    def store() -> Iterator[CaseStore]:
        s = CaseStore.open(case_dir)
        try:
            yield s
        finally:
            s.close()

    @app.get("/api/mode")
    def mode() -> dict[str, str]:
        return {"mode": "single"}

    app.include_router(build_router(store), prefix="/api")

    if WEB_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

        @app.api_route("/", methods=["GET", "HEAD"])
        def index() -> FileResponse:
            return FileResponse(WEB_DIR / "index.html")

    return app
