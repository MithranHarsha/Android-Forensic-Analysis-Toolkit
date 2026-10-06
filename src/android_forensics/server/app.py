"""The multi-case server application (see the package docstring)."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from android_forensics import __version__
from android_forensics.custody.audit import AUDIT_FILENAME, AuditLog
from android_forensics.dashboard.api import WEB_DIR, build_router
from android_forensics.dashboard.security import SecurityHeadersMiddleware
from android_forensics.errors import CaseError
from android_forensics.server.auth import ROLES, Principal, authenticate, client_ip, hash_token, new_token, parse_bearer
from android_forensics.server.db import ServerDB
from android_forensics.server.jobs import KINDS, JobManager
from android_forensics.server.ratelimit import RateLimiter
from android_forensics.server.settings import ServerSettings
from android_forensics.storage.case_store import CaseStore
from android_forensics.util import safe_basename

CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
REPORT_NAME = re.compile(r"^report-[0-9A-Za-z_.-]{1,64}$")
LOG_TAIL_BYTES = 64 * 1024
_REPORT_TYPES = {".html": "text/html", ".json": "application/json", ".csv": "text/csv", ".pdf": "application/pdf",
                 ".txt": "text/plain", ".sig": "application/octet-stream", ".asc": "text/plain"}


class NewCase(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    examiner: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    display_name: str | None = Field(default=None, max_length=200)


class NewJob(BaseModel):
    kind: str
    upload_id: str | None = None


class NewToken(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    role: str


class _IPRateLimit(BaseHTTPMiddleware):
    def __init__(self, app, limiter: RateLimiter, hops: int):  # noqa: ANN001
        super().__init__(app)
        self.limiter, self.hops = limiter, hops

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        ok, retry = self.limiter.hit(client_ip(request, self.hops))
        if not ok:
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": str(int(retry) + 1)})
        return await call_next(request)


def create_server_app(settings: ServerSettings) -> FastAPI:
    s = settings
    for d in (s.cases_dir, s.data_dir, s.uploads_dir, s.jobs_dir):
        d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(s.data_dir, 0o700)   # tokens' hashes, uploads and logs: owner only (best effort on shared/network mounts)
    except OSError:
        pass
    db = ServerDB(s.db_path)
    audit = AuditLog(s.audit_path)
    jobs = JobManager(s, db, audit)
    ip_limiter = RateLimiter(s.rate_limit_per_minute)
    principal_limiter = RateLimiter(s.principal_rate_limit_per_minute)
    fail_limiter = RateLimiter(s.auth_failures_per_minute)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        jobs.start()
        yield
        jobs.stop()
        db.close()

    app = FastAPI(title="Android Forensics Server", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db, app.state.jobs, app.state.audit, app.state.settings = db, jobs, audit, s
    app.add_middleware(_IPRateLimit, limiter=ip_limiter, hops=s.trust_proxy_hops)
    if s.allowed_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(s.allowed_origins), allow_methods=["GET", "POST", "PUT", "DELETE"],
                           allow_headers=["Authorization", "Content-Type"], allow_credentials=False, max_age=600)
    app.add_middleware(SecurityHeadersMiddleware, hsts=s.behind_tls)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(s.allowed_hosts))

    # ------------------------------------------------------------------ authn / authz
    def principal(request: Request) -> Principal:
        ip = client_ip(request, s.trust_proxy_hops)
        locked, retry = fail_limiter.blocked(ip)
        if locked:
            raise HTTPException(429, "too many failed authentication attempts", headers={"Retry-After": str(int(retry) + 1)})
        p = authenticate(db, parse_bearer(request.headers.get("authorization")))
        if p is None:
            fail_limiter.hit(ip)
            raise HTTPException(401, "missing or invalid token", headers={"WWW-Authenticate": "Bearer"})
        ok, retry = principal_limiter.hit(f"p{p.token_id}")
        if not ok:
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(int(retry) + 1)})
        request.state.principal = p
        return p

    def need(role: str):
        def dep(request: Request, p: Principal = Depends(principal)) -> Principal:
            if not p.at_least(role):
                audit.append({"event": "denied", "by": p.name, "token": p.token_id, "role": p.role, "needs": role,
                              "method": request.method, "path": request.url.path, "ip": client_ip(request, s.trust_proxy_hops)})
                raise HTTPException(403, f"this action needs the '{role}' role")
            return p
        return dep

    def record(request: Request, p: Principal, event: str, **detail: Any) -> None:
        audit.append({"event": event, "by": p.name, "token": p.token_id, "role": p.role, "ip": client_ip(request, s.trust_proxy_hops), **detail})

    def known_case(case_id: str) -> dict[str, Any]:
        if not CASE_ID.match(case_id):
            raise HTTPException(404, "no such case")
        row = db.case(case_id)
        if row is None:
            raise HTTPException(404, "no such case")
        return row

    def case_store(case_id: str, _p: Principal = Depends(need("viewer"))) -> Iterator[CaseStore]:
        known_case(case_id)
        try:
            store = CaseStore.open(s.cases_dir / case_id)
        except CaseError as exc:
            raise HTTPException(404, "case has no database yet") from exc
        try:
            yield store
        finally:
            store.close()

    # ------------------------------------------------------------------ unauthenticated (minimal)
    @app.api_route("/api/health", methods=["GET", "HEAD"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/mode")
    def mode() -> dict[str, str]:
        return {"mode": "server", "version": __version__}

    @app.get("/api/me")
    def me(p: Principal = Depends(principal)) -> dict[str, Any]:
        return {"name": p.name, "role": p.role}

    # ------------------------------------------------------------------ cases
    @app.get("/api/cases")
    def list_cases(_p: Principal = Depends(need("viewer"))) -> list[dict[str, Any]]:
        out = []
        for c in db.cases():
            last = db.jobs(c["id"])[:1]
            out.append({**c, "last_job": ({"status": last[0]["status"], "kind": last[0]["kind"], "finished_at": last[0]["finished_at"]} if last else None)})
        return out

    @app.post("/api/cases", status_code=201)
    def create_case(body: NewCase, request: Request, p: Principal = Depends(need("analyst"))) -> dict[str, Any]:
        if not CASE_ID.match(body.id):
            raise HTTPException(422, "case id may contain letters, digits, '.', '_' and '-' (max 64, must start with a letter or digit)")
        if db.one("SELECT 1 AS x FROM cases WHERE id=?", (body.id,)):
            raise HTTPException(409, "a case with that id already exists (deleted cases keep their id)")
        try:
            CaseStore.create(s.cases_dir / body.id, body.id, body.examiner or p.name, body.description).close()
        except CaseError as exc:
            raise HTTPException(409, str(exc)) from exc
        db.add_case(body.id, body.display_name or body.id, body.description, body.examiner or p.name, p.name)
        record(request, p, "case_created", case=body.id)
        return known_case(body.id)

    @app.get("/api/cases/{case_id}/meta")
    def case_meta(case_id: str, _p: Principal = Depends(need("viewer"))) -> dict[str, Any]:
        return known_case(case_id)

    @app.delete("/api/cases/{case_id}")
    def delete_case(case_id: str, request: Request, p: Principal = Depends(need("admin"))) -> dict[str, bool]:
        known_case(case_id)
        db.soft_delete_case(case_id)   # evidence and results are retained on disk: removal is a records-management decision
        record(request, p, "case_deleted", case=case_id)
        return {"deleted": True}

    # ------------------------------------------------------------------ uploads
    @app.put("/api/cases/{case_id}/uploads", status_code=201)
    async def upload(case_id: str, filename: str, request: Request, p: Principal = Depends(need("analyst"))) -> dict[str, Any]:
        known_case(case_id)
        try:
            declared = int(request.headers.get("content-length", ""))
        except ValueError:
            raise HTTPException(411, "Content-Length is required for uploads") from None
        if declared <= 0:
            raise HTTPException(400, "empty upload")
        if declared > s.max_upload_bytes:
            raise HTTPException(413, f"upload exceeds the {s.max_upload_bytes:,}-byte limit")
        folder = s.uploads_dir / case_id
        folder.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(folder).free < declared + (1 << 30):
            raise HTTPException(507, "not enough free disk space for this upload")
        name = safe_basename(filename.replace("\\", "/").rsplit("/", 1)[-1])
        upload_id_hint = uuid.uuid4().hex
        part = folder / f".{upload_id_hint}.part"
        digest, size = hashlib.sha256(), 0
        try:
            with open(part, "wb") as fh:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > declared or size > s.max_upload_bytes:
                        raise HTTPException(413, "body is larger than declared")
                    digest.update(chunk)
                    fh.write(chunk)
            if size != declared:
                raise HTTPException(400, "upload was truncated")
            final = folder / f"{upload_id_hint}_{name}"
            os.replace(part, final)
            os.chmod(final, 0o444)
        finally:
            if part.exists():
                part.unlink()
        upload_id = db.add_upload(case_id, name, str(final), size, digest.hexdigest(), p.name)
        record(request, p, "evidence_uploaded", case=case_id, upload=upload_id, name=name, size=size, sha256=digest.hexdigest())
        return {"id": upload_id, "name": name, "size": size, "sha256": digest.hexdigest()}

    @app.get("/api/cases/{case_id}/uploads")
    def list_uploads(case_id: str, _p: Principal = Depends(need("viewer"))) -> list[dict[str, Any]]:
        known_case(case_id)
        return db.uploads(case_id)

    # ------------------------------------------------------------------ jobs
    @app.post("/api/cases/{case_id}/jobs", status_code=202)
    def create_job(case_id: str, body: NewJob, request: Request, p: Principal = Depends(need("analyst"))) -> dict[str, Any]:
        known_case(case_id)
        if body.kind not in KINDS:
            raise HTTPException(422, f"kind must be one of {', '.join(KINDS)}")
        if body.upload_id is not None:
            up = db.upload(body.upload_id)
            if up is None or up["case_id"] != case_id:
                raise HTTPException(404, "no such upload for this case")
        elif body.kind == "analyze" and not CaseStore.is_case_dir(s.cases_dir / case_id):
            raise HTTPException(422, "analyze needs an upload for a case with no evidence yet")
        job_id = jobs.submit(case_id, body.kind, body.upload_id, p.name)
        record(request, p, "job_submitted", case=case_id, job=job_id, kind=body.kind, upload=body.upload_id)
        return db.job(job_id) or {}

    @app.get("/api/cases/{case_id}/jobs")
    def list_jobs(case_id: str, _p: Principal = Depends(need("viewer"))) -> list[dict[str, Any]]:
        known_case(case_id)
        return db.jobs(case_id)

    @app.get("/api/cases/{case_id}/jobs/{job_id}")
    def get_job(case_id: str, job_id: str, log: bool = False, _p: Principal = Depends(need("viewer"))) -> dict[str, Any]:
        known_case(case_id)
        job = db.job(job_id)
        if job is None or job["case_id"] != case_id:
            raise HTTPException(404, "no such job")
        if log:
            path = jobs.log_path(job_id)
            tail = b""
            if path.is_file():
                with open(path, "rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    fh.seek(max(0, fh.tell() - LOG_TAIL_BYTES))
                    tail = fh.read()
            job["log_tail"] = tail.decode("utf-8", "replace")
        return job

    @app.post("/api/cases/{case_id}/jobs/{job_id}/cancel")
    def cancel_job(case_id: str, job_id: str, request: Request, p: Principal = Depends(need("analyst"))) -> dict[str, bool]:
        known_case(case_id)
        job = db.job(job_id)
        if job is None or job["case_id"] != case_id:
            raise HTTPException(404, "no such job")
        done = jobs.cancel(job_id)
        record(request, p, "job_cancel_requested", case=case_id, job=job_id, accepted=done)
        return {"cancelled": done}

    # ------------------------------------------------------------------ reports (downloads)
    @app.get("/api/cases/{case_id}/reports")
    def list_reports(case_id: str, _p: Principal = Depends(need("viewer"))) -> list[dict[str, Any]]:
        known_case(case_id)
        root = s.cases_dir / case_id / "reports"
        out = []
        if root.is_dir():
            for d in sorted(root.iterdir(), reverse=True):
                if d.is_dir() and REPORT_NAME.match(d.name):
                    files = sorted(f.relative_to(d).as_posix() for f in d.rglob("*") if f.is_file())
                    out.append({"name": d.name, "files": files, "signed": (d / "signature.json").is_file()})
        return out

    @app.get("/api/cases/{case_id}/reports/{report}/{file:path}")
    def download_report(case_id: str, report: str, file: str, request: Request, p: Principal = Depends(need("viewer"))) -> FileResponse:
        known_case(case_id)
        if not REPORT_NAME.match(report):
            raise HTTPException(404, "no such report")
        base = (s.cases_dir / case_id / "reports" / report).resolve()
        target = (base / file).resolve()
        if not target.is_relative_to(base) or not target.is_file():
            raise HTTPException(404, "no such file")
        record(request, p, "report_downloaded", case=case_id, report=report, file=file)
        # Always an attachment with a sandboxing CSP: a report contains attacker-controlled text and its own script, and must
        # never execute in the server's origin.
        return FileResponse(target, media_type=_REPORT_TYPES.get(target.suffix.lower(), "application/octet-stream"),
                            filename=target.name, headers={"Content-Security-Policy": "sandbox; default-src 'none'",
                                                           "X-Content-Type-Options": "nosniff"})

    # ------------------------------------------------------------------ audit + admin
    @app.get("/api/cases/{case_id}/audit")
    def case_audit(case_id: str, _p: Principal = Depends(need("analyst"))) -> dict[str, Any]:
        known_case(case_id)
        log = AuditLog(s.cases_dir / case_id / AUDIT_FILENAME)
        v = log.verify()
        return {"intact": v.ok, "entries": v.entries, "head": v.head, "problem": v.reason or None, "tail": log.entries()[-100:]}

    @app.get("/api/admin/audit")
    def server_audit(_p: Principal = Depends(need("admin"))) -> dict[str, Any]:
        v = audit.verify()
        return {"intact": v.ok, "entries": v.entries, "head": v.head, "problem": v.reason or None, "tail": audit.entries()[-200:]}

    @app.get("/api/admin/tokens")
    def list_tokens(_p: Principal = Depends(need("admin"))) -> list[dict[str, Any]]:
        return db.tokens()

    @app.post("/api/admin/tokens", status_code=201)
    def create_token(body: NewToken, request: Request, p: Principal = Depends(need("admin"))) -> dict[str, Any]:
        if body.role not in ROLES:
            raise HTTPException(422, f"role must be one of {', '.join(ROLES)}")
        token = new_token()
        token_id = db.add_token(body.name, body.role, hash_token(token))
        record(request, p, "token_created", new_token_id=token_id, name=body.name, role=body.role)
        return {"id": token_id, "name": body.name, "role": body.role, "token": token, "note": "shown once; store it now"}

    @app.delete("/api/admin/tokens/{token_id}")
    def revoke_token(token_id: int, request: Request, p: Principal = Depends(need("admin"))) -> dict[str, bool]:
        if token_id == p.token_id:
            raise HTTPException(409, "you cannot revoke the token you are using")
        ok = db.revoke_token(token_id)
        record(request, p, "token_revoked", revoked_token_id=token_id, found=ok)
        return {"revoked": ok}

    # ------------------------------------------------------------------ read-only case data (same router as the local dashboard)
    app.include_router(build_router(case_store), prefix="/api/cases/{case_id}")

    # ------------------------------------------------------------------ frontend
    if WEB_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

        @app.api_route("/", methods=["GET", "HEAD"])
        def index() -> FileResponse:
            return FileResponse(WEB_DIR / "index.html")

    @app.exception_handler(500)
    async def _internal(_request: Request, _exc: Exception) -> PlainTextResponse:   # never leak stack traces to clients
        return PlainTextResponse("internal error", status_code=500)

    return app
