"""Background jobs: ingest + analyse + report, each step a resource-limited child process (see ``sandbox``)."""

from __future__ import annotations

import queue
import sys
import threading
from pathlib import Path

from android_forensics.custody.audit import AuditLog
from android_forensics.server.db import ServerDB
from android_forensics.server.sandbox import Limits, run_limited, scrubbed_env
from android_forensics.server.settings import ServerSettings
from android_forensics.util import now_iso

KINDS = ("analyze", "report")


class JobManager:
    def __init__(self, settings: ServerSettings, db: ServerDB, audit: AuditLog):
        self.s, self.db, self.audit = settings, db, audit
        self._q: queue.Queue[str | None] = queue.Queue()
        self._cancel: dict[str, threading.Event] = {}
        self._case_locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._started = False

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._started:
            return
        self._started = True
        n = self.db.interrupt_orphans()
        if n:
            self.audit.append({"event": "jobs_interrupted_at_startup", "count": n})
        for i in range(max(1, self.s.workers)):
            t = threading.Thread(target=self._worker, name=f"job-worker-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        for ev in list(self._cancel.values()):
            ev.set()
        for _ in self._threads:
            self._q.put(None)
        for t in self._threads:
            t.join(timeout=15)
        self._threads.clear()
        self._started = False

    # ------------------------------------------------------------------ API
    def submit(self, case_id: str, kind: str, upload_id: str | None, user: str) -> str:
        if kind not in KINDS:
            raise ValueError(f"unknown job kind {kind!r}")
        job_id = self.db.add_job(case_id, kind, upload_id, user)
        self._cancel[job_id] = threading.Event()
        self._q.put(job_id)
        return job_id

    def cancel(self, job_id: str) -> bool:
        job = self.db.job(job_id)
        if job is None or job["status"] not in ("queued", "running"):
            return False
        ev = self._cancel.setdefault(job_id, threading.Event())
        ev.set()
        if job["status"] == "queued":
            self.db.update_job(job_id, status="cancelled", finished_at=now_iso(), reason="cancelled before start")
        return True

    def log_path(self, job_id: str) -> Path:
        return self.s.jobs_dir / f"{job_id}.log"

    # ------------------------------------------------------------------ worker
    def _case_lock(self, case_id: str) -> threading.Lock:
        with self._guard:
            return self._case_locks.setdefault(case_id, threading.Lock())

    def _worker(self) -> None:
        while True:
            job_id = self._q.get()
            if job_id is None:
                return
            job = self.db.job(job_id)
            if job is None or job["status"] != "queued":
                continue
            with self._case_lock(job["case_id"]):   # one job per case at a time
                self._run(job)

    def _steps(self, job: dict, case_dir: Path) -> list[list[str]]:
        py, cases = sys.executable, str(self.s.cases_dir)
        base = [py, "-m", "android_forensics"]
        case = job["case_id"]
        steps: list[list[str]] = []
        if job["kind"] == "analyze":
            upload = self.db.upload(job["upload_id"]) if job["upload_id"] else None
            if upload is not None:
                steps.append([*base, "ingest", case, upload["stored_path"], "--cases-dir", cases])
            steps.append([*base, "analyze", case, "--cases-dir", cases, "--no-report"])
        report = [*base, "report", case, "--cases-dir", cases, "--format", "html,json,csv,pdf"]
        if self.s.signing_key is not None:
            report += ["--sign", "--key", str(self.s.signing_key), "--signer", self.s.signer_name]
        steps.append(report)
        return steps

    def _run(self, job: dict) -> None:
        job_id, case_id = job["id"], job["case_id"]
        cancel = self._cancel.setdefault(job_id, threading.Event())
        case_dir = self.s.cases_dir / case_id
        self.db.update_job(job_id, status="running", started_at=now_iso())
        self.audit.append({"event": "job_started", "job": job_id, "case": case_id, "kind": job["kind"], "by": job["created_by"]})
        limits = Limits(self.s.job_cpu_seconds, self.s.job_wall_seconds, self.s.job_memory_bytes, self.s.job_file_bytes)
        env = scrubbed_env({"ANDROID_FORENSICS_CASES": str(self.s.cases_dir), "ANDROID_FORENSICS_ACTOR": f"server:{job['created_by']}",
                            **self.s.extra_env}, home=self.s.jobs_dir)
        final_reason: str = "ok"
        final_code: int | None = 0
        try:
            if not case_dir.is_dir():
                raise FileNotFoundError(f"case directory {case_dir} is missing")
            log = self.log_path(job_id)
            for argv in self._steps(job, case_dir):
                with open(log, "ab") as fh:
                    fh.write(f"\n$ {' '.join(argv[3:])}\n".encode())
                result = run_limited(argv, cwd=self.s.jobs_dir, env=env, limits=limits, log_path=log,
                                     on_start=lambda pid: self.db.update_job(job_id, pid=pid), cancelled=cancel)
                final_reason, final_code = result.reason, result.exit_code
                if result.reason != "ok":
                    break
        except Exception as exc:  # noqa: BLE001 - a job failure must never take a worker thread down
            final_reason, final_code = f"error: {type(exc).__name__}: {exc}", None
        status = {"ok": "succeeded", "cancelled": "cancelled", "timeout": "failed", "killed": "failed", "failed": "failed"}.get(final_reason, "failed")
        self.db.update_job(job_id, status=status, finished_at=now_iso(), exit_code=final_code, reason=final_reason, pid=None)
        self.audit.append({"event": "job_finished", "job": job_id, "case": case_id, "status": status, "reason": final_reason})
        self._cancel.pop(job_id, None)
