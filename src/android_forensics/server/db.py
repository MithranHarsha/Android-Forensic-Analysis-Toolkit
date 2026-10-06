"""The server's own database: tokens, case registry, uploads and jobs. (Case *content* lives in each case's case.db.)"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from android_forensics.util import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('viewer','analyst','admin')),
  token_sha256 TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT, last_used_at TEXT);
CREATE TABLE IF NOT EXISTS cases(
  id TEXT PRIMARY KEY, display_name TEXT NOT NULL, description TEXT, examiner TEXT,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, deleted_at TEXT);
CREATE TABLE IF NOT EXISTS uploads(
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), name TEXT NOT NULL, stored_path TEXT NOT NULL,
  size INTEGER NOT NULL, sha256 TEXT NOT NULL, uploaded_by TEXT NOT NULL, uploaded_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), kind TEXT NOT NULL, status TEXT NOT NULL,
  upload_id TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  exit_code INTEGER, reason TEXT, pid INTEGER);
CREATE INDEX IF NOT EXISTS jobs_case ON jobs(case_id);
"""


class ServerDB:
    """A thread-safe wrapper: one connection, serialised by a lock (traffic here is control-plane, not data-plane)."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
        path.chmod(0o600)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------------------------------------------------------------- generic
    def run(self, sql: str, params: tuple | list = ()) -> None:
        with self._lock, self._conn:
            self._conn.execute(sql, params)

    def one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        with self._lock:
            r = self._conn.execute(sql, params).fetchone()
        return dict(r) if r else None

    def all(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    # ---------------------------------------------------------------- tokens
    def add_token(self, name: str, role: str, sha256: str) -> int:
        with self._lock, self._conn:
            return int(self._conn.execute(
                "INSERT INTO tokens(name, role, token_sha256, created_at) VALUES(?,?,?,?)", (name, role, sha256, now_iso())).lastrowid or 0)

    def token_by_hash(self, sha256: str) -> dict[str, Any] | None:
        return self.one("SELECT * FROM tokens WHERE token_sha256=? AND revoked_at IS NULL", (sha256,))

    def touch_token(self, token_id: int) -> None:
        self.run("UPDATE tokens SET last_used_at=? WHERE id=?", (now_iso(), token_id))

    def revoke_token(self, token_id: int) -> bool:
        with self._lock, self._conn:
            return self._conn.execute("UPDATE tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now_iso(), token_id)).rowcount > 0

    def tokens(self) -> list[dict[str, Any]]:
        return self.all("SELECT id, name, role, created_at, revoked_at, last_used_at FROM tokens ORDER BY id")

    # ---------------------------------------------------------------- cases
    def add_case(self, case_id: str, display_name: str, description: str | None, examiner: str | None, created_by: str) -> None:
        self.run("INSERT INTO cases(id, display_name, description, examiner, created_by, created_at) VALUES(?,?,?,?,?,?)",
                 (case_id, display_name, description, examiner, created_by, now_iso()))

    def case(self, case_id: str) -> dict[str, Any] | None:
        return self.one("SELECT * FROM cases WHERE id=? AND deleted_at IS NULL", (case_id,))

    def cases(self) -> list[dict[str, Any]]:
        return self.all("SELECT * FROM cases WHERE deleted_at IS NULL ORDER BY created_at DESC")

    def soft_delete_case(self, case_id: str) -> bool:
        with self._lock, self._conn:
            return self._conn.execute("UPDATE cases SET deleted_at=? WHERE id=? AND deleted_at IS NULL", (now_iso(), case_id)).rowcount > 0

    # ---------------------------------------------------------------- uploads / jobs
    def add_upload(self, case_id: str, name: str, stored_path: str, size: int, sha256: str, by: str) -> str:
        upload_id = uuid.uuid4().hex
        self.run("INSERT INTO uploads VALUES(?,?,?,?,?,?,?,?)", (upload_id, case_id, name, stored_path, size, sha256, by, now_iso()))
        return upload_id

    def upload(self, upload_id: str) -> dict[str, Any] | None:
        return self.one("SELECT * FROM uploads WHERE id=?", (upload_id,))

    def uploads(self, case_id: str) -> list[dict[str, Any]]:
        return self.all("SELECT id, name, size, sha256, uploaded_by, uploaded_at FROM uploads WHERE case_id=? ORDER BY uploaded_at DESC", (case_id,))

    def add_job(self, case_id: str, kind: str, upload_id: str | None, by: str) -> str:
        job_id = uuid.uuid4().hex
        self.run("INSERT INTO jobs(id, case_id, kind, status, upload_id, created_by, created_at) VALUES(?,?,?,?,?,?,?)",
                 (job_id, case_id, kind, "queued", upload_id, by, now_iso()))
        return job_id

    def job(self, job_id: str) -> dict[str, Any] | None:
        return self.one("SELECT * FROM jobs WHERE id=?", (job_id,))

    def jobs(self, case_id: str) -> list[dict[str, Any]]:
        return self.all("SELECT * FROM jobs WHERE case_id=? ORDER BY created_at DESC LIMIT 200", (case_id,))

    def update_job(self, job_id: str, **fields: Any) -> None:
        cols = ", ".join(f"{k}=?" for k in fields)
        self.run(f"UPDATE jobs SET {cols} WHERE id=?", [*fields.values(), job_id])  # nosec B608 - column names are code constants

    def interrupt_orphans(self) -> int:
        """Jobs left 'running' or 'queued' by a previous process cannot continue: mark them so nobody waits for them."""
        with self._lock, self._conn:
            return self._conn.execute(
                "UPDATE jobs SET status='interrupted', finished_at=?, reason='server restarted' WHERE status IN ('running','queued')",
                (now_iso(),)).rowcount
