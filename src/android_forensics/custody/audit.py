"""Append-only, hash-chained audit log (JSON lines), kept outside the case database.

Each line commits to the previous one: ``hash = sha256(prev_hash + canonical_json(entry_without_hash))``. Removing,
reordering or editing any line breaks every later hash, which :meth:`AuditLog.verify` reports with the first bad line.

The file is opened ``O_APPEND`` and every write is flushed and ``fsync``-ed under an advisory lock, so concurrent
commands cannot interleave a line. For stronger guarantees the operating system can also forbid truncation
(``chflags uappnd`` on macOS, ``chattr +a`` on Linux; both need privileges, see :func:`harden`), and the chain head can be
written to a ticket or printed in a report — the report model includes it, so a later rewrite of the whole file is
detectable against that copy.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
import subprocess  # nosec B404 - fixed argv, no shell, used only by harden()
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from android_forensics import TOOL_NAME, __version__
from android_forensics.util import now_iso

GENESIS = "0" * 64
AUDIT_FILENAME = "audit.log.jsonl"

try:  # POSIX advisory locking; absent on Windows, where single-writer use is assumed
    import fcntl
except ImportError:  # pragma: no cover - platform specific
    fcntl = None  # type: ignore[assignment]


def _canonical(entry: dict[str, Any]) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()


def _entry_hash(prev: str, entry: dict[str, Any]) -> str:
    return hashlib.sha256(prev.encode() + b"\n" + _canonical(entry)).hexdigest()


@dataclass
class AuditVerification:
    ok: bool
    entries: int
    head: str
    error_line: int | None = None
    reason: str = ""
    notes: list[str] = field(default_factory=list)


class AuditLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    # ------------------------------------------------------------------ writing
    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        """Append one event; returns the stored entry (with ``seq``, ``prev`` and ``hash``)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            seq, prev = self._tail(fd)
            entry = {"seq": seq + 1, "ts": now_iso(), **event, "prev": prev}
            entry["hash"] = _entry_hash(prev, {k: v for k, v in entry.items() if k != "hash"})
            os.write(fd, _canonical(entry) + b"\n")
            os.fsync(fd)
            return entry
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @staticmethod
    def _tail(fd: int) -> tuple[int, str]:
        size = os.lseek(fd, 0, os.SEEK_END)
        if size == 0:
            return 0, GENESIS
        # the last line is short; read a generous tail block
        block = min(size, 65536)
        os.lseek(fd, size - block, os.SEEK_SET)
        data = os.read(fd, block)
        lines = [ln for ln in data.split(b"\n") if ln.strip()]
        try:
            last = json.loads(lines[-1])
            return int(last["seq"]), str(last["hash"])
        except (ValueError, KeyError, IndexError):
            # A damaged tail must not be silently papered over: chain from a sentinel so verify() flags it.
            return 0, "CORRUPT-TAIL"

    # ------------------------------------------------------------------ reading
    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def head(self) -> str:
        return self.verify().head

    def verify(self) -> AuditVerification:
        prev, n = GENESIS, 0
        if not self.path.exists():
            return AuditVerification(True, 0, GENESIS, notes=["no audit log yet"])
        with open(self.path, "rb") as fh:
            for lineno, raw in enumerate(fh, 1):
                if not raw.strip():
                    continue
                try:
                    entry = json.loads(raw)
                    claimed = entry.pop("hash")
                except (ValueError, KeyError, TypeError):
                    return AuditVerification(False, n, prev, lineno, "line is not a valid audit entry")
                if entry.get("prev") != prev:
                    return AuditVerification(False, n, prev, lineno, "chain broken: entry does not follow its predecessor")
                if entry.get("seq") != n + 1:
                    return AuditVerification(False, n, prev, lineno, f"sequence gap: expected {n + 1}, found {entry.get('seq')}")
                if _entry_hash(prev, entry) != claimed:
                    return AuditVerification(False, n, prev, lineno, "entry content does not match its hash (edited)")
                prev, n = claimed, n + 1
        return AuditVerification(True, n, prev)


def harden(path: Path | str) -> str:
    """Best-effort OS-level append-only flag. Returns a human-readable outcome; never raises."""
    p = str(path)
    try:
        if sys.platform == "darwin":
            cmd = ["chflags", "uappnd", p]
        elif sys.platform.startswith("linux"):
            cmd = ["chattr", "+a", p]
        else:
            return "no append-only flag available on this platform; rely on the hash chain and an external copy of the head"
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)  # nosec B603
        return "append-only flag set" if r.returncode == 0 else f"could not set append-only flag ({r.stderr.strip() or r.returncode})"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"could not set append-only flag ({exc})"


def actor() -> dict[str, str]:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser can fail in containers without passwd entries
        user = os.environ.get("USER", "unknown")
    return {"user": user, "host": socket.gethostname(), "os": platform.platform()}


def record_command(
    case_dir: Path | str,
    command: str,
    argv: list[str],
    outcome: str,
    *,
    detail: dict[str, Any] | None = None,
    db_chain_head: str | None = None,
    evidence_manifest_sha256: str | None = None,
    seconds: float | None = None,
) -> dict[str, Any]:
    """Write one command execution into ``<case>/audit.log.jsonl``."""
    case_dir = Path(case_dir)
    manifest_hash = evidence_manifest_sha256
    if manifest_hash is None:
        sidecar = case_dir / "evidence_manifest.json.sha256"
        if sidecar.exists():
            manifest_hash = sidecar.read_text().split()[0] if sidecar.read_text().split() else None
    return AuditLog(case_dir / AUDIT_FILENAME).append({
        "tool": TOOL_NAME, "tool_version": __version__, **actor(), "pid": os.getpid(),
        "command": command, "argv": argv, "outcome": outcome, "seconds": None if seconds is None else round(seconds, 3),
        "evidence_manifest_sha256": manifest_hash, "db_custody_head": db_chain_head, "detail": detail or {},
    })
