"""Run an analysis command as a resource-limited child process.

Evidence is hostile, so analysis never runs in the web server's process. Each job is a fresh interpreter started through
:mod:`android_forensics.server.limited_exec`, which applies POSIX resource limits *before* ``exec``-ing the real command (this
avoids ``preexec_fn``, which is unsafe in a multi-threaded server):

* ``RLIMIT_CPU``   — CPU seconds (SIGXCPU, then SIGKILL);
* ``RLIMIT_AS``    — address space, i.e. memory (enforced on Linux; macOS ignores it — use container limits there);
* ``RLIMIT_FSIZE`` — the largest file the job may create (a decompression bomb cannot fill the disk with one file);
* ``RLIMIT_NOFILE``, ``RLIMIT_CORE=0`` — descriptor cap, no core dumps (they would contain evidence).

Plus: a new session/process group (the whole tree can be killed), a wall-clock timeout, a scrubbed environment (no server
secrets are inherited) and a cancel hook. For network isolation run the server itself in a container with ``--network none``
for the worker or use ``unshare -n`` — see docs/deployment.md.
"""

from __future__ import annotations

import os
import signal
import subprocess  # nosec B404 - fixed argv, no shell
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Limits:
    cpu_seconds: int
    wall_seconds: int
    memory_bytes: int
    file_bytes: int
    open_files: int = 2048


@dataclass
class RunResult:
    exit_code: int | None
    reason: str          # ok | failed | timeout | cancelled | killed
    seconds: float


def scrubbed_env(extra: dict[str, str] | None = None, home: Path | None = None) -> dict[str, str]:
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONHASHSEED": "0"}
    if home is not None:
        env["HOME"] = str(home)
        env["TMPDIR"] = str(home)
    env.update(extra or {})
    return env


def limited_command(limits: Limits, argv: list[str]) -> list[str]:
    return [sys.executable, "-m", "android_forensics.server.limited_exec", "--cpu", str(limits.cpu_seconds), "--as", str(limits.memory_bytes),
            "--fsize", str(limits.file_bytes), "--nofile", str(limits.open_files), "--", *argv]


def run_limited(
    argv: list[str], *, cwd: Path, env: dict[str, str], limits: Limits, log_path: Path,
    on_start: Callable[[int], None] | None = None, cancelled: threading.Event | None = None,
) -> RunResult:
    t0 = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(  # nosec B603 - argv is built by the server, never from request data
            limited_command(limits, argv), cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if on_start:
            on_start(proc.pid)
        reason = "ok"
        while True:
            try:
                code = proc.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                if cancelled is not None and cancelled.is_set():
                    reason = "cancelled"
                elif time.monotonic() - t0 > limits.wall_seconds:
                    reason = "timeout"
                else:
                    continue
                _kill_group(proc.pid)
                code = proc.wait()
                break
    if reason == "ok":
        if code < 0:
            reason = "killed"   # by a signal: typically a resource limit (SIGXCPU/SIGKILL/SIGSEGV on MemoryError)
        elif code != 0:
            reason = "failed"
    return RunResult(code, reason, time.monotonic() - t0)


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(pid, 0)
        except (ProcessLookupError, PermissionError):  # macOS reports EPERM for a group whose leader is already a zombie
            return
        time.sleep(0.1)
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
