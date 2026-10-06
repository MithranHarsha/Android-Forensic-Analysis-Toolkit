from __future__ import annotations

import sys
import threading
import time

import pytest

from android_forensics.server.sandbox import Limits, run_limited, scrubbed_env

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX resource limits")

BIG = 1 << 40


def run(code: str, tmp_path, **kw):
    limits = Limits(**{"cpu_seconds": 60, "wall_seconds": 30, "memory_bytes": BIG, "file_bytes": BIG, **kw.pop("limits", {})})
    log = tmp_path / "job.log"
    res = run_limited([sys.executable, "-c", code], cwd=tmp_path, env=scrubbed_env(home=tmp_path, extra=kw.pop("env", None)), limits=limits, log_path=log, **kw)
    return res, log.read_text()


def test_normal_job_succeeds_and_output_is_logged(tmp_path):
    res, log = run("print('hello from the sandbox')", tmp_path)
    assert res.reason == "ok" and res.exit_code == 0 and "hello from the sandbox" in log


def test_failing_job_is_reported_as_failed(tmp_path):
    res, _ = run("import sys; sys.exit(3)", tmp_path)
    assert res.reason == "failed" and res.exit_code == 3


def test_cpu_limit_kills_a_busy_loop(tmp_path):
    t0 = time.monotonic()
    res, _ = run("while True: pass", tmp_path, limits={"cpu_seconds": 1, "wall_seconds": 60})
    assert res.reason == "killed" and time.monotonic() - t0 < 20


def test_wall_clock_timeout_kills_a_sleeper_and_its_children(tmp_path):
    t0 = time.monotonic()
    res, _ = run("import subprocess,time; subprocess.Popen(['sleep','300']); time.sleep(300)", tmp_path, limits={"wall_seconds": 2})
    assert res.reason == "timeout" and time.monotonic() - t0 < 30
    time.sleep(0.5)
    import subprocess
    assert subprocess.run(["pgrep", "-f", "sleep 300"], capture_output=True).returncode == 1, "child process survived the kill"


def test_cancel_stops_the_job(tmp_path):
    ev = threading.Event()
    threading.Timer(1.0, ev.set).start()
    res, _ = run("import time; time.sleep(300)", tmp_path, cancelled=ev)
    assert res.reason == "cancelled"


def test_file_size_limit_stops_a_disk_filler(tmp_path):
    res, log = run("f=open('big.bin','wb')\nfor _ in range(100): f.write(b'x'*1_000_000)\nf.close()", tmp_path, limits={"file_bytes": 2_000_000})
    assert res.reason in ("killed", "failed") and (tmp_path / "big.bin").stat().st_size <= 2_000_000


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS is enforced on Linux (macOS ignores it); containers cap memory there")
def test_memory_limit_stops_a_memory_hog(tmp_path):
    res, log = run("x = bytearray(2 * 1024**3)", tmp_path, limits={"memory_bytes": 512 * 1024 ** 2})
    assert res.reason in ("failed", "killed") and "MemoryError" in log


def test_environment_is_scrubbed_of_server_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "super-secret")
    monkeypatch.setenv("ANDROID_FORENSICS_TOKEN", "afk_secret")
    res, log = run("import os; print(sorted(os.environ))", tmp_path)
    assert "super-secret" not in log and "AWS_SECRET_ACCESS_KEY" not in log and "afk_secret" not in log
    assert "HOME" in log and "PATH" in log


def test_core_dumps_are_disabled(tmp_path):
    res, log = run("import resource; print(resource.getrlimit(resource.RLIMIT_CORE))", tmp_path)
    assert "(0, 0)" in log
