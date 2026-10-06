"""B1 — scaling and memory: how do wall time and *peak process memory* grow with evidence size?

Every measurement runs the real CLI in a fresh child process and reads that child's peak resident set size from the kernel
(``os.wait4``), so nothing is estimated and Python-level tracing does not distort timings.

  B1a  one SQLite database of N rows (with genuine deletions): ``analyze`` (scan, extract, recover, carve, correlate, validate)
  B1b  one large evidence file inside an ext4 image: ingestion throughput and memory (streams, so memory should stay flat)
  B1c  one large hostile-shaped WAL file: memory behaviour of WAL parsing

Usage:  python experiments/b1_scaling.py [--max-rows 1000000] [--image-mb 1024]      writes experiments/results/b1_*.csv|json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from android_forensics import __version__

OUT = Path(__file__).parent / "results"
TEL = "data/data/com.android.providers.telephony/databases"


def run_measured(argv: list[str], env: dict[str, str] | None = None) -> dict:
    t0 = time.monotonic()
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env={**os.environ, **(env or {})})
    _pid, status, ru = os.wait4(proc.pid, 0)
    seconds = time.monotonic() - t0
    err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
    # ru_maxrss is bytes on macOS, kilobytes on Linux
    peak = ru.ru_maxrss if sys.platform == "darwin" else ru.ru_maxrss * 1024
    return {"seconds": round(seconds, 2), "peak_rss_mb": round(peak / 1e6, 1), "exit": os.waitstatus_to_exitcode(status), "stderr_tail": err[-300:]}


def build_sms_db(path: Path, rows: int) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, read INTEGER, body TEXT)")
    batch = []
    for i in range(1, rows + 1):
        batch.append((i, f"+1202555{i % 10000:04d}", 1709280000000 + i * 1000, 1 + i % 2, i % 2, f"message {i} " + "lorem ipsum dolor sit amet " * (1 + i % 5)))
        if len(batch) == 50_000:
            c.executemany("INSERT INTO sms VALUES(?,?,?,?,?,?)", batch)
            batch.clear()
    if batch:
        c.executemany("INSERT INTO sms VALUES(?,?,?,?,?,?)", batch)
    c.commit()
    c.execute("DELETE FROM sms WHERE _id % 50 = 0")      # 2% genuine deletions to recover
    c.commit()
    c.close()
    return path.stat().st_size


def b1a(max_rows: int) -> list[dict]:
    sizes = [r for r in (10_000, 100_000, 300_000, 1_000_000, 3_000_000) if r <= max_rows]
    out = []
    for rows in sizes:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            size = build_sms_db(td / "ev" / TEL / "mmssms.db", rows)
            m = run_measured([sys.executable, "-m", "android_forensics", "analyze", str(td / "ev"), "--cases-dir", str(td / "cases"), "--name", "b", "--no-report"])
            row = {"experiment": "B1a", "rows": rows, "db_mb": round(size / 1e6, 1), **m, "mb_per_s": round(size / 1e6 / m["seconds"], 2) if m["seconds"] else None}
            print(row, flush=True)
            out.append(row)
            shutil.rmtree(td / "cases", ignore_errors=True)
    return out


def b1b(image_mb: int) -> list[dict]:
    """A random-content file of ``image_mb`` inside an ext4 image (built with Docker's mke2fs), ingested with and without preservation."""
    if not shutil.which("docker"):
        print("docker not available: skipping B1b")
        return []
    out = []
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        src = td / "src" / "data" / "com.example" / "files"
        src.mkdir(parents=True)
        with open(src / "blob.bin", "wb") as fh:
            for _ in range(image_mb):
                fh.write(os.urandom(1 << 20))
        (src / "note.txt").write_text("small file")
        size = int(image_mb * 1.2) + 16
        subprocess.run(["docker", "run", "--rm", "-v", f"{td}:/w", "alpine:3.20", "sh", "-c",
                        f"apk add --no-cache e2fsprogs >/dev/null && mke2fs -q -t ext4 -b 4096 -d /w/src -L userdata -E root_owner=0:0 /w/img.raw {size}M"],
                       check=True, capture_output=True)
        img = td / "img.raw"
        for policy in ("none", "all"):
            case = td / f"case_{policy}"
            subprocess.run([sys.executable, "-m", "android_forensics", "init-case", "x", "--cases-dir", str(case)], check=True, capture_output=True)
            m = run_measured([sys.executable, "-m", "android_forensics", "ingest", "x", str(img), "--cases-dir", str(case), "--preserve", policy])
            row = {"experiment": "B1b", "image_mb": round(img.stat().st_size / 1e6), "file_mb": image_mb, "preserve": policy, **m,
                   "mb_per_s": round(img.stat().st_size / 1e6 / m["seconds"], 1) if m["seconds"] else None}
            print(row, flush=True)
            out.append(row)
            shutil.rmtree(case, ignore_errors=True)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-rows", type=int, default=1_000_000)
    ap.add_argument("--image-mb", type=int, default=1024)
    ap.add_argument("--skip", nargs="*", default=[])
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    rows: list[dict] = []
    if "a" not in args.skip:
        rows += b1a(args.max_rows)
    if "b" not in args.skip:
        rows += b1b(args.image_mb)
    meta = {"tool": __version__, "python": sys.version.split()[0], "platform": platform.platform(), "cpu_count": os.cpu_count(),
            "machine": platform.machine()}
    (OUT / "b1_scaling.json").write_text(json.dumps({"meta": meta, "rows": rows}, indent=2))
    if rows:
        cols = sorted({k for r in rows for k in r})
        with open(OUT / "b1_scaling.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)


if __name__ == "__main__":
    main()
