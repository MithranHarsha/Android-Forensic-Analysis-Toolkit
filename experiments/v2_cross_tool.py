"""V2 — independent comparison with reference deleted-record recovery tools on the 28-condition deletion matrix.

Ground truth is physical and independent of any tool (``lab.deletions``): for every case we know which deleted rows still have
their bytes in the files and in which state. Four tools see the *same files*:

  ours            this project's page-level engine (``recover_database``)
  sqlite3 .recover  SQLite's own recovery command (rows it cannot attach to a table land in ``lost_and_found``)
  undark          github.com/inflex/undark (dumps cells it can parse from pages, including freed ones)
  sqlite_dissect  DC3 SQLite Dissect with carving and freelist carving (``-c -f``), WAL/journal aware

Each deleted row carries a unique token (``Msg#00042``) in its text column, so "tool X recovered row R" is decided by whether the
token appears in the tool's output **in a place that is not the live table** (for .recover: ``lost_and_found`` inserts; for the
others the deleted row's token is by definition not in the live data, so any appearance counts).

Reported per tool: recall over rows whose bytes physically survive (``expected_recoverable``) — the only quantity that is
comparable across tools with different output formats. Precision is reported only for ``ours`` (scored structurally by the lab).

Needs the reference tools; point at them with environment variables (defaults to ``scratchpad`` layout used in development):
  AF_SQLD=/path/to/sqlite_dissect   AF_UNDARK_DOCKER_DIR=/dir/containing/undark_linux   (docker is used to run undark)

Usage:  python experiments/v2_cross_tool.py      writes experiments/results/v2_cross_tool.csv|json
"""

from __future__ import annotations

import csv
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from android_forensics import __version__
from android_forensics.lab.deletions import build_case, standard_matrix
from android_forensics.lab.evaluation import score_case
from android_forensics.sqlite.recover_db import recover_database

OUT = Path(__file__).parent / "results"
TOKEN = re.compile(r"Msg#\d{5}")


def tokens(text: str) -> set[str]:
    return set(TOKEN.findall(text))


def run(argv: list[str], timeout: int = 300, **kw) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout, **kw)
        return (r.stdout + b"\n" + r.stderr).decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, OSError) as exc:
        return f"<<{type(exc).__name__}: {exc}>>"


def sqlite_recover(db: Path, work: Path) -> set[str]:
    """Tokens found in lost_and_found: rows .recover could not attach to a live table (i.e. deleted / orphaned rows)."""
    copy = work / "rec.db"
    for p in work.glob("rec.db*"):
        p.unlink()
    shutil.copy(db, copy)
    for suffix in ("-wal", "-journal"):
        if (db.parent / (db.name + suffix)).exists():
            shutil.copy(db.parent / (db.name + suffix), work / ("rec.db" + suffix))
    sql = run(["sqlite3", str(copy), ".recover"])
    lost = "\n".join(line for line in sql.splitlines() if "lost_and_found" in line)
    return tokens(lost)


def undark(db: Path, work: Path, undark_dir: Path | None) -> set[str] | None:
    if undark_dir is None or not shutil.which("docker"):
        return None
    copy = work / "u.db"
    shutil.copy(db, copy)
    for suffix in ("-wal", "-journal"):
        if (db.parent / (db.name + suffix)).exists():
            shutil.copy(db.parent / (db.name + suffix), work / ("u.db" + suffix))
    out = run(["docker", "run", "--rm", "-v", f"{work}:/data", "-v", f"{undark_dir}:/tool:ro", "debian:bookworm-slim", "/tool/undark_linux",
               "-i", "/data/u.db", "--freespace"], timeout=300)
    return tokens(out)


def dissect(db: Path, work: Path, exe: str | None) -> set[str] | None:
    if not exe:
        return None
    outdir = work / "dissect_out"
    shutil.rmtree(outdir, ignore_errors=True)
    outdir.mkdir()
    argv = [exe, str(db), "-d", str(outdir), "-e", "csv", "-c", "-f", "-l", "off"]
    run(argv, timeout=300)
    found: set[str] = set()
    for f in outdir.rglob("*"):
        if f.is_file():
            found |= tokens(f.read_text("utf-8", "replace"))
    return found


def main() -> None:
    exe = os.environ.get("AF_SQLD") or shutil.which("sqlite_dissect")
    undark_dir = Path(os.environ["AF_UNDARK_DOCKER_DIR"]) if os.environ.get("AF_UNDARK_DOCKER_DIR") else None
    rows, per_tool = [], {"ours": [0, 0], "sqlite3_recover": [0, 0], "undark": [0, 0], "sqlite_dissect": [0, 0]}
    with tempfile.TemporaryDirectory(prefix="v2_") as tmp:
        tmp = Path(tmp)
        for case in standard_matrix():
            out = build_case(tmp / "cases", case)
            scratch = tmp / "scratch"
            report = recover_database(out.database, out.sidecars, scratch)
            score = score_case(out.truth, report.rows)
            work = tmp / "work"
            shutil.rmtree(work, ignore_errors=True)
            work.mkdir()
            recoverable = {r["values"]["body"].split()[0] for r in out.truth["deleted_rows"] if r["expected_class"] != "UNRECOVERABLE"}
            tool_found = {
                "sqlite3_recover": sqlite_recover(out.database, work),
                "undark": undark(out.database, work, undark_dir),
                "sqlite_dissect": dissect(out.database, work, exe),
            }
            row = {"case": case.name, "condition": case.condition, "expected_recoverable": len(recoverable),
                   "ours": score.matched_expected, "ours_false_positives": score.false_positives}
            per_tool["ours"][0] += score.matched_expected
            per_tool["ours"][1] += len(recoverable)
            for name, found in tool_found.items():
                if found is None:
                    row[name] = None
                    continue
                hit = len(recoverable & found)
                row[name] = hit
                per_tool[name][0] += hit
                per_tool[name][1] += len(recoverable)
            print({k: row[k] for k in ("case", "expected_recoverable", "ours", "sqlite3_recover", "undark", "sqlite_dissect")}, flush=True)
            rows.append(row)
    summary = {name: {"found": a, "expected_recoverable": b, "recall": round(a / b, 4) if b else None} for name, (a, b) in per_tool.items()}
    print(json.dumps(summary, indent=2))
    OUT.mkdir(exist_ok=True)
    meta = {"tool": __version__, "python": sys.version.split()[0], "platform": platform.platform(), "sqlite3_cli": run(["sqlite3", "--version"]).split()[0],
            "dissect": exe or None, "undark": "inflex/undark (built from source)" if undark_dir else None, "cases": len(rows), "time": time.strftime("%Y-%m-%d")}
    (OUT / "v2_cross_tool.json").write_text(json.dumps({"meta": meta, "summary": summary, "cases": rows}, indent=2))
    with open(OUT / "v2_cross_tool.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
