"""V1 — validation on a real public Android acquisition (Digital Corpora / Josh Hickman images).

What can be checked without a ground-truth list of "what the user deleted"?

  A. **Active-extraction fidelity.** For every table a parser claims, the number of ACTIVE artifacts must equal the number of rows
     SQLite itself reports for that table (read from the same bytes, WAL included). Any difference is listed.
  B. **Run profile.** Wall time and peak memory of the real CLI on the real evidence; every scan issue, validation outcome, status
     count and carved-candidate kind, so nothing is hidden behind a headline.
  C. **Agreement with reference tools on deleted content.** For databases where this tool recovered deleted records, DC3
     SQLite Dissect (-c -f) and SQLite's own ``.recover`` are run on the same bytes. The comparison unit is the set of distinct text
     values (>= 8 chars) that appear in deleted content and nowhere in the live data. This is *agreement*, not accuracy: with no
     ground truth for real deletions, a value only one tool finds is reported as such, never scored as an error.

Usage:  python experiments/v1_real_corpus.py EVIDENCE --name android9 [--cases-dir DIR] [--keep]
        (EVIDENCE may be the .tar.gz / .zip / directory as downloaded; the tool streams it.)
        Optional: AF_SQLD=/path/to/sqlite_dissect
Writes  experiments/results/v1_<name>.json|csv  (+ a short markdown summary on stdout)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from android_forensics import __version__
from android_forensics.sqlite.discovery import preserved_path
from android_forensics.storage.case_store import CaseStore

OUT = Path(__file__).parent / "results"
MIN_TOKEN = 8


def run_measured(argv: list[str]) -> dict:
    t0 = time.monotonic()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    _pid, status, ru = os.wait4(proc.pid, 0)
    out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
    peak = ru.ru_maxrss if sys.platform == "darwin" else ru.ru_maxrss * 1024
    return {"seconds": round(time.monotonic() - t0, 1), "peak_rss_mb": round(peak / 1e6), "exit": os.waitstatus_to_exitcode(status), "tail": out[-600:]}


def live_tokens(db: Path) -> set[str]:
    toks: set[str] = set()
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro&immutable=0", uri=True)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
            try:
                for row in con.execute(f'SELECT * FROM "{name}"'):
                    for v in row:
                        if isinstance(v, str) and len(v) >= MIN_TOKEN:
                            toks.add(v.strip())
            except sqlite3.DatabaseError:
                continue
        con.close()
    except sqlite3.DatabaseError:
        pass
    return toks


def cells(text: str) -> set[str]:
    out = set()
    for piece in re.split(r"[\r\n,|;\t\"]+", text):
        piece = piece.strip()
        if len(piece) >= MIN_TOKEN:
            out.add(piece)
    return out


def copy_db(store: CaseStore, file_row, dest: Path) -> Path:
    """The preserved copy of a database plus its -wal/-journal, copied to ``dest/db*`` for tools that need a path."""
    src = preserved_path(store, file_row)
    for p in dest.glob("db*"):
        p.unlink()
    shutil.copy(src, dest / "db")
    for suffix in ("-wal", "-journal"):
        side = store.one("SELECT * FROM evidence_files WHERE source_id=? AND path=?", (file_row["source_id"], file_row["path"] + suffix))
        if side is not None and side["preserved_copy"]:
            shutil.copy(preserved_path(store, side), dest / ("db" + suffix))
    return dest / "db"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence")
    ap.add_argument("--name", required=True)
    ap.add_argument("--cases-dir", default=None)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--max-ref-db-mb", type=float, default=40.0)
    args = ap.parse_args()
    cases_dir = Path(args.cases_dir or tempfile.mkdtemp(prefix="v1_cases_"))
    exe = os.environ.get("AF_SQLD")

    case_dir = cases_dir / args.name
    if case_dir.exists() and (case_dir / "case.db").exists():
        run = {"seconds": None, "note": "reused existing case"}
    else:
        run = run_measured([sys.executable, "-m", "android_forensics", "analyze", args.evidence, "--cases-dir", str(cases_dir), "--name", args.name, "--no-report"])
    print("run:", {k: v for k, v in run.items() if k != "tail"}, flush=True)
    store = CaseStore.open(case_dir)

    prof = {
        "sources": [dict(r) for r in store.q("SELECT id, source_type, original_name, file_count, total_bytes, complete FROM evidence_sources")],
        "files_by_kind": {r["kind"]: r["n"] for r in store.q("SELECT kind, COUNT(*) n FROM evidence_files GROUP BY kind ORDER BY n DESC")},
        "scan_issues": {r["issue_type"]: r["n"] for r in store.q("SELECT issue_type, COUNT(*) n FROM scan_issues GROUP BY issue_type ORDER BY n DESC")},
        "databases": {r["open_status"]: r["n"] for r in store.q("SELECT open_status, COUNT(*) n FROM databases GROUP BY open_status")},
        "artifacts": {f"{r['artifact_type']}/{r['status']}": r["n"] for r in store.q("SELECT artifact_type, status, COUNT(*) n FROM artifacts GROUP BY 1,2")},
        "recovered_records": {f"{r['status']}/{r['method']}": r["n"] for r in store.q("SELECT status, method, COUNT(*) n FROM recovered_records GROUP BY 1,2")},
        "carved": {r["kind"]: r["n"] for r in store.q("SELECT kind, COUNT(*) n FROM carved_candidates GROUP BY kind")},
        "validation": {r["status"]: r["n"] for r in store.q("SELECT status, COUNT(*) n FROM validation_results GROUP BY status")},
        "timeline_events": store.scalar("SELECT COUNT(*) FROM timeline_events"),
        "counts": store.counts(),
    }

    # ---- A. active-extraction fidelity
    fidelity = []
    scratch = Path(tempfile.mkdtemp(prefix="v1_fid_"))
    for t in store.q("SELECT t.database_id, t.name, t.parsed_by, d.evidence_file_id, f.path, f.preserved_copy, f.source_id FROM db_tables t "
                     "JOIN databases d ON d.id=t.database_id JOIN evidence_files f ON f.id=d.evidence_file_id WHERE t.parsed_by IS NOT NULL AND t.obj_type='table'"):
        if t["parsed_by"] == "contacts":
            continue   # contacts are assembled from several tables; no single row count to compare
        db = copy_db(store, t, scratch)
        try:
            con = sqlite3.connect(db)
            expected = con.execute(f'SELECT COUNT(*) FROM "{t["name"]}"').fetchone()[0]
            con.close()
        except sqlite3.DatabaseError as exc:
            fidelity.append({"database": t["path"], "table": t["name"], "parser": t["parsed_by"], "expected": None, "extracted": None, "error": str(exc)[:80]})
            continue
        got = store.scalar("SELECT COUNT(*) FROM artifacts WHERE status='ACTIVE' AND source_database=? AND source_table=?", (t["path"], t["name"])) or 0
        fidelity.append({"database": t["path"], "table": t["name"], "parser": t["parsed_by"], "expected": expected, "extracted": got, "match": expected == got})
    shutil.rmtree(scratch, ignore_errors=True)
    prof["fidelity"] = {"tables_checked": len(fidelity), "tables_matching": sum(1 for r in fidelity if r.get("match")),
                        "rows_expected": sum(r["expected"] or 0 for r in fidelity), "rows_extracted": sum(r["extracted"] or 0 for r in fidelity),
                        "mismatches": [r for r in fidelity if not r.get("match")]}
    print("fidelity:", {k: v for k, v in prof["fidelity"].items() if k != "mismatches"}, "mismatches:", len(prof["fidelity"]["mismatches"]), flush=True)

    # ---- C. agreement with reference tools on deleted content
    agree = []
    work = Path(tempfile.mkdtemp(prefix="v1_ref_"))
    dbs = store.q("SELECT DISTINCT d.evidence_file_id AS fid, f.path, f.preserved_copy, f.size, f.source_id FROM recovered_records r JOIN evidence_files f ON f.id=r.database_file_id "
                  "JOIN databases d ON d.evidence_file_id=f.id")
    for d in dbs:
        if d["size"] > args.max_ref_db_mb * 1e6:
            continue
        ours_vals: set[str] = set()
        for r in store.q("SELECT values_json FROM recovered_records WHERE database_file_id=?", (d["fid"],)):
            for v in json.loads(r["values_json"] or "{}").values():
                if isinstance(v, str) and len(v) >= MIN_TOKEN:
                    ours_vals.add(v.strip())
        db = copy_db(store, d, work)
        live = live_tokens(db)
        ours = ours_vals - live
        ref: dict[str, set[str]] = {}
        sql = subprocess.run(["sqlite3", str(db), ".recover"], capture_output=True, timeout=600).stdout.decode("utf-8", "replace")
        ref["sqlite3_recover"] = cells("\n".join(line for line in sql.splitlines() if "lost_and_found" in line)) - live
        if exe:
            outdir = work / "dissect"
            shutil.rmtree(outdir, ignore_errors=True)
            outdir.mkdir()
            subprocess.run([exe, str(db), "-d", str(outdir), "-e", "csv", "-c", "-f", "-l", "off"], capture_output=True, timeout=1800)
            txt = "\n".join(f.read_text("utf-8", "replace") for f in outdir.rglob("*") if f.is_file())
            ref["sqlite_dissect"] = cells(txt) - live
        row = {"database": d["path"], "size_mb": round(d["size"] / 1e6, 2), "ours_deleted_values": len(ours)}
        for name, toks in ref.items():
            row[f"{name}_deleted_values"] = len(toks)
            row[f"both_ours_and_{name}"] = len(ours & toks)
            row[f"ours_only_vs_{name}"] = len(ours - toks)
            row[f"{name}_only"] = len(toks - ours)
        agree.append(row)
        print("agree:", row, flush=True)
    shutil.rmtree(work, ignore_errors=True)
    prof["agreement"] = agree

    meta = {"tool": __version__, "python": sys.version.split()[0], "platform": platform.platform(), "dataset": args.name, "run": {k: v for k, v in run.items() if k != "tail"}}
    OUT.mkdir(exist_ok=True)
    (OUT / f"v1_{args.name}.json").write_text(json.dumps({"meta": meta, **prof}, indent=2, default=str))
    with open(OUT / f"v1_{args.name}_fidelity.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["database", "table", "parser", "expected", "extracted", "match", "error"])
        w.writeheader()
        for r in fidelity:
            w.writerow({k: r.get(k) for k in w.fieldnames})
    if not args.keep and not args.cases_dir:
        shutil.rmtree(cases_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
