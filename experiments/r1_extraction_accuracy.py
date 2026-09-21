"""Review 1 experiments — reproducible, measured (nothing here is hard-coded).

E1  Extraction accuracy: for several seeds and dataset sizes, generate synthetic evidence with known ground truth,
    run the full Review 1 pipeline, and score extracted ACTIVE artifacts against the truth (precision / recall / F1).
E2  Scaling: extraction throughput (timed without tracing) and peak Python memory (tracemalloc, separate run) as the SMS table grows.
E3  Ingestion throughput: hashing (MD5 + SHA-1 + SHA-256 in one pass) and copying ~300 MiB from a directory, zip and tar.

Usage:  python experiments/r1_extraction_accuracy.py            (writes experiments/results/*.csv|json)
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import sqlite3
import sys
import tarfile
import tempfile
import time
import tracemalloc
import zipfile
from pathlib import Path

from android_forensics import __version__
from android_forensics.acquisition import PreservePolicy, ingest_evidence
from android_forensics.acquisition.ingest import ingest_source
from android_forensics.lab.ground_truth import compare_active
from android_forensics.lab.synth import SynthSpec, generate
from android_forensics.pipeline.runner import run_pipeline
from android_forensics.storage.case_store import CaseStore

OUT = Path(__file__).parent / "results"
SEEDS = [1, 2, 3, 4, 5]
SIZES = [(20, 10, 10), (120, 60, 30), (500, 250, 80)]  # (sms, calls, contacts)
SCALES = [1_000, 10_000, 50_000, 100_000, 250_000]


def e1() -> list[dict]:
    rows = []
    for seed in SEEDS:
        for sms, calls, contacts in SIZES:
            with tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                spec = SynthSpec(seed=seed, sms_count=sms, call_count=calls, call_wal_rows=max(3, calls // 3), contact_count=contacts,
                                 contacts_marked_deleted=min(3, contacts), browser_urls=40, browser_visits=sms + 30, downloads=5)
                truth = generate(tmp / "ev", spec)
                store = CaseStore.create(tmp / "case", "e1")
                t0 = time.perf_counter()
                ingest_source(store, tmp / "ev" / "android_dump")
                stages = run_pipeline(store)
                elapsed = time.perf_counter() - t0
                for atype, r in compare_active(store, truth).items():
                    rows.append({"seed": seed, "sms_rows": sms, "call_rows": calls, "contacts": contacts, "artifact_type": atype,
                                 "expected": r.expected, "extracted": r.extracted, "correct": r.correct,
                                 "precision": round(r.precision, 4), "recall": round(r.recall, 4), "f1": round(r.f1, 4),
                                 "mismatches": len(r.mismatches), "pipeline_seconds": round(elapsed, 3),
                                 "extract_seconds": stages["extract"]["seconds"]})
    return rows


def _build_sms_db(tmp: Path, n: int) -> Path:
    db = tmp / "ev/data/data/com.android.providers.telephony/databases/mmssms.db"
    db.parent.mkdir(parents=True)
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER, date_sent INTEGER, "
              "read INTEGER, type INTEGER, body TEXT)")
    c.executemany("INSERT INTO sms VALUES(?,?,?,?,?,?,?,?)",
                  ((i, i % 500, f"+1202555{i % 9000:04d}", 1709280000000 + i * 1000, 0, 1, 1 + i % 2, f"message body number {i} " + "x" * (i % 80)) for i in range(1, n + 1)))
    c.commit()
    c.close()
    return db


def _scan_extract(tmp: Path, n: int) -> tuple[CaseStore, dict]:
    store = CaseStore.create(tmp / "case", "e2")
    ingest_source(store, tmp / "ev")
    return store, run_pipeline(store, ["scan", "extract"])


def e2() -> list[dict]:
    """Time and memory are measured in separate runs: tracemalloc slows allocation-heavy code several-fold."""
    rows = []
    for n in SCALES:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            db = _build_sms_db(tmp, n)
            store, stages = _scan_extract(tmp, n)
            extracted = store.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='sms'")
            seconds = stages["extract"]["seconds"]
            db_bytes = db.stat().st_size
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            _build_sms_db(tmp, n)
            tracemalloc.start()
            _scan_extract(tmp, n)
            _cur, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        rows.append({"sms_rows": n, "db_bytes": db_bytes, "extracted": extracted, "extract_seconds": seconds,
                     "rows_per_second": round(extracted / seconds), "peak_python_mib": round(peak / 2**20, 1)})
    return rows


def e3() -> list[dict]:
    """Ingestion throughput on ~300 MiB: 3 x 100 MiB files plus 3,000 small files (incompressible data)."""
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        ev = tmp / "ev"
        ev.mkdir()
        block = os.urandom(1 << 20)
        for i in range(3):
            with open(ev / f"big{i}.bin", "wb") as fh:
                for _ in range(100):
                    fh.write(block)
        for i in range(3000):
            d = ev / f"d{i % 50}"
            d.mkdir(exist_ok=True)
            (d / f"f{i}.txt").write_bytes(block[i : i + 400])
        files = sorted(p for p in ev.rglob("*") if p.is_file())
        total = sum(p.stat().st_size for p in files)
        z, t = tmp / "a.zip", tmp / "a.tar"
        with zipfile.ZipFile(z, "w", zipfile.ZIP_STORED) as zf:
            for p in files:
                zf.write(p, p.relative_to(ev).as_posix())
        with tarfile.open(t, "w") as tf:
            for p in files:
                tf.add(p, p.relative_to(ev).as_posix())

        def run(label: str, src: Path, **kw) -> None:
            t0 = time.perf_counter()
            r = ingest_evidence(src, tmp / f"w_{label.replace(' ', '_')}", **kw)
            dt = time.perf_counter() - t0
            rows.append({"input": label, "files": len(r.files), "mib": round(total / 2**20), "seconds": round(dt, 2),
                         "mib_per_second": round(total / 2**20 / dt)})

        run("directory", ev)
        run("directory, copy all files", ev, preserve=PreservePolicy.ALL)
        run("zip (stored)", z)
        run("tar", t)
        h, t0 = hashlib.sha256(), time.perf_counter()
        for _ in range(300):
            h.update(block)
        rows.append({"input": "reference: SHA-256 alone (hashlib)", "files": 0, "mib": 300,
                     "seconds": round(time.perf_counter() - t0, 2), "mib_per_second": round(300 / (time.perf_counter() - t0))})
    return rows


def write(name: str, rows: list[dict]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / f"{name}.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    print("E1: extraction accuracy over", len(SEEDS) * len(SIZES), "synthetic datasets ...", flush=True)
    r1 = e1()
    write("r1_e1_extraction_accuracy", r1)
    print("E2: scaling ...", flush=True)
    r2 = e2()
    write("r1_e2_scaling", r2)
    print("E3: ingestion throughput ...", flush=True)
    r3 = e3()
    write("r1_e3_ingestion", r3)
    summary = {
        "tool_version": __version__, "python": sys.version.split()[0], "sqlite": sqlite3.sqlite_version, "platform": platform.platform(),
        "e1": {"datasets": len(SEEDS) * len(SIZES), "records_expected": sum(r["expected"] for r in r1),
               "records_extracted": sum(r["extracted"] for r in r1), "records_correct": sum(r["correct"] for r in r1),
               "min_precision": min(r["precision"] for r in r1), "min_recall": min(r["recall"] for r in r1),
               "min_f1": min(r["f1"] for r in r1), "total_field_mismatches": sum(r["mismatches"] for r in r1)},
        "e2": r2,
        "e3": r3,
    }
    (OUT / "r1_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary["e1"], indent=2))
    print(f"{'sms rows':>10} {'db MiB':>8} {'seconds':>8} {'rows/s':>9} {'peak MiB':>9}")
    for r in r2:
        print(f"{r['sms_rows']:>10,} {r['db_bytes']/2**20:>8.1f} {r['extract_seconds']:>8.2f} {r['rows_per_second']:>9,} {r['peak_python_mib']:>9.1f}")
    print(f"{'ingestion input':<38} {'files':>6} {'MiB':>5} {'seconds':>8} {'MiB/s':>7}")
    for r in r3:
        print(f"{r['input']:<38} {r['files']:>6,} {r['mib']:>5} {r['seconds']:>8.2f} {r['mib_per_second']:>7,}")


if __name__ == "__main__":
    main()
