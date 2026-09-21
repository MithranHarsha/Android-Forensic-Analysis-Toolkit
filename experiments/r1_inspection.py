"""Review 1 experiments for the SQLite inspection engine — measured, reproducible (seeded), nothing hard-coded.

E4  Throughput and memory of ``SQLiteInspector``: schema-only, streaming ``iter_records`` and full in-memory ``inspect``
    as one table grows. Time is measured without tracing; peak Python memory in a separate tracemalloc pass.
E5  Fidelity fuzz: many randomly generated databases (random schemas, declared types, all five storage classes, NULLs, blobs,
    extreme numbers, random deleted rows). Every cell the inspector returns is compared with an independent ``sqlite3`` query
    (value, storage class per ``typeof()``, rowid), and no deleted row's unique token may appear anywhere in the output.

Usage:  python experiments/r1_inspection.py           (writes experiments/results/r1_e4_*.csv, r1_e5_*.csv, r1_inspection_summary.json)
"""

from __future__ import annotations

import csv
import json
import platform
import random
import sqlite3
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

from android_forensics import __version__
from android_forensics.sqlite.inspection import BlobValue, SpecialFloat
from android_forensics.sqlite.inspector import SQLiteInspector

OUT = Path(__file__).parent / "results"
SCALES = [1_000, 10_000, 50_000, 100_000, 250_000]
IN_MEMORY_LIMIT = 100_000  # beyond this the tool's advice is to stream, so the full in-memory mode is not measured
FUZZ_DATABASES = 300
DECLARED = ["INTEGER", "INT", "TEXT", "VARCHAR(30)", "REAL", "FLOAT", "BLOB", "NUMERIC", "DATETIME", "BOOLEAN", ""]


def build_scaling_db(path: Path, rows: int) -> None:
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, b INTEGER, c REAL, d BLOB, e TEXT)")
    rng = random.Random(rows)
    c.executemany(
        "INSERT INTO t(a,b,c,d,e) VALUES(?,?,?,?,?)",
        ((f"row {i} " + "x" * 30, rng.randint(0, 10**9), rng.random() * 1000, rng.randbytes(16), None if i % 7 == 0 else f"n{i}") for i in range(rows)),
    )
    c.commit()
    c.close()


def run_mode(path: Path, mode: str) -> int:
    if mode == "schema_only":
        return SQLiteInspector.inspect(path, include_records=False).tables[0].row_count
    if mode == "stream":
        return sum(1 for _ in SQLiteInspector.iter_records(path, "t"))
    return SQLiteInspector.inspect(path).record_count


def e4() -> list[dict]:
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        for n in SCALES:
            db = Path(tmp) / f"s{n}.db"
            build_scaling_db(db, n)
            for mode in ("schema_only", "stream", "in_memory"):
                if mode == "in_memory" and n > IN_MEMORY_LIMIT:
                    continue
                t0 = time.perf_counter()
                got = run_mode(db, mode)
                seconds = time.perf_counter() - t0
                tracemalloc.start()
                run_mode(db, mode)
                peak = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
                out.append({"rows": n, "db_mib": round(db.stat().st_size / 2**20, 1), "mode": mode, "rows_returned": got,
                            "seconds": round(seconds, 3), "rows_per_second": int(n / seconds), "peak_python_mib": round(peak / 2**20, 1)})
                print(f"  {n:>8,} rows {mode:<12} {seconds:>7.2f}s {int(n / seconds):>9,} rows/s  peak {peak / 2**20:>7.1f} MiB", flush=True)
    return out


def random_value(rng: random.Random, token: str):
    pool = [None, 0, 1, -1, 2**31, 2**63 - 1, -2**63, 0.5, -3.25, 1e-300, 1.7976931348623157e308, float("inf"), float("-inf"), "", "text", "12", "3.5",
            "2024-03-01T08:00:00Z", "ünï😀", "x" * rng.randint(0, 400), b"", b"\x00\xff", rng.randbytes(rng.randint(1, 300)), token, True]
    return rng.choice(pool)


def e5() -> list[dict]:
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        for seed in range(FUZZ_DATABASES):
            rng = random.Random(seed)
            path = Path(tmp) / f"f{seed}.db"
            c = sqlite3.connect(path)
            c.execute(f"PRAGMA page_size={rng.choice([512, 1024, 4096])}")
            schema, deleted_tokens = {}, []
            for ti in range(rng.randint(1, 4)):
                cols = [(f"c{ci}", rng.choice(DECLARED)) for ci in range(rng.randint(1, 8))]
                pk = rng.choice(["id INTEGER PRIMARY KEY", "id INTEGER PRIMARY KEY AUTOINCREMENT", "k TEXT, id2 INT"])
                c.execute(f"CREATE TABLE t{ti}({pk}, " + ", ".join(f'"{n}" {t}' for n, t in cols) + ")")
                n_rows = rng.randint(0, 150)
                for ri in range(n_rows):
                    token = f"TOKEN-{seed}-{ti}-{ri}-"
                    vals = [random_value(rng, token + "keep") for _ in cols]
                    if pk.startswith("k"):
                        c.execute(f"INSERT INTO t{ti} VALUES(?, ?, {', '.join('?' * len(cols))})", [f"k{ri}", ri, *vals])
                    else:
                        c.execute(f"INSERT INTO t{ti}(" + ", ".join(f'"{n}"' for n, _ in cols) + f") VALUES({', '.join('?' * len(cols))})", vals)
                doomed = [r for r in range(n_rows) if rng.random() < 0.3]
                for ri in doomed:  # a deleted row carries a token nothing else contains
                    token = f"DELETED-{seed}-{ti}-{ri}"
                    if pk.startswith("k"):
                        c.execute(f"INSERT INTO t{ti} VALUES(?, ?, {', '.join('?' * len(cols))})", [token, 10**6 + ri, *[token] * len(cols)])
                        c.execute(f"DELETE FROM t{ti} WHERE k = ?", (token,))
                    else:
                        c.execute(f"INSERT INTO t{ti}(" + ", ".join(f'"{n}"' for n, _ in cols) + f") VALUES({', '.join('?' * len(cols))})", [token] * len(cols))
                        c.execute(f"DELETE FROM t{ti} WHERE rowid = last_insert_rowid()")
                    deleted_tokens.append(token)
                schema[f"t{ti}"] = [n for n, _ in cols]
            c.commit()
            c.close()

            result = SQLiteInspector.inspect(path, blob_inline_limit=10**6)
            d = sqlite3.connect(path)
            cells = mismatches = rows = 0
            for table in result.tables:
                if table.internal:
                    continue
                names = [col.name for col in table.columns]
                quoted = ", ".join(f'"{n}"' for n in names)
                truth = d.execute(f'SELECT rowid, {quoted} FROM "{table.name}" ORDER BY rowid').fetchall()
                types = d.execute("SELECT " + ", ".join(f'typeof("{n}")' for n in names) + f' FROM "{table.name}" ORDER BY rowid').fetchall()
                if len(truth) != len(table.records) or table.row_count != len(truth):
                    mismatches += 1
                for rec, row, typ in zip(table.records, truth, types):
                    rows += 1
                    if rec.rowid != row[0]:
                        mismatches += 1
                    for got, want, cls, expected_class in zip(rec.values, row[1:], (v.value for v in rec.storage_classes), typ):
                        cells += 1
                        if isinstance(got, BlobValue):
                            got = got.data
                        elif isinstance(got, SpecialFloat):
                            got = float(got.value)
                        if got != want or cls != expected_class or type(got) is not type(want):
                            mismatches += 1
            d.close()
            dumped = result.model_dump_json()
            leaks = sum(tok in dumped for tok in deleted_tokens)
            out.append({"seed": seed, "tables": len(schema), "rows": rows, "cells": cells, "deleted_rows": len(deleted_tokens),
                        "cell_mismatches": mismatches, "deleted_tokens_leaked": leaks, "integrity": result.integrity.status})
    return out


def write(name: str, rows: list[dict]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / f"{name}.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    print("E4: inspector throughput and memory ...", flush=True)
    r4 = e4()
    write("r1_e4_inspection_scaling", r4)
    print(f"E5: fidelity fuzz over {FUZZ_DATABASES} random databases ...", flush=True)
    r5 = e5()
    write("r1_e5_inspection_fidelity", r5)
    summary = {
        "tool_version": __version__, "python": sys.version.split()[0], "sqlite": __import__("sqlite3").sqlite_version, "platform": platform.platform(),
        "e4": r4,
        "e5": {"databases": len(r5), "tables": sum(r["tables"] for r in r5), "rows": sum(r["rows"] for r in r5), "cells": sum(r["cells"] for r in r5),
               "deleted_rows": sum(r["deleted_rows"] for r in r5), "cell_mismatches": sum(r["cell_mismatches"] for r in r5),
               "deleted_tokens_leaked": sum(r["deleted_tokens_leaked"] for r in r5),
               "integrity_ok": sum(r["integrity"] == "ok" for r in r5)},
    }
    (OUT / "r1_inspection_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary["e5"], indent=2))


if __name__ == "__main__":
    main()
