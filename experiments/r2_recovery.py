"""Review 2 experiments -- reproducible, measured (nothing here is hard-coded).

E6  Recovery matrix: the standard deletion matrix (12 conditions x position / record-size / page-size / overwrite
    variants, ~28 cases) run through the real page-level recovery engine, scored against each case's physical ground
    truth (``lab.evaluation.score_case``): precision, recall, F1, false-positive rate, per-status counts.
E7  Confidence calibration and processing time/memory: the full synthetic lab (``lab.synth`` with genuine deletions)
    run through recover -> carve -> correlate -> reconstruct; for every reconstructed RECOVERED/PARTIAL/CORRUPTED
    artifact, whether its reported values agree with the deleted row's actual values, broken down by confidence level
    (deterministic scorer, never a model) -- and the pipeline's wall-clock time and peak Python memory.

Usage:  python experiments/r2_recovery.py                      (writes experiments/results/*.csv|json)
        python experiments/r2_charts.py                        (reads the CSVs, writes experiments/results/*.png)
"""

from __future__ import annotations

import csv
import json
import platform
import sqlite3
import sys
import time
import tracemalloc
from pathlib import Path

from android_forensics import __version__
from android_forensics.acquisition.ingest import ingest_source
from android_forensics.lab.deletions import build_case, standard_matrix
from android_forensics.lab.evaluation import matches, score_case
from android_forensics.lab.synth import SynthSpec, generate
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, run_pipeline
from android_forensics.sqlite.recover_db import recover_database
from android_forensics.storage.case_store import CaseStore

OUT = Path(__file__).parent / "results"
LAB_SEEDS = [11, 12, 13]


def e6() -> list[dict]:
    """The recovery matrix: precision / recall / F1 / false-positive rate / status counts per condition."""
    rows = []
    import tempfile

    with tempfile.TemporaryDirectory(prefix="r2_matrix_") as tmp:
        dest = Path(tmp)
        for case in standard_matrix():
            out = build_case(dest, case)
            t0 = time.perf_counter()
            report = recover_database(out.database, out.sidecars, dest / "_scratch")
            elapsed = time.perf_counter() - t0
            score = score_case(out.truth, report.rows)
            rows.append({
                "case": case.name, "condition": case.condition, "position": case.position, "record_size": case.record_size,
                "page_size": case.page_size, "overwrite": case.overwrite, "rows": case.rows, "deleted": case.delete,
                "expected_recoverable": score.expected_recoverable, "recovered_rows": score.recovered_rows,
                "matched_expected": score.matched_expected, "false_positives": score.false_positives,
                "precision": round(score.precision, 4), "recall": round(score.recall, 4), "f1": round(score.f1, 4),
                "false_positive_rate": round(score.false_positive_rate, 4),
                "recovered_count": score.by_status.get("ArtifactStatus.RECOVERED", score.by_status.get("RECOVERED", 0)),
                "partial_count": score.by_status.get("ArtifactStatus.PARTIAL", score.by_status.get("PARTIAL", 0)),
                "seconds": round(elapsed, 4),
            })
    return rows


def e7() -> tuple[list[dict], dict]:
    """Confidence calibration and processing cost on the full synthetic lab, across three seeds."""
    import tempfile

    rows: list[dict] = []
    timings: list[dict] = []
    for seed in LAB_SEEDS:
        with tempfile.TemporaryDirectory(prefix="r2_lab_") as tmp:
            tmp = Path(tmp)
            truth = generate(tmp / "ev", SynthSpec(seed=seed, with_deletions=True))
            store = CaseStore.create(tmp / "case", f"e7-{seed}")

            tracemalloc.start()
            t0 = time.perf_counter()
            ingest_source(store, tmp / "ev" / "android_dump")
            stage_stats = run_pipeline(store, names=list(FULL_PIPELINE_NAMES))
            elapsed = time.perf_counter() - t0
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            timings.append({
                "seed": seed, "seconds": round(elapsed, 3), "peak_memory_mb": round(peak / (1024 * 1024), 2),
                **{f"{s}_seconds": stage_stats[s]["seconds"] for s in FULL_PIPELINE_NAMES if s in stage_stats},
            })

            truth_by_table: dict[str, dict[int, dict]] = {"sms": {}, "urls": {}, "visits": {}, "downloads": {}}
            sms_file = truth["files"]["data/data/com.android.providers.telephony/databases/mmssms.db"]
            for r in sms_file.get("deleted", []):
                truth_by_table["sms"][r["rowid"]] = r["values"]
            hist = truth["files"]["data/data/com.android.chrome/app_chrome/Default/History"]
            for kind, key in (("urls", "deleted_urls"), ("visits", "deleted_visits"), ("downloads", "deleted_downloads")):
                for r in hist.get(key, []):
                    truth_by_table[kind][r["rowid"]] = r["values"]

            for rec in store.q(
                "SELECT rr.table_name, rr.rowid_value, rr.status, rr.values_json, a.confidence FROM recovered_records rr "
                "LEFT JOIN artifacts a ON a.id = rr.artifact_id WHERE rr.status IN ('RECOVERED','PARTIAL')"
            ):
                table_truth = truth_by_table.get(rec["table_name"], {})
                values = json.loads(rec["values_json"])
                # a PARTIAL row has lost its rowid, so it is matched to a planted row by its surviving *values* (the same
                # notion of a match ``lab.evaluation.matches`` uses for the single-table matrix), not by rowid identity.
                if not table_truth:
                    correct = None  # this table has no planted deletions: nothing to calibrate against
                else:
                    correct = any(matches(values, tv) for tv in table_truth.values())
                rows.append({
                    "seed": seed, "table": rec["table_name"], "status": rec["status"], "confidence": rec["confidence"],
                    "matches_planted_row": correct,
                })
    by_level: dict[str, dict[str, int]] = {}
    for r in rows:
        if r["matches_planted_row"] is None:
            continue
        level = r["confidence"] or "NONE"
        d = by_level.setdefault(level, {"total": 0, "correct": 0})
        d["total"] += 1
        d["correct"] += int(r["matches_planted_row"])
    calibration = {level: {**d, "share_correct": round(d["correct"] / d["total"], 4) if d["total"] else None} for level, d in by_level.items()}
    return rows, {"timings": timings, "calibration": calibration}


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("")
        return
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    matrix_rows = e6()
    _write_csv(OUT / "r2_e6_recovery_matrix.csv", matrix_rows)

    calibration_rows, e7_summary = e7()
    _write_csv(OUT / "r2_e7_confidence_calibration.csv", calibration_rows)

    total_expected = sum(r["expected_recoverable"] for r in matrix_rows)
    total_matched = sum(r["matched_expected"] for r in matrix_rows)
    total_fp = sum(r["false_positives"] for r in matrix_rows)
    total_recovered_rows = sum(r["recovered_rows"] for r in matrix_rows)
    summary = {
        "environment": {"python": sys.version.split()[0], "sqlite": sqlite3.sqlite_version, "platform": platform.platform(),
                        "tool_version": __version__},
        "e6_recovery_matrix": {
            "cases": len(matrix_rows), "total_expected_recoverable": total_expected, "total_matched": total_matched,
            "overall_recall": round(total_matched / total_expected, 4) if total_expected else None,
            "total_false_positives": total_fp,
            "overall_false_positive_rate": round(total_fp / total_recovered_rows, 4) if total_recovered_rows else None,
            "cases_below_95pct_recall": sorted(r["case"] for r in matrix_rows if r["recall"] < 0.95),
        },
        "e7_confidence_calibration": e7_summary["calibration"],
        "e7_timings": e7_summary["timings"],
    }
    (OUT / "r2_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
