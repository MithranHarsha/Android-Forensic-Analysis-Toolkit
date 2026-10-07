"""Parallel recovery/carving must be indistinguishable from the serial run: same rows, same ids, same order."""

from __future__ import annotations

import json
import os

import pytest

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.pipeline.parallel import ordered_map, resolve_workers
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, StageOptions, run_pipeline
from android_forensics.storage.case_store import CaseStore


def _square(x: int) -> int:
    return x * x


def _slow_first(x: int) -> int:
    import time

    time.sleep(0.3 if x == 0 else 0)   # the first task finishes last; the result order must not change
    return x


def test_ordered_map_keeps_task_order_and_bounds_work():
    assert list(ordered_map(_square, range(20), 1)) == [i * i for i in range(20)]
    assert list(ordered_map(_slow_first, range(12), 3)) == list(range(12))
    assert list(ordered_map(_square, [], 4)) == []
    assert list(ordered_map(_slow_first, range(12), 3, cost=lambda x: -x)) == list(range(12))   # cost reorders *execution*, never results
    assert list(ordered_map(_square, range(30), 4, cost=lambda x: x % 7)) == [i * i for i in range(30)]


def test_resolve_workers():
    assert resolve_workers(None) == resolve_workers(1) == resolve_workers("1") == 1
    assert 1 <= resolve_workers("auto") <= 8 and resolve_workers(3) == 3 and resolve_workers("5") == 5
    for bad in (-2, "-1", "many"):
        with pytest.raises(ValueError):
            resolve_workers(bad)


def snapshot(store: CaseStore) -> dict:
    q = lambda sql: [tuple(r) for r in store.q(sql)]  # noqa: E731
    return {
        "recovered": q("SELECT id, database_file_id, source, table_name, rowid_value, status, method, file_offset, length, raw_hex, values_json FROM recovered_records ORDER BY id"),
        "unrecovered": q("SELECT id, database_id, source, file_offset, length, reason, raw_sha256 FROM unrecovered_regions ORDER BY id"),
        "carved": q("SELECT id, evidence_file_id, kind, byte_offset, length, matched, confidence FROM carved_candidates ORDER BY id"),
        "wal": q("SELECT database_id, frame_index, status FROM wal_frames ORDER BY id"),
        "artifacts": q("SELECT id, artifact_type, status, confidence, summary FROM artifacts ORDER BY id"),
    }


def test_parallel_and_serial_runs_produce_identical_case_content(synth, tmp_path):
    out, _ = synth
    snaps = {}
    for workers in (1, 3):
        store = CaseStore.create(tmp_path / f"w{workers}", f"w{workers}", "t")
        ingest_source(store, out / "android_dump")
        run_pipeline(store, names=list(FULL_PIPELINE_NAMES), options=StageOptions(workers=workers))
        snaps[workers] = snapshot(store)
    assert snaps[1]["recovered"] and snaps[1]["carved"]
    assert snaps[1] == snaps[3]
    assert json.dumps(snaps[1], default=str) == json.dumps(snaps[3], default=str)


@pytest.mark.skipif((os.cpu_count() or 1) < 2, reason="needs more than one core")
def test_cli_accepts_workers(synth, tmp_path):
    from typer.testing import CliRunner

    from android_forensics.cli.app import app

    out, _ = synth
    r = CliRunner().invoke(app, ["analyze", str(out / "android_dump"), "--cases-dir", str(tmp_path), "--name", "p", "--no-report", "--workers", "2"],
                           catch_exceptions=False)
    assert r.exit_code == 0 and "RECOVERED" in r.stdout
    bad = CliRunner().invoke(app, ["analyze", str(out / "android_dump"), "--cases-dir", str(tmp_path), "--name", "q", "--no-report", "--workers", "zero"])
    assert bad.exit_code == 2
