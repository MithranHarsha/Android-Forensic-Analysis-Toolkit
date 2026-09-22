"""Phase 13: the full synthetic Android evidence lab, with genuine deletions and physically-derived ground truth.

``lab.synth.generate(..., SynthSpec(with_deletions=True))`` deletes a known set of rows from ``mmssms.db`` (the ``sms``
table) and Chrome's ``History`` (``urls``, ``visits``, ``downloads``) and records, for each one, whether its bytes are
physically RECOVERED, PARTIAL or UNRECOVERABLE -- derived by re-encoding the row and searching the final file, never by
asking the recovery engine. This test runs the real pipeline over that evidence and checks its output against that
ground truth directly, the same way ``tests/integration/test_recovery_matrix.py`` does for the single-table lab.
"""

from __future__ import annotations

from collections import Counter

import pytest

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.lab.synth import SynthSpec, generate
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, run_pipeline
from android_forensics.storage.case_store import CaseStore


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    out = tmp_path_factory.mktemp("synth_del")
    truth = generate(out, SynthSpec(with_deletions=True, seed=2024))
    store = CaseStore.create(tmp_path_factory.mktemp("case_del") / "case", "lab", "pytest")
    ingest_source(store, out / "android_dump")
    run_pipeline(store, names=list(FULL_PIPELINE_NAMES))
    return store, truth


def _deleted_rows(truth: dict) -> list[dict]:
    sms = truth["files"]["data/data/com.android.providers.telephony/databases/mmssms.db"]["deleted"]
    hist = truth["files"]["data/data/com.android.chrome/app_chrome/Default/History"]
    return sms + hist["deleted_urls"] + hist["deleted_visits"] + hist["deleted_downloads"]


def test_ground_truth_matches_the_declared_expectation(lab):
    """The generator's own bookkeeping (``expected``) must equal what it actually wrote."""
    _, truth = lab
    rows = _deleted_rows(truth)
    assert len(rows) == truth["expected"]["deleted_rows"]
    assert dict(Counter(r["expected"] for r in rows)) == truth["expected"]["deleted_rows_by_class"]
    assert truth["expected"]["deleted_rows"] > 0 and "PARTIAL" in truth["expected"]["deleted_rows_by_class"]


def test_every_physically_recoverable_row_is_recovered(lab):
    """Every row ground truth calls RECOVERED or PARTIAL must come back from the real pipeline at least that well."""
    store, truth = lab
    rows = _deleted_rows(truth)
    expect_recoverable = [r for r in rows if r["expected"] in ("RECOVERED", "PARTIAL")]
    assert expect_recoverable
    found = store.q("SELECT table_name, rowid_value, status FROM recovered_records")
    by_table_rowid = {(r["table_name"], r["rowid_value"]): r["status"] for r in found}
    misses = []
    for r in expect_recoverable:
        if r["expected"] == "RECOVERED":
            if by_table_rowid.get((r["table"], r["rowid"])) != "RECOVERED":
                misses.append((r["table"], r["rowid"], "expected RECOVERED"))
        else:  # PARTIAL: the row is expected to appear with no rowid (SQLite's freeblock header ate it)
            values_found = any(
                row["status"] == "PARTIAL"
                for row in store.q("SELECT status FROM recovered_records WHERE table_name=? AND rowid_value IS NULL", (r["table"],))
            )
            if not values_found:
                misses.append((r["table"], r["rowid"], "expected PARTIAL, none found"))
    assert not misses, misses


def test_no_row_is_reported_more_confidently_than_the_ground_truth_allows(lab):
    """A row ground truth calls UNRECOVERABLE must never appear as RECOVERED (there is nothing to recover it from)."""
    store, truth = lab
    unrecoverable = {(r["table"], r["rowid"]) for r in _deleted_rows(truth) if r["expected"] == "UNRECOVERABLE"}
    for table, rowid in unrecoverable:
        assert store.scalar("SELECT COUNT(*) FROM recovered_records WHERE table_name=? AND rowid_value=?", (table, rowid)) == 0


def test_reconstructed_artifacts_carry_the_deleted_values(lab):
    """The reconstructed SMS artifacts include the actual deleted message bodies, not placeholders."""
    store, truth = lab
    deleted_sms = truth["files"]["data/data/com.android.providers.telephony/databases/mmssms.db"]["deleted"]
    bodies = {r["values"]["body"] for r in deleted_sms}
    found_bodies = {row["body"] for row in store.q(
        "SELECT json_extract(fields_json,'$.body') AS body FROM artifacts WHERE artifact_type='sms' AND status IN ('RECOVERED','PARTIAL')"
    )}
    assert bodies & found_bodies, "at least the RECOVERED bodies should be an exact, verbatim match"
    fully_recovered_bodies = {r["values"]["body"] for r in deleted_sms if r["expected"] == "RECOVERED"}
    assert fully_recovered_bodies <= found_bodies


def test_recall_is_measured_and_reported(lab):
    """The measured recall over physically recoverable rows, printed so a human reviewing the run sees the real number."""
    store, truth = lab
    rows = [r for r in _deleted_rows(truth) if r["expected"] in ("RECOVERED", "PARTIAL")]
    hit = 0
    for r in rows:
        if r["expected"] == "RECOVERED":
            hit += store.scalar("SELECT COUNT(*) FROM recovered_records WHERE table_name=? AND rowid_value=? AND status='RECOVERED'",
                                (r["table"], r["rowid"])) > 0
        else:
            hit += store.scalar("SELECT COUNT(*) FROM recovered_records WHERE table_name=? AND status='PARTIAL' AND rowid_value IS NULL",
                                (r["table"],)) > 0
    recall = hit / len(rows)
    print(f"\nsynthetic lab recall: {hit}/{len(rows)} = {recall:.1%}")
    assert recall >= 0.95
