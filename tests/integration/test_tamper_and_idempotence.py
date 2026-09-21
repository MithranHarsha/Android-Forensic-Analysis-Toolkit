import os
import shutil

import pytest

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.pipeline.runner import run_pipeline, run_stage
from android_forensics.storage.case_store import CaseError, CaseStore


@pytest.fixture()
def case_with_copy(synth, tmp_path):
    out, _ = synth
    ev = tmp_path / "ev"
    shutil.copytree(out / "android_dump", ev)
    s = CaseStore.create(tmp_path / "case", "c")
    ingest_source(s, ev)
    run_pipeline(s)
    return s, ev


def hash_results(s):
    return [(r["target_type"], r["status"], r["detail"]) for r in s.q("SELECT * FROM validation_results WHERE check_name='hash_consistency'")]


def test_baseline_hashes_valid(case_with_copy):
    s, _ = case_with_copy
    assert {st for _t, st, _d in hash_results(s)} == {"VALID"}


def test_modified_original_is_detected(case_with_copy):
    s, ev = case_with_copy
    target = ev / "data/data/com.android.providers.telephony/databases/mmssms.db"
    with open(target, "r+b") as fh:
        fh.seek(5000)
        original = fh.read(1)
        fh.seek(5000)
        fh.write(bytes([original[0] ^ 0xFF]))
    run_stage(s, "validate")
    res = hash_results(s)
    assert any(t == "source" and st == "INVALID" and "changed since ingest" in d for t, st, d in res)


def test_modified_preserved_copy_is_detected(case_with_copy):
    s, _ = case_with_copy
    f = s.one("SELECT source_id, preserved_copy, path FROM evidence_files WHERE path LIKE '%mmssms.db'")
    p = s.evidence_dir / f"s{f['source_id']}" / f["preserved_copy"]
    os.chmod(p, 0o644)
    p.write_bytes(p.read_bytes()[:-1] + b"\x01")
    run_stage(s, "validate")
    res = s.q("SELECT * FROM validation_results WHERE check_name='hash_consistency' AND status='INVALID'")
    assert res and any("differs" in r["detail"] or "failed verification" in r["detail"] for r in res)


def test_missing_original_is_unverified_not_silently_valid(case_with_copy):
    s, ev = case_with_copy
    (ev / "sdcard/DCIM/Camera/IMG_20240301_101500.jpg").unlink()
    run_stage(s, "validate")
    src = s.one("SELECT * FROM validation_results WHERE check_name='hash_consistency' AND target_type='source'")
    assert src["status"] == "PARTIAL" and "no longer available" in src["detail"]


def test_no_rehash_option_reports_unverified(case_with_copy):
    from android_forensics.pipeline.runner import StageOptions
    s, _ = case_with_copy
    run_stage(s, "validate", StageOptions(rehash_originals=False))
    src = s.one("SELECT * FROM validation_results WHERE check_name='hash_consistency' AND target_type='source'")
    assert src["status"] == "UNVERIFIED"


def test_tampered_manifest_and_custody_log_are_detected(case_with_copy):
    s, _ = case_with_copy
    s.manifest_path.write_text(s.manifest_path.read_text().replace("sha256", "sha257", 1))
    s.conn.execute("UPDATE custody_log SET action='forged' WHERE id=2")
    s.conn.commit()
    run_stage(s, "validate")
    st = {r["check_name"]: r["status"] for r in s.q("SELECT check_name, status FROM validation_results WHERE check_name IN ('manifest_integrity','custody_chain')")}
    assert st == {"manifest_integrity": "INVALID", "custody_chain": "INVALID"}


def test_stage_rerun_is_idempotent_and_invalidates_dependents(case_with_copy):
    s, _ = case_with_copy
    n_art = s.scalar("SELECT COUNT(*) FROM artifacts")
    n_val = s.scalar("SELECT COUNT(*) FROM validation_results")
    n_tl = s.scalar("SELECT COUNT(*) FROM timeline_events")
    run_stage(s, "extract")
    assert s.scalar("SELECT COUNT(*) FROM artifacts") == n_art
    assert s.scalar("SELECT COUNT(*) FROM validation_results") == 0 and s.scalar("SELECT COUNT(*) FROM timeline_events") == 0
    run_stage(s, "validate")
    run_stage(s, "timeline")
    assert s.scalar("SELECT COUNT(*) FROM validation_results") == n_val and s.scalar("SELECT COUNT(*) FROM timeline_events") == n_tl
    run_stage(s, "scan")
    assert s.scalar("SELECT COUNT(*) FROM artifacts") == 0
    run_pipeline(s)
    assert s.scalar("SELECT COUNT(*) FROM artifacts") == n_art
    assert s.scalar("SELECT COUNT(*) FROM databases") == 8


def test_stage_ordering_is_enforced(fresh_case):
    with pytest.raises(CaseError):
        run_stage(fresh_case, "extract")
    with pytest.raises(CaseError):
        run_stage(fresh_case, "scan")
    with pytest.raises(CaseError):
        run_stage(fresh_case, "nonsense")


def test_edited_raw_row_is_detected_by_the_provenance_check(case_with_copy):
    import json

    s, _ = case_with_copy
    before = s.one("SELECT status, detail FROM validation_results WHERE check_name='provenance_completeness'")
    assert before["status"] == "VALID" and "raw source rows match their digests" in before["detail"]
    aid = s.scalar("SELECT id FROM artifacts WHERE artifact_type='sms' LIMIT 1")
    row = json.loads(s.scalar("SELECT raw_row_json FROM artifacts WHERE id=?", (aid,)))
    row["body"] = "EDITED AFTER EXTRACTION"
    s.conn.execute("UPDATE artifacts SET raw_row_json=? WHERE id=?", (json.dumps(row), aid))
    s.conn.commit()
    run_stage(s, "validate")
    after = s.one("SELECT status, detail, evidence_json FROM validation_results WHERE check_name='provenance_completeness'")
    assert after["status"] == "INVALID" and "no longer matches its recorded digest" in after["detail"]
    assert json.loads(after["evidence_json"])["raw_digest_mismatch"] == [aid]


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_validation_survives_an_original_swapped_for_a_symlink(case_with_copy, tmp_path):
    s, ev = case_with_copy
    target = ev / "data/data/com.android.providers.telephony/databases/mmssms.db"
    twin = tmp_path / "twin.db"
    twin.write_bytes(target.read_bytes())
    target.unlink()
    os.symlink(twin, target)
    run_stage(s, "validate")  # must not raise
    src = s.one("SELECT status, detail FROM validation_results WHERE check_name='hash_consistency' AND target_type='source'")
    assert src["status"] == "PARTIAL" and "no longer available" in src["detail"]
