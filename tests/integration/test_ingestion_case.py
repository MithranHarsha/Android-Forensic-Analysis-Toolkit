"""Ingestion policies carried through a full case (database-backed path)."""

import stat
import sys

from android_forensics.acquisition import PreservePolicy, ingest_source, read_manifest, verify_manifest
from android_forensics.pipeline.runner import run_pipeline
from android_forensics.storage.case_store import CaseStore


def test_hash_only_ingestion_is_honest_downstream(synth, tmp_path):
    out, _ = synth
    s = CaseStore.create(tmp_path / "case", "c")
    r = ingest_source(s, out / "acquisition.zip", preserve=PreservePolicy.NONE)
    assert r.preserved_copies == 0 and r.files == 16 and r.complete
    source_dir = s.evidence_dir / "s1"
    assert not source_dir.exists() or not any(source_dir.iterdir()), "nothing was copied"

    run_pipeline(s)
    status = {row["path"].rsplit("/", 1)[-1]: row["open_status"] for row in s.q(
        "SELECT f.path, d.open_status FROM databases d JOIN evidence_files f ON f.id=d.evidence_file_id")}
    assert status["vault.db"] == "encrypted_suspect", "genuinely encrypted files keep their own label"
    assert {v for k, v in status.items() if k != "vault.db"} == {"not_preserved"}, "no working copy is not the same as encrypted"
    assert s.scalar("SELECT COUNT(*) FROM validation_results WHERE status='INVALID'") == 0
    assert s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type IN ('sms','call','contact','browser_visit','browser_download')") == 0
    assert s.scalar("SELECT COUNT(*) FROM validation_results WHERE check_name='sqlite_header' AND status='UNVERIFIED'") == 8
    assert all(f.hashes.sha256 for f in s.evidence_files()), "every file is still hashed"


def test_preserve_everything_copies_every_file_bit_identically(synth, tmp_path):
    out, _ = synth
    s = CaseStore.create(tmp_path / "case", "c")
    r = ingest_source(s, out / "android_dump", preserve=PreservePolicy.ALL)
    assert r.preserved_copies == r.files == 16
    for f in s.evidence_files():
        copy = s.evidence_dir / f"s{f.source_id}" / f.preserved_copy
        assert copy.stat().st_size == f.size
        if sys.platform != "win32":
            assert stat.S_IMODE(copy.stat().st_mode) == 0o444
    run_pipeline(s)
    assert s.scalar("SELECT COUNT(*) FROM validation_results WHERE status='INVALID'") == 0
    assert s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='sms'") == 120


def test_the_case_manifest_verifies_against_the_evidence_and_the_working_directory(synth, tmp_path):
    out, _ = synth
    s = CaseStore.create(tmp_path / "case", "c")
    r = ingest_source(s, out / "android_dump")
    manifest = read_manifest(r.manifest_path)
    assert manifest.case_id == s.case_id and manifest.tool_version and manifest.analysis_timestamp.endswith("Z")
    report = verify_manifest(manifest, s.workspace)
    assert report.ok and report.checked == 16 + 13
    assert all(e.original_path.startswith(str(out.resolve())) for e in manifest.sources[0].files)
