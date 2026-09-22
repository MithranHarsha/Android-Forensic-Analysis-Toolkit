"""Phase 9: the recover -> carve -> correlate -> reconstruct pipeline, end to end on a real case, and that Review 1's default
pipeline is completely unaffected by any of it."""

from __future__ import annotations

import sqlite3

import pytest

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.artifacts.recovered import DatabaseContext
from android_forensics.models import ArtifactStatus, Confidence
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, PIPELINE, run_pipeline, run_stage
from android_forensics.storage.case_store import CaseError, CaseStore
from tests.unit.recovery_fixtures import SMS_DDL, sms_row


def build_case(root, contact_number="+12025550101"):
    """A dump with a telephony database (deleted rows) and a contacts database naming the same number, in different files."""
    tel = root / "data" / "data" / "com.android.providers.telephony" / "databases" / "mmssms.db"
    tel.parent.mkdir(parents=True)
    conn = sqlite3.connect(tel)
    conn.execute("PRAGMA secure_delete=OFF")
    conn.executescript(SMS_DDL)
    for i in range(1, 61):
        row = sms_row(i)
        row["address"] = contact_number if i == 24 else f"+1202555{2000 + i:04d}"
        conn.execute(f"INSERT INTO sms({','.join(row)}) VALUES({','.join('?' * len(row))})", list(row.values()))
    conn.commit()
    conn.execute("DELETE FROM sms WHERE _id IN (20, 24, 28, 32)")  # isolated deletes: freed cells lose their first bytes (PARTIAL)
    conn.commit()
    conn.close()

    contacts = root / "data" / "data" / "com.android.providers.contacts" / "databases" / "contacts2.db"
    contacts.parent.mkdir(parents=True)
    conn = sqlite3.connect(contacts)
    conn.executescript(
        """
        CREATE TABLE accounts (_id INTEGER PRIMARY KEY AUTOINCREMENT, account_name TEXT, account_type TEXT, data_set TEXT);
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY AUTOINCREMENT, mimetype TEXT NOT NULL);
        CREATE TABLE contacts (_id INTEGER PRIMARY KEY AUTOINCREMENT, name_raw_contact_id INTEGER,
            times_contacted INTEGER DEFAULT 0, last_time_contacted INTEGER, starred INTEGER DEFAULT 0,
            has_phone_number INTEGER DEFAULT 0, lookup TEXT, contact_last_updated_timestamp INTEGER);
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER, contact_id INTEGER,
            display_name TEXT, deleted INTEGER NOT NULL DEFAULT 0, starred INTEGER DEFAULT 0,
            times_contacted INTEGER DEFAULT 0, last_time_contacted INTEGER, version INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE data (_id INTEGER PRIMARY KEY AUTOINCREMENT, mimetype_id INTEGER, raw_contact_id INTEGER,
            is_primary INTEGER DEFAULT 0, data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT, data5 TEXT, data6 TEXT);
        INSERT INTO accounts(account_name, account_type) VALUES('owner@example.com', 'com.google');
        INSERT INTO mimetypes(mimetype) VALUES('vnd.android.cursor.item/email_v2'), ('vnd.android.cursor.item/phone_v2'),
            ('vnd.android.cursor.item/name'), ('vnd.android.cursor.item/organization');
        INSERT INTO contacts(_id, name_raw_contact_id, has_phone_number, lookup, contact_last_updated_timestamp)
            VALUES(1, 1, 1, '1r1', 1709280000000);
        INSERT INTO raw_contacts(_id, account_id, contact_id, display_name) VALUES(1, 1, 1, 'Ann Lee');
        INSERT INTO data(mimetype_id, raw_contact_id, is_primary, data1, data2, data3) VALUES(3, 1, 1, 'Ann Lee', 'Ann', 'Lee');
        """
    )
    conn.execute("INSERT INTO data(mimetype_id, raw_contact_id, is_primary, data1, data2) VALUES(2, 1, 1, ?, '2')", (contact_number,))
    conn.commit()
    conn.close()
    return root


@pytest.fixture
def recovered_case(tmp_path):
    dump = build_case(tmp_path / "dump")
    store = CaseStore.create(tmp_path / "case", "recovery", "pytest")
    ingest_source(store, dump)
    run_pipeline(store, names=list(FULL_PIPELINE_NAMES))
    return store


# ------------------------------------------------------------------ Review 1 default is unaffected


def test_run_pipeline_with_no_names_runs_only_the_review_1_stages(tmp_path):
    dump = build_case(tmp_path / "dump")
    store = CaseStore.create(tmp_path / "case", "c", "pytest")
    ingest_source(store, dump)
    results = run_pipeline(store)
    assert list(results) == ["scan", "extract", "validate", "timeline"] == [s.name for s in PIPELINE]
    assert store.scalar("SELECT COUNT(*) FROM recovered_records") == 0
    assert store.scalar("SELECT COUNT(*) FROM carved_candidates") == 0
    assert store.scalar("SELECT COUNT(*) FROM correlations") == 0
    assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE status != 'ACTIVE'") == 0
    assert not any(r["stage"] in ("recover", "carve", "correlate", "reconstruct") for r in store.q("SELECT stage FROM analysis_runs"))


def test_recovery_stages_run_only_when_named(tmp_path):
    dump = build_case(tmp_path / "dump")
    store = CaseStore.create(tmp_path / "case", "c", "pytest")
    ingest_source(store, dump)
    run_stage(store, "scan")
    with pytest.raises(CaseError, match="requires 'extract'"):
        run_stage(store, "correlate")
    run_stage(store, "extract")
    with pytest.raises(CaseError, match="requires 'correlate'"):
        run_stage(store, "reconstruct")
    run_stage(store, "recover")
    assert store.scalar("SELECT COUNT(*) FROM recovered_records") > 0


# ------------------------------------------------------------------ end to end


def test_the_full_pipeline_recovers_deleted_sms_and_reconstructs_them(recovered_case):
    store = recovered_case
    rows = store.q("SELECT * FROM recovered_records")
    assert rows and {r["status"] for r in rows} <= {"RECOVERED", "PARTIAL", "CORRUPTED"}
    assert all(r["artifact_id"] is not None for r in rows), "reconstruct links every recovered record to its artifact"
    recovered_artifacts = store.q("SELECT * FROM artifacts WHERE status IN ('RECOVERED','PARTIAL','CORRUPTED')")
    assert len(recovered_artifacts) == len(rows)
    for a in recovered_artifacts:
        assert a["confidence"] in ("LOW", "MEDIUM", "HIGH") and a["evidence_file_id"] is not None
        assert a["raw_hex"] and a["byte_offset"] is not None


def test_a_recovered_message_matching_the_contact_is_corroborated(recovered_case):
    store = recovered_case
    record = store.one("SELECT * FROM recovered_records WHERE json_extract(values_json,'$.address')='+12025550101'")
    assert record is not None
    import json as _json

    sources = _json.loads(record["corroboration_json"])
    assert sources == ["contact Ann Lee"], "the correlate stage wrote the corroboration sentence before reconstruct ran"
    art = store.get_artifact(record["artifact_id"])
    assert art.status is not ArtifactStatus.ACTIVE and art.confidence in (Confidence.MEDIUM, Confidence.HIGH)
    assert store.scalar("SELECT COUNT(*) FROM correlations WHERE source_ref=? OR target_ref=?",
                        (f"artifact:{art.id}", f"artifact:{art.id}")) > 0
    assert store.scalar("SELECT COUNT(*) FROM correlations WHERE relation='CONTACT_OF' AND target_ref='phone:2025550101'") == 1


def test_carved_candidates_are_found_and_scored_but_never_promoted(recovered_case):
    store = recovered_case
    carved = store.q("SELECT * FROM carved_candidates")
    assert carved
    assert all(c["status"] == "CARVED CANDIDATE" for c in carved)
    assert all(c["confidence"] != "HIGH" for c in carved)
    assert any(c["confidence"] is not None for c in carved), "correlate scored at least some of them"
    assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE id IN (SELECT id FROM artifacts WHERE artifact_type='carved_candidate')") == 0


def test_validation_runs_over_the_reconstructed_artifacts_too(recovered_case):
    store = recovered_case
    assert store.scalar("SELECT COUNT(*) FROM validation_results WHERE check_name='record_structure' AND target_label='recovered records'") == 1
    assert store.scalar("SELECT COUNT(*) FROM validation_results WHERE check_name='record_structure' AND target_label='carved candidates'") == 1
    row = store.one("SELECT status FROM validation_results WHERE check_name='record_structure' AND target_label='recovered records'")
    assert row["status"] == "VALID"


def test_re_running_recover_resets_carve_correlate_and_reconstruct(recovered_case):
    store = recovered_case
    before = store.scalar("SELECT COUNT(*) FROM artifacts WHERE status != 'ACTIVE'")
    assert before > 0
    run_stage(store, "recover")
    assert store.scalar("SELECT COUNT(*) FROM carved_candidates") == 0, "carve was invalidated by re-running its dependency"
    assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE status != 'ACTIVE'") == 0, "reconstruct's artifacts were removed"
    assert store.scalar("SELECT COUNT(*) FROM correlations") == 0
    run_stage(store, "carve")
    run_stage(store, "correlate")
    run_stage(store, "reconstruct")
    assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE status != 'ACTIVE'") == before, "recovering the same evidence twice gives the same result"


def test_reconstruction_never_modifies_the_evidence_files(tmp_path):
    import hashlib

    dump = build_case(tmp_path / "dump")
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in dump.rglob("*") if p.is_file()}
    store = CaseStore.create(tmp_path / "case", "c", "pytest")
    ingest_source(store, dump)
    run_pipeline(store, names=list(FULL_PIPELINE_NAMES))
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in dump.rglob("*") if p.is_file()}
    assert after == before


def test_a_database_with_no_working_copy_is_skipped_not_fabricated(tmp_path):
    """``--preserve none`` means no bytes were kept to recover from; recovery must attempt nothing rather than invent it."""
    dump = build_case(tmp_path / "dump")
    store = CaseStore.create(tmp_path / "case", "c", "pytest")
    from android_forensics.acquisition.base import PreservePolicy

    ingest_source(store, dump, preserve=PreservePolicy.NONE)
    run_stage(store, "scan")
    assert store.scalar("SELECT COUNT(*) FROM databases WHERE header_valid=1") == 0
    assert store.scalar("SELECT COUNT(*) FROM databases WHERE open_status='not_preserved'") == 2
    run_stage(store, "recover")
    assert store.scalar("SELECT COUNT(*) FROM recovered_records") == 0


def test_recovery_integrity_check_passes_on_a_clean_case(recovered_case):
    store = recovered_case
    rows = store.q("SELECT * FROM validation_results WHERE check_name='record_structure' AND target_type='case'")
    labels = {r["target_label"]: r["status"] for r in rows}
    assert labels.get("recovered records") == "VALID" and labels.get("carved candidates") == "VALID"


def test_recovery_integrity_check_catches_a_tampered_raw_hex(recovered_case):
    store = recovered_case
    rid = store.scalar("SELECT id FROM recovered_records LIMIT 1")
    with store.transaction():
        store.conn.execute("UPDATE recovered_records SET raw_hex='00' WHERE id=?", (rid,))
    from android_forensics.validation.checks import Options, check_recovery_integrity
    results = list(check_recovery_integrity(store, Options()))
    bad = [r for r in results if r.target_label == "recovered records"]
    assert bad and bad[0].status.value == "INVALID" and rid in bad[0].evidence["digest_mismatch"]


def test_a_database_context_can_be_rebuilt_from_a_stored_case(recovered_case):
    """What reconstruct needs (schema, wal frame status) survives in the case database, not just in memory."""
    store = recovered_case
    from android_forensics.pipeline.recovery_stages import _database_context

    fid = store.scalar("SELECT id FROM evidence_files WHERE path LIKE '%mmssms.db'")
    ctx = _database_context(store, fid)
    assert isinstance(ctx, DatabaseContext) and ctx.database_path.endswith("mmssms.db")
    assert any(m.name == "sms" for m in ctx.models)
