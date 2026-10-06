"""Extraction accuracy against synthetic ground truth (values derived independently of the tool)."""

import json

import pytest

from android_forensics.lab.ground_truth import compare_active
from android_forensics.models import ArtifactType, RawKind, SMSMessage, artifact_class
from android_forensics.sqlite.discovery import preserved_path, sidecar_rows
from android_forensics.sqlite.reader import SQLiteSession
from tests.conftest import tree_hash


@pytest.mark.parametrize("atype", ["sms", "call", "contact", "browser_visit", "browser_download"])
def test_active_extraction_is_exact(analyzed, atype):
    store, _results, truth, *_ = analyzed
    res = compare_active(store, truth)[atype]
    assert res.mismatches == []
    assert (res.expected, res.extracted, res.correct) == (res.expected, res.expected, res.expected) and res.expected > 0
    assert res.precision == res.recall == res.f1 == 1.0


def test_acceptance_volumes(analyzed):
    store, _r, truth, *_ = analyzed
    exp = truth["expected"]
    assert exp["sms"] >= 100 and exp["call"] >= 50
    for t in ("sms", "call", "contact", "browser_visit", "browser_download"):
        assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type=?", (t,)) == exp[t]


def test_wal_only_rows_are_extracted_and_flagged(analyzed):
    store, _r, truth, *_ = analyzed
    wal_rows = truth["files"]["data/data/com.android.providers.contacts/databases/calllog.db"]["wal_only_rows"]
    assert wal_rows == 20
    rows = store.q("SELECT source_rowid, view_includes_wal FROM artifacts WHERE artifact_type='call'")
    assert len(rows) == 60 and all(r["view_includes_wal"] == 1 for r in rows)
    assert {r["source_rowid"] for r in rows} == set(range(1, 61))


def test_only_active_status_and_no_physical_provenance_in_review1(analyzed):
    store, *_ = analyzed
    assert store.scalar("SELECT COUNT(DISTINCT status) FROM artifacts") == 1
    assert store.scalar("SELECT status FROM artifacts LIMIT 1") == "ACTIVE"
    assert {r[0] for r in store.conn.execute("SELECT DISTINCT extraction_method FROM artifacts")} == {"ACTIVE_QUERY", "FILESYSTEM_METADATA"}
    assert {r[0] for r in store.conn.execute("SELECT DISTINCT raw_kind FROM artifacts")} == {"sqlite_row", "inventory"}
    assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE page_number IS NOT NULL OR byte_offset IS NOT NULL OR confidence IS NOT NULL") == 0


def test_marked_deleted_contacts_are_flagged_not_recovered(analyzed):
    store, *_ = analyzed
    assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='contact' AND marked_deleted=1") == 3
    assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE marked_deleted=1 AND status!='ACTIVE'") == 0


def test_unknown_app_db_is_catalogued_generically(analyzed):
    store, *_ = analyzed
    row = store.one(
        "SELECT t.* FROM db_tables t JOIN databases d ON d.id=t.database_id JOIN evidence_files f ON f.id=d.evidence_file_id "
        "WHERE f.path LIKE '%com.example.notes/databases/notes.db' AND t.name='notes'")
    assert row["parsed_by"] is None and row["row_count"] == 15
    hints = json.loads(row["hints_json"])["columns"]
    assert "timestamp_like" in hints["created_at"]["hints"] and "unix_ms" in hints["created_at"]["timestamp_formats"]
    assert "text_heavy" not in hints["title"]["hints"]
    assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE source_file LIKE '%notes.db' AND artifact_type!='app_summary'") == 0


def test_encrypted_truncated_and_hot_journal_handling(analyzed):
    store, *_ = analyzed
    st = {r["path"].rsplit("/", 1)[-1]: r for r in store.q(
        "SELECT f.path, d.* FROM databases d JOIN evidence_files f ON f.id=d.evidence_file_id")}
    assert st["vault.db"]["open_status"] == "encrypted_suspect" and st["vault.db"]["integrity_status"] == "UNVERIFIED"
    assert st["broken.db"]["open_status"] == "unopenable" and st["broken.db"]["size_consistent"] == 0
    pend = st["pending.db"]
    assert pend["open_status"] == "ok" and pend["has_journal"] == 1 and pend["integrity_status"] == "VALID"
    assert json.loads(pend["sidecars_json"])["journal"]["magic_valid"] is True
    assert st["calllog.db"]["has_wal"] == 1 and st["calllog.db"]["view_includes_wal"] == 1
    assert st["mmssms.db"]["has_wal"] == 0 and st["mmssms.db"]["view_includes_wal"] == 0


def test_hot_journal_is_rolled_back_on_scratch_copy_only(analyzed):
    store, *_ = analyzed
    frow = store.one("SELECT * FROM evidence_files WHERE path LIKE '%pending.db'")
    db_path = preserved_path(store, frow)
    sidecars = {s: preserved_path(store, r) for s, r in sidecar_rows(store, frow).items()}
    import hashlib
    before = hashlib.sha256(db_path.read_bytes()).hexdigest()
    with SQLiteSession(db_path, sidecars, store.scratch_dir) as s:
        first = next(iter(s.iter_rows("queue")))[1]["a"]
        assert first.startswith("row00000-"), "hot journal should roll the interrupted 'X' update back"
        assert sum(1 for _ in s.iter_rows("queue")) == 4000
    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == before


def test_shared_prefs_keys_only_never_values(analyzed):
    store, *_ = analyzed
    row = store.one("SELECT fields_json FROM artifacts WHERE artifact_type='app_summary' AND application='com.example.notes'")
    keys = json.loads(row["fields_json"])["shared_pref_keys"]
    assert any("auth_token" in v for v in keys.values())
    dump = "\n".join(str(tuple(r)) for r in store.conn.execute("SELECT fields_json, raw_row_json, summary FROM artifacts"))
    assert "SYNTHETIC-NOT-A-REAL-TOKEN" not in dump


def test_application_attribution(analyzed):
    store, *_ = analyzed
    apps = {r["application"]: r["n"] for r in store.q("SELECT application, COUNT(*) n FROM artifacts WHERE artifact_type!='app_summary' GROUP BY 1")}
    assert apps["com.android.providers.telephony"] == 120
    assert apps["com.android.providers.contacts"] == 90
    assert apps["com.android.chrome"] == 157


def test_every_artifact_traces_to_hashed_evidence(analyzed):
    store, *_ = analyzed
    bad = store.scalar(
        "SELECT COUNT(*) FROM artifacts a JOIN evidence_files f ON f.id=a.evidence_file_id WHERE a.source_sha256!=f.sha256")
    assert bad == 0
    assert store.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type!='app_summary' AND (source_table IS NULL OR source_rowid IS NULL)") == 0


def test_original_evidence_never_modified(analyzed):
    store, _r, _t, before, out = analyzed
    assert tree_hash(out / "android_dump") == before
    for f in store.q("SELECT source_id, preserved_copy FROM evidence_files WHERE preserved_copy IS NOT NULL"):
        p = store.evidence_dir / f"s{f['source_id']}" / f["preserved_copy"]
        assert p.stat().st_mode & 0o222 == 0, "preserved copies must be write-protected"


def test_scratch_area_left_clean(analyzed):
    store, *_ = analyzed
    assert list(store.scratch_dir.iterdir()) == []


def test_validation_outcomes_on_synthetic_case(analyzed):
    store, *_ = analyzed
    st = {r["check_name"]: {} for r in store.q("SELECT DISTINCT check_name FROM validation_results")}
    for r in store.q("SELECT check_name, status, COUNT(*) n FROM validation_results GROUP BY 1,2"):
        st[r["check_name"]][r["status"]] = r["n"]
    assert store.scalar("SELECT COUNT(*) FROM validation_results WHERE status='INVALID'") == 0
    assert st["hash_consistency"] == {"VALID": 2}
    assert st["custody_chain"] == {"VALID": 1} and st["manifest_integrity"] == {"VALID": 1}
    assert st["sqlite_header"] == {"VALID": 6, "PARTIAL": 1, "UNVERIFIED": 1}
    assert st["sqlite_integrity"] == {"VALID": 6, "UNVERIFIED": 2}
    assert st["provenance_completeness"] == {"VALID": 1}
    broken = store.one("SELECT detail FROM validation_results WHERE check_name='sqlite_header' AND target_label LIKE '%broken.db'")
    assert "truncated" in broken["detail"]


def test_timeline_is_sorted_and_complete(analyzed):
    store, *_ = analyzed
    ts = [r[0] for r in store.conn.execute("SELECT ts_utc FROM timeline_events ORDER BY id")]
    assert ts == sorted(ts)
    assert store.scalar("SELECT COUNT(*) FROM timeline_events WHERE event_kind='artifact'") == 367
    assert store.scalar("SELECT COUNT(*) FROM timeline_events WHERE event_kind='file_mtime'") == 11
    assert store.scalar("SELECT COUNT(*) FROM timeline_events WHERE artifact_id IS NOT NULL AND status!='ACTIVE'") == 0


def test_every_artifact_reloads_as_its_typed_model_and_round_trips(analyzed):
    """The database and the model layer describe exactly the same artifact — nothing is lost either way."""
    store, *_ = analyzed
    seen = set()
    for row in store.q("SELECT * FROM artifacts"):
        art = store.get_artifact(row["id"])
        assert type(art) is artifact_class(ArtifactType(row["artifact_type"]))
        assert art.id == row["id"]
        record = art.to_record()
        for column, value in record.items():
            if column != "created_at":
                assert row[column] == value, f"artifact {row['id']} column {column}"
        seen.add(type(art).__name__)
    assert seen == {"SMSMessage", "CallRecord", "Contact", "BrowserHistoryEntry", "BrowserDownload", "ApplicationSummary"}


def test_every_artifact_carries_source_file_database_table_and_a_raw_reference(analyzed):
    store, *_ = analyzed
    for row in store.q("SELECT id FROM artifacts WHERE artifact_type!='app_summary'"):
        art = store.get_artifact(row["id"])
        p = art.provenance
        assert p.source_file and p.source_database == p.source_file and p.source_table and p.source_rowid is not None
        assert len(p.source_sha256) == 64 and art.raw.kind is RawKind.SQLITE_ROW and art.raw.row and art.raw.sha256
        assert art.status.value == "ACTIVE" and art.extraction_method.value == "ACTIVE_QUERY"


def test_typed_sms_exposes_fields_as_attributes(analyzed):
    store, _r, truth, *_ = analyzed
    art = store.get_artifact(store.scalar("SELECT id FROM artifacts WHERE artifact_type='sms' AND source_rowid=1"))
    first = truth["files"]["data/data/com.android.providers.telephony/databases/mmssms.db"]["active"][0]
    assert isinstance(art, SMSMessage) and art.address == first["address"] and art.body == first["body"]
    assert art.direction.value in {"RECEIVED", "SENT", "DRAFT"} and art.timestamp.as_datetime.year == 2024
