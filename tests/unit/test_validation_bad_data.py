"""Phase 9: five distinct classes of deliberately bad data, each flagged by validation with the specific, correct reason.
Nothing is fabricated to make a check pass and nothing bad is silently dropped."""

from __future__ import annotations

from datetime import UTC, datetime

from android_forensics.artifacts.base import DbContext, RowSource
from android_forensics.artifacts.schema_probe import RoleMatch, SchemaMatch
from android_forensics.artifacts.sms import SmsParser
from android_forensics.models import ValidationResult, ValidationStatus
from android_forensics.storage.artifact_writer import insert_artifacts
from android_forensics.storage.case_store import CaseStore, utcnow
from android_forensics.validation.runner import run_validation

NOW = datetime(2026, 1, 1, tzinfo=UTC)
DB = "data/data/com.android.providers.telephony/databases/mmssms.db"
MATCH = SchemaMatch("sms", "aosp_sms", {"main": RoleMatch("sms", {}, 1.0)}, 1.0)


def row(values: dict, rowid: int) -> RowSource:
    return RowSource(values=values, raw=dict(values), table="sms", rowid=rowid)


def make(rowid: int, address: str, body: str, date, sha: str = "ab" * 32, type_=1):
    ctx = DbContext(1, 1, DB, sha, "com.android.providers.telephony", False, now=NOW)
    v = {"address": address, "body": body, "date": date, "type": type_, "read": 1, "thread_id": 1}
    return SmsParser().from_row(row(v, rowid), MATCH, ctx)


def seed_evidence(store: CaseStore) -> None:
    """One evidence source and the ``mmssms.db`` file every made-up artifact in this test claims to come from."""
    store.insert("evidence_sources", {"case_id": store.case().id, "original_path": "/x", "original_name": "x",
                                      "source_type": "directory", "file_count": 1, "total_bytes": 0,
                                      "acquisition_time": None, "ingested_at": utcnow(), "complete": 1})
    store.insert("evidence_files", {"source_id": 1, "ordinal": 0, "path": "mmssms.db", "name": "mmssms.db", "size": 100,
                                    "md5": "0" * 32, "sha1": "0" * 40, "sha256": "ab" * 32, "kind": "sqlite_db",
                                    "kind_detail": None, "mtime": None, "atime": None, "ctime": None, "time_basis": None,
                                    "preserved_copy": None, "logical_path": None, "android_root": None, "user_id": None,
                                    "package": "com.android.providers.telephony"})


def by_check(store: CaseStore, check: str) -> list[ValidationResult]:
    return [ValidationResult.from_record(r) for r in store.q("SELECT * FROM validation_results WHERE check_name=?", (check,))]


def test_five_bad_data_classes_are_each_flagged_with_the_specific_reason(tmp_path):
    store = CaseStore.create(tmp_path / "case", "bad-data", "pytest")
    seed_evidence(store)

    # 1. a timestamp predating Android's existence (2005: four years before the first Android phone shipped)
    predates_android = make(1, "+12025550101", "hello from the past", 1_100_000_000_000)
    assert predates_android.timestamp.plausible is False
    # 2. a record missing provenance fields (no source table / rowid -- as if built by hand, bypassing the parser)
    no_provenance = make(2, "+12025550102", "fine otherwise", 1_700_000_000_000)
    no_provenance = no_provenance.evolve(provenance=no_provenance.provenance.model_copy(update={"source_table": None, "source_rowid": None}))
    # 3. a duplicate row: the same timestamp, address and body as another row of the same table
    original = make(4, "+12025550104", "let's meet at noon", 1_700_000_000_000)
    duplicate = make(5, "+12025550104", "let's meet at noon", 1_700_000_000_000)
    # 4. a hash mismatch: the artifact cites a source-file hash that differs from the evidence inventory's
    hash_mismatch = make(6, "+12025550106", "fine otherwise", 1_700_000_000_000, sha="cd" * 32)
    # 5. a type mismatch: a column that fails FieldReader's type check, recorded as a flag on the artifact
    type_mismatch = SmsParser().from_row(
        row({"address": "+12025550107", "body": "fine otherwise", "date": 1_700_000_000_000, "type": "not-a-number", "read": 1}, 7),
        MATCH, DbContext(1, 1, DB, "ab" * 32, None, False, now=NOW),
    )
    assert type_mismatch.flags and any(f.startswith("type_mismatch:type") for f in type_mismatch.flags)

    insert_artifacts(store, store.start_run("extract"), None,
                     [predates_android, no_provenance, original, duplicate, hash_mismatch, type_mismatch])
    summary = run_validation(store, store.start_run("validate"))
    assert summary.total > 0

    # 1. timestamp predating Android
    ts_table = [r for r in by_check(store, "timestamp_plausibility") if r.target_type.value == "table"]
    assert ts_table and ts_table[0].status is ValidationStatus.PARTIAL
    assert "outside 2008-01-01" in ts_table[0].detail and ts_table[0].evidence["implausible"] >= 1

    # 2. missing provenance
    prov = by_check(store, "provenance_completeness")
    assert len(prov) == 1 and prov[0].status is ValidationStatus.INVALID
    assert "lack complete provenance" in prov[0].detail
    assert no_provenance.id is None  # the artifact itself has no id until inserted; the check names it by database row id instead

    # 3. duplicate row
    dup = [r for r in by_check(store, "duplicate_detection") if "sms" in r.target_label]
    assert dup and any(r.status is ValidationStatus.PARTIAL and "duplicate" in r.detail for r in dup)

    # 4. hash mismatch: named specifically, not folded into the "missing" bucket
    assert prov[0].evidence.get("hash_mismatch"), prov[0].evidence

    # 5. type mismatch
    struct = by_check(store, "record_structure")
    assert any(r.target_type.value == "artifact" and "type_mismatch:type" in r.detail for r in struct)


def test_a_correctly_formed_case_reports_no_false_failures(tmp_path):
    """The five-class test above must be testing real detection, not a check that always fires: a clean case stays VALID."""
    store = CaseStore.create(tmp_path / "case", "clean", "pytest")
    seed_evidence(store)
    good = make(1, "+12025550101", "all good here", 1_700_000_000_000)
    insert_artifacts(store, store.start_run("extract"), None, [good])
    run_validation(store, store.start_run("validate"))
    assert store.scalar("SELECT COUNT(*) FROM validation_results WHERE status='INVALID'") == 0
    unexpected = store.q("SELECT check_name, detail FROM validation_results WHERE status='PARTIAL' AND check_name != 'hash_consistency'")
    assert unexpected == [], unexpected
