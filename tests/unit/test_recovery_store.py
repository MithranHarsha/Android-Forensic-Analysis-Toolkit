"""Persistence of the Review 2 evidence: what goes into the case database comes back identical."""

from __future__ import annotations

import sqlite3

import pytest

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.artifacts.recovered import DatabaseContext, reconstruct, record_from_row
from android_forensics.models import (
    ArtifactStatus,
    CarvedCandidate,
    CarveKind,
    Confidence,
    ConfidenceFactor,
    CorrelationEdge,
    EntityKind,
    ExtractionMethod,
    Relation,
    UnrecoveredRegion,
)
from android_forensics.sqlite.recover_db import recover_database
from android_forensics.storage.artifact_writer import insert_artifacts_with_ids
from android_forensics.storage.case_store import CaseStore
from android_forensics.storage.recovery_store import (
    decode_values,
    encode_values,
    insert_carved,
    insert_edges,
    insert_recovered,
    insert_unrecovered,
    link_artifact,
    load_carved,
    load_edges,
    load_recovered,
    load_unrecovered,
    update_carved_scoring,
)
from tests.unit.recovery_fixtures import NOW, SMS_DDL, build_table_db, sms_row


@pytest.fixture
def case(tmp_path):
    """A case that has ingested a directory holding one database with deleted rows, plus that database's recovered rows."""
    db_dir = tmp_path / "dump" / "data" / "data" / "com.android.providers.telephony" / "databases"
    build_table_db(db_dir / "mmssms.db", SMS_DDL, "sms", sms_row, 60, "_id % 4 = 0")
    store = CaseStore.create(tmp_path / "case", "store", "pytest")
    ingest_source(store, tmp_path / "dump")
    ev = next(f for f in store.evidence_files() if f.name == "mmssms.db")
    report = recover_database(db_dir / "mmssms.db")
    records = [record_from_row(r, database_file_id=ev.id, source_file_id=ev.id, source_sha256=ev.hashes.sha256) for r in report.rows]
    dc = DatabaseContext.from_report(report, database_file_id=ev.id, database_sha256=ev.hashes.sha256, application=None, now=NOW)
    return store, ev, report, records, dc


def test_values_survive_encoding_including_blobs_and_non_finite_floats():
    values = {"a": 1, "b": "text ✓", "c": b"\x00\xff\x10", "d": None, "e": 2.5, "f": float("inf"), "g": float("-inf")}
    assert decode_values(encode_values(values)) == values
    nan = decode_values(encode_values({"n": float("nan")}))["n"]
    assert nan != nan


def test_recovered_records_round_trip_exactly(case):
    store, _, _, records, _ = case
    run = store.start_run("recover")
    ids = insert_recovered(store, run, records)
    loaded = list(load_recovered(store))
    assert len(loaded) == len(records) == len(ids) > 0
    for original, back, rid in zip(records, loaded, ids):
        assert back.id == rid
        assert back.model_dump(exclude={"id"}) == original.model_dump(exclude={"id"})
        assert back.raw_sha256 == original.raw_sha256


def test_recovered_records_can_be_filtered(case):
    store, _, _, records, _ = case
    insert_recovered(store, store.start_run("recover"), records)
    partial = list(load_recovered(store, "status=?", ("PARTIAL",)))
    assert partial and all(r.status is ArtifactStatus.PARTIAL for r in partial)
    assert len(partial) == sum(r.status is ArtifactStatus.PARTIAL for r in records)


def test_a_recovered_record_is_linked_to_the_artifact_built_from_it(case):
    store, _, _, records, dc = case
    run = store.start_run("recover")
    ids = insert_recovered(store, run, records)
    built = [reconstruct(r, dc) for r in records]
    artifact_ids = insert_artifacts_with_ids(store, run, None, built)
    assert len(artifact_ids) == len(built)
    for rid, aid in zip(ids, artifact_ids):
        link_artifact(store, rid, aid)
    store.conn.commit()
    for record, aid in zip(load_recovered(store), artifact_ids):
        assert record.artifact_id == aid
        artifact = store.get_artifact(aid)
        assert artifact.status in (ArtifactStatus.RECOVERED, ArtifactStatus.PARTIAL) and not artifact.extraction_method.is_active
        assert artifact.raw.raw_bytes_hex == record.raw_hex and artifact.provenance.physical.byte_offset == record.file_offset


def test_the_database_refuses_a_record_that_points_at_no_evidence_file(case):
    store, _, _, records, _ = case
    bad = records[0].model_copy(update={"database_file_id": 9999, "source_file_id": 9999})
    with pytest.raises(sqlite3.IntegrityError):
        insert_recovered(store, store.start_run("recover"), [bad])


def test_unrecovered_regions_round_trip(case):
    store, ev, _, _, _ = case
    regions = [UnrecoveredRegion(source="main", source_path="x/mmssms.db", page_number=3, page_offset=100, file_offset=8292, length=64,
                                 region="unallocated", reason="zero-filled: the content was overwritten", raw_sha256="0" * 64)]
    insert_unrecovered(store, store.start_run("recover"), regions)
    assert [u.model_dump(exclude={"id"}) for u in load_unrecovered(store)] == [u.model_dump(exclude={"id"}) for u in regions]


def _carved(**kw):
    base = dict(evidence_file_id=1, source_file="f.db", source_sha256="a" * 64, offset=10, length=12, kind=CarveKind.PHONE_NUMBER,
                pattern="phone_e164", matched="+12025550101", context_before_hex="0a0b", context_after_hex="0c")
    return CarvedCandidate(**{**base, **kw})


def test_carved_candidates_round_trip_and_stay_candidates(case):
    store, ev, _, _, _ = case
    c = _carved(evidence_file_id=ev.id)
    (cid,) = insert_carved(store, store.start_run("carve"), [c])
    back = next(load_carved(store))
    assert back.id == cid and back.status == "CARVED CANDIDATE" and back.extraction_method is ExtractionMethod.CARVING
    assert back.model_dump(exclude={"id"}) == c.model_dump(exclude={"id"})


def test_the_database_itself_refuses_a_carved_row_that_is_not_a_candidate(case):
    store, ev, _, _, _ = case
    insert_carved(store, store.start_run("carve"), [_carved(evidence_file_id=ev.id)])
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("UPDATE carved_candidates SET status='ACTIVE'")


def test_scoring_a_carved_candidate_is_stored_without_promoting_it(case):
    store, ev, _, _, _ = case
    (cid,) = insert_carved(store, store.start_run("carve"), [_carved(evidence_file_id=ev.id)])
    scored = _carved(evidence_file_id=ev.id, confidence=Confidence.MEDIUM, corroborated_by=[4, 9], explanation="MEDIUM: carved phone_number.",
                     confidence_factors=[ConfidenceFactor(name="value_validity", satisfied=True, weight=2.0, explanation="valid")])
    update_carved_scoring(store, cid, scored)
    store.conn.commit()
    back = next(load_carved(store))
    assert back.confidence is Confidence.MEDIUM and back.corroborated_by == [4, 9] and back.status == "CARVED CANDIDATE"
    assert back.confidence_factors[0].name == "value_validity"


def test_correlation_edges_round_trip_and_can_be_queried(case):
    store, *_ = case
    edges = [
        CorrelationEdge(source_kind=EntityKind.PERSON, source_ref="person:Ann Lee", target_kind=EntityKind.PHONE_NUMBER,
                        target_ref="phone:2025550101", relation=Relation.CONTACT_OF, strength=1.0, explanation="contact Ann Lee lists it",
                        evidence={"artifact_ids": [3, 4], "note": "é"}),
        CorrelationEdge(source_kind=EntityKind.MESSAGE, source_ref="artifact:7", target_kind=EntityKind.PHONE_NUMBER,
                        target_ref="phone:2025550101", relation=Relation.RECEIVED, strength=0.6, explanation="sms received from it"),
    ]
    assert insert_edges(store, store.start_run("correlate"), edges) == 2
    back = list(load_edges(store))
    assert [e.model_dump(exclude={"id"}) for e in back] == [e.model_dump(exclude={"id"}) for e in edges]
    assert [e.relation for e in load_edges(store, "target_ref=? AND strength<?", ("phone:2025550101", 0.9))] == [Relation.RECEIVED]
