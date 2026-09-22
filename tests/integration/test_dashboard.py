"""Phase 11: the FastAPI dashboard is a read-only view of whatever the case database already holds -- it never runs a
stage, never labels a carved candidate as confirmed, and every endpoint's numbers match the database directly."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.dashboard import create_app
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, run_pipeline
from android_forensics.storage.case_store import CaseStore
from tests.unit.recovery_fixtures import SMS_DDL, build_table_db, sms_row


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dashboard")
    build_table_db(tmp / "dump/data/data/com.android.providers.telephony/databases/mmssms.db", SMS_DDL, "sms", sms_row, 60,
                   "_id % 4 = 0")
    store = CaseStore.create(tmp / "case", "dash", "pytest")
    ingest_source(store, tmp / "dump")
    run_pipeline(store, names=list(FULL_PIPELINE_NAMES))
    return store, tmp / "case"


@pytest.fixture(scope="module")
def client(case):
    _, case_dir = case
    return TestClient(create_app(case_dir))


def test_summary_matches_the_database_directly(case, client):
    store, _ = case
    r = client.get("/api/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["case"]["name"] == "dash"
    assert body["counts"] == store.counts()
    assert {run["stage"] for run in body["runs"]} >= {"scan", "extract", "recover", "carve", "correlate", "reconstruct"}


def test_artifacts_endpoint_lists_and_filters(case, client):
    store, _ = case
    r = client.get("/api/artifacts", params={"limit": 500})
    body = r.json()
    assert body["total"] == store.scalar("SELECT COUNT(*) FROM artifacts")
    assert len(body["artifacts"]) == body["total"]
    for a in body["artifacts"]:
        assert "fields_json" not in a and isinstance(a["fields"], dict)

    r = client.get("/api/artifacts", params={"status": "RECOVERED"})
    got = r.json()["artifacts"]
    assert got and all(a["status"] == "RECOVERED" for a in got)

    r = client.get("/api/artifacts", params={"status": "PARTIAL"})
    got = r.json()["artifacts"]
    assert got and all(a["status"] == "PARTIAL" and a["unknown_fields"] for a in got)


def test_artifact_detail_includes_recovery_and_correlation_context(case, client):
    store, _ = case
    aid = store.scalar("SELECT id FROM artifacts WHERE status='RECOVERED' LIMIT 1")
    r = client.get(f"/api/artifacts/{aid}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == aid and body["confidence"] in ("LOW", "MEDIUM", "HIGH")
    assert "recovered_record" in body and body["recovered_record"]["artifact_id"] == aid
    assert isinstance(body["recovered_record"]["corroboration"], list)
    assert isinstance(body["correlations"], list)


def test_artifact_detail_404_for_an_unknown_id(client):
    r = client.get("/api/artifacts/999999")
    assert r.status_code == 404


def test_recovery_endpoint_never_shows_a_confirmed_status(case, client):
    r = client.get("/api/recovery")
    body = r.json()
    assert set(body["by_status"]) <= {"RECOVERED", "PARTIAL", "CORRUPTED"}
    assert body["last_runs"]["reconstruct"] is not None and body["last_runs"]["reconstruct"]["status"] == "COMPLETED"


def test_recovered_records_endpoint_decodes_its_json_columns(case, client):
    r = client.get("/api/recovered", params={"limit": 500})
    body = r.json()
    assert body["records"]
    for rec in body["records"]:
        assert isinstance(rec["values"], dict) and isinstance(rec["unknown_columns"], list)
        assert isinstance(rec["also_found_at"], list) and isinstance(rec["corroboration"], list)


def test_carved_candidates_are_always_reported_as_candidates(case, client):
    r = client.get("/api/carved", params={"limit": 500})
    body = r.json()
    for c in body["candidates"]:
        assert c["status"] == "CARVED CANDIDATE" and c["confidence"] != "HIGH"
        assert isinstance(c["corroborated_by"], list) and isinstance(c["confidence_factors"], list)


def test_correlations_endpoint_returns_a_consistent_node_and_edge_set(case, client):
    r = client.get("/api/correlations", params={"limit": 2000})
    body = r.json()
    assert body["edges"]
    node_keys = {f"{n['kind']}:{n['ref']}" for n in body["nodes"]}
    for e in body["edges"]:
        assert f"{e['source_kind']}:{e['source_ref']}" in node_keys
        assert f"{e['target_kind']}:{e['target_ref']}" in node_keys
        assert "evidence_json" not in e


def test_correlations_can_be_filtered_by_entity_and_relation(case, client):
    r = client.get("/api/correlations", params={"relation": "CONTACT_OF"})
    body = r.json()
    assert all(e["relation"] == "CONTACT_OF" for e in body["edges"])


def test_validation_endpoint_matches_the_database(case, client):
    store, _ = case
    r = client.get("/api/validation", params={"limit": 1000})
    body = r.json()
    assert sum(body["by_status"].values()) == store.scalar("SELECT COUNT(*) FROM validation_results")
    assert any(res["target_label"] == "recovered records" for res in body["results"])


def test_timeline_endpoint_is_chronological(case, client):
    r = client.get("/api/timeline", params={"limit": 1000})
    events = r.json()["events"]
    assert events == sorted(events, key=lambda e: e["ts_utc"])


def test_the_dashboard_never_writes_to_the_case(case, client):
    store, case_dir = case
    before = json.loads((case_dir / "case.db").read_bytes()[:0] or "null")  # sanity: reading is safe
    del before
    counts_before = store.counts()
    client.get("/api/summary")
    client.get("/api/artifacts")
    client.get("/api/recovery")
    client.get("/api/carved")
    client.get("/api/correlations")
    assert store.counts() == counts_before


def test_the_frontend_page_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "Android Forensics Dashboard" in r.text
    r = client.get("/static/index.html")
    assert r.status_code == 200


def test_create_app_refuses_a_non_case_directory(tmp_path):
    from android_forensics.errors import CaseError

    with pytest.raises(CaseError):
        create_app(tmp_path)
