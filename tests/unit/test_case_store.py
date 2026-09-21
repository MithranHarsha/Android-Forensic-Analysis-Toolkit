import pytest

from android_forensics.storage.case_store import CaseError, CaseStore


def test_create_open_and_duplicate(tmp_path):
    s = CaseStore.create(tmp_path / "c", "n", "ex", "d")
    assert s.case().examiner == "ex" and CaseStore.is_case_dir(tmp_path / "c")
    with pytest.raises(CaseError):
        CaseStore.create(tmp_path / "c", "n")
    with pytest.raises(CaseError):
        CaseStore.open(tmp_path / "nope")
    s.close()
    assert CaseStore.open(tmp_path / "c").case().name == "n"


def test_migrations_idempotent(tmp_path):
    s = CaseStore.create(tmp_path / "c", "n")
    s.close()
    s2 = CaseStore.open(tmp_path / "c")
    assert s2.scalar("SELECT COUNT(*) FROM schema_migrations") == 1


def test_custody_chain_detects_tampering_and_deletion(fresh_case):
    for i in range(3):
        fresh_case.log("act", f"t{i}", {"i": i})
    assert fresh_case.verify_custody_chain()[0]
    fresh_case.conn.execute("UPDATE custody_log SET detail_json='{}' WHERE id=2")
    fresh_case.conn.commit()
    ok, msg = fresh_case.verify_custody_chain()
    assert not ok and "entry 2" in msg


def test_custody_chain_detects_removed_entry(fresh_case):
    for i in range(4):
        fresh_case.log("act", f"t{i}")
    fresh_case.conn.execute("DELETE FROM custody_log WHERE id=3")
    fresh_case.conn.commit()
    assert not fresh_case.verify_custody_chain()[0]


def test_run_lifecycle(fresh_case):
    rid = fresh_case.start_run("scan", {"a": 1})
    assert fresh_case.last_run("scan") is None
    fresh_case.finish_run(rid, "COMPLETED", {"n": 2})
    assert fresh_case.last_run("scan").id == rid


# ------------------------------------------------------------------ typed access to the core models

from android_forensics.models import (  # noqa: E402
    AnalysisRun,
    Case,
    EvidenceFile,
    EvidenceSource,
    FileHashes,
    FileKind,
    FileTimes,
    RunStatus,
    SourceLayout,
    SourceType,
    TimelineEvent,
    TimelineEventKind,
    ValidationResult,
    ValidationStatus,
)

H = FileHashes(md5="a" * 32, sha1="b" * 40, sha256="c" * 64)


def test_case_is_a_typed_model_with_layouts(fresh_case):
    case = fresh_case.case()
    assert isinstance(case, Case) and case.name == "unit" and case.examiner == "pytest" and case.layouts == {}
    fresh_case.set_layouts("android_root", {1: SourceLayout(layout="android_root", detail="16/16 paths")})
    again = fresh_case.case()
    assert again.layout == "android_root" and again.layouts[1].detail == "16/16 paths"
    assert fresh_case.case_id == case.id


def test_runs_are_typed_and_validated(fresh_case):
    rid = fresh_case.start_run("scan", {"k": 1})
    running = fresh_case.get_run(rid)
    assert isinstance(running, AnalysisRun) and running.status is RunStatus.RUNNING and running.params == {"k": 1}
    done = fresh_case.finish_run(rid, "COMPLETED", {"files": 3})
    assert done.status is RunStatus.COMPLETED and done.stats == {"files": 3} and done.duration_seconds >= 0
    assert [r.stage for r in fresh_case.runs()] == ["scan"] and fresh_case.last_run("scan").id == rid
    bad = fresh_case.start_run("extract")
    with pytest.raises(Exception, match="record its error"):
        fresh_case.finish_run(bad, "FAILED")
    assert fresh_case.finish_run(bad, RunStatus.FAILED, error="boom").error == "boom"
    assert fresh_case.last_run("extract") is None, "only COMPLETED runs count"


def test_sources_and_files_round_trip_as_models(fresh_case):
    sid = fresh_case.add_source(EvidenceSource(
        case_id=fresh_case.case_id, original_path="/e/x.zip", original_name="x.zip", source_type=SourceType.ZIP,
        container_size=10, container_hashes=H, acquisition_time="2024-06-04T08:00:00Z", ingested_at="2026-09-21T14:16:50.000Z"))
    f = EvidenceFile(source_id=sid, ordinal=0, path="data/data/com.x/a.db", size=4096, hashes=H, kind=FileKind.SQLITE_DB,
                     times=FileTimes(mtime="2024-06-04T08:00:00.000Z", basis="zip_dos_time"), preserved_copy="0000000_a.db")
    fresh_case.add_files([f])
    fresh_case.update_source_totals(sid, 1, 4096, True)
    [src] = fresh_case.sources()
    assert src.id == sid and src.file_count == 1 and src.total_bytes == 4096 and src.acquisition_time == "2024-06-04T08:00:00.000Z"
    [back] = list(fresh_case.evidence_files(sid))
    assert back.id is not None and back == f.model_copy(update={"id": back.id})
    assert fresh_case.get_file(back.id) == back
    with pytest.raises(CaseError):
        fresh_case.get_file(999)


def test_validation_results_and_timeline_events_persist_through_models(fresh_case):
    sid = fresh_case.add_source(EvidenceSource(case_id=fresh_case.case_id, original_path="/e/d", original_name="d",
                                               source_type=SourceType.DIRECTORY, ingested_at="2026-09-21T14:16:50.000Z"))
    fresh_case.add_files([EvidenceFile(source_id=sid, ordinal=0, path="a.db", size=1, hashes=H, kind=FileKind.SQLITE_DB)])
    file_id = fresh_case.scalar("SELECT id FROM evidence_files")
    rid = fresh_case.start_run("validate")

    n = fresh_case.add_validation_results(rid, [ValidationResult.of("case", None, "x", "custody_chain", ValidationStatus.VALID, "intact")])
    back = ValidationResult.from_record(fresh_case.one("SELECT * FROM validation_results"))
    assert n == 1 and back.run_id == rid and back.created_at is not None and back.check.value == "custody_chain"

    ev = TimelineEvent(timestamp="2024-06-04T08:00:00.000Z", kind=TimelineEventKind.FILE_MTIME, event="File modified: a.db",
                       evidence_file_id=file_id)
    assert fresh_case.add_timeline_events(rid, [ev]) == 1
    stored = TimelineEvent.from_record(fresh_case.one("SELECT * FROM timeline_events"))
    assert stored.run_id == rid and stored.is_file_event and stored.evidence_file_id == file_id


def test_get_artifact_reports_missing_ids(fresh_case):
    with pytest.raises(CaseError, match="No artifact 5"):
        fresh_case.get_artifact(5)
