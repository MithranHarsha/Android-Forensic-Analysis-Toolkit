import json

import pytest
from pydantic import ValidationError

from android_forensics.models import (
    AnalysisRun,
    ArtifactStatus,
    ArtifactType,
    Confidence,
    RunStatus,
    TimelineEvent,
    TimelineEventKind,
    ValidationCheck,
    ValidationResult,
    ValidationStatus,
    ValidationTarget,
)

CASE_ID = "0123456789abcdef0123456789abcdef"
T0, T1 = "2026-09-21T14:16:50.000Z", "2026-09-21T14:16:52.500Z"


def run(**kw):
    return AnalysisRun(**(dict(case_id=CASE_ID, stage="extract", started_at=T0, tool_version="0.1.0") | kw))


class TestAnalysisRun:
    def test_new_run_is_running(self):
        r = run()
        assert r.status is RunStatus.RUNNING and r.finished_at is None and r.duration_seconds is None

    def test_lifecycle_rules(self):
        with pytest.raises(ValidationError, match="RUNNING"):
            run(finished_at=T1)
        with pytest.raises(ValidationError, match="finish time"):
            run(status=RunStatus.COMPLETED)
        with pytest.raises(ValidationError, match="record its error"):
            run(status=RunStatus.FAILED, finished_at=T1)
        with pytest.raises(ValidationError, match="cannot carry an error"):
            run(status=RunStatus.COMPLETED, finished_at=T1, error="x")
        with pytest.raises(ValidationError, match="before it started"):
            run(status=RunStatus.COMPLETED, finished_at="2026-09-21T14:16:49.000Z")

    def test_finished_returns_a_new_completed_run(self):
        r = run(id=4, params={"timeline_files": "key"})
        done = r.finished(RunStatus.COMPLETED, T1, stats={"total": 373})
        assert r.status is RunStatus.RUNNING and done.status is RunStatus.COMPLETED and done.id == 4
        assert done.stats == {"total": 373} and done.params == {"timeline_files": "key"} and done.duration_seconds == 2.5

    def test_failed_run_keeps_its_error(self):
        failed = run().finished(RunStatus.FAILED, T1, error="CaseError: nothing to scan")
        assert failed.error == "CaseError: nothing to scan"
        with pytest.raises(ValidationError):
            run().finished(RunStatus.FAILED, T1)

    def test_fields_are_validated(self):
        for bad in (dict(case_id="x"), dict(stage=" "), dict(started_at="now"), dict(tool_version=""), dict(status="PAUSED")):
            with pytest.raises(ValidationError):
                run(**bad)

    def test_immutable(self):
        with pytest.raises(ValidationError):
            run().stage = "scan"

    def test_record_round_trip(self):
        r = run(id=2, params={"a": [1]}).finished(RunStatus.COMPLETED, T1, stats={"n": 1})
        record = dict(r.to_record(), id=2)
        assert json.loads(record["stats_json"]) == {"n": 1} and record["status"] == "COMPLETED"
        assert AnalysisRun.from_record(record) == r


def vr(**kw):
    base = dict(target_type="database", target_id=3, target_label="a.db", check="sqlite_integrity", status=ValidationStatus.VALID,
                detail="PRAGMA integrity_check: ok")
    return ValidationResult(**(base | kw))


class TestValidationResult:
    def test_strings_coerce_to_enums(self):
        r = vr()
        assert r.target_type is ValidationTarget.DATABASE and r.check is ValidationCheck.SQLITE_INTEGRITY and r.passed and not r.failed

    def test_every_outcome_needs_an_explanation(self):
        for status in ValidationStatus:
            assert vr(status=status).status is status
            with pytest.raises(ValidationError):
                vr(status=status, detail="  ")

    def test_check_and_target_must_be_known(self):
        with pytest.raises(ValidationError):
            vr(check="vibes")
        with pytest.raises(ValidationError):
            vr(target_type="galaxy")
        with pytest.raises(ValidationError):
            vr(target_label="")

    @pytest.mark.parametrize("check", list(ValidationCheck))
    def test_every_documented_check_is_constructible(self, check):
        assert vr(check=check).check is check

    def test_of_factory_takes_positional_arguments_like_the_check_functions(self):
        r = ValidationResult.of("source", 1, "source s1", "hash_consistency", ValidationStatus.INVALID, "container changed", {"recorded": "a"})
        assert r.failed and r.evidence == {"recorded": "a"} and r.target_id == 1
        assert ValidationResult.of("case", None, "x", "custody_chain", ValidationStatus.VALID, "intact").evidence == {}

    def test_record_round_trip_with_and_without_evidence(self):
        for r in (vr(), vr(evidence={"ids": [1, 2]}, run_id=5, created_at="2026-09-21T14:16:50.000Z")):
            record = dict(r.to_record(), id=9)
            assert record["check_name"] == r.check.value
            assert ValidationResult.from_record(record) == r.model_copy(update={"id": 9})
        assert vr().to_record()["evidence_json"] is None


def ev(**kw):
    base = dict(timestamp="2024-03-01T08:00:00.000Z", kind=TimelineEventKind.ARTIFACT, artifact_type=ArtifactType.SMS,
                event="SMS RECEIVED from +1: hi", source="mmssms.db → sms#5", status=ArtifactStatus.ACTIVE, artifact_id=5,
                evidence_file_id=2)
    return TimelineEvent(**(base | kw))


def file_ev(**kw):
    base = dict(timestamp="2024-06-04T08:00:00.000Z", kind=TimelineEventKind.FILE_MTIME, event="File modified: /data/x/a.db",
                evidence_file_id=2, time_basis="fs_stat")
    return TimelineEvent(**(base | kw))


class TestTimelineEvent:
    def test_active_artifact_event(self):
        e = ev()
        assert not e.is_recovered and not e.is_file_event and e.status is ArtifactStatus.ACTIVE

    def test_recovered_events_are_distinguishable(self):
        for status in ArtifactStatus:
            if status is not ArtifactStatus.ACTIVE:
                assert ev(status=status, confidence=Confidence.LOW).is_recovered

    def test_artifact_event_needs_type_status_and_id(self):
        for missing in ("artifact_type", "status", "artifact_id"):
            with pytest.raises(ValidationError, match="artifact event needs"):
                ev(**{missing: None})

    def test_file_event_is_filesystem_metadata_only(self):
        e = file_ev()
        assert e.is_file_event and e.status is None and not e.is_recovered
        for extra in (dict(status=ArtifactStatus.ACTIVE), dict(artifact_id=1), dict(artifact_type=ArtifactType.SMS)):
            with pytest.raises(ValidationError, match="filesystem metadata"):
                file_ev(**extra)
        with pytest.raises(ValidationError, match="evidence_file_id"):
            file_ev(evidence_file_id=None)

    def test_timestamp_must_be_canonical_utc_and_event_non_empty(self):
        with pytest.raises(ValidationError):
            ev(timestamp="2024-03-01 08:00:00")
        with pytest.raises(ValidationError):
            ev(event=" ")

    def test_events_sort_chronologically_by_timestamp_string(self):
        events = [ev(timestamp="2024-03-02T00:00:00.000Z"), ev(timestamp="2024-03-01T23:59:59.999Z"), ev(timestamp="2023-12-31T00:00:00.000Z")]
        assert [e.timestamp for e in sorted(events, key=lambda e: e.timestamp)] == [
            "2023-12-31T00:00:00.000Z", "2024-03-01T23:59:59.999Z", "2024-03-02T00:00:00.000Z"]

    def test_record_round_trip_for_both_kinds(self):
        for e in (ev(id=1, run_id=4, confidence=Confidence.HIGH, timestamp_raw="1709280000000"), file_ev(id=2, run_id=4)):
            record = dict(e.to_record(), id=e.id)
            assert TimelineEvent.from_record(record) == e
        assert file_ev().to_record()["status"] is None and ev().to_record()["ts_utc"] == "2024-03-01T08:00:00.000Z"
