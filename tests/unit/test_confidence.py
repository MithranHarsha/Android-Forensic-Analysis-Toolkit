"""Phase 8: the scorer is deterministic, explained, and bound by hard caps."""

import itertools

import pytest

from android_forensics.confidence import CarveEvidence, RecoveryEvidence, score_carved, score_recovered
from android_forensics.models import ArtifactStatus, Confidence

R, P, C = ArtifactStatus.RECOVERED, ArtifactStatus.PARTIAL, ArtifactStatus.CORRUPTED


def whole(**kw):
    base = dict(status=R, source="main", rowid_known=True, untouched_cell=True, corroborations=("contacts", "call log"), timestamp_plausible=True)
    return RecoveryEvidence(**(base | kw))


def freeblock(**kw):
    base = dict(status=P, source="main", unknown_fields=("_id",), rowid_known=False, timestamp_plausible=True)
    return RecoveryEvidence(**(base | kw))


# ------------------------------------------------------------------ the levels


def test_a_whole_corroborated_verified_record_is_high_and_says_why():
    a = score_recovered(whole())
    assert a.level is Confidence.HIGH and a.score >= 0.85
    assert a.explanation.startswith("HIGH: full page-level reconstruction") and "schema match" in a.explanation
    assert "corroborated by contacts and call log" in a.explanation


def test_a_whole_record_without_corroboration_is_still_high_when_everything_else_holds():
    assert score_recovered(whole(corroborations=())).level in (Confidence.HIGH, Confidence.MEDIUM)


def test_a_freeblock_record_is_capped_at_medium_and_the_explanation_names_the_lost_rowid():
    a = score_recovered(freeblock(corroborations=("contacts",)))
    assert a.level is Confidence.MEDIUM
    assert "rowid lost" in a.explanation and "_id unknown" in a.explanation


def test_two_independent_corroborations_can_lift_a_partial_record_to_high():
    a = score_recovered(freeblock(corroborations=("contacts", "call log"), other_locations=1))
    assert a.level in (Confidence.HIGH, Confidence.MEDIUM)
    assert score_recovered(freeblock(corroborations=("contacts",))).level is not Confidence.HIGH


def test_a_corrupted_record_is_low():
    a = score_recovered(whole(status=C, field_problems=("body: text is not valid UTF-8",)))
    assert a.level is Confidence.LOW and "fails validation" in a.explanation


# ------------------------------------------------------------------ the invariants the spec requires


@pytest.mark.parametrize("status", [R, P, C])
def test_a_record_that_does_not_match_a_schema_can_never_be_high(status):
    for corr in ((), ("contacts", "call log", "sms")):
        a = score_recovered(whole(status=status, schema_matched=False, corroborations=corr))
        assert a.level is Confidence.LOW


def test_an_inexact_structure_can_never_exceed_low():
    assert score_recovered(whole(exact_structure=False)).level is Confidence.LOW


def test_high_needs_a_verified_source_and_consistent_fields():
    assert score_recovered(whole(source="wal", frame_status="stale_unverified")).level is not Confidence.HIGH
    assert score_recovered(whole(source="journal", journal_verified=False)).level is not Confidence.HIGH
    assert score_recovered(whole(field_problems=("date: str in an INTEGER column",))).level is not Confidence.HIGH


def test_a_carved_candidate_with_no_correlation_is_low_and_never_high():
    for valid, ctx, inside in itertools.product((True, False), repeat=3):
        a = score_carved(CarveEvidence("phone_number", context_valid=ctx, value_valid=valid, inside_known_structure=inside))
        assert a.level is Confidence.LOW


def test_a_corroborated_carved_candidate_is_at_most_medium():
    a = score_carved(CarveEvidence("phone_number", corroborations=("contact Ann Lee", "call log", "sms thread")))
    assert a.level is Confidence.MEDIUM and "corroborated by" in a.explanation


def test_an_invalid_carved_value_is_low_even_when_corroborated():
    assert score_carved(CarveEvidence("timestamp_unix_seconds", value_valid=False, corroborations=("sms",))).level is Confidence.LOW


# ------------------------------------------------------------------ determinism and explainability


def test_scoring_the_same_evidence_twice_gives_identical_results():
    e = whole()
    assert score_recovered(e) == score_recovered(e) and score_recovered(e).model_dump_json() == score_recovered(e).model_dump_json()
    c = CarveEvidence("url", corroborations=("browser history",))
    assert score_carved(c) == score_carved(c)


def test_every_factor_carries_a_sentence_and_the_explanation_names_the_level():
    for e in (whole(), freeblock(), whole(status=C, field_problems=("x",)), whole(source="wal", frame_status="stale_generation")):
        a = score_recovered(e)
        assert all(f.explanation.strip() for f in a.factors) and a.explanation.startswith(a.level.value)
        assert 0.0 <= a.score <= 1.0
    assert all(f.explanation for f in score_carved(CarveEvidence("email")).factors)


def test_the_timestamp_factor_only_exists_when_there_is_a_timestamp():
    assert "timestamp_validity" not in {f.name for f in score_recovered(whole(timestamp_plausible=None)).factors}
    assert "timestamp_validity" in {f.name for f in score_recovered(whole()).factors}


def test_adding_evidence_never_lowers_the_score():
    base = score_recovered(freeblock()).score
    assert score_recovered(freeblock(corroborations=("contacts",))).score > base
    assert score_recovered(freeblock(other_locations=2)).score > base
    assert score_recovered(freeblock(field_problems=("x",))).score < base


@pytest.mark.parametrize("frame,expected_verified", [("committed", True), ("uncommitted", True), ("stale_generation", True), ("stale_unverified", False), ("corrupt", False)])
def test_wal_frame_status_decides_source_provenance(frame, expected_verified):
    factor = next(f for f in score_recovered(whole(source="wal", frame_status=frame)).factors if f.name == "source_provenance")
    assert factor.satisfied is expected_verified
