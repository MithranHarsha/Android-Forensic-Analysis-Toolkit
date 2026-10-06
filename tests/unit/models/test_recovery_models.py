"""Review 2 evidence models: what they refuse is as important as what they hold."""

import hashlib

import pytest
from pydantic import ValidationError

from android_forensics.models import (
    CARVED_CANDIDATE,
    ArtifactStatus,
    CarvedCandidate,
    CarveKind,
    Confidence,
    ConfidenceAssessment,
    ConfidenceFactor,
    CorrelationEdge,
    EntityKind,
    ExtractionMethod,
    RecoveredRecord,
    Relation,
    UnrecoveredRegion,
)

SHA = "ab" * 32
RAW = b"\x25\x05\x09hello"


def record(**kw):
    base = dict(
        database_file_id=1, source="main", source_file_id=1, source_path="/case/evidence/s1/sms.db", source_sha256=SHA, table="sms",
        values={"address": "+1202", "body": "hi"}, unknown_columns=["_id"], status=ArtifactStatus.PARTIAL, method=ExtractionMethod.FREEBLOCK,
        page_number=4, page_offset=426, file_offset=3 * 4096 + 426, length=len(RAW), region="freeblock", raw_hex=RAW.hex(), fit=1.0)
    return RecoveredRecord(**(base | kw))


def factor(name="schema_match", ok=True):
    return ConfidenceFactor(name=name, satisfied=ok, weight=1.0, explanation=f"{name} explained")


class TestRecoveredRecord:
    def test_the_raw_bytes_are_bound_to_their_digest(self):
        r = record()
        assert r.raw == RAW and r.raw_sha256 == hashlib.sha256(RAW).hexdigest()
        with pytest.raises(ValidationError, match="does not match the raw bytes"):
            record(raw_sha256="00" * 32)

    def test_length_must_match_the_bytes(self):
        with pytest.raises(ValidationError, match="length"):
            record(length=len(RAW) + 1)

    @pytest.mark.parametrize("status", [ArtifactStatus.ACTIVE, ArtifactStatus.CARVED, ArtifactStatus.UNRECOVERABLE, ArtifactStatus.INVALID])
    def test_only_recovery_statuses_are_allowed(self, status):
        with pytest.raises(ValidationError, match="RECOVERED, PARTIAL or CORRUPTED"):
            record(status=status)

    @pytest.mark.parametrize("method", [ExtractionMethod.ACTIVE_QUERY, ExtractionMethod.FILESYSTEM_METADATA, ExtractionMethod.CARVING])
    def test_the_method_must_be_a_page_level_recovery_method(self, method):
        with pytest.raises(ValidationError, match="not a page-level recovery method"):
            record(method=method)

    def test_a_record_from_a_sidecar_says_so(self):
        with pytest.raises(ValidationError, match="sidecar"):
            record(source="wal")
        assert record(source="wal", method=ExtractionMethod.WAL_FRAME, frame=3).frame == 3

    def test_a_column_cannot_be_both_known_and_unknown(self):
        with pytest.raises(ValidationError, match="both known and unknown"):
            record(unknown_columns=["body"])

    def test_recovered_means_complete(self):
        with pytest.raises(ValidationError, match="that is what PARTIAL is for"):
            record(status=ArtifactStatus.RECOVERED)
        assert record(status=ArtifactStatus.RECOVERED, unknown_columns=[]).status is ArtifactStatus.RECOVERED

    def test_locations_are_validated(self):
        for bad in (dict(page_number=0), dict(page_offset=-1), dict(file_offset=-1)):
            with pytest.raises(ValidationError):
                record(**bad)

    def test_json_round_trip_and_immutability(self):
        r = record()
        assert RecoveredRecord.model_validate_json(r.model_dump_json()) == r
        with pytest.raises(ValidationError):
            r.status = ArtifactStatus.RECOVERED


def test_an_unrecovered_region_carries_its_reason():
    u = UnrecoveredRegion(source="main", source_path="/x/sms.db", page_number=3, page_offset=100, file_offset=8292, length=60,
                          region="freeblock", reason="zero-filled", raw_sha256=SHA)
    assert UnrecoveredRegion.model_validate_json(u.model_dump_json()) == u
    with pytest.raises(ValidationError):
        UnrecoveredRegion(**{**u.model_dump(), "reason": "  "})


class TestCarvedCandidate:
    def make(self, **kw):
        base = dict(evidence_file_id=2, source_file="/x/blob.bin", source_sha256=SHA, offset=512, length=12, kind=CarveKind.PHONE_NUMBER,
                    pattern="e164", matched="+12025550101")
        return CarvedCandidate(**(base | kw))

    def test_a_carved_hit_is_a_candidate_never_evidence(self):
        c = self.make()
        assert c.status == CARVED_CANDIDATE == "CARVED CANDIDATE" and c.extraction_method is ExtractionMethod.CARVING and c.confidence is None
        with pytest.raises(ValidationError):
            self.make(status="RECOVERED")
        with pytest.raises(ValidationError):
            self.make(extraction_method=ExtractionMethod.FREEBLOCK)

    def test_it_can_never_be_high_confidence(self):
        with pytest.raises(ValidationError, match="never be HIGH"):
            self.make(confidence=Confidence.HIGH, confidence_factors=[factor()])
        assert self.make(confidence=Confidence.MEDIUM, confidence_factors=[factor()]).confidence is Confidence.MEDIUM

    def test_a_scored_candidate_must_say_why(self):
        with pytest.raises(ValidationError, match="factors"):
            self.make(confidence=Confidence.LOW)

    def test_round_trip(self):
        c = self.make(context_before_hex="00ff", corroborated_by=[3, 9])
        assert CarvedCandidate.model_validate_json(c.model_dump_json()) == c

    def test_offsets_and_hex_are_validated(self):
        for bad in (dict(offset=-1), dict(length=0), dict(context_after_hex="xyz")):
            with pytest.raises(ValidationError):
                self.make(**bad)


class TestCorrelationEdge:
    def edge(self, **kw):
        base = dict(source_kind=EntityKind.PHONE_NUMBER, source_ref="phone:2025550101", target_kind=EntityKind.CONTACT,
                    target_ref="artifact:7", relation=Relation.CONTACT_OF, explanation="the number belongs to contact 7")
        return CorrelationEdge(**(base | kw))

    def test_an_edge_links_two_different_entities(self):
        e = self.edge()
        assert e.strength == 1.0 and CorrelationEdge.model_validate_json(e.model_dump_json()) == e
        with pytest.raises(ValidationError, match="itself"):
            self.edge(target_kind=EntityKind.PHONE_NUMBER, target_ref="phone:2025550101")

    def test_strength_and_explanation_are_constrained(self):
        with pytest.raises(ValidationError):
            self.edge(strength=1.5)
        with pytest.raises(ValidationError):
            self.edge(explanation=" ")

    def test_every_relation_of_the_spec_exists(self):
        assert {r.value for r in Relation} == {"SENT", "RECEIVED", "CALLED", "CONTACT_OF", "FOUND_IN", "RECOVERED_FROM", "CORRELATES_WITH"}
        assert {"person", "phone_number", "message", "call", "contact", "application", "database", "file", "timestamp", "url"} <= {k.value for k in EntityKind}


class TestConfidenceAssessment:
    def test_the_explanation_names_its_level(self):
        a = ConfidenceAssessment(level=Confidence.HIGH, score=0.95, factors=[factor()], explanation="HIGH: an untouched cell with a schema match")
        assert ConfidenceAssessment.model_validate_json(a.model_dump_json()) == a
        with pytest.raises(ValidationError, match="begin with the level"):
            ConfidenceAssessment(level=Confidence.HIGH, score=0.9, factors=[factor()], explanation="MEDIUM: something else")

    def test_at_least_one_factor_is_required(self):
        with pytest.raises(ValidationError):
            ConfidenceAssessment(level=Confidence.LOW, score=0.1, factors=[], explanation="LOW: nothing")
