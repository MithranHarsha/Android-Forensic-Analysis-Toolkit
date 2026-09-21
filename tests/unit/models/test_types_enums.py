import hashlib

import pytest
from pydantic import BaseModel, ValidationError

from android_forensics.models import (
    ArtifactStatus,
    ArtifactType,
    CallPresentation,
    CallType,
    Confidence,
    DownloadState,
    ExtractionMethod,
    FileKind,
    MessageDirection,
    PageTransition,
    RawKind,
    TransitionQualifier,
    ValidationCheck,
)
from android_forensics.models.enums import STATUSES_PRODUCED_IN_REVIEW_1
from android_forensics.models.types import IsoInput, Md5Hex, Sha1Hex, Sha256Hex, UtcIso, canonical_json, normalize_iso_utc


class Holder(BaseModel):
    sha256: Sha256Hex | None = None
    sha1: Sha1Hex | None = None
    md5: Md5Hex | None = None
    utc: UtcIso | None = None
    lenient: IsoInput | None = None


@pytest.mark.parametrize("field,good", [("sha256", "a" * 64), ("sha1", "0" * 40), ("md5", "f" * 32)])
def test_hash_types_accept_lowercase_hex_of_exact_length(field, good):
    assert getattr(Holder(**{field: good}), field) == good


@pytest.mark.parametrize("field,bad", [
    ("sha256", "A" * 64), ("sha256", "a" * 63), ("sha256", "g" * 64), ("sha1", "a" * 64), ("md5", "a" * 31), ("md5", ""),
])
def test_hash_types_reject_malformed_values(field, bad):
    with pytest.raises(ValidationError):
        Holder(**{field: bad})


def test_utc_iso_is_strictly_the_canonical_form():
    assert Holder(utc="2024-03-01T08:00:00.000Z").utc == "2024-03-01T08:00:00.000Z"
    for bad in ("2024-03-01T08:00:00Z", "2024-03-01 08:00:00.000Z", "2024-03-01T08:00:00.000+00:00", "yesterday"):
        with pytest.raises(ValidationError):
            Holder(utc=bad)


@pytest.mark.parametrize("given,expected", [
    ("2024-06-04T08:00:00Z", "2024-06-04T08:00:00.000Z"),
    ("2024-06-04T13:30:00+05:30", "2024-06-04T08:00:00.000Z"),
    ("2024-06-04T08:00:00.123456+00:00", "2024-06-04T08:00:00.123Z"),
    ("2024-06-04T08:00:00.000Z", "2024-06-04T08:00:00.000Z"),
])
def test_iso_input_normalises_to_canonical_utc(given, expected):
    assert normalize_iso_utc(given) == expected
    assert Holder(lenient=given).lenient == expected


@pytest.mark.parametrize("bad", ["2024-06-04T08:00:00", "2024-06-04", "not a date", ""])
def test_iso_input_rejects_ambiguous_or_garbage(bad):
    with pytest.raises(ValidationError):
        Holder(lenient=bad)


def test_canonical_json_is_order_independent_and_unicode_safe():
    assert canonical_json({"b": 1, "a": [2, {"d": 1, "c": 2}]}) == canonical_json({"a": [2, {"c": 2, "d": 1}], "b": 1})
    assert canonical_json({"k": "é日本"}) == '{"k":"é日本"}'
    assert hashlib.sha256(canonical_json({"a": 1}).encode()).hexdigest() == hashlib.sha256(b'{"a":1}').hexdigest()


# ------------------------------------------------------------------ status vocabulary


def test_status_enum_contains_every_state_the_recovery_design_needs():
    required = {"ACTIVE", "RECOVERED", "PARTIAL", "CARVED", "INVALID"}  # the states named in the requirements
    original_spec = {"CORRUPTED", "UNRECOVERABLE"}  # the states named in the project specification
    assert required | original_spec <= {s.value for s in ArtifactStatus}


def test_review1_produces_only_active():
    assert STATUSES_PRODUCED_IN_REVIEW_1 == {ArtifactStatus.ACTIVE}
    assert ArtifactStatus.ACTIVE.is_active and not ArtifactStatus.ACTIVE.is_recovery_state


@pytest.mark.parametrize("status", [s for s in ArtifactStatus if s is not ArtifactStatus.ACTIVE])
def test_every_non_active_status_is_a_recovery_state(status):
    assert status.is_recovery_state and not status.is_active


def test_confidence_is_required_exactly_where_a_record_is_asserted():
    needs = {s for s in ArtifactStatus if s.requires_confidence}
    assert needs == {ArtifactStatus.RECOVERED, ArtifactStatus.PARTIAL, ArtifactStatus.CARVED, ArtifactStatus.CORRUPTED}
    assert ArtifactStatus.CARVED.is_candidate and not ArtifactStatus.RECOVERED.is_candidate


def test_confidence_ranks_order_high_above_low():
    assert Confidence.HIGH.rank > Confidence.MEDIUM.rank > Confidence.LOW.rank


def test_extraction_methods_split_into_active_and_recovery():
    active = {m for m in ExtractionMethod if m.is_active}
    assert active == {ExtractionMethod.ACTIVE_QUERY, ExtractionMethod.FILESYSTEM_METADATA}
    assert {ExtractionMethod.FREELIST_PAGE, ExtractionMethod.WAL_FRAME, ExtractionMethod.CARVING} <= set(ExtractionMethod) - active


def test_raw_kinds_split_into_rows_and_bytes():
    assert {k for k in RawKind if not k.is_bytes} == {RawKind.SQLITE_ROW, RawKind.INVENTORY}


def test_string_enums_compare_equal_to_their_values():
    assert ArtifactStatus.ACTIVE == "ACTIVE" and ArtifactType.SMS == "sms" and CallType.MISSED == "MISSED"


def test_validation_checks_are_the_fourteen_documented_checks():
    assert len(ValidationCheck) == 14 and ValidationCheck("hash_consistency") is ValidationCheck.HASH_CONSISTENCY


def test_file_kind_sqlite_family():
    assert {k for k in FileKind if k.is_sqlite_family} == {
        FileKind.SQLITE_DB, FileKind.SQLITE_WAL, FileKind.SQLITE_SHM, FileKind.SQLITE_JOURNAL}


# ------------------------------------------------------------------ Android code tables


@pytest.mark.parametrize("code,expected", [
    (1, "RECEIVED"), (2, "SENT"), (3, "DRAFT"), (4, "OUTBOX"), (5, "FAILED"), (6, "QUEUED"), (99, "UNRECOGNISED"), (0, "UNRECOGNISED")])
def test_message_direction_codes(code, expected):
    assert MessageDirection.from_code(code) == expected


@pytest.mark.parametrize("code,expected", [
    (1, "INCOMING"), (2, "OUTGOING"), (3, "MISSED"), (4, "VOICEMAIL"), (5, "REJECTED"), (6, "BLOCKED"),
    (7, "ANSWERED_EXTERNALLY"), (42, "UNRECOGNISED")])
def test_call_type_codes(code, expected):
    assert CallType.from_code(code) == expected


def test_call_presentation_keeps_androids_own_unknown_distinct_from_unmapped():
    assert CallPresentation.from_code(3) is CallPresentation.UNKNOWN
    assert CallPresentation.from_code(9) is CallPresentation.UNRECOGNISED
    assert CallPresentation.from_code(2) is CallPresentation.RESTRICTED


def test_none_code_means_no_value_not_unrecognised():
    for enum in (MessageDirection, CallType, CallPresentation, PageTransition, DownloadState):
        assert enum.from_code(None) is None


def test_unanswered_call_types():
    assert {t for t in CallType if t.is_unanswered} == {CallType.MISSED, CallType.REJECTED, CallType.BLOCKED}


def test_transition_masks_qualifier_bits_and_decodes_flags():
    code = 1 | 0x02000000 | 0x10000000
    assert PageTransition.from_code(code) is PageTransition.TYPED
    assert TransitionQualifier.from_flags(code) == [TransitionQualifier.FROM_ADDRESS_BAR, TransitionQualifier.CHAIN_START]
    assert PageTransition.from_code(0) is PageTransition.LINK and TransitionQualifier.from_flags(0) == []
    assert PageTransition.from_code(200) is PageTransition.UNRECOGNISED
    assert TransitionQualifier.from_flags(0x80000000) == [TransitionQualifier.SERVER_REDIRECT]


@pytest.mark.parametrize("code,expected", [(0, "IN_PROGRESS"), (1, "COMPLETE"), (2, "CANCELLED"), (3, "INTERRUPTED"), (7, "UNRECOGNISED")])
def test_download_state_codes(code, expected):
    assert DownloadState.from_code(code) == expected
