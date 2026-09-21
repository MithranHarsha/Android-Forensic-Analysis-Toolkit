import json

import pytest
from pydantic import ValidationError

from android_forensics.models import (
    UNKNOWN,
    ApplicationSummary,
    Artifact,
    ArtifactStatus,
    ArtifactType,
    BrowserDownload,
    BrowserHistoryEntry,
    CallRecord,
    Confidence,
    Contact,
    ExtractionMethod,
    MessageDirection,
    PageTransition,
    RawKind,
    RawReference,
    SMSMessage,
    TransitionQualifier,
    artifact_adapter,
    artifact_class,
)
from tests.unit.models.factories import (
    factor,
    one_of_each_type,
    parser,
    physical,
    prov,
    raw_bytes,
    raw_row,
    recovered_sms,
    sms,
    ts,
)

ALL_CLASSES = [SMSMessage, CallRecord, Contact, BrowserHistoryEntry, BrowserDownload, ApplicationSummary]


# ------------------------------------------------------------------ the requested field set


REQUESTED = {"id", "artifact_type", "provenance", "extraction_method", "timestamp", "status", "confidence", "raw", "metadata"}


@pytest.mark.parametrize("cls", ALL_CLASSES)
def test_every_artifact_class_carries_the_requested_envelope(cls):
    assert REQUESTED <= set(cls.model_fields)
    assert {"source_file", "source_database", "source_table"} <= set(type(prov()).model_fields)


def test_artifact_types_map_one_to_one_onto_classes():
    assert {c.model_fields["artifact_type"].default for c in ALL_CLASSES} == set(ArtifactType)
    for cls in ALL_CLASSES:
        assert artifact_class(cls.model_fields["artifact_type"].default) is cls


def test_base_artifact_is_abstract():
    with pytest.raises(ValidationError, match="abstract"):
        Artifact(artifact_type=ArtifactType.SMS, provenance=prov(), raw=raw_row(), parser=parser())


@pytest.mark.parametrize("artifact", one_of_each_type(), ids=lambda a: type(a).__name__)
def test_review1_defaults_are_active_from_an_active_method(artifact):
    assert artifact.status is ArtifactStatus.ACTIVE
    assert artifact.extraction_method.is_active
    assert artifact.confidence is None and artifact.confidence_factors == []
    assert artifact.provenance.physical is None


def test_extraction_method_defaults_per_source():
    arts = {type(a).__name__: a for a in one_of_each_type()}
    assert arts["SMSMessage"].extraction_method is ExtractionMethod.ACTIVE_QUERY
    assert arts["ApplicationSummary"].extraction_method is ExtractionMethod.FILESYSTEM_METADATA
    assert arts["ApplicationSummary"].raw.kind is RawKind.INVENTORY


def test_artifact_type_is_fixed_by_the_class():
    with pytest.raises(ValidationError):
        SMSMessage(provenance=prov(), raw=raw_row(), parser=parser(), artifact_type=ArtifactType.CALL)


# ------------------------------------------------------------------ typed payloads


def test_payload_is_typed_coerced_and_forbids_typos():
    a = sms(direction="RECEIVED", read=True)
    assert a.direction is MessageDirection.RECEIVED
    with pytest.raises(ValidationError):
        sms(direction="SIDEWAYS")
    with pytest.raises(ValidationError):
        sms(adress="typo")
    with pytest.raises(ValidationError):
        sms(date_sent_utc="2024-03-01")


def test_payload_fields_exclude_the_envelope_and_dump_json_safely():
    a = sms(direction=MessageDirection.SENT, type_code=2)
    assert "address" in SMSMessage.payload_fields() and "status" not in SMSMessage.payload_fields()
    payload = a.payload()
    assert payload["direction"] == "SENT" and "provenance" not in payload
    json.dumps(payload)  # JSON-safe


def test_sms_status_column_does_not_collide_with_artifact_status():
    a = sms(delivery_status=-1)
    assert a.status is ArtifactStatus.ACTIVE and a.delivery_status == -1


def test_contact_payload_is_typed_and_deleted_flag_is_on_the_envelope():
    contact = next(a for a in one_of_each_type() if isinstance(a, Contact))
    assert contact.phones[0].phone_key == "2025550101" and contact.emails[0].address == "ann@example.com"
    assert contact.marked_deleted is True and contact.status is ArtifactStatus.ACTIVE, "flagged-deleted is not a recovery"
    assert "marked_deleted" not in Contact.payload_fields()


def test_browser_entry_enums_and_qualifiers():
    e = BrowserHistoryEntry(provenance=prov(), raw=raw_row(), parser=parser(), url="https://a", transition=PageTransition.TYPED,
                            transition_code=1 | 0x02000000, transition_qualifiers=[TransitionQualifier.FROM_ADDRESS_BAR])
    assert e.payload()["transition_qualifiers"] == ["FROM_ADDRESS_BAR"] and e.url_level_only is False


def test_unrecognised_codes_keep_the_raw_integer():
    a = CallRecord(provenance=prov(), raw=raw_row(), parser=parser(), type_code=42, call_type="UNRECOGNISED")
    assert a.type_code == 42 and a.call_type.value == "UNRECOGNISED"


# ------------------------------------------------------------------ UNKNOWN vs NULL


def test_build_separates_unknown_from_null():
    a = SMSMessage.build({"address": "+1", "body": None, "date_sent_utc": UNKNOWN, "service_center": UNKNOWN},
                         provenance=prov(), raw=raw_row(), parser=parser())
    assert a.body is None and a.date_sent_utc is None
    assert a.unknown_fields == ["date_sent_utc", "service_center"], "UNKNOWN is recorded; a stored NULL is not"


def test_unknown_fields_must_exist_and_be_unset_and_unique():
    kw = dict(provenance=prov(), raw=raw_row(), parser=parser())
    with pytest.raises(ValidationError, match="not a field of SMSMessage"):
        SMSMessage(unknown_fields=["nope"], **kw)
    with pytest.raises(ValidationError, match="marked UNKNOWN but holds a value"):
        SMSMessage(unknown_fields=["body"], body="present", **kw)
    with pytest.raises(ValidationError, match="duplicates"):
        SMSMessage(unknown_fields=["body", "body"], **kw)
    with pytest.raises(ValidationError, match="not a field"):
        SMSMessage(unknown_fields=["status"], **kw)  # an envelope field is never 'unknown'


def test_unknown_container_field_must_be_empty():
    kw = dict(provenance=prov(), raw=RawReference(kind=RawKind.INVENTORY, row={}), parser=parser(), package="p",
              file_count=1, total_bytes=1, database_count=0, sidecar_count=0)
    with pytest.raises(ValidationError, match="holds a value"):
        ApplicationSummary(unknown_fields=["shared_pref_keys"], shared_pref_keys={"f": ["k"]}, **kw)
    assert ApplicationSummary(unknown_fields=["shared_pref_keys"], **kw).unknown_fields == ["shared_pref_keys"]


# ------------------------------------------------------------------ immutability and evolution


def test_artifacts_are_immutable():
    a = sms()
    with pytest.raises(ValidationError):
        a.body = "changed"
    with pytest.raises(ValidationError):
        a.status = ArtifactStatus.RECOVERED


def test_evolve_returns_a_new_validated_artifact():
    a = sms()
    b = a.evolve(id=9, summary="s")
    assert a.id is None and b.id == 9 and b.summary == "s" and b.body == a.body and b is not a


def test_evolve_revalidates():
    with pytest.raises(ValidationError, match="RECOVERED artifact"):
        sms().evolve(status=ArtifactStatus.RECOVERED)


def test_carved_candidate_can_be_promoted_only_with_evidence_of_why():
    carved = recovered_sms(ArtifactStatus.CARVED, extraction_method=ExtractionMethod.CARVING, confidence=Confidence.LOW)
    promoted = carved.evolve(status=ArtifactStatus.RECOVERED, extraction_method=ExtractionMethod.FREELIST_PAGE,
                             confidence=Confidence.HIGH, confidence_factors=[factor("corroborated", "phone number is in contacts")])
    assert promoted.status is ArtifactStatus.RECOVERED and promoted.confidence is Confidence.HIGH
    assert carved.status is ArtifactStatus.CARVED, "the candidate itself is unchanged"


# ------------------------------------------------------------------ forensic invariants


def test_active_cannot_use_a_recovery_method_and_recovered_cannot_use_an_active_one():
    with pytest.raises(ValidationError, match="ACTIVE artifact cannot use recovery method WAL_FRAME"):
        sms(extraction_method=ExtractionMethod.WAL_FRAME)
    with pytest.raises(ValidationError, match="cannot use active method ACTIVE_QUERY"):
        recovered_sms(extraction_method=ExtractionMethod.ACTIVE_QUERY)


def test_active_artifact_must_reference_a_row_not_bytes():
    with pytest.raises(ValidationError, match="must reference a row"):
        sms(raw=raw_bytes())


@pytest.mark.parametrize("status", [s for s in ArtifactStatus if s is not ArtifactStatus.ACTIVE])
def test_recovery_states_must_preserve_raw_bytes(status):
    with pytest.raises(ValidationError, match="raw bytes it was reconstructed from"):
        recovered_sms(status, raw=raw_row(), validation_notes=["x"])


@pytest.mark.parametrize("status", [s for s in ArtifactStatus if s is not ArtifactStatus.ACTIVE])
def test_recovery_states_require_a_physical_location(status):
    with pytest.raises(ValidationError, match="physical location"):
        recovered_sms(status, provenance=prov(source_rowid=None), validation_notes=["x"])


@pytest.mark.parametrize("status", [ArtifactStatus.RECOVERED, ArtifactStatus.PARTIAL, ArtifactStatus.CARVED, ArtifactStatus.CORRUPTED])
def test_asserting_states_require_confidence_and_its_explanation(status):
    with pytest.raises(ValidationError, match="requires a confidence level"):
        recovered_sms(status, confidence=None)
    with pytest.raises(ValidationError, match="requires confidence_factors"):
        recovered_sms(status, confidence_factors=[])


def test_a_carved_candidate_is_never_high_confidence():
    with pytest.raises(ValidationError, match="CARVED candidate cannot be HIGH"):
        recovered_sms(ArtifactStatus.CARVED, confidence=Confidence.HIGH)
    for level in (Confidence.LOW, Confidence.MEDIUM):
        assert recovered_sms(ArtifactStatus.CARVED, confidence=level).confidence is level


def test_invalid_artifacts_must_say_why():
    with pytest.raises(ValidationError, match="validation_notes"):
        recovered_sms(ArtifactStatus.INVALID, confidence=None, confidence_factors=[])
    a = recovered_sms(ArtifactStatus.INVALID, confidence=None, confidence_factors=[],
                      validation_notes=["serial type 5 in TEXT column 'address'"])
    assert a.status is ArtifactStatus.INVALID


@pytest.mark.parametrize("status", list(ArtifactStatus))
def test_every_status_is_representable(status):
    """The whole point of the model design: Review 2 needs no model change to emit any of these."""
    if status is ArtifactStatus.ACTIVE:
        art = sms()
    else:
        extras = {"validation_notes": ["rejected by schema check"]} if status is ArtifactStatus.INVALID else {}
        if status in (ArtifactStatus.INVALID, ArtifactStatus.UNRECOVERABLE):
            extras |= dict(confidence=None, confidence_factors=[])
        art = recovered_sms(status, **extras)
    assert art.status is status
    assert Artifact.from_record(art.to_record()) == art


def test_partial_recovery_marks_lost_columns_unknown():
    a = SMSMessage.build({"address": UNKNOWN, "body": "half a message", "date_sent_utc": UNKNOWN},
                         status=ArtifactStatus.PARTIAL, extraction_method=ExtractionMethod.FREEBLOCK,
                         confidence=Confidence.LOW, confidence_factors=[factor("record_header", "header intact, first columns overwritten")],
                         provenance=prov(physical=physical(region="freeblock")), raw=raw_bytes(), parser=parser())
    assert a.unknown_fields == ["address", "date_sent_utc"] and a.body == "half a message"


def test_recovered_provenance_can_name_a_sidecar_as_its_source_file():
    a = recovered_sms(extraction_method=ExtractionMethod.WAL_FRAME, raw=RawReference(kind=RawKind.WAL_FRAME, raw_bytes_hex="ff00"),
                      provenance=prov(source_file="x/mmssms.db-wal", source_sha256="cd" * 32, source_rowid=None, physical=physical(region="wal_frame")))
    assert a.provenance.source_file.endswith("-wal") and a.provenance.source_database.endswith("mmssms.db")


def test_active_artifact_may_also_carry_a_physical_location():
    a = sms(provenance=prov(physical=physical()))
    assert a.provenance.physical.page_number == 12 and a.status is ArtifactStatus.ACTIVE


# ------------------------------------------------------------------ persistence round trip


@pytest.mark.parametrize("artifact", one_of_each_type(), ids=lambda a: type(a).__name__)
def test_record_round_trip_preserves_every_artifact_type(artifact):
    record = artifact.to_record()
    restored = Artifact.from_record(record)
    assert type(restored) is type(artifact) and restored == artifact


def test_record_columns_are_flat_json_safe_scalars():
    for a in one_of_each_type():
        for column, value in a.to_record().items():
            assert value is None or isinstance(value, (str, int, float)), f"{column} is {type(value).__name__}"


def test_record_round_trip_keeps_timestamp_raw_types_and_recovery_details():
    for raw in (1709280000000, 1.5, "garbage", None):
        a = sms(timestamp=ts(raw=raw, utc="2024-03-01T08:00:00.000Z"))
        assert Artifact.from_record(a.to_record()).timestamp.raw == raw
    rec = recovered_sms(unknown_fields=["subject"], flags=["f"], metadata={"k": [1, 2]}, validation_notes=["n"],
                        provenance=prov(physical=physical(), source_rowid=None))
    back = Artifact.from_record(rec.to_record())
    assert back == rec and back.provenance.physical == physical() and back.raw.raw_bytes_hex == "0a1b2c3d"
    assert back.confidence_factors[0].explanation == "record matches the sms schema"


def test_round_trip_carries_database_identity_columns():
    record = sms().to_record()
    assert record["source_file"] == record["source_database"] and record["extraction_method"] == "ACTIVE_QUERY"
    assert record["status"] == "ACTIVE" and record["raw_kind"] == "sqlite_row" and len(record["raw_sha256"]) == 64
    assert record["page_number"] is None and record["byte_offset"] is None and record["confidence"] is None


def test_raw_digest_binds_the_artifact_to_its_row():
    a = sms()
    tampered = dict(a.to_record(), raw_row_json=json.dumps({"_id": 5, "address": "+1", "body": "EDITED"}))
    with pytest.raises(ValidationError, match="digest mismatch"):
        Artifact.from_record(tampered)


def test_from_record_rejects_unknown_types_and_invalid_combinations():
    record = sms().to_record()
    with pytest.raises(ValidationError):
        Artifact.from_record(dict(record, artifact_type="voicemail"))
    with pytest.raises(ValidationError, match="RECOVERED artifact"):
        Artifact.from_record(dict(record, status="RECOVERED"))


# ------------------------------------------------------------------ polymorphic adapter


@pytest.mark.parametrize("artifact", one_of_each_type(), ids=lambda a: type(a).__name__)
def test_adapter_selects_the_subclass_from_json(artifact):
    restored = artifact_adapter().validate_json(artifact.model_dump_json())
    assert type(restored) is type(artifact) and restored == artifact


def test_adapter_rejects_an_unknown_discriminator():
    data = json.loads(sms().model_dump_json())
    data["artifact_type"] = "nonsense"
    with pytest.raises(ValidationError):
        artifact_adapter().validate_python(data)
