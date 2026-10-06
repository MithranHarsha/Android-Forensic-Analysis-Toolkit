"""Builders for valid model instances, so each test states only what it is about."""

from __future__ import annotations

from typing import Any

from android_forensics.models import (
    ApplicationSummary,
    ArtifactStatus,
    BrowserDownload,
    BrowserHistoryEntry,
    CallRecord,
    Confidence,
    ConfidenceFactor,
    Contact,
    ContactEmail,
    ContactPhone,
    ExtractionMethod,
    GenericRecord,
    ParserInfo,
    PhysicalLocation,
    Provenance,
    RawKind,
    RawReference,
    SMSMessage,
    TimestampFormat,
    TimestampInfo,
)

SHA = "ab" * 32
DB_PATH = "data/data/com.android.providers.telephony/databases/mmssms.db"


def prov(**kw: Any) -> Provenance:
    base = dict(evidence_file_id=1, source_file=DB_PATH, source_sha256=SHA, source_database=DB_PATH,
                source_table="sms", source_rowid=5, view_includes_wal=False)
    return Provenance(**(base | kw))


def raw_row(**row: Any) -> RawReference:
    return RawReference(row=row or {"_id": 5, "address": "+12025550123", "body": "hi"})


def raw_bytes(hex_: str = "0a1b2c3d") -> RawReference:
    return RawReference(kind=RawKind.PAGE_BYTES, raw_bytes_hex=hex_)


def parser(**kw: Any) -> ParserInfo:
    return ParserInfo(**(dict(name="sms", version="1.0", schema_variant="aosp_sms", schema_match_score=1.0) | kw))


def ts(**kw: Any) -> TimestampInfo:
    return TimestampInfo(**(dict(raw=1709280000000, format=TimestampFormat.UNIX_MS,
                                 utc="2024-03-01T08:00:00.000Z", plausible=True) | kw))


def factor(name: str = "schema_match", explanation: str = "record matches the sms schema") -> ConfidenceFactor:
    return ConfidenceFactor(name=name, satisfied=True, weight=1.0, explanation=explanation)


def physical(**kw: Any) -> PhysicalLocation:
    return PhysicalLocation(**(dict(page_number=12, cell_index=5, byte_offset=0xA42F, page_type="leaf_table", region="freeblock") | kw))


def sms(**kw: Any) -> SMSMessage:
    base: dict[str, Any] = dict(provenance=prov(), raw=raw_row(), parser=parser(), timestamp=ts(),
                                address="+12025550123", body="hi", phone_key="2025550123")
    return SMSMessage(**(base | kw))


def recovered_sms(status: ArtifactStatus = ArtifactStatus.RECOVERED, **kw: Any) -> SMSMessage:
    """A structurally valid non-ACTIVE SMS, as the Review 2 engine would emit it."""
    base: dict[str, Any] = dict(
        status=status, extraction_method=ExtractionMethod.FREELIST_PAGE, confidence=Confidence.MEDIUM,
        confidence_factors=[factor()], provenance=prov(physical=physical(), source_rowid=None),
        raw=raw_bytes(), parser=parser(), address="+12025550123", body="recovered")
    return SMSMessage(**(base | kw))


def one_of_each_type() -> list[Any]:
    """One valid ACTIVE artifact per concrete artifact class."""
    call = CallRecord(provenance=prov(source_table="calls"), raw=raw_row(number="+1"), parser=parser(name="calls"),
                      number="+12025550101", duration_seconds=30, type_code=1, timestamp=ts(), phone_key="2025550101")
    contact = Contact(provenance=prov(source_table="raw_contacts"), raw=raw_row(_id=1), parser=parser(name="contacts"),
                      display_name="Ann Lee", phones=[ContactPhone(number="(202) 555-0101", label="MOBILE", primary=True,
                                                                   number_normalized="2025550101", phone_key="2025550101")],
                      emails=[ContactEmail(address="ann@example.com", label="HOME")], phone_key="2025550101",
                      marked_deleted=True, timestamp=ts())
    visit = BrowserHistoryEntry(provenance=prov(source_table="visits"), raw=raw_row(id=1), parser=parser(name="browser"),
                                url="https://example.org/", title="Example", transition_code=1, timestamp=ts(format=TimestampFormat.WEBKIT_US))
    dl = BrowserDownload(provenance=prov(source_table="downloads"), raw=raw_row(id=1), parser=parser(name="browser"),
                         target_path="/sdcard/Download/a.pdf", total_bytes=10, download_state_code=1)
    app = ApplicationSummary(provenance=prov(source_table=None, source_rowid=None, source_database=None),
                             raw=RawReference(kind=RawKind.INVENTORY, row={"member_count": 3}),
                             parser=parser(name="app_data"), package="com.example.app", file_count=3, total_bytes=100,
                             database_count=1, sidecar_count=0)
    generic = GenericRecord(provenance=prov(source_table="notes", source_rowid=3), raw=raw_row(_id=3, title="t"), parser=parser(name="generic"),
                            table="notes", columns={"_id": 3, "title": "t"})
    return [sms(), call, contact, visit, dl, app, generic]
