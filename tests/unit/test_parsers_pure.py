"""Parsers must work on plain rows (no sqlite3 cursor): this is the seam Review 2 recovery plugs into."""

from datetime import datetime, timezone

from android_forensics.artifacts.base import DbContext, RowSource
from android_forensics.artifacts.browser import BrowserParser, decode_transition
from android_forensics.artifacts.calls import CallsParser
from android_forensics.artifacts.contacts import ContactsParser
from android_forensics.artifacts.schema_probe import RoleMatch, SchemaMatch
from android_forensics.artifacts.sms import SmsParser
from android_forensics.models import (
    UNKNOWN,
    AddressKind,
    ArtifactStatus,
    BrowserDownload,
    BrowserHistoryEntry,
    CallPresentation,
    CallRecord,
    CallType,
    Contact,
    DownloadState,
    ExtractionMethod,
    MessageDirection,
    PageTransition,
    RawKind,
    SMSMessage,
    TransitionQualifier,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
DB = "data/data/x/databases/a.db"
CTX = DbContext(1, 1, DB, "ab" * 32, "x", False, now=NOW)


def match(variant="v", **roles):
    return SchemaMatch("p", variant, {k: RoleMatch(k, {}, 1.0) for k in roles} or {"main": RoleMatch("t", {}, 1.0)}, 1.0)


def row(values, table="t", rowid=1):
    return RowSource(values=values, raw=dict(values), table=table, rowid=rowid)


def test_sms_full_row():
    a = SmsParser().from_row(
        row({"address": "+12025550123", "body": "hi", "date": 1709280000000, "type": 1, "read": 1, "thread_id": 4,
             "date_sent": 1709279999000, "service_center": "+1", "sub_id": 1}, "sms", 9),
        match("aosp_sms"), CTX)
    assert isinstance(a, SMSMessage)
    assert a.direction is MessageDirection.RECEIVED and a.read is True and a.address_kind is AddressKind.PHONE
    assert a.timestamp.utc == "2024-03-01T08:00:00.000Z" and a.date_sent_utc == "2024-03-01T07:59:59.000Z"
    assert a.phone_key == "2025550123"
    assert a.status is ArtifactStatus.ACTIVE and a.confidence is None and a.extraction_method is ExtractionMethod.ACTIVE_QUERY


def test_active_row_provenance_is_complete_and_logical():
    a = SmsParser().from_row(row({"address": "+1", "body": "x", "date": 1709280000000}, "sms", 9), match("aosp_sms"), CTX)
    p = a.provenance
    assert (p.source_file, p.source_database, p.source_table, p.source_rowid) == (DB, DB, "sms", 9)
    assert p.source_sha256 == "ab" * 32 and p.evidence_file_id == 1 and p.view_includes_wal is False
    assert p.physical is None, "page/offset provenance is Review 2"
    assert a.raw.kind is RawKind.SQLITE_ROW and a.raw.row["body"] == "x" and len(a.raw.sha256) == 64
    assert a.parser.name == "p" or a.parser.schema_variant == "aosp_sms"


def test_sms_missing_columns_become_unknown_not_guessed():
    a = SmsParser().from_row(row({"address": "AX-BANK", "body": "otp", "date": 1709280000000}), match(), CTX)
    assert {"type_code", "read", "thread_id", "date_sent_utc", "service_center"} <= set(a.unknown_fields)
    assert a.direction is None  # UNKNOWN is stored as absent, never a default like RECEIVED
    assert a.phone_key is None and a.address_kind is AddressKind.ALPHANUMERIC


def test_sms_type_violations_are_flagged_not_coerced():
    a = SmsParser().from_row(row({"address": "1", "body": b"blob", "date": "yesterday", "type": 99, "read": 7}), match(), CTX)
    joined = " | ".join(a.flags)
    assert "expected text, found bytes" in joined and "unknown_type_code:99" in joined and "expected 0/1" in joined
    assert a.direction is MessageDirection.UNRECOGNISED and a.type_code == 99, "the raw code survives an unmapped value"
    assert a.timestamp.utc is None and a.body is None


def test_date_sent_zero_is_unset():
    a = SmsParser().from_row(row({"address": "+12025550123", "body": "x", "date": 1709280000000, "date_sent": 0}), match(), CTX)
    assert a.date_sent_utc is None and a.date_sent_raw == 0


def test_call_row_and_private_number():
    a = CallsParser().from_row(row({"number": "", "date": 1709280000000, "duration": 12, "type": 3, "presentation": 2}), match(), CTX)
    assert isinstance(a, CallRecord)
    assert a.call_type is CallType.MISSED and a.presentation is CallPresentation.RESTRICTED
    assert a.phone_key is None and "private/unknown" in a.summary
    b = CallsParser().from_row(row({"number": "+1 202 555 0100", "date": 1709280000000, "duration": -3, "type": 2}), match(), CTX)
    assert "invalid_duration:-3" in b.flags and b.call_type is CallType.OUTGOING and b.duration_seconds == -3


def test_contact_marked_deleted_stays_active_with_flag():
    v = {"id": 5, "display_name": "Ann Lee", "deleted": 1, "phones": [{"number": "(202) 555-0101", "label": "MOBILE"}],
         "emails": [{"address": "a@example.com"}], "updated": 1709280000000}
    a = ContactsParser().from_row(row(v, "raw_contacts", 5), match("aosp_contacts2"), CTX)
    assert isinstance(a, Contact)
    assert a.status is ArtifactStatus.ACTIVE and a.marked_deleted is True
    assert a.phone_key == "2025550101" and a.timestamp.utc == "2024-03-01T08:00:00.000Z"
    assert a.phones[0].number == "(202) 555-0101" and a.phones[0].phone_key == "2025550101" and a.phones[0].label == "MOBILE"
    assert a.emails[0].address == "a@example.com" and "flagged deleted" in a.summary


def test_contact_without_timestamp_or_phone():
    a = ContactsParser().from_row(row({"id": 1, "display_name": "Solo", "phones": [], "emails": []}), match(), CTX)
    assert a.timestamp is None and a.phone_key is None and a.phones == []


def test_browser_visit_and_dangling_reference():
    v = {"_kind": "visit", "id": 3, "url": "https://e.example/", "title": "E", "visit_time": 13353755292947000,
         "transition": 1 | 0x02000000 | 0x10000000, "visit_duration": 5, "visit_count": 2}
    a = BrowserParser().from_row(row(v, "visits", 3), match("chromium_history"), CTX)
    assert isinstance(a, BrowserHistoryEntry)
    assert a.timestamp.utc == "2024-03-01T08:28:12.947Z" and a.transition is PageTransition.TYPED
    assert a.transition_code == v["transition"]
    assert a.transition_qualifiers == [TransitionQualifier.FROM_ADDRESS_BAR, TransitionQualifier.CHAIN_START]
    dangling = dict(v, url=UNKNOWN, _dangling=True)
    d = BrowserParser().from_row(row(dangling, "visits", 4), match("chromium_history"), CTX)
    assert "url" in d.unknown_fields and any("dangling_url_reference" in f for f in d.flags)


def test_url_level_entry_has_no_visit_specific_fields():
    a = BrowserParser().from_row(row({"_kind": "url", "id": 7, "url": "https://x/", "last_visit_time": 0}, "urls", 7), match("chromium_history"), CTX)
    assert a.url_level_only is True and a.timestamp.utc is None
    assert {"visit_id", "transition", "transition_code"} <= set(a.unknown_fields)


def test_transition_decoder_unknown_core():
    assert decode_transition(0)[0] is PageTransition.LINK and decode_transition(8)[0] is PageTransition.RELOAD
    assert decode_transition(200)[0] is PageTransition.UNRECOGNISED


def test_download_state_mapping():
    v = {"_kind": "download", "id": 1, "target_path": "/sdcard/Download/a.pdf", "start_time": 13353755292947000,
         "total_bytes": 10, "state": 1, "end_time": 13353755297947000}
    a = BrowserParser().from_row(row(v, "downloads", 1), match("chromium_history"), CTX)
    assert isinstance(a, BrowserDownload)
    assert a.download_state is DownloadState.COMPLETE and a.download_state_code == 1
    assert a.end_time_utc == "2024-03-01T08:28:17.947Z"


def test_every_parser_output_satisfies_the_artifact_invariants():
    """Constructing the models already enforces them; this documents that parsers only ever emit ACTIVE artifacts."""
    outputs = [
        SmsParser().from_row(row({"address": "+1", "body": "x", "date": 1}), match(), CTX),
        CallsParser().from_row(row({"number": "1", "date": 1, "duration": 0, "type": 1}), match(), CTX),
        ContactsParser().from_row(row({"id": 1, "display_name": "A", "phones": [], "emails": []}), match(), CTX),
        BrowserParser().from_row(row({"_kind": "legacy", "url": "u", "date": 1}), match(), CTX),
    ]
    assert all(o.status is ArtifactStatus.ACTIVE and o.extraction_method.is_active and o.provenance.physical is None for o in outputs)
