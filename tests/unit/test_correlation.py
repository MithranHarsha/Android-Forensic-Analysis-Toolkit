"""Phase 7: the evidence graph. One number in three sources is one PhoneNumber; a recovered SMS is linked to, and corroborated by,
independent artifacts -- and only by independent ones."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from android_forensics.artifacts.base import DbContext, RowSource
from android_forensics.artifacts.calls import CallsParser
from android_forensics.artifacts.contacts import ContactsParser
from android_forensics.artifacts.schema_probe import RoleMatch, SchemaMatch
from android_forensics.artifacts.sms import SmsParser
from android_forensics.artifacts.browser import BrowserParser
from android_forensics.artifacts.recovered import reconstruct
from android_forensics.correlation import FileInfo, Subject, build_correlation, database_of, facts_of, normalise_url
from android_forensics.models import (
    ArtifactStatus,
    CarvedCandidate,
    CarveKind,
    EntityKind,
    Relation,
)
from android_forensics.storage.case_store import CaseStore
from android_forensics.storage.recovery_store import insert_edges, load_edges
from tests.unit.recovery_fixtures import SMS_DDL, build_table_db, sms_row, stage

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
SMS_DB, CALL_DB, CONTACT_DB, CHROME_DB = "data/mmssms.db", "data/calllog.db", "data/contacts2.db", "data/History"
FILES = {1: FileInfo(1, SMS_DB, "database", "com.android.providers.telephony"), 2: FileInfo(2, CALL_DB, "database", "com.android.providers.contacts"),
         3: FileInfo(3, CONTACT_DB, "database", "com.android.providers.contacts"), 4: FileInfo(4, CHROME_DB, "database", "com.android.chrome"),
         5: FileInfo(5, f"{SMS_DB}-wal", "sidecar"), 6: FileInfo(6, "data/cache/blob.bin", "file")}


def ctx(path: str, file_id: int) -> DbContext:
    return DbContext(file_id, file_id, path, "ab" * 32, None, False, now=NOW)


def match(role="main") -> SchemaMatch:
    return SchemaMatch("p", "v", {role: RoleMatch("t", {}, 1.0)}, 1.0)


def row(values, table="t", rowid=1) -> RowSource:
    return RowSource(values=values, raw=dict(values), table=table, rowid=rowid)


MS = 1709280000000  # 2024-03-01T08:00:00Z


def sms(ref_id, address="+12025550101", body="see you at eight", type_=1, date=MS, database=SMS_DB, file_id=1):
    a = SmsParser().from_row(row({"address": address, "body": body, "date": date, "type": type_}, "sms", ref_id), match(), ctx(database, file_id))
    return Subject(f"artifact:{ref_id}", a, "active", database, file_id)


def call(ref_id, number="202-555-0101", type_=2, date=MS + 30_000, name="Ann Lee"):
    a = CallsParser().from_row(row({"number": number, "type": type_, "date": date, "duration": 42, "name": name}, "calls", ref_id),
                               match(), ctx(CALL_DB, 2))
    return Subject(f"artifact:{ref_id}", a, "active", CALL_DB, 2)


def contact(ref_id, name="Ann Lee", numbers=("(202) 555-0101",), emails=("ann@example.org",)):
    values = {"id": ref_id, "display_name": name, "phones": [{"number": n} for n in numbers], "emails": [{"address": e} for e in emails],
              "updated": MS}
    a = ContactsParser().from_row(row(values, "raw_contacts", ref_id), match(), ctx(CONTACT_DB, 3))
    return Subject(f"artifact:{ref_id}", a, "active", CONTACT_DB, 3)


def browser(ref_id, url="https://www.example.com/page", date=13353753600000000):
    a = BrowserParser().from_row(row({"_kind": "visit", "id": ref_id, "url": url, "title": "T", "visit_time": date, "transition": 1}, "visits", ref_id),
                                 match("chromium_history"), ctx(CHROME_DB, 4))
    return Subject(f"artifact:{ref_id}", a, "active", CHROME_DB, 4)


def recovered(record_id: int, subject: Subject) -> Subject:
    """A recovered draft of ``subject``'s artifact: the same payload in a recovery envelope, in the SMS database's WAL (file 5)."""
    return subject_as_recovered(record_id, subject)


def subject_as_recovered(record_id: int, s: Subject, found_in: int = 1) -> Subject:
    from android_forensics.models import ConfidenceFactor, ExtractionMethod, PhysicalLocation, RawKind, RawReference

    art = s.artifact.evolve(
        status=ArtifactStatus.RECOVERED, extraction_method=ExtractionMethod.FREEBLOCK, confidence="LOW",
        confidence_factors=[ConfidenceFactor(name="x", satisfied=True, weight=1.0, explanation="x")],
        raw=RawReference(kind=RawKind.PAGE_BYTES, raw_bytes_hex="00"),
        provenance=s.artifact.provenance.model_copy(update={"physical": PhysicalLocation(page_number=2, byte_offset=100)}),
    )
    return Subject(f"recovered:{record_id}", art, "recovered", s.database, s.file_id, found_in)


def carved(cid: int, kind: CarveKind, matched: str, file_id: int = 6, offset: int = 100, **kw) -> CarvedCandidate:
    return CarvedCandidate(id=cid, evidence_file_id=file_id, source_file=FILES[file_id].path, source_sha256="cd" * 32, offset=offset,
                           length=max(len(matched), 1), kind=kind, pattern="test", matched=matched, **kw)


PHONE = (EntityKind.PHONE_NUMBER, "phone:2025550101")


# ------------------------------------------------------------------ worked example (a)


def test_one_number_in_sms_call_log_and_contacts_is_one_phone_entity():
    c = build_correlation([sms(1), call(2), contact(3)], files=FILES)
    g = c.graph
    phones = g.nodes(EntityKind.PHONE_NUMBER)
    assert [p.ref for p in phones] == ["phone:2025550101"], "three spellings, one entity"
    (phone,) = phones
    assert {n.kind for n in g.neighbours(phone)} == {EntityKind.MESSAGE, EntityKind.CALL, EntityKind.CONTACT}
    assert {(e.relation, e.source_kind, e.target_kind) for e in g.query(target=PHONE) + g.query(source=PHONE)} == {
        (Relation.SENT, EntityKind.PHONE_NUMBER, EntityKind.MESSAGE),
        (Relation.RECEIVED, EntityKind.PHONE_NUMBER, EntityKind.CALL),
        (Relation.CONTACT_OF, EntityKind.CONTACT, EntityKind.PHONE_NUMBER),
    }


def test_the_edges_are_queryable_by_relation_endpoint_and_kind():
    g = build_correlation([sms(1), call(2), contact(3)], files=FILES).graph
    (sent,) = g.query(relation=Relation.SENT)
    assert (sent.source_ref, sent.target_ref) == ("phone:2025550101", "artifact:1")
    assert [e.source_ref for e in g.query(relation=Relation.CONTACT_OF, target=PHONE)] == ["artifact:3"]
    assert {e.target_ref for e in g.query(source=PHONE)} == {"artifact:1", "artifact:2"}
    assert {e.relation for e in g.query(source_kind=EntityKind.MESSAGE)} == {Relation.FOUND_IN}
    phone = g.find(*PHONE)
    assert [n.ref for n in g.neighbours(phone, Relation.CONTACT_OF, "in")] == ["artifact:3"]
    assert [n.ref for n in g.neighbours(phone, direction="out")] == ["artifact:2", "artifact:1"], "ordered by kind (call, message), then ref"


def test_direction_decides_the_relation():
    incoming, outgoing = sms(1, type_=1), sms(2, type_=2)
    missed, made = call(3, type_=3), call(4, type_=2)
    g = build_correlation([incoming, outgoing, missed, made], files=FILES).graph
    got = {(e.target_ref, e.relation) for e in g.query(source=PHONE)}
    assert got == {("artifact:1", Relation.SENT), ("artifact:2", Relation.RECEIVED), ("artifact:3", Relation.CALLED), ("artifact:4", Relation.RECEIVED)}


def test_a_message_with_no_known_direction_is_linked_without_claiming_one():
    g = build_correlation([sms(1, type_=99)], files=FILES).graph
    (e,) = g.query(source=PHONE)
    assert e.relation is Relation.CORRELATES_WITH and "not known" in e.explanation


def test_short_codes_and_sender_names_are_never_phone_entities():
    g = build_correlation([sms(1, address="22000"), sms(2, address="BANK-ALERT"), sms(3, address=None)], files=FILES).graph
    assert g.nodes(EntityKind.PHONE_NUMBER) == []


def test_contacts_are_linked_to_their_numbers_and_to_the_person():
    g = build_correlation([contact(3, numbers=("(202) 555-0101", "+1 303 555 0142"))], files=FILES).graph
    assert {n.ref for n in g.nodes(EntityKind.PHONE_NUMBER)} == {"phone:2025550101", "phone:3035550142"}
    (person,) = g.nodes(EntityKind.PERSON)
    assert person.ref == "person:ann lee" and [e.relation for e in g.query(target=(EntityKind.PERSON, "person:ann lee"))] == [Relation.CONTACT_OF]


def test_where_each_artifact_lives_is_part_of_the_graph():
    g = build_correlation([sms(1), call(2), contact(3)], files=FILES).graph
    assert {e.target_ref for e in g.query(relation=Relation.FOUND_IN, target_kind=EntityKind.DATABASE)} == {"database:1", "database:2", "database:3"}
    apps = {e.target_ref for e in g.query(relation=Relation.FOUND_IN, target_kind=EntityKind.APPLICATION)}
    assert apps == {"app:com.android.providers.telephony", "app:com.android.providers.contacts"}


def test_graph_edges_are_unique_and_the_build_is_deterministic():
    subjects = [sms(1), sms(2, body="another one"), call(3), contact(4)]
    a, b = build_correlation(subjects, files=FILES).graph, build_correlation(list(reversed(subjects)), files=FILES).graph
    assert [e.model_dump() for e in a.edges] == [e.model_dump() for e in b.edges]
    assert len({(e.source_kind, e.source_ref, e.relation, e.target_kind, e.target_ref) for e in a.edges}) == len(a.edges)
    assert a.summary()["node_count"] == len(a.nodes()) and a.summary()["edge_count"] == len(a)


# ------------------------------------------------------------------ worked example (b)


def test_a_recovered_sms_matching_an_active_contact_with_a_valid_timestamp_is_linked_and_corroborated():
    deleted = subject_as_recovered(7, sms(9))
    c = build_correlation([contact(3), deleted], files=FILES)
    corr = c.for_ref("recovered:7")
    assert corr.corroborated and corr.sources == ("contact Ann Lee",) and corr.targets == ("artifact:3",)
    (link,) = c.graph.query(source=(EntityKind.MESSAGE, "recovered:7"), relation=Relation.CORRELATES_WITH)
    assert link.target_ref == "artifact:3" and link.evidence["corroborated"] is True and link.evidence["timestamp_valid"] is True
    assert link.evidence["via"] == "phone:2025550101" and link.strength == 1.0
    (origin,) = c.graph.query(source=(EntityKind.MESSAGE, "recovered:7"), relation=Relation.RECOVERED_FROM)
    assert origin.target_ref == "database:1" and origin.evidence["status"] == "RECOVERED"


def test_the_call_log_and_contacts_together_give_two_sources_and_the_call_log_gap_is_reported():
    deleted = subject_as_recovered(7, sms(9, date=MS))
    corr = build_correlation([contact(3), call(4, date=MS + 42_000), call(5, date=MS + 7 * 86_400_000), deleted], files=FILES).for_ref("recovered:7")
    assert corr.sources == ("contact Ann Lee", "call log (2 calls with this number; nearest 42 s from this record)")
    assert corr.targets == ("artifact:3", "artifact:4", "artifact:5")


def test_a_recovered_message_is_not_corroborated_by_other_messages_or_by_its_own_database():
    deleted = subject_as_recovered(7, sms(9))
    same_db_contact = contact(3)
    same_db_contact = Subject(same_db_contact.ref, same_db_contact.artifact, "active", SMS_DB, 1)  # pretend it lives in the SMS database
    other_sms = sms(8, database="data/other_sms.db", file_id=9)
    corr = build_correlation([same_db_contact, other_sms, deleted], files=FILES).for_ref("recovered:7")
    assert not corr.corroborated and corr.sources == () and corr.targets == ()


def test_a_recovered_record_with_an_implausible_timestamp_is_linked_but_not_counted():
    impossible = subject_as_recovered(7, sms(9, date=1_000_000))  # 1970: before Android existed
    assert impossible.artifact.timestamp.plausible is False
    c = build_correlation([contact(3), impossible], files=FILES)
    corr = c.for_ref("recovered:7")
    assert not corr.corroborated and corr.sources == () and "not counted as corroboration" in corr.notes[0]
    (link,) = c.graph.query(source=(EntityKind.MESSAGE, "recovered:7"), relation=Relation.CORRELATES_WITH)
    assert link.evidence["corroborated"] is False and link.evidence["timestamp_valid"] is False and "not counted" in link.explanation


def test_a_recovered_record_without_a_timestamp_can_still_be_corroborated():
    """Nothing to judge is not the same as something wrong: a missing timestamp is UNKNOWN, not implausible."""
    s = sms(9)
    art = s.artifact.evolve(timestamp=None)
    corr = build_correlation([contact(3), subject_as_recovered(7, Subject(s.ref, art, "active", SMS_DB, 1))], files=FILES).for_ref("recovered:7")
    assert corr.corroborated


def test_a_recovered_call_is_corroborated_by_contacts_and_the_sms_thread():
    deleted = subject_as_recovered(7, call(9))
    deleted = Subject(deleted.ref, deleted.artifact, "recovered", CALL_DB, 2, 2)
    corr = build_correlation([contact(3), sms(4), sms(5, body="second"), deleted], files=FILES).for_ref("recovered:7")
    assert corr.sources == ("contact Ann Lee", "SMS thread (2 messages with this number)")


def test_only_a_few_links_are_drawn_but_the_count_is_complete():
    calls = [call(100 + i, date=MS + i * 1000) for i in range(20)]
    c = build_correlation([contact(3), *calls, subject_as_recovered(7, sms(9))], files=FILES)
    assert c.for_ref("recovered:7").sources[1].startswith("call log (20 calls")
    links = c.graph.query(source=(EntityKind.MESSAGE, "recovered:7"), relation=Relation.CORRELATES_WITH, target_kind=EntityKind.CALL)
    assert len(links) == 5 and [e.target_ref for e in links] == [f"artifact:{100 + i}" for i in range(5)], "the five nearest in time"


def test_a_sidecar_is_the_same_database():
    assert database_of("data/x/mmssms.db-wal") == database_of("data/x/mmssms.db-journal") == "data/x/mmssms.db"
    wal_record = subject_as_recovered(7, sms(9), found_in=5)
    c = build_correlation([contact(3), wal_record], files=FILES)
    (origin,) = c.graph.query(source=(EntityKind.MESSAGE, "recovered:7"), relation=Relation.RECOVERED_FROM)
    assert origin.target_ref == "file:5", "found in the -wal, which is a file rather than a database"
    assert c.for_ref("recovered:7").corroborated


def test_real_recovered_rows_correlate_end_to_end(tmp_path):
    """Rows recovered from a real database file, reconstructed, then correlated with a contact and a call from other databases."""
    path = tmp_path / "mmssms.db"
    build_table_db(path, SMS_DDL, "sms", sms_row, 60, "_id BETWEEN 20 AND 29")
    _, dc, records = stage(path)
    drafts = [Subject(f"recovered:{r.id or i}", reconstruct(r, dc), "recovered", str(path), 1, 1) for i, r in enumerate(records, 1)]
    number = drafts[0].artifact.phone_key
    assert number
    c = build_correlation([contact(3, numbers=(f"+1{number}",)), *drafts], files=FILES)
    hit = next(d for d in drafts if d.artifact.phone_key == number)
    assert c.for_ref(hit.ref).corroborated and c.for_ref(hit.ref).sources == ("contact Ann Lee",)
    others = [d for d in drafts if d.artifact.phone_key != number]
    assert others and not any(c.for_ref(d.ref).corroborated for d in others)


# ------------------------------------------------------------------ persistence


def test_edges_persist_to_the_correlations_table_and_are_queryable_there(tmp_path):
    corr = build_correlation([sms(1), call(2), contact(3), subject_as_recovered(7, sms(9))], files=FILES)
    store = CaseStore.create(tmp_path / "case", "c", "pytest")
    assert insert_edges(store, store.start_run("correlate"), corr.graph.edges) == len(corr.graph)
    stored = list(load_edges(store))
    assert [e.model_dump(exclude={"id"}) for e in stored] == [e.model_dump(exclude={"id"}) for e in corr.graph.edges]
    assert [e.source_ref for e in load_edges(store, "relation=? AND target_ref=?", ("CONTACT_OF", "phone:2025550101"))] == ["artifact:3"]
    assert store.scalar("SELECT COUNT(DISTINCT target_ref) FROM correlations WHERE relation='SENT'") == 2  # artifact:1 and recovered:7


# ------------------------------------------------------------------ carved candidates


def test_a_carved_number_is_corroborated_by_independent_sources_only():
    c = build_correlation([contact(3), sms(1)], [carved(1, CarveKind.PHONE_NUMBER, "+12025550101", file_id=6)], FILES)
    corr = c.for_ref("carved:1")
    assert corr.corroborated and corr.sources == ("contact Ann Lee", "SMS thread (1 message with this number)")
    (link,) = c.graph.query(source=(EntityKind.CARVED, "carved:1"), relation=Relation.CORRELATES_WITH)
    assert (link.target_kind, link.target_ref) == PHONE, "linked to the same phone entity as every artifact that carries it"
    (found,) = c.graph.query(source=(EntityKind.CARVED, "carved:1"), relation=Relation.FOUND_IN)
    assert found.target_ref == "file:6" and found.evidence["offset"] == 100


def test_a_hit_in_a_databases_own_free_space_is_not_corroborated_by_that_databases_rows():
    """The -wal of mmssms.db and mmssms.db are one database: a live row there is not an independent witness."""
    c = build_correlation([sms(1), contact(3)], [carved(1, CarveKind.PHONE_NUMBER, "+12025550101", file_id=5)], FILES)
    assert c.for_ref("carved:1").sources == ("contact Ann Lee",), "the contact (another database) counts; the SMS (same database) does not"


def test_a_carved_number_nobody_carries_is_not_corroborated():
    c = build_correlation([contact(3)], [carved(1, CarveKind.PHONE_NUMBER, "+14155552671")], FILES)
    assert not c.for_ref("carved:1").corroborated and c.for_ref("carved:1").sources == ()


def test_a_carved_number_supported_only_by_a_recovered_record_says_so():
    c = build_correlation([subject_as_recovered(7, sms(9))], [carved(1, CarveKind.PHONE_NUMBER, "+12025550101")], FILES)
    assert c.for_ref("carved:1").sources == ("recovered SMS thread (1 message with this number)",)


@pytest.mark.parametrize("kind, text, expected", [
    (CarveKind.URL, "https://WWW.Example.com/page/", "browser history (1 entry for this address)"),
    (CarveKind.EMAIL, "Ann@Example.org", "contact Ann Lee"),
    (CarveKind.TIMESTAMP_UNIX_MILLIS, "1709280000123", "the timestamp of 1 message"),
    (CarveKind.TIMESTAMP_UNIX_SECONDS, "1709280000", "the timestamp of 1 message"),
    (CarveKind.TIMESTAMP_TEXT, "2024-03-01 08:00:00", "the timestamp of 1 message"),
    (CarveKind.TIMESTAMP_TEXT, "Mar 1, 2024 8:00:00 AM", "the timestamp of 1 message"),
    (CarveKind.SMS_LIKE_TEXT, "see  you at   eight", "the body of 1 message"),
])
def test_carved_values_are_matched_with_the_artifacts_that_carry_them(kind, text, expected):
    subjects = [contact(3), browser(4), sms(5, database="data/other_sms.db", file_id=9)]
    c = build_correlation(subjects, [carved(1, kind, text)], FILES)
    assert expected in c.for_ref("carved:1").sources, c.for_ref("carved:1")


def test_a_carved_timestamp_of_the_same_second_and_no_other_is_matched():
    subjects = [sms(5, date=MS + 999, database="data/other_sms.db", file_id=9)]
    assert build_correlation(subjects, [carved(1, CarveKind.TIMESTAMP_UNIX_SECONDS, "1709280000")], FILES).for_ref("carved:1").corroborated
    assert not build_correlation(subjects, [carved(1, CarveKind.TIMESTAMP_UNIX_SECONDS, "1709280001")], FILES).for_ref("carved:1").corroborated


def test_a_timestamp_shared_by_a_carved_value_and_an_artifact_becomes_a_timestamp_entity():
    c = build_correlation([sms(5, database="data/other_sms.db", file_id=9)], [carved(1, CarveKind.TIMESTAMP_UNIX_MILLIS, "1709280000000")], FILES)
    (stamp,) = c.graph.nodes(EntityKind.TIMESTAMP)
    assert stamp.ref == "timestamp:2024-03-01T08:00:00Z"
    assert {e.source_ref for e in c.graph.query(target=(EntityKind.TIMESTAMP, stamp.ref))} == {"carved:1", "artifact:5"}


def test_a_carved_url_and_the_browser_visit_share_a_url_entity():
    c = build_correlation([browser(4)], [carved(1, CarveKind.URL, "https://www.example.com/page")], FILES)
    (url,) = c.graph.nodes(EntityKind.URL)
    assert url.ref == "url:https://www.example.com/page"
    assert {e.source_ref for e in c.graph.query(target=(EntityKind.URL, url.ref))} == {"carved:1", "artifact:4"}


def test_a_carved_record_shape_is_matched_through_the_values_it_decodes_to():
    matched = '["+12025550101", 1709280000000, "see you at eight", "Ann Lee"]'
    subjects = [contact(3), sms(5, database="data/other_sms.db", file_id=9)]
    corr = build_correlation(subjects, [carved(1, CarveKind.SQLITE_RECORD, matched)], FILES).for_ref("carved:1")
    assert {"contact Ann Lee", "SMS thread (1 message with this number)", "the body of 1 message"} <= set(corr.sources)
    assert build_correlation(subjects, [carved(1, CarveKind.SQLITE_RECORD, "not json")], FILES).for_ref("carved:1").sources == ()


def test_correlation_never_changes_a_candidate_or_an_artifact():
    cand = carved(1, CarveKind.PHONE_NUMBER, "+12025550101")
    subjects = [contact(3), subject_as_recovered(7, sms(9))]
    before = ([cand.model_dump()], [s.artifact.model_dump() for s in subjects])
    build_correlation(subjects, [cand], FILES)
    assert ([cand.model_dump()], [s.artifact.model_dump() for s in subjects]) == before
    assert cand.status == "CARVED CANDIDATE" and cand.confidence is None


def test_facts_read_only_what_an_artifact_carries():
    f = facts_of(contact(3).artifact)
    assert (f.role, f.phones, f.names, f.emails) == ("contact", ("2025550101",), ("Ann Lee",), ("ann@example.org",))
    f = facts_of(sms(1).artifact)
    assert (f.role, f.phones, f.texts, f.direction, f.moment, f.moment_valid) == ("message", ("2025550101",), ("see you at eight",), "in", "2024-03-01T08:00:00", True)
    assert facts_of(browser(4).artifact).urls == ("https://www.example.com/page",)
    assert normalise_url("HTTPS://Example.COM/a/#frag") == "https://example.com/a" and normalise_url("not a url") is None
