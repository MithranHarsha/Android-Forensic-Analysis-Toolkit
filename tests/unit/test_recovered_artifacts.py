"""Phase 5: recovered records become typed artifacts through the same parsers as active rows -- and never look active.

Every test builds a real SQLite database, deletes rows from it, recovers them from the file's bytes and converts them.
"""

from __future__ import annotations

import hashlib
import sqlite3

import pytest

from android_forensics.artifacts.recovered import record_from_row, reconstruct
from android_forensics.models import (
    UNKNOWN,
    ArtifactStatus,
    ArtifactType,
    BrowserDownload,
    BrowserHistoryEntry,
    CallRecord,
    Confidence,
    ExtractionMethod,
    GenericRecord,
    MessageDirection,
    RawKind,
    RecoveredRecord,
    SMSMessage,
)
from tests.unit.recovery_fixtures import (
    CALLS_DDL,
    NOTES_DDL,
    SMS_DDL,
    active_urls,
    artifacts,
    build_chrome_db,
    build_table_db,
    call_row,
    note_row,
    sha256_of,
    sms_row,
    stage,
)

RECOVERY_STATUSES = {ArtifactStatus.RECOVERED, ArtifactStatus.PARTIAL, ArtifactStatus.CORRUPTED}


@pytest.fixture
def sms_whole(tmp_path):
    """Rows 20-29 deleted as one run: their cells are contiguous, so every one is recovered whole (RECOVERED)."""
    path = tmp_path / "mmssms.db"
    return path, build_table_db(path, SMS_DDL, "sms", sms_row, 60, "_id BETWEEN 20 AND 29")


@pytest.fixture
def sms_partial(tmp_path):
    """Every fourth row deleted. The isolated freed cells lose their first bytes to SQLite's freeblock header (PARTIAL, rowid
    lost); copies that survived whole -- in the gap of a page, or as residue of a b-tree split -- come back RECOVERED."""
    path = tmp_path / "mmssms.db"
    return path, build_table_db(path, SMS_DDL, "sms", sms_row, 60, "_id % 4 = 0")


def partial_only(found):
    return [a for a in found if a.status is ArtifactStatus.PARTIAL]


def active_twin(dc, table, original, rowid):
    """What the parser makes of the row while it is still in the database."""
    parser, match, role_name = dc.routes()[table]
    return parser.from_row(parser.map_row(rowid, dict(original), match.roles[role_name]), match, dc.parser_context())


# ------------------------------------------------------------------ the same parser, a different envelope


def test_a_recovered_sms_is_read_by_the_sms_parser_exactly_as_the_active_row_would_be(sms_whole):
    path, originals = sms_whole
    _, dc, records = stage(path, "com.android.providers.telephony")
    whole = [r for r in records if r.status is ArtifactStatus.RECOVERED]
    assert {r.rowid for r in whole} == set(range(20, 30))
    for record in whole:
        recovered = reconstruct(record, dc)
        active = active_twin(dc, "sms", originals[record.rowid], record.rowid)
        assert isinstance(recovered, SMSMessage)
        assert recovered.payload() == active.payload(), "same payload: the parser saw the same values"
        assert recovered.timestamp == active.timestamp and recovered.phone_key == active.phone_key
        assert recovered.summary == active.summary


def test_the_envelope_says_recovered_where_and_how_never_active(sms_whole):
    path, _ = sms_whole
    for a in artifacts(path, "sms"):
        assert a.status in RECOVERY_STATUSES and a.status is not ArtifactStatus.ACTIVE
        assert not a.extraction_method.is_active
        assert a.raw.kind is RawKind.PAGE_BYTES and a.raw.raw_bytes_hex
        assert a.raw.sha256 == hashlib.sha256(bytes.fromhex(a.raw.raw_bytes_hex)).hexdigest()
        assert a.marked_deleted is False
        loc = a.provenance.physical
        assert loc.page_number >= 1 and loc.byte_offset >= 0 and loc.region and loc.page_type


def test_provenance_points_at_the_real_bytes(sms_whole):
    path, _ = sms_whole
    data = path.read_bytes()
    for a in artifacts(path, "sms"):
        raw = bytes.fromhex(a.raw.raw_bytes_hex)
        assert data[a.provenance.physical.byte_offset:][:len(raw)] == raw, "the offset finds the raw bytes in the evidence file"
        assert a.provenance.source_sha256 == sha256_of(path)
        assert a.provenance.source_table == "sms" and a.provenance.source_database == str(path)


def test_a_whole_cell_keeps_its_rowid_and_a_freeblock_cell_does_not(sms_partial):
    path, originals = sms_partial
    found = artifacts(path, "sms")
    assert {a.status for a in found} == {ArtifactStatus.RECOVERED, ArtifactStatus.PARTIAL}
    for a in found:
        if a.status is ArtifactStatus.RECOVERED:
            rowid = a.provenance.source_rowid
            assert rowid is not None and a.msg_id == rowid and not a.unknown_fields and a.body == originals[rowid]["body"]
        else:
            assert a.provenance.source_rowid is None and a.msg_id is None and "msg_id" in a.unknown_fields
            assert a.extraction_method is ExtractionMethod.FREEBLOCK


def test_a_partial_artifact_marks_what_was_lost_unknown_and_keeps_everything_else_true(sms_partial):
    path, originals = sms_partial
    by_body = {o["body"]: o for o in originals.values()}
    found = artifacts(path, "sms")
    assert len(found) == 15
    partial = partial_only(found)
    assert partial
    for a in partial:
        original = by_body[a.body]
        assert (a.address, a.thread_id, a.type_code, a.subject, a.service_center) == \
               (original["address"], original["thread_id"], original["type"], None, original["service_center"])
        assert a.timestamp.raw == original["date"]
        assert a.direction is MessageDirection.from_code(original["type"])


def test_unknown_is_not_null(sms_partial):
    """A lost column is listed as unknown; a column that held NULL is a value. The two must never be confused."""
    path, _ = sms_partial
    a = partial_only(artifacts(path, "sms"))[0]
    assert a.subject is None and "subject" not in a.unknown_fields, "subject really was NULL"
    assert a.msg_id is None and "msg_id" in a.unknown_fields, "the rowid alias was lost"


# ------------------------------------------------------------------ confidence


def test_every_recovered_artifact_carries_a_level_the_factors_and_an_explanation(sms_partial):
    path, _ = sms_partial
    for a in artifacts(path, "sms"):
        assert a.confidence in (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)
        assert len(a.confidence_factors) >= 9
        assert a.metadata["confidence_explanation"] == a.validation_notes[-1]
        assert a.validation_notes[-1].startswith(a.confidence.value)


def test_a_partial_row_is_never_high_without_two_corroborations(sms_partial):
    path, _ = sms_partial
    _, dc, records = stage(path)
    record = next(r for r in records if r.status is ArtifactStatus.PARTIAL)
    assert reconstruct(record, dc, ("a contact",)).confidence is not Confidence.HIGH
    assert reconstruct(record, dc, ("a contact", "the call log")).confidence in (Confidence.MEDIUM, Confidence.HIGH)
    assert reconstruct(record, dc).confidence is not Confidence.HIGH


def test_corroboration_is_what_lifts_a_whole_recovered_row_to_high(sms_partial):
    """A whole cell with a verified source, exact structure and plausible timestamp still sits below HIGH on its own;
    an independent artifact that carries the same facts is what closes the gap."""
    path, _ = sms_partial
    _, dc, records = stage(path)
    whole = next(r for r in records if r.status is ArtifactStatus.RECOVERED and not r.also_found_at)
    alone = reconstruct(whole, dc)
    backed = reconstruct(whole, dc, ("a call with the same number",))
    assert alone.confidence is Confidence.MEDIUM and backed.confidence is Confidence.HIGH
    assert "corroborated by a call with the same number" in backed.validation_notes[-1]
    assert {f.name: f.satisfied for f in alone.confidence_factors}["cross_artifact_corroboration"] is False
    assert alone.metadata["confidence_score"] < backed.metadata["confidence_score"]


def test_a_second_location_counts_and_is_reported(sms_whole):
    """Every one of these rows survives in two places (its freed cell and residue of a page split): the scorer credits that."""
    path, _ = sms_whole
    _, dc, records = stage(path)
    assert records and all(r.also_found_at for r in records)
    for r in records:
        a = reconstruct(r, dc)
        assert {f.name: f.satisfied for f in a.confidence_factors}["multiple_locations"] is True
        assert a.metadata["also_found_at"] == r.also_found_at and "also found in 1 other location" in a.metadata["confidence_explanation"]


def test_the_same_record_always_gets_the_same_assessment(sms_whole):
    path, _ = sms_whole
    _, dc, records = stage(path)
    one = [reconstruct(r, dc) for r in records]
    two = [reconstruct(r, dc) for r in records]
    assert [a.model_dump() for a in one] == [a.model_dump() for a in two]


def test_the_source_of_a_wal_record_decides_its_provenance_factor(sms_whole):
    path, _ = sms_whole
    _, dc, records = stage(path)
    base = records[0].model_dump()
    for frame_status, verified in (("committed", True), ("stale_generation", True), ("stale_unverified", False), ("corrupt", False)):
        record = RecoveredRecord(**{**base, "source": "wal", "method": ExtractionMethod.WAL_FRAME, "frame": 3, "region": "wal_frame_3"})
        dc.wal_frame_status = {3: frame_status}
        a = reconstruct(record, dc)
        assert a.raw.kind is RawKind.WAL_FRAME and a.extraction_method is ExtractionMethod.WAL_FRAME
        assert {f.name: f.satisfied for f in a.confidence_factors}["source_provenance"] is verified


# ------------------------------------------------------------------ other parsers


def test_recovered_calls_are_call_records(tmp_path):
    path = tmp_path / "calllog.db"
    originals = build_table_db(path, CALLS_DDL, "calls", call_row, 50, "_id BETWEEN 10 AND 19")
    _, dc, records = stage(path, "com.android.providers.contacts")
    found = [reconstruct(r, dc) for r in records if r.table == "calls"]
    assert len(found) == 10 and all(isinstance(a, CallRecord) for a in found)
    whole = [a for a in found if a.status is ArtifactStatus.RECOVERED]
    assert whole
    for a in whole:
        assert a.payload() == active_twin(dc, "calls", originals[a.provenance.source_rowid], a.provenance.source_rowid).payload()
        assert a.number == originals[a.call_id]["number"] and a.cached_name == originals[a.call_id]["name"]


def test_recovered_browser_rows(tmp_path):
    path = tmp_path / "History"
    originals = build_chrome_db(path)
    found = artifacts(path, application="com.android.chrome", urls=active_urls(path))
    urls = [a for a in found if a.provenance.source_table == "urls"]
    visits = [a for a in found if a.provenance.source_table == "visits"]
    downloads = [a for a in found if a.provenance.source_table == "downloads"]
    assert (len(urls), len(visits), len(downloads)) == (4, 16, 2)
    assert all(isinstance(a, BrowserHistoryEntry) for a in urls + visits) and all(isinstance(a, BrowserDownload) for a in downloads)

    by_url = {u["url"]: u for u in originals["urls"].values()}
    assert set(by_url) >= {a.url for a in urls} and len({a.url for a in urls}) == 4
    for a in urls:
        o = by_url[a.url]
        assert a.url_level_only, "a urls row says when a URL was last visited, not that a visit happened"
        assert (a.title, a.visit_count, a.timestamp.raw) == (o["title"], o["visit_count"], o["last_visit_time"])
        assert a.status is ArtifactStatus.PARTIAL and "url_id" in a.unknown_fields, "the row's id (its rowid alias) was overwritten"

    by_path = {d["target_path"]: d for d in originals["downloads"].values()}
    assert {a.target_path for a in downloads} == {originals["downloads"][3]["target_path"], originals["downloads"][4]["target_path"]}
    for a in downloads:
        o = by_path[a.target_path]
        assert (a.timestamp.raw, a.total_bytes, a.mime_type, a.tab_url) == (o["start_time"], o["total_bytes"], o["mime_type"], o["tab_url"])


def test_a_recovered_visit_takes_its_url_from_the_active_urls_table_and_says_so(tmp_path):
    path = tmp_path / "History"
    originals = build_chrome_db(path)
    urls = active_urls(path)
    visits = artifacts(path, "visits", urls=urls)
    by_time = {v["visit_time"]: v for v in originals["visits"].values()}
    resolved = [a for a in visits if a.url is not None]
    dangling = [a for a in visits if a.url is None]
    deleted = [v for v in originals["visits"].values() if v["id"] % 5 == 0]  # the deletion in build_chrome_db
    orphaned = [v for v in deleted if v["url"] in {33, 34, 35, 36}]  # their urls rows were deleted too
    assert len(visits) == len(deleted) == 16 and len(dangling) == len(orphaned) == 2 and len(resolved) == 14
    for a in visits:
        o = by_time[a.timestamp.raw]
        assert not a.url_level_only and (a.url_id, a.transition_code, a.visit_duration_us) == (o["url"], o["transition"], o["visit_duration"])
    for a in resolved:
        assert a.url == urls[a.url_id][0] and any(f.startswith("url_from_active_urls_table") for f in a.flags)
    for a in dangling:  # the urls row is gone too, so the URL text is nowhere: UNKNOWN, not guessed
        assert "url" in a.unknown_fields and a.url_id == 36 and not any(f.startswith("url_from_active") for f in a.flags)


# ------------------------------------------------------------------ the generic fallback


def test_a_table_no_parser_knows_becomes_a_generic_record(tmp_path):
    path = tmp_path / "notes.db"
    originals = build_table_db(path, NOTES_DDL, "notes", note_row, 40, "_id BETWEEN 10 AND 19")
    found = artifacts(path, "notes")
    assert len(found) == 10 and all(isinstance(a, GenericRecord) for a in found)
    assert all(a.artifact_type is ArtifactType.GENERIC_RECORD and a.table == "notes" and a.parser.name == "generic" for a in found)
    by_title = {o["title"]: o for o in originals.values()}
    for a in found:
        original = by_title[a.columns["title"]]
        assert a.status in RECOVERY_STATUSES and a.confidence is not None and a.confidence_factors
        if a.status is ArtifactStatus.RECOVERED:
            assert a.columns == original and not a.unknown_columns and a.provenance.source_rowid == original["_id"]
        else:  # the freeblock header ate the payload size and rowid: the values survive, the rowid alias does not
            assert a.unknown_columns == ["_id"] and "_id" not in a.columns and a.provenance.source_rowid is None
            assert a.columns == {k: v for k, v in original.items() if k != "_id"}


def test_a_generic_record_never_claims_a_meaning_for_its_columns(tmp_path):
    path = tmp_path / "notes.db"
    build_table_db(path, NOTES_DDL, "notes", note_row, 40, "_id BETWEEN 10 AND 19")
    for a in artifacts(path, "notes"):
        assert a.timestamp is None and a.phone_key is None and a.summary.startswith("Row of table notes")


def test_a_contacts_style_table_is_not_forced_into_a_typed_artifact(tmp_path):
    """One row of ``data`` cannot say whose number it is: it stays generic instead of pretending to be a contact."""
    path = tmp_path / "data.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA secure_delete=OFF")
    conn.executescript("""CREATE TABLE data (_id INTEGER PRIMARY KEY AUTOINCREMENT, mimetype_id INTEGER, raw_contact_id INTEGER,
        is_primary INTEGER, data1 TEXT, data2 TEXT, data3 TEXT, data4 TEXT);""")
    conn.executemany("INSERT INTO data(mimetype_id, raw_contact_id, is_primary, data1, data2, data3, data4) VALUES(?,?,?,?,?,?,?)",
                     [(5, i, 1, f"+1202555{i:04d}", "2", None, f"+1202555{i:04d}") for i in range(1, 41)])
    conn.commit()
    conn.execute("DELETE FROM data WHERE _id BETWEEN 10 AND 19")
    conn.commit()
    conn.close()
    found = artifacts(path, "data")
    assert found and all(isinstance(a, GenericRecord) for a in found)


# ------------------------------------------------------------------ staging records


def test_staging_drops_undetermined_columns_and_binds_the_raw_bytes(sms_partial):
    path, _ = sms_partial
    report, _, records = stage(path)
    assert any(r.unknown_columns for r in records) and any(not r.unknown_columns for r in records)
    for row, record in zip(report.rows, records):
        assert record.unknown_columns == row.unknown_columns == (["_id"] if row.status is ArtifactStatus.PARTIAL else [])
        assert ("_id" in record.values) is (row.status is ArtifactStatus.RECOVERED) and UNKNOWN not in record.values.values()
        assert record.raw == row.raw and record.raw_sha256 == hashlib.sha256(row.raw).hexdigest()
        assert record.status is row.status and record.method is row.method


def test_a_blob_survives_staging_and_reconstruction(tmp_path):
    path = tmp_path / "blobs.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("CREATE TABLE files(_id INTEGER PRIMARY KEY, name TEXT, data BLOB, size INTEGER, added INTEGER)")
    conn.executemany("INSERT INTO files VALUES(?,?,?,?,?)", [(i, f"file{i}.bin", bytes([i, 0, 255, 7]) * 10, 40, 1709280000000 + i) for i in range(1, 60)])
    conn.commit()
    conn.execute("DELETE FROM files WHERE _id BETWEEN 20 AND 29")
    conn.commit()
    conn.close()
    _, dc, records = stage(path)
    assert records and all(isinstance(r.values["data"], dict) and "$blob" in r.values["data"] for r in records)
    for a in (reconstruct(r, dc) for r in records):
        assert isinstance(a, GenericRecord) and a.columns["data"]["__blob__"] is True and a.columns["data"]["length"] == 40


def test_reconstruction_never_changes_the_evidence(sms_whole):
    path, _ = sms_whole
    before = sha256_of(path)
    _, dc, records = stage(path)
    for r in records:
        reconstruct(r, dc)
    assert sha256_of(path) == before and sorted(p.name for p in path.parent.iterdir()) == [path.name]


def test_record_from_row_preserves_every_locator(sms_whole):
    path, _ = sms_whole
    report, _, _ = stage(path)
    row = report.rows[0]
    record = record_from_row(row, database_file_id=4, source_file_id=4, source_sha256=sha256_of(path))
    assert (record.page_number, record.page_offset, record.file_offset, record.length) == (row.page_number, row.page_offset, row.file_offset, row.length)
    assert (record.region, record.page_type, record.cell_index, record.fit) == (row.region, row.page_type, row.cell_index, row.fit)
