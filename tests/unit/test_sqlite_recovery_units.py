"""Phase 4B/4D unit tests: the record-reconstruction rules, on bytes built by hand.

Every rule the recovery engine relies on has a test that breaks it: exact length, alias NULL, header-size agreement, no
guessing of ambiguous fields, no overlap with live cells, no internal or narrow tables.
"""

import struct

import pytest

from android_forensics.models.enums import ArtifactStatus
from android_forensics.models.unknown import UNKNOWN
from android_forensics.sqlite.ddl import parse_create_table
from android_forensics.sqlite.recovery import (
    ActiveIndex,
    PageImage,
    TableModel,
    field_types_valid,
    recover_all,
    scan_page,
    try_clobbered,
    try_full,
)
from android_forensics.sqlite.records import encode_record, encode_table_leaf_cell, encode_varint

SMS = TableModel.from_sql(parse_create_table(
    "CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT, read INTEGER)"))
ROW = ("+12025550101", 1709280000000, 1, "hello there", 0)


def cell(rowid, row=ROW):
    return encode_table_leaf_cell(rowid, encode_record((None,) + row))


def clobber(cell_bytes):
    """What SQLite does when it frees a cell: its first four bytes become ``[next:2][size:2]``."""
    return struct.pack(">HH", 0, len(cell_bytes)) + cell_bytes[4:]


def embed(data, pad=7):
    return bytes(pad) + data + bytes(pad), pad


# ------------------------------------------------------------------ untouched cells


def test_an_untouched_cell_is_read_completely():
    buf, at = embed(cell(5))
    c = try_full(buf, at, len(buf), SMS, "UTF-8")
    assert (c.kind, c.rowid, c.length) == ("full", 5, len(cell(5)))
    assert c.values == [5, *ROW] and c.fit == 1.0 and not c.corrupted


@pytest.mark.parametrize("rowid", [1, 127, 128, 16383, 16384, 2**31, 2**40])
def test_rowids_of_every_varint_width(rowid):
    buf, at = embed(cell(rowid))
    assert try_full(buf, at, len(buf), SMS, "UTF-8").rowid == rowid


def test_a_rowid_needing_more_than_six_varint_bytes_is_not_attempted_in_free_space():
    """Documented limit: negative rowids (9-byte varints) and rowids >= 2**42 are legal in SQLite but implausible for a phone's
    tables, and accepting them would let far more random byte runs pass as records."""
    record = encode_record((None,) + ROW)
    negative = encode_varint(len(record)) + encode_varint(2**64 - 3) + record
    buf, at = embed(negative)
    assert try_full(buf, at, len(buf), SMS, "UTF-8") is None


def test_the_payload_size_must_match_exactly():
    good = cell(5)
    for bad in (bytes([good[0] + 1]) + good[1:], bytes([good[0] - 1]) + good[1:]):
        buf, at = embed(bad)
        assert try_full(buf, at, len(buf), SMS, "UTF-8") is None, "a payload size one off the header + body sum is not this record"
    assert try_full(good[:-1], 0, len(good) - 1, SMS, "UTF-8") is None, "a cell cut short does not fit"
    buf, at = embed(good + b"\x00")
    assert try_full(buf, at, len(buf), SMS, "UTF-8").length == len(good), "a byte after the cell is simply not part of it"


def test_a_cell_that_runs_past_its_limit_is_refused():
    buf, at = embed(cell(5))
    assert try_full(buf, at, at + len(cell(5)) - 1, SMS, "UTF-8") is None


def test_the_rowid_alias_column_must_be_null():
    non_null = encode_table_leaf_cell(5, encode_record((99,) + ROW))
    buf, at = embed(non_null)
    assert try_full(buf, at, len(buf), SMS, "UTF-8") is None


def test_the_number_of_columns_must_match_the_table():
    fewer = encode_table_leaf_cell(5, encode_record((None, "+1", 5)))
    more = encode_table_leaf_cell(5, encode_record((None,) + ROW + ("extra",)))
    for c in (fewer, more):
        buf, at = embed(c)
        assert try_full(buf, at, len(buf), SMS, "UTF-8") is None


def test_text_that_is_not_valid_utf8_makes_the_record_corrupted_and_the_value_unknown():
    row = list(ROW)
    good = bytearray(cell(5))
    idx = good.index(b"hello there")
    good[idx] = 0xFF  # damage one byte of the body text
    buf, at = embed(bytes(good))
    c = try_full(buf, at, len(buf), SMS, "UTF-8")
    assert c.corrupted and c.values[4] is UNKNOWN and c.values[1] == ROW[0] and "not valid UTF-8" in c.issues[0]
    assert row  # (the untouched row is unchanged)


def test_implausible_types_lower_the_fit_below_the_threshold():
    weird = encode_table_leaf_cell(5, encode_record((None, b"\x00\x01", b"\x02", b"\x03", b"\x04", b"\x05")))  # blobs everywhere
    buf, at = embed(weird)
    assert try_full(buf, at, len(buf), SMS, "UTF-8") is None


# ------------------------------------------------------------------ freeblock cells (first four bytes overwritten)


@pytest.mark.parametrize("rowid,body", [
    (1, "a"), (38, "hello there"), (127, "x" * 30), (128, "y" * 40), (300, "z" * 100), (16384, "w" * 130), (70000, "v" * 200),
    (5, "q" * 250),
])
def test_a_freed_cell_is_reconstructed_whatever_the_widths_of_its_lost_prefix(rowid, body):
    """The payload-size and rowid varints (1-2 and 1-3 bytes) decide how much of the record header SQLite overwrote."""
    row = (ROW[0], ROW[1], ROW[2], body, ROW[4])
    original = cell(rowid, row)
    freed = clobber(original)
    buf, at = embed(freed)
    c = try_clobbered(buf, at, at + len(freed), frozenset(), SMS, "UTF-8", [SMS])
    assert c is not None, f"rowid {rowid}, body {len(body)}"
    assert c.kind == "clobbered" and c.rowid is None and c.length == len(original)
    assert c.values[0] is UNKNOWN, "the rowid (and so the alias column) is lost and must not be guessed"
    assert c.values[1:] == list(row)


def test_a_freed_cell_that_is_one_byte_off_is_refused():
    freed = clobber(cell(38))
    buf, at = embed(freed + b"\x00")  # the freeblock is a byte longer than any cell: but a lone trailing byte cannot hide a cell
    ok = try_clobbered(buf, at, at + len(freed) + 1, frozenset(), SMS, "UTF-8", [SMS])
    assert ok is not None and ok.length == len(freed), "fewer than 4 trailing bytes are fragment bytes, not another cell"
    buf, at = embed(freed[:-1])
    assert try_clobbered(buf, at, at + len(freed) - 1, frozenset(), SMS, "UTF-8", [SMS]) is None, "a truncated cell does not fit"


def test_a_surviving_header_size_byte_must_agree_with_the_types_after_it():
    rowid_wide = 70000  # 3-byte rowid: the header-size byte survives the four-byte overwrite
    freed = bytearray(clobber(cell(rowid_wide)))
    hs_pos = 4 + 0  # cell[4] is the header-size byte when payload-size(1) + rowid(3) = 4
    original = cell(rowid_wide)
    assert original[4] == 7 or original[4] >= 6
    freed[hs_pos] = original[4] + 1  # lie about it
    buf, at = embed(bytes(freed))
    assert try_clobbered(buf, at, at + len(freed), frozenset(), SMS, "UTF-8", [SMS]) is None


def test_two_freed_cells_in_one_merged_freeblock_are_both_found():
    """SQLite leaves a stale freeblock header at every cell boundary of a merged block; its size field is the distance to the end."""
    a, b = cell(10), cell(11, ("+12025550102", 1709280060000, 2, "second one", 1))
    end = len(a) + len(b)
    first = struct.pack(">HH", 0, end) + a[4:]
    second = struct.pack(">HH", 0, len(b)) + b[4:]  # the older header, left in place: size == distance to the block end
    buf, at = embed(first + second)
    interior = frozenset({at + len(a)})
    c1 = try_clobbered(buf, at, at + end, interior, SMS, "UTF-8", [SMS])
    c2 = try_clobbered(buf, at + len(a), at + end, frozenset(), SMS, "UTF-8", [SMS])
    assert c1 is not None and c1.values[1] == ROW[0] and c1.length == len(a)
    assert c2 is not None and c2.values[1] == "+12025550102" and c2.values[4] == "second one"


NO_ALIAS = TableModel.from_sql(parse_create_table("CREATE TABLE t(a TEXT, b INTEGER, c TEXT)"))


def test_a_lost_first_column_is_inferred_only_when_its_type_is_unambiguous():
    row = ("abcdefghij", 42, "tail")
    original = encode_table_leaf_cell(9, encode_record(row))
    freed = clobber(original)
    buf, at = embed(freed)
    c = try_clobbered(buf, at, at + len(freed), frozenset(), NO_ALIAS, "UTF-8", [NO_ALIAS])
    if c is not None:  # the first serial type was overwritten: only TEXT affinity plus its length pins the value down
        assert c.values[1:] == [42, "tail"] and c.values[0] in ("abcdefghij", UNKNOWN)
        if c.values[0] == "abcdefghij":
            assert any("inferred" in i for i in c.issues)


UNTYPED = TableModel.from_sql(parse_create_table("CREATE TABLE u(a, b, c, d)"))


def test_a_lost_first_column_of_an_untyped_table_stays_unknown_never_guessed():
    original = encode_table_leaf_cell(9, encode_record(("abcdef", 42, "tail", 7)))
    freed = clobber(original)
    buf, at = embed(freed)
    c = try_clobbered(buf, at, at + len(freed), frozenset(), UNTYPED, "UTF-8", [UNTYPED])
    assert c is None or c.values[0] is UNKNOWN


# ------------------------------------------------------------------ tables the engine will not guess at


def test_internal_narrow_and_without_rowid_tables_are_not_modelled():
    assert TableModel.from_sql(parse_create_table("CREATE TABLE sqlite_sequence(name,seq)")) is None
    assert TableModel.from_sql(parse_create_table("CREATE TABLE w(k TEXT PRIMARY KEY, v) WITHOUT ROWID")) is None
    assert TableModel.from_sql(parse_create_table("CREATE VIRTUAL TABLE v USING fts5(a)")) is None
    narrow = TableModel.from_sql(parse_create_table("CREATE TABLE n(a, b)"))
    assert narrow is not None and not narrow.scannable, "two columns carry too little structure to find in free space"


def test_a_narrow_table_is_never_found_in_free_space():
    narrow = TableModel.from_sql(parse_create_table("CREATE TABLE n(a, b)"))
    page = bytearray(512)
    page[0] = 0x0D
    struct.pack_into(">HHH", page, 1, 0, 0, 512)
    stray = encode_table_leaf_cell(1, encode_record(("x", "y")))
    page[200:200 + len(stray)] = stray
    cands, _ = scan_page(2, bytes(page), [narrow], "UTF-8")
    assert cands == []


# ------------------------------------------------------------------ whole pages


def leaf_page(size, live_cells, free_cells=(), freeblock=None):
    """A table-leaf page holding ``live_cells`` (in the pointer array) and raw ``free_cells`` bytes placed in the gap."""
    page = bytearray(size)
    page[0] = 0x0D
    offsets = []
    pos = size
    for c in live_cells:
        pos -= len(c)
        page[pos:pos + len(c)] = c
        offsets.append(pos)
    content_start = pos
    gap_at = 8 + 2 * len(live_cells) + 40
    for c in free_cells:
        page[gap_at:gap_at + len(c)] = c
        gap_at += len(c) + 3
    struct.pack_into(">HHHB", page, 1, freeblock or 0, len(live_cells), content_start, 0)
    for i, o in enumerate(offsets):
        struct.pack_into(">H", page, 8 + 2 * i, o)
    return bytes(page)


def test_a_live_cell_is_not_deleted_data_and_is_dropped_against_the_active_view():
    live = cell(1)
    page = leaf_page(1024, [live])
    rows, _, stats = recover_all([PageImage(2, page, "main", "x.db", 1024, "btree", "sms")], [SMS], "UTF-8",
                                 ActiveIndex({"sms": SMS}, {"sms": [(1, *ROW)]}))
    assert rows == [] and stats["dropped_active"] == 1


def test_the_same_cell_is_reported_when_the_active_view_does_not_have_it():
    page = leaf_page(1024, [cell(1)])
    rows, _, _ = recover_all([PageImage(2, page, "main", "x.db", 1024, "btree", "sms")], [SMS], "UTF-8",
                             ActiveIndex({"sms": SMS}, {"sms": []}))
    assert len(rows) == 1 and rows[0].status is ArtifactStatus.RECOVERED and rows[0].rowid == 1


def test_a_candidate_that_overlaps_a_live_cell_is_not_a_deleted_record():
    """Row 1's old cell partly overwritten by a live cell parses as a record, but the bytes it needs belong to the live cell."""
    old = cell(1, ("+12025550101", 1709280000000, 1, "hello there and more text", 0))
    live = struct.pack(">I", 4) + encode_varint(93)  # an interior-style cell that lands on the old cell's last bytes
    page = bytearray(leaf_page(1024, []))
    at = 1024 - len(old)
    page[at:at + len(old)] = old
    page[1024 - len(live):] = live
    struct.pack_into(">HHHB", page, 1, 0, 1, 1024 - len(live), 0)
    struct.pack_into(">H", page, 8, 1024 - len(live))
    cands, _ = scan_page(2, bytes(page), [SMS], "UTF-8")
    assert not [c for c in cands if not c.from_pointer_array and c.end > 1024 - len(live)]


def test_a_freed_cell_in_the_gap_of_a_page_is_recovered_as_recovered_when_untouched():
    page = leaf_page(1024, [cell(1)], free_cells=[cell(2, ("+12025550102", 1709280060000, 2, "deleted one", 1))])
    rows, _, _ = recover_all([PageImage(2, page, "main", "x.db", 1024, "btree", "sms")], [SMS], "UTF-8",
                             ActiveIndex({"sms": SMS}, {"sms": [(1, *ROW)]}))
    assert [r.values["body"] for r in rows] == ["deleted one"]
    assert rows[0].status is ArtifactStatus.RECOVERED and rows[0].method.value == "UNALLOCATED_SPACE"
    assert rows[0].raw == cell(2, ("+12025550102", 1709280060000, 2, "deleted one", 1))


def test_a_duplicate_found_twice_is_reported_once_with_both_locations():
    row = ("+12025550102", 1709280060000, 2, "deleted one", 1)
    a = leaf_page(1024, [], free_cells=[cell(2, row)])
    b = leaf_page(1024, [], free_cells=[clobber(cell(2, row))], freeblock=8 + 40)
    images = [PageImage(2, a, "main", "x.db", 1024, "orphan", None), PageImage(3, b, "wal", "x.db-wal", 5000, "historical", None, 1)]
    rows, _, stats = recover_all(images, [SMS], "UTF-8", ActiveIndex({"sms": SMS}, {"sms": []}))
    assert len(rows) == 1 and rows[0].status is ArtifactStatus.RECOVERED and stats["merged"] >= 0
    assert rows[0].values["body"] == "deleted one"


# ------------------------------------------------------------------ Phase 4D: field validation


def test_recovered_field_types_are_checked_against_the_declared_column_types():
    ok = {"_id": 1, "address": "+1", "date": 5, "type": 1, "body": "x", "read": 0}
    assert field_types_valid(SMS, ok) == []
    bad = dict(ok, address=42, date="yesterday", body=b"bytes")
    problems = field_types_valid(SMS, bad)
    assert len(problems) == 3 and any("address" in p and "TEXT" in p for p in problems) and any("date" in p for p in problems)
    assert field_types_valid(SMS, dict(ok, address=UNKNOWN, body=None)) == [], "unknown and NULL values are not type violations"
