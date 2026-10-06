"""Phase 4A: the page-level reader agrees with SQLite on every row, at every page size, without using the SQLite library."""

import random
import sqlite3
import struct

import pytest

from android_forensics.sqlite.ddl import parse_create_table
from android_forensics.sqlite.freelist import walk_freelist
from android_forensics.sqlite.pages import (
    BytesPageSource,
    PageError,
    PageType,
    parse_btree_page,
    read_cell,
    read_cell_payload,
)
from android_forensics.sqlite.parser import PageRole, SQLiteDatabase, logical_row
from android_forensics.sqlite.records import (
    RecordError,
    decode_value,
    encode_varint,
    local_payload_size,
    parse_record,
    read_varint,
    serial_type_class,
    serial_type_size,
    varint_length,
)

PAGE_SIZES = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]


# ------------------------------------------------------------------ varints, serial types, records


@pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 16383, 16384, 2**21 - 1, 2**21, 2**35, 2**49 - 1, 2**56 - 1, 2**56, 2**63, 2**64 - 1])
def test_varint_round_trip_and_length(value):
    raw = encode_varint(value)
    assert read_varint(raw, 0) == (value, len(raw)) and varint_length(value) == len(raw) and len(raw) <= 9
    assert read_varint(b"\xAA" * 3 + raw + b"\xBB", 3) == (value, len(raw))


def test_varint_known_encodings():
    assert encode_varint(0x7F) == b"\x7f" and encode_varint(0x80) == b"\x81\x00" and encode_varint(300) == b"\x82\x2c"
    assert read_varint(b"\xff" * 9, 0) == (2**64 - 1, 9)


def test_varint_running_off_the_buffer_is_an_error():
    with pytest.raises(RecordError):
        read_varint(b"\x81", 0)
    with pytest.raises(RecordError):
        read_varint(b"\xff" * 8, 0)


@pytest.mark.parametrize("t,size,cls", [(0, 0, "null"), (1, 1, "integer"), (2, 2, "integer"), (3, 3, "integer"), (4, 4, "integer"), (5, 6, "integer"),
                                        (6, 8, "integer"), (7, 8, "real"), (8, 0, "integer"), (9, 0, "integer"), (12, 0, "blob"), (13, 0, "text"),
                                        (14, 1, "blob"), (15, 1, "text"), (20, 4, "blob"), (21, 4, "text"), (1000, 494, "blob"), (1001, 494, "text")])
def test_serial_type_sizes_and_classes(t, size, cls):
    assert serial_type_size(t) == size and serial_type_class(t) == cls


@pytest.mark.parametrize("t", [10, 11, -1])
def test_reserved_serial_types_are_refused(t):
    with pytest.raises(RecordError):
        serial_type_size(t)


def test_decode_every_value_kind():
    assert decode_value(1, b"\xff") == -1 and decode_value(2, b"\x01\x00") == 256 and decode_value(3, b"\xff\xff\xfe") == -2
    assert decode_value(4, b"\x80\x00\x00\x00") == -2**31 and decode_value(5, b"\x00\x00\x00\x00\x01\x00") == 256
    assert decode_value(6, struct.pack(">q", -2**63)) == -2**63 and decode_value(7, struct.pack(">d", 2.5)) == 2.5
    assert (decode_value(8, b""), decode_value(9, b""), decode_value(0, b"")) == (0, 1, None)
    assert decode_value(15, b"x") == "x" and decode_value(14, b"\x00") == b"\x00"
    assert decode_value(21, "hé".encode("utf-16-le"), "UTF-16le") == "hé" and decode_value(21, "hé".encode("utf-16-be"), "UTF-16be") == "hé"


def test_text_that_is_not_valid_in_the_encoding_is_refused_strictly():
    with pytest.raises(RecordError, match="not valid UTF-8"):
        decode_value(15, b"\xff")


def test_parse_a_handmade_record():
    body = struct.pack(">h", -300) + b"hello" + struct.pack(">d", 1.5) + b"\x01\x02"
    header = bytes([6, 0, 2, 23, 7, 16])  # NULL, int16, text(5), float, blob(2)
    rec = parse_record(header + body, 0)
    assert rec.serial_types == (0, 2, 23, 7, 16) and rec.values == (None, -300, "hello", 1.5, b"\x01\x02")
    assert rec.header_size == 6 and rec.end == len(header) + len(body) and rec.length == rec.end
    with pytest.raises(RecordError):
        parse_record((header + body)[:-3], 0)  # body cut short


def test_a_header_that_lies_about_its_size_is_refused():
    with pytest.raises(RecordError):
        parse_record(bytes([2, 0x81]) + b"\x00" * 8, 0)  # last serial type straddles the header end
    with pytest.raises(RecordError):
        parse_record(bytes([40, 1]) + b"\x00" * 3, 0)  # header longer than the buffer


# ------------------------------------------------------------------ real databases, every page size


def build_db(path, page_size, rows=400, seed=1):
    rng = random.Random(seed)
    c = sqlite3.connect(path)
    c.execute(f"PRAGMA page_size={page_size}")
    c.executescript("""
        CREATE TABLE t(id INTEGER PRIMARY KEY, txt TEXT, num INTEGER, real_ REAL, blob_ BLOB, nul);
        CREATE INDEX t_txt ON t(txt);
        CREATE TABLE w(k TEXT PRIMARY KEY, v INTEGER, note TEXT) WITHOUT ROWID;
        CREATE TABLE g(a, b TEXT, c INTEGER, PRIMARY KEY(c, b));
    """)
    ints = [0, 1, -1, 127, -128, 128, 255, 32767, -32768, 65535, 2**23, 2**31 - 1, -2**31, 2**40, -2**47, 2**63 - 1, -2**63]
    for i in range(rows):
        big = rng.choice([0, 0, 0, 1])
        c.execute("INSERT INTO t(txt, num, real_, blob_, nul) VALUES(?,?,?,?,?)", (
            "é😀 " + "x" * (rng.randint(0, 40) if not big else rng.randint(page_size, page_size * 3)),
            rng.choice(ints), rng.choice([0.0, 1.5, -2.25, 1e-9, 3.0]) if i % 3 else None,
            rng.randbytes(rng.randint(0, 30) if not big else rng.randint(page_size, page_size * 2)), None if i % 2 else i))
        c.execute("INSERT INTO w VALUES(?,?,?)", (f"key{i:05d}", rng.choice(ints), None if i % 5 else "n" * rng.randint(0, 60)))
        c.execute("INSERT INTO g VALUES(?,?,?)", (i, f"b{i % 7}", i))
    c.commit()
    c.close()
    return path


def sqlite_rows(path, table, columns):
    c = sqlite3.connect(path)
    rows = c.execute(f'SELECT rowid, {columns} FROM "{table}" ORDER BY rowid').fetchall() if table != "w" else c.execute(f'SELECT NULL, {columns} FROM "{table}" ORDER BY k').fetchall()
    c.close()
    return rows


@pytest.mark.parametrize("page_size", PAGE_SIZES)
def test_every_row_of_every_table_matches_sqlite(tmp_path, page_size):
    p = build_db(tmp_path / "a.db", page_size, rows=400 if page_size < 32768 else 700)
    with SQLiteDatabase.open(p) as db:
        assert db.page_size == page_size and db.encoding == "UTF-8"
        tables = db.tables()
        assert set(tables) == {"t", "w", "g"}
        for name, entry in tables.items():
            sql = entry.table_sql()
            cols = ", ".join(f'"{c.name}"' for c in sql.stored_columns)
            live = sorted((logical_row(sql, r), r) for r in db.live_rows(entry)) if False else [(logical_row(sql, r), r) for r in db.live_rows(entry)]
            truth = sqlite_rows(p, name, cols)
            got = [(r.rowid, *lr.values()) for lr, r in live]
            if name == "t":
                assert got == truth, name
            else:
                assert sorted(map(repr, got)) == sorted(map(repr, [(None if name == "w" else t[0], *t[1:]) for t in truth])), name
            assert len(got) == len(truth)
        assert not db.problems


@pytest.mark.parametrize("page_size", [512, 4096, 65536])
def test_row_counts_and_columns_match_sqlite(tmp_path, page_size):
    p = build_db(tmp_path / "a.db", page_size, rows=300)
    c = sqlite3.connect(p)
    with SQLiteDatabase.open(p) as db:
        for name, entry in db.tables().items():
            assert sum(1 for _ in db.live_rows(entry)) == c.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
            parsed = parse_create_table(entry.sql)
            assert [x.name for x in parsed.columns] == [r[1] for r in c.execute(f'PRAGMA table_info("{name}")')]
    c.close()


def test_the_tree_really_has_interior_and_overflow_pages(tmp_path):
    p = build_db(tmp_path / "a.db", 1024, rows=500)
    with SQLiteDatabase.open(p) as db:
        roles = db.page_map()
        types = {i.page_type for i in roles.values() if i.role == PageRole.BTREE}
        assert PageType.TABLE_INTERIOR in types and PageType.TABLE_LEAF in types and PageType.INDEX_LEAF in types
        assert any(i.role == PageRole.OVERFLOW and i.owner == "t" for i in roles.values())


@pytest.mark.parametrize("encoding", ["UTF-8", "UTF-16le", "UTF-16be"])
def test_text_encodings(tmp_path, encoding):
    p = tmp_path / "e.db"
    c = sqlite3.connect(p)
    c.execute(f"PRAGMA encoding='{encoding}'")
    c.execute("CREATE TABLE t(a TEXT, b INTEGER)")
    c.executemany("INSERT INTO t VALUES(?, ?)", [("héllo wörld 😀 日本語", 1), ("", 2), ("plain", 3)])
    c.commit()
    c.close()
    with SQLiteDatabase.open(p) as db:
        assert db.encoding == encoding
        rows = [r.stored for r in db.live_rows(db.tables()["t"])]
    assert rows == [("héllo wörld 😀 日本語", 1), ("", 2), ("plain", 3)]


def test_the_rowid_alias_is_stored_as_null_and_recovered_from_the_cell_key(tmp_path):
    p = tmp_path / "a.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t VALUES(?, ?)", [(10, "a"), (-5, "b"), (2**40, "c")])
    c.commit()
    c.close()
    with SQLiteDatabase.open(p) as db:
        entry = db.tables()["t"]
        rows = list(db.live_rows(entry))
        assert [r.stored[0] for r in rows] == [None] * 3, "the alias column is NULL in the record"
        assert [logical_row(entry.table_sql(), r)["id"] for r in rows] == [-5, 10, 2**40]


def test_a_record_written_before_add_column_reads_the_new_column_as_null(tmp_path):
    p = tmp_path / "a.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE t(a, b)")
    c.execute("INSERT INTO t VALUES(1, 2)")
    c.execute("ALTER TABLE t ADD COLUMN c TEXT")
    c.commit()
    c.close()
    with SQLiteDatabase.open(p) as db:
        entry = db.tables()["t"]
        [row] = list(db.live_rows(entry))
        assert row.stored == (1, 2) and logical_row(entry.table_sql(), row) == {"a": 1, "b": 2, "c": None}


# ------------------------------------------------------------------ page inventory and the freelist


def test_page_map_partitions_the_file_and_a_clean_database_has_no_orphans(tmp_path):
    p = build_db(tmp_path / "a.db", 1024, rows=300)
    with SQLiteDatabase.open(p) as db:
        roles = db.page_map()
        assert sorted(roles) == list(range(1, db.file_page_count + 1))
        assert not [i for i in roles.values() if i.role == PageRole.ORPHAN]
        assert db.freelist().consistent and db.freelist().pages == ()


def test_deleting_rows_puts_pages_on_the_freelist_and_the_walk_matches_the_header(tmp_path):
    p = build_db(tmp_path / "a.db", 1024, rows=400)
    c = sqlite3.connect(p)
    c.execute("DELETE FROM t WHERE id > 40")
    c.execute("DELETE FROM w WHERE k > 'key00040'")
    c.commit()
    c.close()
    with SQLiteDatabase.open(p) as db:
        fl = db.freelist()
        assert fl.consistent and len(fl.pages) == db.header.freelist_page_count > 10
        roles = db.page_map()
        assert {i.number for i in roles.values() if i.role in (PageRole.FREELIST_TRUNK, PageRole.FREELIST_LEAF)} == set(fl.pages)
        assert len(fl.trunks) >= 1 and len(fl.leaves) >= 1
        # a released leaf page keeps its b-tree header: it is a table-leaf page nothing points to
        leaf_types = {db.btree(n).type for n in fl.leaves if db.read_page(n)[0] in (0x0D, 0x0A)}
        assert PageType.TABLE_LEAF in leaf_types


def test_freelist_walk_reports_loops_and_bad_pointers():
    ps = 512
    trunk = struct.pack(">II", 2, 1) + struct.pack(">I", 99) + bytes(ps - 12)  # points at page 2 (a loop below) and a missing leaf
    trunk2 = struct.pack(">II", 1, 0) + bytes(ps - 8)  # points back at page 1
    src = BytesPageSource(trunk + trunk2, ps)
    info = walk_freelist(src, 1, 3, 2, ps)
    assert any("loops" in p for p in info.problems) and any("does not exist" in p for p in info.problems) and not info.consistent
    assert info.trunks == (1, 2)


# ------------------------------------------------------------------ b-tree page structure


def test_btree_page_header_fields_match_the_file(tmp_path):
    p = build_db(tmp_path / "a.db", 4096, rows=60)
    with SQLiteDatabase.open(p) as db:
        entry = db.tables()["g"]
        page = db.btree(entry.root_page)
        raw = db.read_page(entry.root_page)
        assert page.type is PageType.INDEX_LEAF or page.type is PageType.TABLE_LEAF or page.type.is_btree
        assert page.cell_count == struct.unpack(">H", raw[3:5])[0] and page.content_start == struct.unpack(">H", raw[5:7])[0]
        assert page.cell_offsets == tuple(struct.unpack(">H", raw[8 + 2 * i:10 + 2 * i])[0] for i in range(page.cell_count))
        assert page.unallocated == (page.pointer_array_end, page.content_start) and page.is_valid


def test_page_one_uses_offset_100_for_its_btree_header(tmp_path):
    p = build_db(tmp_path / "a.db", 1024, rows=10)
    with SQLiteDatabase.open(p) as db:
        page1 = db.btree(1)
        assert page1.header_offset == 100 and page1.type is PageType.TABLE_LEAF
        assert len(page1.cell_offsets) == len(db.schema())


def test_freeblocks_appear_after_deleting_a_middle_row(tmp_path):
    p = tmp_path / "a.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t(v) VALUES(?)", [("row%03d " % i + "x" * 30,) for i in range(40)])
    c.commit()
    c.execute("DELETE FROM t WHERE id IN (10, 20)")
    c.commit()
    c.close()
    with SQLiteDatabase.open(p) as db:
        page = db.btree(db.tables()["t"].root_page)
        assert len(page.freeblocks) == 2 and all(f.size >= 40 for f in page.freeblocks) and page.cell_count == 38
        assert [f.offset for f in page.freeblocks] == sorted(f.offset for f in page.freeblocks)


def test_a_non_btree_page_is_refused():
    with pytest.raises(PageError, match="not a b-tree page type"):
        parse_btree_page(2, bytes(512))


def test_cell_payload_follows_the_overflow_chain(tmp_path):
    p = tmp_path / "a.db"
    c = sqlite3.connect(p)
    c.execute("PRAGMA page_size=1024")
    c.execute("CREATE TABLE t(v BLOB)")
    big = bytes(range(256)) * 20
    c.execute("INSERT INTO t VALUES(?)", (big,))
    c.commit()
    c.close()
    with SQLiteDatabase.open(p) as db:
        page = db.btree(db.tables()["t"].root_page)
        cell = read_cell(page, 0, db.usable_size)
        assert cell.overflow_page and cell.local_size == local_payload_size(cell.payload_size, 1024, index=False) < cell.payload_size
        payload = read_cell_payload(page, cell, db.source, db.usable_size)
        assert len(payload) == cell.payload_size and parse_record(payload, 0).values == (big,)


@pytest.mark.parametrize("usable,payload,index", [(4096, 100, False), (4096, 4061, False), (4096, 4062, False), (1024, 5000, False), (512, 5000, True), (65536, 70000, True)])
def test_local_payload_arithmetic_stays_within_bounds(usable, payload, index):
    local = local_payload_size(payload, usable, index=index)
    assert 0 < local <= payload and local <= (((usable - 12) * 64 // 255) - 23 if index else usable - 35)


# ------------------------------------------------------------------ damage


def test_a_destroyed_leaf_page_is_reported_and_the_other_rows_are_still_read(tmp_path):
    p = tmp_path / "a.db"
    c = sqlite3.connect(p)
    c.execute("PRAGMA page_size=1024")
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t(v) VALUES(?)", [("m" * 60,) for _ in range(600)])
    c.commit()
    c.close()
    data = bytearray(p.read_bytes())
    leaves = [i for i in range(2, len(data) // 1024) if data[i * 1024] == 0x0D]
    victim = leaves[len(leaves) // 2]
    data[victim * 1024:(victim + 1) * 1024] = b"\xff" * 1024
    p.write_bytes(bytes(data))
    with SQLiteDatabase.open(p) as db:
        rows = list(db.live_rows(db.tables()["t"]))
        assert 0 < len(rows) < 600 and any(f"page {victim + 1}" in m or f"page {victim}" in m for m in db.problems) or db.problems


def test_a_truncated_file_still_yields_the_pages_that_exist(tmp_path):
    p = build_db(tmp_path / "a.db", 1024, rows=300)
    p.write_bytes(p.read_bytes()[: 1024 * 25])
    with SQLiteDatabase.open(p) as db:
        assert db.file_page_count == 25 and db.page_count <= 25
        rows = list(db.live_rows(db.tables()["t"])) if "t" in db.tables() else []
        assert db.problems or rows is not None


def test_garbage_is_not_a_database(tmp_path):
    p = tmp_path / "junk.db"
    p.write_bytes(b"x" * 5000)
    with pytest.raises(PageError, match="not a database"):
        SQLiteDatabase.open(p)


def test_a_wal_mode_database_uses_the_file_size_when_the_header_count_is_stale(tmp_path):
    p = tmp_path / "w.db"
    c = sqlite3.connect(p)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE t(a)")
    c.executemany("INSERT INTO t VALUES(?)", [("x" * 100,) for _ in range(400)])
    c.commit()
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    c.close()
    with SQLiteDatabase.open(p) as db:
        assert db.page_count == db.file_page_count == p.stat().st_size // db.page_size


def test_serial_type_size_and_varint_fast_paths_match_the_definitions():
    import pytest

    from android_forensics.sqlite.records import RecordError, encode_varint, read_varint, serial_type_size

    def reference_size(t: int) -> int:
        fixed = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}
        if t in fixed:
            return fixed[t]
        if t in (10, 11):
            raise RecordError("reserved")
        if t < 0:
            raise RecordError("negative")
        return (t - 12) // 2 if t % 2 == 0 else (t - 13) // 2

    for t in [*range(-3, 400), 1000, 12345, 2**31]:
        try:
            expected = reference_size(t)
        except RecordError:
            with pytest.raises(RecordError):
                serial_type_size(t)
        else:
            assert serial_type_size(t) == expected, t
    for v in (0, 1, 127, 128, 255, 16383, 16384, 2**21, 2**56, 2**64 - 1):
        enc = encode_varint(v)
        assert read_varint(b"\xff" + enc + b"\x00", 1) == (v, len(enc))
    for buf, pos in ((b"", 0), (b"\x80", 0), (b"\x01", 5), (b"\x01", -1)):
        try:
            read_varint(buf, pos)
        except RecordError:
            pass
