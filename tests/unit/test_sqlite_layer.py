import hashlib
import shutil
import sqlite3

import pytest

from android_forensics.sqlite.header import inspect_database_file, parse_header
from android_forensics.sqlite.reader import SQLiteOpenError, SQLiteSession
from android_forensics.sqlite.sidecars import inspect_journal, inspect_shm, inspect_wal


def make_db(path, rows=200, page_size=4096):
    c = sqlite3.connect(path)
    c.execute(f"PRAGMA page_size={page_size}")
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t(v) VALUES(?)", [("x" * 100,) for _ in range(rows)])
    c.commit()
    c.close()


@pytest.mark.parametrize("page_size", [512, 1024, 4096, 16384, 65536])
def test_header_parses_common_page_sizes(tmp_path, page_size):
    p = tmp_path / "a.db"
    make_db(p, 50, page_size)
    rep = inspect_database_file(p)
    assert rep.header.valid and rep.header.page_size == page_size
    assert rep.size_consistent is True
    assert rep.header.text_encoding == "UTF-8"


def test_header_reports_freelist_after_delete(tmp_path):
    p = tmp_path / "a.db"
    make_db(p, 400)
    c = sqlite3.connect(p)
    c.execute("DELETE FROM t WHERE id > 20")
    c.commit()
    c.close()
    h = inspect_database_file(p).header
    assert h.freelist_page_count and h.freelist_page_count > 0
    assert h.first_freelist_trunk


def test_header_detects_truncation_and_garbage(tmp_path):
    p = tmp_path / "a.db"
    make_db(p, 300)
    data = p.read_bytes()
    (tmp_path / "cut.db").write_bytes(data[: len(data) // 2 + 17])
    rep = inspect_database_file(tmp_path / "cut.db")
    assert rep.header.valid and rep.size_consistent is False
    assert any("truncated" in n for n in rep.notes)
    assert not parse_header(b"x" * 100).magic_ok
    assert not parse_header(b"SQLite format 3\x00").valid
    bad = bytearray(data[:100])
    bad[16:18] = (1000).to_bytes(2, "big")
    assert not parse_header(bytes(bad)).valid


def test_wal_journal_shm_facts(tmp_path):
    p = tmp_path / "w.db"
    conn = sqlite3.connect(p)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE t(a)")
    conn.executemany("INSERT INTO t VALUES(?)", [(i,) for i in range(50)])
    conn.commit()
    wal = inspect_wal(tmp_path / "w.db-wal", 4096)
    assert wal.magic_valid and wal.page_size == 4096 and wal.frame_slots and wal.frame_slots >= 1
    assert wal.matches_db_page_size is True
    shm = inspect_shm(tmp_path / "w.db-shm")
    assert shm.format_version == 3007000 and shm.max_frame == wal.frame_slots
    conn.close()
    z = tmp_path / "z-journal"
    z.write_bytes(b"\0" * 600)
    assert inspect_journal(z, 4096).header_zeroed


def test_reader_never_modifies_preserved_copy_and_sees_wal(tmp_path):
    src = tmp_path / "src.db"
    w = sqlite3.connect(src)
    w.execute("PRAGMA journal_mode=WAL")
    w.execute("PRAGMA wal_autocheckpoint=0")
    w.execute("CREATE TABLE t(a)")
    w.executemany("INSERT INTO t VALUES(?)", [(i,) for i in range(10)])
    w.commit()
    ev = tmp_path / "ev"
    ev.mkdir()
    for suffix in ("", "-wal", "-shm"):
        shutil.copyfile(f"{src}{suffix}", ev / f"a.db{suffix}")
    w.close()
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in ev.iterdir()}
    scratch = tmp_path / "scratch"
    with SQLiteSession(ev / "a.db", {"-wal": ev / "a.db-wal", "-shm": ev / "a.db-shm"}, scratch) as s:
        assert [o.row_count for o in s.schema() if o.name == "t"] == [10]
        assert s.integrity() == ["ok"]
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in ev.iterdir()}
    assert before == after
    assert not any(scratch.iterdir())


def test_reader_errors_and_decoding(tmp_path):
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"x" * 5000)
    with pytest.raises(SQLiteOpenError):
        with SQLiteSession(junk, {}, tmp_path / "s"):
            pass
    p = tmp_path / "bad.db"
    c = sqlite3.connect(p)
    c.text_factory = bytes
    c.execute("CREATE TABLE t(a TEXT)")
    c.execute("INSERT INTO t VALUES(?)", (b"ok",))
    c.execute("INSERT INTO t VALUES(CAST(? AS TEXT))", (b"\xff\xfe bad",))
    c.commit()
    c.close()
    with SQLiteSession(p, {}, tmp_path / "s") as s:
        rows = list(s.iter_rows("t"))
        assert len(rows) == 2
        assert s.decode_errors == 1


def test_android_collation_and_without_rowid(tmp_path):
    p = tmp_path / "c.db"
    c = sqlite3.connect(p)
    c.create_collation("LOCALIZED", lambda a, b: (a > b) - (a < b))
    c.execute("CREATE TABLE t(a TEXT COLLATE LOCALIZED, b)")
    c.execute("CREATE INDEX i ON t(a)")
    c.execute("CREATE TABLE w(k TEXT PRIMARY KEY, v) WITHOUT ROWID")
    c.execute("INSERT INTO t VALUES('x', 1)")
    c.execute("INSERT INTO w VALUES('k', 1)")
    c.commit()
    c.close()
    with SQLiteSession(p, {}, tmp_path / "s") as s:
        objs = {o.name: o for o in s.schema()}
        assert objs["t"].row_count == 1 and objs["w"].rowid_table is False
        assert list(s.iter_rows(objs["w"]))[0][0] is None
        assert list(s.iter_rows(objs["t"]))[0][0] == 1


@pytest.mark.parametrize("mode,expected", [("NONE", "none"), ("FULL", "full"), ("INCREMENTAL", "incremental")])
def test_header_reports_auto_vacuum_mode(tmp_path, mode, expected):
    p = tmp_path / "av.db"
    c = sqlite3.connect(p)
    c.execute(f"PRAGMA auto_vacuum={mode}")
    c.execute("CREATE TABLE t(a)")
    c.execute("INSERT INTO t VALUES(1)")
    c.commit()
    c.close()
    assert inspect_database_file(p).header.auto_vacuum == expected


def test_header_accepts_a_database_that_never_had_a_schema(tmp_path):
    """A pragma alone writes the header with text encoding 0 and schema format 0. SQLite opens that file; it is not corrupt."""
    p = tmp_path / "never_had_a_table.db"
    c = sqlite3.connect(p)
    c.execute("PRAGMA user_version=7")
    c.commit()
    c.close()
    h = inspect_database_file(p).header
    assert h.valid and h.user_version == 7 and h.text_encoding is None and h.schema_format == 0
    assert any("never had a schema" in w for w in h.warnings)
    # ...but either field being 0 on its own, or an unknown value, is still corruption
    data = bytearray(p.read_bytes()[:100])
    data[56:60] = (1).to_bytes(4, "big")  # an encoding with no schema format
    assert not parse_header(bytes(data)).valid
    data[56:60] = (0).to_bytes(4, "big")
    data[44:48] = (4).to_bytes(4, "big")  # a schema format with no encoding
    assert not parse_header(bytes(data)).valid
