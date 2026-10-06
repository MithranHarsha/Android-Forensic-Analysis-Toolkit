"""Property-based fuzzing: hostile bytes must produce a *declared* error or a result — never an unexpected exception,
a hang or an unbounded allocation. Run a longer campaign with  HYPOTHESIS_PROFILE=ci  (or =soak)."""

from __future__ import annotations

import gzip
import sqlite3
import struct
import time
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from android_forensics.acquisition.image.ext4 import Ext4FileSystem
from android_forensics.acquisition.image.source import ImageError, RawImageSource, open_image
from android_forensics.acquisition.safety import UnsafePathError, normalize_member_path
from android_forensics.carving.carver import CarveSource, carve_bytes
from android_forensics.sqlite.ddl import DdlError, parse_create_table
from android_forensics.sqlite.header import parse_header
from android_forensics.sqlite.journal import parse_journal
from android_forensics.sqlite.pages import PageError, parse_btree_page, read_cell
from android_forensics.sqlite.parser import SQLiteDatabase
from android_forensics.sqlite.records import RecordError, parse_record, read_varint
from android_forensics.sqlite.recover_db import recover_database
from android_forensics.sqlite.wal import parse_wal

FIX = Path(__file__).resolve().parents[1] / "fixtures"
BLOB = st.binary(max_size=4096)


# ---------------------------------------------------------------------------- pure functions


@given(st.text(max_size=200))
def test_member_paths_are_safe_or_rejected(name):
    try:
        out = normalize_member_path(name)
    except UnsafePathError:
        return
    parts = out.split("/")
    assert ".." not in parts and "" not in parts and "." not in parts
    assert not out.startswith("/") and "\x00" not in out and "\\" not in out
    assert not (len(out) >= 2 and out[1] == ":" and out[0].isascii() and out[0].isalpha())


@given(st.lists(st.sampled_from(["..", ".", "", "a", "b c", "ü", "\\", "C:", "\x00", "…"]), max_size=12).map("/".join))
def test_traversal_shaped_member_paths(name):
    try:
        out = normalize_member_path(name)
    except UnsafePathError:
        return
    assert ".." not in out.split("/") and not out.startswith("/")


@given(BLOB, st.integers(min_value=0, max_value=5000))
def test_varint_never_over_reads(buf, pos):
    try:
        value, length = read_varint(buf, pos)
    except RecordError:
        return
    assert 0 <= value < 2**64 and 1 <= length <= 9 and pos + length <= len(buf)


@given(BLOB)
def test_record_parser_only_raises_its_own_error(buf):
    try:
        parse_record(buf, 0)
    except RecordError:
        pass


@given(BLOB)
def test_header_parser_never_raises(buf):
    parse_header(buf)


@given(st.text(max_size=300))
def test_ddl_parser(sql):
    try:
        parse_create_table("CREATE TABLE " + sql)
    except DdlError:
        pass


_DDL_PIECES = st.sampled_from(["(", ")", ",", ".", "a", "b INTEGER", "PRIMARY KEY", "PRIMARY", "KEY", "CONSTRAINT", "c", "NOT NULL",
                               "DEFAULT", "'x'", '"q"', "[r]", "`s`", "GENERATED ALWAYS AS (", "AUTOINCREMENT", "UNIQUE", "CHECK(", " ", "--", "/*"])


@given(st.lists(_DDL_PIECES, max_size=25).map(" ".join))
def test_ddl_parser_on_structured_garbage(body):
    for prefix in ("CREATE TABLE t(", "CREATE TABLE s.t(", "CREATE TABLE IF NOT EXISTS t (", "CREATE VIRTUAL TABLE v USING "):
        try:
            parse_create_table(prefix + body)
        except DdlError:
            pass


@given(st.binary(min_size=512, max_size=4096), st.integers(min_value=1, max_value=4))
def test_btree_page_and_cells(data, number):
    try:
        page = parse_btree_page(number, data)
        for i in range(min(page.cell_count, 50)):
            read_cell(page, i, len(data))
    except PageError:
        pass


@given(BLOB)
def test_carver_output_is_always_unconfirmed(data):
    res = carve_bytes(data, CarveSource(evidence_file_id=1, source_file="f", source_sha256="0" * 64, container="file"))
    for c in res.candidates:
        assert c.status == "CARVED CANDIDATE"
        assert str(getattr(c, "confidence", "")).upper() != "HIGH"


@pytest.mark.parametrize("sql", ["CREATE TABLE :.", "CREATE TABLE s.", "CREATE TABLE t(", "CREATE TABLE", "CREATE"])
def test_ddl_regressions_found_by_fuzzing(sql):
    with pytest.raises(DdlError):
        parse_create_table(sql)


@pytest.mark.parametrize("sql", ["CREATE TABLE t(a,,b)", "CREATE TABLE t(,)", "CREATE TABLE t(PRIMARY KEY())", "CREATE TABLE t(a, PRIMARY KEY(,))"])
def test_ddl_odd_but_survivable(sql):
    try:
        parse_create_table(sql)
    except DdlError:
        pass

# ---------------------------------------------------------------------------- mutated real databases


@pytest.fixture(scope="module")
def good_db(tmp_path_factory) -> bytes:
    p = tmp_path_factory.mktemp("fz") / "good.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT)")
    c.executemany("INSERT INTO sms VALUES(?,?,?,?,?)", [(i, f"+1202555{i:04d}", 1709280000000 + i, 1 + i % 2, f"message number {i} " * 6) for i in range(1, 120)])
    c.commit()
    c.execute("DELETE FROM sms WHERE _id % 7 = 0")
    c.commit()
    c.close()
    return p.read_bytes()


def mutations(size: int):
    return st.lists(st.tuples(st.integers(0, size - 1), st.integers(0, 255)), min_size=1, max_size=40)


def test_mutated_database_never_crashes_the_page_reader_or_recovery(good_db, tmp_path):
    @given(mutations(len(good_db)))
    def run(muts):
        raw = bytearray(good_db)
        for off, val in muts:
            raw[off] = val
        p = tmp_path / "m.db"
        p.write_bytes(bytes(raw))
        t0 = time.monotonic()
        try:
            with SQLiteDatabase.open(p) as db:
                for entry in db.schema():
                    try:
                        list(db.live_rows(entry))
                    except (PageError, RecordError):
                        pass
                try:
                    db.freelist()
                    db.page_map()
                except (PageError, RecordError):
                    pass
        except (PageError, RecordError, OSError):
            pass
        report = recover_database(p, None, scratch=tmp_path / "scratch")
        assert report is not None
        assert time.monotonic() - t0 < 20, "a mutated database must not make the engine hang"

    (tmp_path / "scratch").mkdir()
    run()


def test_truncated_database_at_every_page_boundary(good_db, tmp_path):
    for cut in range(0, len(good_db), 1024):
        p = tmp_path / f"t{cut}.db"
        p.write_bytes(good_db[:cut])
        try:
            with SQLiteDatabase.open(p) as db:
                for entry in db.schema():
                    list(db.live_rows(entry))
        except (PageError, RecordError, OSError):
            pass
        recover_database(p, None, scratch=tmp_path)


@given(data=BLOB)
def test_wal_and_journal_parsers_accept_arbitrary_bytes(tmp_path_factory, data):
    d = tmp_path_factory.mktemp("wj")
    (d / "x-wal").write_bytes(data)
    (d / "x-journal").write_bytes(data)
    parse_wal(d / "x-wal", expected_page_size=4096)
    parse_journal(d / "x-journal", db_page_size=4096, db_page_count=10)


# ---------------------------------------------------------------------------- hostile images


@pytest.fixture(scope="module")
def ext4_raw() -> bytes:
    return gzip.decompress((FIX / "ext4_4k_extents.img.gz").read_bytes())


def test_mutated_ext4_only_raises_image_errors_and_stays_bounded(ext4_raw, tmp_path):
    meta = 64 * 1024   # the metadata-dense region: superblock, group descriptors, inode table and directory blocks

    @given(st.lists(st.tuples(st.integers(0, meta - 1), st.integers(0, 255)), min_size=1, max_size=30))
    def run(muts):
        raw = bytearray(ext4_raw)
        for off, val in muts:
            raw[off] = val
        p = tmp_path / "e.img"
        p.write_bytes(bytes(raw))
        t0 = time.monotonic()
        try:
            with RawImageSource(p) as src:
                fs = Ext4FileSystem(src)
                n = 0
                for e in fs.walk():
                    n += 1
                    if e.inode.is_file and e.inode.size < 2_000_000 and not e.inode.encrypted:
                        try:
                            fs.read_all(e.inode, limit=4_000_000)
                        except ImageError:
                            pass
                    if n > 5000:
                        break
        except (ImageError, struct.error):
            pass
        assert time.monotonic() - t0 < 20

    run()


def test_mutated_ewf_and_sparse_only_raise_image_errors(tmp_path):
    ewf = (FIX / "ewf" / "ext4_best.E01").read_bytes()

    @given(st.lists(st.tuples(st.integers(0, len(ewf) - 1), st.integers(0, 255)), min_size=1, max_size=20))
    def run(muts):
        raw = bytearray(ewf)
        for off, val in muts:
            raw[off] = val
        p = tmp_path / "f.E01"
        p.write_bytes(bytes(raw))
        try:
            with open_image(p) as src:
                src.read_at(0, 1 << 20)
                getattr(src, "verify", lambda: None)()
        except ImageError:
            pass

    run()

    @given(BLOB)
    def sparse(tail):
        p = tmp_path / "s.simg"
        p.write_bytes(struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 4096, 4, 3, 0) + tail)
        try:
            with open_image(p) as src:
                src.read_at(0, 4096 * 4)
        except ImageError:
            pass

    sparse()


def test_mutated_f2fs_only_raises_image_errors_and_stays_bounded(tmp_path):
    from android_forensics.acquisition.image.f2fs import F2fsFileSystem

    raw = gzip.decompress((FIX / "f2fs" / "kernel_extra_clean.img.gz").read_bytes())
    meta = 24 * 1024 * 1024   # superblock, checkpoints, SIT, NAT, SSA and the first part of the main area (inodes, dentries)

    @given(st.lists(st.tuples(st.integers(0, meta - 1), st.integers(0, 255)), min_size=1, max_size=40))
    def run(muts):
        buf = bytearray(raw)
        for off, val in muts:
            buf[off] = val
        p = tmp_path / "f.img"
        p.write_bytes(bytes(buf))
        t0 = time.monotonic()
        try:
            with RawImageSource(p) as src:
                fs = F2fsFileSystem(src)
                n = 0
                for e in fs.walk():
                    n += 1
                    if e.inode.is_file and e.inode.size < 2_000_000 and not e.inode.encrypted:
                        try:
                            fs.read_all(e.inode, limit=4_000_000)
                        except ImageError:
                            pass
                    if n > 3000:
                        break
        except (ImageError, struct.error):
            pass
        assert time.monotonic() - t0 < 30

    run()
