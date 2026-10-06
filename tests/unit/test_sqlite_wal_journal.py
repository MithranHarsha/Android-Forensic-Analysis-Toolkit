"""Phase 4C: WAL and rollback-journal parsing, checked against files SQLite itself wrote."""

import shutil
import sqlite3
import struct

import pytest

from android_forensics.lab.deletions import DeletionCase, build_case
from android_forensics.lab.journal import build_hot_journal
from android_forensics.sqlite.journal import MAGIC, journal_checksum, parse_journal
from android_forensics.sqlite.wal import (
    COMMITTED,
    CORRUPT,
    EMPTY,
    FRAME_HEADER,
    STALE,
    STALE_UNVERIFIED,
    UNCOMMITTED,
    WAL_HEADER,
    parse_wal,
    wal_checksum,
)
from tests.unit.sqlite_helpers import numbered_db


def wal_pair(tmp_path, rows=60, checkpoint=None, name="w.db"):
    """A WAL-mode database whose ``-wal`` is copied while the writer is connected (so it is not checkpointed away)."""
    src = tmp_path / "_src" / name
    src.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(src)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t(v) VALUES(?)", [("row %d " % i + "x" * 80,) for i in range(rows)])
    c.commit()
    if checkpoint:
        c.execute(f"PRAGMA wal_checkpoint({checkpoint})")
    dest = tmp_path / "ev"
    dest.mkdir(exist_ok=True)
    shutil.copyfile(src, dest / name)
    shutil.copyfile(f"{src}-wal", dest / f"{name}-wal")
    c.close()
    return dest / name, dest / f"{name}-wal"


# ------------------------------------------------------------------ checksum


def test_checksum_follows_sqlites_algorithm():
    assert wal_checksum(bytes(8), big_endian=False) == (0, 0)
    data = struct.pack("<2I", 3, 5)
    s0 = 0 + 3 + 0
    s1 = 0 + 5 + s0
    assert wal_checksum(data, big_endian=False) == (s0, s1)
    assert wal_checksum(struct.pack(">2I", 3, 5), big_endian=True) == (s0, s1)
    assert wal_checksum(data, big_endian=True) != (s0, s1), "the word byte order changes the value"


def test_checksums_are_cumulative():
    a, b = struct.pack("<2I", 1, 2), struct.pack("<2I", 7, 9)
    assert wal_checksum(a + b, big_endian=False) == wal_checksum(b, *wal_checksum(a, big_endian=False), big_endian=False)


def test_checksum_input_must_be_a_multiple_of_eight():
    with pytest.raises(ValueError):
        wal_checksum(b"\x00" * 12, big_endian=False)


# ------------------------------------------------------------------ WAL files written by SQLite


def test_a_real_wal_validates_completely(tmp_path):
    _, wal = wal_pair(tmp_path)
    w = parse_wal(wal)
    assert w.header.checksum_valid and w.header.page_size == 4096 and w.header.magic in (0x377F0682, 0x377F0683)
    assert w.frames and all(f.status == COMMITTED for f in w.frames) and w.problems == []
    assert w.frames[-1].is_commit and [f.index for f in w.frames] == list(range(1, len(w.frames) + 1))
    assert {f.page_number for f in w.frames} >= {1, 2}
    assert w.size == WAL_HEADER + len(w.frames) * (FRAME_HEADER + 4096)


def test_a_flipped_byte_in_a_page_breaks_that_frame_and_every_frame_after_it(tmp_path):
    _, wal = wal_pair(tmp_path)
    data = bytearray(wal.read_bytes())
    slot = FRAME_HEADER + 4096
    data[WAL_HEADER + slot + FRAME_HEADER + 100] ^= 0xFF  # a byte of frame 2's page
    wal.write_bytes(bytes(data))
    w = parse_wal(wal)
    statuses = [f.status for f in w.frames]
    assert all(s == CORRUPT for s in statuses[1:]), "the checksum chain is cumulative: nothing after a broken frame can be trusted"
    assert statuses[0] == UNCOMMITTED, "frame 1 is intact, but the commit frame that would have made it visible is gone"


def test_a_damaged_header_checksum_is_reported_and_frames_are_no_longer_trusted(tmp_path):
    _, wal = wal_pair(tmp_path)
    data = bytearray(wal.read_bytes())
    data[24] ^= 0x01
    wal.write_bytes(bytes(data))
    w = parse_wal(wal)
    assert not w.header.checksum_valid and any("header checksum" in p for p in w.problems)
    assert all(f.status != COMMITTED for f in w.frames)


def test_a_wal_with_a_destroyed_header_still_yields_its_frames_when_the_page_size_is_known(tmp_path):
    _, wal = wal_pair(tmp_path)
    data = bytearray(wal.read_bytes())
    data[:4] = b"\x00\x00\x00\x00"
    wal.write_bytes(bytes(data))
    assert parse_wal(wal).frames == []
    w = parse_wal(wal, expected_page_size=4096)
    assert w.frames and all(f.status in (STALE, STALE_UNVERIFIED) for f in w.frames) and any("magic invalid" in p for p in w.problems)
    assert w.frames[1].status == STALE, "consecutive frames still verify against each other"


def test_a_transaction_that_never_committed_leaves_an_uncommitted_tail(tmp_path):
    src = tmp_path / "_src" / "u.db"
    src.parent.mkdir()
    c = sqlite3.connect(src)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.commit()
    c.isolation_level = None
    c.execute("PRAGMA cache_size=10")  # a tiny cache spills dirty pages into the WAL before the commit
    c.execute("BEGIN")
    c.executemany("INSERT INTO t(v) VALUES(?)", [("z" * 300,) for _ in range(400)])
    wal_copy = tmp_path / "u.db-wal"
    shutil.copyfile(f"{src}-wal", wal_copy)
    c.execute("ROLLBACK")
    c.close()
    w = parse_wal(wal_copy)
    counts = w.summary()
    if counts[UNCOMMITTED] == 0:
        pytest.skip("this SQLite kept the transaction in its cache: no frame reached the WAL before the commit")
    assert counts[COMMITTED] >= 1 and counts[UNCOMMITTED] >= 1
    first_unc = min(f.index for f in w.frames if f.status == UNCOMMITTED)
    assert all(f.status == COMMITTED for f in w.frames if f.index < first_unc), "uncommitted frames only ever follow committed ones"


def test_frames_left_over_from_an_earlier_wal_generation_are_stale(tmp_path):
    out = build_case(tmp_path, DeletionCase(name="s", condition="wal_stale"))
    w = parse_wal(out.sidecars["-wal"])
    counts = w.summary()
    assert counts[COMMITTED] >= 1 and counts[STALE] + counts[STALE_UNVERIFIED] >= 3
    first_stale = min(f.index for f in w.frames if f.status in (STALE, STALE_UNVERIFIED))
    assert all(f.status == COMMITTED for f in w.frames if f.index < first_stale)
    assert counts[STALE] >= counts[STALE_UNVERIFIED], "stale frames verify against their predecessor; only the first cannot"
    salts = {(f.salt1, f.salt2) for f in w.frames if f.status == COMMITTED}
    assert salts == {(w.header.salt1, w.header.salt2)} and not salts & {(f.salt1, f.salt2) for f in w.frames if f.status in (STALE, STALE_UNVERIFIED)}


def test_zero_filled_frame_slots_are_empty(tmp_path):
    _, wal = wal_pair(tmp_path)
    wal.write_bytes(wal.read_bytes() + bytes(FRAME_HEADER + 4096))
    w = parse_wal(wal)
    assert w.frames[-1].status == EMPTY and w.frames[-2].status == COMMITTED


def test_a_partly_written_last_frame_is_reported(tmp_path):
    _, wal = wal_pair(tmp_path)
    wal.write_bytes(wal.read_bytes() + b"\xAB" * 100)
    assert any("trailing bytes" in p for p in parse_wal(wal).problems)


def test_wal_shorter_than_its_header(tmp_path):
    p = tmp_path / "x-wal"
    p.write_bytes(b"\x37\x7f\x06\x82")
    w = parse_wal(p)
    assert w.header is None and w.frames == [] and any("shorter" in m for m in w.problems)


def test_wal_pages_can_be_read_back(tmp_path):
    db, wal = wal_pair(tmp_path)
    w = parse_wal(wal)
    frame = next(f for f in w.frames if f.page_number == 2)
    page = w.page(frame)
    assert len(page) == 4096 and page[0] in (0x0D, 0x05)


# ------------------------------------------------------------------ rollback journals


def hot_pair(tmp_path):
    before = numbered_db(tmp_path / "before.db", 300)
    after = tmp_path / "after.db"
    shutil.copyfile(before, after)
    c = sqlite3.connect(after)
    c.execute("UPDATE t SET v = 'X' || v")
    c.commit()
    c.close()
    n = build_hot_journal(before, after, tmp_path / "hot.db", tmp_path / "hot.db-journal")
    return before, tmp_path / "hot.db", tmp_path / "hot.db-journal", n


def test_a_hot_journal_parses_and_every_record_verifies(tmp_path):
    before, db, journal, n = hot_pair(tmp_path)
    j = parse_journal(journal, db_page_size=4096, db_page_count=before.stat().st_size // 4096)
    assert j.kind == "valid_header" and j.header_valid and len(j.records) == n == j.declared_records
    assert j.page_size == 4096 and j.sector_size == 512 and j.initial_db_pages == before.stat().st_size // 4096 and j.problems == []
    original = before.read_bytes()
    for r in j.records:
        assert j.page(r) == original[(r.page_number - 1) * 4096: r.page_number * 4096], "a journal record is the page as it was before"


def test_the_journal_checksum_matches_sqlites(tmp_path):
    _, _, journal, _ = hot_pair(tmp_path)
    data = journal.read_bytes()
    nonce = struct.unpack(">I", data[12:16])[0]
    page = data[512 + 4: 512 + 4 + 4096]
    assert struct.unpack(">I", data[512 + 4 + 4096: 512 + 8 + 4096])[0] == journal_checksum(page, nonce)


def test_a_bad_checksum_stops_the_reading_at_that_record(tmp_path):
    before, _, journal, n = hot_pair(tmp_path)
    data = bytearray(journal.read_bytes())
    data[512 + 4104 + 4 + 96] ^= 0xFF  # byte 96 of the second record's page: one of the bytes the checksum samples (every 200th)
    journal.write_bytes(bytes(data))
    j = parse_journal(journal, db_page_size=4096)
    assert len(j.records) == 1 and any("does not verify" in p for p in j.problems)


def test_the_journal_checksum_only_samples_every_200th_byte_so_other_damage_goes_unnoticed(tmp_path):
    """A property of SQLite's format, not of this parser: a flipped byte the checksum does not sample still verifies. Recovered
    journal content is therefore validated against the table schema as well, never trusted on the checksum alone."""
    _, _, journal, n = hot_pair(tmp_path)
    data = bytearray(journal.read_bytes())
    data[512 + 4104 + 4 + 100] ^= 0xFF  # byte 100 is not sampled
    journal.write_bytes(bytes(data))
    assert len(parse_journal(journal, db_page_size=4096).records) == n


def test_records_beyond_the_declared_count_are_still_read(tmp_path):
    """The header's count reflects the last sync only; the file may hold more verified records."""
    _, _, journal, n = hot_pair(tmp_path)
    data = bytearray(journal.read_bytes())
    data[8:12] = struct.pack(">I", 1)
    journal.write_bytes(bytes(data))
    j = parse_journal(journal, db_page_size=4096)
    assert len(j.records) == n and j.declared_records == 1 and any("declares 1" in p for p in j.problems)


def test_a_zeroed_journal_header_is_recovered_from_the_records_themselves(tmp_path):
    out = build_case(tmp_path, DeletionCase(name="p", condition="journal_persist"))
    j = parse_journal(out.sidecars["-journal"], db_page_size=4096, db_page_count=out.database.stat().st_size // 4096)
    assert j.kind == "zeroed_header" and not j.header_valid and j.records and j.nonce is not None
    assert any("derived from the first record" in p for p in j.problems)
    assert j.sector_size == 512 and all(r.checksum_ok for r in j.records)


def test_an_empty_journal_has_no_records(tmp_path):
    p = tmp_path / "e-journal"
    p.write_bytes(b"")
    assert parse_journal(p, db_page_size=4096).kind == "empty" and parse_journal(p, db_page_size=4096).records == []


def test_random_bytes_are_not_mistaken_for_a_journal(tmp_path):
    import os

    p = tmp_path / "r-journal"
    p.write_bytes(os.urandom(20000))
    j = parse_journal(p, db_page_size=4096, db_page_count=10)
    assert not j.header_valid and j.records == [] and any("no verifiable page records" in m for m in j.problems)


def test_a_journal_whose_page_size_disagrees_with_the_database_is_flagged(tmp_path):
    _, _, journal, _ = hot_pair(tmp_path)
    j = parse_journal(journal, db_page_size=1024)
    assert any("differs from the database" in p for p in j.problems)
    assert MAGIC == journal.read_bytes()[:8]


def test_oversized_sidecars_are_reported_not_read_into_memory(tmp_path, monkeypatch):
    from android_forensics import config
    from android_forensics.sqlite.journal import parse_journal
    from android_forensics.sqlite.wal import parse_wal

    monkeypatch.setattr(config, "MAX_SIDECAR_BYTES", 1000)
    (tmp_path / "x-wal").write_bytes(b"\x00" * 5000)
    (tmp_path / "x-journal").write_bytes(b"\x00" * 5000)
    w = parse_wal(tmp_path / "x-wal", expected_page_size=4096)
    j = parse_journal(tmp_path / "x-journal", db_page_size=4096)
    for info in (w, j):
        assert info.size == 5000 and info.problems and "over the 1,000-byte limit" in info.problems[0]
    assert w.frames == [] and w.data == b"" and j.data == b""
