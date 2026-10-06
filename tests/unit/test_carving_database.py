"""Phase 6: carving inside SQLite files. Live rows and already-recovered rows are skipped; free space and history are carved."""

from __future__ import annotations

import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from android_forensics.carving import (
    CarveSource,
    carve_database_file,
    journal_exclusions,
    main_file_exclusions,
    wal_exclusions,
)
from android_forensics.lab.journal import build_hot_journal
from android_forensics.models import CarveKind
from android_forensics.sqlite.journal import parse_journal
from android_forensics.sqlite.parser import SQLiteDatabase
from android_forensics.sqlite.recover_db import recover_database
from android_forensics.sqlite.wal import COMMITTED, parse_wal
from tests.unit.recovery_fixtures import SMS_DDL, build_table_db, sms_row

NOW = datetime(2026, 1, 1, tzinfo=UTC)
SRC = CarveSource(evidence_file_id=1, source_file="stub.db", source_sha256="cd" * 32)


def number(i: int) -> str:
    return f"+1202555{i:04d}"


def stub_db(path: Path, rows: int = 40, delete: str | None = "id BETWEEN 10 AND 19") -> Path:
    """``stub(id, number)``: two columns, so the recovery engine (which needs three to tell a record from noise) cannot read its
    freed cells -- only carving can find what they still hold."""
    for suffix in ("", "-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)
    c = sqlite3.connect(path)
    c.execute("PRAGMA secure_delete=OFF")
    c.execute("CREATE TABLE stub(id INTEGER PRIMARY KEY, number TEXT)")
    c.executemany("INSERT INTO stub VALUES(?,?)", [(i, number(i)) for i in range(1, rows + 1)])
    c.commit()
    if delete:
        c.execute(f"DELETE FROM stub WHERE {delete}")
        c.commit()
    c.close()
    return path


def phones(result) -> set[str]:
    return {c.matched for c in result.candidates if c.kind is CarveKind.PHONE_NUMBER}


def carve_main(path, wal=None, recovered=()):
    with SQLiteDatabase.open(path) as db:
        ex = main_file_exclusions(db, wal, recovered)
    return carve_database_file(path, SRC, ex, now=NOW)


# ------------------------------------------------------------------ the main file


def test_live_rows_are_skipped_and_the_bytes_of_deleted_rows_are_carved(tmp_path):
    path = stub_db(tmp_path / "stub.db")
    result = carve_main(path)
    assert phones(result) == {number(i) for i in range(10, 20)}, "exactly the deleted rows: the 30 live ones belong to the parsers"
    assert result.stats["excluded_overlaps"] >= 30, "the live cells were found and set aside, not missed"


def test_hits_inside_a_database_are_tagged_as_free_space_and_locate_the_real_bytes(tmp_path):
    path = stub_db(tmp_path / "stub.db")
    data = path.read_bytes()
    result = carve_main(path)
    assert result.candidates
    for c in result.candidates:
        assert c.container == "sqlite_free_space" and c.context_valid
        assert data[c.offset:c.offset + c.length].decode() == c.matched


def test_without_the_exclusions_the_live_rows_would_be_carved_too(tmp_path):
    """The control: the same file carved blind reports all 40 numbers, so the 30 missing above were excluded on purpose."""
    path = stub_db(tmp_path / "stub.db")
    blind = carve_database_file(path, SRC, [], now=NOW)
    assert phones(blind) == {number(i) for i in range(1, 41)}


def test_a_database_with_nothing_deleted_has_nothing_to_carve(tmp_path):
    result = carve_main(stub_db(tmp_path / "stub.db", delete=None))
    assert result.candidates == [] and result.stats["excluded_overlaps"] >= 40, "every live value was found and set aside"


def test_rows_recovery_already_reported_are_not_carved_again(tmp_path):
    path = tmp_path / "mmssms.db"
    build_table_db(path, SMS_DDL, "sms", sms_row, 60, "_id % 4 = 0")
    report = recover_database(path)
    assert report.rows
    ranges = [(r.file_offset, r.length) for r in report.rows]

    def inside_reported(result):
        return [c for c in result.candidates if any(c.offset < o + n and o < c.offset + c.length for o, n in ranges)]

    assert inside_reported(carve_main(path)), "carved blind, the reported rows' bytes are full of hits ..."
    assert not inside_reported(carve_main(path, recovered=ranges)), "... and once recovery has them, they are not repeated"


def test_a_released_page_is_carved_even_though_it_once_held_live_cells(tmp_path):
    path = stub_db(tmp_path / "stub.db", rows=600, delete="id > 20")  # most of the table's pages are released to the freelist
    with SQLiteDatabase.open(path) as db:
        assert len(db.freelist().pages) >= 3
    found = phones(carve_main(path))
    assert len(found) > 300 and number(300) in found and number(600) in found


# ------------------------------------------------------------------ the WAL


def wal_pair(dest: Path) -> Path:
    """40 rows checkpointed into the main file, then rows 10-19 deleted *in the WAL* (files copied while the writer is connected)."""
    dest.mkdir(parents=True, exist_ok=True)
    src = dest / "_src.db"
    for suffix in ("", "-wal", "-shm"):
        Path(f"{src}{suffix}").unlink(missing_ok=True)
    w = sqlite3.connect(src)
    w.execute("PRAGMA journal_mode=WAL")
    w.execute("PRAGMA wal_autocheckpoint=0")
    w.execute("PRAGMA secure_delete=OFF")
    w.execute("CREATE TABLE stub(id INTEGER PRIMARY KEY, number TEXT)")
    w.executemany("INSERT INTO stub VALUES(?,?)", [(i, number(i)) for i in range(1, 41)])
    w.commit()
    w.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    w.execute("DELETE FROM stub WHERE id BETWEEN 10 AND 19")
    w.commit()
    for suffix in ("", "-wal"):
        shutil.copyfile(f"{src}{suffix}", dest / f"w.db{suffix}")
    w.close()
    return dest / "w.db"


def test_a_page_the_wal_has_replaced_is_history_and_its_old_rows_are_carved(tmp_path):
    main = wal_pair(tmp_path)
    wal = parse_wal(f"{main}-wal", expected_page_size=4096)
    assert wal.count(COMMITTED) >= 1
    assert phones(carve_main(main)) == set(), "on its own the main file's page looks current: its 40 rows are live cells"
    with_wal = phones(carve_main(main, wal=wal))
    assert with_wal == {number(i) for i in range(1, 41)}, "the WAL replaced that page: what the main file holds is history"


def test_the_current_wal_frame_is_skipped_but_its_free_space_is_carved(tmp_path):
    main = wal_pair(tmp_path)
    wal_path = Path(f"{main}-wal")
    wal = parse_wal(wal_path, expected_page_size=4096)
    with SQLiteDatabase.open(main) as db:
        ex = wal_exclusions(wal, db)
    result = carve_database_file(wal_path, CarveSource(2, "w.db-wal", "ef" * 32), ex, now=NOW)
    assert phones(result) == {number(i) for i in range(10, 20)}, "the 30 rows still live in the newest frame are not repeated"
    assert all(c.container == "sqlite_free_space" and c.evidence_file_id == 2 for c in result.candidates)


def test_older_wal_frames_are_history_and_are_carved_whole(tmp_path):
    """Two commits touching the same page leave two frames for it; only the newest is current."""
    path = tmp_path / "h.db"
    w = sqlite3.connect(path)
    w.execute("PRAGMA journal_mode=WAL")
    w.execute("PRAGMA wal_autocheckpoint=0")
    w.execute("PRAGMA secure_delete=OFF")
    w.execute("CREATE TABLE stub(id INTEGER PRIMARY KEY, number TEXT)")
    w.executemany("INSERT INTO stub VALUES(?,?)", [(i, number(i)) for i in range(1, 21)])
    w.commit()
    w.execute("UPDATE stub SET number = '+13035550' || substr(number, -3) WHERE id <= 20")  # rewrites every row on the page
    w.commit()
    for suffix in ("", "-wal"):
        shutil.copyfile(f"{path}{suffix}", tmp_path / f"c.db{suffix}")
    w.close()
    copy = tmp_path / "c.db"
    wal = parse_wal(f"{copy}-wal", expected_page_size=4096)
    with SQLiteDatabase.open(copy) as db:
        ex = wal_exclusions(wal, db)
    found = phones(carve_database_file(f"{copy}-wal", SRC, ex, now=NOW))
    assert {number(i) for i in range(1, 21)} <= found, "the pre-update values survive in the older frame"
    assert not any(n.startswith("+13035550") for n in found), "the newest frame's rows are live: carved by the parsers, not here"


# ------------------------------------------------------------------ the rollback journal


def test_a_journal_holds_the_pages_as_they_were_before_the_transaction_and_they_are_carved(tmp_path):
    before, after = tmp_path / "before.db", tmp_path / "after.db"
    stub_db(before, delete=None)
    shutil.copyfile(before, after)
    c = sqlite3.connect(after)
    c.execute("PRAGMA secure_delete=ON")
    c.execute("UPDATE stub SET number = 'redacted-' || id")  # the interrupted transaction wipes every number
    c.commit()
    c.close()
    db_path, journal = tmp_path / "p.db", tmp_path / "p.db-journal"
    build_hot_journal(before, after, db_path, journal)
    info = parse_journal(journal, db_page_size=4096)
    assert info.records
    with SQLiteDatabase.open(db_path) as db:
        ex = journal_exclusions(info, db)
        main = carve_main(db_path)
    result = carve_database_file(journal, CarveSource(3, "p.db-journal", "12" * 32), ex, now=NOW)
    assert phones(result) == {number(i) for i in range(1, 41)}, "the wiped numbers are all still in the journal's copies"
    assert phones(main) == set(), "and nowhere in the database the transaction left behind"
    assert all(c.evidence_file_id == 3 for c in result.candidates)
