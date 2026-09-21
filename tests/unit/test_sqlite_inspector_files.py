"""SQLiteInspector: sidecars, damaged and non-SQLite files, the read-only guarantee, and agreement with the rest of the tool."""

import hashlib
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

from android_forensics.errors import InspectionError
from android_forensics.filesystem.scanner import scan_directory
from android_forensics.models.enums import OpenStatus, SqliteStatus
from android_forensics.sqlite.header import inspect_database_file
from android_forensics.sqlite.inspector import SQLiteInspector
from android_forensics.sqlite.reader import SQLiteSession
from tests.conftest import tree_hash
from tests.unit.sqlite_helpers import collated_db, corrupt_middle_leaf, hot_journal_snapshot, numbered_db, wal_snapshot

is_root = hasattr(os, "geteuid") and os.geteuid() == 0
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions/symlinks")


def inspect(path, **kw):
    return SQLiteInspector.inspect(path, **kw)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot(root: Path) -> dict[str, tuple[int, int, str]]:
    return {str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns, sha(p)) for p in sorted(root.rglob("*")) if p.is_file()}


# ------------------------------------------------------------------ WAL, SHM and journal files


class TestWal:
    def test_committed_wal_rows_are_part_of_the_active_view(self, tmp_path):
        p = wal_snapshot(tmp_path / "ev")
        r = inspect(p)
        t = r.table("t")
        assert t.row_count == 8 and [x.values[1] for x in t.records] == [f"main-{i}" for i in range(5)] + [f"wal-{i}" for i in range(3)]
        assert r.engine.view_includes_wal is True and r.engine.applied_sidecars == ["wal", "shm"] and r.integrity.status == "ok"
        assert r.engine.wal_frames_valid >= 1, "SQLite's own count of the WAL frames it validated"

    def test_wal_and_shm_are_detected_with_their_facts(self, tmp_path):
        p = wal_snapshot(tmp_path / "ev")
        r = inspect(p)
        assert [s.kind.value for s in r.sidecars] == ["wal", "shm"]
        wal, shm = r.sidecar("wal"), r.sidecar("shm")
        real = Path(f"{p}-wal")
        assert wal.path == str(real.resolve()) and wal.size == real.stat().st_size and wal.sha256 == sha(real) and wal.applied
        assert wal.header_valid is True and wal.wal.magic_valid and wal.wal.page_size == 4096 and wal.wal.matches_db_page_size is True
        assert wal.wal.frame_slots >= 1 and wal.shm is None and wal.journal is None
        assert shm.shm.format_version == 3007000 and shm.shm.max_frame > 0 and shm.header_valid is None and shm.sha256 == sha(f"{p}-shm")

    def test_without_applying_sidecars_the_view_is_the_main_file_alone(self, tmp_path):
        r = inspect(wal_snapshot(tmp_path / "ev"), apply_sidecars=False)
        assert r.table("t").row_count == 5 and r.engine.view_includes_wal is False and r.engine.applied_sidecars == []
        assert not r.engine.wal_frames_valid
        assert [s.kind.value for s in r.sidecars] == ["wal", "shm"] and not any(s.applied for s in r.sidecars), "still detected, just not applied"
        assert any("apply_sidecars=False" in n for n in r.engine.notes)

    def test_a_wal_mode_database_whose_wal_is_missing(self, tmp_path):
        p = wal_snapshot(tmp_path / "ev")
        Path(f"{p}-wal").unlink()
        Path(f"{p}-shm").unlink()
        r = inspect(p)
        assert r.header.journal_mode == "wal" and r.sidecars == [] and r.table("t").row_count == 5 and r.engine.view_includes_wal is False

    def test_explicit_sidecar_paths_replace_looking_beside_the_database(self, tmp_path):
        p = wal_snapshot(tmp_path / "ev")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        main = tmp_path / "isolated" / "w.db"
        main.parent.mkdir()
        main.write_bytes(p.read_bytes())
        (elsewhere / "kept-wal").write_bytes(Path(f"{p}-wal").read_bytes())
        assert inspect(main).table("t").row_count == 5, "nothing beside it: main file only"
        r = inspect(main, sidecars={"-wal": elsewhere / "kept-wal"})
        assert r.table("t").row_count == 8 and r.engine.applied_sidecars == ["wal"] and r.sidecar("wal").path == str(elsewhere / "kept-wal")
        assert inspect(p, sidecars={}).table("t").row_count == 5, "an empty mapping means: use no sidecars, even ones beside the database"

    def test_a_missing_explicit_sidecar_is_reported_and_skipped(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 10)
        r = inspect(p, sidecars={"-wal": tmp_path / "nope-wal"})
        assert r.sidecars == [] and any(i.kind == "sidecar_unreadable" for i in r.issues) and r.table("t").row_count == 10

    def test_a_wal_with_no_valid_frames_beside_a_rollback_mode_database_adds_nothing(self, tmp_path):
        wal_src = wal_snapshot(tmp_path / "src")
        p = numbered_db(tmp_path / "ev" / "a.db", 200)
        Path(f"{p}-wal").write_bytes(Path(f"{wal_src}-wal").read_bytes()[:32])  # a valid WAL header and nothing after it
        r = inspect(p)
        assert r.table("t").row_count == 200 and r.engine.view_includes_wal is False and r.engine.wal_frames_valid == 0
        assert r.sidecar("wal").wal.magic_valid and r.header.journal_mode == "rollback"
        assert any("not in WAL mode" in n and "wal_frames_valid" in n for n in r.engine.notes)

    def test_sqlite_applies_any_wal_that_exists_whatever_the_header_says(self, tmp_path):
        """An unrelated WAL that is valid in itself is applied by SQLite even beside a rollback-mode database — here it makes
        the file unopenable. That is why the inspector reports SQLite's own verdict instead of trusting the header, and why
        the main file can always be inspected alone."""
        wal_src = wal_snapshot(tmp_path / "src")
        p = numbered_db(tmp_path / "ev" / "a.db", 200)
        Path(f"{p}-wal").write_bytes(Path(f"{wal_src}-wal").read_bytes())
        with_wal = inspect(p)
        assert with_wal.sidecar("wal").wal.magic_valid
        assert with_wal.engine.open_status is OpenStatus.UNOPENABLE or with_wal.engine.wal_frames_valid > 0
        alone = inspect(p, apply_sidecars=False)
        assert alone.engine.open_status is OpenStatus.OK and alone.table("t").row_count == 200 and alone.sidecar("wal") is not None

    def test_a_corrupt_wal_is_flagged_and_the_inspection_still_completes(self, tmp_path):
        p = wal_snapshot(tmp_path / "ev")
        Path(f"{p}-wal").write_bytes(b"\xde\xad\xbe\xef" + bytes(4000))
        r = inspect(p)
        wal = r.sidecar("wal")
        assert wal.header_valid is False and wal.wal.magic_valid is False and "invalid" in wal.note
        assert r.engine.view_includes_wal is False and r.engine.open_status is OpenStatus.OK

    def test_empty_sidecars_are_facts_not_errors(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 10)
        Path(f"{p}-wal").write_bytes(b"")
        Path(f"{p}-journal").write_bytes(b"")
        r = inspect(p)
        assert {s.kind.value: (s.size, s.header_valid) for s in r.sidecars} == {"wal": (0, None), "journal": (0, None)}
        assert r.table("t").row_count == 10 and r.sidecar("wal").sha256 == hashlib.sha256(b"").hexdigest()

    def test_sidecars_come_in_a_stable_order(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 5)
        for suffix in ("-journal", "-shm", "-wal"):
            Path(f"{p}{suffix}").write_bytes(b"")
        assert [s.kind.value for s in inspect(p).sidecars] == ["wal", "shm", "journal"]

    @posix_only
    def test_a_symlinked_sidecar_is_not_followed(self, tmp_path):
        p = numbered_db(tmp_path / "ev" / "a.db", 5)
        outside = tmp_path / "outside-wal"
        outside.write_bytes(b"\x37\x7f\x06\x82" + bytes(100))
        os.symlink(outside, f"{p}-wal")
        r = inspect(p)
        assert r.sidecars == [] and any(i.kind == "sidecar_symlink_skipped" for i in r.issues)


class TestHotJournal:
    def test_the_journal_is_detected_applied_and_the_transaction_rolled_back_on_the_copy(self, tmp_path):
        p = hot_journal_snapshot(tmp_path / "ev")
        r = inspect(p)
        j = r.sidecar("journal")
        assert j.journal.magic_valid and j.header_valid is True and j.applied and j.size == Path(f"{p}-journal").stat().st_size
        t = r.table("q")
        assert t.row_count == 4000 and all(x.values[0].startswith("row") for x in t.records), "every row is as it was before the interrupted UPDATE"
        assert r.engine.applied_sidecars == ["journal"] and r.engine.view_includes_wal is False and r.integrity.status == "ok"
        assert any("rolled it back" in n for n in r.engine.notes)

    def test_the_evidence_pair_is_not_touched_by_the_rollback(self, tmp_path):
        ev = tmp_path / "ev"
        p = hot_journal_snapshot(ev)
        before = snapshot(ev)
        inspect(p)
        assert snapshot(ev) == before and (ev / "p.db-journal").exists(), "the rollback happened on the scratch copy only"

    def test_without_the_journal_the_main_file_is_read_as_it_lies(self, tmp_path):
        r = inspect(hot_journal_snapshot(tmp_path / "ev"), apply_sidecars=False)
        assert r.engine.applied_sidecars == [] and r.sidecar("journal") is not None and not r.sidecar("journal").applied


# ------------------------------------------------------------------ damaged, encrypted and non-SQLite files


class TestDamagedFiles:
    def test_truncated_database(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 300)
        data = p.read_bytes()
        p.write_bytes(data[: len(data) // 2 + 17])
        r = inspect(p)
        assert r.status is SqliteStatus.TRUNCATED and r.header.valid and r.size.consistent is False
        assert r.file.sha256 == sha(p) and r.file.size == len(data) // 2 + 17
        assert "database_truncated" in {i.kind for i in r.issues}
        assert r.engine.open_status in (OpenStatus.OK, OpenStatus.UNOPENABLE)

    def test_a_valid_header_over_a_destroyed_schema_page_is_valid_bytes_but_unopenable(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 50)
        data = bytearray(p.read_bytes())
        data[100:4096] = b"\xff" * (4096 - 100)  # page 1 keeps its header; the schema b-tree that follows it is gone
        p.write_bytes(bytes(data))
        r = inspect(p)
        assert r.status is SqliteStatus.VALID, "the byte-level check sees a sound header and size…"
        assert r.engine.open_status is OpenStatus.UNOPENABLE and "malformed" in r.engine.open_error, "…SQLite itself does not"
        assert r.tables == [] and r.schema_entries == [] and r.integrity.status == "not_run"
        assert r.file.sha256 == sha(p) and "database_unopenable" in {i.kind for i in r.issues} and r.header.page_size == 4096

    def test_a_page_destroyed_mid_table_keeps_the_rows_before_it(self, tmp_path):
        p = tmp_path / "a.db"
        c = sqlite3.connect(p)
        c.execute("PRAGMA page_size=1024")
        c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
        c.executemany("INSERT INTO t(v) VALUES(?)", [("m" * 60,) for _ in range(800)])
        c.commit()
        c.close()
        corrupt_middle_leaf(p)
        r = inspect(p)
        t = r.table("t")
        assert r.engine.open_status is OpenStatus.OK and r.integrity.status == "failed"
        assert 0 < len(t.records) < 800 and t.records_truncated and "rows:" in t.read_error
        assert [x.rowid for x in t.records] == list(range(1, len(t.records) + 1)), "an unbroken run from the start: nothing invented, nothing skipped"
        assert {"table_read_error", "database_integrity_failure"} <= {i.kind for i in r.issues}

    def test_encrypted_looking_file_is_reported_and_never_opened(self, tmp_path):
        p = tmp_path / "vault.db"
        p.write_bytes(os.urandom(16384))
        r = inspect(p)
        assert r.status is SqliteStatus.ENCRYPTED_SUSPECT and r.engine.open_status is OpenStatus.ENCRYPTED_SUSPECT
        assert r.tables == [] and r.file.sha256 == sha(p) and "encrypted_suspect" in {i.kind for i in r.issues}
        assert any("not asked to open" in n for n in r.engine.notes)

    @pytest.mark.parametrize("name,content,status", [
        ("empty.db", b"", SqliteStatus.EMPTY),
        ("notes.db", b"this is plain text, not a database\n" * 40, SqliteStatus.NOT_SQLITE),
        ("zeros.db", bytes(8192), SqliteStatus.NOT_SQLITE),
        ("blob.bin", b"x" * 5000, SqliteStatus.NOT_SQLITE),  # any file the caller names is inspected as a database
        ("magic_only.db", b"SQLite format 3\x00" + bytes(84), SqliteStatus.CORRUPT_HEADER),
    ])
    def test_files_that_are_not_databases(self, tmp_path, name, content, status):
        p = tmp_path / name
        p.write_bytes(content)
        r = inspect(p)
        assert r.status is status and r.tables == [] and r.record_count == 0 and not r.is_readable_by_sqlite
        assert r.file.size == len(content) and r.file.sha256 == hashlib.sha256(content).hexdigest() and r.issues

    def test_a_bad_page_size_is_a_corrupt_header_and_says_why(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 20)
        data = bytearray(p.read_bytes())
        data[16:18] = (1000).to_bytes(2, "big")
        p.write_bytes(bytes(data))
        r = inspect(p)
        assert r.status is SqliteStatus.CORRUPT_HEADER and r.engine.open_status is OpenStatus.HEADER_INVALID
        assert "invalid page size 1000" in r.status_detail and any("invalid page size" in n for n in r.notes) and r.header.page_size is None

    def test_a_random_file_with_an_ordinary_name_is_still_encrypted_looking_when_asked_for(self, tmp_path):
        p = tmp_path / "random.dat"
        p.write_bytes(os.urandom(8192))
        assert inspect(p).status is SqliteStatus.ENCRYPTED_SUSPECT

    @pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
    def test_a_sidecar_handed_in_as_the_database_is_not_a_database(self, tmp_path, suffix):
        p = numbered_db(tmp_path / "a.db", 10)
        side = Path(f"{p}{suffix}")
        side.write_bytes(b"\x37\x7f\x06\x82" + bytes(500) if suffix == "-wal" else bytes(500))
        r = inspect(side)
        assert r.status is SqliteStatus.NOT_SQLITE and r.tables == [] and r.sidecars == []

    def test_a_database_that_never_had_a_table(self, tmp_path):
        p = tmp_path / "e.db"
        c = sqlite3.connect(p)
        c.execute("PRAGMA user_version=1")
        c.commit()
        c.close()
        r = inspect(p)
        assert r.status is SqliteStatus.VALID and r.tables == [] and r.engine.open_status is OpenStatus.OK
        assert r.header.user_version == 1 and any("never had a schema" in n for n in r.notes)

    @pytest.mark.skipif(is_root or sys.platform == "win32", reason="root ignores file permissions")
    def test_an_unreadable_file_is_described_not_raised(self, tmp_path):
        p = numbered_db(tmp_path / "a.db", 10)
        p.chmod(0)
        try:
            r = inspect(p)
        finally:
            p.chmod(0o644)
        assert r.status is SqliteStatus.UNREADABLE and r.engine.open_status is OpenStatus.UNREADABLE and "PermissionError" in r.engine.open_error
        assert r.file.sha256 is None and r.tables == [] and "database_unreadable" in {i.kind for i in r.issues}


class TestUnusablePaths:
    def test_a_sqlite_library_too_old_to_describe_tables_is_refused_clearly(self, tmp_path, monkeypatch):
        p = numbered_db(tmp_path / "a.db", 3)
        monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 25, 9))
        monkeypatch.setattr(sqlite3, "sqlite_version", "3.25.9")
        with pytest.raises(InspectionError, match="needs SQLite 3.26.0 or newer.*3.25.9"):
            inspect(p)
        with pytest.raises(InspectionError, match="needs SQLite 3.26.0"):
            SQLiteInspector.iter_records(p, "t")

    def test_missing_path(self, tmp_path):
        with pytest.raises(InspectionError, match="does not exist"):
            inspect(tmp_path / "nope.db")

    def test_a_directory(self, tmp_path):
        with pytest.raises(InspectionError, match="is a directory"):
            inspect(tmp_path)

    @posix_only
    def test_a_dangling_symlink(self, tmp_path):
        os.symlink(tmp_path / "gone", tmp_path / "link.db")
        with pytest.raises(InspectionError, match="does not exist"):
            inspect(tmp_path / "link.db")

    @posix_only
    def test_a_symlink_named_explicitly_is_followed_and_its_target_reported(self, tmp_path):
        real = numbered_db(tmp_path / "real" / "a.db", 12)
        os.symlink(real, tmp_path / "alias.db")
        r = inspect(tmp_path / "alias.db")
        assert r.file.path == str(real.resolve()) and r.table("t").row_count == 12


# ------------------------------------------------------------------ the evidence is never touched


class TestReadOnlyGuarantee:
    @pytest.mark.parametrize("apply", [True, False])
    @pytest.mark.parametrize("maker", ["plain", "wal", "journal", "truncated", "encrypted", "empty"])
    def test_nothing_in_the_evidence_directory_changes(self, tmp_path, maker, apply):
        ev = tmp_path / "ev"
        if maker == "plain":
            p = numbered_db(ev / "a.db", 300)
        elif maker == "wal":
            p = wal_snapshot(ev)
        elif maker == "journal":
            p = hot_journal_snapshot(ev)
        elif maker == "truncated":
            p = numbered_db(ev / "a.db", 300)
            p.write_bytes(p.read_bytes()[:5000])
        elif maker == "encrypted":
            p = ev / "a.db"
            ev.mkdir()
            p.write_bytes(os.urandom(8192))
        else:
            p = ev / "a.db"
            ev.mkdir()
            p.write_bytes(b"")
        before, before_hash = snapshot(ev), tree_hash(ev)
        inspect(p, apply_sidecars=apply)
        list(SQLiteInspector.iter_records(p, "t", apply_sidecars=apply)) if maker in ("plain", "wal") else None
        assert snapshot(ev) == before and tree_hash(ev) == before_hash, "sizes, mtimes, contents and the set of files are all unchanged"

    def test_opening_a_wal_database_leaves_no_shm_behind(self, tmp_path):
        ev = tmp_path / "ev"
        p = wal_snapshot(ev)
        Path(f"{p}-shm").unlink()
        Path(f"{p}-wal").unlink()
        inspect(p)
        assert sorted(x.name for x in ev.iterdir()) == ["w.db"]

    def test_the_default_working_copy_is_removed_afterwards(self, tmp_path, monkeypatch):
        tmp = tmp_path / "tmp"
        tmp.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(tmp))
        good = numbered_db(tmp_path / "ev" / "a.db", 50)
        broken = tmp_path / "ev" / "b.db"
        broken.write_bytes(good.read_bytes()[:100] + b"\xff" * 3996)
        inspect(good)
        assert inspect(broken).engine.open_status is OpenStatus.UNOPENABLE
        list(SQLiteInspector.iter_records(good, "t"))
        assert list(tmp.iterdir()) == [], "no working copy is left behind, even after a failed open"

    def test_an_explicit_scratch_directory_is_left_empty(self, tmp_path):
        p = wal_snapshot(tmp_path / "ev")
        scratch = tmp_path / "scratch"
        inspect(p, scratch_dir=scratch)
        assert scratch.is_dir() and list(scratch.iterdir()) == []

    def test_scratch_inside_the_evidence_directory_is_refused_and_nothing_is_written(self, tmp_path):
        p = numbered_db(tmp_path / "ev" / "a.db", 10)
        for bad in (tmp_path / "ev", tmp_path / "ev" / "scratch", tmp_path / "ev" / "deep" / "er"):
            with pytest.raises(InspectionError, match="inside the evidence directory"):
                inspect(p, scratch_dir=bad)
        assert sorted(x.name for x in (tmp_path / "ev").iterdir()) == ["a.db"]

    def test_the_hash_is_of_the_exact_bytes_that_were_inspected(self, tmp_path):
        p = wal_snapshot(tmp_path / "ev")
        r = inspect(p)
        assert r.file.sha256 == sha(p) and r.sidecar("wal").sha256 == sha(f"{p}-wal") and r.sidecar("shm").sha256 == sha(f"{p}-shm")


# ------------------------------------------------------------------ agreement with the rest of the tool


class TestAgreesWithTheRestOfTheTool:
    @pytest.fixture()
    def dump(self, synth):
        out, truth = synth
        return out / "android_dump", truth

    def databases(self, dump):
        return sorted(p for p in dump.rglob("*") if p.is_file() and not p.name.endswith(("-wal", "-shm", "-journal")) and (p.suffix == ".db" or p.name == "History"))

    def test_status_matches_the_filesystem_scanners_for_every_database(self, dump):
        root, _ = dump
        scanned = {d.path: d.status for d in scan_directory(root).databases}
        inspected = {str(p.relative_to(root)): inspect(p, include_records=False).status for p in self.databases(root)}
        assert inspected == scanned and set(inspected.values()) >= {SqliteStatus.VALID, SqliteStatus.TRUNCATED, SqliteStatus.ENCRYPTED_SUSPECT}

    def test_header_facts_match_the_header_parser(self, dump):
        root, _ = dump
        for p in self.databases(root):
            r = inspect(p, include_records=False)
            assert r.header == inspect_database_file(p).header and r.size.actual_size == p.stat().st_size, p.name

    def test_tables_columns_and_counts_match_the_pipelines_own_reader(self, dump, tmp_path):
        root, _ = dump
        for p in self.databases(root):
            r = inspect(p)
            if r.engine.open_status is not OpenStatus.OK:
                continue
            sidecars = {s: Path(f"{p}{s}") for s in ("-wal", "-shm", "-journal") if Path(f"{p}{s}").exists()}
            with SQLiteSession(p, sidecars, tmp_path / "s") as session:
                legacy = [o for o in session.schema() if o.obj_type == "table"]
            assert [t.name for t in r.tables] == [o.name for o in legacy], p.name
            for t, o in zip(r.tables, legacy):
                assert [(c.name, c.declared_type, c.not_null, c.primary_key_position) for c in t.columns] == [(c.name, c.type, c.notnull, c.pk) for c in o.columns], (p.name, t.name)
                assert (t.row_count, not t.without_rowid, t.kind.value == "virtual") == (o.row_count, o.rowid_table, o.is_virtual), (p.name, t.name)

    def test_the_synthetic_labs_ground_truth(self, dump):
        root, truth = dump
        expected = truth["expected"]
        tel = inspect(root / "data/data/com.android.providers.telephony/databases/mmssms.db")
        assert tel.table("sms").row_count == expected["sms"] == len(tel.table("sms").records)
        calls = inspect(root / "data/data/com.android.providers.contacts/databases/calllog.db")
        assert calls.table("calls").row_count == expected["call"] and calls.engine.view_includes_wal is True
        without_wal = inspect(root / "data/data/com.android.providers.contacts/databases/calllog.db", apply_sidecars=False)
        assert without_wal.table("calls").row_count == expected["call"] - truth["spec"]["call_wal_rows"], "the WAL-only calls are absent from the main file"
        assert truth["spec"]["call_wal_rows"] > 0
        pending = inspect(root / "data/data/com.example.notes/databases/pending.db")
        assert pending.table("queue").row_count == expected["hot_journal_rows_after_rollback"] and pending.sidecar("journal").applied
        assert inspect(root / "data/data/com.example.corrupt/databases/broken.db").status is SqliteStatus.TRUNCATED
        assert inspect(root / "data/data/com.example.secure/databases/vault.db").status is SqliteStatus.ENCRYPTED_SUSPECT


class TestIntegrityAndApproximatedCollations:
    """Android supplies collations (LOCALIZED, PHONEBOOK…) that SQLite lacks. This tool substitutes a plain comparison, so
    ``integrity_check`` cannot vouch for an index that orders keys with one — but a healthy phone database must not be called damaged."""

    def test_a_healthy_database_with_a_localized_index_is_partial_not_failed(self, tmp_path):
        r = inspect(collated_db(tmp_path / "c.db", reverse=True))
        assert r.integrity.status == "partial" and r.integrity.messages and all("idx_name" in m for m in r.integrity.messages)
        assert "idx_name" in r.integrity.caveats[0] and "LOCALIZED" in r.integrity.caveats[0] and "quick_check confirms" in r.integrity.caveats[0]
        assert "integrity_partial" in {i.kind for i in r.issues} and "database_integrity_failure" not in {i.kind for i in r.issues}
        assert r.engine.open_status is OpenStatus.OK and r.table("contacts").row_count == len(r.table("contacts").records) == 320

    def test_an_index_whose_order_happens_to_agree_is_simply_ok(self, tmp_path):
        r = inspect(collated_db(tmp_path / "c.db", key=lambda s: s))  # binary order: nothing to distrust
        assert r.integrity.status == "ok" and r.integrity.caveats == []

    def test_real_damage_is_not_excused_by_the_presence_of_such_an_index(self, tmp_path):
        p = collated_db(tmp_path / "c.db", reverse=True, rows=800, page_size=1024)
        corrupt_middle_leaf(p, 1024, leaf_type=0x0D)  # a table page
        r = inspect(p)
        assert r.integrity.status == "failed" and not r.integrity.caveats
        assert "database_integrity_failure" in {i.kind for i in r.issues}

    def test_ordinary_index_damage_is_a_failure(self, tmp_path):
        p = tmp_path / "n.db"
        c = sqlite3.connect(p)
        c.execute("PRAGMA page_size=1024")
        c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT COLLATE NOCASE, pad TEXT)")
        c.execute("CREATE INDEX idx ON t(name)")
        c.executemany("INSERT INTO t(name, pad) VALUES(?, ?)", [(f"name{i:05d}", "x" * 50) for i in range(1500)])
        c.commit()
        c.close()
        corrupt_middle_leaf(p, 1024, leaf_type=0x0A)  # an index page
        r = inspect(p)
        assert r.integrity.status == "failed" and "database_integrity_failure" in {i.kind for i in r.issues}

    def test_the_integrity_check_can_be_skipped_and_then_says_nothing(self, tmp_path):
        r = inspect(collated_db(tmp_path / "c.db", reverse=True), integrity_check=False)
        assert r.integrity.status == "not_run" and r.issues == []
