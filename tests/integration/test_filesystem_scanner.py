"""``scan_directory`` against real trees on disk: layouts that exist in the wild, and damage the scanner must survive."""

import hashlib
import json
import os
import random
import sqlite3
import sys

import pytest

import android_forensics.filesystem.scanner as scanner_module
from android_forensics.errors import DiscoveryError
from android_forensics.filesystem.scanner import scan_directory
from android_forensics.models import FileKind, FilesystemScan, SidecarKind, SqliteStatus
from tests.conftest import tree_hash

is_root = hasattr(os, "geteuid") and os.geteuid() == 0
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions/symlinks")
needs_permissions = pytest.mark.skipif(is_root or sys.platform == "win32", reason="root ignores file permissions")

JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(64) + b"\xff\xd9"
PNG = b"\x89PNG\r\n\x1a\n" + bytes(64)


def make_db(path, rows=200, wal=False, page_size=4096):
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.execute(f"PRAGMA page_size={page_size}")
    if wal:
        c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t(v) VALUES(?)", [("row %d " % i + "x" * 90,) for i in range(rows)])
    c.commit()
    c.close()
    return path


def put(root, rel, data=b"data"):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def by_path(scan):
    return {d.path: d for d in scan.databases}


def issue_types(scan):
    return sorted({i.issue_type for i in scan.issues})


@pytest.fixture()
def phone(tmp_path):
    """A small but representative device dump: two apps, an external card, logs, media, and every sidecar type."""
    root = tmp_path / "phone"
    tel = root / "data/data/com.android.providers.telephony/databases"
    make_db(tel / "mmssms.db")
    put(tel, "mmssms.db-wal", b"\x37\x7f\x06\x82" + bytes(4148))
    put(tel, "mmssms.db-shm", bytes(32768))
    put(tel, "mmssms.db-journal", bytes(600))
    make_db(root / "data/data/com.example.chat/databases/chat.db")
    put(root, "data/data/com.example.chat/shared_prefs/prefs.xml", "<map><string name='a'>b</string></map>")
    put(root, "data/data/com.example.chat/files/state.json", '{"k": 1}')
    put(root, "data/data/com.example.chat/files/chat.log", "2024-03-01 10:00:00 started\n")
    put(root, "sdcard/DCIM/Camera/IMG_1.jpg", JPEG)
    put(root, "storage/emulated/0/Pictures/s.png", PNG)
    put(root, "sdcard/Download/notes.txt", "hello")
    return root


# ------------------------------------------------------------------ the requested classifications


class TestClassification:
    def test_every_requested_category_is_detected(self, phone):
        scan = scan_directory(phone)
        cats = scan.category_counts
        assert cats["database"] == 2 and cats["sqlite_wal"] == 1 and cats["sqlite_shm"] == 1 and cats["sqlite_journal"] == 1
        assert cats["xml"] == 1 and cats["json"] == 1 and cats["log"] == 1 and cats["media"] == 2
        assert {f.path for f in scan.media_files} == {"sdcard/DCIM/Camera/IMG_1.jpg", "storage/emulated/0/Pictures/s.png"}
        assert [f.path for f in scan.files_of(FileKind.LOG)] == ["data/data/com.example.chat/files/chat.log"]
        assert scan.total_files == sum(scan.category_counts.values()) == 11

    def test_android_application_directories(self, phone):
        apps = {a.package: a for a in scan_directory(phone).app_directories}
        assert set(apps) == {"com.android.providers.telephony", "com.example.chat"}
        chat = apps["com.example.chat"]
        assert chat.logical_path == "/data/data/com.example.chat" and chat.file_count == 4 and chat.database_count == 1
        assert chat.subdirectories == ["databases", "files", "shared_prefs"]
        assert "Telephony" in apps["com.android.providers.telephony"].known_app
        assert apps["com.android.providers.telephony"].database_count == 1, "sidecars are not databases"

    def test_files_carry_their_android_path(self, phone):
        scan = scan_directory(phone)
        f = next(x for x in scan.files if x.path.endswith("IMG_1.jpg"))
        assert (f.logical_path, f.area, f.package) == ("/sdcard/DCIM/Camera/IMG_1.jpg", "shared_storage", None)
        c = next(x for x in scan.files if x.path.endswith("chat.db"))
        # /data/data does not name a user, so none is claimed (on a device it is user 0's directory, but the path does not say so)
        assert (c.logical_path, c.area, c.package, c.user_id) == ("/data/data/com.example.chat/databases/chat.db", "app_internal", "com.example.chat", None)

    def test_layout_is_reported_and_absent_roots_are_named_not_invented(self, phone):
        scan = scan_directory(phone)
        assert scan.layout.layout == "android_root"
        assert {"data/data", "sdcard", "storage/emulated"} <= set(scan.layout.roots_present)
        assert scan.layout.roots_absent == ["data/user"]


# ------------------------------------------------------------------ database records


class TestDatabaseRecords:
    def test_path_size_sha256_status_and_sidecars(self, phone):
        scan = scan_directory(phone)
        rel = "data/data/com.android.providers.telephony/databases/mmssms.db"
        d = by_path(scan)[rel]
        real = phone / rel
        assert d.size == real.stat().st_size and d.sha256 == sha(real) and d.status is SqliteStatus.VALID and d.is_sqlite
        assert d.logical_path == "/" + rel and d.package == "com.android.providers.telephony"
        assert (d.page_size, d.text_encoding, d.journal_mode) == (4096, "UTF-8", "rollback")
        assert sorted(s.kind.value for s in d.sidecars) == ["journal", "shm", "wal"]
        for s in d.sidecars:
            p = phone / s.path
            assert s.size == p.stat().st_size and s.sha256 == sha(p)
        assert d.wal.header_valid is True and d.shm.header_valid is None
        assert scan.orphan_sidecars == []

    def test_a_database_without_sidecars(self, phone):
        d = by_path(scan_directory(phone))["data/data/com.example.chat/databases/chat.db"]
        assert d.sidecars == [] and d.wal is None and d.status is SqliteStatus.VALID

    def test_a_real_wal_mode_database_with_its_wal(self, tmp_path):
        p = make_db(tmp_path / "ev/data/data/com.x/databases/w.db", wal=True)
        keep = sqlite3.connect(p)  # keep the WAL alive: an open connection prevents the checkpoint on close
        keep.execute("INSERT INTO t(v) VALUES('later')")
        keep.commit()
        try:
            assert (tmp_path / "ev/data/data/com.x/databases/w.db-wal").exists()
            scan = scan_directory(tmp_path / "ev")
        finally:
            keep.close()
        d = scan.databases[0]
        assert d.status is SqliteStatus.VALID and d.journal_mode == "wal" and d.wal.header_valid is True and d.wal.size > 0

    def test_extensionless_databases_and_their_sidecars(self, tmp_path):
        ev = tmp_path / "ev"
        hist = make_db(ev / "data/data/com.android.chrome/app_chrome/Default/History")
        put(ev, "data/data/com.android.chrome/app_chrome/Default/History-journal", bytes(512))
        [d] = scan_directory(ev).databases
        assert d.path.endswith("/History") and d.status is SqliteStatus.VALID and d.journal is not None
        assert d.sha256 == sha(hist)

    def test_databases_are_found_by_content_not_by_name(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "data/data/com.x/files/blob.dat")
        make_db(ev / "data/data/com.x/files/store")
        scan = scan_directory(ev)
        assert {d.path.rsplit("/", 1)[-1] for d in scan.databases} == {"blob.dat", "store"}
        assert all(d.status is SqliteStatus.VALID for d in scan.databases)

    def test_sha256_is_computed_for_databases_and_sidecars_only_unless_asked(self, phone):
        default = scan_directory(phone)
        assert all(f.sha256 for f in default.files if f.kind.is_database_candidate or f.kind.is_sidecar)
        assert all(f.sha256 is None for f in default.files if not (f.kind.is_database_candidate or f.kind.is_sidecar))
        everything = scan_directory(phone, hash_all=True)
        assert all(f.sha256 == sha(phone / f.path) for f in everything.files)
        nothing = scan_directory(phone, hash_databases=False)
        assert all(d.sha256 is None for d in nothing.databases) and nothing.databases[0].status is SqliteStatus.VALID


class TestSqliteDetectionStatuses:
    def build(self, tmp_path):
        ev = tmp_path / "ev"
        d = ev / "data/data/com.x/databases"
        good = make_db(d / "good.db")
        data = good.read_bytes()
        put(d, "truncated.db", data[: len(data) // 2 + 33])
        put(d, "cut_on_page.db", data[: 4096 * 3])
        put(d, "zero.db", b"")
        put(d, "random.db", random.Random(5).randbytes(16384))
        put(d, "zeros.db", bytes(8192))
        put(d, "text.db", "this is definitely not a database\n" * 20)
        put(d, "magic_only.db", b"SQLite format 3\x00" + bytes(84))
        bad = bytearray(data)
        bad[16:18] = (777).to_bytes(2, "big")
        put(d, "bad_pagesize.db", bytes(bad))
        return ev

    def test_each_kind_of_damage_gets_its_own_status(self, tmp_path):
        got = {p.rsplit("/", 1)[-1]: d.status for p, d in by_path(scan_directory(self.build(tmp_path))).items()}
        assert got == {
            "good.db": SqliteStatus.VALID, "truncated.db": SqliteStatus.TRUNCATED, "cut_on_page.db": SqliteStatus.TRUNCATED,
            "zero.db": SqliteStatus.EMPTY, "random.db": SqliteStatus.ENCRYPTED_SUSPECT, "zeros.db": SqliteStatus.NOT_SQLITE,
            "text.db": SqliteStatus.NOT_SQLITE, "magic_only.db": SqliteStatus.CORRUPT_HEADER, "bad_pagesize.db": SqliteStatus.CORRUPT_HEADER,
        }

    def test_damaged_databases_are_still_reported_with_size_and_hash_and_raise_issues(self, tmp_path):
        ev = self.build(tmp_path)
        scan = scan_directory(ev)
        for d in scan.databases:
            assert d.size == (ev / d.path).stat().st_size and d.sha256 == sha(ev / d.path) and d.detail
        assert {"database_truncated", "database_empty", "encrypted_suspect", "db_unrecognised", "database_corrupt_header"} <= set(issue_types(scan))
        assert {i.path.rsplit("/", 1)[-1] for i in scan.issues_of("database_truncated")} == {"truncated.db", "cut_on_page.db"}
        assert not [i for i in scan.issues if i.path.endswith("good.db")]

    def test_a_truncated_database_keeps_its_sidecars(self, tmp_path):
        ev = tmp_path / "ev"
        data = make_db(ev / "data/data/com.x/databases/a.db").read_bytes()
        put(ev, "data/data/com.x/databases/a.db", data[:5000])
        put(ev, "data/data/com.x/databases/a.db-wal", b"\x37\x7f\x06\x83" + bytes(100))
        [d] = scan_directory(ev).databases
        assert d.status is SqliteStatus.TRUNCATED and d.is_sqlite and d.wal is not None and d.wal.header_valid is True

    def test_a_corrupt_wal_is_flagged(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "data/data/com.x/databases/a.db")
        put(ev, "data/data/com.x/databases/a.db-wal", b"\xde\xad\xbe\xef" + bytes(4000))
        scan = scan_directory(ev)
        assert scan.databases[0].status is SqliteStatus.VALID and scan.databases[0].wal.header_valid is False
        [issue] = scan.issues_of("sidecar_header_invalid")
        assert issue.path.endswith("a.db-wal") and "MISMATCH" in issue.detail


class TestOrphanSidecars:
    def test_orphans_are_reported_not_attached_to_a_guess(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "data/data/com.x/databases/live.db")
        put(ev, "data/data/com.x/databases/deleted.db-wal", b"\x37\x7f\x06\x82" + bytes(4148))
        put(ev, "data/data/com.x/databases/deleted.db-journal", bytes(700))
        scan = scan_directory(ev)
        assert scan.databases[0].sidecars == []
        assert sorted(o.kind.value for o in scan.orphan_sidecars) == ["journal", "wal"]
        assert all("no database named" in o.note for o in scan.orphan_sidecars)
        assert sorted(i.path.rsplit("/", 1)[-1] for i in scan.issues_of("orphan_sidecar")) == ["deleted.db-journal", "deleted.db-wal"]

    def test_sidecars_are_matched_within_their_own_directory_only(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "data/data/com.a/databases/x.db")
        make_db(ev / "data/data/com.b/databases/x.db")
        put(ev, "data/data/com.b/databases/x.db-wal", b"\x37\x7f\x06\x82" + bytes(100))
        scan = scan_directory(ev)
        a, b = sorted(scan.databases, key=lambda d: d.path)
        assert a.wal is None and b.wal is not None


# ------------------------------------------------------------------ layouts that are not the textbook one


class TestUnusualLayouts:
    def test_missing_directories_only_sdcard(self, tmp_path):
        ev = tmp_path / "ev"
        put(ev, "sdcard/DCIM/a.jpg", JPEG)
        scan = scan_directory(ev)
        assert scan.app_directories == [] and scan.databases == [] and scan.layout.layout == "android_root"
        assert scan.layout.roots_present == ["sdcard"] and "data/data" in scan.layout.roots_absent
        assert scan.issues == []

    def test_empty_evidence_directory(self, tmp_path):
        (tmp_path / "ev").mkdir()
        scan = scan_directory(tmp_path / "ev")
        assert scan.total_files == 0 and scan.databases == [] and scan.files == [] and scan.directories == 0
        assert scan.layout.layout == "loose_files" and scan.issues == []

    def test_only_empty_directories(self, tmp_path):
        (tmp_path / "ev/data/data/com.empty.app/databases").mkdir(parents=True)
        scan = scan_directory(tmp_path / "ev")
        assert scan.total_files == 0 and scan.directories == 4
        assert [a.package for a in scan.app_directories] == ["com.empty.app"] and scan.app_directories[0].is_empty

    def test_dump_below_a_prefix_directory(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "extraction_2024/userdata/data/data/com.x/databases/a.db")
        put(ev, "extraction_2024/userdata/sdcard/x.txt", "x")
        scan = scan_directory(ev)
        assert scan.layout.layout == "android_root_with_prefix" and scan.layout.roots[0].prefix == "extraction_2024/userdata"
        assert scan.databases[0].logical_path == "/data/data/com.x/databases/a.db"

    def test_two_devices_in_one_directory(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "phoneA/data/data/com.x/databases/a.db")
        make_db(ev / "phoneB/data/data/com.x/databases/a.db")
        scan = scan_directory(ev)
        assert scan.layout.layout == "multiple_roots" and len(scan.databases) == 2 and "multiple_dumps" in issue_types(scan)
        assert {d.path for d in scan.databases} == {"phoneA/data/data/com.x/databases/a.db", "phoneB/data/data/com.x/databases/a.db"}
        assert {a.path for a in scan.app_directories} == {"phoneA/data/data/com.x", "phoneB/data/data/com.x"}

    def test_multi_user_and_data_user_0_alias(self, tmp_path):
        ev = tmp_path / "ev"
        content = make_db(tmp_path / "template.db").read_bytes()
        for rel in ("data/data/com.x", "data/user/0/com.x", "data/user/10/com.x"):
            put(ev, f"{rel}/databases/a.db", content)
        scan = scan_directory(ev)
        assert sorted((str(d.user_id), d.path.split("/")[1]) for d in scan.databases) == [("0", "user"), ("10", "user"), ("None", "data")]
        assert len(scan.app_directories) == 3
        [alias] = scan.issues_of("app_directory_alias")  # only user 0 can alias /data/data; user 10 is a different application
        assert alias.path == "data/user/0/com.x" and "identical contents" in alias.detail

    def test_bare_package_directories(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "com.foo.bar/databases/a.db")
        put(ev, "com.foo.bar/shared_prefs/p.xml", "<map/>")
        scan = scan_directory(ev)
        assert scan.layout.layout == "app_directories"
        assert [(a.package, a.area, a.logical_path) for a in scan.app_directories] == [("com.foo.bar", "app_directory_dump", "/com.foo.bar")]

    def test_loose_files_with_no_android_structure(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "exports/messages.db")
        put(ev, "exports/readme.txt", "x")
        scan = scan_directory(ev)
        assert scan.layout.layout == "loose_files" and "layout_unrecognised" in issue_types(scan)
        d = scan.databases[0]  # no Android location is claimed: the area says the layout was not recognised
        assert d.area == "unrecognised_layout" and d.package is None and d.status is SqliteStatus.VALID

    def test_removable_storage_and_apk_directories(self, tmp_path):
        ev = tmp_path / "ev"
        put(ev, "storage/1234-ABCD/DCIM/a.jpg", JPEG)
        put(ev, "data/app/~~abc==/com.apk.app-xyz==/base.apk", b"PK\x03\x04" + bytes(40))
        put(ev, "sdcard/Android/data/com.ext.app/files/f.log", "log")
        scan = scan_directory(ev)
        assert {(a.package, a.area) for a in scan.app_directories} == {("com.apk.app", "app_binary"), ("com.ext.app", "app_external")}
        img = next(f for f in scan.files if f.path.endswith("a.jpg"))
        assert img.area == "shared_storage" and img.logical_path == "/storage/1234-ABCD/DCIM/a.jpg"

    def test_odd_names_deep_trees_and_unicode(self, tmp_path):
        ev = tmp_path / "ev"
        deep = "data/data/com.x/" + "/".join(f"d{i}" for i in range(60))
        make_db(ev / deep / "deep.db")
        make_db(ev / "data/data/com.x/databases/naïve  file (1).db")
        put(ev, "sdcard/Pictures/ファイル.jpg", JPEG)
        scan = scan_directory(ev)
        assert len(scan.databases) == 2 and all(d.status is SqliteStatus.VALID for d in scan.databases)
        assert any(f.path.endswith("ファイル.jpg") for f in scan.media_files)

    def test_lookalike_names_are_not_mistaken_for_android_roots(self, tmp_path):
        ev = tmp_path / "ev"
        put(ev, "my_sdcard_backup/data/data.txt", "x")
        put(ev, "data_data/x.db", "not a db")
        scan = scan_directory(ev)
        assert scan.layout.layout == "loose_files" and scan.app_directories == []


# ------------------------------------------------------------------ hostile and damaged trees


class TestGracefulFailure:
    def test_missing_root_raises_a_forensics_error(self, tmp_path):
        with pytest.raises(DiscoveryError, match="does not exist"):
            scan_directory(tmp_path / "nope")

    def test_a_file_is_not_a_directory_to_scan(self, tmp_path):
        f = put(tmp_path, "single.db", b"x")
        with pytest.raises(DiscoveryError, match="not a directory"):
            scan_directory(f)

    @posix_only
    def test_symlinks_are_reported_and_never_followed(self, tmp_path):
        ev = tmp_path / "ev"
        outside = tmp_path / "outside"
        make_db(outside / "secret.db")
        put(ev, "data/data/com.x/files/a.txt", "a")
        os.symlink(outside, ev / "data/data/com.x/link_dir")
        os.symlink(outside / "secret.db", ev / "data/data/com.x/link.db")
        os.symlink(tmp_path / "does-not-exist", ev / "data/data/com.x/dangling")
        scan = scan_directory(ev)
        assert scan.databases == [] and scan.total_files == 1
        assert sorted(i.issue_type for i in scan.issues) == ["dangling_symlink", "symlink_skipped", "symlink_skipped"]

    @posix_only
    def test_a_symlinked_evidence_root_is_scanned(self, tmp_path):
        real = tmp_path / "real"
        make_db(real / "data/data/com.x/databases/a.db")
        os.symlink(real, tmp_path / "link")
        scan = scan_directory(tmp_path / "link")
        assert len(scan.databases) == 1 and scan.root == str(real.resolve())

    @posix_only
    def test_special_files_are_skipped_not_opened(self, tmp_path):
        ev = tmp_path / "ev"
        put(ev, "data/data/com.x/a.txt", "a")
        os.mkfifo(ev / "data/data/com.x/pipe")  # opening a FIFO for reading would block forever
        scan = scan_directory(ev)
        assert scan.total_files == 1 and [i.issue_type for i in scan.issues] == ["special_file_skipped"]

    @needs_permissions
    def test_unreadable_file_is_recorded_and_the_scan_continues(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "data/data/com.x/databases/ok.db")
        locked = make_db(ev / "data/data/com.x/databases/locked.db")
        blocked = put(ev, "data/data/com.x/files/secret.bin", b"\x00" * 100)
        locked.chmod(0)
        blocked.chmod(0)
        try:
            scan = scan_directory(ev)
        finally:
            locked.chmod(0o644)
            blocked.chmod(0o644)
        dbs = {d.path.rsplit("/", 1)[-1]: d for d in scan.databases}
        assert dbs["ok.db"].status is SqliteStatus.VALID
        assert dbs["locked.db"].status is SqliteStatus.UNREADABLE and dbs["locked.db"].sha256 is None and dbs["locked.db"].size > 0
        secret = next(f for f in scan.files if f.path.endswith("secret.bin"))
        assert secret.readable is False and secret.sha256 is None
        assert {"database_unreadable", "unreadable_file"} <= set(issue_types(scan))

    @needs_permissions
    def test_unreadable_directory_is_recorded_and_the_rest_is_scanned(self, tmp_path):
        ev = tmp_path / "ev"
        make_db(ev / "data/data/com.a/databases/a.db")
        make_db(ev / "data/data/com.b/databases/b.db")
        (ev / "data/data/com.b/databases").chmod(0)
        try:
            scan = scan_directory(ev)
        finally:
            (ev / "data/data/com.b/databases").chmod(0o755)
        assert [d.path for d in scan.databases] == ["data/data/com.a/databases/a.db"]
        [issue] = scan.issues_of("unreadable_directory")
        assert issue.path == "data/data/com.b/databases" and "PermissionError" in issue.detail

    def test_a_file_that_vanishes_mid_scan_is_an_issue_not_a_crash(self, tmp_path, monkeypatch):
        ev = tmp_path / "ev"
        make_db(ev / "data/data/com.x/databases/a.db")
        gone = put(ev, "data/data/com.x/databases/gone.db", b"x" * 100)
        real_open = scanner_module.open_readonly

        def flaky(path, **kw):
            if str(path).endswith("gone.db"):
                raise FileNotFoundError(path)
            return real_open(path, **kw)

        monkeypatch.setattr(scanner_module, "open_readonly", flaky)
        scan = scan_directory(ev)
        assert [d.path.rsplit("/", 1)[-1] for d in scan.databases] == ["a.db"]
        [issue] = scan.issues_of("vanished")
        assert issue.path.endswith("gone.db") and gone.exists()

    def test_a_read_error_partway_through_hashing_marks_the_file_unreadable(self, tmp_path, monkeypatch):
        ev = tmp_path / "ev"
        make_db(ev / "data/data/com.x/databases/a.db")

        def broken(path):
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(scanner_module, "sha256_of", broken)
        scan = scan_directory(ev)
        assert scan.databases[0].status is SqliteStatus.UNREADABLE and scan.databases[0].sha256 is None

    def test_binary_xml_is_classified_and_flagged_as_not_parsed(self, tmp_path):
        ev = tmp_path / "ev"
        put(ev, "data/system/packages.xml", b"ABX\x00" + bytes(200))
        put(ev, "data/system/users/0.xml", "<?xml version='1.0'?><user id='0'/>")
        scan = scan_directory(ev)
        assert scan.category_counts["xml"] == 2 and [i.path for i in scan.issues_of("binary_xml_not_parsed")] == ["data/system/packages.xml"]

    def test_log_like_files_are_found(self, tmp_path):
        ev = tmp_path / "ev"
        put(ev, "data/data/com.x/files/app.log", "2024-01-01 12:00:00 I/App: hi\n")
        put(ev, "data/data/com.x/files/app.log.1", "old\n")
        put(ev, "data/anr/anr_2024-01-01", "----- pid 1 at 2024 -----\n")
        put(ev, "data/tombstones/tombstone_00", "*** *** ***\n")
        scan = scan_directory(ev)
        assert len(scan.files_of(FileKind.LOG)) == 4


# ------------------------------------------------------------------ guarantees


class TestGuarantees:
    def test_the_evidence_is_never_modified(self, phone):
        before = tree_hash(phone)
        scan_directory(phone, hash_all=True)
        assert tree_hash(phone) == before

    def test_opening_no_database_leaves_no_sidecars_behind(self, phone):
        before = sorted(p.name for p in phone.rglob("*"))
        scan_directory(phone)
        assert sorted(p.name for p in phone.rglob("*")) == before

    def test_the_scan_is_deterministic(self, phone):
        a, b = scan_directory(phone), scan_directory(phone)
        assert a.model_copy(update={"scanned_at": ""}) == b.model_copy(update={"scanned_at": ""})

    def test_include_files_false_drops_only_the_file_list(self, phone):
        full, lean = scan_directory(phone), scan_directory(phone, include_files=False)
        assert lean.files == [] and lean.total_files == full.total_files and lean.databases == full.databases

    def test_progress_is_reported(self, phone):
        events = []

        class P:
            def start(self, label, total): events.append(("start", label))
            def advance(self, n=1): events.append(("advance", n))
            def stop(self): events.append(("stop", None))

        scan_directory(phone, progress=P())
        assert events[0][0] == "start" and events[-1] == ("stop", None) and sum(1 for e in events if e[0] == "advance") == 11

    def test_result_round_trips_through_json(self, phone):
        scan = scan_directory(phone)
        assert FilesystemScan.model_validate_json(scan.model_dump_json()) == scan
        assert json.loads(scan.model_dump_json())["databases"][0]["sidecars"] is not None

    def test_relative_paths_are_posix_and_never_escape_the_root(self, phone):
        for f in scan_directory(phone).files:
            assert not f.path.startswith("/") and ".." not in f.path.split("/") and "\\" not in f.path

    def test_a_sidecar_with_wal_kind_is_typed(self, phone):
        d = by_path(scan_directory(phone))["data/data/com.android.providers.telephony/databases/mmssms.db"]
        assert d.wal.kind is SidecarKind.WAL and d.shm.kind is SidecarKind.SHM and d.journal.kind is SidecarKind.JOURNAL


def test_scanning_a_large_flat_directory_is_not_quadratic(tmp_path):
    ev = tmp_path / "ev/data/data/com.x/files"
    ev.mkdir(parents=True)
    for i in range(3000):
        (ev / f"f{i}.txt").write_text("x")
    import time

    t = time.perf_counter()
    scan = scan_directory(tmp_path / "ev")
    assert scan.total_files == 3000 and time.perf_counter() - t < 10
