"""The discovery analysis core: statuses, sidecar association, application directories and issues (no file system involved)."""

import hashlib
import random
import sqlite3

import pytest
from pydantic import ValidationError

from android_forensics.filesystem.analysis import FileObservation, analyze_files, detect_sqlite_status, sidecar_header_status
from android_forensics.models import (
    DiscoveredDatabase,
    FileKind,
    FilesystemScan,
    Sidecar,
    SidecarKind,
    SqliteStatus,
)
from android_forensics.sqlite.header import inspect_database_file

DB = "data/data/com.example.app/databases/app.db"
D = "data/data/com.example.app/databases"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def obs(path, kind=FileKind.TEXT, size=100, **kw):
    kw.setdefault("sha256", sha(path))
    return FileObservation(path=path, size=size, kind=kind, **kw)


def db_obs(path=DB, **kw):
    return obs(path, FileKind.SQLITE_DB, 8192, **kw)


def make_db(path, rows=300, page_size=4096):
    c = sqlite3.connect(path)
    c.execute(f"PRAGMA page_size={page_size}")
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t(v) VALUES(?)", [("x" * 100,) for _ in range(rows)])
    c.commit()
    c.close()
    return path


def status_of(path, kind=FileKind.SQLITE_DB):
    return detect_sqlite_status(FileObservation(path.name, path.stat().st_size, kind, header=inspect_database_file(path)))


# ------------------------------------------------------------------ SQLite detection status


class TestDetectSqliteStatus:
    def test_kinds_without_a_header(self):
        assert detect_sqlite_status(obs("a.db", FileKind.DB_UNRECOGNISED, 50, readable=False))[0] is SqliteStatus.UNREADABLE
        assert detect_sqlite_status(obs("a.db", FileKind.DB_UNRECOGNISED, 0))[0] is SqliteStatus.EMPTY
        assert detect_sqlite_status(obs("a.db", FileKind.ENCRYPTED_SUSPECT, 4096))[0] is SqliteStatus.ENCRYPTED_SUSPECT
        assert detect_sqlite_status(obs("a.db", FileKind.DB_UNRECOGNISED, 4096))[0] is SqliteStatus.NOT_SQLITE
        status, detail = detect_sqlite_status(obs("a.db", FileKind.SQLITE_DB, 4096))
        assert status is SqliteStatus.UNVERIFIED and "not inspected" in detail

    def test_a_healthy_database_is_valid(self, tmp_path):
        s, detail = status_of(make_db(tmp_path / "ok.db"))
        assert s is SqliteStatus.VALID and "valid" in detail

    @pytest.mark.parametrize("page_size", [512, 1024, 4096, 16384])
    def test_every_common_page_size(self, tmp_path, page_size):
        assert status_of(make_db(tmp_path / "p.db", 200, page_size))[0] is SqliteStatus.VALID

    def test_truncation_mid_file_and_on_a_page_boundary(self, tmp_path):
        p = make_db(tmp_path / "t.db")
        data = p.read_bytes()
        mid = tmp_path / "mid.db"
        mid.write_bytes(data[: len(data) // 2 + 17])
        s, detail = status_of(mid)
        assert s is SqliteStatus.TRUNCATED and "header implies" in detail
        boundary = tmp_path / "bound.db"
        boundary.write_bytes(data[: 4096 * 3])
        s, detail = status_of(boundary)
        assert s is SqliteStatus.TRUNCATED and "header implies" in detail

    def test_extra_data_after_the_last_page_versus_a_partial_trailing_page(self, tmp_path):
        data = make_db(tmp_path / "t.db").read_bytes()
        whole = tmp_path / "whole.db"
        whole.write_bytes(data + b"\xAA" * 4096)
        s, detail = status_of(whole)
        assert s is SqliteStatus.VALID and "trailing data" in detail
        partial = tmp_path / "partial.db"
        partial.write_bytes(data + b"\xAA" * 100)
        s, detail = status_of(partial)
        assert s is SqliteStatus.TRUNCATED and "mid-page" in detail

    def test_corrupt_headers(self, tmp_path):
        data = bytearray(make_db(tmp_path / "t.db").read_bytes())
        bad_page = bytearray(data)
        bad_page[16:18] = (1000).to_bytes(2, "big")
        bad_enc = bytearray(data)
        bad_enc[56:60] = (9).to_bytes(4, "big")
        cases = {"page.db": bytes(bad_page), "enc.db": bytes(bad_enc), "magic_only.db": b"SQLite format 3\x00" + b"\x00" * 84,
                 "short.db": b"SQLite format 3\x00" + b"\x01" * 20}
        for name, content in cases.items():
            p = tmp_path / name
            p.write_bytes(content)
            s, detail = status_of(p)
            assert s is SqliteStatus.CORRUPT_HEADER and detail, name

    def test_a_wal_mode_database_is_valid_and_reports_its_mode(self, tmp_path):
        p = tmp_path / "w.db"
        c = sqlite3.connect(p)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE t(a)")
        c.commit()
        c.close()
        scan = analyze_files([FileObservation("w.db", p.stat().st_size, FileKind.SQLITE_DB, header=inspect_database_file(p), sha256=sha("w"))])
        assert scan.databases[0].status is SqliteStatus.VALID and scan.databases[0].journal_mode == "wal"
        assert scan.databases[0].page_size == 4096 and scan.databases[0].text_encoding == "UTF-8"


class TestSidecarHeaderStatus:
    @pytest.mark.parametrize("kind,detail,expected", [
        (SidecarKind.WAL, "WAL magic valid", True), (SidecarKind.WAL, "WAL magic MISMATCH (corrupt or overwritten)", False),
        (SidecarKind.WAL, "WAL magic present under non-standard name", True), (SidecarKind.WAL, "empty WAL (checkpointed/truncated)", None),
        (SidecarKind.JOURNAL, "journal magic valid", True), (SidecarKind.JOURNAL, "journal header not standard (zeroed/PERSIST mode or corrupt)", None),
        (SidecarKind.JOURNAL, "empty journal", None), (SidecarKind.SHM, "wal-index shared memory file", None), (SidecarKind.WAL, None, None),
    ])
    def test_mapping(self, kind, detail, expected):
        assert sidecar_header_status(kind, detail)[0] is expected


# ------------------------------------------------------------------ databases and their sidecars


class TestDatabaseAssociation:
    def test_all_three_sidecars_are_associated_with_their_database(self):
        scan = analyze_files([
            db_obs(), obs(DB + "-wal", FileKind.SQLITE_WAL, 4152, kind_detail="WAL magic valid", evidence_file_id=11),
            obs(DB + "-shm", FileKind.SQLITE_SHM, 32768, evidence_file_id=12), obs(DB + "-journal", FileKind.SQLITE_JOURNAL, 600, evidence_file_id=13),
        ])
        [d] = scan.databases
        assert d.path == DB and d.size == 8192 and d.sha256 == sha(DB)
        assert (d.wal.path, d.wal.size, d.wal.sha256, d.wal.header_valid, d.wal.evidence_file_id) == (DB + "-wal", 4152, sha(DB + "-wal"), True, 11)
        assert d.shm.size == 32768 and d.journal.size == 600 and len(d.sidecars) == 3
        assert scan.orphan_sidecars == [] and scan.issues == []

    def test_a_database_with_no_sidecars_and_one_with_only_a_wal(self):
        scan = analyze_files([db_obs("a/one.db"), db_obs("a/two.db"), obs("a/two.db-wal", FileKind.SQLITE_WAL, 100)])
        one, two = scan.databases
        assert one.sidecars == [] and one.wal is None and [s.kind for s in two.sidecars] == [SidecarKind.WAL]

    def test_extensionless_databases_like_chromes_history(self):
        p = "data/data/com.android.chrome/app_chrome/Default/History"
        scan = analyze_files([db_obs(p), obs(p + "-journal", FileKind.SQLITE_JOURNAL, 512)])
        assert scan.databases[0].journal.path == p + "-journal" and scan.orphan_sidecars == []

    def test_sidecars_belong_to_the_database_in_their_own_directory(self):
        scan = analyze_files([db_obs("a/x.db"), db_obs("b/x.db"), obs("b/x.db-wal", FileKind.SQLITE_WAL, 100)])
        a, b = scan.databases
        assert a.wal is None and b.wal is not None

    def test_database_record_carries_android_attribution(self):
        [d] = analyze_files([db_obs("userdata/data/user/10/com.example.app/databases/app.db")]).databases
        assert (d.logical_path, d.package, d.user_id, d.area) == ("/data/user/10/com.example.app/databases/app.db", "com.example.app", 10, "app_internal")

    def test_every_database_like_kind_gets_a_record_with_its_status(self):
        scan = analyze_files([
            obs(f"{D}/ok.db", FileKind.SQLITE_DB, 4096), obs(f"{D}/text.db", FileKind.DB_UNRECOGNISED, 500),
            obs(f"{D}/enc.db", FileKind.ENCRYPTED_SUSPECT, 4096), obs(f"{D}/zero.db", FileKind.DB_UNRECOGNISED, 0),
            obs(f"{D}/locked.db", FileKind.DB_UNRECOGNISED, 400, readable=False, sha256=None),
        ])
        assert {d.path.rsplit("/", 1)[-1]: d.status for d in scan.databases} == {
            "ok.db": SqliteStatus.UNVERIFIED, "text.db": SqliteStatus.NOT_SQLITE, "enc.db": SqliteStatus.ENCRYPTED_SUSPECT,
            "zero.db": SqliteStatus.EMPTY, "locked.db": SqliteStatus.UNREADABLE}
        assert scan.database(f"{D}/locked.db").sha256 is None
        assert {i.issue_type for i in scan.issues} == {"db_unrecognised", "encrypted_suspect", "database_empty", "database_unreadable"}


class TestOrphanSidecars:
    def test_wal_without_a_database(self):
        scan = analyze_files([obs("a/gone.db-wal", FileKind.SQLITE_WAL, 900, kind_detail="WAL magic valid")])
        [o] = scan.orphan_sidecars
        assert o.kind is SidecarKind.WAL and "no database named 'a/gone.db'" in o.note
        assert [i.issue_type for i in scan.issues] == ["orphan_sidecar"]

    def test_sidecar_whose_base_file_is_not_a_database(self):
        scan = analyze_files([obs("a/readme.txt", FileKind.TEXT, 10), obs("a/readme.txt-journal", FileKind.SQLITE_JOURNAL, 600)])
        assert "exists but is not a database (text)" in scan.orphan_sidecars[0].note

    def test_sidecar_by_content_under_a_non_standard_name(self):
        scan = analyze_files([obs("a/backup.wal", FileKind.SQLITE_WAL, 900, kind_detail="WAL magic present under non-standard name")])
        assert "does not follow" in scan.orphan_sidecars[0].note and scan.orphan_sidecars[0].header_valid is True

    def test_case_mismatch_is_orphaned_rather_than_guessed(self):
        scan = analyze_files([db_obs("a/x.db"), obs("a/x.DB-wal", FileKind.SQLITE_WAL, 100)])
        assert scan.databases[0].wal is None and len(scan.orphan_sidecars) == 1

    def test_corrupt_wal_is_flagged_whether_associated_or_orphaned(self):
        bad = "WAL magic MISMATCH (corrupt or overwritten)"
        scan = analyze_files([db_obs("a/x.db"), obs("a/x.db-wal", FileKind.SQLITE_WAL, 900, kind_detail=bad),
                              obs("b/y.db-wal", FileKind.SQLITE_WAL, 900, kind_detail=bad)])
        assert scan.databases[0].wal.header_valid is False
        assert [i.path for i in scan.issues_of("sidecar_header_invalid")] == ["a/x.db-wal", "b/y.db-wal"]
        assert [i.path for i in scan.issues_of("orphan_sidecar")] == ["b/y.db-wal"]


# ------------------------------------------------------------------ application directories


class TestApplicationDirectories:
    def files(self):
        base = "data/data/com.example.app"
        return [
            obs(f"{base}/databases/app.db", FileKind.SQLITE_DB, 4096), obs(f"{base}/databases/app.db-wal", FileKind.SQLITE_WAL, 100),
            obs(f"{base}/shared_prefs/p.xml", FileKind.XML, 200), obs(f"{base}/files/a.log", FileKind.LOG, 300),
            obs(f"{base}/app_flutter/x.json", FileKind.JSON, 50), obs(f"{base}/stray.txt", FileKind.TEXT, 5),
            obs("data/data/com.other.app/databases/o.db", FileKind.SQLITE_DB, 4096),
        ]

    def test_counts_bytes_databases_kinds_and_standard_subdirectories(self):
        scan = analyze_files(self.files())
        app = next(a for a in scan.app_directories if a.package == "com.example.app")
        assert (app.path, app.logical_path, app.root, app.area, app.file_count, app.total_bytes, app.database_count) == (
            "data/data/com.example.app", "/data/data/com.example.app", "data/data", "app_internal", 6, 4096 + 100 + 200 + 300 + 50 + 5, 1)
        assert app.subdirectories == ["app_flutter", "databases", "files", "shared_prefs"], "stray.txt is not a subdirectory"
        assert app.kind_counts == {"json": 1, "log": 1, "sqlite_db": 1, "sqlite_wal": 1, "text": 1, "xml": 1}
        assert [a.package for a in scan.app_directories] == ["com.example.app", "com.other.app"]

    def test_an_application_with_no_files_is_still_an_application_directory(self):
        scan = analyze_files([obs("sdcard/a.txt")], directories=["data/data/com.empty.app", "data/data/com.empty.app/databases"])
        [app] = scan.app_directories
        assert app.package == "com.empty.app" and app.is_empty and app.subdirectories == ["databases"] and app.database_count == 0

    def test_users_are_separate_applications(self):
        scan = analyze_files([obs("data/user/0/com.x/files/a"), obs("data/user/10/com.x/files/a")])
        assert sorted((a.user_id, a.path) for a in scan.app_directories) == [(0, "data/user/0/com.x"), (10, "data/user/10/com.x")]

    def test_app_specific_external_storage_and_apk_directories(self):
        scan = analyze_files([obs("sdcard/Android/data/com.ext.app/files/f.txt"), obs("data/app/~~x==/com.apk.app-y==/base.apk", FileKind.APK, 9)])
        assert {(a.package, a.area) for a in scan.app_directories} == {("com.ext.app", "app_external"), ("com.apk.app", "app_binary")}

    def test_known_applications_are_labelled(self):
        scan = analyze_files([obs("data/data/com.android.providers.telephony/databases/mmssms.db", FileKind.SQLITE_DB, 4096)])
        assert "Telephony" in scan.app_directories[0].known_app

    def test_dumps_are_kept_apart(self):
        scan = analyze_files([obs("A/data/data/com.x/f"), obs("B/data/data/com.x/f")])
        assert [a.path for a in scan.app_directories] == ["A/data/data/com.x", "B/data/data/com.x"]
        assert scan.issues_of("multiple_dumps")

    def test_bare_application_directories(self):
        scan = analyze_files([obs("com.foo/databases/a.db", FileKind.SQLITE_DB, 100), obs("com.foo/cache/x")])
        [app] = scan.app_directories
        assert (app.package, app.path, app.area, app.file_count) == ("com.foo", "com.foo", "app_directory_dump", 2)


class TestAliasedApplicationDirectories:
    def pair(self, second_hash="same"):
        return [
            FileObservation("data/data/com.x/databases/a.db", 100, FileKind.SQLITE_DB, sha256=sha("same")),
            FileObservation("data/user/0/com.x/databases/a.db", 100, FileKind.SQLITE_DB, sha256=sha(second_hash)),
        ]

    def test_identical_copies_under_data_data_and_data_user_0_are_flagged(self):
        [issue] = analyze_files(self.pair()).issues_of("app_directory_alias")
        assert "identical contents" in issue.detail and issue.path == "data/user/0/com.x"

    def test_different_contents_are_called_out(self):
        [issue] = analyze_files(self.pair("other")).issues_of("app_directory_alias")
        assert "DIFFERENT contents" in issue.detail

    def test_unhashed_contents_are_not_compared(self):
        files = [FileObservation("data/data/com.x/f.txt", 1, FileKind.TEXT), FileObservation("data/user/0/com.x/f.txt", 1, FileKind.TEXT)]
        assert "not compared" in analyze_files(files).issues_of("app_directory_alias")[0].detail

    def test_other_users_are_not_aliases(self):
        files = [obs("data/data/com.x/f"), obs("data/user/10/com.x/f")]
        assert analyze_files(files).issues_of("app_directory_alias") == []


# ------------------------------------------------------------------ categories, issues and determinism


def test_every_requested_category_is_counted():
    scan = analyze_files([
        db_obs(), obs(DB + "-wal", FileKind.SQLITE_WAL), obs(DB + "-shm", FileKind.SQLITE_SHM), obs(DB + "-journal", FileKind.SQLITE_JOURNAL),
        obs("a/x.xml", FileKind.XML), obs("a/y.json", FileKind.JSON), obs("a/z.log", FileKind.LOG),
        obs("a/i.jpg", FileKind.IMAGE), obs("a/v.mp4", FileKind.VIDEO), obs("a/s.mp3", FileKind.AUDIO), obs("a/t.txt", FileKind.TEXT),
    ])
    assert scan.category_counts == {"database": 1, "json": 1, "log": 1, "media": 3, "other": 1, "sqlite_journal": 1, "sqlite_shm": 1, "sqlite_wal": 1, "xml": 1}
    assert len(scan.media_files) == 3 and [f.path for f in scan.files_of(FileKind.LOG)] == ["a/z.log"]
    assert scan.total_files == 11 and scan.total_bytes == 8192 + 10 * 100 and scan.kind_counts["image"] == 1


def test_issues_for_binary_xml_unreadable_files_and_unrecognised_layouts():
    scan = analyze_files([
        obs("data/system/packages.xml", FileKind.XML_BINARY, kind_detail="Android Binary XML (ABX)"),
        obs("data/system/locked.bin", FileKind.UNKNOWN, readable=False, sha256=None, kind_detail="unreadable (PermissionError)"),
    ])
    assert sorted((i.issue_type, i.path) for i in scan.issues) == [("binary_xml_not_parsed", "data/system/packages.xml"), ("unreadable_file", "data/system/locked.bin")]
    assert analyze_files([obs("misc/a.txt"), obs("b.bin")]).issues_of("layout_unrecognised")
    assert analyze_files([obs("data/data/com.x/f")]).issues == []


def test_results_do_not_depend_on_input_order():
    files = [db_obs(), obs(DB + "-wal", FileKind.SQLITE_WAL), obs("sdcard/x.jpg", FileKind.IMAGE), obs("data/data/com.o.app/f")]
    shuffled = files[:]
    random.Random(3).shuffle(shuffled)
    a, b = analyze_files(files), analyze_files(shuffled)
    assert a.model_copy(update={"scanned_at": b.scanned_at}) == b


def test_include_files_false_keeps_aggregates_but_drops_the_file_list():
    scan = analyze_files([db_obs(), obs("a/x.txt")], include_files=False)
    assert scan.files == [] and scan.total_files == 2 and len(scan.databases) == 1 and scan.category_counts


def test_layout_information_is_carried_into_the_result():
    scan = analyze_files([obs("phoneA/sdcard/x"), obs("phoneB/data/data/com.x/f")])
    assert scan.layout.layout == "multiple_roots" and sorted(r.prefix for r in scan.layout.roots) == ["phoneA", "phoneB"]
    assert "sdcard" in scan.layout.roots_present and "data/user" in scan.layout.roots_absent


# ------------------------------------------------------------------ the result models


def test_scan_round_trips_through_json():
    scan = analyze_files([db_obs(), obs(DB + "-wal", FileKind.SQLITE_WAL), obs("sdcard/a.log", FileKind.LOG)], root="/evidence")
    assert FilesystemScan.model_validate_json(scan.model_dump_json()) == scan


def test_model_invariants():
    side = dict(kind=SidecarKind.WAL, path="x-wal", size=1)
    with pytest.raises(ValidationError, match="at most one sidecar"):
        DiscoveredDatabase(path="x", size=1, status=SqliteStatus.VALID, sidecars=[Sidecar(**side), Sidecar(**side)])
    with pytest.raises(ValidationError):
        DiscoveredDatabase(path="x", size=1, status=SqliteStatus.VALID, sha256="not-a-hash")
    with pytest.raises(ValidationError):
        Sidecar(kind="lock", path="x", size=1)
    d = DiscoveredDatabase(path="x", size=1, status=SqliteStatus.TRUNCATED)
    assert d.is_sqlite and not DiscoveredDatabase(path="x", size=1, status=SqliteStatus.NOT_SQLITE).is_sqlite
    with pytest.raises(ValidationError):
        d.size = 2
