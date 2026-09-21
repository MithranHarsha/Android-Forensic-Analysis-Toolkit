import os

from android_forensics.filesystem.android_paths import analyze_layout
from android_forensics.filesystem.classifier import classify, should_preserve
from android_forensics.models.enums import FileKind

SQLITE = b"SQLite format 3\x00" + b"\x00" * 100


def test_sqlite_by_content_not_name():
    assert classify("History", SQLITE, 4096).kind is FileKind.SQLITE_DB
    assert classify("photo.jpg", SQLITE, 4096).kind is FileKind.SQLITE_DB


def test_sidecars_by_name_and_magic():
    assert classify("x.db-wal", b"\x37\x7f\x06\x82" + b"\0" * 28, 100).kind is FileKind.SQLITE_WAL
    bad = classify("x.db-wal", b"nope" + b"\0" * 28, 100)
    assert bad.kind is FileKind.SQLITE_WAL and "MISMATCH" in bad.detail
    assert classify("x.db-wal", b"", 0).kind is FileKind.SQLITE_WAL
    assert classify("x.db-shm", b"\0" * 32, 32768).kind is FileKind.SQLITE_SHM
    assert classify("x.db-journal", bytes.fromhex("d9d505f920a163d7") + b"\0" * 20, 600).kind is FileKind.SQLITE_JOURNAL
    assert "zeroed" in classify("x.db-journal", b"\0" * 64, 600).detail


def test_abx_media_and_text():
    assert classify("packages.xml", b"ABX\x00" + b"\x01" * 50, 60).kind is FileKind.XML_BINARY
    assert classify("a.jpg", b"\xff\xd8\xff\xe0" + b"0" * 20, 100).kind is FileKind.IMAGE
    assert classify("a.png", b"\x89PNG\r\n\x1a\n" + b"0", 20).kind is FileKind.IMAGE
    assert classify("a.xml", b"<?xml version='1.0'?><a/>", 30).kind is FileKind.XML
    assert classify("a.json", b'{"a": 1}', 8).kind is FileKind.JSON
    assert classify("notes.txt", b"hello world\n" * 20, 240).kind is FileKind.TEXT
    assert classify("z", b"", 0).kind is FileKind.EMPTY


def test_encrypted_vs_unrecognised_db():
    random_head = os.urandom(4096)
    assert classify("vault.db", random_head, 16384).kind is FileKind.ENCRYPTED_SUSPECT
    assert classify("msgstore.db.crypt14", random_head, 16384).kind is FileKind.ENCRYPTED_SUSPECT
    low = classify("x.db", b"\x00" * 4096, 4096)
    assert low.kind is FileKind.DB_UNRECOGNISED


def test_preserve_policy():
    assert should_preserve(classify("a.db", SQLITE, 4096), 4096)
    assert not should_preserve(classify("a.jpg", b"\xff\xd8\xff\xe0" + b"0" * 20, 10**9), 10**9)
    assert not should_preserve(classify("big.txt", b"a" * 4096, 100 * 1024 * 1024), 100 * 1024 * 1024)
    assert not should_preserve(classify("vault.db", os.urandom(4096), 4096), 4096)


def test_layout_detection_and_parsing():
    paths = ["userdata/data/data/com.a/databases/x.db", "userdata/data/user/0/com.b/files/y", "userdata/sdcard/Android/data/com.c/f.txt"]
    lay = analyze_layout(paths)
    assert lay.layout == "android_root_with_prefix" and [r.prefix for r in lay.roots] == ["userdata"]
    a = lay.locate(paths[0])
    assert (a.logical_path, a.package, a.area, a.app_root) == ("/data/data/com.a/databases/x.db", "com.a", "app_internal", "userdata/data/data/com.a")
    b = lay.locate(paths[1])
    assert (b.user_id, b.package) == (0, "com.b")
    c = lay.locate(paths[2])
    assert (c.package, c.area) == ("com.c", "app_external")


def test_app_directory_layout_and_loose_files():
    lay = analyze_layout(["com.foo/databases/a.db", "com.foo/shared_prefs/p.xml"])
    assert lay.layout == "app_directories"
    assert lay.locate("com.foo/databases/a.db").package == "com.foo"
    assert analyze_layout(["random/notes.txt", "other/a.bin"]).layout == "loose_files"
    assert analyze_layout(["only.db"]).layout == "single_file"
