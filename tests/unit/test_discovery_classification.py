"""Classification for filesystem discovery: databases, sidecars, XML, JSON, logs and media."""

import os

import pytest

from android_forensics.filesystem.classifier import classify, classify_unreadable
from android_forensics.filesystem.sidecars import SIDECAR_SUFFIX, sidecar_paths, split_sidecar
from android_forensics.models import FileKind, SidecarKind

SQLITE = b"SQLite format 3\x00" + b"\x00" * 100
TEXT = b"2024-03-01 08:00:00 I/ActivityManager: starting\n" * 5


def kind(path, head=TEXT, size=None):
    return classify(path, head, len(head) if size is None else size).kind


# ------------------------------------------------------------------ the categories the scanner reports


@pytest.mark.parametrize("fk,category", [
    (FileKind.SQLITE_DB, "database"), (FileKind.DB_UNRECOGNISED, "database"), (FileKind.ENCRYPTED_SUSPECT, "database"),
    (FileKind.SQLITE_WAL, "sqlite_wal"), (FileKind.SQLITE_SHM, "sqlite_shm"), (FileKind.SQLITE_JOURNAL, "sqlite_journal"),
    (FileKind.XML, "xml"), (FileKind.XML_BINARY, "xml"), (FileKind.JSON, "json"), (FileKind.LOG, "log"),
    (FileKind.IMAGE, "media"), (FileKind.VIDEO, "media"), (FileKind.AUDIO, "media"),
    (FileKind.TEXT, "other"), (FileKind.APK, "other"), (FileKind.UNKNOWN, "other"), (FileKind.EMPTY, "other"),
])
def test_every_file_kind_maps_to_a_discovery_category(fk, category):
    assert fk.category == category


def test_kind_predicates():
    assert {k for k in FileKind if k.is_media} == {FileKind.IMAGE, FileKind.VIDEO, FileKind.AUDIO}
    assert {k for k in FileKind if k.is_sidecar} == {FileKind.SQLITE_WAL, FileKind.SQLITE_SHM, FileKind.SQLITE_JOURNAL}
    assert {k for k in FileKind if k.is_database_candidate} == {FileKind.SQLITE_DB, FileKind.DB_UNRECOGNISED, FileKind.ENCRYPTED_SUSPECT}
    assert FileKind.SQLITE_WAL.is_sqlite_family and not FileKind.LOG.is_sqlite_family


# ------------------------------------------------------------------ log files


@pytest.mark.parametrize("path", [
    "data/local/tmp/app.log", "sdcard/logs/session.txt", "data/anr/traces.txt", "data/tombstones/tombstone_03",
    "data/system/dropbox/system_app_crash@1709.txt", "sdcard/x/app.log.1", "sdcard/x/app.log.old", "cache/recovery/last_kmsg",
    "sdcard/x/logcat", "sdcard/x/dmesg", "data/misc/logs/boot.txt", "sdcard/crash/report.txt",
])
def test_log_files_are_recognised_by_name_or_log_directory(path):
    assert kind(path) is FileKind.LOG


@pytest.mark.parametrize("path", ["sdcard/notes/todo.txt", "sdcard/catalog.txt", "sdcard/blog/post.txt", "data/data/com.x/files/readme"])
def test_ordinary_text_is_not_mistaken_for_a_log(path):
    assert kind(path) is FileKind.TEXT


def test_xml_and_json_win_over_log_directories_and_binary_files_are_never_logs():
    assert kind("sdcard/logs/config.xml", b"<?xml version='1.0'?><a/>") is FileKind.XML
    assert kind("sdcard/logs/config.json", b'{"a": 1}') is FileKind.JSON
    assert kind("sdcard/logs/blob.bin", bytes(range(256))) is FileKind.UNKNOWN
    assert kind("sdcard/app.log", b"\x00\x01\x02binary") is FileKind.UNKNOWN


# ------------------------------------------------------------------ media


@pytest.mark.parametrize("path,head,expected", [
    ("a.jpg", b"\xff\xd8\xff\xe0" + b"0" * 30, FileKind.IMAGE),
    ("a.png", b"\x89PNG\r\n\x1a\n" + b"0" * 30, FileKind.IMAGE),
    ("a.gif", b"GIF89a" + b"0" * 30, FileKind.IMAGE),
    ("a.webp", b"RIFF\x00\x00\x00\x00WEBPVP8 ", FileKind.IMAGE),
    ("a.tif", b"II*\x00" + b"0" * 30, FileKind.IMAGE),
    ("IMG.HEIC", b"\x00\x00\x00\x18ftypheic" + b"0" * 20, FileKind.IMAGE),
    ("a.avif", b"\x00\x00\x00\x18ftypavif" + b"0" * 20, FileKind.IMAGE),
    ("v.mp4", b"\x00\x00\x00\x18ftypisom" + b"0" * 20, FileKind.VIDEO),
    ("v.3gp", b"\x00\x00\x00\x14ftyp3gp4" + b"0" * 20, FileKind.VIDEO),
    ("v.mkv", b"\x1a\x45\xdf\xa3" + b"0" * 30, FileKind.VIDEO),
    ("v.avi", b"RIFF\x00\x00\x00\x00AVI LIST", FileKind.VIDEO),
    ("s.m4a", b"\x00\x00\x00\x18ftypM4A " + b"0" * 20, FileKind.AUDIO),
    ("s.wav", b"RIFF\x00\x00\x00\x00WAVEfmt ", FileKind.AUDIO),
    ("s.ogg", b"OggS" + b"\x00" * 30, FileKind.AUDIO),
    ("s.flac", b"fLaC" + b"\x00" * 30, FileKind.AUDIO),
    ("s.mp3", b"ID3\x03" + b"\x00" * 30, FileKind.AUDIO),
    ("s.amr", b"#!AMR\n" + b"\x00" * 30, FileKind.AUDIO),
])
def test_media_is_recognised_by_signature(path, head, expected):
    assert kind(path, head) is expected
    assert expected.is_media


def test_media_signature_beats_a_misleading_extension_and_extension_is_the_fallback():
    assert kind("holiday.txt", b"\xff\xd8\xff\xe0" + b"0" * 30) is FileKind.IMAGE
    assert kind("clip.mp4", bytes(range(200, 256)) * 3) is FileKind.VIDEO, "no signature: extension only"
    assert "extension only" in classify("clip.mp4", bytes(range(200, 256)) * 3, 168).detail


# ------------------------------------------------------------------ databases and sidecars


def test_databases_are_found_by_content_even_without_an_extension_or_with_a_lying_one():
    assert kind("data/data/com.android.chrome/app_chrome/Default/History", SQLITE) is FileKind.SQLITE_DB
    assert kind("sdcard/holiday.jpg", SQLITE) is FileKind.SQLITE_DB


def test_a_zero_length_database_is_a_database_not_just_an_empty_file():
    c = classify("data/data/com.x/databases/wiped.db", b"", 0)
    assert c.kind is FileKind.DB_UNRECOGNISED and "zero-length" in c.detail
    assert classify("notes/empty.txt", b"", 0).kind is FileKind.EMPTY


@pytest.mark.parametrize("name,fk", [("x.db-wal", FileKind.SQLITE_WAL), ("x.db-shm", FileKind.SQLITE_SHM), ("x.db-journal", FileKind.SQLITE_JOURNAL),
                                     ("History-journal", FileKind.SQLITE_JOURNAL), ("X.DB-WAL", FileKind.SQLITE_WAL)])
def test_sidecars_are_classified_by_name(name, fk):
    assert kind(f"d/{name}", b"\x00" * 64) is fk


def test_sidecar_content_signatures_are_recognised_under_any_name():
    assert kind("d/x.wal", b"\x37\x7f\x06\x82" + b"\x00" * 60) is FileKind.SQLITE_WAL
    assert kind("d/x.jrnl", bytes.fromhex("d9d505f920a163d7") + b"\x00" * 60) is FileKind.SQLITE_JOURNAL


def test_unreadable_files_are_classified_by_name_only_and_say_so():
    for path, expected in (("d/x.db", FileKind.DB_UNRECOGNISED), ("d/x.db-wal", FileKind.SQLITE_WAL), ("d/x.db-shm", FileKind.SQLITE_SHM),
                           ("d/x.db-journal", FileKind.SQLITE_JOURNAL), ("d/x.bin", FileKind.UNKNOWN), ("d/photo.jpg", FileKind.UNKNOWN)):
        c = classify_unreadable(path, "PermissionError")
        assert c.kind is expected and "unreadable" in c.detail and "PermissionError" in c.detail


# ------------------------------------------------------------------ sidecar naming rules


def test_sidecar_paths_and_their_inverse():
    paths = sidecar_paths("data/data/com.x/databases/a.db")
    assert paths == {SidecarKind.WAL: "data/data/com.x/databases/a.db-wal", SidecarKind.SHM: "data/data/com.x/databases/a.db-shm",
                     SidecarKind.JOURNAL: "data/data/com.x/databases/a.db-journal"}
    for kind_, p in paths.items():
        assert split_sidecar(p) == ("data/data/com.x/databases/a.db", kind_)
    assert set(SIDECAR_SUFFIX) == set(SidecarKind)


def test_split_sidecar_handles_case_extensionless_databases_and_non_sidecars():
    assert split_sidecar("d/History-journal") == ("d/History", SidecarKind.JOURNAL)
    assert split_sidecar("d/A.DB-SHM") == ("d/A.DB", SidecarKind.SHM)
    for name in ("d/a.db", "d/a.wal", "d/notes-wal-backup", "-wal", ""):
        assert split_sidecar(name) is None


def test_classification_never_raises_on_hostile_input():
    for head in (b"", b"\x00" * 10, os.urandom(4096), b"\xff" * 5000, b"<" * 3000):
        for name in ("", "a", "a.db", "x/y/z.log", "-wal", "é ☃.jpg"):
            assert classify(name, head, len(head)).kind in set(FileKind)
