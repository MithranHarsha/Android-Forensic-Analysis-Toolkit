"""The evidence-ingestion library end to end, using only small synthetic files (no case database involved)."""

from __future__ import annotations

import bz2
import hashlib
import io
import json
import os
import re
import sqlite3
import stat
import struct
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

from android_forensics import TOOL_NAME, __version__
from android_forensics.acquisition import (
    ExtractionBudget,
    IngestionSession,
    PreservePolicy,
    ingest_evidence,
    make_manifest,
    read_manifest,
    verify_manifest,
    write_manifest_file,
)
from android_forensics.errors import IngestionError
from android_forensics.models import FileKind, SourceType
from android_forensics.workspace import Workspace

CASE_ID = "0123456789abcdef0123456789abcdef"
BASE_TIME = 1_709_280_000  # 2024-03-01T08:00:00Z
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions/symlinks")


# ------------------------------------------------------------------ synthetic evidence


def _sqlite_bytes(tmp: Path) -> bytes:
    p = tmp / "_seed.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE t(a)")
    c.executemany("INSERT INTO t VALUES(?)", [(i,) for i in range(20)])
    c.commit()
    c.close()
    data = p.read_bytes()
    p.unlink()
    return data


def synthetic_contents(tmp: Path) -> dict[str, bytes]:
    big = bytes((i * 31 + 7) % 251 for i in range(1000)) * 2700  # 2.7 MB: crosses the 1 MiB read chunk twice
    return {
        "data/data/com.example.app/databases/app.db": _sqlite_bytes(tmp),
        "data/data/com.example.app/databases/app.db-wal": b"\x37\x7f\x06\x82" + b"\x00" * 60,
        "data/data/com.example.app/shared_prefs/prefs.xml": b"<?xml version='1.0'?>\n<map><string name=\"k\">v</string></map>\n",
        "data/system/users/0.xml": b"<?xml version='1.0'?><user id=\"0\"/>\n",
        "sdcard/DCIM/Camera/IMG_0001.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(range(256)) * 4 + b"\xff\xd9",
        "sdcard/notes/empty.txt": b"",
        "sdcard/notes/a/b/c/d/e/leaf.txt": b"a leaf, five directories down",
        "sdcard/Download/café ☃ report.txt": b"unicode name",
        "sdcard/.hidden": b"hidden file",
        "sdcard/A/name.txt": b"same basename, first directory",
        "sdcard/B/name.txt": b"same basename, second directory",
        "sdcard/big.bin": big,
    }


def write_tree(root: Path, contents: dict[str, bytes]) -> None:
    for i, (rel, data) in enumerate(sorted(contents.items())):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        ts = BASE_TIME + i * 60
        os.utime(p, (ts, ts))


def make_zip(root: Path, dest: Path) -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(x for x in root.rglob("*") if x.is_file()):
            zi = zipfile.ZipInfo(p.relative_to(root).as_posix(), date_time=time.gmtime(p.stat().st_mtime)[:6])
            zi.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zi, p.read_bytes())


def make_tar(root: Path, dest: Path, mode: str) -> None:
    if mode == "bz2-manual":
        raise AssertionError
    with tarfile.open(dest, mode) as tf:
        for p in sorted(x for x in root.rglob("*") if x.is_file()):
            tf.add(p, arcname=p.relative_to(root).as_posix())


@pytest.fixture()
def contents(tmp_path):
    return synthetic_contents(tmp_path)


@pytest.fixture()
def tree(tmp_path, contents):
    root = tmp_path / "evidence" / "acq"
    write_tree(root, contents)
    return root


def package(tree: Path, tmp_path: Path, kind: str) -> Path:
    if kind == "directory":
        return tree
    dest = tmp_path / "evidence" / {"zip": "acq.zip", "tar": "acq.tar", "tar.gz": "acq.tar.gz", "tar.bz2": "acq.tar.bz2", "tar.xz": "acq.tar.xz"}[kind]
    if kind == "zip":
        make_zip(tree, dest)
    else:
        make_tar(tree, dest, {"tar": "w", "tar.gz": "w:gz", "tar.bz2": "w:bz2", "tar.xz": "w:xz"}[kind])
    return dest


def expected_hashes(contents: dict[str, bytes]) -> dict[str, tuple]:
    return {
        rel: (len(d), hashlib.md5(d).hexdigest(), hashlib.sha1(d).hexdigest(), hashlib.sha256(d).hexdigest())
        for rel, d in contents.items()
    }


def snapshot(root: Path) -> dict[str, tuple]:
    """Everything observable about a tree: entries, sizes, modes, mtimes, and content hashes."""
    snap = {}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink() else None
        snap[p.relative_to(root).as_posix()] = (st.st_size, stat.S_IMODE(st.st_mode), st.st_mtime_ns, digest)
    return snap


KINDS = ["directory", "zip", "tar", "tar.gz", "tar.bz2", "tar.xz"]


# ------------------------------------------------------------------ 1. every supported input


@pytest.mark.parametrize("kind", KINDS)
def test_every_input_type_yields_exact_sizes_and_hashes(kind, tmp_path, tree, contents):
    src = package(tree, tmp_path, kind)
    r = ingest_evidence(src, tmp_path / "work", case_id=CASE_ID)
    assert r.complete and r.issues == []
    got = {f.path: (f.size, f.hashes.md5, f.hashes.sha1, f.hashes.sha256) for f in r.files}
    assert got == expected_hashes(contents)
    assert r.source.source_type is (SourceType.DIRECTORY if kind == "directory" else SourceType.ZIP if kind == "zip" else SourceType.TAR)
    assert r.totals.files == len(contents) and r.totals.bytes == sum(len(d) for d in contents.values())


def test_all_input_types_agree_with_each_other(tmp_path, tree):
    listings = {}
    for kind in KINDS:
        r = ingest_evidence(package(tree, tmp_path, kind), tmp_path / f"work_{kind}", case_id=CASE_ID)
        listings[kind] = [(f.path, f.size, f.hashes.sha256, f.kind.value) for f in sorted(r.files, key=lambda f: f.path)]
    assert all(v == listings["directory"] for v in listings.values())


def test_files_are_classified_by_content(tmp_path, tree):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    kinds = {f.path.rsplit("/", 1)[-1]: f.kind for f in r.files}
    assert kinds["app.db"] is FileKind.SQLITE_DB and kinds["app.db-wal"] is FileKind.SQLITE_WAL
    assert kinds["prefs.xml"] is FileKind.XML and kinds["IMG_0001.jpg"] is FileKind.IMAGE
    assert kinds["leaf.txt"] is FileKind.TEXT and kinds["empty.txt"] is FileKind.EMPTY


def test_a_single_database_brings_its_sidecars(tmp_path, contents):
    lab = tmp_path / "lab"
    lab.mkdir()
    db = lab / "calls.db"
    db.write_bytes(contents["data/data/com.example.app/databases/app.db"])
    (lab / "calls.db-wal").write_bytes(b"\x37\x7f\x06\x83" + b"\x00" * 28)
    (lab / "calls.db-shm").write_bytes(b"\x00" * 64)
    (lab / "unrelated.txt").write_text("not a sidecar")
    r = ingest_evidence(db, tmp_path / "work", case_id=CASE_ID)
    assert r.source.source_type is SourceType.SINGLE_FILE
    assert sorted(f.path for f in r.files) == ["calls.db", "calls.db-shm", "calls.db-wal"]
    assert {e.original_path for e in r.manifest.sources[0].files} == {str(lab.resolve() / n) for n in ("calls.db", "calls.db-shm", "calls.db-wal")}


# ------------------------------------------------------------------ 2. the manifest


@pytest.mark.parametrize("kind", ["directory", "zip", "tar", "tar.gz"])
def test_manifest_records_everything_that_was_asked_for(kind, tmp_path, tree, contents):
    src = package(tree, tmp_path, kind)
    before = time.time()
    ingest_evidence(src, tmp_path / "work", case_id=CASE_ID, case_name="synthetic")
    on_disk = json.loads((tmp_path / "work" / "evidence_manifest.json").read_text())

    assert on_disk["case_id"] == CASE_ID and on_disk["case_name"] == "synthetic"
    assert on_disk["tool_version"] == __version__ and on_disk["tool_name"] == TOOL_NAME
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", on_disk["analysis_timestamp"])
    stamp = time.mktime(time.strptime(on_disk["analysis_timestamp"][:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    assert before - 5 <= stamp <= time.time() + 5

    [source] = on_disk["sources"]
    assert source["original_path"] == str(src.resolve())
    assert len(source["files"]) == len(contents) and source["file_count"] == len(contents)
    assert source["total_bytes"] == sum(len(d) for d in contents.values())
    for entry in source["files"]:
        size, md5, sha1, sha256 = expected_hashes(contents)[entry["relative_path"]]
        assert (entry["size"], entry["md5"], entry["sha1"], entry["sha256"]) == (size, md5, sha1, sha256)
        if kind == "directory":
            assert entry["original_path"] == os.path.join(str(src.resolve()), entry["relative_path"])
        else:
            assert entry["original_path"] == f"{src.resolve()}!/{entry['relative_path']}"
    if kind != "directory":
        assert source["container_sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
        assert source["container_md5"] == hashlib.md5(src.read_bytes()).hexdigest()


def test_manifest_hash_sidecar_and_round_trip(tmp_path, tree):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    path = r.manifest_path
    assert r.manifest_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert (path.parent / "evidence_manifest.json.sha256").read_text() == f"{r.manifest_sha256}  evidence_manifest.json\n"
    assert read_manifest(path) == r.manifest


def test_case_id_is_generated_when_omitted_and_manifest_can_be_skipped(tmp_path, tree):
    r = ingest_evidence(tree, tmp_path / "work")
    assert re.fullmatch(r"[0-9a-f]{32}", r.manifest.case_id)
    r2 = ingest_evidence(tree, tmp_path / "work2", case_id=CASE_ID, write_manifest=False)
    assert r2.manifest_path is None and not (tmp_path / "work2" / "evidence_manifest.json").exists()
    assert r2.manifest.case_id == CASE_ID, "the manifest object is still returned"


def test_manifest_lists_each_preserved_copy_under_the_workdir(tmp_path, tree):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    for entry in r.manifest.sources[0].files:
        if entry.preserved_copy:
            assert (r.workspace.root / entry.preserved_copy).is_file()
    assert {e.relative_path.rsplit("/", 1)[-1] for e in r.manifest.sources[0].files if e.preserved_copy} == {
        "app.db", "app.db-wal", "prefs.xml", "0.xml", "leaf.txt", "café ☃ report.txt", ".hidden", "name.txt"}


# ------------------------------------------------------------------ 3. the original evidence is never modified


@pytest.mark.parametrize("kind", KINDS)
def test_ingestion_leaves_the_evidence_byte_for_byte_and_timestamp_for_timestamp_identical(kind, tmp_path, tree):
    src = package(tree, tmp_path, kind)
    evidence_root = tmp_path / "evidence"
    before = snapshot(evidence_root)
    ingest_evidence(src, tmp_path / "work", case_id=CASE_ID)
    after = snapshot(evidence_root)
    assert after == before, "no file was changed, added, removed or re-timestamped"
    dir_mtimes = {p: (evidence_root / p).stat().st_mtime_ns for p in before}
    assert all(dir_mtimes[p] == before[p][2] for p in before)


def test_everything_written_lands_inside_the_working_directory(tmp_path, tree):
    everything_before = {p for p in tmp_path.rglob("*")}
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    created = {p for p in tmp_path.rglob("*")} - everything_before
    assert created and all(r.workspace.root in p.parents or p == r.workspace.root for p in created)


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores read-only permissions")
def test_evidence_that_is_physically_read_only_can_still_be_ingested(tmp_path, tree, contents):
    for p in sorted(tree.rglob("*"), reverse=True):
        os.chmod(p, 0o555 if p.is_dir() else 0o444)
    os.chmod(tree, 0o555)
    try:
        r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
        assert r.complete and {f.path for f in r.files} == set(contents)
        assert all(stat.S_IMODE(p.stat().st_mode) in (0o555, 0o444) for p in tree.rglob("*"))
    finally:
        for p in [tree, *tree.rglob("*")]:
            os.chmod(p, 0o755 if p.is_dir() else 0o644)


def test_preserved_copies_are_identical_write_protected_and_only_for_analysis_files(tmp_path, tree, contents):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    preserved = r.preserved_files
    assert preserved and len(preserved) < len(r.files)
    for f in preserved:
        copy = r.workspace.source_dir(f.source_id) / f.preserved_copy
        assert copy.read_bytes() == contents[f.path]
        if sys.platform != "win32":
            assert stat.S_IMODE(copy.stat().st_mode) == 0o444
    assert not any(f.preserved_copy for f in r.files if f.path.endswith((".jpg", ".bin")))


# ------------------------------------------------------------------ 4. the working analysis directory


def test_working_directory_is_created_with_its_layout(tmp_path, tree):
    work = tmp_path / "deep" / "er" / "work"
    r = ingest_evidence(tree, work, case_id=CASE_ID)
    for sub in ("evidence", "scratch", "reports"):
        assert (work / sub).is_dir()
    assert r.workspace.source_dir(1).is_dir() and list(r.workspace.source_dir(1).iterdir())


def test_the_same_working_directory_can_be_reused_for_several_sources(tmp_path, tree, contents):
    zip_src = package(tree, tmp_path, "zip")
    a = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    b = ingest_evidence(zip_src, tmp_path / "work", case_id=CASE_ID)
    assert (a.source.id, b.source.id) == (1, 2)
    assert (tmp_path / "work" / "evidence" / "s1").is_dir() and (tmp_path / "work" / "evidence" / "s2").is_dir()
    assert {f.path for f in b.files} == set(contents)
    merged = make_manifest(CASE_ID, "two sources", [(a.source, a.files), (b.source, b.files)])
    assert [s.source_id for s in merged.sources] == [1, 2] and verify_manifest(merged, a.workspace).ok


def test_preserved_evidence_is_never_mixed_or_overwritten(tmp_path, tree):
    ws = Workspace(tmp_path / "work")
    ingest_evidence(tree, ws.root, case_id=CASE_ID)
    session = IngestionSession(tree, ws, case_id=CASE_ID)
    session.prepare()
    session.bind_source_id(1)
    with pytest.raises(IngestionError, match="refusing to mix"):
        next(session.run())


def test_workdir_and_evidence_must_not_overlap(tmp_path, tree):
    with pytest.raises(IngestionError, match="must not be inside the evidence directory"):
        ingest_evidence(tree, tree / "work", case_id=CASE_ID)
    with pytest.raises(IngestionError, match="cannot be the evidence"):
        ingest_evidence(tree, tree, case_id=CASE_ID)
    inner = tmp_path / "work"
    (inner / "planted").mkdir(parents=True)
    with pytest.raises(IngestionError, match="inside the working directory"):
        ingest_evidence(inner / "planted", inner, case_id=CASE_ID)
    assert not (tree / "work").exists(), "a rejected run creates nothing inside the evidence"


def test_workdir_that_is_a_file_is_rejected(tmp_path, tree):
    f = tmp_path / "file"
    f.write_text("x")
    with pytest.raises(IngestionError, match="not a directory"):
        ingest_evidence(tree, f, case_id=CASE_ID)


def test_preserve_policies(tmp_path, tree, contents):
    analysis = ingest_evidence(tree, tmp_path / "w1", case_id=CASE_ID, preserve=PreservePolicy.ANALYSIS)
    everything = ingest_evidence(tree, tmp_path / "w2", case_id=CASE_ID, preserve=PreservePolicy.ALL)
    nothing = ingest_evidence(tree, tmp_path / "w3", case_id=CASE_ID, preserve=PreservePolicy.NONE)
    assert 0 < len(analysis.preserved_files) < len(everything.preserved_files) == len(contents)
    assert nothing.preserved_files == [] and not any((tmp_path / "w3" / "evidence").rglob("*_*"))
    for result in (analysis, everything, nothing):
        assert {f.path: f.hashes.sha256 for f in result.files} == {p: h[3] for p, h in expected_hashes(contents).items()}
    big = next(f for f in everything.files if f.path == "sdcard/big.bin")
    assert (everything.workspace.source_dir(1) / big.preserved_copy).read_bytes() == contents["sdcard/big.bin"]


# ------------------------------------------------------------------ 5. recursive enumeration


def test_recursion_hidden_unicode_empty_and_duplicate_names(tmp_path, tree, contents):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    paths = {f.path for f in r.files}
    assert "sdcard/notes/a/b/c/d/e/leaf.txt" in paths and "sdcard/.hidden" in paths and "sdcard/Download/café ☃ report.txt" in paths
    assert {"sdcard/A/name.txt", "sdcard/B/name.txt"} <= paths
    empty = next(f for f in r.files if f.path.endswith("empty.txt"))
    assert empty.size == 0 and empty.hashes.sha256 == hashlib.sha256(b"").hexdigest()
    copies = [f.preserved_copy for f in r.files if f.path.endswith("name.txt")]
    assert len(set(copies)) == 2, "files sharing a name never collide in the working directory"


def test_empty_directories_are_not_files_and_an_empty_source_is_valid(tmp_path):
    ev = tmp_path / "ev"
    (ev / "a" / "b").mkdir(parents=True)
    r = ingest_evidence(ev, tmp_path / "work", case_id=CASE_ID)
    assert r.files == [] and r.complete and r.manifest.sources[0].file_count == 0
    assert verify_manifest(r.manifest, r.workspace).ok


def test_enumeration_order_and_ordinals_are_deterministic(tmp_path, tree):
    a = ingest_evidence(tree, tmp_path / "w1", case_id=CASE_ID)
    b = ingest_evidence(tree, tmp_path / "w2", case_id=CASE_ID)
    key = lambda r: [(f.ordinal, f.path, f.size, f.hashes, f.kind, f.preserved_copy) for f in r.files]  # noqa: E731
    assert key(a) == key(b) and [f.ordinal for f in a.files] == list(range(len(a.files)))


@posix_only
def test_symlinks_are_reported_never_followed(tmp_path, tree):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    os.symlink(outside, tree / "linked_dir")
    os.symlink(outside / "secret.txt", tree / "linked_file")
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    assert {i.path: i.issue_type for i in r.issues} == {"linked_dir": "symlink_skipped", "linked_file": "symlink_skipped"}
    assert not any("secret" in f.path or "linked" in f.path for f in r.files)


def test_thousands_of_tiny_files(tmp_path):
    ev = tmp_path / "ev"
    for i in range(1500):
        d = ev / f"d{i % 30}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"f{i}.txt").write_bytes(f"file {i}".encode())
    r = ingest_evidence(ev, tmp_path / "work", case_id=CASE_ID)
    assert len(r.files) == 1500 and r.totals.bytes == sum(len(f"file {i}") for i in range(1500))
    assert len({f.hashes.sha256 for f in r.files}) == 1500


def test_streaming_session_yields_incrementally_and_finalises_only_when_done(tmp_path, tree, contents):
    ws = Workspace(tmp_path / "work")
    session = IngestionSession(tree, ws, case_id=CASE_ID)
    stream = session.run()
    first = next(stream)
    assert session.totals.files == 1 and first.path in contents
    with pytest.raises(RuntimeError, match="exhausted"):
        session.finalized_source()
    rest = list(stream)
    final = session.finalized_source()
    assert final.file_count == 1 + len(rest) == len(contents) and final.id == 1 and final.complete


# ------------------------------------------------------------------ 6. timestamps


def test_directory_timestamps_come_from_the_filesystem(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    p = ev / "a.txt"
    p.write_text("timed")
    os.utime(p, (BASE_TIME + 5, BASE_TIME))
    [f] = ingest_evidence(ev, tmp_path / "work", case_id=CASE_ID).files
    assert f.times.mtime == "2024-03-01T08:00:00.000Z" and f.times.atime == "2024-03-01T08:00:05.000Z"
    assert f.times.ctime is not None and f.times.basis.startswith("fs_stat")


def test_tar_timestamps_including_pax_extended_times(tmp_path):
    plain, pax = tmp_path / "plain.tar", tmp_path / "pax.tar"
    for dest, fmt, headers in ((plain, tarfile.USTAR_FORMAT, {}), (pax, tarfile.PAX_FORMAT, {"atime": "1709280060.5", "ctime": "1709280120"})):
        with tarfile.open(dest, "w", format=fmt) as tf:
            ti = tarfile.TarInfo("d/x.txt")
            ti.size, ti.mtime = 3, BASE_TIME
            ti.pax_headers = dict(headers)
            tf.addfile(ti, io.BytesIO(b"abc"))
    [a] = ingest_evidence(plain, tmp_path / "w1", case_id=CASE_ID).files
    [b] = ingest_evidence(pax, tmp_path / "w2", case_id=CASE_ID).files
    assert a.times.mtime == b.times.mtime == "2024-03-01T08:00:00.000Z" and a.times.atime is None
    assert b.times.atime == "2024-03-01T08:01:00.500Z" and b.times.ctime == "2024-03-01T08:02:00.000Z" and "PAX" in b.times.basis


def test_zip_timestamps_prefer_the_utc_extra_field_over_dos_time(tmp_path):
    z = tmp_path / "t.zip"
    with zipfile.ZipFile(z, "w") as zf:
        dos = zipfile.ZipInfo("dos.txt", date_time=(2024, 3, 1, 8, 0, 0))
        ut = zipfile.ZipInfo("ut.txt", date_time=(2024, 3, 1, 8, 0, 0))
        ut.extra = struct.pack("<HHBl", 0x5455, 5, 1, BASE_TIME + 3600)
        zf.writestr(dos, "d")
        zf.writestr(ut, "u")
    files = {f.path: f.times for f in ingest_evidence(z, tmp_path / "work", case_id=CASE_ID).files}
    assert files["dos.txt"].mtime == "2024-03-01T08:00:00.000Z" and "timezone unspecified" in files["dos.txt"].basis
    assert files["ut.txt"].mtime == "2024-03-01T09:00:00.000Z" and "UTC" in files["ut.txt"].basis


# ------------------------------------------------------------------ 7. files that change while being read


def _install_mutating_open(monkeypatch, when: str):
    from android_forensics.acquisition import base

    real_open = base.open_readonly

    class MutatingReader:
        def __init__(self, path):
            self.path = path
            if when == "open":
                self._append()
            self._real = real_open(path)
            self._done = False

        def _append(self):
            with open(self.path, "ab") as fh:
                fh.write(b"<appended while the evidence was being acquired>")

        def read(self, n=-1):
            data = self._real.read(n)
            if when == "read" and not self._done:
                self._done = True
                self._append()
            return data

        def fileno(self):
            return self._real.fileno()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._real.close()

    monkeypatch.setattr(base, "open_readonly", lambda path: MutatingReader(path) if str(path).endswith("victim.txt") else real_open(path))


@pytest.mark.parametrize("when", ["read", "open"])
def test_a_file_that_changes_during_acquisition_is_recorded_but_flagged(when, monkeypatch, tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    (ev / "victim.txt").write_bytes(b"original content " * 100)
    (ev / "stable.txt").write_bytes(b"stable")
    _install_mutating_open(monkeypatch, when)
    r = ingest_evidence(ev, tmp_path / "work", case_id=CASE_ID)
    flagged = [i for i in r.issues if i.issue_type == "changed_during_read"]
    assert [i.path for i in flagged] == ["victim.txt"] and "not a stable version" in flagged[0].detail
    assert {f.path for f in r.files} == {"victim.txt", "stable.txt"}, "the file is still listed, with the hash of what was read"
    assert r.complete and all(i.path != "stable.txt" for i in r.issues)


# ------------------------------------------------------------------ 8. damaged, hostile and unusual input


def test_truncated_archive_is_incomplete_but_keeps_what_was_read(tmp_path, tree):
    src = package(tree, tmp_path, "tar.gz")
    data = src.read_bytes()
    src.write_bytes(data[: len(data) // 2])
    r = ingest_evidence(src, tmp_path / "work", case_id=CASE_ID)
    assert not r.complete and not r.source.complete
    assert r.issues and {i.issue_type for i in r.issues} <= {"archive_truncated", "member_read_error"}, "where the cut lands decides which"
    assert all(i.incomplete for i in r.issues)
    assert 0 < len(r.files) < len(synthetic_contents(tmp_path))
    assert r.manifest.sources[0].complete is False and len(r.manifest.sources[0].files) == len(r.files)


def test_corrupt_zip_member_is_skipped_and_reported_without_losing_the_rest(tmp_path):
    z = tmp_path / "c.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("good1.txt", "first good file")
        zf.writestr("bad.txt", "PAYLOAD-OF-THE-CORRUPT-MEMBER")
        zf.writestr("good2.txt", "second good file")
    raw = bytearray(z.read_bytes())
    raw[raw.index(b"PAYLOAD-OF-THE-CORRUPT-MEMBER") + 3] ^= 0xFF
    z.write_bytes(bytes(raw))
    r = ingest_evidence(z, tmp_path / "work", case_id=CASE_ID, preserve=PreservePolicy.ALL)
    assert sorted(f.path for f in r.files) == ["good1.txt", "good2.txt"]
    assert [i.issue_type for i in r.issues] == ["member_read_error"] and "CRC" in r.issues[0].detail
    assert not any("bad.txt" in p.name for p in (tmp_path / "work" / "evidence").rglob("*")), "no partial copy is left behind"


def test_archive_attacks_are_recorded_and_write_nothing_outside_the_workdir(tmp_path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../escaped.txt", "x")
        zf.writestr("ok.txt", "ok")
    r = ingest_evidence(z, tmp_path / "work", case_id=CASE_ID, preserve=PreservePolicy.ALL)
    assert [f.path for f in r.files] == ["ok.txt"] and [i.issue_type for i in r.issues] == ["unsafe_path_skipped"]
    assert not list(tmp_path.rglob("escaped.txt"))


def test_extraction_budget_makes_the_acquisition_incomplete(tmp_path, tree):
    r = ingest_evidence(package(tree, tmp_path, "zip"), tmp_path / "work", case_id=CASE_ID, budget=ExtractionBudget(max_entries=3))
    assert not r.complete and len(r.files) == 3 and any(i.issue_type == "budget_exceeded" for i in r.issues)


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores permissions")
def test_unreadable_files_and_directories_are_recorded_not_fatal(tmp_path):
    ev = tmp_path / "ev"
    (ev / "locked").mkdir(parents=True)
    (ev / "locked" / "x.txt").write_text("x")
    (ev / "ok.txt").write_text("ok")
    (ev / "secret.txt").write_text("s")
    os.chmod(ev / "secret.txt", 0)
    os.chmod(ev / "locked", 0)
    try:
        r = ingest_evidence(ev, tmp_path / "work", case_id=CASE_ID)
        assert [f.path for f in r.files] == ["ok.txt"]
        assert {i.path: i.issue_type for i in r.issues} == {"locked": "unreadable_directory", "secret.txt": "read_error"}
    finally:
        os.chmod(ev / "locked", 0o755)
        os.chmod(ev / "secret.txt", 0o644)


def test_bad_inputs_are_rejected_with_clear_errors(tmp_path, tree):
    with pytest.raises(IngestionError, match="does not exist"):
        ingest_evidence(tmp_path / "missing", tmp_path / "work", case_id=CASE_ID)
    with pytest.raises(IngestionError, match="timezone"):
        ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID, acquired_at="2024-06-04T08:00:00")
    assert not (tmp_path / "work" / "evidence" / "s1").exists()
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID, acquired_at="2024-06-04T13:30:00+05:30")
    assert r.manifest.sources[0].acquisition_time == "2024-06-04T08:00:00.000Z"


def test_an_unrecognised_regular_file_is_treated_as_a_single_file_source(tmp_path):
    blob = tmp_path / "blob.gz"
    blob.write_bytes(bz2.compress(b"not a tar archive"))
    r = ingest_evidence(blob, tmp_path / "work", case_id=CASE_ID)
    assert r.source.source_type is SourceType.SINGLE_FILE and [f.path for f in r.files] == ["blob.gz"]


# ------------------------------------------------------------------ 9. verifying evidence against the manifest


def _flip(path: Path, offset: int = 3) -> None:
    os.chmod(path, 0o644)
    raw = bytearray(path.read_bytes())
    raw[offset] ^= 0xFF
    path.write_bytes(bytes(raw))


def kinds_of(report):
    return sorted(d.kind for d in report.discrepancies)


def test_untouched_evidence_verifies_cleanly(tmp_path, tree):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    report = verify_manifest(r.manifest, r.workspace)
    assert report.ok and report.checked == len(r.files) + len(r.preserved_files)
    assert verify_manifest(read_manifest(r.manifest_path)).ok, "a manifest read back from disk verifies the same"


def test_a_modified_missing_or_added_original_is_detected(tmp_path, tree):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    _flip(tree / "sdcard/notes/a/b/c/d/e/leaf.txt")
    (tree / "sdcard/.hidden").unlink()
    (tree / "sdcard/added-after-ingest.txt").write_text("new")
    report = verify_manifest(r.manifest, r.workspace)
    assert kinds_of(report) == ["original_missing", "original_modified", "original_unlisted"]
    assert {Path(d.path).name for d in report.discrepancies} == {"leaf.txt", ".hidden", "added-after-ingest.txt"}


def test_a_modified_or_missing_preserved_copy_is_detected(tmp_path, tree):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    copies = sorted(r.workspace.source_dir(1).iterdir())
    _flip(copies[0])
    copies[1].unlink()
    report = verify_manifest(r.manifest, r.workspace)
    assert kinds_of(report) == ["preserved_missing", "preserved_modified"]
    assert verify_manifest(r.manifest).ok, "without a workspace the preserved copies are not examined"


@pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz"])
def test_a_modified_or_missing_archive_is_detected(kind, tmp_path, tree):
    src = package(tree, tmp_path, kind)
    r = ingest_evidence(src, tmp_path / "work", case_id=CASE_ID)
    assert verify_manifest(r.manifest).ok
    _flip(src, offset=len(src.read_bytes()) // 2)
    assert kinds_of(verify_manifest(r.manifest)) == ["container_modified"]
    src.unlink()
    assert kinds_of(verify_manifest(r.manifest)) == ["container_missing"]


def test_a_sidecar_added_to_a_single_database_after_ingest_is_detected(tmp_path, contents):
    lab = tmp_path / "lab"
    lab.mkdir()
    db = lab / "x.db"
    db.write_bytes(contents["data/data/com.example.app/databases/app.db"])
    r = ingest_evidence(db, tmp_path / "work", case_id=CASE_ID)
    assert verify_manifest(r.manifest, r.workspace).ok
    (lab / "x.db-wal").write_bytes(b"\x37\x7f\x06\x82" + b"\x00" * 28)
    assert kinds_of(verify_manifest(r.manifest, r.workspace)) == ["original_unlisted"]


def test_the_manifest_alone_is_enough_to_detect_tampering_with_the_manifest_itself(tmp_path, tree):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    recorded = (r.manifest_path.parent / "evidence_manifest.json.sha256").read_text().split()[0]
    text = r.manifest_path.read_text().replace(r.files[0].hashes.sha256, "0" * 64)
    r.manifest_path.write_text(text)
    assert hashlib.sha256(r.manifest_path.read_bytes()).hexdigest() != recorded
    assert not verify_manifest(read_manifest(r.manifest_path), r.workspace).ok
    write_manifest_file(r.manifest, r.manifest_path)
    assert verify_manifest(read_manifest(r.manifest_path), r.workspace).ok


@posix_only
def test_an_original_or_copy_swapped_for_a_symlink_is_reported_not_followed(tmp_path, tree):
    r = ingest_evidence(tree, tmp_path / "work", case_id=CASE_ID)
    original = tree / "sdcard/notes/a/b/c/d/e/leaf.txt"
    twin = tmp_path / "twin.txt"
    twin.write_bytes(original.read_bytes())  # identical content: a naive verifier following the link would call it clean
    original.unlink()
    os.symlink(twin, original)
    copy = sorted(r.workspace.source_dir(1).iterdir())[0]
    copy_twin = tmp_path / "copy_twin"
    copy_twin.write_bytes(copy.read_bytes())
    copy.unlink()
    os.symlink(copy_twin, copy)
    report = verify_manifest(r.manifest, r.workspace)
    assert kinds_of(report) == ["original_unreadable", "preserved_unreadable"]
    assert all("symlink" in d.detail for d in report.discrepancies)
