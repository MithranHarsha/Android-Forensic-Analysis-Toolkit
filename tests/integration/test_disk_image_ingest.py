from __future__ import annotations

import gzip
from pathlib import Path

import pytest
from typer.testing import CliRunner

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.cli.app import app
from android_forensics.models import SourceType
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, run_pipeline
from android_forensics.storage.case_store import CaseStore

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="module")
def userdata_img(tmp_path_factory) -> Path:
    p = tmp_path_factory.mktemp("img") / "userdata.img"
    p.write_bytes(gzip.decompress((FIXTURES / "android_userdata_ext4.img.gz").read_bytes()))
    return p


def _files(store: CaseStore) -> dict[str, str]:
    return {r["path"]: r["sha256"] for r in store.q("SELECT path, sha256 FROM evidence_files")}


def test_image_yields_the_same_files_and_artifacts_as_the_directory_dump(synth, userdata_img, tmp_path):
    out, _ = synth
    dir_store = CaseStore.create(tmp_path / "dir", "dir", "t")
    ingest_source(dir_store, out / "android_dump")
    img_store = CaseStore.create(tmp_path / "img", "img", "t")
    summary = ingest_source(img_store, userdata_img)
    assert summary.source_type is SourceType.DISK_IMAGE and summary.container_sha256 and summary.complete

    from_dir = {p: h for p, h in _files(dir_store).items() if p.startswith("data/")}
    from_img = _files(img_store)
    assert from_img.keys() == from_dir.keys()
    # SQLite files embed the library version and random WAL salts, so databases made on another machine/SQLite differ byte-wise from a
    # fresh dump; the ext4 reader's byte-exactness is proved against a known tree in tests/unit/test_ext4_images.py. Here every
    # file that SQLite did not write (xml, json, text, media) must match exactly.
    plain = {p for p in from_img if not p.endswith((".db", "-wal", "-shm", "-journal", "History", ".sqlite", ".sqlite3"))}
    assert plain and all(from_img[p] == from_dir[p] for p in plain)

    run_pipeline(dir_store, names=list(FULL_PIPELINE_NAMES))
    run_pipeline(img_store, names=list(FULL_PIPELINE_NAMES))
    q = "SELECT artifact_type, status, COUNT(*) n FROM artifacts WHERE status='ACTIVE' GROUP BY 1,2 ORDER BY 1,2"
    dir_counts = [tuple(r) for r in dir_store.q(q)]
    img_counts = [tuple(r) for r in img_store.q(q)]
    assert img_counts == dir_counts and dir_counts  # the same active artifacts from the image as from the directory
    # deleted-record recovery works inside the image too (exact counts depend on the SQLite version that laid out the pages)
    assert img_store.scalar("SELECT COUNT(*) FROM recovered_records") > 0 and dir_store.scalar("SELECT COUNT(*) FROM recovered_records") > 0


def test_image_source_is_recorded_with_format_and_filesystem_notes(userdata_img, tmp_path):
    store = CaseStore.create(tmp_path / "c", "c", "t")
    ingest_source(store, userdata_img)
    issues = {r["issue_type"]: r["detail"] for r in store.q("SELECT issue_type, detail FROM scan_issues WHERE stage='ingest'")}
    assert "raw image" in issues["image_format"]
    assert "ext2/3/4" in issues["filesystem_found"] and "userdata" in issues["filesystem_found"]


def test_original_image_is_never_modified(userdata_img, tmp_path):
    import hashlib
    before = hashlib.sha256(userdata_img.read_bytes()).hexdigest()
    st = userdata_img.stat()
    store = CaseStore.create(tmp_path / "c", "c", "t")
    ingest_source(store, userdata_img)
    run_pipeline(store)
    assert hashlib.sha256(userdata_img.read_bytes()).hexdigest() == before
    assert userdata_img.stat().st_mtime_ns == st.st_mtime_ns


def test_mount_point_override(userdata_img, tmp_path):
    store = CaseStore.create(tmp_path / "c", "c", "t")
    ingest_source(store, userdata_img, mount_point="custom")
    paths = [r["path"] for r in store.q("SELECT path FROM evidence_files")]
    assert paths and all(p.startswith("custom/") for p in paths)


def test_cli_analyze_accepts_an_image(userdata_img, tmp_path):
    r = CliRunner().invoke(app, ["analyze", str(userdata_img), "--cases-dir", str(tmp_path / "cases"), "--name", "imgcase", "--no-report"],
                           catch_exceptions=False)
    assert r.exit_code == 0 and "Artifacts (ACTIVE)" in r.stdout


def test_unrecognised_filesystem_in_a_partition_is_reported_not_guessed(tmp_path):
    import struct
    # GPT with one partition of random bytes: neither ext nor f2fs
    hdr = bytearray(512)
    hdr[:8] = b"EFI PART"
    struct.pack_into("<QII", hdr, 72, 2, 128, 128)
    entry = bytearray(128)
    entry[:16] = b"\x01" * 16
    struct.pack_into("<QQ", entry, 32, 2048, 2048 + 255)
    entry[56:56 + 14] = "userdata".encode("utf-16le")
    table = bytes(entry) + bytes(128 * 127)
    head = bytes(512) + bytes(hdr) + table
    img = tmp_path / "enc.img"
    img.write_bytes(head + bytes(2048 * 512 - len(head)) + bytes((i * 31 + 7) % 256 for i in range(256 * 512)))
    store = CaseStore.create(tmp_path / "c", "c", "t")
    s = ingest_source(store, img)
    types = {r["issue_type"] for r in store.q("SELECT issue_type FROM scan_issues WHERE stage='ingest'")}
    assert s.source_type is SourceType.DISK_IMAGE and "filesystem_not_recognised" in types and s.files == 0


# ---------------------------------------------------------------------------- E01


def _ewf(tmp_path: Path) -> Path:
    import shutil
    p = tmp_path / "userdata.E01"
    shutil.copy(FIXTURES / "ewf" / "android_userdata.E01", p)
    return p


def test_e01_acquisition_equals_the_raw_image_and_verifies_its_stored_hash(userdata_img, tmp_path):
    raw_store = CaseStore.create(tmp_path / "raw", "raw", "t")
    ingest_source(raw_store, userdata_img)
    e01_store = CaseStore.create(tmp_path / "e01", "e01", "t")
    s = ingest_source(e01_store, _ewf(tmp_path))
    assert s.source_type is SourceType.DISK_IMAGE and s.complete
    assert _files(e01_store) == _files(raw_store)           # identical bytes through a different container
    issues = {r["issue_type"]: r["detail"] for r in e01_store.q("SELECT issue_type, detail FROM scan_issues WHERE stage='ingest'")}
    assert "E01" in issues["image_format"] and "matches" in issues["image_hash_verified"]


def test_tampered_e01_fails_acquisition_integrity(tmp_path):
    p = _ewf(tmp_path)
    data = bytearray(p.read_bytes())
    at = data.rindex(b"hash\0")                    # the hash section descriptor near the end
    data[at + 76 + 3] ^= 0xFF                      # first bytes of the stored MD5
    p.write_bytes(bytes(data))
    store = CaseStore.create(tmp_path / "c", "c", "t")
    s = ingest_source(store, p)
    types = {r["issue_type"] for r in store.q("SELECT issue_type FROM scan_issues WHERE stage='ingest'")}
    assert "image_hash_mismatch" in types and not s.complete


# ---------------------------------------------------------------------------- f2fs


def test_f2fs_image_is_acquired_like_a_directory_and_noted(tmp_path):
    import hashlib

    from tests.tools.f2fs_tree import expected_files

    img = tmp_path / "userdata.img"
    img.write_bytes(gzip.decompress((FIXTURES / "f2fs" / "kernel_extra_dirty.img.gz").read_bytes()))
    store = CaseStore.create(tmp_path / "c", "c", "t")
    s = ingest_source(store, img)
    assert s.source_type is SourceType.DISK_IMAGE and s.complete
    got = {r["path"]: r["sha256"] for r in store.q("SELECT path, sha256 FROM evidence_files")}
    # the volume's root holds "data" and "system", so it is recognised as an Android /data partition and mounted at data/
    want = {f"data/{p}": hashlib.sha256(d).hexdigest() for p, d in expected_files().items()}
    assert got == want                                    # paths and bytes identical to what the kernel was asked to write
    issues = {r["issue_type"]: r["detail"] for r in store.q("SELECT issue_type, detail FROM scan_issues WHERE stage='ingest'")}
    assert "f2fs" in issues["filesystem_found"] and "userdata" in issues["filesystem_found"]
    assert "not cleanly unmounted" in issues["filesystem_note"]
    assert "symlink_skipped" in {r["issue_type"] for r in store.q("SELECT issue_type FROM scan_issues WHERE stage='ingest'")}
