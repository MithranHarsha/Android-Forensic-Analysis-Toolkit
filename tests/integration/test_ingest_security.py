import hashlib
import io
import os
import shutil
import stat
import tarfile
import zipfile

import pytest

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.acquisition.manifest import read_manifest
from android_forensics.acquisition.safety import ExtractionBudget
from android_forensics.errors import IngestionError
from android_forensics.pipeline.runner import run_pipeline
from android_forensics.storage.case_store import CaseStore


def files_of(store):
    return {(r["path"], r["sha256"]) for r in store.q("SELECT path, sha256 FROM evidence_files")}


def test_dir_zip_tar_produce_identical_inventory_and_results(synth, tmp_path):
    out, truth = synth
    inv, counts = {}, {}
    for label, src in (("dir", out / "android_dump"), ("zip", out / "acquisition.zip"), ("tgz", out / "acquisition.tar.gz")):
        s = CaseStore.create(tmp_path / label, label)
        r = ingest_source(s, src)
        assert r.complete and r.issues == 0
        run_pipeline(s)
        inv[label] = files_of(s)
        counts[label] = {row["artifact_type"]: row["n"] for row in s.q("SELECT artifact_type, COUNT(*) n FROM artifacts GROUP BY 1")}
    assert inv["dir"] == inv["zip"] == inv["tgz"]
    assert counts["dir"] == counts["zip"] == counts["tgz"]
    assert counts["dir"]["sms"] == 120 and counts["dir"]["call"] == 60


def test_container_hash_and_time_basis_are_recorded(synth, tmp_path):
    out, _ = synth
    s = CaseStore.create(tmp_path / "c", "c")
    ingest_source(s, out / "acquisition.zip", acquired_at="2024-06-04T08:00:00Z")
    src = s.one("SELECT * FROM evidence_sources")
    assert src["container_sha256"] == hashlib.sha256((out / "acquisition.zip").read_bytes()).hexdigest()
    assert src["acquisition_time"] == "2024-06-04T08:00:00.000Z" and src["source_type"] == "zip"
    assert "timezone unspecified" in s.scalar("SELECT time_basis FROM evidence_files LIMIT 1")
    m = read_manifest(s.manifest_path)
    assert m.sources[0].container_sha256 == src["container_sha256"] and len(m.sources[0].files) == 16


def test_zip_slip_absolute_symlink_and_encrypted_entries(tmp_path):
    zp = tmp_path / "evil.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("../escaped.txt", "x")
        z.writestr("a/../../escaped2.txt", "x")
        z.writestr("/abs/ok.txt", "kept")
        link = zipfile.ZipInfo("link")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(link, "/etc/passwd")
        z.writestr("good.txt", "good")
    s = CaseStore.create(tmp_path / "case", "c")
    r = ingest_source(s, zp)
    kinds = {i["issue_type"] for i in s.q("SELECT issue_type FROM scan_issues")}
    assert {"unsafe_path_skipped", "symlink_skipped"} <= kinds
    assert files_of(s) == {("abs/ok.txt", hashlib.sha256(b"kept").hexdigest()), ("good.txt", hashlib.sha256(b"good").hexdigest())}
    assert not (tmp_path / "escaped.txt").exists() and not (tmp_path / "escaped2.txt").exists()
    assert not any(p.name.startswith("escaped") for p in tmp_path.rglob("*"))
    assert r.issues == 3


def test_tar_symlink_hardlink_device_and_traversal(tmp_path):
    tp = tmp_path / "evil.tar"
    with tarfile.open(tp, "w") as t:
        for name, kind, extra in (("sym", tarfile.SYMTYPE, "/etc/passwd"), ("hard", tarfile.LNKTYPE, "good.txt"), ("dev", tarfile.CHRTYPE, "")):
            ti = tarfile.TarInfo(name)
            ti.type = kind
            ti.linkname = extra
            t.addfile(ti)
        ti = tarfile.TarInfo("../../up.txt")
        ti.size = 1
        t.addfile(ti, io.BytesIO(b"x"))
        ti = tarfile.TarInfo("good.txt")
        ti.size = 4
        t.addfile(ti, io.BytesIO(b"good"))
    s = CaseStore.create(tmp_path / "case", "c")
    ingest_source(s, tp)
    issues = {i["path"]: i["issue_type"] for i in s.q("SELECT path, issue_type FROM scan_issues")}
    assert issues["sym"] == "symlink_skipped" and issues["hard"] == "symlink_skipped"
    assert issues["dev"] == "special_file_skipped" and issues["../../up.txt"] == "unsafe_path_skipped"
    assert [r["path"] for r in s.q("SELECT path FROM evidence_files")] == ["good.txt"]


def test_directory_symlinks_not_followed(tmp_path):
    ev = tmp_path / "ev"
    (ev / "d").mkdir(parents=True)
    (ev / "d" / "a.txt").write_text("a")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    os.symlink(outside, ev / "linked_dir")
    os.symlink(outside / "secret.txt", ev / "linked_file")
    s = CaseStore.create(tmp_path / "case", "c")
    ingest_source(s, ev)
    assert [r["path"] for r in s.q("SELECT path FROM evidence_files")] == ["d/a.txt"]
    assert {i["issue_type"] for i in s.q("SELECT issue_type FROM scan_issues")} == {"symlink_skipped"}


def test_truncated_archive_marks_acquisition_incomplete_and_validation_fails(synth, tmp_path):
    out, _ = synth
    data = (out / "acquisition.tar.gz").read_bytes()
    cut = tmp_path / "cut.tar.gz"
    cut.write_bytes(data[: len(data) // 2])
    s = CaseStore.create(tmp_path / "case", "c")
    r = ingest_source(s, cut)
    assert r.complete is False
    run_pipeline(s, ["scan", "extract", "validate"])
    row = s.one("SELECT status, detail FROM validation_results WHERE check_name='acquisition_completeness'")
    assert row["status"] == "INVALID" and "INCOMPLETE" in row["detail"]


def test_extraction_budget_stops_and_flags(synth, tmp_path):
    out, _ = synth
    s = CaseStore.create(tmp_path / "case", "c")
    r = ingest_source(s, out / "acquisition.zip", budget=ExtractionBudget(max_entries=3))
    assert not r.complete and r.files == 3
    assert s.scalar("SELECT COUNT(*) FROM scan_issues WHERE issue_type='budget_exceeded'") == 1


def test_single_database_ingest_brings_its_sidecars(synth, tmp_path):
    out, _ = synth
    d = tmp_path / "lab"
    d.mkdir()
    base = out / "android_dump/data/data/com.android.providers.contacts/databases"
    for suffix in ("", "-wal", "-shm"):
        shutil.copyfile(base / f"calllog.db{suffix}", d / f"calllog.db{suffix}")
    s = CaseStore.create(tmp_path / "case", "c")
    r = ingest_source(s, d / "calllog.db")
    assert r.source_type.value == "single_file" and r.files == 3
    run_pipeline(s)
    assert s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='call'") == 60
    assert s.scalar("SELECT layout FROM cases") == "single_file" or s.scalar("SELECT layout FROM cases") == "loose_files"


def test_rejects_missing_path_and_evidence_inside_case(tmp_path):
    s = CaseStore.create(tmp_path / "case", "c")
    with pytest.raises(IngestionError, match="does not exist"):
        ingest_source(s, tmp_path / "nope")
    inner = s.case_dir / "sneaky"
    inner.mkdir()
    (inner / "f").write_text("x")
    with pytest.raises(IngestionError, match="inside the working directory"):
        ingest_source(s, inner)


def test_preserved_copies_are_bit_identical_and_read_only(synth, tmp_path):
    out, _ = synth
    s = CaseStore.create(tmp_path / "case", "c")
    ingest_source(s, out / "android_dump")
    n = 0
    for f in s.q("SELECT source_id, path, sha256, preserved_copy FROM evidence_files WHERE preserved_copy IS NOT NULL"):
        p = s.evidence_dir / f"s{f['source_id']}" / f["preserved_copy"]
        assert hashlib.sha256(p.read_bytes()).hexdigest() == f["sha256"]
        assert stat.S_IMODE(p.stat().st_mode) == 0o444
        n += 1
    assert n == 13
    with pytest.raises(PermissionError):
        open(p, "ab")


def test_acquisition_time_must_carry_a_timezone(synth, tmp_path):
    out, _ = synth
    s = CaseStore.create(tmp_path / "case", "c")
    with pytest.raises(IngestionError, match="timezone"):
        ingest_source(s, out / "acquisition.zip", acquired_at="2024-06-04T08:00:00")
    with pytest.raises(IngestionError, match="ISO 8601"):
        ingest_source(s, out / "acquisition.zip", acquired_at="last tuesday")
    assert s.scalar("SELECT COUNT(*) FROM evidence_sources") == 0, "nothing is recorded for rejected metadata"
    ingest_source(s, out / "acquisition.zip", acquired_at="2024-06-04T13:30:00+05:30")
    assert s.sources()[0].acquisition_time == "2024-06-04T08:00:00.000Z"


def test_file_names_survive_byte_for_byte_including_padding_spaces(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    for name in (" leading.txt", "trailing.txt ", "in ner.txt"):
        (ev / name).write_text("hello world")
    s = CaseStore.create(tmp_path / "case", "c")
    ingest_source(s, ev)
    assert {f.path for f in s.evidence_files()} == {" leading.txt", "trailing.txt ", "in ner.txt"}
