"""Building blocks of the ingestion subsystem, tested in isolation with tiny synthetic inputs."""

import errno
import hashlib
import io
import os
import struct
import sys
import tarfile
import zipfile

import pytest

from android_forensics.acquisition.archive import _tar_times, _zip_times
from android_forensics.acquisition.hashing import hash_file
from android_forensics.acquisition.manifest import make_manifest, read_manifest, write_manifest_file
from android_forensics.errors import CaseError, ForensicsError, IngestionError
from android_forensics.readonly import fingerprint, open_readonly
from android_forensics.workspace import Workspace

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")


# ------------------------------------------------------------------ read-only access


class TestOpenReadonly:
    def test_reads_bytes_and_cannot_write(self, tmp_path):
        p = tmp_path / "e.bin"
        p.write_bytes(b"evidence")
        with open_readonly(p) as fh:
            assert fh.read() == b"evidence"
            with pytest.raises(io.UnsupportedOperation):
                fh.write(b"tamper")
        assert p.read_bytes() == b"evidence"

    def test_leaves_content_and_mtime_untouched(self, tmp_path):
        p = tmp_path / "e.bin"
        p.write_bytes(b"x" * 100_000)
        os.utime(p, (1_700_000_000, 1_700_000_100))
        before = p.stat()
        with open_readonly(p) as fh:
            fh.read()
        after = p.stat()
        assert (before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino)

    def test_missing_file_raises_oserror(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            open_readonly(tmp_path / "nope")

    @posix_only
    def test_refuses_to_follow_a_symlink(self, tmp_path):
        target = tmp_path / "secret.txt"
        target.write_text("secret")
        link = tmp_path / "link"
        os.symlink(target, link)
        with pytest.raises(OSError) as excinfo:
            open_readonly(link)
        assert excinfo.value.errno == errno.ELOOP

    @posix_only
    def test_hashing_originals_goes_through_the_same_guarded_opener(self, tmp_path):
        target = tmp_path / "t.bin"
        target.write_bytes(b"content")
        link = tmp_path / "l.bin"
        os.symlink(target, link)
        assert hash_file(target).sha256 == hashlib.sha256(b"content").hexdigest()
        with pytest.raises(OSError):
            hash_file(link)
        assert hash_file(link, follow_symlinks=True).sha256 == hashlib.sha256(b"content").hexdigest()

    def test_fingerprint_changes_with_content_state(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"a")
        first = fingerprint(p.stat())
        p.write_bytes(b"ab")
        assert fingerprint(p.stat()) != first
        assert len(first) == 3


# ------------------------------------------------------------------ working directory


class TestWorkspace:
    def test_layout_and_creation(self, tmp_path):
        ws = Workspace(tmp_path / "a" / "b" / "work").create()
        assert ws.root == (tmp_path / "a" / "b" / "work").resolve()
        for d in (ws.evidence_dir, ws.scratch_dir, ws.reports_dir):
            assert d.is_dir() and d.parent == ws.root
        assert ws.manifest_path == ws.root / "evidence_manifest.json"
        assert ws.source_dir(3) == ws.evidence_dir / "s3"
        ws.create()  # idempotent

    def test_a_file_cannot_be_a_workspace(self, tmp_path):
        f = tmp_path / "file"
        f.write_text("x")
        with pytest.raises(IngestionError, match="not a directory"):
            Workspace(f).create()

    def test_next_source_id_follows_existing_source_directories(self, tmp_path):
        ws = Workspace(tmp_path / "w").create()
        assert ws.next_source_id() == 1
        ws.source_dir(1).mkdir()
        ws.source_dir(4).mkdir()
        (ws.evidence_dir / "not-a-source").mkdir()
        (ws.evidence_dir / "s9").write_text("a file, not a source directory")
        assert ws.next_source_id() == 5

    def test_workspace_and_evidence_must_not_overlap_in_either_direction(self, tmp_path):
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "a.txt").write_text("a")
        work = Workspace(tmp_path / "work").create()
        work.assert_disjoint_from(evidence)  # siblings are fine
        with pytest.raises(IngestionError, match="inside the working directory"):
            work.assert_disjoint_from(work.root / "planted")
        with pytest.raises(IngestionError, match="cannot be the evidence"):
            work.assert_disjoint_from(work.root)
        with pytest.raises(IngestionError, match="must not be inside the evidence directory"):
            Workspace(evidence / "work").assert_disjoint_from(evidence)

    def test_an_archive_beside_the_workspace_is_fine(self, tmp_path):
        archive = tmp_path / "acq.zip"
        archive.write_bytes(b"zip")
        Workspace(tmp_path / "work").assert_disjoint_from(archive)

    def test_error_hierarchy(self):
        assert issubclass(IngestionError, ForensicsError) and issubclass(CaseError, ForensicsError)


# ------------------------------------------------------------------ archive timestamps


def zip_info(date_time=(2024, 3, 1, 8, 0, 0), extra=b""):
    info = zipfile.ZipInfo("f.txt", date_time=date_time)
    info.extra = extra
    return info


def ut_field(mtime, flags=1):
    return struct.pack("<HHBl", 0x5455, 5, flags, mtime)


class TestZipTimes:
    def test_dos_time_is_labelled_as_timezone_less(self):
        t = _zip_times(zip_info())
        assert t.mtime == "2024-03-01T08:00:00.000Z" and "dos_time" in t.basis and "timezone unspecified" in t.basis
        assert t.atime is None and t.ctime is None

    def test_extended_timestamp_field_wins_and_is_utc(self):
        t = _zip_times(zip_info(extra=ut_field(1709283600)))  # 2024-03-01T09:00:00Z, differs from the DOS time
        assert t.mtime == "2024-03-01T09:00:00.000Z" and "UT" in t.basis and "UTC" in t.basis

    def test_unrelated_extra_fields_are_skipped(self):
        other = struct.pack("<HH4s", 0x9999, 4, b"junk")
        assert _zip_times(zip_info(extra=other + ut_field(1709283600))).mtime == "2024-03-01T09:00:00.000Z"

    @pytest.mark.parametrize("extra", [ut_field(1709283600, flags=0), ut_field(1709283600)[:6], b"\x55\x54", b"\x00"])
    def test_absent_or_malformed_ut_field_falls_back_to_dos(self, extra):
        t = _zip_times(zip_info(extra=extra))
        assert t.mtime == "2024-03-01T08:00:00.000Z" and "dos_time" in t.basis

    def test_invalid_dos_date_yields_no_time_rather_than_a_guess(self):
        info = zipfile.ZipInfo("f.txt")
        info.date_time = (1980, 0, 0, 0, 0, 0)
        assert _zip_times(info).mtime is None


def tar_member(mtime=1709280000, pax=None):
    m = tarfile.TarInfo("f.txt")
    m.mtime = mtime
    m.pax_headers = pax or {}
    return m


class TestTarTimes:
    def test_mtime_only_for_plain_headers(self):
        t = _tar_times(tar_member())
        assert t.mtime == "2024-03-01T08:00:00.000Z" and t.atime is None and t.ctime is None
        assert "PAX" not in t.basis and "tar_header_mtime" in t.basis

    def test_pax_headers_supply_atime_and_ctime(self):
        t = _tar_times(tar_member(pax={"atime": "1709280001.5", "ctime": "1709280002"}))
        assert t.atime == "2024-03-01T08:00:01.500Z" and t.ctime == "2024-03-01T08:00:02.000Z" and "PAX" in t.basis

    def test_garbage_pax_values_are_ignored(self):
        t = _tar_times(tar_member(pax={"atime": "soon", "ctime": ""}))
        assert t.atime is None and t.ctime is None and "PAX" not in t.basis

    def test_fractional_mtime_is_preserved_to_the_millisecond(self):
        assert _tar_times(tar_member(mtime=1709280000.25)).mtime == "2024-03-01T08:00:00.250Z"


# ------------------------------------------------------------------ manifest writing


class TestManifestFile:
    def test_atomic_write_sidecar_and_read_back(self, tmp_path):
        m = make_manifest("0" * 32, "case", [], analysis_timestamp="2026-09-21T10:00:00.000Z")
        path = tmp_path / "out" / "evidence_manifest.json"
        digest = write_manifest_file(m, path)
        assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
        assert (tmp_path / "out" / "evidence_manifest.json.sha256").read_text() == f"{digest}  evidence_manifest.json\n"
        assert not list((tmp_path / "out").glob("*.tmp")), "the temporary file is renamed away"
        assert read_manifest(path) == m

    def test_rewriting_replaces_the_manifest_and_its_hash(self, tmp_path):
        path = tmp_path / "m.json"
        a = write_manifest_file(make_manifest("0" * 32, "one", [], analysis_timestamp="2026-09-21T10:00:00.000Z"), path)
        b = write_manifest_file(make_manifest("0" * 32, "two", [], analysis_timestamp="2026-09-21T10:00:00.000Z"), path)
        assert a != b and read_manifest(path).case_name == "two"
        assert (tmp_path / "m.json.sha256").read_text().startswith(b)

    def test_top_level_fields(self):
        from android_forensics import TOOL_NAME, __version__

        m = make_manifest("a" * 32, "case", [])
        assert (m.case_id, m.tool_name, m.tool_version, m.manifest_version) == ("a" * 32, TOOL_NAME, __version__, 2)
        assert m.analysis_timestamp.endswith("Z") and len(m.analysis_timestamp) == 24
