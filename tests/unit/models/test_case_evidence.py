import hashlib
import json

import pytest
from pydantic import ValidationError

from android_forensics.models import (
    EMPTY_HASHES,
    Case,
    EvidenceFile,
    EvidenceSource,
    FileHashes,
    FileKind,
    FileTimes,
    Manifest,
    ManifestEntry,
    ManifestSource,
    SourceLayout,
    SourceType,
)

CASE_ID = "0123456789abcdef0123456789abcdef"
HASHES = FileHashes(md5="a" * 32, sha1="b" * 40, sha256="c" * 64)
NOW = "2026-09-21T14:16:50.296Z"


def make_file(**kw):
    base = dict(source_id=1, ordinal=0, path="data/data/com.x/databases/a.db", size=4096, hashes=HASHES, kind=FileKind.SQLITE_DB,
                times=FileTimes(mtime="2024-06-04T08:00:00.000Z", basis="fs_stat"), preserved_copy="0000000_a.db")
    return EvidenceFile(**(base | kw))


def make_source(**kw):
    base = dict(case_id=CASE_ID, original_path="/evidence/dump", original_name="dump", source_type=SourceType.DIRECTORY,
                ingested_at=NOW, file_count=2, total_bytes=100)
    return EvidenceSource(**(base | kw))


class TestCase:
    def make(self, **kw):
        return Case(**(dict(id=CASE_ID, name="case001", created_at=NOW, tool_version="0.1.0") | kw))

    def test_minimal_case(self):
        c = self.make()
        assert c.examiner is None and c.layouts == {} and c.layout is None

    def test_id_is_a_uuid_hex_and_name_is_required(self):
        for bad in ({"id": "not-hex"}, {"id": CASE_ID.upper()}, {"name": "  "}, {"created_at": "2026-09-21"}, {"tool_version": ""}):
            with pytest.raises(ValidationError):
                self.make(**bad)

    def test_immutable_and_strict(self):
        c = self.make()
        with pytest.raises(ValidationError):
            c.name = "other"
        with pytest.raises(ValidationError):
            self.make(unexpected=1)

    def test_record_round_trip_with_layouts(self):
        c = self.make(examiner="A. Examiner", description="d", layout="android_root",
                      layouts={1: SourceLayout(layout="android_root", prefix="", detail="16/16 paths")})
        record = c.to_record()
        assert json.loads(record["layout_detail"]) == {"1": {"layout": "android_root", "prefix": "", "detail": "16/16 paths"}}
        assert Case.from_record(record) == c

    def test_from_record_tolerates_an_unscanned_case(self):
        rec = self.make().to_record()
        rec["layout_detail"] = None
        assert Case.from_record(rec).layouts == {}


class TestFileHashes:
    def test_empty_hashes_are_those_of_empty_input(self):
        assert EMPTY_HASHES.sha256 == hashlib.sha256(b"").hexdigest()
        assert EMPTY_HASHES.sha1 == hashlib.sha1(b"").hexdigest()
        assert EMPTY_HASHES.md5 == hashlib.md5(b"").hexdigest()

    def test_each_hash_is_validated(self):
        for bad in (dict(md5="x" * 32), dict(sha1="a" * 39), dict(sha256="A" * 64)):
            with pytest.raises(ValidationError):
                FileHashes(**({"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64} | bad))


class TestFileTimes:
    def test_times_must_state_their_basis(self):
        with pytest.raises(ValidationError, match="basis"):
            FileTimes(mtime="2024-06-04T08:00:00.000Z")
        assert FileTimes().mtime is None
        assert FileTimes(mtime="2024-06-04T08:00:00.000Z", basis="tar_header_mtime").basis == "tar_header_mtime"

    def test_times_are_canonical_utc(self):
        with pytest.raises(ValidationError):
            FileTimes(mtime="2024-06-04T08:00:00Z", basis="x")


class TestEvidenceFile:
    def test_name_is_derived_from_path(self):
        f = make_file()
        assert f.name == "a.db" and f.is_preserved
        assert make_file(path="only.db").name == "only.db"

    @pytest.mark.parametrize("bad", ["/abs/a.db", "a/../b.db", "a//b", "./a", "a/./b", "a/", "  "])
    def test_paths_must_be_relative_and_normalised(self, bad):
        with pytest.raises(ValidationError):
            make_file(path=bad)

    def test_path_is_never_modified_only_rejected_when_blank(self):
        assert make_file(path=" padded name .txt ").path == " padded name .txt "
        with pytest.raises(ValidationError):
            make_file(path="   ")

    def test_zero_length_files_must_carry_empty_hashes(self):
        assert make_file(size=0, hashes=EMPTY_HASHES, kind=FileKind.EMPTY, preserved_copy=None).size == 0
        with pytest.raises(ValidationError, match="empty input"):
            make_file(size=0)

    def test_preserved_copy_is_a_name_not_a_path(self):
        for bad in ("../x", "s1/x", "a\\b"):
            with pytest.raises(ValidationError):
                make_file(preserved_copy=bad)
        assert make_file(preserved_copy=None).is_preserved is False

    def test_bounds(self):
        for bad in (dict(size=-1), dict(source_id=0), dict(ordinal=-1)):
            with pytest.raises(ValidationError):
                make_file(**bad)

    def test_kind_is_an_enum(self):
        assert make_file(kind="sqlite_wal").kind is FileKind.SQLITE_WAL
        with pytest.raises(ValidationError):
            make_file(kind="floppy")

    def test_record_round_trip(self):
        f = make_file(id=3, kind_detail="SQLite header magic present", logical_path="/data/data/com.x/databases/a.db",
                      android_root="data/data", user_id=0, package="com.x")
        record = dict(f.to_record(), id=3)
        assert record["name"] == "a.db" and record["sha256"] == "c" * 64 and record["time_basis"] == "fs_stat"
        assert EvidenceFile.from_record(record) == f


class TestEvidenceSource:
    def test_directory_has_no_container(self):
        s = make_source()
        assert s.container_hashes is None and s.complete
        with pytest.raises(ValidationError, match="no container"):
            make_source(container_hashes=HASHES, container_size=10)

    @pytest.mark.parametrize("stype", [SourceType.ZIP, SourceType.TAR])
    def test_archives_must_record_their_container_hashes(self, stype):
        with pytest.raises(ValidationError, match="container size and hashes"):
            make_source(source_type=stype)
        assert make_source(source_type=stype, container_hashes=HASHES, container_size=10).container_hashes == HASHES

    def test_single_file_source_has_no_container(self):
        assert make_source(source_type=SourceType.SINGLE_FILE).source_type is SourceType.SINGLE_FILE

    def test_acquisition_time_is_normalised_and_must_be_unambiguous(self):
        assert make_source(acquisition_time="2024-06-04T08:00:00Z").acquisition_time == "2024-06-04T08:00:00.000Z"
        assert make_source(acquisition_time="2024-06-04T13:30:00+05:30").acquisition_time == "2024-06-04T08:00:00.000Z"
        with pytest.raises(ValidationError, match="timezone"):
            make_source(acquisition_time="2024-06-04T08:00:00")

    def test_counts_cannot_be_negative(self):
        for bad in (dict(file_count=-1), dict(total_bytes=-1), dict(container_size=-1)):
            with pytest.raises(ValidationError):
                make_source(**bad)

    def test_record_round_trip_for_directory_and_archive(self):
        for s in (make_source(id=1), make_source(id=2, source_type=SourceType.ZIP, container_hashes=HASHES, container_size=99,
                                                 acquisition_time="2024-06-04T08:00:00Z", complete=False)):
            record = dict(s.to_record(), id=s.id)
            assert EvidenceSource.from_record(record) == s
        assert make_source(source_type=SourceType.TAR, container_hashes=HASHES, container_size=1).to_record()["container_sha256"] == "c" * 64


class TestManifest:
    def test_entry_records_original_and_relative_paths_and_flat_hashes(self):
        e = ManifestEntry.from_evidence_file(make_file(), "/ev/dump/data/data/com.x/databases/a.db")
        assert (e.md5, e.sha1, e.sha256) == (HASHES.md5, HASHES.sha1, HASHES.sha256)
        assert e.relative_path == "data/data/com.x/databases/a.db" and e.original_path.startswith("/ev/dump/")
        assert e.preserved_copy == "evidence/s1/0000000_a.db"
        assert ManifestEntry.from_evidence_file(make_file(preserved_copy=None), "/x").preserved_copy is None

    def test_original_path_of_depends_on_the_source_type(self):
        directory = make_source(id=1, original_path="/ev/dump")
        assert directory.original_path_of("data/a.db") == "/ev/dump/data/a.db"
        single = make_source(id=2, original_path="/lab/calllog.db", source_type=SourceType.SINGLE_FILE)
        assert single.original_path_of("calllog.db-wal") == "/lab/calllog.db-wal"
        for stype in (SourceType.ZIP, SourceType.TAR):
            archive = make_source(id=3, original_path="/ev/acq.x", source_type=stype, container_hashes=HASHES, container_size=1)
            assert archive.original_path_of("data/a.db") == "/ev/acq.x!/data/a.db"

    def test_source_and_manifest_round_trip_through_json(self):
        src = make_source(id=1, source_type=SourceType.ZIP, container_hashes=HASHES, container_size=5, original_path="/ev/acq.zip")
        ms = ManifestSource.from_source(src, [make_file(), make_file(ordinal=1, path="b.txt", kind=FileKind.TEXT, preserved_copy=None)])
        assert ms.container_sha256 == "c" * 64 and ms.file_count == 2 and len(ms.files) == 2
        assert [f.original_path for f in ms.files] == ["/ev/acq.zip!/data/data/com.x/databases/a.db", "/ev/acq.zip!/b.txt"]
        m = Manifest(case_id=CASE_ID, case_name="c", analysis_timestamp=NOW, tool_name="android-forensics", tool_version="0.1.0", sources=[ms])
        assert Manifest.model_validate_json(m.model_dump_json()) == m
        assert m.manifest_version == 2 and "never modified" in m.note

    def test_a_source_needs_its_id_before_it_can_be_listed(self):
        with pytest.raises(ValueError, match="source id"):
            ManifestSource.from_source(make_source(), [])

    def test_manifest_rejects_malformed_entries(self):
        with pytest.raises(ValidationError):
            ManifestEntry(original_path="/a", relative_path="a", size=1, md5="x", sha1="y", sha256="z", kind=FileKind.TEXT)
