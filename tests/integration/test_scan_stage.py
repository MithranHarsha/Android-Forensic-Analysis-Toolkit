"""The pipeline ``scan`` stage and the ``discover`` command: persistence, consistency with the standalone scanner, CLI behaviour."""

import json

import pytest
from typer.testing import CliRunner

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.cli.app import app
from android_forensics.filesystem.scanner import scan_directory
from android_forensics.pipeline.runner import run_pipeline, run_stage
from android_forensics.storage.case_store import CaseStore
from tests.conftest import tree_hash

runner = CliRunner()

# Only the case pipeline opens databases with SQLite, so only it can add these; the byte-level scan never reports them.
ENGINE_LEVEL_ISSUES = {"database_unopenable", "database_integrity_failure"}

DUMP_DB_PATHS = {
    "data/data/com.android.chrome/app_chrome/Default/History",
    "data/data/com.android.providers.contacts/databases/calllog.db",
    "data/data/com.android.providers.contacts/databases/contacts2.db",
    "data/data/com.android.providers.telephony/databases/mmssms.db",
    "data/data/com.example.corrupt/databases/broken.db",
    "data/data/com.example.notes/databases/notes.db",
    "data/data/com.example.notes/databases/pending.db",
    "data/data/com.example.secure/databases/vault.db",
}


def scan_case(tmp_path, source, name="c"):
    store = CaseStore.create(tmp_path / name, name, "pytest")
    ingest_source(store, source)
    stats = run_stage(store, "scan")
    return store, stats


def normalise(scan):
    """What must agree between the standalone scan and the case scan (per-file evidence ids and timestamps differ by design)."""
    return {
        "layout": scan.layout.layout,
        "categories": scan.category_counts,
        "databases": {d.path: (d.status.value, d.size, d.sha256, sorted((s.kind.value, s.path, s.sha256) for s in d.sidecars)) for d in scan.databases},
        "apps": [(a.package, a.path, a.logical_path, a.file_count, a.total_bytes, a.database_count, a.subdirectories) for a in scan.app_directories],
        "issues": sorted((i.issue_type, i.path) for i in scan.issues),
    }


# ------------------------------------------------------------------ what the stage persists


class TestPersistedDiscovery:
    def test_every_file_is_attributed_to_the_android_filesystem(self, analyzed):
        store = analyzed[0]
        rows = store.q("SELECT path, logical_path, android_root, package FROM evidence_files")
        assert rows and all(r["logical_path"] for r in rows)
        chat = next(r for r in rows if r["path"].endswith("mmssms.db"))
        assert (chat["logical_path"], chat["android_root"], chat["package"]) == (
            "/data/data/com.android.providers.telephony/databases/mmssms.db", "data/data", "com.android.providers.telephony")
        assert next(r for r in rows if r["path"].endswith(".jpg"))["android_root"] == "sdcard"

    def test_application_directories_are_stored(self, analyzed):
        store = analyzed[0]
        rows = {r["package"]: r for r in store.q("SELECT * FROM app_directories")}
        assert set(rows) == {"com.android.chrome", "com.android.providers.contacts", "com.android.providers.telephony",
                             "com.example.corrupt", "com.example.notes", "com.example.secure"}
        notes = rows["com.example.notes"]
        assert (notes["logical_path"], notes["root"], notes["area"], notes["file_count"], notes["database_count"]) == (
            "/data/data/com.example.notes", "data/data", "app_internal", 4, 2)
        assert json.loads(notes["subdirectories_json"]) == ["databases", "shared_prefs"]
        assert json.loads(notes["kind_counts_json"])["sqlite_journal"] == 1
        assert "Contacts" in rows["com.android.providers.contacts"]["known_app"]

    def test_databases_carry_their_detection_status(self, analyzed):
        store = analyzed[0]
        rows = {r["path"]: r for r in store.q(
            "SELECT e.path, d.sqlite_status, d.sqlite_status_detail, d.open_status, d.has_wal, d.has_shm, d.has_journal "
            "FROM databases d JOIN evidence_files e ON e.id=d.evidence_file_id")}
        assert set(rows) == DUMP_DB_PATHS
        status = {p.rsplit("/", 1)[-1]: r["sqlite_status"] for p, r in rows.items()}
        assert status["broken.db"] == "TRUNCATED" and status["vault.db"] == "ENCRYPTED_SUSPECT"
        assert all(v == "VALID" for k, v in status.items() if k not in ("broken.db", "vault.db"))
        assert all(r["sqlite_status_detail"] for r in rows.values())
        cl = rows["data/data/com.android.providers.contacts/databases/calllog.db"]
        assert (cl["has_wal"], cl["has_shm"], cl["has_journal"]) == (1, 1, 0)
        assert rows["data/data/com.example.notes/databases/pending.db"]["has_journal"] == 1

    def test_the_byte_level_status_and_the_engine_level_open_status_are_separate_facts(self, analyzed):
        store = analyzed[0]
        broken = store.one("SELECT sqlite_status, open_status FROM databases d JOIN evidence_files e ON e.id=d.evidence_file_id WHERE e.path LIKE '%broken.db'")
        assert broken["sqlite_status"] == "TRUNCATED" and broken["open_status"] in ("ok", "unopenable")

    def test_issues_are_recorded_once_each(self, analyzed):
        store = analyzed[0]
        issues = [(r["issue_type"], r["path"]) for r in store.q("SELECT * FROM scan_issues WHERE stage='scan'")]
        assert ("database_truncated", "data/data/com.example.corrupt/databases/broken.db") in issues
        assert ("encrypted_suspect", "data/data/com.example.secure/databases/vault.db") in issues
        assert ("binary_xml_not_parsed", "data/system/packages.xml") in issues
        assert len(issues) == len(set(issues))
        assert not [i for i in issues if i[0] == "database_unopenable" and i[1].endswith("vault.db")]

    def test_the_stage_reports_what_it_found(self, tmp_path, synth):
        out, _ = synth
        _, stats = scan_case(tmp_path, out / "android_dump")
        assert stats["files"] == 16 and stats["layout"] == "android_root" and stats["app_directories"] == 6 and stats["databases"] == 8
        assert stats["categories"]["sqlite_wal"] == 1 and stats["categories"]["media"] == 2 and stats["with_wal"] == 1 and stats["with_journal"] == 1

    def test_the_original_evidence_is_untouched(self, analyzed):
        _, _, _, before, out = analyzed
        assert tree_hash(out / "android_dump") == before


# ------------------------------------------------------------------ consistency and re-runs


class TestConsistency:
    def test_case_scan_and_standalone_scan_agree(self, tmp_path, synth):
        out, _ = synth
        store, _ = scan_case(tmp_path, out / "android_dump")
        standalone = scan_directory(out / "android_dump", hash_all=True)
        rows = store.q("SELECT app_directories.* FROM app_directories ORDER BY path")
        assert [r["path"] for r in rows] == [a.path for a in standalone.app_directories]
        db_status = {r["path"]: r["sqlite_status"] for r in store.q(
            "SELECT e.path, d.sqlite_status FROM databases d JOIN evidence_files e ON e.id=d.evidence_file_id")}
        assert db_status == {d.path: d.status.value for d in standalone.databases}
        stored = [(r["issue_type"], r["path"]) for r in store.q("SELECT * FROM scan_issues WHERE stage='scan'")]
        assert sorted(i for i in stored if i[0] not in ENGINE_LEVEL_ISSUES) == sorted((i.issue_type, i.path) for i in standalone.issues)
        engine = [i for i in stored if i[0] in ENGINE_LEVEL_ISSUES]
        assert engine and {path for _, path in engine} <= {d.path for d in standalone.databases}, "engine-level issues concern databases only"

    @pytest.mark.parametrize("archive", ["acquisition.zip", "acquisition.tar.gz"])
    def test_an_archive_discovers_the_same_filesystem_as_the_directory(self, tmp_path, synth, archive):
        out, _ = synth
        from_dir, _ = scan_case(tmp_path, out / "android_dump", "dir")
        from_arc, _ = scan_case(tmp_path, out / archive, "arc")

        def summary(store):
            return (
                sorted((r["path"], r["logical_path"], r["package"]) for r in store.q("SELECT path, logical_path, package FROM evidence_files")),
                sorted((r["package"], r["file_count"], r["database_count"]) for r in store.q("SELECT * FROM app_directories")),
                sorted((r["e_path"], r["sqlite_status"]) for r in store.q(
                    "SELECT e.path AS e_path, d.sqlite_status FROM databases d JOIN evidence_files e ON e.id=d.evidence_file_id")),
                store.case().layout,
            )

        assert summary(from_arc) == summary(from_dir)

    def test_rescanning_replaces_rather_than_duplicates(self, tmp_path, synth):
        out, _ = synth
        store, first = scan_case(tmp_path, out / "android_dump")
        counts = lambda: tuple(store.scalar(f"SELECT COUNT(*) FROM {t}") for t in ("app_directories", "databases", "db_tables"))  # noqa: E731
        issues = lambda: store.scalar("SELECT COUNT(*) FROM scan_issues WHERE stage='scan'")  # noqa: E731
        before = (counts(), issues())
        run_stage(store, "scan")
        run_stage(store, "scan")
        assert (counts(), issues()) == before

    def test_rescanning_invalidates_what_was_built_on_it(self, tmp_path, synth):
        out, _ = synth
        store, _ = scan_case(tmp_path, out / "android_dump")
        run_pipeline(store, ["extract"])
        assert store.scalar("SELECT COUNT(*) FROM artifacts") > 0
        run_stage(store, "scan")
        assert store.scalar("SELECT COUNT(*) FROM artifacts") == 0, "the extraction must be redone after the inventory it used was rebuilt"

    def test_a_case_with_no_ingested_evidence_says_so(self, tmp_path):
        store = CaseStore.create(tmp_path / "empty", "empty", "pytest")
        from android_forensics.errors import CaseError

        with pytest.raises(CaseError, match="ingest evidence first"):
            run_stage(store, "scan")

    def test_evidence_that_is_only_an_sdcard_scans_cleanly(self, tmp_path):
        ev = tmp_path / "ev"
        (ev / "sdcard/DCIM").mkdir(parents=True)
        (ev / "sdcard/DCIM/a.jpg").write_bytes(b"\xff\xd8\xff\xe0" + bytes(100))
        store, stats = scan_case(tmp_path, ev)
        assert stats["databases"] == 0 and stats["app_directories"] == 0 and stats["categories"] == {"media": 1}
        assert store.scalar("SELECT COUNT(*) FROM scan_issues WHERE stage='scan'") == 0


# ------------------------------------------------------------------ the report shows it


def test_the_report_lists_application_directories_and_detection_status(analyzed, tmp_path):
    from android_forensics.reporting.generate import generate_report

    store = analyzed[0]
    result = generate_report(store, ["html", "json"], out_dir=tmp_path / "rep")
    paths = {p.name: p for p in tmp_path.rglob("report.*")}
    html = paths["report.html"].read_text()
    assert "Android application directories" in html and "com.example.notes" in html
    assert "TRUNCATED" in html and "ENCRYPTED_SUSPECT" in html
    data = json.loads(paths["report.json"].read_text())
    assert {a["package"] for a in data["app_directories"]} >= {"com.example.notes", "com.example.secure"}
    statuses = {d["path"].rsplit("/", 1)[-1]: d["sqlite_status"] for d in data["databases"]}
    assert statuses["broken.db"] == "TRUNCATED" and statuses["mmssms.db"] == "VALID"
    assert result is not None


# ------------------------------------------------------------------ the discover command


class TestDiscoverCommand:
    wide = {"COLUMNS": "250"}  # Rich folds long names in narrow tables; the assertions are about content, not wrapping

    def test_human_readable_output(self, synth):
        out, _ = synth
        r = runner.invoke(app, ["discover", str(out / "android_dump")], env=self.wide, catch_exceptions=False)
        assert r.exit_code == 0
        for expected in ("Filesystem discovery", "android_root", "Application directories", "com.example.notes", "Databases",
                         "calllog.db", "TRUNCATED", "ENCRYPTED_SUSPECT", "File categories"):
            assert expected in r.stdout, expected

    def test_json_output_is_the_full_typed_scan(self, synth):
        from android_forensics.models import FilesystemScan

        out, _ = synth
        r = runner.invoke(app, ["discover", str(out / "android_dump"), "--json"], catch_exceptions=False)
        assert r.exit_code == 0
        scan = FilesystemScan.model_validate_json(r.stdout)
        assert scan.total_files == 16 and {d.path for d in scan.databases} == DUMP_DB_PATHS
        calllog = scan.database("data/data/com.android.providers.contacts/databases/calllog.db")
        assert sorted(s.kind.value for s in calllog.sidecars) == ["shm", "wal"] and calllog.sha256

    def test_files_flag_lists_every_file(self, synth):
        out, _ = synth
        r = runner.invoke(app, ["discover", str(out / "android_dump"), "--files"], env=self.wide, catch_exceptions=False)
        assert r.exit_code == 0 and "IMG_20240301_101500.jpg" in r.stdout

    def test_hash_all_hashes_every_file(self, synth):
        out, _ = synth
        r = runner.invoke(app, ["discover", str(out / "android_dump"), "--json", "--hash-all"], catch_exceptions=False)
        scan_files = json.loads(r.stdout)["files"]
        assert scan_files and all(f["sha256"] for f in scan_files)

    def test_a_missing_directory_is_a_clean_error(self, tmp_path):
        r = runner.invoke(app, ["discover", str(tmp_path / "nope")])
        assert r.exit_code != 0 and "does not exist" in r.output and "Traceback" not in r.output

    def test_a_file_instead_of_a_directory_is_a_clean_error(self, synth):
        out, _ = synth
        r = runner.invoke(app, ["discover", str(out / "acquisition.zip")])
        assert r.exit_code != 0 and "not a directory" in r.output and "Traceback" not in r.output

    def test_needs_no_case_and_writes_nothing(self, synth, tmp_path, monkeypatch):
        out, _ = synth
        monkeypatch.chdir(tmp_path)
        before = tree_hash(out / "android_dump")
        r = runner.invoke(app, ["discover", str(out / "android_dump")], catch_exceptions=False)
        assert r.exit_code == 0 and list(tmp_path.iterdir()) == [] and tree_hash(out / "android_dump") == before

    def test_an_empty_directory_reports_nothing_found(self, tmp_path):
        (tmp_path / "ev").mkdir()
        r = runner.invoke(app, ["discover", str(tmp_path / "ev")], catch_exceptions=False)
        assert r.exit_code == 0 and "Files" in r.stdout

    def test_scan_command_shows_application_directories(self, synth, tmp_path):
        out, _ = synth
        env = {"ANDROID_FORENSICS_CASES": str(tmp_path / "cases")}
        assert runner.invoke(app, ["init-case", "c1", "--examiner", "T"], env=env, catch_exceptions=False).exit_code == 0
        assert runner.invoke(app, ["ingest", "c1", str(out / "android_dump")], env=env, catch_exceptions=False).exit_code == 0
        r = runner.invoke(app, ["scan", "c1"], env=env, catch_exceptions=False)
        assert r.exit_code == 0 and "Application directories" in r.stdout and "android_root" in r.stdout
