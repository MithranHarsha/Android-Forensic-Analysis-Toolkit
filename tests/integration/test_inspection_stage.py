"""The case pipeline runs every discovered database through SQLiteInspector and stores what it finds."""

import json
import pytest

from android_forensics.reporting.generate import generate_report
from android_forensics.sqlite.inspection import EngineInfo, IndexSchema, TableInspection, VersionInfo
from android_forensics.sqlite.inspector import SQLiteInspector

DB_DIR = "data/data/com.android.providers"


def stored(store):
    return {
        r["path"].rsplit("/", 1)[-1]: r
        for r in store.q("SELECT e.path, d.* FROM databases d JOIN evidence_files e ON e.id=d.evidence_file_id")
    }


def tables_of(store, filename):
    return {
        r["name"]: r
        for r in store.q(
            "SELECT t.* FROM db_tables t JOIN databases d ON d.id=t.database_id JOIN evidence_files e ON e.id=d.evidence_file_id "
            "WHERE e.path LIKE ?", (f"%/{filename}",))
    }


class TestPersistedInspection:
    def test_version_and_engine_facts_are_stored_for_every_database_that_was_opened(self, analyzed):
        store = analyzed[0]
        for name, row in stored(store).items():
            if row["open_status"] in ("encrypted_suspect", "not_preserved"):
                assert row["version_json"] is None and row["engine_json"] is None, name
                continue
            version, engine = VersionInfo.model_validate_json(row["version_json"]), EngineInfo.model_validate_json(row["engine_json"])
            assert version.inspecting_library_version == engine.sqlite_library_version and engine.open_status.value == row["open_status"], name
            assert version.last_writer_version, name

    def test_schema_details_are_stored_per_table_without_the_rows(self, analyzed):
        store = analyzed[0]
        sms = tables_of(store, "mmssms.db")["sms"]
        details = TableInspection.model_validate_json(sms["details_json"])
        assert details.primary_key == ["_id"] and details.rowid_alias == "_id" and details.records == [] and details.row_count == sms["row_count"] == 120
        assert "records" not in json.loads(sms["details_json"]) or json.loads(sms["details_json"])["records"] == []
        assert [c[0] for c in json.loads(sms["columns_json"])][:3] == [c.name for c in details.columns][:3], "the older columns_json keeps its shape"

    def test_indexes_are_stored_both_with_their_table_and_as_their_own_entries(self, analyzed):
        store = analyzed[0]
        contacts = tables_of(store, "contacts2.db")
        assert [i.name for i in TableInspection.model_validate_json(contacts["raw_contacts"]["details_json"]).indexes] == ["raw_contacts_name"]
        entry = contacts["raw_contacts_name"]
        assert entry["obj_type"] == "index" and entry["sql"].startswith("CREATE INDEX raw_contacts_name")
        index = IndexSchema.model_validate_json(entry["details_json"])
        assert index.table == "raw_contacts" and index.columns and index.root_page == entry["root_page"]

    def test_without_rowid_and_autoindex_keys_are_recorded(self, analyzed):
        store = analyzed[0]
        settings = TableInspection.model_validate_json(tables_of(store, "notes.db")["settings"]["details_json"])
        assert settings.primary_key == ["key"] and settings.rowid_alias is None and [i.origin for i in settings.indexes] == ["pk"]

    def test_the_stage_agrees_with_the_standalone_inspector_on_every_table(self, analyzed):
        store, _, _, _, out = analyzed
        for name, row in stored(store).items():
            if row["open_status"] != "ok":
                continue
            original = next((out / "android_dump").rglob(name))
            inspection = SQLiteInspector.inspect(original, include_records=False)
            got = {t["name"]: (t["obj_type"], t["row_count"], t["rowid_table"], t["is_virtual"]) for t in tables_of(store, name).values() if t["obj_type"] == "table"}
            want = {t.name: ("table", t.row_count, int(not t.without_rowid), int(t.kind.value == "virtual")) for t in inspection.tables}
            assert got == want, name
            assert {t["name"] for t in tables_of(store, name).values()} == {e.name for e in inspection.schema_entries}, name

    def test_view_includes_wal_is_sqlites_own_verdict_and_null_where_nothing_was_opened(self, analyzed):
        store = analyzed[0]
        rows = stored(store)
        assert rows["calllog.db"]["view_includes_wal"] == 1 and rows["mmssms.db"]["view_includes_wal"] == 0
        assert rows["broken.db"]["open_status"] == "unopenable" and rows["broken.db"]["view_includes_wal"] is None
        assert rows["vault.db"]["view_includes_wal"] is None
        engine = EngineInfo.model_validate_json(rows["calllog.db"]["engine_json"])
        assert engine.wal_frames_valid >= 1 and engine.applied_sidecars == ["wal", "shm"]

    def test_the_hot_journal_is_applied_and_explained(self, analyzed):
        store = analyzed[0]
        pending = stored(store)["pending.db"]
        engine = EngineInfo.model_validate_json(pending["engine_json"])
        assert engine.applied_sidecars == ["journal"] and any("rolled it back" in n for n in engine.notes)
        assert any("rolled it back" in w for w in json.loads(pending["warnings_json"]))
        assert tables_of(store, "pending.db")["queue"]["row_count"] == 4000

    def test_statuses_keep_their_meaning(self, analyzed):
        rows = stored(analyzed[0])
        assert {n: r["open_status"] for n, r in rows.items() if n in ("mmssms.db", "broken.db", "vault.db")} == {
            "mmssms.db": "ok", "broken.db": "unopenable", "vault.db": "encrypted_suspect"}
        assert rows["broken.db"]["sqlite_status"] == "TRUNCATED" and rows["broken.db"]["integrity_detail"] == "database could not be opened by SQLite"
        assert rows["mmssms.db"]["integrity_status"] == "VALID" and rows["mmssms.db"]["integrity_detail"] == "ok"

    def test_scanning_again_replaces_rather_than_accumulates(self, synth, tmp_path):
        from android_forensics.acquisition.ingest import ingest_source
        from android_forensics.pipeline.runner import run_stage
        from android_forensics.storage.case_store import CaseStore

        out, _ = synth
        store = CaseStore.create(tmp_path / "case", "again", "pytest")  # its own case: re-running scan resets what is built on it
        ingest_source(store, out / "android_dump")
        run_stage(store, "scan")
        counts = lambda: [store.scalar(f"SELECT COUNT(*) FROM {t}") for t in ("databases", "db_tables")]  # noqa: E731
        first = counts()
        run_stage(store, "scan")
        assert counts() == first and first[0] == 8 and first[1] > 0, "8 databases; every catalogue entry stored exactly once"


class TestReport:
    @pytest.fixture()
    def report(self, analyzed, tmp_path):
        store = analyzed[0]
        generate_report(store, ["html", "json"], out_dir=tmp_path / "rep")
        files = {p.name: p for p in tmp_path.rglob("report.*")}
        return files["report.html"].read_text(), json.loads(files["report.json"].read_text())

    def test_databases_carry_their_version_and_wal_frames(self, report):
        _, data = report
        dbs = {d["path"].rsplit("/", 1)[-1]: d for d in data["databases"]}
        assert dbs["mmssms.db"]["sqlite_version"] and dbs["mmssms.db"]["schema_format"] == 4
        assert dbs["calllog.db"]["wal_frames_valid"] >= 1 and dbs["vault.db"]["sqlite_version"] is None

    def test_the_table_catalogue_lists_keys_and_indexes(self, report):
        html, data = report
        catalogue = {(t["database"].rsplit("/", 1)[-1], t["name"]): t for t in data["table_catalog"]}
        assert catalogue[("mmssms.db", "sms")]["primary_key"] == ["_id"]
        raw = catalogue[("contacts2.db", "raw_contacts")]
        assert raw["indexes"] == [{"name": "raw_contacts_name", "unique": False, "origin": "c", "partial": False, "columns": raw["indexes"][0]["columns"]}]
        assert catalogue[("notes.db", "settings")]["primary_key"] == ["key"]
        assert "PK(_id)" in html and "index raw_contacts_name(" in html and "last written by SQLite" in html


class TestApproximatedCollationsInTheCase:
    """A healthy phone database with a LOCALIZED-collated index is PARTIALly verified in the case — never INVALID."""

    @pytest.fixture()
    def case(self, tmp_path):
        from android_forensics.acquisition.ingest import ingest_source
        from android_forensics.pipeline.runner import run_pipeline
        from android_forensics.storage.case_store import CaseStore
        from tests.unit.sqlite_helpers import collated_db

        ev = tmp_path / "ev"
        collated_db(ev / "data/data/com.android.providers.contacts/databases/contacts2.db", reverse=True)
        store = CaseStore.create(tmp_path / "case", "coll", "pytest")
        ingest_source(store, ev)
        run_pipeline(store)
        return store

    def test_it_is_stored_as_partial_with_the_reason(self, case):
        row = case.one("SELECT * FROM databases")
        assert row["open_status"] == "ok" and row["integrity_status"] == "PARTIAL"
        assert "idx_name" in row["integrity_detail"] and "LOCALIZED" in row["integrity_detail"]

    def test_it_is_not_reported_as_an_integrity_failure(self, case):
        assert case.scalar("SELECT COUNT(*) FROM scan_issues WHERE issue_type='database_integrity_failure'") == 0

    def test_validation_reports_partial_not_invalid(self, case):
        [check] = [dict(r) for r in case.q("SELECT * FROM validation_results WHERE check_name='sqlite_integrity'")]
        assert check["status"] == "PARTIAL" and "idx_name" in check["detail"]
