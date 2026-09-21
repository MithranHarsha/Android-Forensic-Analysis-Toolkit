"""Phase 4D: the recovery engine against the deletion matrix (every condition, ground truth derived from the files' bytes)."""

import pytest

from android_forensics.lab.deletions import DeletionCase, build_case, standard_matrix
from android_forensics.lab.evaluation import matches, score_case
from android_forensics.models.enums import ArtifactStatus, ExtractionMethod
from android_forensics.models.unknown import UNKNOWN
from android_forensics.sqlite.recover_db import recover_database
from tests.conftest import tree_hash

# Layouts where a neighbouring cell's head was also destroyed, so a freed cell's end cannot be confirmed; documented limits.
MIN_RECALL = {"plain_ps1024": 0.70, "plain_ps2048": 0.75, "overwrite_50": 0.90}
STATUS = {"RECOVERED": ArtifactStatus.RECOVERED, "PARTIAL": ArtifactStatus.PARTIAL}


@pytest.fixture(scope="module")
def matrix(tmp_path_factory):
    dest = tmp_path_factory.mktemp("matrix")
    results = {}
    for case in standard_matrix():
        out = build_case(dest, case)
        report = recover_database(out.database, out.sidecars, dest / "_scratch")
        results[case.name] = (out, report, score_case(out.truth, report.rows))
    return dest, results


def test_the_matrix_covers_every_condition(matrix):
    _, results = matrix
    from android_forensics.lab.deletions import CONDITIONS

    assert {r[0].case.condition for r in results.values()} == set(CONDITIONS)
    assert len(results) >= 28


def test_no_case_reports_a_row_that_was_not_deleted(matrix):
    """Precision 1.0 everywhere: nothing is invented, and nothing that is still active is reported as deleted."""
    _, results = matrix
    for name, (_, report, score) in results.items():
        assert score.false_positives == 0, (name, score)
        assert score.precision == 1.0


def test_recall_of_the_physically_recoverable_rows(matrix):
    _, results = matrix
    for name, (_, _, score) in results.items():
        assert score.recall >= MIN_RECALL.get(name, 1.0), (name, score.recall, score.matched_expected, score.expected_recoverable)


def test_overall_recall_is_high_and_measured(matrix):
    _, results = matrix
    found = sum(s.matched_expected for _, _, s in results.values())
    expected = sum(s.expected_recoverable for _, _, s in results.values())
    assert expected > 400 and found / expected >= 0.97, (found, expected)


def test_every_matched_row_carries_the_class_the_bytes_justify(matrix):
    """RECOVERED only where the whole cell survived, PARTIAL where the freeblock header took the first four bytes."""
    _, results = matrix
    for name, (_, _, score) in results.items():
        assert score.class_correct == score.matched, (name, score)


@pytest.mark.parametrize("case", ["vacuum", "secure_delete"])
def test_nothing_is_recovered_when_nothing_survives(matrix, case):
    _, results = matrix
    out, report, score = results[case]
    assert report.rows == [] and out.truth["expected_counts"]["UNRECOVERABLE"] == 25


def test_erased_space_is_reported_as_unrecoverable_evidence(matrix):
    _, results = matrix
    _, report, _ = results["secure_delete"]
    assert report.unrecovered and all("zero-filled" in u.reason for u in report.unrecovered)
    assert all(not any(u.raw[4:]) for u in report.unrecovered if u.region == "freeblock")


# ------------------------------------------------------------------ the definition of done: 100 rows, 25 deleted, no VACUUM, rollback journal


@pytest.mark.parametrize("case", ["plain", "journal_off", "journal_truncate"])
def test_every_recovered_row_has_complete_and_true_provenance(matrix, case):
    _, results = matrix
    out, report, _ = results[case]
    assert len(report.rows) >= 20
    for row in report.rows:
        assert row.table == "sms" and row.page_number >= 1 and row.file_offset >= 0 and row.length > 0
        assert isinstance(row.method, ExtractionMethod) and not row.method.is_active and row.status in STATUS.values()
        source = out.database if row.source == "main" else out.sidecars["-wal" if row.source == "wal" else "-journal"]
        assert row.source_path == str(source)
        # the recorded location really holds the recorded bytes
        assert source.read_bytes()[row.file_offset: row.file_offset + row.length] == row.raw
        assert row.file_offset == (row.page_number - 1) * 4096 + row.page_offset if row.source == "main" else row.file_offset > 0


def test_a_field_the_bytes_do_not_determine_is_unknown_never_guessed(matrix):
    _, results = matrix
    out, report, _ = results["plain"]
    partial = [r for r in report.rows if r.status is ArtifactStatus.PARTIAL]
    assert len(partial) == 25
    for r in partial:
        assert r.rowid is None and r.values["_id"] is UNKNOWN and "_id" in r.unknown_columns
        assert any("rowid is unknown" in i for i in r.issues)
        # every field the row *does* claim is right
        assert any(matches(r.values, t["values"]) for t in out.truth["deleted_rows"])


def test_recovered_rows_never_carry_a_wrong_known_value(matrix):
    _, results = matrix
    for name, (out, report, _) in results.items():
        truth = [t["values"] for t in out.truth["deleted_rows"]]
        for r in report.rows:
            assert any(matches(r.values, t) for t in truth), (name, r.values)


# ------------------------------------------------------------------ where each kind of remnant comes from


def methods(matrix, case):
    return {r.method for r in matrix[1][case][1].rows}


def test_a_persistent_journal_gives_intact_pages(matrix):
    assert methods(matrix, "journal_persist") == {ExtractionMethod.JOURNAL_PAGE}
    assert all(r.status is ArtifactStatus.RECOVERED and r.rowid for r in matrix[1]["journal_persist"][1].rows)


def test_wal_history_is_read_from_the_frames(matrix):
    assert methods(matrix, "wal_history") == {ExtractionMethod.WAL_FRAME}
    rows = matrix[1]["wal_history"][1].rows
    assert all(r.frame and "committed WAL frame" in " ".join(r.issues) for r in rows)


def test_a_delete_still_in_the_wal_leaves_intact_cells_in_the_main_file(matrix):
    rows = matrix[1]["wal_uncheckpointed"][1].rows
    assert {r.method for r in rows} == {ExtractionMethod.RAW_PAGE_SCAN} and {r.status for r in rows} == {ArtifactStatus.RECOVERED}
    assert all("no longer contains" in " ".join(r.issues) for r in rows)


def test_stale_wal_frames_hold_the_pre_delete_pages_too(matrix):
    report = matrix[1]["wal_stale"][1]
    assert report.wal["stale_generation"] >= 3
    assert any("wal:" in loc for r in report.rows for loc in r.also_found_at), "the same rows also survive in stale frames"


def test_split_residue_in_a_released_root_is_found_without_freeblocks(matrix):
    rows = matrix[1]["plain_residue"][1].rows
    assert len(rows) == 25 and {r.status for r in rows} == {ArtifactStatus.RECOVERED}
    assert {r.method for r in rows} == {ExtractionMethod.UNALLOCATED_SPACE}


def test_whole_released_pages_come_from_the_freelist(matrix):
    assert ExtractionMethod.FREELIST_PAGE in methods(matrix, "plain_large")


def test_more_overwriting_means_fewer_recoverable_rows(matrix):
    _, results = matrix
    matched = [results[n][2].matched for n in ("overwrite_50", "overwrite_100", "overwrite_200")]
    assert matched[0] >= matched[1] >= matched[2] and matched[0] > matched[2]
    assert [results[n][0].truth["expected_counts"]["UNRECOVERABLE"] for n in ("overwrite_50", "overwrite_100", "overwrite_200")] == [12, 24, 24]


# ------------------------------------------------------------------ guarantees


def test_recovery_never_modifies_the_evidence(tmp_path):
    out = build_case(tmp_path, DeletionCase(name="w", condition="wal_checkpointed"))
    folder = out.database.parent
    before = tree_hash(folder)
    recover_database(out.database, out.sidecars, tmp_path / "scratch")
    recover_database(out.database, out.sidecars)
    assert tree_hash(folder) == before and sorted(p.name for p in folder.iterdir()) == ["ground_truth.json", "sms.db", "sms.db-wal"]
    assert not list((tmp_path / "scratch").iterdir()), "the scratch copy is deleted afterwards"


def test_recovery_is_deterministic(tmp_path):
    out = build_case(tmp_path, DeletionCase(name="d", condition="plain", position="random"))
    a = recover_database(out.database, out.sidecars)
    b = recover_database(out.database, out.sidecars)
    key = lambda r: (r.page_number, r.page_offset, r.status, r.method, tuple(sorted((k, repr(v)) for k, v in r.values.items())))  # noqa: E731
    assert [key(r) for r in a.rows] == [key(r) for r in b.rows] and len(a.rows) == 25


def test_a_database_sqlite_cannot_read_is_still_recovered_from_its_pages(tmp_path):
    """Destroy the table's root page: SQLite can no longer read the table, but every leaf page still holds cells."""
    out = build_case(tmp_path, DeletionCase(name="broken", condition="plain"))
    data = bytearray(out.database.read_bytes())
    data[4096:8192] = b"\xff" * 4096  # page 2: the root (interior) page of sms
    out.database.write_bytes(bytes(data))
    report = recover_database(out.database, out.sidecars)
    deleted = [t["values"] for t in out.truth["deleted_rows"]]
    found = [r for r in report.rows if any(matches(r.values, d) for d in deleted)]
    assert len(found) == 25, "all deleted rows are still recovered"
    orphans = [r for r in report.rows if r.region == "orphan_page"]
    assert len(orphans) == 100, "rows on pages no b-tree reaches any more are reported from those orphan pages"
    intact = [r for r in orphans if r.status is ArtifactStatus.RECOVERED]
    assert len(intact) == 75 and all(r.rowid for r in intact), "the 75 rows that were never deleted come back whole, with their rowids"
    assert len(orphans) - len(intact) == 25 and all(r.rowid is None and r.status is ArtifactStatus.PARTIAL for r in orphans if r not in intact)


def test_a_database_with_no_readable_schema_says_so(tmp_path):
    out = build_case(tmp_path, DeletionCase(name="noschema", condition="plain"))
    data = bytearray(out.database.read_bytes())
    data[100:4096] = b"\xff" * (4096 - 100)  # page 1 keeps its header, loses the schema b-tree
    out.database.write_bytes(bytes(data))
    report = recover_database(out.database, out.sidecars)
    assert report.rows == [] and any("no table schema" in n for n in report.notes)


def test_a_file_that_is_not_a_database_is_declined(tmp_path):
    p = tmp_path / "junk.db"
    p.write_bytes(b"x" * 5000)
    report = recover_database(p)
    assert report.rows == [] and any("no usable header" in n for n in report.notes)


def test_stats_are_reported(matrix):
    _, results = matrix
    _, report, _ = results["plain"]
    assert report.stats["pages_examined"] >= 4 and report.stats["candidates"] >= 25 and report.stats["dropped_active"] >= 75
    assert report.tables_attempted == ["sms"] and report.active_source.startswith("sqlite")
