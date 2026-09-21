"""Hostile / damaged / odd inputs: the tool must record the problem and keep going, never crash or invent data."""

import json
import os
import sqlite3
import stat

import pytest

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.pipeline.runner import run_pipeline
from android_forensics.reporting.generate import generate_report
from android_forensics.storage.case_store import CaseStore

TEL = "data/data/com.android.providers.telephony/databases"
CON = "data/data/com.android.providers.contacts/databases"


def sms_db(path, rows, extra_cols=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.execute(f"CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT{extra_cols})")
    c.executemany("INSERT INTO sms VALUES(?,?,?,?,?)", rows)
    c.commit()
    c.close()


def analyze(tmp_path, ev):
    s = CaseStore.create(tmp_path / "case", "c")
    ingest_source(s, ev)
    run_pipeline(s)
    return s


def results(s, check):
    return [dict(r) for r in s.q("SELECT * FROM validation_results WHERE check_name=?", (check,))]


def test_duplicates_are_detected_within_and_across_databases(tmp_path):
    ev = tmp_path / "ev"
    rows = [(1, "+12025550123", 1709280000000, 1, "same"), (2, "+12025550123", 1709280000000, 1, "same"), (3, "+12025550123", 1709280005000, 1, "other")]
    sms_db(ev / TEL / "mmssms.db", rows)
    sms_db(ev / TEL / "mmssms_backup.db", rows[:1])
    s = analyze(tmp_path, ev)
    dup = [r for r in results(s, "duplicate_detection") if r["target_type"] == "artifact"]
    assert dup and dup[0]["status"] == "PARTIAL"
    assert len(json.loads(dup[0]["evidence_json"])["artifact_ids"]) == 3  # 2 in main + 1 in backup
    assert "different tables/databases" in dup[0]["detail"]
    summary = [r for r in results(s, "duplicate_detection") if r["target_type"] == "case"][0]
    assert summary["status"] == "PARTIAL"


def test_implausible_and_unparseable_timestamps_are_flagged_not_dropped(tmp_path):
    ev = tmp_path / "ev"
    sms_db(ev / TEL / "mmssms.db", [
        (1, "+12025550123", 1709280000000, 1, "ok"), (2, "+12025550123", 1000, 1, "epoch-ish"),
        (3, "+12025550123", 4102444800000, 1, "year 2100"), (4, "+12025550123", "garbage", 1, "text date"),
        (5, "+12025550123", 9223372036854775807, 1, "overflow")])
    s = analyze(tmp_path, ev)
    assert s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='sms'") == 5, "bad timestamps must not drop the record"
    flagged = [r for r in results(s, "timestamp_plausibility") if r["target_type"] == "artifact"]
    assert len(flagged) == 4
    assert s.scalar("SELECT ts_utc FROM artifacts WHERE source_rowid=4") is None
    assert s.scalar("SELECT ts_utc FROM artifacts WHERE source_rowid=5") is None


def test_cross_artifact_mismatch_between_call_name_and_contact(tmp_path):
    ev = tmp_path / "ev"
    (ev / CON).mkdir(parents=True)
    c = sqlite3.connect(ev / CON / "calllog.db")
    c.execute("CREATE TABLE calls(_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER, name TEXT)")
    c.executemany("INSERT INTO calls VALUES(?,?,?,?,?,?)", [
        (1, "+12025550101", 1709280000000, 30, 1, "Alice Smith"), (2, "+12025550101", 1709280100000, 0, 3, "Someone Else"),
        (3, "+12025550102", 1709280200000, 9, 3, None)])
    c.commit()
    c.close()
    c = sqlite3.connect(ev / "contacts.db")  # flat contacts variant, name hint 'contacts'
    c.close()
    (ev / "contacts.db").unlink()
    c = sqlite3.connect(ev / CON / "contacts_flat.db")
    c.execute("CREATE TABLE contacts(_id INTEGER PRIMARY KEY, display_name TEXT, number TEXT)")
    c.execute("INSERT INTO contacts VALUES(1,'Alice Smith','(202) 555-0101')")
    c.commit()
    c.close()
    s = analyze(tmp_path, ev)
    assert s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='contact'") == 1
    cross = results(s, "cross_artifact_consistency")
    mism = [r for r in cross if r["target_type"] == "artifact"]
    assert len(mism) == 1 and "Someone Else" in mism[0]["detail"]
    odd = [r for r in cross if r["target_label"] == "call type vs duration"]
    assert odd and odd[0]["status"] == "PARTIAL"  # call 3 is MISSED but has 9 seconds


def test_corrupted_middle_page_keeps_rows_read_and_flags_the_rest(tmp_path):
    ev = tmp_path / "ev"
    p = ev / TEL / "mmssms.db"
    p.parent.mkdir(parents=True)
    c = sqlite3.connect(p)
    c.execute("PRAGMA page_size=1024")
    c.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT)")
    c.executemany("INSERT INTO sms VALUES(?,?,?,?,?)", [(i, "+12025550123", 1709280000000 + i, 1, "m" * 60) for i in range(1, 801)])
    c.commit()
    c.close()
    data = bytearray(p.read_bytes())
    leaves = [i for i in range(2, len(data) // 1024) if data[i * 1024] == 0x0D]  # table-leaf b-tree pages
    victim = leaves[len(leaves) // 2]
    data[victim * 1024:(victim + 1) * 1024] = os.urandom(1024)
    p.write_bytes(bytes(data))
    s = analyze(tmp_path, ev)
    db = s.one("SELECT * FROM databases")
    assert db["integrity_status"] == "INVALID"
    got = s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='sms'")
    assert 0 < got < 800, "rows read before the damage are kept; the rest are not invented"
    assert results(s, "sqlite_integrity")[0]["status"] == "INVALID"
    assert s.scalar("SELECT COUNT(*) FROM scan_issues WHERE issue_type IN ('extraction_error','database_integrity_failure')") >= 1
    tbl = s.one("SELECT read_error FROM db_tables WHERE name='sms'")
    assert tbl["read_error"] and results(s, "schema_consistency")[0]["status"] == "PARTIAL"


def test_permission_denied_file_and_directory_are_recorded_and_skipped(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores file permissions")
    ev = tmp_path / "ev"
    (ev / "ok").mkdir(parents=True)
    (ev / "ok/a.txt").write_text("a")
    (ev / "locked_dir").mkdir()
    (ev / "locked_dir/x.txt").write_text("x")
    (ev / "secret.txt").write_text("s")
    os.chmod(ev / "secret.txt", 0)
    os.chmod(ev / "locked_dir", 0)
    try:
        s = CaseStore.create(tmp_path / "case", "c")
        ingest_source(s, ev)
        assert [r["path"] for r in s.q("SELECT path FROM evidence_files")] == ["ok/a.txt"]
        kinds = {i["path"]: i["issue_type"] for i in s.q("SELECT path, issue_type FROM scan_issues")}
        assert kinds["secret.txt"] == "read_error" and kinds["locked_dir"] == "unreadable_directory"
    finally:
        os.chmod(ev / "locked_dir", stat.S_IRWXU)
        os.chmod(ev / "secret.txt", stat.S_IRUSR | stat.S_IWUSR)


def test_non_utf8_filenames_do_not_crash(tmp_path):
    import io
    import tarfile

    tp = tmp_path / "odd.tar"
    with tarfile.open(tp, "w", encoding="utf-8", errors="surrogateescape") as t:
        ti = tarfile.TarInfo("caf\udce9-\udcff.txt")  # raw bytes b"caf\xe9-\xff.txt"
        ti.size = 11
        t.addfile(ti, io.BytesIO(b"hello world"))
    s = CaseStore.create(tmp_path / "case", "c")
    ingest_source(s, tp)
    run_pipeline(s)
    generate_report(s, ["html", "json", "csv"], tmp_path / "out")
    assert "caf" in s.scalar("SELECT path FROM evidence_files")


def test_non_utf8_filenames_on_disk_do_not_crash(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    try:
        with open(os.path.join(os.fsencode(ev), b"caf\xe9-\xff.txt"), "wb") as fh:
            fh.write(b"hello world")
    except OSError:
        pytest.skip("this filesystem rejects non-UTF-8 file names (e.g. APFS)")
    s2 = CaseStore.create(tmp_path / "case2", "c")
    ingest_source(s2, ev)
    assert s2.scalar("SELECT COUNT(*) FROM evidence_files") == 1


def test_empty_evidence_directory_produces_a_valid_empty_report(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    s = analyze(tmp_path, ev)
    assert s.scalar("SELECT COUNT(*) FROM artifacts") == 0
    res = generate_report(s, ["html", "json", "csv"], tmp_path / "out")
    assert "NOT PERFORMED" in res.html.read_text() and json.loads(res.json.read_text())["artifact_summary"]["total"] == 0


def test_utf16_database_is_read_correctly(tmp_path):
    ev = tmp_path / "ev"
    p = ev / TEL / "mmssms.db"
    p.parent.mkdir(parents=True)
    c = sqlite3.connect(p)
    c.execute("PRAGMA encoding='UTF-16le'")
    c.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT)")
    c.execute("INSERT INTO sms VALUES(1,'+12025550123',1709280000000,1,?)", ("héllo wörld 日本語 🙂",))
    c.commit()
    c.close()
    s = analyze(tmp_path, ev)
    assert s.scalar("SELECT text_encoding FROM databases") == "UTF-16le"
    assert json.loads(s.scalar("SELECT fields_json FROM artifacts WHERE artifact_type='sms'"))["body"] == "héllo wörld 日本語 🙂"


def test_wrong_schema_never_becomes_an_artifact(tmp_path):
    ev = tmp_path / "ev/data/data/com.example.app/databases"
    ev.mkdir(parents=True)
    c = sqlite3.connect(ev / "app.db")
    c.execute("CREATE TABLE sms_like(a, b, c)")
    c.execute("CREATE TABLE stuff(address TEXT, note TEXT)")
    c.execute("INSERT INTO stuff VALUES('+12025550123', 'not an sms table')")
    c.commit()
    c.close()
    s = analyze(tmp_path, tmp_path / "ev")
    assert s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type!='app_summary'") == 0


def test_large_database_scales(tmp_path):
    ev = tmp_path / "ev"
    n = 60000
    sms_db(ev / TEL / "mmssms.db", [(i, f"+1202555{i % 9000:04d}", 1709280000000 + i * 1000, 1 + i % 2, f"message body {i}") for i in range(1, n + 1)])
    s = analyze(tmp_path, ev)
    assert s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='sms'") == n
    res = generate_report(s, ["html", "json"], tmp_path / "out")
    html = res.html.read_text()
    assert f"Showing the first 3,000 of {n:,} rows" in html
