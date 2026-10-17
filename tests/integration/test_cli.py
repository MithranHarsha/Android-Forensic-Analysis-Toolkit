import json

from typer.testing import CliRunner

from android_forensics.cli.app import app

runner = CliRunner()


def run(*args, cases):
    return runner.invoke(app, [*args], catch_exceptions=False, env={"ANDROID_FORENSICS_CASES": str(cases)})


def test_full_manual_workflow(synth, tmp_path):
    out, _ = synth
    cases = tmp_path / "cases"
    r = run("init-case", "case001", "--examiner", "Tester", cases=cases)
    assert r.exit_code == 0 and "Case created" in r.stdout
    r = run("ingest", "case001", str(out / "acquisition.zip"), cases=cases)
    assert r.exit_code == 0 and "Manifest SHA-256" in r.stdout and "16" in r.stdout
    r = run("scan", "case001", cases=cases)
    assert r.exit_code == 0 and "SQLite databases" in r.stdout and "android_root" in r.stdout
    r = run("analyze", "case001", "--no-report", "--no-recover", cases=cases)
    assert r.exit_code == 0 and "Artifacts (ACTIVE)" in r.stdout and "373" in r.stdout
    assert "Deleted-data recovery was not run (--no-recover)" in r.stdout
    r = run("artifacts", "case001", "--type", "sms", "--limit", "3", cases=cases)
    assert r.exit_code == 0 and "of 120" in r.stdout
    r = run("artifacts", "case001", "--show", "1", cases=cases)
    assert r.exit_code == 0 and "Provenance" in r.stdout and "File SHA-256" in r.stdout and "Raw source" in r.stdout
    r = run("validate", "case001", cases=cases)
    assert r.exit_code == 0 and "UNVERIFIED" in r.stdout and "truncated" in r.stdout
    r = run("timeline", "case001", "--limit", "5", "--type", "call", cases=cases)
    assert r.exit_code == 0 and "ACTIVE" in r.stdout
    r = run("report", "case001", "--format", "html,json", cases=cases)
    assert r.exit_code == 0 and "report.html" in r.stdout
    r = run("report", "case001", "--format", "html,json,csv,pdf", cases=cases)
    assert r.exit_code == 0 and "report.html" in r.stdout and "report.pdf" in r.stdout and "CSV dir" in r.stdout
    r = run("info", "case001", cases=cases)
    assert r.exit_code == 0 and "custody" in r.stdout.lower() and "intact" in r.stdout


def test_analyze_directly_on_a_path_creates_case_and_report(synth, tmp_path):
    out, _ = synth
    cases = tmp_path / "cases"
    r = run("analyze", str(out / "android_dump"), "--name", "auto", cases=cases)
    assert r.exit_code == 0 and "Report:" in r.stdout
    assert (cases / "auto" / "case.db").exists() and list((cases / "auto" / "reports").glob("report-*/report.html"))


def test_analyze_runs_recovery_by_default_and_reports_real_numbers(synth, tmp_path):
    out, _ = synth
    cases = tmp_path / "cases"
    r = run("init-case", "case-r2", cases=cases)
    assert r.exit_code == 0
    run("ingest", "case-r2", str(out / "android_dump"), cases=cases)
    run("scan", "case-r2", cases=cases)
    r = run("analyze", "case-r2", "--no-report", cases=cases)
    assert r.exit_code == 0
    assert "Deleted-data recovery" in r.stdout and "Deleted/superseded records found" in r.stdout
    assert "Deleted-data recovery was not run" not in r.stdout
    r = run("info", "case-r2", cases=cases)
    assert r.exit_code == 0 and "Recovered/partial/corrupted records" in r.stdout and "Carved candidates" in r.stdout


def test_the_standalone_recover_command_requires_scan_and_extract_first(synth, tmp_path):
    out, _ = synth
    cases = tmp_path / "cases"
    run("init-case", "case-r3", cases=cases)
    run("ingest", "case-r3", str(out / "android_dump"), cases=cases)
    r = run("recover", "case-r3", cases=cases)
    assert r.exit_code != 0 and "scan" in r.output.lower()
    run("scan", "case-r3", cases=cases)
    r = run("recover", "case-r3", cases=cases)
    assert r.exit_code != 0 and "extract" in r.output.lower()
    run("analyze", "case-r3", "--no-report", "--no-recover", cases=cases)
    r = run("recover", "case-r3", cases=cases)
    assert r.exit_code == 0 and "Deleted-data recovery" in r.stdout
    r2 = run("recover", "case-r3", cases=cases)  # recovering the same evidence twice gives the same counts
    assert r2.exit_code == 0 and "Deleted/superseded records found" in r2.stdout


def test_info_on_database_file_and_hash_json(synth, tmp_path):
    out, _ = synth
    db = out / "android_dump/data/data/com.android.providers.contacts/databases/calllog.db"
    r = run("info", str(db), cases=tmp_path)
    assert r.exit_code == 0 and "Page size" in r.stdout and "frame_slots" in r.stdout
    r = run("hash", str(db), "--json", cases=tmp_path)
    data = json.loads(r.stdout)
    assert r.exit_code == 0 and len(data[0]["sha256"]) == 64 and data[0]["path"] == "calllog.db"


def test_hash_command_follows_an_explicit_symlink_but_not_symlinks_inside_a_directory(tmp_path):
    import hashlib
    import os

    real = tmp_path / "real.bin"
    real.write_bytes(b"payload")
    link = tmp_path / "link.bin"
    os.symlink(real, link)
    r = run("hash", str(link), "--json", cases=tmp_path)
    assert r.exit_code == 0 and json.loads(r.stdout)[0]["sha256"] == hashlib.sha256(b"payload").hexdigest()
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    os.symlink(real, folder / "via_link")
    listed = [e["path"] for e in json.loads(run("hash", str(folder), "--json", cases=tmp_path).stdout)]
    assert listed == ["a.txt"], "symlinks inside a directory are not followed"


def test_ingest_preserve_option(synth, tmp_path):
    out, _ = synth
    cases = tmp_path / "cases"
    run("init-case", "c", cases=cases)
    r = run("ingest", "c", str(out / "acquisition.zip"), "--preserve", "none", cases=cases)
    assert r.exit_code == 0 and "Preserved copies" in r.stdout
    r = run("ingest", "c", str(out / "acquisition.zip"), "--preserve", "sideways", cases=cases)
    assert r.exit_code != 0


def test_errors_exit_2_with_message(tmp_path):
    r = run("scan", "nosuchcase", cases=tmp_path)
    assert r.exit_code == 2
    r = run("init-case", "bad name!", cases=tmp_path)
    assert r.exit_code == 2
    run("init-case", "c1", cases=tmp_path)
    r = run("ingest", "c1", str(tmp_path / "missing"), cases=tmp_path)
    assert r.exit_code == 2
    r = run("report", "c1", cases=tmp_path)
    assert r.exit_code == 2
    evidence = tmp_path / "evidence_dir"
    evidence.mkdir()
    (evidence / "a.txt").write_text("hello")
    r = run("ingest", "c1", str(evidence), "--acquired-at", "2024-06-04T08:00:00", cases=tmp_path)
    assert r.exit_code == 2 and "timezone" in r.output
    r = run("ingest", "c1", str(tmp_path), cases=tmp_path)  # the parent of the case directory contains the working directory
    assert r.exit_code == 2 and "working directory" in r.output


def test_synth_command_is_reproducible(tmp_path):
    for name in ("a", "b"):
        assert run("synth", str(tmp_path / name), "--seed", "7", cases=tmp_path).exit_code == 0
    ta = json.loads((tmp_path / "a/ground_truth.json").read_text())
    tb = json.loads((tmp_path / "b/ground_truth.json").read_text())
    assert ta["files"] == tb["files"]
