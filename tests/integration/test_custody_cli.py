from __future__ import annotations

import json

from typer.testing import CliRunner

from android_forensics.cli.app import app
from android_forensics.custody import AuditLog

runner = CliRunner()


def run(*args, cases, env=None):
    return runner.invoke(app, [*args], catch_exceptions=False, env={"ANDROID_FORENSICS_CASES": str(cases), **(env or {})})


def test_every_case_command_is_audited_and_the_log_verifies(synth, tmp_path):
    out, _ = synth
    cases = tmp_path / "cases"
    assert run("init-case", "c1", "--examiner", "Tester", cases=cases).exit_code == 0
    assert run("ingest", "c1", str(out / "acquisition.zip"), cases=cases).exit_code == 0
    assert run("analyze", "c1", "--no-report", "--no-recover", cases=cases).exit_code == 0
    assert run("info", "c1", cases=cases).exit_code == 0
    entries = AuditLog(cases / "c1" / "audit.log.jsonl").entries()
    assert [e["command"] for e in entries] == ["init-case", "ingest", "analyze", "info"]
    assert all(e["outcome"] == "ok" and e["user"] and e["host"] and e["tool_version"] for e in entries)
    assert entries[-1]["evidence_manifest_sha256"] and entries[-1]["db_custody_head"]
    r = run("audit-verify", "c1", "--show", "2", cases=cases)
    assert r.exit_code == 0 and "intact" in r.stdout

    # rewriting history is caught
    log = cases / "c1" / "audit.log.jsonl"
    lines = log.read_text().splitlines()
    doc = json.loads(lines[1]); doc["user"] = "someone-else"; lines[1] = json.dumps(doc)
    log.write_text("\n".join(lines) + "\n")
    r = run("audit-verify", "c1", cases=cases)
    assert r.exit_code == 1 and "BROKEN" in r.stdout


def test_failed_command_is_audited_with_its_error(tmp_path):
    cases = tmp_path / "cases"
    run("init-case", "c2", cases=cases)
    r = run("ingest", "c2", str(tmp_path / "missing"), cases=cases)
    assert r.exit_code != 0
    last = AuditLog(cases / "c2" / "audit.log.jsonl").entries()[-1]
    assert last["command"] == "ingest" and last["outcome"] != "ok"


def test_signed_report_roundtrip_and_tamper(synth, tmp_path):
    out, _ = synth
    cases, keydir = tmp_path / "cases", tmp_path / "keys"
    key = keydir / "k.pem"
    r = run("keygen", "--key", str(key), cases=cases)
    assert r.exit_code == 0 and key.exists()
    assert run("analyze", str(out / "android_dump"), "--name", "c3", "--no-report", cases=cases).exit_code == 0
    r = run("report", "c3", "--format", "html,json,csv", "--sign", "--key", str(key), "--signer", "Dr. Test", cases=cases)
    assert r.exit_code == 0 and "Signed" in r.stdout
    rep = next((cases / "c3" / "reports").iterdir())
    pub = key.with_suffix(".pub.pem")
    r = run("verify-report", str(rep), "--trusted-key", str(pub), cases=cases)
    assert r.exit_code == 0 and "VALID" in r.stdout and "Dr. Test" in r.stdout
    # the report carries the build stamp and the audit head
    rj = json.loads((rep / "report.json").read_text())
    assert rj["provenance"]["tool_stamp"]["fingerprint"] and rj["provenance"]["audit"]["intact"] is True
    assert "audit" in (rep / "report.html").read_text().lower()
    (rep / "report.html").write_text("tampered")
    r = run("verify-report", str(rep), cases=cases)
    assert r.exit_code == 1 and "NOT VALID" in r.stdout
