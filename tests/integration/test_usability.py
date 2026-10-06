from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from android_forensics import plugins, userconfig
from android_forensics.artifacts import registry
from android_forensics.cli.app import app
from android_forensics.reporting.generate import generate_report
from android_forensics.storage.case_store import CaseStore

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "plugins"
runner = CliRunner()


def run(*args, env=None):
    return runner.invoke(app, [*args], catch_exceptions=False, env=env or {})


@pytest.fixture()
def clean_plugins():
    loaded_before = list(plugins.LOADED)
    yield
    registry._PARSERS[:] = [p for p in registry._PARSERS if plugins.is_builtin(p)]   # drop only what plugins added
    plugins.LOADED[:] = loaded_before
    for name in [m for m in sys.modules if m.startswith("android_forensics_plugin_")]:
        del sys.modules[name]


def plugin_copy(tmp_path: Path, name: str, mode: int = 0o600) -> Path:
    dst = tmp_path / name
    shutil.copy(EXAMPLES / name, dst)
    dst.chmod(mode)
    return dst


def oem_evidence(tmp_path: Path) -> Path:
    ev = tmp_path / "ev" / "data/data/com.acme.dialer/databases"
    ev.mkdir(parents=True)
    c = sqlite3.connect(ev / "acme.db")
    c.execute("CREATE TABLE call_history(id INTEGER PRIMARY KEY, phone TEXT, started INTEGER, secs INTEGER, direction TEXT)")
    c.executemany("INSERT INTO call_history VALUES(?,?,?,?,?)", [(1, "+12025550123", 1709280000, 60, "in"), (2, "+12025550124", 1709280600, 0, "miss"),
                                                                 (3, "+12025550125", 1709281200, 30, "out"), (4, "+12025550126", 1709281300, 5, "sideways")])
    c.commit()
    c.close()
    return tmp_path / "ev"


# ---------------------------------------------------------------------------- plugins


def test_plugin_parses_a_schema_the_builtins_do_not_know(tmp_path, clean_plugins):
    ev = oem_evidence(tmp_path)
    cases = tmp_path / "cases"
    before = run("analyze", str(ev), "--cases-dir", str(cases), "--name", "plain", "--no-report", "--no-recover")
    assert before.exit_code == 0
    assert CaseStore.open(cases / "plain").scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='call'") == 0

    p = plugin_copy(tmp_path, "acme_calls.py")
    r = run("--plugin", str(p), "analyze", str(ev), "--cases-dir", str(cases), "--name", "withplugin", "--no-report", "--no-recover")
    assert r.exit_code == 0
    s = CaseStore.open(cases / "withplugin")
    rows = s.q("SELECT parser, status, summary, flags_json FROM artifacts WHERE artifact_type='call' ORDER BY id")
    assert len(rows) == 4 and {r_["parser"] for r_ in rows} == {"acme_calls"} and {r_["status"] for r_ in rows} == {"ACTIVE"}
    assert any("unknown_direction:sideways" in r_["flags_json"] for r_ in rows)   # odd values are flagged, not hidden


def test_plugins_are_attributed_in_the_report(tmp_path, clean_plugins):
    ev = oem_evidence(tmp_path)
    p = plugin_copy(tmp_path, "acme_calls.py")
    cases = tmp_path / "cases"
    assert run("--plugin", str(p), "analyze", str(ev), "--cases-dir", str(cases), "--name", "c", "--no-report").exit_code == 0
    store = CaseStore.open(cases / "c")
    res = generate_report(store, ["html", "json"], tmp_path / "rep")
    prov = json.loads(res.json.read_text())["provenance"]["plugins"]
    assert prov[0]["name"] == "acme_calls" and len(prov[0]["sha256"]) == 64 and prov[0]["parsers"][0].endswith("AcmeCalls")
    html = res.html.read_text()
    assert "Parser plugins" in html and "acme_calls" in html


def test_a_crashing_plugin_is_recorded_and_does_not_stop_the_analysis(tmp_path, clean_plugins):
    ev = oem_evidence(tmp_path)
    good, bad = plugin_copy(tmp_path, "acme_calls.py"), plugin_copy(tmp_path, "crashing.py")
    cases = tmp_path / "cases"
    r = run("--plugin", str(good), "--plugin", str(bad), "analyze", str(ev), "--cases-dir", str(cases), "--name", "c", "--no-report", "--no-recover")
    assert r.exit_code == 0
    s = CaseStore.open(cases / "c")
    assert s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='call'") == 4          # the good plugin still ran
    issue = s.one("SELECT detail FROM scan_issues WHERE issue_type='parser_plugin_error'")
    assert issue and "boom in identify" in issue["detail"]


def test_unsafe_or_missing_plugin_files_are_refused(tmp_path, clean_plugins):
    open_perms = plugin_copy(tmp_path, "acme_calls.py", mode=0o666)
    assert open_perms.stat().st_mode & stat.S_IWOTH
    r = run("--plugin", str(open_perms), "plugins")
    assert r.exit_code == 2 and "writable" in (r.stdout + r.stderr)
    r = run("--plugin", str(tmp_path / "nope.py"), "plugins")
    assert r.exit_code == 2 and "not found" in (r.stdout + r.stderr)
    broken = tmp_path / "broken.py"
    broken.write_text("raise SystemExit('nope')\n")
    broken.chmod(0o600)
    r = run("--plugin", str(broken), "plugins")
    assert r.exit_code == 2 and "failed to load" in (r.stdout + r.stderr)


def test_plugins_command_lists_builtin_and_plugin_parsers(tmp_path, clean_plugins):
    p = plugin_copy(tmp_path, "acme_calls.py")
    out = run("--plugin", str(p), "plugins").stdout
    assert "calls" in out and "built-in" in out and "acme_calls" in out and "plugin" in out


def test_environment_variable_loads_plugins(tmp_path, clean_plugins):
    p = plugin_copy(tmp_path, "acme_calls.py")
    out = run("plugins", env={"ANDROID_FORENSICS_PLUGINS": str(p)}).stdout
    assert "acme_calls" in out


# ---------------------------------------------------------------------------- config file


def test_config_file_supplies_defaults_but_never_overrides(tmp_path, monkeypatch):
    cfg = tmp_path / "af.toml"
    cfg.write_text(f'cases_dir = "{tmp_path / "from-config"}"\n[examiner]\nname = "Dr. Config"\ntitle = "Examiner"\norganisation = "Lab X"\n'
                   '[report]\nagency = "Agency Y"\nclassification = "CONFIDENTIAL"\n')
    for var in ("ANDROID_FORENSICS_CASES", "ANDROID_FORENSICS_EXAMINER"):
        monkeypatch.delenv(var, raising=False)
    r = run("--config", str(cfg), "init-case", "cfg1")
    assert r.exit_code == 0
    store = CaseStore.open(tmp_path / "from-config" / "cfg1")
    assert store.case().examiner == "Dr. Config"
    d = store.details()
    assert d["examiner_organisation"] == "Lab X" and d["agency"] == "Agency Y" and d["classification"] == "CONFIDENTIAL"
    # an explicit option beats the file
    other = tmp_path / "explicit"
    r = run("--config", str(cfg), "init-case", "cfg2", "--cases-dir", str(other), "--examiner", "Someone Else")
    assert CaseStore.open(other / "cfg2").case().examiner == "Someone Else"


def test_bad_config_is_a_clear_error(tmp_path):
    for body, needle in (('bogus = 1\n', "unknown top-level"), ('[examiner]\nshoe_size = 9\n', "unknown key"), ('cases_dir = \n', "cannot read")):
        cfg = tmp_path / "bad.toml"
        cfg.write_text(body)
        r = run("--config", str(cfg), "plugins")
        assert r.exit_code == 2 and needle in (r.stdout + r.stderr), body
    r = run("--config", str(tmp_path / "missing.toml"), "plugins")
    assert r.exit_code == 2 and "not found" in (r.stdout + r.stderr)


def test_search_path_prefers_local_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "android-forensics.toml").write_text('cases_dir = "/x"\n')
    assert userconfig.load().cases_dir == "/x"


# ---------------------------------------------------------------------------- case details + court report


def test_case_details_flow_into_the_report_with_a_signature_block(tmp_path):
    cases = tmp_path / "cases"
    ev = tmp_path / "ev" / "data/data/x"
    ev.mkdir(parents=True)
    (ev / "a.txt").write_text("hi")
    assert run("init-case", "court", "--cases-dir", str(cases), "--examiner", "Dr. Doe", "--detail", "case_number=2026-0042",
               "--detail", "agency=City PD", "--detail", "classification=LAW ENFORCEMENT SENSITIVE").exit_code == 0
    r = run("case-details", "court", "--cases-dir", str(cases), "--set", "evidence_description=Samsung SM-G991 (S/N 123)", "--set",
            "statement=I certify this is accurate.", "--set", "footer=Page footer text", "--set", "witness_name=A. <b>Witness</b>")
    assert r.exit_code == 0 and "2026-0042" in r.stdout
    assert run("ingest", "court", str(tmp_path / "ev"), "--cases-dir", str(cases)).exit_code == 0
    assert run("analyze", "court", "--cases-dir", str(cases), "--no-report").exit_code == 0
    store = CaseStore.open(cases / "court")
    res = generate_report(store, ["html", "pdf", "json"], tmp_path / "rep")
    html = res.html.read_text()
    for needle in ("2026-0042", "City PD", "LAW ENFORCEMENT SENSITIVE", "Samsung SM-G991", "I certify this is accurate.", "Page footer text",
                   "Examiner signature", "Dr. Doe"):
        assert needle in html, needle
    assert "A. &lt;b&gt;Witness&lt;/b&gt;" in html and "<b>Witness</b>" not in html       # details are data, never markup
    from pypdf import PdfReader
    text = " ".join(p.extract_text() for p in PdfReader(res.pdf).pages)
    assert "2026-0042" in text and "Examiner signature" in text and "LAW ENFORCEMENT SENSITIVE" in text
    # every change to a detail is in the tamper-evident custody log
    ok, _ = store.verify_custody_chain()
    assert ok and store.scalar("SELECT COUNT(*) FROM custody_log WHERE action='case_detail_set'") >= 6


def test_case_detail_validation(tmp_path):
    cases = tmp_path / "cases"
    run("init-case", "v", "--cases-dir", str(cases))
    for bad in ("Bad Key=x", "=x", "novalue", "UPPER=x", "k=" + "x" * 4001):
        r = run("case-details", "v", "--cases-dir", str(cases), "--set", bad)
        assert r.exit_code == 2, bad


# ---------------------------------------------------------------------------- logging


def test_json_logging_records_each_stage(tmp_path):
    ev = tmp_path / "ev" / "data/data/x"
    ev.mkdir(parents=True)
    (ev / "a.txt").write_text("hi")
    logfile = tmp_path / "log" / "af.jsonl"
    r = run("--log-level", "INFO", "--log-file", str(logfile), "--log-format", "json", "analyze", str(tmp_path / "ev"), "--cases-dir",
            str(tmp_path / "cases"), "--name", "lg", "--no-report")
    assert r.exit_code == 0
    for h in logging.getLogger("android_forensics").handlers:
        h.flush()
    events = [json.loads(line) for line in logfile.read_text().splitlines()]
    done = [e for e in events if e["msg"] == "stage completed"]
    assert {e["stage"] for e in done} >= {"scan", "extract", "validate", "timeline"} and all(e["level"] == "INFO" and "seconds" in e for e in done)
    logging.getLogger("android_forensics").handlers.clear()
