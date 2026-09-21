import csv
import hashlib
import json
import re
import sqlite3

import pytest

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.pipeline.runner import run_pipeline
from android_forensics.reporting.generate import _csv_safe, generate_report
from android_forensics.storage.case_store import CaseStore


@pytest.fixture(scope="module")
def report(analyzed, tmp_path_factory):
    store, *_ = analyzed
    return generate_report(store, ["html", "json", "csv"], tmp_path_factory.mktemp("rep"))


def test_all_16_sections_and_review_scope(report):
    html = report.html.read_text()
    for n in range(1, 17):
        assert f'id="s{n}"' in html
    assert html.count("NOT PERFORMED (Review 2)") >= 4
    for label in ("ACTIVE DATA", "RECOVERED DELETED DATA", "PARTIAL RECOVERIES", "CARVED CANDIDATES", "UNRECOVERABLE DATA"):
        assert label in html
    assert "not a finding" in html.lower() or "not findings" in html.lower()
    assert "TRIM" in html  # recoverability disclaimer


def test_json_report_is_complete_and_carries_provenance(report):
    data = json.loads(report.json.read_text())
    assert data["recovery"]["performed"] is False
    assert data["active"]["sms"]["total"] == 120 and len(data["active"]["sms"]["rows"]) == 120
    assert data["artifact_summary"]["total"] == 373
    for sec in data["active"].values():
        for row in sec["rows"]:
            p = row["prov"]
            assert re.fullmatch(r"[0-9a-f]{64}", p["sha256"]) and p["file"] and p["method"] in ("ACTIVE_QUERY", "FILESYSTEM_METADATA")
            if sec["title"] != "Application summary":
                assert p["table"] and p["rowid"] is not None
    assert data["custody"]["intact"] is True
    assert data["validation"]["by_status"]["INVALID"] if "INVALID" in data["validation"]["by_status"] else True


def test_csv_exports_and_bom(report):
    art = (report.csv_dir / "artifacts.csv").read_bytes()
    assert art.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader((report.csv_dir / "artifacts.csv").open(encoding="utf-8-sig")))
    assert len(rows) == 373 and {r["status"] for r in rows} == {"ACTIVE"}
    assert len(list(csv.DictReader((report.csv_dir / "evidence_files.csv").open(encoding="utf-8-sig")))) == 16


def test_sha256sums_match_files(report):
    for line in report.sums.read_text().strip().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((report.out_dir / name).read_bytes()).hexdigest() == digest


def test_unsupported_format_rejected(analyzed, tmp_path):
    store, *_ = analyzed
    with pytest.raises(ValueError):
        generate_report(store, ["pdf"], tmp_path)


def test_html_row_cap_truncates_html_only(analyzed, tmp_path):
    store, *_ = analyzed
    res = generate_report(store, ["html", "json"], tmp_path, html_row_cap=5)
    assert "Showing the first 5 of 120 rows" in res.html.read_text()
    assert len(json.loads(res.json.read_text())["active"]["sms"]["rows"]) == 120


def test_csv_formula_injection_neutralised_without_mangling_numbers():
    assert _csv_safe("=1+1") == "'=1+1" and _csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert _csv_safe("+cmd|x") == "'+cmd|x" and _csv_safe("-cmd|x") == "'-cmd|x"
    assert _csv_safe("+12025550123") == "+12025550123" and _csv_safe("-5") == "-5"
    assert _csv_safe("normal") == "normal" and _csv_safe(None) is None and _csv_safe(7) == 7


def test_hostile_evidence_cannot_inject_html_or_formulas(tmp_path):
    ev = tmp_path / "ev/data/data/com.android.providers.telephony/databases"
    ev.mkdir(parents=True)
    c = sqlite3.connect(ev / "mmssms.db")
    c.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT)")
    evil = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    c.execute("INSERT INTO sms VALUES(1,'+12025550123',1709280000000,1,?)", (evil,))
    c.execute("INSERT INTO sms VALUES(2,'=HYPERLINK(\"http://evil\",\"x\")',1709280001000,1,'=1+1')")
    c.commit()
    c.close()
    (tmp_path / "ev/=cmd.txt").write_text("hello world")
    s = CaseStore.create(tmp_path / "case", "c")
    ingest_source(s, tmp_path / "ev")
    run_pipeline(s)
    res = generate_report(s, ["html", "csv", "json"], tmp_path / "out")
    html = res.html.read_text()
    assert "<script>alert(1)</script>" not in html and "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "&lt;img src=x onerror=alert(2)&gt;" in html
    files_csv = (res.csv_dir / "evidence_files.csv").read_text(encoding="utf-8-sig")
    assert "'=cmd.txt" in files_csv
    art = list(csv.DictReader((res.csv_dir / "artifacts.csv").open(encoding="utf-8-sig")))
    assert all(not r["summary"].startswith("=") for r in art)
    data = json.loads(res.json.read_text())
    assert evil in json.dumps(data["active"]["sms"]["rows"])  # evidence preserved verbatim in JSON
