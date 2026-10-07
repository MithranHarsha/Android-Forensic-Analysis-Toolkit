import csv
import hashlib
import json
import re
import sqlite3

import pytest
from pypdf import PdfReader

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, run_pipeline
from android_forensics.reporting.generate import _csv_safe, generate_report
from android_forensics.storage.case_store import CaseStore
from tests.unit.test_pipeline_recovery import build_case


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
        generate_report(store, ["xml"], tmp_path)


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


# ------------------------------------------------------------------ Phase 12: a report over recovered evidence


@pytest.fixture(scope="module")
def recovered_report(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("recovered")
    dump = build_case(tmp / "dump")
    store = CaseStore.create(tmp / "case", "recovery", "pytest")
    ingest_source(store, dump)
    run_pipeline(store, names=list(FULL_PIPELINE_NAMES))
    res = generate_report(store, ["html", "json", "csv", "pdf"], tmp_path_factory.mktemp("rep2"))
    return store, res


def test_recovery_sections_show_real_content_instead_of_not_performed(recovered_report):
    _, res = recovered_report
    html = res.html.read_text()
    assert "Review 1 + Review 2" in html
    assert html.count("NOT PERFORMED (Review 2)") == 0, "every Review 2 stage ran for this case"
    assert 'id="t-rec"' in html and 'id="t-carved"' in html and 'id="t-corr"' in html
    assert "CARVED CANDIDATE" in html
    assert "reconstructed with a confidence explanation" in html or "corrupted" in html


def test_recovery_json_carries_real_records_with_confidence_and_explanation(recovered_report):
    _, res = recovered_report
    data = json.loads(res.json.read_text())
    rec = data["recovery"]
    assert rec["performed"] is True
    assert all(rec["stages_run"].values())
    assert rec["recovered"] or rec["corrupted"]
    for row in rec["recovered"] + rec["corrupted"] + rec["partial"]:
        assert row["confidence"] in ("LOW", "MEDIUM", "HIGH")
        assert row["explanation"].startswith(row["confidence"])
        assert isinstance(row["values"], dict) and isinstance(row["unknown_columns"], list)
    assert rec["carved"] and all(c["status"] if "status" in c else True for c in rec["carved"])
    assert rec["correlations"]
    assert any(e["relation"] == "CONTACT_OF" for e in rec["correlations"])
    for g in data["at_a_glance"]:
        if g["label"] in ("RECOVERED DELETED DATA", "CARVED CANDIDATES"):
            assert isinstance(g["value"], int) and g["value"] > 0


def test_recovery_csv_exports_exist_and_have_rows(recovered_report):
    _, res = recovered_report
    for name in ("recovered_records.csv", "carved_candidates.csv", "correlations.csv"):
        rows = list(csv.DictReader((res.csv_dir / name).open(encoding="utf-8-sig")))
        assert rows, name


def test_carved_candidates_never_read_as_confirmed_in_the_report(recovered_report):
    _, res = recovered_report
    data = json.loads(res.json.read_text())
    assert data["recovery"]["carved"]
    for c in data["recovery"]["carved"]:
        assert c["status"] == "CARVED CANDIDATE" and c["confidence"] != "HIGH"


def test_pdf_report_has_all_16_sections_and_real_recovery_content(recovered_report):
    _, res = recovered_report
    assert res.pdf is not None and res.pdf.stat().st_size > 1000
    reader = PdfReader(str(res.pdf))
    assert len(reader.pages) >= 16
    text = "\n".join((p.extract_text() or "") for p in reader.pages)
    for heading in (
        "1. Case information", "7. Recovered deleted data", "8. Active data", "9. Partial recoveries",
        "10. Carved candidates", "11. Timeline", "12. Correlation findings", "14. Recovery methodology",
        "15. Limitations", "16. Appendix",
    ):
        assert heading in text, heading
    assert "Review 1 + Review 2" in text
    assert "CARVED CANDIDATE" in text
    assert "NOT PERFORMED" not in text


def test_pdf_report_shows_not_performed_when_recovery_did_not_run(report, analyzed, tmp_path):
    assert report.pdf is None  # the module fixture only asked for html/json/csv
    store, *_ = analyzed
    res = generate_report(store, ["pdf"], tmp_path)
    reader = PdfReader(str(res.pdf))
    text = "\n".join((p.extract_text() or "") for p in reader.pages)
    assert text.count("NOT PERFORMED (Review 2)") >= 4


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


def test_html_caps_big_recovery_tables_but_json_and_csv_keep_everything(recovered_report, tmp_path):
    import json

    from android_forensics.reporting.generate import generate_report

    store, _ = recovered_report
    res = generate_report(store, ["html", "json", "csv"], tmp_path / "rep", html_row_cap=5)
    html = res.html.read_text()
    data = json.loads(res.json.read_text())
    counts = data["recovery"]["counts"]
    assert counts["carved"] > 5 and counts["recovered"] + counts["corrupted"] > 5
    assert len(data["recovery"]["carved"]) == counts["carved"]                         # nothing is lost from the machine-readable report
    assert f"of {counts['carved']:,} rows" in html and "Summary of all" in html          # …and the HTML says it is showing a sample, and summarises the whole
    assert "Showing the first 5 of" in html
    csv_rows = (res.csv_dir / "carved_candidates.csv").read_text(encoding="utf-8-sig").splitlines()
    assert len(csv_rows) - 1 == counts["carved"]
    assert len(html) < 3_000_000
