"""Evidence is attacker-controlled. These tests feed the tool deliberately malicious acquisitions and assert that nothing
escapes, nothing is modified, nothing executes, and nothing is rendered as markup."""

from __future__ import annotations

import io
import re
import sqlite3
import tarfile
import zipfile
from html.parser import HTMLParser
from pathlib import Path

import pytest
from typer.testing import CliRunner

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.acquisition.safety import ExtractionBudget
from android_forensics.cli.app import app
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, run_pipeline
from android_forensics.reporting.generate import generate_report
from android_forensics.sqlite.reader import SQLiteSession
from android_forensics.storage.case_store import CaseStore

TEL = "data/data/com.android.providers.telephony/databases"
XSS = [
    "<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "<svg/onload=alert(1)>", "javascript:alert(1)",
    "</td></tr></table><h1>pwn</h1>", "{{7*7}}", "{% for x in y %}", "${7*7}", "'; DROP TABLE artifacts;--", "\x1b[2J\x1b]0;pwned\x07",
]


def make_case(tmp_path, name="c") -> CaseStore:
    return CaseStore.create(tmp_path / name, name, "tester")


# ---------------------------------------------------------------------------- archive bombs


def test_zip_bomb_is_stopped_by_the_member_budget(tmp_path):
    zp = tmp_path / "bomb.zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("bomb.bin", bytes(40 * 1024 * 1024))          # ~40 KB on disk, 40 MB inflated
        z.writestr("after.txt", "never reached")
    assert zp.stat().st_size < 100_000
    s = make_case(tmp_path)
    r = ingest_source(s, zp, budget=ExtractionBudget(max_member_bytes=5 * 1024 * 1024))
    assert not r.complete
    assert s.scalar("SELECT COUNT(*) FROM scan_issues WHERE issue_type='budget_exceeded'") == 1
    stored = sum(p.stat().st_size for p in (tmp_path / "c" / "evidence").rglob("*") if p.is_file())
    assert stored <= 6 * 1024 * 1024, "a bomb must not be written out in full"


def test_tar_gz_bomb_is_stopped_by_the_total_budget(tmp_path):
    tp = tmp_path / "bomb.tar.gz"
    with tarfile.open(tp, "w:gz") as t:
        for i in range(10):
            data = bytes(4 * 1024 * 1024)
            ti = tarfile.TarInfo(f"f{i}.bin")
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    s = make_case(tmp_path)
    r = ingest_source(s, tp, budget=ExtractionBudget(max_total_bytes=10 * 1024 * 1024))
    assert not r.complete and r.files < 10


def test_zip_with_a_million_empty_names_hits_the_entry_limit(tmp_path):
    zp = tmp_path / "many.zip"
    with zipfile.ZipFile(zp, "w") as z:
        for i in range(2000):
            z.writestr(f"d/{i}", "")
    s = make_case(tmp_path)
    r = ingest_source(s, zp, budget=ExtractionBudget(max_entries=500))
    assert not r.complete and r.files == 500


def test_hostile_member_names_never_escape_the_case(tmp_path):
    names = ["../../etc/cron.d/x", "..\\..\\windows\\x", "/abs/path", "C:\\boot.ini", "a/./b/../../../c", "nul\x00name", "ok/file.txt",
             "a" * 5000, "dir//double//slash"]
    zp = tmp_path / "names.zip"
    with zipfile.ZipFile(zp, "w") as z:
        for n in names:
            try:
                z.writestr(n, "x")
            except (ValueError, OSError):
                pass
    s = make_case(tmp_path)
    ingest_source(s, zp)
    stored = [r["path"] for r in s.q("SELECT path FROM evidence_files")]
    assert all(".." not in p.split("/") and not p.startswith("/") and "\\" not in p and "\x00" not in p for p in stored)
    assert not any(p.name in ("x", "boot.ini") and tmp_path not in p.parents for p in tmp_path.parent.rglob("x"))
    escaped = [p for p in tmp_path.rglob("*") if p.is_file() and "evidence" not in p.parts and "c" not in p.parts and p != zp]
    assert escaped == []


# ---------------------------------------------------------------------------- hostile SQLite


def _hostile_db(path: Path, script: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.executescript(script)
    c.commit()
    c.close()
    return path


def test_session_refuses_everything_but_reading(tmp_path):
    db = _hostile_db(tmp_path / "e.db", "CREATE TABLE t(a); INSERT INTO t VALUES(1);")
    with SQLiteSession(db, None, tmp_path / "scratch") as s:
        for stmt in ("INSERT INTO t VALUES(2)", "DELETE FROM t", "DROP TABLE t", "CREATE TABLE u(b)", "ATTACH DATABASE ':memory:' AS x",
                     "PRAGMA writable_schema=1", "SELECT load_extension('x')", "SELECT writefile('/tmp/x','y')", "VACUUM"):
            with pytest.raises(sqlite3.DatabaseError):
                s.conn.execute(stmt)
        assert s.conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1


def test_malicious_view_and_trigger_cannot_run_unsafe_functions(tmp_path):
    db = _hostile_db(tmp_path / "e.db", """
        CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT);
        INSERT INTO sms VALUES(1,'+12025550123',1709280000000,1,'hi');
        CREATE VIEW v AS SELECT load_extension('/tmp/evil') FROM sms;
        CREATE TRIGGER trg AFTER INSERT ON sms BEGIN SELECT writefile('/tmp/pwned','x'); END;
    """)
    with SQLiteSession(db, None, tmp_path / "scratch") as s:
        assert s.conn.execute("SELECT COUNT(*) FROM sms").fetchone()[0] == 1
        with pytest.raises(sqlite3.DatabaseError):
            s.conn.execute("SELECT * FROM v").fetchall()
    assert not Path("/tmp/pwned").exists()


def test_runaway_query_is_aborted_by_the_deadline(tmp_path):
    db = _hostile_db(tmp_path / "e.db", "CREATE TABLE t(a); INSERT INTO t VALUES(1);")
    with SQLiteSession(db, None, tmp_path / "scratch", statement_seconds=0.5) as s:
        s.arm()
        with pytest.raises(sqlite3.DatabaseError, match="interrupted"):
            s.conn.execute("WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT COUNT(*) FROM r").fetchone()


def test_hostile_identifiers_do_not_inject_sql_into_the_case_database(tmp_path):
    ev = tmp_path / "ev"
    _hostile_db(ev / TEL / "mmssms.db", """
        CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT);
        INSERT INTO sms VALUES(1,'+12025550123',1709280000000,1,'ok');
        CREATE TABLE "x""); DROP TABLE artifacts;--"(a INTEGER, "b""c" TEXT);
        INSERT INTO "x""); DROP TABLE artifacts;--" VALUES(1, 'v');
    """)
    s = make_case(tmp_path)
    ingest_source(s, ev)
    run_pipeline(s, names=list(FULL_PIPELINE_NAMES))
    assert s.scalar("SELECT COUNT(*) FROM artifacts WHERE artifact_type='sms'") == 1
    assert s.scalar("SELECT COUNT(*) FROM sqlite_master WHERE name='artifacts'") == 1


# ---------------------------------------------------------------------------- injection into output


def _xss_case(tmp_path):
    ev = tmp_path / "ev"
    rows = [(i + 1, "+1202555" + f"{i:04d}", 1709280000000 + i, 1, payload) for i, payload in enumerate(XSS)]
    _hostile_db(ev / TEL / "mmssms.db",
                "CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT);")
    c = sqlite3.connect(ev / TEL / "mmssms.db")
    c.executemany("INSERT INTO sms VALUES(?,?,?,?,?)", rows)
    c.commit()
    c.close()
    # hostile file and package names too
    (ev / "data/data/com.evil.<script>alert(1)</script>/databases").mkdir(parents=True)
    (ev / "data/data/com.evil.<script>alert(1)</script>/databases/x.txt").write_text("<img src=x onerror=1>")
    (ev / "data/data/com.example.app/files").mkdir(parents=True)
    (ev / 'data/data/com.example.app/files/"><svg onload=alert(1)>.json').write_text("{}")
    s = make_case(tmp_path)
    ingest_source(s, ev)
    run_pipeline(s, names=list(FULL_PIPELINE_NAMES))
    return s


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_report_html_never_contains_live_markup_from_evidence(tmp_path):
    s = _xss_case(tmp_path)
    res = generate_report(s, ["html", "json", "csv"], tmp_path / "rep")
    html = res.html.read_text(encoding="utf-8")
    parsed = _Tags()
    parsed.feed(html)
    tags = [t for t, _ in parsed.tags]
    # structural check: evidence must not have produced any element, event handler, javascript: URL or injected heading
    template = Path(generate_report.__globals__["__file__"]).parent / "templates" / "report.html.j2"
    assert "img" not in tags and "svg" not in tags and "iframe" not in tags
    assert tags.count("script") == template.read_text().count("<script")   # only the report's own script, none from evidence
    handler = re.compile(r"^ftab\(this,'t-[a-z_]+'\)$")   # the template's one filter-box handler, with a code-generated table id
    for _tag, attrs in parsed.tags:
        for name, value in attrs.items():
            if name.startswith("on"):
                assert name == "oninput" and handler.match(value or ""), f"event handler not from the template: {(name, value)}"
            assert not (value or "").lower().lstrip().startswith("javascript:")
    assert "pwn" not in [h for _, h in re.findall(r"<(h1)[^>]*>([^<]*)</h1>", html)]
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html          # shown to the examiner, but inert
    assert "49" not in re.findall(r"\{\{7\*7\}\}|\b49\b", html)      # template syntax in evidence is data, not code
    # the machine-readable outputs keep the raw evidence faithfully
    assert "<script>alert(1)</script>" in res.json.read_text()


def test_csv_formula_injection_is_neutralised(tmp_path):
    ev = tmp_path / "ev"
    _hostile_db(ev / TEL / "mmssms.db", "CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT);")
    c = sqlite3.connect(ev / TEL / "mmssms.db")
    c.executemany("INSERT INTO sms VALUES(?,?,?,?,?)", [(1, "+12025550123", 1709280000000, 1, "=HYPERLINK(\"http://evil\",\"x\")"),
                                                          (2, "+12025550123", 1709280001000, 1, "@SUM(1+1)"), (3, "+12025550123", 1709280002000, 1, "+cmd|' /C calc'!A0")])
    c.commit()
    c.close()
    s = make_case(tmp_path)
    ingest_source(s, ev)
    run_pipeline(s, names=list(FULL_PIPELINE_NAMES))
    res = generate_report(s, ["csv"], tmp_path / "rep")
    import csv
    with open(res.csv_dir / "artifacts.csv", newline="", encoding="utf-8-sig") as fh:
        cells = [c for row in csv.reader(fh) for c in row]
    dangerous = [c for c in cells if c and c[0] in "=@\t\r" or (c and c[0] in "+-" and not re.match(r"^[+-]?[\d\s().\-]+$", c))]
    assert dangerous == []


def test_terminal_escape_sequences_in_evidence_names_do_not_reach_the_terminal(tmp_path):
    ev = tmp_path / "ev"
    d = ev / "data/data/com.example.app/files"
    d.mkdir(parents=True)
    (d / "evil\x1b[2J\x1b]0;pwned\x07name.txt").write_text("x")
    cases = tmp_path / "cases"
    runner = CliRunner()
    r = runner.invoke(app, ["analyze", str(ev), "--cases-dir", str(cases), "--name", "t", "--no-report"], catch_exceptions=False)
    r2 = runner.invoke(app, ["discover", str(ev), "--files"], catch_exceptions=False)
    r3 = runner.invoke(app, ["info", "t", "--cases-dir", str(cases)], catch_exceptions=False)
    for out in (r.stdout, r2.stdout, r3.stdout):
        assert "\x1b]0;" not in out and "\x1b[2J" not in out and "\x07" not in out


def _strip_calls(src: str, names: tuple[str, ...]) -> str:
    """Remove balanced ``esc(...)`` / ``pill(...)`` calls: what is inside them is escaped by construction."""
    out, i = [], 0
    pattern = re.compile(r"\b(?:" + "|".join(names) + r")\(")
    while i < len(src):
        m = pattern.search(src, i)
        if not m:
            out.append(src[i:])
            break
        out.append(src[i:m.start()])
        depth, k = 1, m.end()
        quote = None
        while k < len(src) and depth:
            ch = src[k]
            if quote:
                if ch == "\\":
                    k += 1
                elif ch == quote:
                    quote = None
            elif ch in "\"'`":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            k += 1
        out.append("ESCAPED")
        i = k
    return "".join(out)


def test_dashboard_frontend_escapes_every_evidence_derived_value():
    """Static guard on the single-page app: values from the API reach markup only through esc()/pill()."""
    from android_forensics.dashboard.api import WEB_DIR
    js = (WEB_DIR / "app.js").read_text()
    html = (WEB_DIR / "index.html").read_text()
    assert "<script>" not in html and "onclick=" not in html and "style=" not in html, "no inline script/handlers: CSP stays strict"
    bare = _strip_calls(js, ("esc", "pill"))
    risky = []
    for m in re.finditer(r"\$\{([^}]*)\}", bare):
        expr = m.group(1).strip()
        if re.search(r"\b(?:r|x|e|d|s|g|c|v|t|rec|f|a)\.[A-Za-z_]", expr) and not (
            "toUpperCase" in expr or expr.startswith(("f.type", "f.status", "state.")) or ".length" in expr
        ):
            risky.append(expr)
    # tolerated: error text assembled from the HTTP status (escaped where it is finally rendered) and textContent assignments
    safe = {
        "r.status", "await r.text()",                                        # error text; escaped where finally rendered
        "s.case.name", "s.case.id.slice(0, 8)", 's.case.layout || "not scanned"',  # assigned with textContent, never parsed as HTML
        "d.total.toLocaleString()", "t.total.toLocaleString()",              # numbers
    }
    risky = [e for e in risky if e not in safe and not e.startswith(("table(", "["))]
    assert risky == [], f"unescaped interpolations in app.js: {risky}"
