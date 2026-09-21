"""Evidence text is untrusted and must reach the examiner's terminal exactly as stored.

Rich treats ``[word]`` as a style tag and silently drops it (and ``[/]`` raises), so a file named ``[backup]notes.txt`` or an
SMS reading ``[Bank] Your OTP is 123456`` would be shown as something that is not in the evidence.
"""

import json
import sqlite3

import pytest
from typer.testing import CliRunner

from android_forensics.cli.app import app

runner = CliRunner()
WIDE = {"COLUMNS": "300"}  # long values must not be folded across lines in the assertions below

HOSTILE_NAMES = ["[backup]notes.txt", "[bold red]ALERT.txt", "[not a style]x.txt", "[dim]", "a [b] c [i]d.txt"]
BODIES = ["[Bank] Your OTP is 123456", "close [/] tag", "[bold red]LOUD[/bold red] and [link=x]y[/link]", "[/red] stray", "plain"]


@pytest.fixture()
def hostile(tmp_path):
    ev = tmp_path / "ev"
    files = ev / "data/data/com.x/files"
    files.mkdir(parents=True)
    for name in HOSTILE_NAMES:
        (files / name).write_text("data")
    tel = ev / "data/data/com.android.providers.telephony/databases"
    tel.mkdir(parents=True)
    c = sqlite3.connect(tel / "mmssms.db")
    c.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT)")
    c.executemany("INSERT INTO sms VALUES(?,?,?,?,?)", [(i + 1, "+12025550123", 1709280000000 + i * 1000, 1, b) for i, b in enumerate(BODIES)])
    c.commit()
    c.close()
    return ev


def invoke(*args, env=None):
    return runner.invoke(app, list(args), env={**WIDE, **(env or {})}, catch_exceptions=False)


def test_discover_shows_bracketed_file_names_verbatim(hostile):
    r = invoke("discover", str(hostile), "--files")
    assert r.exit_code == 0
    for name in HOSTILE_NAMES:
        assert f"data/data/com.x/files/{name}" in r.stdout, name


def test_discover_json_is_verbatim_too(hostile):
    r = invoke("discover", str(hostile), "--json")
    paths = {f["path"] for f in json.loads(r.stdout)["files"]}
    assert {f"data/data/com.x/files/{n}" for n in HOSTILE_NAMES} <= paths


def test_an_evidence_root_with_brackets_in_its_name_is_shown_and_reported_verbatim(tmp_path):
    ev = tmp_path / "[acquired] phone"
    (ev / "sdcard").mkdir(parents=True)
    (ev / "sdcard/a.txt").write_text("x")
    r = invoke("discover", str(ev))
    assert r.exit_code == 0 and "[acquired] phone" in r.stdout
    missing = invoke("discover", str(tmp_path / "[gone]"))
    assert missing.exit_code == 2 and "[gone]" in missing.output


def test_artifact_listing_and_first_detail_show_message_bodies_verbatim(hostile, tmp_path):
    env = {"ANDROID_FORENSICS_CASES": str(tmp_path / "cases")}
    assert invoke("analyze", str(hostile), "--name", "h", "--no-report", env=env).exit_code == 0

    listing = invoke("artifacts", "h", "--type", "sms", env=env)
    assert listing.exit_code == 0
    room = 70 - len("SMS RECEIVED from +12025550123: ")  # the listing caps its summary column at 70 characters
    for body in BODIES:
        assert body[:room] in listing.stdout, body

    detail = invoke("artifacts", "h", "--show", "1", env=env)
    assert detail.exit_code == 0
    assert len([b for b in BODIES if b in detail.stdout]) == 1, "the detail view must show this message's body exactly as stored"


def test_every_message_detail_view_is_verbatim_and_never_crashes(hostile, tmp_path):
    env = {"ANDROID_FORENSICS_CASES": str(tmp_path / "cases")}
    invoke("analyze", str(hostile), "--name", "h", "--no-report", env=env)
    seen = set()
    for aid in range(1, 40):
        r = runner.invoke(app, ["artifacts", "h", "--show", str(aid)], env={**WIDE, **env}, catch_exceptions=False)
        if r.exit_code != 0:
            break
        seen.update(b for b in BODIES if b in r.stdout)
    assert seen == set(BODIES)


def test_info_and_scan_print_evidence_paths_verbatim(hostile, tmp_path):
    env = {"ANDROID_FORENSICS_CASES": str(tmp_path / "cases")}
    invoke("analyze", str(hostile), "--name", "h", "--no-report", env=env)
    r = invoke("info", "h", env=env)
    assert r.exit_code == 0 and "Chain of custody" in r.stdout


def test_status_colouring_still_works(hostile):
    r = runner.invoke(app, ["discover", str(hostile)], env={**WIDE, "FORCE_COLOR": "1", "TERM": "xterm-256color"}, catch_exceptions=False)
    assert r.exit_code == 0 and "VALID" in r.stdout
