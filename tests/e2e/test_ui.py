"""Drive the real browser UI against a live server: sign in, create a case, upload evidence, run the job, browse the results,
download a signed report — and confirm hostile evidence text stays inert. Skipped when Playwright/Chromium are unavailable."""

from __future__ import annotations

import sqlite3
import threading
import time

import pytest

playwright_sync = pytest.importorskip("playwright.sync_api")
import uvicorn  # noqa: E402

from android_forensics.custody import generate_keypair  # noqa: E402
from android_forensics.server import ServerSettings, create_server_app  # noqa: E402
from android_forensics.server.auth import hash_token, new_token  # noqa: E402
from android_forensics.server.db import ServerDB  # noqa: E402

PAYLOAD = '<img src=x onerror="window.__pwned=1">'


@pytest.fixture(scope="module")
def live(tmp_path_factory, synth):
    base = tmp_path_factory.mktemp("ui")
    key, _pub, _fp = generate_keypair(base / "k" / "key.pem")
    settings = ServerSettings(cases_dir=base / "cases", data_dir=base / "data", workers=1, signing_key=key,
                              allowed_hosts=("127.0.0.1", "localhost"))
    token = new_token()
    ServerDB(settings.db_path).add_token("ui-admin", "admin", hash_token(token))
    app = create_server_app(settings)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    port = server.servers[0].sockets[0].getsockname()[1]
    # an acquisition whose message text is an XSS payload, so the UI has hostile content to render
    ev = base / "ev" / "data/data/com.android.providers.telephony/databases"
    ev.mkdir(parents=True)
    c = sqlite3.connect(ev / "mmssms.db")
    c.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT)")
    c.executemany("INSERT INTO sms VALUES(?,?,?,?,?)", [(i, "+12025550123", 1709280000000 + i * 1000, 1, f"{PAYLOAD} {i}") for i in range(1, 6)])
    c.commit()
    c.close()
    import zipfile
    zp = base / "evidence.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.write(ev / "mmssms.db", "data/data/com.android.providers.telephony/databases/mmssms.db")
    yield f"http://127.0.0.1:{port}", token, zp
    server.should_exit = True
    t.join(timeout=10)


@pytest.fixture(scope="module")
def browser():
    with playwright_sync.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"chromium unavailable: {exc}")
        yield b
        b.close()


def test_full_workflow_in_the_browser(live, browser, tmp_path):
    url, token, evidence = live
    page = browser.new_page(accept_downloads=True)
    dialogs, console_errors = [], []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.goto(url)

    # --- sign-in: a wrong token is refused, the right one is accepted
    page.fill("#token", "afk_wrong")
    page.click("#login button[type=submit]")
    page.wait_for_selector("#login .err")
    page.fill("#token", token)
    page.click("#login button[type=submit]")
    page.wait_for_selector("#new-case")
    assert "ui-admin (admin)" in page.inner_text("#user-label")

    # --- create a case, upload evidence, analyse
    page.fill("#nc-id", "ui-case")
    page.fill("#nc-examiner", "Dr. UI")
    page.click("#new-case button[type=submit]")
    page.wait_for_selector("#up-file")
    page.set_input_files("#up-file", str(evidence))
    page.click("#up-go")
    page.wait_for_selector("button[data-analyze]")
    page.click("button[data-analyze]")
    page.wait_for_selector("text=succeeded", timeout=240_000)

    # --- browse results; the hostile message body is shown as text and nothing executes
    page.click("nav button[data-tab=artifacts]")
    page.wait_for_selector("#view:has-text('onerror')")   # (page.evaluate-style string evals are blocked by the CSP: that is the point)
    body = page.inner_text("#view")
    assert "onerror" in body and "<img" in body                       # visible, as literal text
    assert page.evaluate("() => window.__pwned") is None
    assert page.locator("#view img").count() == 0
    assert dialogs == []

    # --- the other tabs load without errors
    for tab in ("summary", "recovery", "carved", "correlation", "validation", "timeline", "audit"):
        page.click(f"nav button[data-tab={tab}]")
        page.wait_for_selector(f"nav button.active[data-tab={tab}]")
        page.wait_for_timeout(700)   # let the tab's fetch + render settle
        assert page.inner_text("#view").strip() and "Failed to load" not in page.inner_text("#view"), tab

    # --- reports: signed, downloadable
    page.click("nav button[data-tab=reports]")
    page.wait_for_selector("button[data-rep]")
    with page.expect_download() as dl:
        page.click("button[data-rep][data-file='report.html']")
    saved = tmp_path / "report.html"
    dl.value.save_as(saved)
    html = saved.read_text()
    assert "<!doctype html>" in html.lower() and "&lt;img src=x onerror" in html

    # --- a CSP violation (inline script) would show up as a console error
    assert not [m for m in console_errors if "Content Security Policy" in m]

    # --- sign out returns to the login form and drops the token
    page.click("#logout")
    page.wait_for_selector("#login")
    assert page.evaluate("() => sessionStorage.getItem('af_token')") is None
    page.close()
