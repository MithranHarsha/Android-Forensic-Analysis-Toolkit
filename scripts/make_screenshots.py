"""Regenerate docs/images/*.png from the real UI running against the synthetic lab (needs: pip install ".[e2e]" && playwright install chromium).

    python scripts/make_screenshots.py
"""

from __future__ import annotations

import shutil
import tempfile
import threading
import time
from pathlib import Path

import uvicorn
from playwright.sync_api import sync_playwright

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.lab.synth import SynthSpec, generate
from android_forensics.pipeline.runner import FULL_PIPELINE_NAMES, run_pipeline
from android_forensics.server import ServerSettings, create_server_app
from android_forensics.server.auth import hash_token, new_token
from android_forensics.server.db import ServerDB
from android_forensics.storage.case_store import CaseStore

OUT = Path(__file__).resolve().parents[1] / "docs" / "images"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        generate(td / "ev", SynthSpec())
        settings = ServerSettings(cases_dir=td / "cases", data_dir=td / "data", workers=1, allowed_hosts=("127.0.0.1", "localhost"))
        token = new_token()
        db = ServerDB(settings.db_path)
        db.add_token("examiner", "admin", hash_token(token))
        settings.cases_dir.mkdir(parents=True)
        store = CaseStore.create(settings.cases_dir / "demo-case", "demo-case", "Dr. Jane Doe", "Synthetic Android lab (deterministic, with genuine deletions)")
        ingest_source(store, td / "ev" / "android_dump")
        run_pipeline(store, names=list(FULL_PIPELINE_NAMES))
        store.close()
        db.add_case("demo-case", "demo-case", "Synthetic Android lab", "Dr. Jane Doe", "examiner")
        server = uvicorn.Server(uvicorn.Config(create_server_app(settings), host="127.0.0.1", port=0, log_level="error"))
        threading.Thread(target=server.run, daemon=True).start()
        while not server.started:
            time.sleep(0.1)
        url = f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 760})
            page.goto(url)
            page.screenshot(path=OUT / "login.png")
            page.fill("#token", token)
            page.click("#login button[type=submit]")
            page.wait_for_selector("a[data-case]")
            page.screenshot(path=OUT / "cases.png")
            page.click("a[data-case]")
            page.wait_for_selector("nav button[data-tab=summary]")
            for tab, wait in (("summary", "table"), ("artifacts", "table tbody tr"), ("recovery", ".card"), ("carved", "table"), ("validation", "table")):
                page.click(f"nav button[data-tab={tab}]")
                page.wait_for_selector(f"nav button.active[data-tab={tab}]")
                page.wait_for_selector(wait)
                page.wait_for_timeout(500)
                page.screenshot(path=OUT / f"{tab}.png")
            browser.close()
        server.should_exit = True
    print("wrote", sorted(p.name for p in OUT.glob("*.png")))


if __name__ == "__main__":
    main()
