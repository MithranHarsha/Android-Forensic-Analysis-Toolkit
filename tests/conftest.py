from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.lab.synth import SynthSpec, generate
from android_forensics.pipeline.runner import run_pipeline
from android_forensics.storage.case_store import CaseStore


def tree_hash(root: Path) -> str:
    """Hash every file's relative path, size, mtime and content: proves a tree was not modified."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            st = p.stat()
            h.update(f"{p.relative_to(root)}|{st.st_size}|{st.st_mtime_ns}".encode())
            h.update(p.read_bytes())
    return h.hexdigest()


@pytest.fixture(scope="session")
def synth(tmp_path_factory):
    out = tmp_path_factory.mktemp("synth")
    truth = generate(out, SynthSpec())
    return out, truth


@pytest.fixture(scope="session")
def analyzed(synth, tmp_path_factory):
    """A case with the full Review 1 pipeline run once over the synthetic directory dump."""
    out, truth = synth
    before = tree_hash(out / "android_dump")
    store = CaseStore.create(tmp_path_factory.mktemp("cases") / "gt", "gt", "pytest")
    ingest_source(store, out / "android_dump")
    results = run_pipeline(store)
    return store, results, truth, before, out


@pytest.fixture()
def fresh_case(tmp_path):
    return CaseStore.create(tmp_path / "case", "unit", "pytest")


def load_truth(out: Path) -> dict:
    return json.loads((out / "ground_truth.json").read_text())
