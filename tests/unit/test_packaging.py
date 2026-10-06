from __future__ import annotations

import tomllib
from pathlib import Path

import android_forensics
from android_forensics.dashboard import api

ROOT = Path(__file__).resolve().parents[2]


def test_version_matches_pyproject():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert android_forensics.__version__ == meta["project"]["version"]


def test_dashboard_frontend_ships_inside_the_package():
    assert api.WEB_DIR.is_dir()
    assert (api.WEB_DIR / "index.html").is_file()
    assert api.WEB_DIR.is_relative_to(Path(android_forensics.__file__).parent)


def test_package_data_declared():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())
    data = meta["tool"]["setuptools"]["package-data"]["android_forensics"]
    assert "dashboard/web/*" in data
    assert "reporting/templates/*.j2" in data
