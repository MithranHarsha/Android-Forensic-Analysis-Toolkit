"""A reproducibility stamp: exactly which build produced a result."""

from __future__ import annotations

import hashlib
import platform
import sqlite3
import subprocess  # nosec B404 - fixed argv, no shell
import sys
from functools import lru_cache
from importlib import metadata
from pathlib import Path
from typing import Any

from android_forensics import TOOL_NAME, __version__

RUNTIME_DEPENDENCIES = ("typer", "rich", "pydantic", "jinja2", "fastapi", "uvicorn", "fpdf2", "defusedxml", "cryptography")


def _dep_versions() -> dict[str, str]:
    out = {}
    for name in RUNTIME_DEPENDENCIES:
        try:
            out[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            out[name] = "not installed"
    return out


def _lock_sha256() -> str | None:
    """Hash of ``requirements.lock`` when the tool runs from a source checkout; otherwise None."""
    for parent in Path(__file__).resolve().parents[:5]:
        candidate = parent / "requirements.lock"
        if candidate.is_file():
            return hashlib.sha256(candidate.read_bytes()).hexdigest()
    return None


def _git_commit() -> str | None:
    root = Path(__file__).resolve().parents[3]
    if not (root / ".git").exists():
        return None
    try:
        r = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)  # nosec B603 B607
        return r.stdout.strip() or None if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


@lru_cache(maxsize=1)
def tool_stamp() -> dict[str, Any]:
    deps = _dep_versions()
    stamp: dict[str, Any] = {
        "tool": TOOL_NAME, "version": __version__, "python": sys.version.split()[0], "implementation": platform.python_implementation(),
        "platform": platform.platform(), "sqlite_library": sqlite3.sqlite_version, "dependencies": deps,
        "lock_sha256": _lock_sha256(), "git_commit": _git_commit(), "frozen_binary": bool(getattr(sys, "frozen", False)),
    }
    canonical = "|".join(f"{k}={stamp[k]}" for k in ("tool", "version", "python", "sqlite_library")) + "|" + \
        ",".join(f"{k}={v}" for k, v in sorted(deps.items()))
    stamp["fingerprint"] = hashlib.sha256(canonical.encode()).hexdigest()
    return stamp
