"""Build a standalone single-file executable with PyInstaller:  python packaging/build_binary.py"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "android_forensics"
SEP = ";" if sys.platform == "win32" else ":"


def main() -> int:
    cmd = [
        sys.executable, "-m", "PyInstaller", "--onefile", "--clean", "--noconfirm",
        "--name", "android-forensics",
        "--paths", str(ROOT / "src"),
        "--add-data", f"{PKG / 'reporting' / 'templates'}{SEP}android_forensics/reporting/templates",
        "--add-data", f"{PKG / 'dashboard' / 'web'}{SEP}android_forensics/dashboard/web",
        "--collect-submodules", "android_forensics",
        "--collect-submodules", "uvicorn",          # uvicorn imports its loops/protocols by name at runtime
        "--collect-submodules", "cryptography",
        "--collect-data", "fpdf",
        "--hidden-import", "multipart",
        str(PKG / "__main__.py"),
    ]
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
