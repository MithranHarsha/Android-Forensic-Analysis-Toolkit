"""Regenerate tests/fixtures/*.img.gz with real mke2fs (via Docker). Not run in CI: the images are committed.

    python tests/tools/make_ext_images.py

Each image is built from a small deterministic tree so tests can compare file bytes/hashes exactly.
"""

from __future__ import annotations

import gzip
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "fixtures"


def tree(root: Path) -> None:
    """A miniature Android /data: includes a >12-block file (indirect blocks), a sparse file, an empty file, a symlink."""
    d = root / "data" / "com.example.app" / "databases"
    d.mkdir(parents=True)
    (root / "system").mkdir()
    (root / "misc").mkdir()
    (root / "app").mkdir()
    (d / "small.txt").write_text("hello android\n")
    (d / "empty.bin").write_bytes(b"")
    (root / "system" / "packages.xml").write_text("<packages><package name='com.example.app'/></packages>\n")
    big = bytes((i * 7 + 3) % 251 for i in range(300_000))
    (d / "big.bin").write_bytes(big)
    with open(d / "sparse.bin", "wb") as fh:  # a real hole in the middle
        fh.write(b"HEAD")
        fh.seek(200_000)
        fh.write(b"TAIL")
    (d / "link").symlink_to("small.txt")
    (root / "data" / "com.example.app" / "files").mkdir()
    for i in range(120):  # enough names to exercise multi-block directories
        (root / "data" / "com.example.app" / "files" / f"f{i:03d}.dat").write_bytes(bytes([i]) * (i * 13))


def build(name: str, mkfs_args: str, size_mb: int, populate=tree) -> None:
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "src"
        src.mkdir()
        populate(src)
        script = (f"set -e; apk add --no-cache e2fsprogs >/dev/null; cd /w; "
                  f"mke2fs -q {mkfs_args} -d /w/src -L userdata -E root_owner=0:0 /w/out.img {size_mb}M")
        subprocess.run(["docker", "run", "--rm", "-v", f"{td}:/w", "alpine:3.20", "sh", "-c", script], check=True)
        raw = (Path(td) / "out.img").read_bytes()
        FIXTURES.mkdir(exist_ok=True)
        with gzip.GzipFile(FIXTURES / f"{name}.img.gz", "wb", mtime=0) as fh:
            fh.write(raw)
        print(name, len(raw), hashlib.sha256(raw).hexdigest())


def android_userdata(root: Path) -> None:
    """The synthetic lab's /data (genuine deletions included), so the image can be compared with the directory dump."""
    sys.path.insert(0, str(HERE.parents[1] / "src"))
    from android_forensics.lab.synth import SynthSpec, generate

    with tempfile.TemporaryDirectory() as td:
        generate(Path(td), SynthSpec())
        shutil.copytree(Path(td) / "android_dump" / "data", root, dirs_exist_ok=True)


if __name__ == "__main__":
    if not shutil.which("docker"):
        sys.exit("docker is required to regenerate the fixtures")
    build("ext4_4k_extents", "-t ext4 -b 4096", 4)
    build("ext2_1k_blockmap", "-t ext2 -b 1024", 6)
    build("android_userdata_ext4", "-t ext4 -b 4096", 12, populate=android_userdata)
