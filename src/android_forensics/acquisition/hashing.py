"""Streaming multi-hash. MD5/SHA-1 are recorded for compatibility with legacy
reference sets only; SHA-256 is the integrity anchor."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from android_forensics.config import CHUNK_SIZE
from android_forensics.readonly import open_readonly


@dataclass(frozen=True)
class Digests:
    md5: str
    sha1: str
    sha256: str
    size: int


class MultiHasher:
    def __init__(self) -> None:
        self._md5 = hashlib.md5(usedforsecurity=False)
        self._sha1 = hashlib.sha1(usedforsecurity=False)
        self._sha256 = hashlib.sha256()
        self.size = 0

    def update(self, data: bytes) -> None:
        self._md5.update(data)
        self._sha1.update(data)
        self._sha256.update(data)
        self.size += len(data)

    def digests(self) -> Digests:
        return Digests(self._md5.hexdigest(), self._sha1.hexdigest(), self._sha256.hexdigest(), self.size)


def hash_stream(src: BinaryIO, dest: BinaryIO | None = None, first_chunk: bytes = b"") -> Digests:
    """Hash ``src`` (optionally tee-ing bytes to ``dest``). ``first_chunk`` is data already read."""
    h = MultiHasher()
    if first_chunk:
        h.update(first_chunk)
        if dest is not None:
            dest.write(first_chunk)
    while True:
        chunk = src.read(CHUNK_SIZE)
        if not chunk:
            break
        h.update(chunk)
        if dest is not None:
            dest.write(chunk)
    return h.digests()


def sha256_of(path: Path) -> str:
    """SHA-256 of a file through the read-only opener (for callers that need only the integrity anchor)."""
    h = hashlib.sha256()
    with open_readonly(path) as fh:
        while chunk := fh.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def hash_file(path: Path, *, follow_symlinks: bool = False) -> Digests:
    """Hash a file through the read-only opener (refuses symlinks unless asked; avoids touching access times where possible)."""
    with open_readonly(path, follow_symlinks=follow_symlinks) as fh:
        return hash_stream(fh)
