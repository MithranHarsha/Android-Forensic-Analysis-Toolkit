"""Honest detection of encrypted evidence — detection only, never decryption.

Two kinds of encryption defeat a logical-file analysis, and a tool that quietly reports "0 artifacts" on such evidence is
worse than useless: the examiner must be told the evidence is not readable and why.

* **Per-database encryption (SQLCipher and similar)** — the file has no ``SQLite format 3`` header and looks like random
  bytes. Handled in the classifier / SQLite discovery (``ENCRYPTED_SUSPECT``); this module does not repeat it.
* **File-based encryption (FBE)** — Android 7+ encrypts the *names* and contents of files in credential-encrypted storage
  (``/data/data``, ``/data/user/N``, ``/data/media``). A dump taken without the keys shows directories full of
  base64-looking names such as ``Zq3vP_8nT1kXw0b7YlJc9Q``. Nothing inside can be parsed.

FBE names are the ciphertext of the real name, encoded with a URL-safe base64 alphabet (no padding), so they are at
least 22 characters, contain no dots and have high character entropy. The heuristic below is deliberately conservative: a
directory is only reported when several of its entries look this way, and the finding says "suspected".
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

_B64URL = re.compile(r"^[A-Za-z0-9_+\-]{22,}$")
MIN_ENTRIES = 3          # a directory needs at least this many FBE-looking names ...
MIN_FRACTION = 0.5       # ... making up at least this share of its entries


def _entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def looks_like_fbe_name(name: str) -> bool:
    """True for a name that resembles an FBE-encrypted file/directory name."""
    if not _B64URL.match(name) or "." in name:
        return False
    has_upper, has_lower = any(c.isupper() for c in name), any(c.islower() for c in name)
    # random ciphertext mixes cases; real identifiers (uuids, hashes) are single-case hex or dash-separated words
    if not (has_upper and has_lower):
        return False
    return _entropy(name) >= 3.8


@dataclass(frozen=True)
class EncryptedDirectory:
    path: str
    entries: int
    encrypted_looking: int
    examples: tuple[str, ...]

    @property
    def detail(self) -> str:
        return (
            f"{self.encrypted_looking} of {self.entries} entries have names that look like file-based-encryption ciphertext "
            f"(e.g. {', '.join(self.examples)}). The evidence was probably acquired without the decryption keys; the contents "
            "of this directory cannot be parsed and are NOT represented in any artifact count. This tool never decrypts."
        )


def find_fbe_directories(paths: Iterable[str]) -> list[EncryptedDirectory]:
    """Directories (by evidence-relative path) whose children are mostly FBE-looking names."""
    children: dict[str, set[str]] = defaultdict(set)
    for p in paths:
        parts = p.split("/")
        for i in range(1, len(parts)):
            children["/".join(parts[:i - 1])].add(parts[i - 1])
        children["/".join(parts[:-1])].add(parts[-1])
    found: list[EncryptedDirectory] = []
    for directory, names in children.items():
        ciphertext = sorted(n for n in names if looks_like_fbe_name(n))
        if len(ciphertext) >= MIN_ENTRIES and len(ciphertext) / len(names) >= MIN_FRACTION:
            found.append(EncryptedDirectory(directory or ".", len(names), len(ciphertext), tuple(ciphertext[:3])))
    # report only the outermost affected directories
    found.sort(key=lambda d: d.path)
    outer: list[EncryptedDirectory] = []
    for d in found:
        if not any(d.path.startswith(o.path.rstrip("/") + "/") for o in outer if o.path != "."):
            outer.append(d)
    return outer[:50]
