"""File classification by content signature first, name second.

Extensions are hints only: Chrome's ``History`` database has no extension, and an
attacker-renamed ``.jpg`` can hold a SQLite file. Encrypted databases (SQLCipher,
app-level encryption) are *flagged*, never decrypted.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from android_forensics.config import PRESERVE_TEXT_MAX_BYTES
from android_forensics.models.enums import FileKind

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGICS = (b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83")
JOURNAL_MAGIC = bytes.fromhex("d9d505f920a163d7")
ABX_MAGIC = b"ABX\x00"

_DB_EXTS = (".db", ".sqlite", ".sqlite3", ".db3", ".sqlitedb", ".sdb")
_CRYPT_RE = re.compile(r"\.(crypt\d*|enc|encrypted|sqlcipher)$", re.I)
_LOG_DIRS = frozenset({"logs", "log", "logcat", "anr", "tombstones", "dropbox", "crash", "crashes"})
_LOG_NAME = re.compile(r"(\.log(\.(\d+|old|bak|txt))?$)|^(logcat|dmesg|last_kmsg|tombstone_\d+|anr_)", re.I)
_HEIF_BRANDS = frozenset({b"heic", b"heix", b"heim", b"heis", b"mif1", b"msf1", b"avif"})
_AUDIO_BRANDS = frozenset({b"M4A ", b"M4B ", b"M4P "})
_MEDIA_EXT = {
    FileKind.IMAGE: (".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp"),
    FileKind.VIDEO: (".mp4", ".3gp", ".mkv", ".mov", ".webm"),
    FileKind.AUDIO: (".mp3", ".m4a", ".aac", ".ogg", ".amr", ".wav", ".opus"),
}
ENTROPY_ENCRYPTED_THRESHOLD = 7.2


@dataclass(frozen=True)
class Classification:
    kind: FileKind
    detail: str = ""


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _is_db_name(lower: str) -> bool:
    return lower.endswith(_DB_EXTS) or bool(_CRYPT_RE.search(lower))


def _is_log(rel_path: str, lower_name: str) -> bool:
    """Log by name (``*.log``, ``logcat``, ``tombstone_00``…) or by living in a log-type directory (anr, tombstones, logs…)."""
    if _LOG_NAME.search(lower_name):
        return True
    return any(part in _LOG_DIRS for part in rel_path.lower().split("/")[:-1])


def _looks_text(head: bytes) -> bool:
    """Valid UTF-8 (a multi-byte character cut by the sample boundary is tolerated) that is almost entirely printable."""
    sample = head[:2048]
    if not sample or b"\x00" in sample:
        return False
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(sample) - 3:
            return False
        text = sample[: exc.start].decode("utf-8")
    if not text:
        return False
    return sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r") / len(text) > 0.93


def classify(rel_path: str, head: bytes, size: int) -> Classification:
    name = rel_path.rsplit("/", 1)[-1]
    lower = name.lower()

    if head.startswith(SQLITE_MAGIC):
        return Classification(FileKind.SQLITE_DB, "SQLite header magic present")

    if lower.endswith("-wal"):
        if size == 0:
            return Classification(FileKind.SQLITE_WAL, "empty WAL (checkpointed/truncated)")
        ok = head[:4] in WAL_MAGICS
        return Classification(
            FileKind.SQLITE_WAL, "WAL magic valid" if ok else "WAL magic MISMATCH (corrupt or overwritten)"
        )
    if lower.endswith("-shm"):
        return Classification(FileKind.SQLITE_SHM, "wal-index shared memory file")
    if lower.endswith("-journal"):
        if size == 0:
            return Classification(FileKind.SQLITE_JOURNAL, "empty journal")
        ok = head[:8] == JOURNAL_MAGIC
        return Classification(
            FileKind.SQLITE_JOURNAL,
            "journal magic valid" if ok else "journal header not standard (zeroed/PERSIST mode or corrupt)",
        )

    if head[:4] in WAL_MAGICS:
        return Classification(FileKind.SQLITE_WAL, "WAL magic present under non-standard name")
    if head[:8] == JOURNAL_MAGIC:
        return Classification(FileKind.SQLITE_JOURNAL, "journal magic present under non-standard name")

    if size == 0:
        if _is_db_name(lower):
            return Classification(FileKind.DB_UNRECOGNISED, "zero-length file with a database name (empty or wiped)")
        return Classification(FileKind.EMPTY, "zero-length file")

    if head.startswith(ABX_MAGIC):
        return Classification(FileKind.XML_BINARY, "Android Binary XML (ABX); not parsed in Review 1")

    if head[:3] == b"\xff\xd8\xff" or head[:8] == b"\x89PNG\r\n\x1a\n" or head[:4] == b"GIF8" or (
        head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    ) or head[:4] in (b"II*\x00", b"MM\x00*"):
        return Classification(FileKind.IMAGE, "image signature")
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in _HEIF_BRANDS:
            return Classification(FileKind.IMAGE, f"HEIF/AVIF image (ISO base media brand {brand.decode('latin-1')!r})")
        if brand in _AUDIO_BRANDS:
            return Classification(FileKind.AUDIO, f"MPEG-4 audio (brand {brand.decode('latin-1')!r})")
        return Classification(FileKind.VIDEO, "ISO base media (mp4/3gp/mov)")
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return Classification(FileKind.AUDIO, "WAV audio")
    if head[:4] == b"RIFF" and head[8:12] == b"AVI ":
        return Classification(FileKind.VIDEO, "AVI video")
    if head[:4] == b"\x1a\x45\xdf\xa3":
        return Classification(FileKind.VIDEO, "Matroska/WebM video")
    if head[:4] in (b"OggS", b"fLaC") or head[:3] == b"ID3" or head[:6] == b"#!AMR\n":
        return Classification(FileKind.AUDIO, "audio signature")
    if head[:4] == b"PK\x03\x04":
        if lower.endswith(".apk"):
            return Classification(FileKind.APK, "APK (zip) signature")
        return Classification(FileKind.ARCHIVE, "zip container")

    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped.startswith(b"<?xml") or (lower.endswith(".xml") and stripped.startswith(b"<")):
        return Classification(FileKind.XML, "text XML")
    if lower.endswith(".json") and stripped[:1] in (b"{", b"["):
        return Classification(FileKind.JSON, "JSON document")

    if _is_db_name(lower):
        if len(head) >= 1024 and shannon_entropy(head) >= ENTROPY_ENCRYPTED_THRESHOLD:
            return Classification(
                FileKind.ENCRYPTED_SUSPECT,
                f"database-like name without SQLite header; high entropy "
                f"({shannon_entropy(head):.2f} bits/byte) — likely encrypted, not attempted",
            )
        return Classification(
            FileKind.DB_UNRECOGNISED,
            "database-like name but no SQLite header (corrupt, overwritten or unsupported format)",
        )

    if _looks_text(head):
        if lower.endswith(".xml"):
            return Classification(FileKind.XML, "XML by extension")
        if _is_log(rel_path, lower):
            return Classification(FileKind.LOG, "log file (by name or log-type directory; not parsed)")
        return Classification(FileKind.TEXT, "printable text")

    for kind, exts in _MEDIA_EXT.items():
        if lower.endswith(exts):
            return Classification(kind, "media by extension only (no matching signature)")

    return Classification(FileKind.UNKNOWN, "unrecognised content")


def classify_unreadable(rel_path: str, reason: str) -> Classification:
    """Best effort for a file whose content could not be read: by name only, and said so."""
    lower = rel_path.rsplit("/", 1)[-1].lower()
    note = f"unreadable ({reason}); classified by name only"
    if lower.endswith("-wal"):
        return Classification(FileKind.SQLITE_WAL, note)
    if lower.endswith("-shm"):
        return Classification(FileKind.SQLITE_SHM, note)
    if lower.endswith("-journal"):
        return Classification(FileKind.SQLITE_JOURNAL, note)
    if _is_db_name(lower):
        return Classification(FileKind.DB_UNRECOGNISED, note)
    return Classification(FileKind.UNKNOWN, f"unreadable ({reason}); content not classified")


def should_preserve(c: Classification, size: int) -> bool:
    """Which files get a write-protected working copy in the case evidence store."""
    if c.kind in (
        FileKind.SQLITE_DB,
        FileKind.SQLITE_WAL,
        FileKind.SQLITE_SHM,
        FileKind.SQLITE_JOURNAL,
        FileKind.DB_UNRECOGNISED,
    ):
        return True
    if c.kind in (FileKind.XML, FileKind.XML_BINARY, FileKind.JSON, FileKind.TEXT, FileKind.LOG):
        return size <= PRESERVE_TEXT_MAX_BYTES
    return False
