"""A hot rollback journal — an interrupted write transaction — built deterministically from SQLite's documented file format.

A phone frozen after SQLite changed the database file but before ``COMMIT`` leaves two files: the changed database, and a
rollback journal holding the *original* of every page that changed. The next time SQLite opens the pair it rolls the
database back. Provoking SQLite into leaving that state by shrinking its page cache is not reproducible — whether the
cache spills (and so whether the journal header is ever written) depends on other connections in the process — so the
pair is constructed directly from the format (https://www.sqlite.org/fileformat2.html#the_rollback_journal) and then
proved hot by asking SQLite to roll it back.
"""

from __future__ import annotations

import shutil
import sqlite3
import struct
import tempfile
from pathlib import Path

JOURNAL_MAGIC = bytes.fromhex("d9d505f920a163d7")
SECTOR_SIZE = 512
_NONCE = 0x5EED1234  # arbitrary: it only seeds each page record's checksum


def _checksum(page: bytes, nonce: int) -> int:
    """SQLite's sparse page checksum: the nonce plus every 200th byte, counting back from 200 bytes before the page's end."""
    total = nonce
    i = len(page) - 200
    while i > 0:
        total += page[i]
        i -= 200
    return total & 0xFFFFFFFF


def build_hot_journal(before: Path, after: Path, database_out: Path, journal_out: Path) -> int:
    """Write the pair a crashed phone would leave: ``after`` (the database as the interrupted transaction left it) and a
    rollback journal holding ``before``'s version of every page that differs. SQLite restores ``before`` when it opens them.

    Returns the number of journalled pages. Raises ``RuntimeError`` if SQLite does not treat the pair as a hot journal."""
    old, new = before.read_bytes(), after.read_bytes()
    (raw,) = struct.unpack(">H", old[16:18])
    page_size = 65536 if raw == 1 else raw
    pages_before = len(old) // page_size
    changed = [
        (n, old[(n - 1) * page_size : n * page_size])
        for n in range(1, pages_before + 1)
        if old[(n - 1) * page_size : n * page_size] != new[(n - 1) * page_size : n * page_size]
    ]
    if not changed:
        raise ValueError("the two database files are identical: there is no transaction to interrupt")
    header = JOURNAL_MAGIC + struct.pack(">5I", len(changed), _NONCE, pages_before, SECTOR_SIZE, page_size)
    records = b"".join(struct.pack(">I", n) + page + struct.pack(">I", _checksum(page, _NONCE)) for n, page in changed)
    database_out.write_bytes(new)
    journal_out.write_bytes(header.ljust(SECTOR_SIZE, b"\0") + records)
    _prove_hot(database_out, journal_out, expected=old)
    return len(changed)


def _prove_hot(database: Path, journal: Path, expected: bytes) -> None:
    """Open copies of the pair with SQLite: a hot journal is rolled back, restoring the original bytes and being deleted."""
    with tempfile.TemporaryDirectory(prefix="hotjournal_") as tmp:
        work = Path(tmp) / "v.db"
        shutil.copyfile(database, work)
        shutil.copyfile(journal, Path(f"{work}-journal"))
        conn = sqlite3.connect(work)
        try:
            conn.execute("SELECT count(*) FROM sqlite_master").fetchall()
        finally:
            conn.close()
        if work.read_bytes() != expected or Path(f"{work}-journal").exists():
            raise RuntimeError("the constructed journal is not hot: SQLite did not roll the database back to its original state")
