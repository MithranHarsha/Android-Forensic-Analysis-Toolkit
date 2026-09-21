"""Builders for the SQLite inspection tests: small generated databases of every shape the inspector must handle."""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

from android_forensics.lab.journal import build_hot_journal


def build(path: Path, script: str) -> Path:
    """Create a database at ``path`` by running ``script`` (several statements) and closing cleanly."""
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.executescript(script)
    c.commit()
    c.close()
    return path


def numbered_db(path: Path, rows: int = 200, page_size: int = 4096) -> Path:
    """One table ``t(id INTEGER PRIMARY KEY, v TEXT)`` with ``rows`` rows of 100 characters each."""
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.execute(f"PRAGMA page_size={page_size}")
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t(v) VALUES(?)", [(f"row {i:05d} " + "x" * 90,) for i in range(rows)])
    c.commit()
    c.close()
    return path


def wal_snapshot(dest: Path, name: str = "w.db", in_main: int = 5, only_in_wal: int = 3) -> Path:
    """A WAL-mode database as found on a phone: ``in_main`` rows checkpointed into the main file and ``only_in_wal`` rows
    that exist only in the ``-wal`` (files copied while the writer is still connected, so nothing is checkpointed on close)."""
    dest.mkdir(parents=True, exist_ok=True)
    src = dest / f"_src_{name}"
    w = sqlite3.connect(src)
    w.execute("PRAGMA journal_mode=WAL")
    w.execute("PRAGMA wal_autocheckpoint=0")
    w.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    w.executemany("INSERT INTO t(v) VALUES(?)", [(f"main-{i}",) for i in range(in_main)])
    w.commit()
    w.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    w.executemany("INSERT INTO t(v) VALUES(?)", [(f"wal-{i}",) for i in range(only_in_wal)])
    w.commit()
    for suffix in ("", "-wal", "-shm"):
        shutil.copyfile(f"{src}{suffix}", dest / f"{name}{suffix}")
    w.close()
    for suffix in ("", "-wal", "-shm"):
        Path(f"{src}{suffix}").unlink(missing_ok=True)
    return dest / name


def hot_journal_snapshot(dest: Path, name: str = "p.db", rows: int = 4000) -> Path:
    """A database frozen mid-transaction: the file as an interrupted UPDATE left it plus the rollback journal holding the
    original of every page it changed. Opening the pair rolls the transaction back, so every row reads ``row…`` — none
    starts with ``X``. Built from the journal format, so it does not depend on how SQLite happens to spill its cache."""
    dest.mkdir(parents=True, exist_ok=True)
    before, after = dest / f"_before_{name}", dest / f"_after_{name}"
    c = sqlite3.connect(before)
    c.execute("CREATE TABLE q(a TEXT)")
    c.executemany("INSERT INTO q VALUES(?)", [(f"row{i:05d}-" + "p" * 120,) for i in range(rows)])
    c.commit()
    c.close()
    shutil.copyfile(before, after)
    c = sqlite3.connect(after)
    c.execute("UPDATE q SET a = 'X' || a")
    c.commit()
    c.close()
    build_hot_journal(before, after, dest / name, dest / f"{name}-journal")
    before.unlink()
    after.unlink()
    return dest / name


def corrupt_middle_leaf(path: Path, page_size: int = 1024, leaf_type: int = 0x0D) -> None:
    """Overwrite one leaf page from the middle of the file with 0xFF (never a valid b-tree page type), so the rows
    before it stay readable and reading the damaged page fails every time. ``leaf_type``: 0x0D table leaf, 0x0A index leaf."""
    data = bytearray(path.read_bytes())
    leaves = [i for i in range(2, len(data) // page_size) if data[i * page_size] == leaf_type]
    victim = leaves[len(leaves) // 2]
    data[victim * page_size:(victim + 1) * page_size] = b"\xff" * page_size
    path.write_bytes(bytes(data))


def fts5_available() -> bool:
    c = sqlite3.connect(":memory:")
    try:
        c.execute("CREATE VIRTUAL TABLE x USING fts5(a)")
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        c.close()


def collated_db(path: Path, key=lambda name: name.lower(), reverse: bool = False, rows: int = 320, page_size: int = 4096) -> Path:
    """A healthy database whose ``idx_name`` index orders keys by a ``LOCALIZED`` collation the way a phone would (here:
    case-insensitively, optionally reversed) — which differs from the plain comparison this tool substitutes."""
    def collation(a: str, b: str) -> int:
        ka, kb = key(a), key(b)
        return ((ka > kb) - (ka < kb)) * (-1 if reverse else 1)

    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.create_collation("LOCALIZED", collation)
    c.execute(f"PRAGMA page_size={page_size}")
    c.execute("CREATE TABLE contacts(id INTEGER PRIMARY KEY, name TEXT COLLATE LOCALIZED, note TEXT)")
    c.execute("CREATE INDEX idx_name ON contacts(name COLLATE LOCALIZED)")
    names = ["alice", "Bob", "carol", "Dave", "eve", "Frank", "grace", "Heidi"]
    c.executemany("INSERT INTO contacts(name, note) VALUES(?, ?)", [(names[i % 8] + str(i), "n" * 60) for i in range(rows)])
    c.commit()
    assert c.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "fixture: healthy on the phone's own collation"
    c.close()
    return path
