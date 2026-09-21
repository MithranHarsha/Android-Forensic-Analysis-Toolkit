"""Deletion lab: databases with rows deleted under controlled conditions, and ground truth about what is physically recoverable.

Each ``DeletionCase`` builds one SMS-shaped database, deletes (or updates) a known set of rows under one *condition*, and
writes the files a phone would hold afterwards (the database and, where the condition leaves them, ``-wal`` / ``-journal``).

**Ground truth is physical, not predicted.** After the files exist, every deleted row is re-encoded exactly as SQLite wrote it
(``records.encode_table_leaf_cell``) and the bytes are searched for in each file:

* the whole cell is present  -> expected class ``RECOVERED`` (rowid and every field are still there);
* only the cell *after its first four bytes* is present (SQLite overwrote them with a freeblock header when it freed the cell)
  -> ``PARTIAL`` (the rowid and, sometimes, the first column are lost);
* neither -> ``UNRECOVERABLE`` from structured data. (The row's text may still survive as loose bytes that carving can find;
  ``text_present_in`` records that.)

So an expectation never depends on the recovery algorithm being evaluated.

Conditions (``DeletionCase.condition``):

``plain``              DELETE, rollback-journal mode ``DELETE`` (journal removed at commit)
``vacuum``             DELETE then VACUUM (the file is rewritten compactly)
``secure_delete``      ``PRAGMA secure_delete=ON``: freed content is overwritten with zeros
``auto_vacuum``        ``auto_vacuum=FULL``: freed pages are returned to the file system at commit
``journal_persist``    ``journal_mode=PERSIST``: the journal is kept, its header zeroed, its page images left behind
``journal_truncate``   ``journal_mode=TRUNCATE``: the journal is truncated to zero bytes
``journal_off``        ``journal_mode=OFF``: no journal at all
``wal_uncheckpointed`` WAL mode; the DELETE sits in the ``-wal`` while the main file still holds the pre-delete pages
``wal_checkpointed``   WAL mode; the DELETE is checkpointed into the main file, older frames remain in the ``-wal``
``wal_history``        WAL mode, never checkpointed: everything, including pre-delete page versions, is in the ``-wal``
``wal_stale``          WAL mode; a checkpoint restarts the log, so the DELETE lands in a new WAL generation while the previous
                       generation's frames (the pre-delete pages) linger beyond the new end, marked stale by their salts
``update``             rows are UPDATEd rather than deleted: the old versions are the "deleted" rows
"""

from __future__ import annotations

import json
import random
import shutil
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from android_forensics.sqlite.records import encode_record, encode_table_leaf_cell

CONDITIONS = (
    "plain", "vacuum", "secure_delete", "auto_vacuum", "journal_persist", "journal_truncate", "journal_off",
    "wal_uncheckpointed", "wal_checkpointed", "wal_history", "wal_stale", "update",
)
POSITIONS = ("first", "middle", "last", "random", "block", "every_other")
RECORD_SIZES = {"small": (18, 40), "medium": (90, 150), "large": (400, 900)}
BASE_MS = 1_709_280_000_000
_WORDS = "call me later see you at noon ok thanks where are you meeting is moved dinner tonight lets go home soon bring keys".split()


@dataclass(frozen=True)
class DeletionCase:
    name: str
    condition: str = "plain"
    page_size: int = 4096
    rows: int = 100
    delete: int = 25
    position: str = "middle"
    record_size: str = "small"
    overwrite: float = 0.0  # after deleting, insert this fraction of ``delete`` new rows into the freed space
    clean_base: bool = True  # build the base with secure_delete ON and VACUUM it, so b-tree split residue does not pre-date the condition
    seed: int = 7

    def __post_init__(self) -> None:
        if self.condition not in CONDITIONS:
            raise ValueError(f"unknown condition {self.condition!r}")
        if self.position not in POSITIONS:
            raise ValueError(f"unknown position {self.position!r}")
        if self.record_size not in RECORD_SIZES:
            raise ValueError(f"unknown record size {self.record_size!r}")
        if not 0 < self.delete <= self.rows:
            raise ValueError("delete must be between 1 and rows")


@dataclass
class CaseOutput:
    case: DeletionCase
    database: Path
    sidecars: dict[str, Path] = field(default_factory=dict)  # "-wal" / "-journal" -> path
    truth: dict[str, Any] = field(default_factory=dict)


def make_row(i: int, rng: random.Random, size: str) -> tuple:
    """Row ``i`` of the SMS-shaped table: (address, date, type, body, read). The body starts with a unique token."""
    low, high = RECORD_SIZES[size]
    target = rng.randint(low, high)
    body = f"Msg#{i:05d} "
    while len(body) < target:
        body += rng.choice(_WORDS) + " "
    return (f"+1202555{i:04d}", BASE_MS + i * 61_000, 1 + i % 2, body.rstrip(), i % 2)


def choose_ids(rows: int, count: int, position: str, rng: random.Random) -> list[int]:
    ids = list(range(1, rows + 1))
    if position == "first":
        return ids[:count]
    if position == "last":
        return ids[-count:]
    if position == "middle":
        start = (rows - count) // 2
        return ids[start:start + count]
    if position == "block":
        start = rng.randint(0, rows - count)
        return ids[start:start + count]
    if position == "every_other":
        return ids[1::2][:count]
    return sorted(rng.sample(ids, count))


def _row_cell(rowid: int, row: tuple) -> bytes:
    """The bytes SQLite writes for this row: the rowid alias column is NULL in the record."""
    return encode_table_leaf_cell(rowid, encode_record((None,) + row))


def build_case(dest: Path, case: DeletionCase) -> CaseOutput:
    """Build the case in ``dest/<name>/`` and return its files and physical ground truth."""
    folder = dest / case.name
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    work = folder / "_work" / "sms.db"
    work.parent.mkdir()
    rng = random.Random(case.seed)
    originals = {i: make_row(i, rng, case.record_size) for i in range(1, case.rows + 1)}
    victims = choose_ids(case.rows, case.delete, case.position, rng)

    conn = sqlite3.connect(work)
    conn.execute(f"PRAGMA page_size={case.page_size}")
    # A b-tree root that splits leaves its old leaf content behind in the (now interior) root page unless secure_delete is on,
    # so a clean base is built with secure_delete ON and the condition then runs with it OFF (or ON, for that condition).
    conn.execute(f"PRAGMA secure_delete={'ON' if case.clean_base else 'OFF'}")
    if case.condition == "auto_vacuum":
        conn.execute("PRAGMA auto_vacuum=FULL")
    if case.condition in ("wal_history", "wal_stale"):
        conn.execute("PRAGMA journal_mode=WAL")  # from the very first write
        conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT, date INTEGER, type INTEGER, body TEXT, read INTEGER)")
    conn.executemany("INSERT INTO sms VALUES(?,?,?,?,?,?)", [(i, *originals[i]) for i in originals])
    conn.commit()
    if case.clean_base and case.condition not in ("wal_history", "wal_stale"):
        conn.execute("VACUUM")  # a compact, freshly written file
        conn.commit()
    conn.execute("PRAGMA secure_delete=OFF")
    if case.condition == "wal_stale":
        conn.execute("PRAGMA wal_checkpoint(RESTART)")  # the next write starts a new WAL generation from frame 1
    if case.condition in ("wal_uncheckpointed", "wal_checkpointed"):
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
    if case.condition == "wal_uncheckpointed":
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # the main file holds every row; the delete will live only in the WAL
    if case.condition == "journal_persist":
        conn.execute("PRAGMA journal_mode=PERSIST")
    elif case.condition == "journal_truncate":
        conn.execute("PRAGMA journal_mode=TRUNCATE")
    elif case.condition == "journal_off":
        conn.execute("PRAGMA journal_mode=OFF")
    elif case.condition == "secure_delete":
        conn.execute("PRAGMA secure_delete=ON")

    lost: dict[int, tuple] = {}  # id -> the row content that was removed or replaced
    if case.condition == "update":
        for i in victims:
            lost[i] = originals[i]
            new_body = "EDITED " + originals[i][3][::-1]
            conn.execute("UPDATE sms SET body=? WHERE _id=?", (new_body, i))
    else:
        marks = ",".join(str(i) for i in victims)
        conn.execute(f"DELETE FROM sms WHERE _id IN ({marks})")
        lost = {i: originals[i] for i in victims}
    conn.commit()
    if case.condition == "wal_checkpointed":
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
    if case.condition == "vacuum":
        conn.execute("VACUUM")
        conn.commit()
    if case.overwrite > 0 and case.condition != "update":
        extra = max(1, round(case.overwrite * case.delete))
        reuse = list(victims) + [case.rows + 1 + k for k in range(extra)]  # the deleted rowids first: their new cells land in the freed space
        for j in reuse[:extra]:
            row = make_row(j, rng, case.record_size)
            conn.execute("INSERT INTO sms VALUES(?,?,?,?,?,?)", (j, row[0], row[1], row[2], "New#" + row[3][4:], row[4]))
        conn.commit()

    db = folder / "sms.db"
    sidecars: dict[str, Path] = {}
    shutil.copyfile(work, db)  # copy while the connection is open: a WAL / persistent journal is then still on disk
    for suffix in ("-wal", "-journal"):
        src = Path(f"{work}{suffix}")
        if src.exists():
            shutil.copyfile(src, folder / f"sms.db{suffix}")
            sidecars[suffix] = folder / f"sms.db{suffix}"
    final_rows = [list(r) for r in conn.execute("SELECT _id, address, date, type, body, read FROM sms ORDER BY _id")]
    conn.close()
    shutil.rmtree(folder / "_work")

    truth = physical_truth(case, db, sidecars, lost, final_rows)
    (folder / "ground_truth.json").write_text(json.dumps(truth, indent=2))
    return CaseOutput(case, db, sidecars, truth)


def physical_truth(case: DeletionCase, db: Path, sidecars: dict[str, Path], lost: dict[int, tuple], active: list[list]) -> dict[str, Any]:
    files = {"main": db.read_bytes()}
    files.update({"wal": sidecars["-wal"].read_bytes()} if "-wal" in sidecars else {})
    files.update({"journal": sidecars["-journal"].read_bytes()} if "-journal" in sidecars else {})
    rows = []
    for rowid, row in sorted(lost.items()):
        cell = _row_cell(rowid, row)
        where_cell = [name for name, data in files.items() if cell in data]
        where_tail = [name for name, data in files.items() if cell[4:] in data]
        where_text = [name for name, data in files.items() if row[3].encode() in data]
        expected = "RECOVERED" if where_cell else ("PARTIAL" if where_tail else "UNRECOVERABLE")
        rows.append({
            "id": rowid, "values": {"_id": rowid, "address": row[0], "date": row[1], "type": row[2], "body": row[3], "read": row[4]},
            "cell_intact_in": where_cell, "tail_intact_in": where_tail, "text_present_in": where_text, "expected_class": expected,
        })
    counts = {k: sum(1 for r in rows if r["expected_class"] == k) for k in ("RECOVERED", "PARTIAL", "UNRECOVERABLE")}
    return {
        "case": asdict(case), "files": {name: len(data) for name, data in files.items()},
        "deleted_rows": rows, "expected_counts": counts,
        "active_rows": [{"_id": r[0], "address": r[1], "date": r[2], "type": r[3], "body": r[4], "read": r[5]} for r in active],
        "method": "each deleted row is re-encoded as SQLite writes it and searched for in every file (see lab/deletions.py)",
    }


def standard_matrix(seed: int = 7) -> list[DeletionCase]:
    """The Phase 4D test matrix: every condition at the DoD size (100 rows, 25 deleted), plus position / size / page-size variants."""
    cases = [DeletionCase(name=c, condition=c, seed=seed) for c in CONDITIONS]
    cases += [DeletionCase(name=f"plain_{p}", condition="plain", position=p, seed=seed) for p in POSITIONS]
    cases += [DeletionCase(name=f"plain_{s}", condition="plain", record_size=s, seed=seed) for s in ("medium", "large")]
    cases += [DeletionCase(name=f"plain_ps{ps}", condition="plain", page_size=ps, seed=seed) for ps in (1024, 2048, 8192, 16384)]
    cases += [DeletionCase(name=f"overwrite_{int(f * 100)}", condition="plain", overwrite=f, seed=seed) for f in (0.5, 1.0, 2.0)]
    cases.append(DeletionCase(name="plain_residue", condition="plain", clean_base=False, seed=seed))  # split residue left by the inserts
    return cases
