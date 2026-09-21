# SQLite inspection

`SQLiteInspector` answers, for one SQLite database: **what is in it as SQLite itself presents it, and what does the file say
about itself?** It validates the header, reports page size and version information, enumerates tables, columns, primary keys,
indexes and foreign keys, reads every active record, detects the WAL / SHM / journal files beside it, and records the
database's metadata — and it returns all of that as one structured, typed result, not as a bare `SELECT *`.

**Scope.** This is *normal* inspection: the "active view". A row that was deleted is simply absent, exactly as it is from an
ordinary query. The inspector does not look for deleted rows, freelist pages, free blocks or superseded WAL frames; that
page-level work is Review 2 ([sqlite_recovery.md](sqlite_recovery.md)).

```python
from android_forensics.sqlite.inspector import SQLiteInspector

r = SQLiteInspector.inspect("mmssms.db")                    # -> DatabaseInspection (never raises for a damaged file)
r.file.sha256, r.header.page_size, r.version.last_writer_version, r.status
for table in r.tables:
    table.name, table.primary_key, [i.name for i in table.indexes], table.row_count
    for rec in table.records:                                # active rows, in rowid order
        rec.rowid, rec.values, rec.storage_classes           # each value exactly as stored
r.sidecars, r.engine.view_includes_wal, r.integrity.status

SQLiteInspector.inspect(p, include_records=False)            # schema, metadata and row counts only
SQLiteInspector.inspect(p, max_records_per_table=1000, tables=("sms",))
for rec in SQLiteInspector.iter_records(p, "sms"):           # stream a table too big to hold in memory
    ...
```

```bash
android-forensics inspect ./mmssms.db                        # metadata, sidecars, tables, first 3 rows of each
android-forensics inspect ./mmssms.db --json                 # everything, as JSON (DatabaseInspection)
android-forensics inspect ./mmssms.db --table sms --rows 20 --no-sidecars
```

## What each requirement maps to

| Requirement | Where it is in the result |
|---|---|
| 1. Validate the SQLite header | `header` (`SQLiteHeader`: `valid`, `fatal`, `warnings`), `status` + `status_detail` (`VALID`, `TRUNCATED`, `CORRUPT_HEADER`, `NOT_SQLITE`, `ENCRYPTED_SUSPECT`, `EMPTY`, `UNREADABLE`), `size` (declared vs actual size) |
| 2. Page size | `header.page_size`, cross-checked by `engine.pragmas["page_size"]` |
| 3. Version information | `version`: `last_writer_version` (e.g. `3.39.4`) with `last_writer_version_reliable`, `write_format` / `read_format` (rollback journal / WAL), `schema_format` and `schema_format_min_version`, `inspecting_library_version` |
| 4. Tables | `tables[]` (`TableInspection`): `kind` (table / virtual / shadow), `internal`, `sql`, `root_page`, `without_rowid`, `strict`, `autoincrement`, `row_count`; views and triggers are in `schema_entries` |
| 5. Columns | `tables[].columns[]`: `cid`, `name`, `declared_type`, `affinity`, `not_null`, `default`, `hidden` (generated / hidden virtual-table columns) |
| 6. Primary keys | `tables[].primary_key` (in key order), `columns[].primary_key_position`, `rowid_alias` (the `INTEGER PRIMARY KEY` column, which *is* the rowid) |
| 7. Indexes | `tables[].indexes[]`: `unique`, `origin` (`c` CREATE INDEX · `u` UNIQUE · `pk` PRIMARY KEY), `partial`, key `columns` (with direction, collation; expressions have no name), `sql`, `root_page`; also `tables[].foreign_keys[]` |
| 8. Active records | `tables[].records[]` (`ActiveRecord`) |
| 9. Database metadata | `file` (path, size, SHA-256, mtime), `header`, `version`, `engine` (open status, library version, engine pragmas, view notes), `integrity`, `notes`, `issues` |
| 10. WAL / SHM / journal | `sidecars[]`: `kind`, `path`, `size`, `sha256`, `header_valid`, header facts (`wal` / `shm` / `journal`), `applied` |

`schema_entries` is `sqlite_master` verbatim (every table, index, view and trigger with its `CREATE` text, root page and rowid),
so nothing about the schema is lost to interpretation.

## Records keep their context

An `ActiveRecord` is `{state: "ACTIVE", table, rowid, ordinal, values, undecodable_text}`. The database path and hash are on the
enclosing `DatabaseInspection`; `DatabaseInspection.iter_records()` flattens the result into provenance-complete dictionaries
(`database`, `sha256`, `table`, `rowid`, `ordinal`, `values` by column name) for export.

* **Values are exactly what is stored, never coerced.** SQLite is dynamically typed: a column *declares* an affinity, but each value
  has its own **storage class** (`null`, `integer`, `real`, `text`, `blob`). `record.storage_classes` gives it; an `INTEGER`
  column that holds `'abc'` shows `text`, a `DATETIME` column holding `1709280000` shows `integer`, and `'2024-03-01 08:00:00'`
  shows `text`. (Affinity conversions happen when SQLite *stores* a value; the record shows the result.) Timestamps are not
  interpreted here — that is the artifact layer's job.
* **NULL** is `None`; it is distinct from `''`, `0` and an empty BLOB.
* **BLOBs** are `BlobValue(length, sha256, hex_head, hex)`: length, SHA-256 and the first 32 bytes always; the complete bytes when
  at most `blob_inline_limit` (default 256). The digest binds the summary to the evidence.
* **REAL** `+Inf` / `-Inf` are kept as `SpecialFloat` so JSON cannot lose them (SQLite itself turns NaN into NULL).
* **TEXT that is not valid UTF-8** is returned with a lossy decoding **and** the original bytes in `undecodable_text[column]` (hex),
  counted in `engine.decode_errors`, and raised as an `undecodable_text` issue. Nothing is silently altered.
* **Row identity.** `rowid` is the real rowid, even if a column is *named* `rowid` (then `oid` / `_rowid_` reach it; if all three
  are taken it is `None` and a `rowid_unavailable` issue says so). `WITHOUT ROWID` tables have `rowid = None` (their identity
  is the primary key). Rows come in rowid order (primary-key order for `WITHOUT ROWID` tables).
* Hidden virtual-table columns are described but are not part of a row; generated columns are.
* Round-trip: the whole result survives `model_dump_json()` → `model_validate_json()` unchanged.

## The active view, WAL and journals

The rows are what SQLite returns when it opens the database *together with its sidecars*: committed WAL frames are included and
a hot rollback journal is rolled back — the same view the phone's own SQLite would give. `apply_sidecars=False` reads the main
file alone (the sidecars are still detected and described, with `applied = False`).

* **`engine.wal_frames_valid`** is SQLite's own count of WAL frames it validated (read from the wal-index it maintains for the
  working copy), and `engine.view_includes_wal` follows from it. This is deliberately not derived from the header: SQLite opens
  a `-wal` that exists whatever the header's journal-mode bytes say, and validates its frames itself. A WAL from another
  database, valid in itself, sitting beside a rollback-mode database is applied — and made the file unopenable in the test that
  demonstrates it — which is why `apply_sidecars=False` always remains available.
* A rollback journal with a valid header is noted as applied ("if it was hot, SQLite rolled it back").
* **Integrity.** `PRAGMA integrity_check` on the working copy: `ok`, `failed` (also when SQLite has to abort the check on a
  malformed file), `not_run`, or **`partial`**. Android supplies collations (`LOCALIZED`, `PHONEBOOK`, `UNICODE`, `LOCALE`)
  that SQLite lacks; this tool substitutes a plain comparison so such tables and indexes can be read, but a *healthy* phone
  database then fails `integrity_check` with "row N missing from index X". When every message concerns such indexes and
  `PRAGMA quick_check` confirms the b-tree structure, the result is `partial` with a caveat naming them — never `ok`, never a
  failure. Any other message keeps it `failed`, so real damage is not excused.

## How the evidence stays untouched

The database and its sidecars are opened through the read-only opener (`O_RDONLY`, no symlink following, `O_NOATIME` where
allowed), copied once into a private scratch directory, and SQLite only ever opens that copy. Even a "read-only" SQLite
connection can create `-shm` files, replay a WAL or roll back a hot journal; those effects land on the copy, which is deleted
afterwards (also after a failed open). The SHA-256 in `file.sha256` is computed *as the copy is made*, so it names the exact
bytes SQLite was given. A `scratch_dir` inside the evidence directory is refused. The tests hash the evidence directory before and
after (sizes, mtimes, contents, the set of files) for plain, WAL, hot-journal, truncated, encrypted and empty inputs.

A symlink named explicitly on the command line is followed (its target is reported); a symlinked *sidecar* is not
(`sidecar_symlink_skipped`).

## Damaged, encrypted and non-SQLite files

`inspect()` raises `InspectionError` only for a missing path, a directory, a non-regular file, an unsafe scratch directory, or a
SQLite library older than 3.26. Everything else is described:

| Input | Result |
|---|---|
| Truncated | `status = TRUNCATED` with header, size check and hash; opened if SQLite will |
| Valid header, destroyed schema page | `status = VALID` (bytes are sound) but `engine.open_status = unopenable`; no tables; `database_unopenable` issue |
| A page destroyed mid-table | rows before it are kept, `records_truncated`, `read_error` on the table, `integrity = failed` |
| Encrypted-looking | `ENCRYPTED_SUSPECT`; never opened |
| Empty, text, zeros, a WAL/journal handed in as the database | `EMPTY` / `NOT_SQLITE`; header facts and hash still reported |
| Bad header fields | `CORRUPT_HEADER` with the reasons |
| Unreadable (permissions) | `UNREADABLE`, `engine.open_status = unreadable` |
| A database that never had a table (only a pragma set) | `VALID`, with a note: both text-encoding and schema-format header fields are 0 until the first schema is written |
| Virtual table whose module is missing | that table gets `read_error`; the rest is inspected |

The byte-level `status` uses exactly the rules of the filesystem scanner ([filesystem_discovery.md](filesystem_discovery.md)), and
`engine.open_status` is what SQLite itself did — two separate facts.

## Options

`include_records` · `max_records_per_table` (row counts stay exact; `records_truncated` says rows were left out) · `tables`
(records only from these; the schema is always complete) · `blob_inline_limit` · `apply_sidecars` · `integrity_check` ·
`hash_files` · `sidecars` (explicit `{"-wal": path, …}`; `{}` means none) · `scratch_dir`. Unknown option names are a `TypeError`.

## In the case pipeline and the report

The `scan` stage runs every preserved database (with its preserved sidecars) through the inspector and stores: the header and size
facts, `version_json` and `engine_json` on `databases`, the sidecar facts, `view_includes_wal` (SQLite's own verdict; `NULL` where
nothing was opened), `integrity_status` (`VALID` / `PARTIAL` / `INVALID`), and on `db_tables` — one row per `sqlite_master`
entry — `details_json`: each table's full schema (keys, indexes, foreign keys, flags) and each index's definition. Records are
not stored there; extraction reads them table by table through the artifact parsers. The report's database table shows the
last-writing SQLite version and valid WAL frames, and its table catalogue shows primary keys, indexes and foreign keys.

## Measured

Time is measured without tracing and peak Python memory in a separate `tracemalloc` pass; SQLite 3.53.3, macOS, one table of six mixed columns
(`experiments/r1_inspection.py`, results in `experiments/results/`).

| Rows | Streaming `iter_records` | Full `inspect()` (all records in memory) | Schema only |
|---|---|---|---|
| 10,000 | 0.06 s · 176 k rows/s · 1.8 MiB | 0.07 s · 138 k rows/s · 21 MiB | < 0.01 s |
| 100,000 | 0.55 s · 181 k rows/s · 2.0 MiB | 0.82 s · 122 k rows/s · 214 MiB | 0.01 s |
| 250,000 | 1.37 s · 182 k rows/s · 2.0 MiB | not measured | 0.03 s |

Streaming is flat in memory; the full result costs about 2 KiB per row of typed, validated values, so use `iter_records` or
`max_records_per_table` beyond ~100,000 rows.

**Fidelity fuzz.** 300 randomly generated databases (739 tables, 55,740 active rows, 329,930 cells; random declared types, all five
storage classes, NULLs, blobs, extreme numbers, and 16,779 rows deleted along the way) were compared cell by cell with an
independent `sqlite3` query — value, Python type, `typeof()` storage class and rowid: **0 mismatches**. None of the 16,779 deleted
rows' unique tokens appears anywhere in any result (**0 leaks**). This shows the inspector adds nothing and loses nothing; it says
nothing about real-world coverage of app schemas.

## Limitations

* **Active view only.** No deleted, superseded or unallocated data (Review 2).
* **The whole database is copied** to the scratch directory (disk space ≈ database + WAL). `inspect()` holds every requested record
  in memory; stream or cap large tables.
* **Android collations are approximated** (see *Integrity*). Ordering-dependent behaviour of such indexes is not reproduced; rows are
  always read in rowid order. A collation an *app* registers at run time (anything beyond SQLite's built-ins and the four above) is
  unavailable, and a read that needs it fails with a recorded error.
* **Virtual tables** return what their module returns and need that module compiled into the local SQLite (FTS5, R-Tree usually are);
  their shadow tables are only recognised as such with SQLite ≥ 3.37 (`PRAGMA table_list`) — with older ones they read as ordinary
  tables. `WITHOUT ROWID` / `STRICT` fall back to reading the `CREATE` text.
* **UTF-16 databases** are decoded by SQLite; the original UTF-16 bytes of a value are not kept.
* **The last-writer version is an indicator.** It is reliable only when the header's version-valid-for number equals the change
  counter, and an app's bundled SQLite can differ from the system's.
* **Timestamps and content are not interpreted.** Values are returned as stored; normalisation is the artifact layer's job.
* Inspecting requires SQLite ≥ 3.26.

## Tests

`tests/unit/test_inspection_models.py` (values, blobs, affinity rules, version decoding, model invariants, JSON round-trips),
`test_sqlite_inspector_schema.py` (header, page sizes 512–65536, encodings, versions, tables, columns, primary keys, indexes,
foreign keys, generated / STRICT / virtual / WITHOUT ROWID tables, the `table_list` fallback), `test_sqlite_inspector_records.py`
(multiple tables cross-checked against an independent query, every data type, NULLs, timestamps in every format, deleted rows
asserted absent, options, undecodable text, streaming), `test_sqlite_inspector_files.py` (WAL / SHM / hot journal, damaged and
non-SQLite files, the read-only guarantee, the collation caveat, agreement with the scanner, the pipeline's reader and the
synthetic lab's ground truth), and `tests/integration/test_inspection_stage.py` and `test_inspect_cli.py`.
