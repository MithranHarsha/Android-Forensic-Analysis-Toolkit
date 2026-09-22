# The synthetic evidence labs (Phase 13)

Two generators build evidence with **physical, tool-independent ground truth** — never a prediction of what the recovery
engine ought to find, always a fact about what bytes the file actually contains.

## The full Android dump — `lab/synth.py`

`generate(out_dir, SynthSpec(...))` builds a complete Android acquisition (SMS, call log with WAL-only rows, contacts,
Chromium history, a generic notes app, an encrypted-looking blob, a truncated database, a hot rollback journal) and writes
`ground_truth.json` beside it. This is what every Review 1 test's `synth` fixture calls, and what
`android-forensics synth` writes to `synthetic_evidence/` (the copy checked into this repository).

**`SynthSpec.with_deletions`** (default `False` for the test fixture; `True` for the CLI and this repo's checked-in copy)
genuinely deletes a known set of rows from the two databases opened in plain rollback-journal mode — `mmssms.db` (the `sms`
table) and Chromium's `History` (`urls`, `visits`, `downloads`) — *after* they are built, then computes ground truth for
each deleted row the same way `lab/deletions.py` does (see below): re-encode it exactly as SQLite would write it
(`sqlite.records.encode_table_leaf_cell`), and search the final file bytes. `ground_truth.json`'s `files.*.deleted` /
`.deleted_urls` / `.deleted_visits` / `.deleted_downloads` list, for every deleted row, its table, rowid, the values it
held, and whether it is physically `RECOVERED`, `PARTIAL` or `UNRECOVERABLE` — independent of what any recovery run finds.
`expected.deleted_rows` and `expected.deleted_rows_by_class` summarise the same facts.

`calllog.db` (WAL mode; already exercises the WAL-history condition) and `contacts2.db` (three tables joined; already
exercises the application-level `deleted=1` soft-delete flag) are left undisturbed — D-031 records why.

`tests/integration/test_synthetic_recovery_lab.py` runs the full `recover → carve → correlate → reconstruct` pipeline over
this dump and checks the result against `ground_truth.json` directly: every `RECOVERED` row must come back `RECOVERED`
under its own rowid, every `PARTIAL` row must come back as a `PARTIAL` row of that table, and no `UNRECOVERABLE` row may
ever be reported as recovered. On the seed checked into this repo, recall over the physically recoverable rows is 100%
(31/31).

## The single-table recovery matrix — `lab/deletions.py`

A `DeletionCase` builds one SMS-shaped table under one of twelve conditions (`plain`, `vacuum`, `secure_delete`,
`auto_vacuum`, three journal modes, four WAL conditions, `update`) crossed with database size, deletion count, position and
record size — `lab/deletions.CONDITIONS` / `standard_matrix()`. This is the finer-grained lab Phase 4 used to reach and
document 507/511 measured recall (`docs/sqlite_recovery.md` §6); `tests/integration/test_recovery_matrix.py` runs it.

Both labs derive ground truth the same way, so a result from either is directly comparable: **RECOVERED** if the row's
whole cell (rowid included) is still in the file; **PARTIAL** if only the bytes after its first four are (SQLite's
freeblock header overwrote the payload size and rowid when the cell was freed); **UNRECOVERABLE** otherwise. "Deleted" and
"recoverable" are never conflated — the matrix's own bad-data test proves this by construction (`vacuum` and heavy
`overwrite` conditions produce genuinely `UNRECOVERABLE` rows, which the engine is checked *not* to report).
