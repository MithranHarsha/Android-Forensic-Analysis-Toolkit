# Evaluation

Every number below was produced by running the code in this repository; none is estimated or hard-coded.
They were re-measured after the typed data-model migration (`docs/data_models.md`).
Reproduce with `python experiments/r1_extraction_accuracy.py` (≈ 65 s). Raw results:
`experiments/results/r1_e1_extraction_accuracy.csv`, `r1_e2_scaling.csv`, `r1_summary.json`.

Environment of the reported run: Python 3.12.13, SQLite 3.53.3, macOS (arm64).

## Method

The synthetic generator (`lab/synth.py`) writes AOSP-schema databases (SMS, call log with WAL-only rows, contacts2, Chromium
History, an unknown app DB with a hot rollback journal, an encrypted-looking blob, a truncated database) and records the
ground truth it wrote. `lab/ground_truth.py` derives the *expected* normalised values (UTC timestamps, direction names,
flags, phone keys) with its own arithmetic, independent of the tool's converters, and compares them field by field with
what the tool extracted, matching on `(database, table, rowid)`.

* **Expected** = ground-truth records; **extracted** = ACTIVE artifacts of that type from that database;
  **correct** = extracted records whose every compared field equals the expectation.
* Precision = correct / extracted, recall = correct / expected, F1 = harmonic mean.

## E1 — active-extraction accuracy

15 datasets = 5 seeds × 3 sizes (SMS/calls/contacts = 20/10/10, 120/60/30, 500/250/80; browser visits scale with SMS).

| Artifact | Expected | Extracted | Correct | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| SMS | 3,200 | 3,200 | 3,200 | 1.000 | 1.000 | 1.000 |
| Call log (incl. WAL-only rows) | 1,600 | 1,600 | 1,600 | 1.000 | 1.000 | 1.000 |
| Contacts (incl. marked-deleted) | 600 | 600 | 600 | 1.000 | 1.000 | 1.000 |
| Browser visits (incl. URL-only rows) | 3,735 | 3,735 | 3,735 | 1.000 | 1.000 | 1.000 |
| Browser downloads | 75 | 75 | 75 | 1.000 | 1.000 | 1.000 |
| **Total** | **9,210** | **9,210** | **9,210** | **1.000** | **1.000** | **1.000** |

0 field mismatches. Whole-pipeline time (ingest → scan → extract → validate → timeline) averaged 0.055 s, 0.077 s and
0.169 s for the three sizes.

*An instructive bug the experiment caught:* the first E1 run reported precision 0.79–0.99 on small datasets. The extra
records were URL rows with no visit rows, which the browser parser (correctly, by design) emits as URL-level records; the
generator's ground truth had listed only the two deliberate orphans. The ground truth was fixed, not the tool.

## E2 — scaling

SMS table of N rows, `extract` stage. Time and memory are measured in **separate runs**: `tracemalloc` slows allocation-heavy
code several-fold, so timing with it enabled (as an earlier version of this experiment did, reporting ≈ 7 k rows/s) understates
throughput.

| SMS rows | DB size | Time (s) | Rows / s | Peak Python memory |
|---:|---:|---:|---:|---:|
| 1,000 | 0.1 MiB | 0.06 | 16,949 | 6.2 MiB |
| 10,000 | 1.0 MiB | 0.57 | 17,452 | 6.3 MiB |
| 50,000 | 4.9 MiB | 2.85 | 17,519 | 6.3 MiB |
| 100,000 | 9.8 MiB | 5.90 | 16,941 | 6.3 MiB |
| 250,000 | 24.7 MiB | 15.62 | 16,004 | 6.3 MiB |

Linear time and flat memory: rows are streamed from SQLite and written in batches of 1,000. Peak memory is ≈ 2 MiB higher than
before the model migration because each artifact is now a validated model with provenance and a raw-row digest. (`tracemalloc`
counts Python allocations, not SQLite's page cache or the process RSS.)

## E3 — ingestion throughput

301 MiB of incompressible data (3 × 100 MiB files + 3,000 small files) ingested with `ingest_evidence`, hashing MD5 + SHA-1 +
SHA-256 in one pass (`experiments/results/r1_e3_ingestion.csv`):

| Input | Files | Time (s) | MiB/s |
|---|---:|---:|---:|
| directory | 3,003 | 0.79 | 381 |
| directory, copy every file into the working directory | 3,003 | 1.09 | 276 |
| zip (stored) | 3,003 | 1.30 | 232 |
| tar | 3,003 | 1.28 | 236 |
| *reference: SHA-256 alone (hashlib)* | — | 0.10 | 3,080 |

The three-hash pass, per-file overhead and (for archives) member streaming dominate; ingestion is single-threaded.

## E4 — SQLite inspection throughput and memory

`SQLiteInspector` on one table of six mixed columns (INTEGER key, TEXT, INTEGER, REAL, BLOB, TEXT with NULLs), time without
tracing and peak Python memory in a separate `tracemalloc` pass (`experiments/r1_inspection.py`,
`experiments/results/r1_e4_inspection_scaling.csv`; SQLite 3.53.3):

| Rows | Streaming `iter_records` | Full `inspect()` (every record in memory) | Schema only (`include_records=False`) |
|---:|---|---|---|
| 1,000 | 168 k rows/s · 1.1 MiB | 142 k rows/s · 2.1 MiB | < 0.01 s |
| 10,000 | 176 k rows/s · 1.8 MiB | 138 k rows/s · 21 MiB | < 0.01 s |
| 50,000 | 178 k rows/s · 2.0 MiB | 134 k rows/s · 107 MiB | 0.01 s |
| 100,000 | 181 k rows/s · 2.0 MiB | 122 k rows/s · 214 MiB | 0.01 s |
| 250,000 | 182 k rows/s · 2.0 MiB | not measured (stream instead) | 0.03 s |

Streaming is linear in time and flat in memory. The full result costs about 2 KiB per row (typed, validated values with their storage
classes), which is why the tool offers streaming and per-table caps. Schema-only inspection is bounded by the row-count query.

## E5 — SQLite inspection fidelity (fuzz)

300 randomly generated databases (seeded; 512 / 1,024 / 4,096-byte pages; 1–4 tables each with a random declared type per column, an
`INTEGER PRIMARY KEY` (with or without `AUTOINCREMENT`) or no key at all, all five storage classes, NULLs, empty and 300-byte blobs, `Inf`, 64-bit extremes, numeric-looking text,
booleans) in which 30 % of the rows were inserted and then deleted, each carrying a token found nowhere else. Every cell of every
active row the inspector returned was compared with an independent `sqlite3` query — value, Python type, `typeof()` storage class and
rowid — and every result was searched for the deleted rows' tokens (`experiments/results/r1_e5_inspection_fidelity.csv`):

| Databases | Tables | Active rows | Cells compared | Deleted rows | Cell mismatches | Deleted tokens found in any result | `integrity_check` ok |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 300 | 739 | 55,740 | 329,930 | 16,779 | **0** | **0** | 300 |

This demonstrates that the inspector neither alters nor loses what SQLite returns, and that deleted rows are absent from normal
inspection. It says nothing about coverage of real applications' schemas.

## Other verification

The 1,054-test suite (1,053 pass; 1 is skipped on file systems that reject non-UTF-8 names, such as APFS) includes 239 unit tests of the data models, 27 of the ingestion building blocks, 61 end-to-end ingestion tests (every input type, manifest contents, read-only guarantees, change detection, verification), 367 tests of the SQLite inspection engine (85 of the typed results and helpers, 69 of header / version / schema, 124 of active records — every data type, NULLs, timestamps, deleted rows asserted absent — 62 of sidecars, damaged files, the read-only guarantee and the integrity caveat, plus 13 CLI and 14 pipeline-stage tests), 232 tests of filesystem discovery (72 of classification, 34 of the Android layout model, 48 of the analysis core, 47 scanner tests over real trees — every category, every kind of database damage, missing / unreadable / vanishing / symlinked entries — and 31 of the scan stage and CLI, including verbatim display of evidence text) and exactness checks on the default synthetic case (120 SMS, 60 calls, 30 contacts, 152 browser
visits, 5 downloads; the 20 call rows that exist only in the WAL; the hot journal rolled back on the scratch copy; the
encrypted and truncated databases flagged), tamper detection, archive attacks, corruption mid-table (rows before the damage
kept), UTF-16 databases, report escaping and the CLI.

## Threats to validity

* **Synthetic and schema-aware.** The data follow the schemas the parsers know, so E1 shows *implementation correctness*,
  not coverage of real handsets. Real devices have vendor variants, unusual pragmas, sync-adapter tables and app-specific
  encodings. Validation on real (authorised) acquisitions is the next step.
* **Small cardinality of failure modes.** Damaged-database cases are single examples, not a distribution.
* **Single machine.** Timings are indicative; the linear trend is the point.
* **Review 1 measures active data only.** Nothing here says anything about deleted-data recovery. E5's deleted rows are generated to prove
  their *absence* from normal inspection, not to measure recovery.
* **E4 uses one table shape** (six columns, short values); wide rows or large BLOBs change the per-row memory of the in-memory mode.

## Review 2 synthetic lab (Phase 13, built)

The full-dump generator and the single-table recovery matrix now both produce evidence with genuinely deleted rows and physically-derived ground truth (`docs/synthetic_lab.md`); `tests/integration/test_synthetic_recovery_lab.py` and `tests/integration/test_recovery_matrix.py` check the engine's output against it directly (100% and 507/511 measured recall respectively, on the seeds checked into this repo). The systematic measurement across the matrix's independent variables, written up as numbers and charts, is Phase 15, below.

## Review 2 evaluation plan (Phase 15)

Extend the generator with controlled deletions and overwrites, record what is recoverable by construction, and measure the
recovery engine against it. Independent variables: database size, number of deletions, record size, deletion position
(head / middle / tail of the table, last-cell vs interior), WAL enabled/disabled, journal mode, page size, auto-vacuum mode,
`secure_delete`, checkpoint state, degree of overwriting. Metrics: precision, recall, F1, false-positive rate, per-status
counts (`RECOVERED` / `PARTIAL` / `CORRUPTED` / `UNRECOVERABLE`), confidence calibration (share of `HIGH` that are correct),
processing time and memory; results as CSV/JSON with graphs. The ground truth will distinguish *recoverable by
construction* from *overwritten*, so "recovery rate" is measured against what was actually recoverable, not against everything
that was deleted.
