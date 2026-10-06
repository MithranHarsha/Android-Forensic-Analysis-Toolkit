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

*(Updated for release 0.3.)* The suite is 1,644 tests, all passing (two are skipped on this platform: one on file systems that reject non-UTF-8 names, such as APFS, and the Linux-only memory-limit test; the browser end-to-end test needs Playwright). Line
coverage of `src/android_forensics` (`coverage run -m pytest && coverage report`, config in `.coveragerc`) is **94.0%**
(13,517 statements, 810 missed); the full per-file report is `docs/coverage.txt`. Review 1 (evidence integrity through
reporting) and Review 2 (recovery, carving, correlation, confidence, the dashboard, PDF reports, the synthetic labs) are
both exercised: 239 unit tests of the data models, 27 of the ingestion building blocks, 61 end-to-end ingestion tests,
367 of the SQLite inspection engine, 232 of filesystem discovery, ~150 of the page-level recovery engine and WAL/journal
parsing (`test_sqlite_recovery_units.py`, `test_sqlite_wal_journal.py`, `test_recovery_matrix.py`), ~60 of raw carving
(the planted-string fixture plus the SQLite free-space carver), 35 of the correlation graph, 22 of the confidence scorer,
storage round-trips and the recovery pipeline stages, the FastAPI dashboard (`TestClient` against a real recovered case),
the report in every format (HTML/JSON/CSV/PDF, with and without recovery having run) and the full synthetic lab
(100% recall over the physically recoverable rows it plants). The lowest-covered modules are error branches that need a
specific, hard-to-provoke I/O failure (`readonly.py`, `acquisition/archive.py`, `acquisition/single_file.py`) and CLI
argument-parsing edges; nothing forensic-critical (a status transition, a confidence rule, a byte-offset calculation) is
below its module's own average.

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

## Review 2 evaluation (Phase 15)

Reproduce with `python experiments/r2_recovery.py` (≈4 min: the matrix is quick; the confidence/timing experiment runs the
full synthetic lab three times) then `python experiments/r2_charts.py`. Raw results: `experiments/results/r2_e6_recovery_matrix.csv`,
`r2_e7_confidence_calibration.csv`, `r2_summary.json`; charts: `r2_recall_by_condition.png`, `r2_status_breakdown.png`,
`r2_confidence_calibration.png`. Environment of the reported run: Python 3.12.13, SQLite 3.53.3, macOS (arm64).

### E6 — recovery matrix

The standard deletion matrix (`lab.deletions.standard_matrix`: 12 conditions plus position / record-size / page-size /
overwrite variants — 28 cases) run through the page-level recovery engine and scored against each case's physical ground
truth (`lab.evaluation.score_case`).

| | |
|---|---:|
| Cases | 28 |
| Physically recoverable rows (RECOVERED or PARTIAL by construction) | 511 |
| Matched | 507 |
| **Overall recall** | **99.22%** |
| False positives (any case) | 0 |
| **Overall false-positive rate** | **0.0%** |
| RECOVERED (whole cell) | 146 |
| PARTIAL (freeblock header overwrote the first bytes) | 361 |
| Missed | 4 |

Every case reaches 100% precision and recall except three, all previously documented layout limits
(`docs/sqlite_recovery.md` §7): `plain_ps1024` (75%), `plain_ps2048` (78%) — a neighbouring cell's own head is also
destroyed at these page sizes, so a freed cell's end cannot be confirmed — and `overwrite_50` (92%), where half the freed
space was reused before recovery ran. See `r2_recall_by_condition.png` for the full per-condition bar chart and
`r2_status_breakdown.png` for the RECOVERED/PARTIAL/missed split.

### E7 — confidence calibration and processing cost

The full synthetic lab (`lab.synth`, genuine deletions, three seeds) run through `recover → carve → correlate →
reconstruct`; every reconstructed RECOVERED/PARTIAL artifact is checked against the planted deleted row it corresponds to
(`lab.evaluation.matches`, by value — a PARTIAL row has lost its rowid, so it cannot be matched by rowid) and grouped by
its confidence level.

| Confidence | n | Share matching the real deleted values |
|---|---:|---:|
| HIGH | 29 | 100% |
| MEDIUM | 64 | 100% |
| LOW | 0 | — |

No LOW-confidence recovered artifact appeared in this lab (every recovered row in it either had a schema match and exact
structure, or was excluded before reconstruction); HIGH and MEDIUM are both perfectly calibrated on this run — see
`r2_confidence_calibration.png`. This is a small, synthetic sample and a stronger calibration claim would need many more
runs and real-world evidence; it is reported as what was measured, not extrapolated.

Processing cost, averaged over the three seeds (full Android dump: 120 SMS, 60 calls, 30 contacts, 152 browser visits,
notes, misc files):

| Stage | Seconds |
|---|---:|
| scan | 0.03 |
| extract | 0.13 |
| recover | 40.6 |
| carve | 1.4 |
| correlate | 5.2 |
| reconstruct | 11.9 |
| validate | 0.2 |
| timeline | 0.02 |
| **Total (incl. ingest)** | **≈59.6** |
| Peak Python memory | ≈147 MB |

`recover` dominates: it scans every page of every database for byte sequences that parse as a record, which is
inherently more work than a single indexed `SELECT`. `carve` is comparatively cheap because it excludes everything
`recover` already accounted for (live cells, structure, and rows already reported).

### Threats to validity (Review 2)

* **Confidence calibration's sample is small and synthetic.** 93 data points from one synthetic lab across three seeds is
  enough to show the mechanism works as designed (higher levels are not wrong more often), not enough to claim a
  precise, generalisable calibration curve.
* **The recovery matrix isolates one table.** E6 uses the same SMS-shaped table as `lab/deletions.py`'s proof of the
  engine's core logic; E7's full-dump lab is what exercises multiple real schemas (SMS, Chromium `urls`/`visits`/
  `downloads`) together, but only two of its databases carry genuine deletions (D-031).
* **Single machine, single SQLite build.** Page-level byte layouts are governed by the SQLite library that wrote the
  file; a different version could, in principle, lay out freeblocks slightly differently. The physical-ground-truth
  method does not depend on this, but the *measured* recall numbers are for this environment's SQLite 3.53.3.
