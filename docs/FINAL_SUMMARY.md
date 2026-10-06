# Final Summary — Android Deleted Data Recovery and Evidence Reconstruction Framework

> **Historical document — the Review 2 acceptance record (v0.1/Phase 17).** It is kept exactly as written because its numbers come from
> that run. For the current state of the tool (disk images, signing, the server, real-corpus validation, performance fixes, packaging)
> see the [README](../README.md), [validation.md](validation.md), [performance.md](performance.md) and the [CHANGELOG](../CHANGELOG.md).

B.Tech Cyber Forensics Capstone. This document is written from an actual, real, end-to-end run of the tool (Phase 17
acceptance run, `cases/acceptance`, `reports/acceptance/`) executed against the synthetic evidence set committed at
`synthetic_evidence/` — not from what the pipeline is expected to do. Every number below is either the literal output of
that run, of the test suite, or of `experiments/r2_recovery.py`.

## 1. What this is

A Python forensic toolkit that takes an Android acquisition, proves the integrity of the evidence, discovers and
validates every SQLite database, extracts active artifacts, **recovers deleted and superseded SQLite records**, **carves
raw patterns** outside structured records, **correlates** evidence across sources, assigns every recovered or carved item
a **deterministic, explainable confidence level**, validates the result, builds a unified timeline, and produces a
provenance-rich forensic report (HTML/JSON/CSV/PDF) plus a read-only dashboard. Built in Python ≥3.11, no ML/LLM anywhere
in the decision path, no network calls, no cloud dependency.

## 2. What was implemented, phase by phase

| Phase | What it delivered |
|---|---|
| 0–3 | Project scaffold, typed pydantic models, evidence ingestion (dir/zip/tar/single file), filesystem discovery |
| 4A | SQLite header/version/schema parsing, normal (active-only) inspection engine |
| 4B–4D | The page-level recovery engine: `sqlite/{records,pages,ddl,recovery,recover_db,wal,journal,freelist}.py` — scans main-file pages, WAL frames and rollback-journal pages for freed/superseded cells |
| 5 | Recovered rows converted into typed artifacts through the *same* parser code active rows use (`artifacts/recovered.py`) |
| 6 | Raw carving: phone numbers, URLs, e-mails, timestamps, SMS-like text, loose SQLite-record shapes (`carving/`) |
| 7 | The correlation evidence graph and cross-source corroboration (`correlation/`) |
| 8 | The deterministic confidence scorer (`confidence/scorer.py`) |
| 9 | Migration 002/003 (recovered_records, carved_candidates, wal_frames, freelist_pages, correlations, corroboration), the `recover`/`carve`/`correlate`/`reconstruct` pipeline stages, recovery/carving integrity validation, the five-bad-data-class test |
| 10 | CLI: `analyze` runs recovery by default (`--no-recover` to opt out), standalone `recover` command, real-numbers summary panels |
| 11 | FastAPI dashboard (`dashboard/api.py`) + static frontend (`src/android_forensics/dashboard/web/index.html`) |
| 12 | Report sections 7/9/10/12 render real recovered/carved/correlated content when those stages ran; PDF format (`reporting/pdf.py`) |
| 13 | The synthetic lab gains genuine deletions with physically-derived ground truth (`lab/synth.py`, `SynthSpec.with_deletions`) |
| 14 | Full green suite, measured coverage |
| 15 | `experiments/r2_recovery.py` / `r2_charts.py` — real recovery-matrix and confidence-calibration numbers, CSV/JSON/PNG |
| 16 | README and every doc rewritten to describe what is actually built |
| 17 | This document, from a real end-to-end run |

Every decision made along the way, and why, is logged in [`docs/decisions.md`](decisions.md) (36 entries, D-001 through
D-036).

## 3. Complete project structure (real, from the filesystem)

```
.
├── README.md · LICENSE · pyproject.toml · requirements.txt · .coveragerc
├── docs/                architecture · artifact_formats · carving · correlation · coverage.txt · dashboard ·
│                        dashboard_export.json · data_models · decisions · evaluation · evidence_ingestion ·
│                        filesystem_discovery · forensic_methodology · limitations · pipeline_stages · reporting ·
│                        sqlite_inspection · sqlite_recovery · synthetic_lab · FINAL_SUMMARY.md (this file)
├── src/android_forensics/
│   ├── acquisition/     hashing, safety, dir/zip/tar/single-file acquirers, manifest, ingest
│   ├── filesystem/      classifier, sidecars, android_paths, analysis, scanner
│   ├── sqlite/          header, sidecars, reader, inspection/inspector, discovery, pages, records, ddl,
│   │                    recovery (the page-level engine), recover_db, wal, journal, freelist
│   ├── artifacts/       schema_probe, timestamps, base/registry, sms, calls, contacts, browser, generic,
│   │                    extract, recovered (recovered-row → artifact)
│   ├── carving/         rules, sms, records, carver, database
│   ├── correlation/     graph, facts, builder
│   ├── confidence/      scorer
│   ├── normalization/   phone
│   ├── validation/      checks, runner
│   ├── timeline/        builder
│   ├── reporting/       model, generate, text, pdf, templates/report.html.j2
│   ├── dashboard/       api (FastAPI app)
│   ├── storage/         schema (3 migrations), case_store, artifact_writer, recovery_store
│   ├── pipeline/        runner (stage registry), recovery_stages
│   ├── models/          types, enums, provenance, case, evidence, artifacts, recovery, runs, validation,
│   │                    timeline, discovery, unknown
│   ├── lab/             synth (+ genuine deletions), ground_truth, deletions (matrix), evaluation (scorer), journal
│   └── cli/             app (Typer), console (Rich helpers)
├── web/                 index.html (dashboard frontend)
├── tests/                unit/ (models, sqlite, carving, correlation, pipeline, validation, storage, confidence) ·
│                        integration/ (CLI, dashboard, report, recovery matrix, synthetic lab, tamper/security)
├── synthetic_evidence/  generated dataset with genuine deletions: android_dump/, acquisition.zip/.tar.gz, ground_truth.json
├── experiments/         r1_extraction_accuracy.py · r1_inspection.py · r2_recovery.py · r2_charts.py · results/
├── reports/acceptance/  this document's own supporting evidence — the real end-to-end run (§6)
└── cases/                (gitignored) case databases, e.g. cases/acceptance from this run
```

## 4. How to run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
android-forensics --version

android-forensics synth synthetic_evidence                       # deterministic dataset + ground truth, WITH deletions
android-forensics init-case demo
android-forensics ingest demo synthetic_evidence/android_dump
android-forensics scan demo
android-forensics analyze demo                                   # scan→extract→recover→carve→correlate→reconstruct→validate→timeline→report
android-forensics report demo --format html,json,csv,pdf
android-forensics dashboard demo                                 # → http://127.0.0.1:8765/
```

## 5. Test results (real pytest output)

```
$ pytest -q
............................................................................ (…)
1481 passed, 1 skipped in ~50s      (exit code 0)
```

1,482 tests collected; the one skip is platform-dependent (a file system, such as APFS, that rejects non-UTF-8 file
names). Line coverage of `src/android_forensics` (`coverage run -m pytest && coverage report`): **95.7%** (10,481
statements, 447 missed — full per-file report: `docs/coverage.txt`). The suite covers hashing, archive attacks,
filesystem discovery, SQLite header/sidecar/reader behaviour, the page-level recovery engine (untouched cells,
freeblocks, WAL, journals, the 28-condition deletion matrix), raw carving, the correlation graph, the confidence scorer,
storage round-trips, the four recovery pipeline stages, the FastAPI dashboard, the report in every format, the full
synthetic lab end to end, tamper detection, idempotence, injection defences and the CLI.

## 6. The Phase 17 end-to-end acceptance run (real, just executed)

Case `acceptance`, evidence `synthetic_evidence/android_dump/` (16 files, 1.3 MiB, 8 SQLite databases — one encrypted
suspect, one truncated/corrupt, one WAL-mode, one with a hot rollback journal — meeting every Phase 17 minimum: ≥100 SMS,
≥50 calls, contacts, browser history, multiple databases, deleted records, WAL data, journal data, and partial records).

Command sequence run: `init-case → ingest → scan → analyze → validate → report --format html,json,csv,pdf → info`, plus a
live dashboard check against this exact case.

```
Artifacts (ACTIVE): 346    (SMS 108 · calls 60 · contacts 30 · browser visits 138 · downloads 4 · app summaries 6)

Deleted-data recovery (Review 2)
  Deleted/superseded records found: 8,244    reconstructed → RECOVERED: 8,218   → PARTIAL: 26   → CORRUPTED: 0
  Unrecoverable regions (proven, empty): 4     Corroborated by another source: 10
  Carved candidates (CARVED CANDIDATE — unconfirmed): 177     corroborated: 93
  Correlation edges: 9,079

Validation: 76 checks — VALID 56 · PARTIAL 12 · INVALID 0 · UNVERIFIED 8
Timeline events: 382 (371 artifact, 11 file)
```

**On the 8,244 figure.** This is real output, and it is larger than the ~31 rows genuinely deleted by
`SynthSpec.with_deletions` — deliberately, and correctly. The recovery engine scans every page of every database,
including `calllog.db`'s WAL: that database is written row-by-row before a mid-stream checkpoint (to model a WAL-mode
provider database as a phone would leave it), which leaves many superseded page versions in the WAL history, each a
legitimate distinct recoverable finding — page-level recovery reports *every* superseded page version it can prove
existed, not only rows a user chose to delete. This is exactly what forensic recovery is supposed to do, and it is why
the number is large: it is evidence of write history, most of it entirely mundane, correctly distinguished from the 26
genuinely deleted SMS/browser rows that are `PARTIAL` (lost their rowid to a freeblock header) rather than `RECOVERED`.

**Report correctness, checked, not assumed.** `reports/acceptance/report.html` contains the literal string
`NOT PERFORMED` **zero** times (every Review 2 stage ran, so every section shows real content); `report.json`'s
`recovery.performed` is `true`; a sample recovered row carries `confidence: "LOW"` and an explanation beginning
`"LOW: full page-level reconstruction..."`; a sample carved row carries `status: "CARVED CANDIDATE"` — never anything
else. `report.pdf` (21 pages, via `pypdf` text extraction) contains every one of the 16 section headings and the same
real numbers as the HTML.

**Evidence integrity, verified, not assumed.** Every one of the 16 original files under `synthetic_evidence/android_dump`
was re-hashed after the full run and compared against `cases/acceptance/evidence_manifest.json`: **0 mismatches, 0
missing files** — the acquisition was never modified.

**The dashboard**, queried live against this case: `/api/summary` returned the same counts as the CLI; `/api/recovery`
returned `{"PARTIAL": 26, "RECOVERED": 8218}` with `corroborated: 10`; `/` served the frontend page.

## 7. Recovery experiment results (real numbers from `experiments/results/`)

**E6 — recovery matrix** (`r2_e6_recovery_matrix.csv`, `r2_summary.json`, 28 conditions):

| | |
|---|---:|
| Physically recoverable rows (by construction) | 511 |
| Matched | 507 |
| **Recall** | **99.22%** |
| False positives | 0 |
| RECOVERED / PARTIAL / missed | 146 / 361 / 4 |

Every case reaches 100% except three documented layout limits: `plain_ps1024` (75%), `plain_ps2048` (78%),
`overwrite_50` (92%) — see `docs/sqlite_recovery.md` §7. Charts: `r2_recall_by_condition.png`, `r2_status_breakdown.png`.

**E7 — confidence calibration** (`r2_e7_confidence_calibration.csv`, three seeds of the full synthetic lab): of the
recovered artifacts matched to a genuinely planted deleted row, **29 HIGH and 64 MEDIUM, both 100%** correct against the
real deleted values; no LOW-confidence result appeared in this lab. Chart: `r2_confidence_calibration.png`. Processing
cost: ≈59.6s end to end per run of the full synthetic lab, dominated by `recover` (≈40.6s of it, because it scans every
page rather than issuing an indexed query); ≈147 MB peak Python memory.

Full numbers, method and threats to validity: [`docs/evaluation.md`](evaluation.md).

## 8. Known limitations

Full list: [`docs/limitations.md`](limitations.md). Highlights:

* Recovery does not attempt tables with fewer than 3 stored columns, `WITHOUT ROWID` tables, virtual tables, or rowids
  needing more than 6 varint bytes.
* A journal-sourced record's checksum verification is not re-derived at reconstruct time (only WAL frame status is);
  it defaults to verified.
* The synthetic lab's genuine deletions are limited to `mmssms.db` and Chrome `History` (both plain rollback-journal
  mode); `calllog.db` (WAL) and `contacts2.db` (multi-table) exercise other Review 2 conditions instead.
* Carving is a shape match (a bare digit run is never a phone number; a binary timestamp is not carved alone).
* Correlation matches by identity of a value, not by meaning.
* Confidence calibration was measured on a small synthetic sample (93 artifacts, 3 seeds) — it demonstrates the
  mechanism works as designed, not a generalisable precision curve.
* Recovering a database ingested with `--preserve none` (hash-only) has no working copy to recover from.
* Everything inherited from Review 1: damaged databases SQLite refuses to open yield no *active* artifacts (page-level
  recovery still attempts them directly); encrypted databases are flagged, never opened; ABX XML and MMS attachments
  are not decoded; phone-number matching is heuristic; parsers and the recovery engine were validated on synthetic
  evidence, not a corpus of real devices.

## 9. What is genuinely impossible (regardless of tool quality)

These limits come from Android, the storage medium and cryptography — no SQLite-level or carving technique removes them:

* **File-based / full-disk encryption without the key.** Modern Android (mandatory FBE from Android 10) encrypts user
  data with keys bound to the lock-screen credential and hardware-backed keystores. This tool does not attempt key
  extraction or lock bypass, by design; ciphertext without the key contains no recoverable plaintext.
* **TRIM / garbage collection / wear levelling.** On eMMC/UFS flash, freed blocks are erased in the background,
  typically before an image is even taken. Filesystem-level recovery of deleted files is unavailable on most modern
  devices for this reason.
* **Genuine overwriting.** Data overwritten by later writes — reused freelist pages, rewritten WAL frames, a vacuumed
  database, `secure_delete` zero-fill — cannot be reconstructed; the bytes are gone. The E6 matrix's `overwrite_50`
  case (92% recall) shows the effect directly: half the freed space reused before recovery ran.
* **`VACUUM` / `auto_vacuum`.** A database compacted at commit or by `VACUUM` no longer holds file remnants of deleted
  rows at all.
* **Missing acquisition content.** A logical (e.g. backup-based) acquisition omits databases, sidecars and unallocated
  space that a physical/full-filesystem acquisition contains; what was never acquired cannot be analysed afterward.
* **Server-side data** (cloud accounts, provider retention) is outside the scope of any single device acquisition.

Because recoverability depends on all of the above, **the absence of a recovered or carved result in a report is never
evidence that the data never existed** — this sentence is the recoverability disclaimer printed on every report.

## 10. Recommended next research directions

* **A `journal_records` table** (parallel to `wal_frames`) so a journal-sourced record's checksum is re-verified at
  reconstruct time instead of defaulting to verified (closes D-021).
* **Genuine deletions in `calllog.db` and `contacts2.db`** in the synthetic lab, with a WAL-aware and a multi-table
  physical-ground-truth method respectively, to broaden Phase 13/15's coverage beyond the two plain-journal databases.
* **A larger, more varied confidence-calibration corpus** — more seeds, more record shapes, and eventually real
  (authorised) device acquisitions — to move from "the mechanism works as designed" to a precise, generalisable
  calibration curve with confidence intervals.
* **E164 phone-number parsing with a real numbering-plan database**, replacing the conservative trailing-ten-digits
  heuristic, so correlation and duplicate detection are more precise across international numbers.
* **Android Binary XML (ABX) decoding**, so `SharedPreferences` and other ABX-encoded files contribute more than key
  names to the active view and to carving.
* **Packaging the dashboard frontend as installed data** (or serving it from an embedded resource) so `android-forensics
  dashboard` works from a wheel install, not only from a repository checkout.
* **Validation against real, authorised device acquisitions** across OEM variants and Android versions, to measure how
  E1/E6/E7's synthetic-schema numbers generalise — the single largest gap between what this capstone measured and
  real-world deployment.
