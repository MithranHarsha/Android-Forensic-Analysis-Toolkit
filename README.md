# Android Deleted Data Recovery and Evidence Reconstruction Framework

**B.Tech Cyber Forensics Capstone — Review 1: Forensic Foundation**

A Python forensic toolkit that takes an Android acquisition (filesystem dump, TAR/ZIP archive, or a single SQLite
database), proves the integrity of the evidence, discovers and validates every SQLite database, extracts and normalises
**active** artifacts (SMS, call log, contacts, browser history, application data), validates the result, builds a unified
timeline, and produces a provenance-rich forensic report.

> **Scope of this review.** Review 1 builds the foundation only. **Deleted-data recovery is deliberately not implemented
> yet** (freelist / unallocated-space / WAL / rollback-journal analysis, raw carving, correlation and confidence scoring
> are Review 2). Every report says so explicitly and never presents an empty "recovered" section as if nothing were
> deleted. See [docs/sqlite_recovery.md](docs/sqlite_recovery.md) for the Review 2 design.

> **Use only on evidence you are legally authorised to examine.** The tool does not bypass locks, decrypt data, harvest
> credentials, or access devices. See [Legal and ethical considerations](#legal-and-ethical-considerations).

---

## Features

| Area | What Review 1 does |
|---|---|
| **Evidence ingestion** | A reusable, database-independent library ([docs/evidence_ingestion.md](docs/evidence_ingestion.md)): directory, `.zip`, `.tar` / `.tar.gz` / `.tar.bz2` / `.tar.xz` or a single SQLite file; SHA-256 (anchor) + SHA-1 + MD5 in one read-only pass; size and timestamps with their basis; `evidence_manifest.json` (case ID, analysis timestamp, tool version, original + relative path, size, hashes) with a `.sha256` and a standalone `verify_manifest`; originals opened read-only (`O_RDONLY`, `O_NOFOLLOW`, `O_NOATIME` where allowed) and never written; change-during-read detection; write-protected (0444) working copies; hash-chained chain-of-custody log |
| **Inputs** | Extracted filesystem dumps, `.zip`, `.tar` / `.tar.gz` / `.tar.bz2` / `.tar.xz`, a single SQLite file (its `-wal` / `-shm` / `-journal` are picked up automatically) |
| **Archive safety** | Zip-slip / absolute-path / drive-letter rejection, symlinks and device files never followed, entry / size budgets, truncated-archive detection |
| **Filesystem discovery** | A standalone `discover` command and library ([docs/filesystem_discovery.md](docs/filesystem_discovery.md)): recursive, read-only, content-signature classification of SQLite databases, WAL / SHM / journal sidecars, XML, JSON, logs and media; Android layout *detected* not assumed (`/data/data`, `/data/user/N`, `/storage/emulated/N`, `/sdcard`, prefixed or multiple dumps, bare app directories — absent roots are reported, never an error); application directories with package / user attribution; per-database path, size, SHA-256, SQLite detection status (`VALID`, `TRUNCATED`, `CORRUPT_HEADER`, `NOT_SQLITE`, `ENCRYPTED_SUSPECT`, `EMPTY`, `UNREADABLE`) and associated sidecars; orphan sidecars; unreadable, vanishing, corrupt and symlinked entries recorded as issues while the scan continues |
| **SQLite inspection** | A reusable engine, `SQLiteInspector.inspect(path)` ([docs/sqlite_inspection.md](docs/sqlite_inspection.md)), run on every discovered database: header validation, page size, version information (last-writing SQLite, schema format), tables, columns (declared type, affinity, defaults, generated), primary keys, indexes, foreign keys, and every **active** record with its rowid and storage class — values exactly as stored, never coerced — plus WAL / SHM / journal detection with SQLite's own count of valid WAL frames, integrity check, and file metadata. Works on a private scratch copy; damaged, encrypted and non-SQLite files are described, not refused. Deleted rows are absent (recovery is Review 2) |
| **Active extraction** | Schema-scored parsers for SMS, call log, contacts (multi-table join), Chromium/Android browser history and downloads; generic column-hint parser and application summaries for everything else |
| **Normalisation** | UTC timestamps from *declared* formats with raw value and plausibility retained; conservative phone-matching key; `UNKNOWN` distinct from SQL `NULL` |
| **Validation** | 14 automated checks, four outcomes (`VALID` / `PARTIAL` / `INVALID` / `UNVERIFIED`), failures kept and explained |
| **Timeline** | Artifact events + file-system times, sortable, status-tagged |
| **Reporting** | Self-contained HTML (16 sections), JSON, CSV, plus `sha256sums.txt` for the report files themselves |
| **Typed data models** | Immutable, validated pydantic models for Case, EvidenceFile, Artifact (SMS, call, contact, browser…), AnalysisRun, ValidationResult and TimelineEvent; an artifact already represents `ACTIVE`, `RECOVERED`, `PARTIAL`, `CARVED`, `CORRUPTED`, `UNRECOVERABLE` and `INVALID` — see [docs/data_models.md](docs/data_models.md) |
| **Test laboratory** | Deterministic synthetic Android evidence generator with ground truth; 1,054 automated tests; reproducible experiments |

## Architecture

```
            ┌───────────────────────── cli (Typer + Rich) ─────────────────────────┐
            │  init-case · ingest · hash · discover · inspect · scan · analyze     │
            │  artifacts · validate · timeline · report · info · synth             │
            └───────────────────────────────┬──────────────────────────────────────┘
                                            ▼
                     pipeline (stage registry: scan → extract → validate | timeline)
   ┌────────────┬─────────────┬────────────┬────────────┬────────────┬────────────┬───────────┐
   │acquisition │ filesystem  │  sqlite    │ artifacts  │ validation │  timeline  │ reporting │
   │ dir/zip/tar│ classifier  │ header     │ schema     │ 14 checks  │ merged     │ HTML/JSON │
   │ hash·manif.│ android path│ sidecars   │ probe +    │            │ events     │ /CSV      │
   │ safety     │ layout      │ reader(ro) │ parsers    │            │            │           │
   └────────────┴─────────────┴────────────┴────────────┴────────────┴────────────┴───────────┘
                          models (pydantic) · storage (case.db, migrations, custody log)
```

Full description, storage schema and the Review 2 extension points: [docs/architecture.md](docs/architecture.md).

## Installation

Requires Python 3.11+. No cloud services; dependencies are `typer`, `rich`, `pydantic`, `jinja2` (and `pytest` for development).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
android-forensics --version
```

## Quick start (synthetic evidence)

```bash
android-forensics synth synthetic_evidence           # deterministic dataset + ground_truth.json
android-forensics analyze synthetic_evidence/android_dump --name demo
# → cases/demo/reports/report-<timestamp>/report.html
```

## CLI usage

```bash
android-forensics init-case case001 --examiner "A. Examiner" --description "Handset 3"
android-forensics ingest    case001 ./evidence            # dir | .zip | .tar | .tar.gz | database.db
android-forensics scan      case001                        # filesystem analysis + SQLite discovery
android-forensics analyze   case001                        # scan → extract → validate → timeline → report
android-forensics artifacts case001 --type sms --limit 20
android-forensics artifacts case001 --show 42              # full provenance for one artifact
android-forensics validate  case001 --all
android-forensics timeline  case001 --type call --since 2024-03-01
android-forensics report    case001 --format html,json,csv
android-forensics ingest    case001 ./acq.tar.gz --acquired-at 2024-06-04T08:00:00Z --preserve analysis
android-forensics hash      ./evidence --json              # standalone hashing
android-forensics discover  ./evidence                     # standalone filesystem discovery (no case needed)
android-forensics discover  ./evidence --json --hash-all   # the full typed scan as JSON, every file hashed
android-forensics inspect   ./mmssms.db                    # one database: header, version, sidecars, tables, keys, indexes, active rows
android-forensics inspect   ./mmssms.db --json             # the complete typed inspection (every active record) as JSON
android-forensics info      case001                        # case overview, custody-chain check
android-forensics info      ./mmssms.db                    # header + WAL/journal facts for one database
```

`analyze` accepts either a case or a raw evidence path (a case is created automatically):
`android-forensics analyze ./acquisition.zip`. Cases live under `./cases` (override with `--cases-dir` or
`ANDROID_FORENSICS_CASES`). Re-running any stage is idempotent and invalidates only what was built on it.

Example output of `analyze` on the synthetic case:

```
Files discovered: 16      SQLite databases: 8 (6 readable, 1 encrypted suspect, 1 unreadable)
Artifacts (ACTIVE): 373   (SMS 120 · calls 60 · contacts 30 · browser visits 152 · downloads 5 · app summaries 6)
Validation: 54 checks — VALID 50 · PARTIAL 1 · INVALID 0 · UNVERIFIED 3
Timeline events: 378
Deleted-data recovery has not been run (Review 2).
```

## Ingestion as a library

The ingestion subsystem needs no database and no CLI — a case ID and a working directory are enough
(details: [docs/evidence_ingestion.md](docs/evidence_ingestion.md)):

```python
from android_forensics.acquisition import ingest_evidence, verify_manifest

r = ingest_evidence("./acquisition.tar.gz", workdir="./work", case_id="0123456789abcdef0123456789abcdef")
print(r.totals.files, r.totals.bytes, r.complete)     # every file hashed (SHA-256 + SHA-1 + MD5), sizes and times recorded
print(r.manifest_path)                                # ./work/evidence_manifest.json (+ .sha256)
assert verify_manifest(r.manifest, r.workspace).ok    # later: re-check originals and working copies against the manifest
```

## Evidence preparation

1. Acquire lawfully, using an accepted method for the device (logical/physical extraction by an authorised tool or
   examiner). This tool consumes acquisitions; it does not acquire from devices.
2. Work from a copy or a read-only mount. Where possible use a hardware write blocker for physical media.
3. Record the source hash independently (`shasum -a 256 acquisition.tar`) and compare it with the tool's manifest.
4. Point the tool at the top of the dump. Any of these layouts works: `data/data/<pkg>/…`, a prefixed dump
   (`userdata/data/data/<pkg>/…`), bare app directories (`<pkg>/databases/…`), or a single `.db` file with its sidecars.
5. Keep the case directory: it holds `case.db`, `evidence_manifest.json`, the write-protected working copies and reports.

## Artifact support

| Artifact | Recognised schema | Extracted |
|---|---|---|
| SMS | AOSP `sms` table and compatible | address, body, date, date_sent, type/direction, read, seen, thread, service centre, subscription, status, protocol |
| Call log | AOSP `calls` | number, type, date, duration, presentation, cached name, lookup URI, account/subscription, geocode, country |
| Contacts | AOSP `contacts2` (`raw_contacts` ⨝ `data` ⨝ `mimetypes` ⨝ `accounts`), flat `contacts` tables | id, names, phones, emails, organisation, account, starred, timestamps, *deleted-flag* |
| Browser | Chromium `History` (`urls`, `visits`, `downloads`), flat legacy `history` | URL, title, visit time, count, decoded transition + qualifiers, duration, downloads (path, size, state, source page) |
| Other app data | Anything else | table catalogue, column hints (timestamp/phone/URL-like), per-app summary; SharedPreferences **key names only** |

Details, code tables and the scoring rules: [docs/artifact_formats.md](docs/artifact_formats.md).

## SQLite recovery methodology

Review 1 implements the *read side* only: header parsing, sidecar inspection, and `SQLiteInspector` — read-only access to an
"active view" (main file + committed WAL frames, hot journal rolled back — always on a disposable scratch copy). Recovery-potential
**indicators** (freelist page count, auto-vacuum mode, WAL frame slots, valid-magic journals) are reported as facts, never
findings. How deleted records survive in SQLite — cell removal, freeblocks, freelist pages, WAL generations, journals —
and the Review 2 recovery design are in [docs/sqlite_recovery.md](docs/sqlite_recovery.md).

## Deleted-data recovery methodology

Not implemented in Review 1. The pipeline reserves the seams (see [docs/architecture.md](docs/architecture.md#review-2-seams)):
physical provenance fields, the full artifact-status vocabulary (`ACTIVE`, `RECOVERED`, `PARTIAL`, `CARVED`, `CORRUPTED`,
`UNRECOVERABLE`, `INVALID`) with invariants that keep recovered data honest, a row-based parser contract that recovered records will reuse, a stage slot, nullable confidence
columns, and numbered storage migrations.

## Confidence model

Review 1 does **not** assign recovery confidence: active records are read through the SQLite engine, so the meaningful
number is *how well the schema matched the parser* — stored as `schema_match_score` with every artifact together with the
matched variant. The transparent, factor-based confidence engine for recovered data (schema match, structural validity,
serial-type validity, provenance, corroboration, timestamp validity, completeness — each with an explanation) is Review 2.

## Validation

`VALID` / `PARTIAL` / `INVALID` / `UNVERIFIED`, never silently discarded: SHA-256 re-verification of originals and working
copies, chain-of-custody hash chain, manifest integrity, acquisition completeness, SQLite header + integrity, schema
consistency and file-name agreement, record structure / datatype anomalies, timestamp plausibility, duplicate detection,
cross-artifact consistency, provenance completeness.

## Testing

```bash
pytest                                  # 1,054 tests (1,053 pass, 1 platform-dependent skip), ~15 s
python experiments/r1_extraction_accuracy.py   # measured accuracy + scaling → experiments/results/
python experiments/r1_inspection.py            # inspector throughput/memory + cell-by-cell fidelity fuzz
```

The suite covers hashing, archive attacks (zip-slip, symlinks, truncation, budgets), classification and Android filesystem
discovery (every layout, every kind of damage, unreadable / vanishing / symlinked entries), SQLite header /
sidecar / reader behaviour (including WAL, hot journal, UTF-16, corruption mid-table), pure-row parsers, ground-truth
extraction accuracy, tamper detection (modified originals, working copies, manifest, custody log), idempotence, report
structure, HTML/CSV injection defences, verbatim display of evidence text in the CLI, and the CLI itself.

## Evaluation

Measured on 15 synthetic datasets (5 seeds × 3 sizes), scored field-by-field against ground truth computed independently of
the tool: **9,210 / 9,210 active records extracted and correct — precision = recall = F1 = 1.000, 0 field mismatches.**
Scaling: 1 k → 250 k SMS rows at ≈ 16–17.5 k rows/s with a flat **≈ 6 MiB** peak Python memory (rows are streamed).
Ingestion: ≈ 230–380 MiB/s hashing (MD5 + SHA-1 + SHA-256) 301 MiB from a directory, zip or tar.
These figures come from `experiments/results/`, are reproducible with the command above, and — being synthetic data built
around the parsers' known schemas — demonstrate implementation correctness, **not** real-world coverage. Details and
threats to validity: [docs/evaluation.md](docs/evaluation.md).

## Limitations

Highlights (full list in [docs/limitations.md](docs/limitations.md)): no deleted-data recovery yet; databases SQLite refuses to
open (truncated, malformed) yield no artifacts; encrypted databases are flagged, not opened; ABX XML and MMS attachments
are not decoded; phone-number matching is heuristic; parsers were validated on synthetic evidence — real devices vary.

## Project structure

```
.
├── README.md · LICENSE · pyproject.toml · requirements.txt
├── src/android_forensics/
│   ├── acquisition/   hashing, safety, dir/zip/tar/single-file acquirers, IngestionSession, manifest (+ verify), ingest
│   ├── readonly.py    the guarded read-only opener used by ingestion, discovery and the SQLite header reader
│   ├── filesystem/    classifier, sidecars (naming rules), android_paths (layout model), analysis (pure discovery core), scanner
│   ├── sqlite/        header, sidecars, reader (read-only session), inspection (result models), inspector (SQLiteInspector), discovery
│   ├── artifacts/     schema_probe, timestamps, base/registry, sms, calls, contacts, browser, generic, extract
│   ├── normalization/ phone keys
│   ├── validation/    checks, runner
│   ├── timeline/      builder
│   ├── reporting/     model, generate, text, templates/report.html.j2
│   ├── storage/       schema (migrations), case_store, artifact_writer
│   ├── pipeline/      stage registry + runner
│   ├── models/        types, enums, provenance, case, evidence, artifacts (SMSMessage…), runs, validation, timeline, discovery, UNKNOWN
│   ├── lab/           synthetic evidence generator + ground-truth comparator + hot-journal builder
│   └── cli/           Typer app + Rich helpers
├── tests/             unit/ · integration/
├── synthetic_evidence/  generated dataset (dir, .zip, .tar.gz, ground_truth.json)
├── experiments/       r1_extraction_accuracy.py · r1_inspection.py · results/
├── reports/           review1_acceptance/ (example report on the synthetic case)
└── docs/              architecture · evidence_ingestion · filesystem_discovery · sqlite_inspection · data_models · forensic_methodology · sqlite_recovery · artifact_formats · evaluation · limitations
```

## Legal and ethical considerations

This is a forensic **examination** tool. It must be used only on evidence you are authorised to examine (a warrant, consent,
employer policy, or your own devices/test data). It intentionally implements none of: lock-screen bypass, decryption or
credential extraction, exploitation, live-device access, stealth or persistence. Encrypted databases are reported and left
alone. SharedPreferences values are never extracted (tokens/passwords). Reports contain personal data (messages, numbers,
browsing) — handle them as evidence, apply your organisation's retention and access rules, and follow applicable law.

## License

MIT (see [LICENSE](LICENSE)), with the authorised-use notice above.
