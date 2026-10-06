# Android Deleted Data Recovery and Evidence Reconstruction Framework

**B.Tech Cyber Forensics Capstone — Review 1 (forensic foundation) + Review 2 (deleted-data recovery) + release 0.3 (deployable)**

A Python forensic toolkit that takes an Android acquisition — a filesystem dump, ZIP/TAR archive, **raw / sparse disk image (ext4 and
f2fs) or EnCase E01** — proves the integrity of the evidence, discovers and validates every SQLite database, extracts and normalises
**active** artifacts (SMS, call log, contacts, browser history, application data), **recovers deleted and superseded SQLite
records** (freelist, unallocated space, WAL and rollback-journal analysis), **carves raw patterns** outside structured records,
**correlates** evidence across sources, assigns every recovered or carved item a **deterministic, explainable confidence level**,
validates the result, builds a unified timeline, and produces a provenance-rich, optionally **signed** forensic report (HTML, JSON,
CSV, PDF). It runs as a CLI, a Docker image, a single-file binary, or an **authenticated multi-case web server** with sandboxed
background analysis jobs.

> **Recovery is opt-in but on by default.** `analyze` runs the full pipeline — scan, extract, recover, carve, correlate,
> reconstruct, validate, timeline — unless `--no-recover` is given, in which case it behaves exactly as Review 1 always
> did. A recovered record is never presented as confirmed evidence without its physical location, its raw bytes and a
> confidence level with the sentence that justifies it; a carved candidate's status is always the literal `CARVED CANDIDATE` and
> its confidence can never be `HIGH`. See [docs/sqlite_recovery.md](docs/sqlite_recovery.md), [docs/carving.md](docs/carving.md)
> and [docs/correlation.md](docs/correlation.md).

> **Use only on evidence you are legally authorised to examine.** The tool does not bypass locks, decrypt data, harvest
> credentials, or access devices. Encrypted evidence is *detected and reported*, never attacked. See
> [Legal and ethical considerations](#legal-and-ethical-considerations).

**What "deployable" means here, and what it does not.** Hash-pinned dependency locks, a non-root read-only Docker image, a
PyInstaller single-file binary, CI (lint, types, security scan, dependency audit, 3-OS × 3-Python tests), an external
append-only audit log, Ed25519-signed reports, hostile-input hardening verified by fuzzing and adversarial tests, an authenticated
server with rate limits, strict CSP and sandboxed jobs, and measured performance. It is **not** a certified or accredited product:
nobody outside the author has reviewed it, real-world validation is limited to the corpora listed in
[docs/validation.md](docs/validation.md), and the standards mapping in [docs/standards_alignment.md](docs/standards_alignment.md)
is a self-assessment. Read [Limitations](#limitations) before relying on it in casework.

---

## Features

| Area | What it does |
|---|---|
| **Evidence ingestion** | A reusable, database-independent library ([docs/evidence_ingestion.md](docs/evidence_ingestion.md)): directory, `.zip`, `.tar` / `.tar.gz` / `.tar.bz2` / `.tar.xz` or a single SQLite file; SHA-256 (anchor) + SHA-1 + MD5 in one read-only pass; size and timestamps with their basis; `evidence_manifest.json` with a `.sha256` and a standalone `verify_manifest`; originals opened read-only and never written; change-during-read detection; write-protected (0444) working copies; hash-chained chain-of-custody log |
| **Disk images** | Raw / Android-sparse / **E01 (multi-segment)** images, GPT and MBR; read-only **ext2/3/4 and f2fs** parsers written for hostile input (bounds-checked, cycle-guarded; f2fs applies the checkpoint's NAT journal and cross-checks every node); encrypted directories are *reported*, never decrypted ([docs/disk_images.md](docs/disk_images.md)) |
| **Chain of custody & signing** | In-database hash chain **plus** an external append-only audit log (who, host, command, outcome, evidence hash) whose head goes into the report; Ed25519-signed reports with offline `verify-report`; exact build/dependency/plugin stamp in every report ([docs/standards_alignment.md](docs/standards_alignment.md)) |
| **Web server** | Token-authenticated roles (viewer / analyst / admin), multi-case registry, streamed hash-while-uploading evidence, **resource-limited child-process jobs**, rate limiting + lockout, strict CSP, server audit log, browser UI ([docs/deployment.md](docs/deployment.md)) |
| **Plugins, config, logging** | Parser plugins (`--plugin`, entry points) with SHA-256 attribution in the report ([docs/plugins.md](docs/plugins.md)); TOML config for examiner details; structured JSON logs; court-oriented case details and certification block |
| **Filesystem discovery** | A standalone `discover` command and library ([docs/filesystem_discovery.md](docs/filesystem_discovery.md)): recursive, read-only, content-signature classification of SQLite databases, sidecars, XML, JSON, logs and media; Android layout *detected* not assumed; application directories with package / user attribution |
| **SQLite inspection** | `SQLiteInspector.inspect(path)` ([docs/sqlite_inspection.md](docs/sqlite_inspection.md)): header, version info, tables, columns, keys, indexes, foreign keys, every **active** record with its storage class, WAL/journal facts, integrity check. Damaged, encrypted and non-SQLite files are described, not refused |
| **Active extraction** | Schema-scored parsers for SMS, call log, contacts, Chromium/Android browser history and downloads; generic column-hint parser and application summaries for everything else |
| **Deleted-data recovery** | A pure-Python page-level engine ([docs/sqlite_recovery.md](docs/sqlite_recovery.md)) scans every page image (main file, WAL frames, rollback-journal pages) for byte sequences that parse as a record of a known table — untouched cells (`RECOVERED`) and cells whose first bytes were overwritten by SQLite's own freeblock header (`PARTIAL`, lost columns marked `UNKNOWN`, never guessed). Measured 507/511 (99.22%) recall, 0 false positives across a 28-condition matrix (`docs/evaluation.md`) |
| **Raw carving** | Pattern candidates (phone numbers, URLs, e-mails, timestamps, SMS-like text, loose SQLite-record shapes) in bytes no parser reads ([docs/carving.md](docs/carving.md)); every hit is a `CarvedCandidate`, status literally `CARVED CANDIDATE`, never confirmed evidence |
| **Correlation** | An in-memory evidence graph ([docs/correlation.md](docs/correlation.md)) links a phone number across SMS/calls/contacts, and corroborates a recovered record or carved candidate only with an artifact of another kind in another database |
| **Confidence scoring** | A fixed, explainable, deterministic calculation (`confidence/scorer.py`) — schema match, structural validity, provenance, corroboration, completeness, timestamp plausibility — never a model; every non-active artifact carries its level and the sentence that justifies it |
| **Normalisation** | UTC timestamps from *declared* formats with raw value and plausibility retained; conservative phone-matching key; `UNKNOWN` distinct from SQL `NULL` |
| **Validation** | 15 automated checks (incl. recovery/carving integrity), four outcomes (`VALID` / `PARTIAL` / `INVALID` / `UNVERIFIED`), failures kept and explained |
| **Timeline** | Artifact events (active and recovered) + file-system times, sortable, status-tagged |
| **Reporting** | Self-contained HTML (16 sections), JSON, CSV and PDF ([docs/reporting.md](docs/reporting.md)); every section shows real recovery/carving/correlation content when those stages ran, or an explicit `NOT PERFORMED` box when they did not — never both |
| **Dashboard** | A read-only FastAPI REST API + static frontend ([docs/dashboard.md](docs/dashboard.md)) over one case's results; `android-forensics dashboard CASE` (the web server reuses the same router per case) |
| **Typed data models** | Immutable, validated pydantic models — see [docs/data_models.md](docs/data_models.md) — for every artifact status (`ACTIVE`, `RECOVERED`, `PARTIAL`, `CORRUPTED`, `CARVED CANDIDATE`, `INVALID`), `RecoveredRecord`, `CarvedCandidate`, `CorrelationEdge` and `ConfidenceAssessment` |
| **Test laboratory** | Deterministic synthetic Android evidence generator with ground truth, now including genuine deletions and physically-derived recovery expectations ([docs/synthetic_lab.md](docs/synthetic_lab.md)); 1,482 automated tests; reproducible experiments |

## Architecture

```
            ┌───────────────────────────── cli (Typer + Rich) ─────────────────────────────┐
            │  init-case · ingest · hash · discover · inspect · scan · analyze · recover   │
            │  artifacts · validate · timeline · report · dashboard · info · synth         │
            └────────────────────────────────────┬─────────────────────────────────────────┘
                                                   ▼
        pipeline (stage registry): scan → extract → [recover → carve → correlate → reconstruct] → validate → timeline
   ┌────────────┬────────────┬───────────┬──────────┬──────────┬─────────────┬────────────┬────────────┬────────────┐
   │acquisition │ filesystem │  sqlite   │artifacts │ carving  │ correlation │ confidence │ validation │  timeline  │
   │ dir/zip/tar│ classifier │ header    │ schema   │ patterns │ evidence    │ deterministic│ 15 checks │ merged     │
   │ hash·manif.│ android    │ sidecars  │ probe +  │ + free-  │ graph       │ scorer     │            │ events     │
   │ safety     │ path·layout│ pages ·   │ parsers ·│ space    │             │            │            │            │
   │            │            │ recovery  │ recovered│ scan     │             │            │            │            │
   └────────────┴────────────┴───────────┴──────────┴──────────┴─────────────┴────────────┴────────────┴────────────┘
              models (pydantic) · storage (case.db, migrations, custody log) · reporting (HTML/JSON/CSV/PDF) · dashboard (FastAPI)
```

`analyze` runs the full pipeline by default; `--no-recover` restores exactly Review 1's four stages
(`scan → extract → validate → timeline`), and every existing Review 1 result is unchanged either way. Full description,
storage schema and how each Review 2 module plugs into the Review 1 seams: [docs/architecture.md](docs/architecture.md)
and [docs/pipeline_stages.md](docs/pipeline_stages.md).

## Installation

Requires Python 3.11+ (tested on 3.11–3.13 on Linux and macOS; **Windows is untested**). No cloud services.

```bash
# from source
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"                       # dev = tests + lint + type-check + fuzzing tools
android-forensics --version

# reproducible, hash-verified runtime install
pip install --require-hashes --no-deps -r requirements.lock && pip install --no-deps .

# container (non-root, read-only evidence, no network)
docker build -t android-forensics .
docker run --rm --network none --read-only --tmpfs /tmp -v "$PWD/evidence:/evidence:ro" -v "$PWD/cases:/cases" \
    android-forensics analyze /evidence/userdata.img --cases-dir /cases --name case1

# single-file binary (no Python needed)
pip install ".[binary]" && python packaging/build_binary.py && ./dist/android-forensics --version
```

Optional extras: `.[docs]` (MkDocs), `.[e2e]` (Playwright browser tests), `.[binary]` (PyInstaller).

## Quick start (synthetic evidence)

```bash
android-forensics synth synthetic_evidence            # deterministic dataset + ground_truth.json, WITH deletions
android-forensics analyze synthetic_evidence/android_dump --name demo
# → cases/demo/reports/report-<timestamp>/report.html  (sections 7/9/10/12 show real recovered/carved/correlated data)
android-forensics dashboard demo                       # → http://127.0.0.1:8765/
```

## CLI usage

```bash
android-forensics init-case case001 --examiner "A. Examiner" --description "Handset 3"
android-forensics ingest    case001 ./evidence            # dir | .zip | .tar | .tar.gz | database.db
android-forensics scan      case001                        # filesystem analysis + SQLite discovery
android-forensics analyze   case001                        # scan → extract → recover → carve → correlate → reconstruct → validate → timeline → report
android-forensics analyze   case001 --no-recover            # exactly the Review 1 pipeline
android-forensics recover   case001                         # just the four Review 2 stages, on a case already scanned+extracted
android-forensics artifacts case001 --type sms --status RECOVERED
android-forensics artifacts case001 --show 42               # full provenance for one artifact
android-forensics validate  case001 --all
android-forensics timeline  case001 --type call --since 2024-03-01
android-forensics report    case001 --format html,json,csv,pdf
android-forensics dashboard case001 --port 8765             # read-only REST API + browser frontend
android-forensics ingest    case001 ./acq.tar.gz --acquired-at 2024-06-04T08:00:00Z --preserve analysis
android-forensics hash      ./evidence --json               # standalone hashing
android-forensics discover  ./evidence                      # standalone filesystem discovery (no case needed)
android-forensics inspect   ./mmssms.db                     # one database: header, version, sidecars, tables, keys, indexes, active rows
android-forensics info      case001                         # case overview, recovery/carving/correlation counts, custody-chain check
android-forensics info      ./mmssms.db                     # header + WAL/journal facts for one database

# release 0.3
android-forensics ingest    case001 ./userdata.img          # raw/sparse image (ext4, f2fs) or .E01; --mount-point to override /data detection
android-forensics keygen                                    # Ed25519 key for signing reports
android-forensics report    case001 --sign --signer "Dr. Doe"        # …and, offline:
android-forensics verify-report cases/case001/reports/report-… --trusted-key doe.pub.pem
android-forensics audit-verify case001                      # tamper-evidence of the command history
android-forensics case-details case001 --set case_number=2026-042 --set agency="City PD"
android-forensics --plugin ./acme_calls.py plugins          # parsers in effect (built-in + plugins)
android-forensics server-token create --name alice --role analyst --data-dir ./server-data
android-forensics serve     --cases-dir ./cases --data-dir ./server-data                # authenticated multi-case server
```

`analyze` accepts either a case or a raw evidence path (a case is created automatically):
`android-forensics analyze ./acquisition.zip`. Cases live under `./cases` (override with `--cases-dir` or
`ANDROID_FORENSICS_CASES`). Re-running any stage is idempotent and invalidates only what was built on it.

Example output of `analyze` on the synthetic case (`--with-deletions`, the default):

```
Files discovered: 16      SQLite databases: 8 (6 readable, 1 encrypted suspect, 1 unreadable)
Artifacts (ACTIVE): 373   (SMS 108 · calls 60 · contacts 30 · browser visits 137 · downloads 4 · app summaries 6)
Deleted-data recovery (Review 2)
  Deleted/superseded records found: 31    reconstructed → RECOVERED: 5   → PARTIAL: 26
  Corroborated by another source: 2       Carved candidates: 118 (corroborated: 6)
Validation: 58 checks — VALID 53 · PARTIAL 2 · INVALID 0 · UNVERIFIED 3
Timeline events: 402
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
| Other app data | Anything else, including a recovered/carved row of an unrecognised table | table catalogue, column hints, per-app summary (active); `GenericRecord` (recovered) — values kept, no meaning claimed; SharedPreferences **key names only** |

Every artifact type above is produced from a **recovered** row too, through the same parser code as an active row
(`ArtifactParser.from_row`) — only the envelope (status, method, raw bytes, physical location, confidence) differs.
Details, code tables and the scoring rules: [docs/artifact_formats.md](docs/artifact_formats.md).

## SQLite recovery methodology

`sqlite/recovery.py` scans every page image byte-for-byte: an untouched freed cell (whole payload size, rowid and body
intact) is `RECOVERED`; a cell whose first bytes were overwritten by SQLite's own freeblock header when it was freed is
`PARTIAL` (rowid and sometimes the first column are `UNKNOWN`, never guessed); WAL frames and rollback-journal pages are
scanned the same way, so a page a checkpoint or rollback superseded is not lost. Ground truth for evaluation is physical
— each deleted row is re-encoded exactly as SQLite would write it and searched for in the file's actual bytes — never
predicted by the algorithm being measured. Full design, byte-level detail and measured results:
[docs/sqlite_recovery.md](docs/sqlite_recovery.md).

## Confidence model

Every `RECOVERED` / `PARTIAL` / `CORRUPTED` artifact and every `CarvedCandidate` carries a level (`LOW` / `MEDIUM` /
`HIGH`) from a fixed, explainable, deterministic calculation (`confidence/scorer.py`) — schema match, structural
validity, serial-type validity, field consistency, page integrity, source provenance, cross-artifact corroboration,
timestamp plausibility, raw-byte completeness — never a model, and the same bytes always score the same way. Hard caps:
no schema match or inexact structure → `LOW`; `CORRUPTED` → `LOW`; `PARTIAL` → at most `MEDIUM` unless two independent
sources corroborate it; a carved candidate → at most `MEDIUM`, `LOW` without corroboration. Every level ships with the
factor list and a sentence, e.g. *"HIGH: full page-level reconstruction (the whole cell survived), schema match,
corroborated by contact Ann Lee."* Measured calibration (a small synthetic sample): 100% of HIGH and MEDIUM recovered
artifacts matched the actual deleted values — [docs/evaluation.md](docs/evaluation.md).

## Validation

`VALID` / `PARTIAL` / `INVALID` / `UNVERIFIED`, never silently discarded: SHA-256 re-verification of originals and working
copies, chain-of-custody hash chain, manifest integrity, acquisition completeness, SQLite header + integrity, schema
consistency and file-name agreement, record structure / datatype anomalies, timestamp plausibility, duplicate detection,
cross-artifact consistency, provenance completeness, and recovery/carving integrity (a recovered record's raw bytes still
match their digest; a carved row is still, in the database, exactly `CARVED CANDIDATE`).

## Testing

```bash
pytest                                          # 1,482 tests (1 platform-dependent skip)
coverage run -m pytest && coverage report       # 95.7% line coverage of src/android_forensics
python experiments/r1_extraction_accuracy.py    # Review 1: measured accuracy + scaling → experiments/results/
python experiments/r1_inspection.py             # Review 1: inspector throughput/memory + fidelity fuzz
python experiments/r2_recovery.py               # Review 2: recovery matrix + confidence calibration + timing
python experiments/r2_charts.py                 # → experiments/results/*.png
```

The suite covers hashing, archive attacks, filesystem discovery, SQLite header/sidecar/reader behaviour, pure-row
parsers, ground-truth extraction accuracy, the page-level recovery engine (untouched cells, freeblocks, WAL, journals,
the 28-condition deletion matrix), raw carving (a planted-string fixture, SQLite free-space carving with exclusions),
the correlation graph, the confidence scorer, storage round-trips, the four recovery pipeline stages, the FastAPI
dashboard, the report in every format with and without recovery having run, the full synthetic lab end to end, tamper
detection, idempotence, injection defences and the CLI.

## Evaluation

**Review 1** (15 synthetic datasets, 5 seeds × 3 sizes, scored field-by-field against independently-computed ground
truth): 9,210/9,210 active records extracted and correct — precision = recall = F1 = 1.000. Scaling: 1k→250k SMS rows at
≈16–17.5k rows/s, ≈6 MiB flat peak memory. Ingestion: ≈230–380 MiB/s hashing 301 MiB.

**Review 2** (28-condition deletion matrix + the full synthetic lab, three seeds): **507/511 (99.22%) recall, 0 false
positives** recovering deleted records; three documented layout limits account for every miss. Confidence calibration on
this run: 29 HIGH and 64 MEDIUM recovered artifacts, both **100%** matching the real deleted values. Recovery is the
dominant cost (≈41s of a ≈60s full-pipeline run on the synthetic lab; ≈147 MB peak memory) because it scans every page
of every database rather than issuing an indexed query.

**Release 0.3 additions** (all reproducible; details in [docs/validation.md](docs/validation.md) and
[docs/performance.md](docs/performance.md)):

* *Cross-tool comparison* on the same 28-condition matrix, over the 511 rows whose bytes physically survive: this tool **99.2 %**,
  DC3 SQLite Dissect **91.8 %**, undark **43.6 %**, SQLite's `.recover` **1.8 %** (it targets corruption, not deletion). The matrix
  was authored alongside this tool, so this shows relative behaviour on those conditions, not general superiority.
* *Real corpus*: the public Android 9 acquisition from Digital Corpora (4.5 GB tar.gz) — see `docs/validation.md` for what was and
  was not checked.
* *Fuzzing and hostile evidence*: property-based fuzzing of every parser (found and fixed a real DDL-parser crash), mutated-image
  tests for ext4/f2fs/E01/sparse, archive bombs, injection, control-character and XSS tests, and a real-browser end-to-end test.
* *Scaling*: ~0.4–0.6 ms per database row end-to-end (131 MB / 1M rows in 9.3 min, 4.7 GB peak); image ingestion streams at
  ~280 MB/s with ~70 MB peak memory. The benchmark found and fixed two defects (15 GB-per-million-rows correlation memory; a
  quadratic carver).

These figures come from `experiments/results/`, are reproducible with the commands above, and — being synthetic data
built around the parsers' known schemas — demonstrate implementation correctness, **not** real-world coverage. Full
numbers, charts and threats to validity: [docs/evaluation.md](docs/evaluation.md).

## Limitations

Highlights (full list in [docs/limitations.md](docs/limitations.md)): **encrypted `/data` (the norm on phones) yields no artifacts — it is reported, not decrypted**; deleted *files* are not recovered at file-system level (only deleted SQLite records); ext4 `inline_data` and f2fs compression are unsupported; Windows is untested and the server's job sandbox is POSIX-only; databases SQLite refuses to open yield no active
artifacts (page-level recovery still attempts them); encrypted databases are flagged, not opened; ABX XML and MMS
attachments are not decoded; phone-number matching is heuristic; parsers and the recovery engine were validated on
synthetic evidence — real devices vary; recovery cannot restore data that was actually overwritten (VACUUM,
`secure_delete`, sufficient reuse) — its absence here is not evidence it never existed; a carved candidate is never
confirmed evidence; confidence calibration was measured on a small synthetic sample.

## Project structure

```
.
├── README.md · LICENSE · pyproject.toml · requirements.txt
├── src/android_forensics/
│   ├── acquisition/   hashing, safety, dir/zip/tar/single-file acquirers, IngestionSession, manifest (+ verify), ingest
│   │   └── image/     sources (raw/sparse/E01), partitions (GPT/MBR), ext4, f2fs, acquirer
│   ├── custody/       audit (external hash-chained log), signing (Ed25519/GPG), stamp (build identity)
│   ├── server/        authenticated multi-case server: app, auth, db, jobs, sandbox + limited_exec, ratelimit, settings
│   ├── plugins.py · plugin_api.py · userconfig.py · logs.py
│   ├── readonly.py    the guarded read-only opener used throughout
│   ├── filesystem/    classifier, sidecars, android_paths (layout model), analysis (pure discovery core), scanner
│   ├── sqlite/        header, sidecars, reader, inspection/inspector, discovery, pages/records/ddl, recovery (engine),
│   │                  recover_db (orchestration), wal, journal, freelist
│   ├── artifacts/     schema_probe, timestamps, base/registry, sms, calls, contacts, browser, generic, extract, recovered
│   ├── carving/       rules (patterns + validators), sms (SMS-like text), records (SQLite record shapes), carver, database
│   ├── correlation/   graph, facts, builder (the evidence graph + corroboration)
│   ├── confidence/     scorer (deterministic recovery/carved-candidate confidence)
│   ├── normalization/ phone keys
│   ├── validation/    checks, runner
│   ├── timeline/      builder
│   ├── reporting/     model, generate, text, pdf, templates/report.html.j2
│   ├── dashboard/      FastAPI app (api.py), security headers, web/ (index.html, app.js, style.css)
│   ├── storage/       schema (migrations), case_store, artifact_writer, recovery_store
│   ├── pipeline/      stage registry + runner, recovery_stages (recover/carve/correlate/reconstruct)
│   ├── models/        types, enums, provenance, case, evidence, artifacts, recovery (RecoveredRecord/CarvedCandidate/
│   │                  CorrelationEdge/ConfidenceAssessment), runs, validation, timeline, discovery, UNKNOWN
│   ├── lab/           synthetic evidence generator (+ genuine deletions) · ground-truth comparator · deletion matrix ·
│   │                  matrix scorer · hot-journal builder
│   └── cli/           Typer app + Rich helpers
├── tests/             unit/ · integration/ · security/ (fuzz, hostile evidence, sandbox) · e2e/ (browser) · fixtures/ · tools/
├── deploy/            docker-compose + Caddy/nginx/systemd · packaging/ (PyInstaller) · examples/plugins/
├── synthetic_evidence/  generated dataset (dir, .zip, .tar.gz, ground_truth.json — with genuine deletions)
├── experiments/       r1_*.py, r2_*.py · results/ (CSV, JSON, PNG charts)
├── reports/           acceptance/ (Phase 17 end-to-end run on synthetic_evidence/, full pipeline, every format)
└── docs/              architecture · evidence_ingestion · filesystem_discovery · sqlite_inspection · sqlite_recovery ·
                       carving · correlation · dashboard · reporting · pipeline_stages · synthetic_lab · data_models ·
                       forensic_methodology · artifact_formats · evaluation · limitations · decisions · coverage.txt ·
                       user_guide · disk_images · plugins · deployment · performance · validation · standards_alignment
                       (browse with `mkdocs serve`)
```

## Legal and ethical considerations

This is a forensic **examination** tool. It must be used only on evidence you are authorised to examine (a warrant, consent,
employer policy, or your own devices/test data). It intentionally implements none of: lock-screen bypass, decryption or
credential extraction, exploitation, live-device access, stealth or persistence. Encrypted databases are reported and left
alone. SharedPreferences values are never extracted (tokens/passwords). A carved candidate is never presented as confirmed
evidence. Reports contain personal data (messages, numbers, browsing) — handle them as evidence, apply your organisation's
retention and access rules, and follow applicable law.

## License

MIT (see [LICENSE](LICENSE)), with the authorised-use notice above.
