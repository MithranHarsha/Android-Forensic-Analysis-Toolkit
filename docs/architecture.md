# Architecture (Review 1)

## Design rules

1. **Evidence is immutable.** Originals are read once through a read-only handle. Everything the engine must open is a
   write-protected copy in the case evidence store, and SQLite only ever touches a *disposable scratch copy* of that.
2. **Provenance from birth.** Every artifact is created with its evidence file, SHA-256, table and rowid. A result that
   cannot be traced is a validation failure.
3. **Uncertainty is data.** `UNKNOWN` (not determinable) is distinct from `NULL` (stored as NULL). Timestamps keep the raw
   value next to the UTC interpretation and a plausibility verdict. Nothing is defaulted or guessed.
4. **Schema, not file name.** Parsers score table/column similarity; the score is stored with each artifact.
5. **Parsers consume rows, never cursors.** `from_row(RowSource)` is a pure function returning a typed artifact (`SMSMessage`, `CallRecord`, …) — see Review 2 seams.
6. **Models are typed, validated and immutable.** Hashes, timestamps and enums are checked at construction; forensic invariants (for example *a recovered artifact must have a physical location and an explained confidence*) live in the model, not in callers.
7. **Idempotent stages.** Every stage clears only its own derived data and can be re-run; dependents are invalidated.
8. **Deterministic.** No ML, no LLM, no network. Same evidence → same results.

## Pipeline

```
ingest ─► scan ─► extract ─┬─► validate
 (CLI)   fs + SQLite       └─► timeline            report (read-only over the case store)
         discovery
```

| Stage | Module | Reads | Writes |
|---|---|---|---|
| ingest | `acquisition.session` (library) + `acquisition.ingest` (case) | original evidence (read-only) | `evidence_sources`, `evidence_files`, `scan_issues`, preserved copies, `evidence_manifest.json`, `custody_log` |
| scan | `filesystem.scanner` → `filesystem.analysis`, then `sqlite.discovery` (which runs `sqlite.inspector` on every preserved database) | inventory + preserved copies | layout, `evidence_files` Android attribution, `app_directories`, `databases` (`sqlite_status`, version, engine facts), `db_tables` (with each table's keys, indexes, foreign keys), `scan_issues` |
| extract | `artifacts.extract` | preserved copies (via scratch session) | `artifacts` + typed tables, table→parser mapping, column hints |
| validate | `validation.*` | everything + originals (re-hash) | `validation_results` |
| timeline | `timeline.builder` | `artifacts`, `evidence_files` | `timeline_events` |
| report | `reporting.*` | the store | `report.html` / `report.json` / `csv/` / `sha256sums.txt` |

Stages are declared in `pipeline/runner.py` (`Stage(name, run, reset, requires)`); `run_stage` resets the stage and its
transitive dependents, records an `analysis_runs` row and appends to the custody log.

## Package map

| Package | Responsibility |
|---|---|
| `acquisition` | the ingestion subsystem — see [evidence_ingestion.md](evidence_ingestion.md): `hashing` (MD5/SHA-1/SHA-256 in one pass), `safety` (path normalisation, budgets), `directory` / `archive` / `single_file` acquirers behind one `Acquirer` protocol, `session` (`IngestionSession`, `ingest_evidence` — no database), `manifest` (build, atomic write, `verify_manifest`), `ingest` (`ingest_source` into a case) |
| top level | `readonly` (the guarded opener shared by ingestion, discovery and the SQLite header reader), `workspace` (the working analysis directory and its overlap rules), `errors` (`ForensicsError` → `CaseError`, `IngestionError`, `DiscoveryError`), `progress`, `fmt`, `util`, `config` |
| `filesystem` | see [filesystem_discovery.md](filesystem_discovery.md): `classifier` (signatures first), `sidecars` (the `-wal` / `-shm` / `-journal` naming rule shared with SQLite discovery), `android_paths` (layout model, package/user attribution), `analysis` (pure: inventory → `FilesystemScan`), `scanner` (`scan_directory` standalone; `scan_filesystem` for the case pipeline) |
| `sqlite` | see [sqlite_inspection.md](sqlite_inspection.md): `header` (pure-Python, works on damaged files), `sidecars` (WAL/SHM/journal header facts), `reader` (scratch-copy read-only session, Android collation shims, streaming rows), `inspection` (typed result models), `inspector` (`SQLiteInspector.inspect` / `iter_records`), `discovery` (the pipeline stage that persists the inspector's results) |
| `artifacts` | `schema_probe`, `timestamps`, `base` (`RowSource`, `FieldReader`, `ArtifactParser`), `registry`, parsers (`sms`, `calls`, `contacts`, `browser`), `generic`, `extract` |
| `normalization` | phone classification / matching key / snippets |
| `validation` | `checks` (registry of check functions), `runner` |
| `timeline` | merge artifact events and file-system times |
| `reporting` | `model` (assembly), `generate` (HTML/JSON/CSV + hashes), `text`, Jinja2 template |
| `storage` | numbered migrations, `CaseStore` (runs, custody chain, resets), `artifact_writer` |
| `models` | the typed core models — see [data_models.md](data_models.md): enums, `Case`, `EvidenceSource`/`EvidenceFile`, the `Artifact` hierarchy, provenance value objects, `AnalysisRun`, `ValidationResult`, `TimelineEvent`, manifest, the discovery result (`FilesystemScan`, `DiscoveredDatabase`, `Sidecar`, `AndroidAppDirectory`), `UNKNOWN` |
| `lab` | synthetic evidence generator, ground-truth comparator, and a deterministic hot-rollback-journal builder |
| `cli` | Typer commands, Rich rendering. Evidence text is always rendered as plain text (`SafeTable`, `plain_panel`) — never as Rich markup |

## Case directory

```
cases/<name>/
├── case.db                  analysis results (SQLite)
├── evidence_manifest.json   hashes + metadata for every ingested file
├── evidence/s<N>/           write-protected (0444) preserved copies: databases, sidecars, small text/XML/JSON
├── scratch/                 disposable SQLite session copies (empty between runs)
└── reports/report-<UTC>/    report.html · report.json · csv/ · sha256sums.txt
```

Large media is hashed but not copied; only files the engine must open are preserved.

## Storage (migration 001)

`cases` · `evidence_sources` · `evidence_files` · `scan_issues` · `app_directories` · `databases` (header, version and engine facts, sidecar facts) · `db_tables` (one row per `sqlite_master` entry, schema details as JSON) · `analysis_runs` ·
`artifacts` (common envelope: `status`, `extraction_method`, `confidence`, provenance, raw reference and digest, parser, timestamp triple, `fields_json`) ·
typed projections `messages` / `calls` / `contacts` / `browser_history` (queryable columns, FK to `artifacts`) ·
`validation_results` · `timeline_events` · `custody_log` (hash-chained).

The envelope keeps artifact-specific fields in JSON (no monolithic table); the typed tables exist for querying. The raw
source row is always kept verbatim (blobs summarised by length/SHA-256/head).

## Review 2 seams

These hooks exist **now** and are used by Review 1; Review 2 adds code without rewriting them.

| Seam | In Review 1 | Review 2 adds |
|---|---|---|
| Provenance | `Provenance(evidence_file_id, source_file, source_sha256, source_database, source_table, source_rowid, view_includes_wal, physical=None)` and a digest-bound `RawReference`; `artifacts` has nullable `page_number`, `cell_index`, `byte_offset`, `page_type`, `region`, `raw_hex` | fills `PhysicalLocation` and raw bytes for recovered records |
| Active records | `ActiveRecord` (`state: "ACTIVE"`, table, rowid, ordinal, values with storage classes) from `SQLiteInspector` | recovered rows get a separate type carrying physical provenance; the active records are the built-in baseline they are de-duplicated against |
| Status / method | `ArtifactStatus` has all seven values and `ExtractionMethod` the recovery methods; only `ACTIVE` / `ACTIVE_QUERY` / `FILESYSTEM_METADATA` are emitted; `Artifact` invariants already forbid a recovered record without a physical location, raw bytes, confidence and its explanation | emits `RECOVERED` / `PARTIAL` / `CARVED` / `CORRUPTED` / `UNRECOVERABLE` / `INVALID` — no model change |
| Row contract | `ArtifactParser.from_row(RowSource, SchemaMatch, DbContext)` — pure, tolerates `UNKNOWN` fields | recovered raw records are turned into `RowSource`s and pass through the *same* code |
| Schema knowledge | `SchemaMatch` / `FieldSpec` separate from extraction | tests candidate records against known schemas |
| Byte access | `sqlite.header` + `sqlite.sidecars`; `SQLiteInspector` already reports every b-tree root page (`sqlite_master`), the freelist header facts and each sidecar's header facts | `PageSource` (db / WAL / journal pages behind one interface), `pages`, `records`, `freelist`, `wal`, `journal`, `recovery` |
| Stage registry | `PIPELINE` list with `requires` and `reset` | `recover`, `carve`, `correlate`, `reconstruct` registered in `BY_NAME` (run by name, or via `FULL_PIPELINE_NAMES`); `run_pipeline(store)` with no explicit names still runs only Review 1's four stages, so nothing about Review 1 changes unless recovery is asked for (D-022) |
| Confidence | nullable `confidence`, `confidence_factors_json`; `schema_match_score` stored | `ConfidenceScorer` returning level + explained factors |
| Correlation | `phone_key` on messages / calls / contacts | `Correlator`, entity and relation tables |
| Validation | check registry (`CHECKS`) | `check_recovery_integrity`: a recovered record's raw bytes still match its digest and its linked artifact's; a carved row is still, in the database, exactly `CARVED CANDIDATE` and never `HIGH` |
| Storage | numbered migrations | migration 002: `recovered_records`, `carved_candidates`, `wal_frames`, `freelist_pages`, `correlations`; migration 003: a recovered record's corroboration sentences |
| Synthetic lab | ground truth per database | controlled deletion / overwrite experiments on the same generator |

## Extending

* **New artifact parser** — subclass `ArtifactParser`, implement `identify` (score tables with `FieldSpec`s),
  `extract` (yield artifacts) and `from_row` (pure conversion), decorate with `@register`, add the enum member and, if
  needed, a typed field model. No other module changes.
* **New validation check** — write `def check_x(store, opts) -> Iterator[ValidationResult]` and append it to `CHECKS`.
* **New stage** — add a `Stage` to `PIPELINE`; the CLI and dependency invalidation pick it up.
* **New acquirer** — implement `Acquirer.acquire(ctx)` yielding `AcquiredFile` / `AcquisitionIssue`.
