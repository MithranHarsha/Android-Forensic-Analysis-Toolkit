# Core data models

Every entity the toolchain reasons about is a **strongly typed, validated, immutable** pydantic model in
`android_forensics/models/`. Persistence is a thin mapping (`to_record` / `from_record`) — the database and the models
describe the same thing, and a test proves it on every artifact of the acceptance case.

```
Case ─┬─ EvidenceSource ── EvidenceFile ──┐            (hashed inventory)
      │                                   │ provenance
      ├─ AnalysisRun  (one per stage)     ▼
      │      ├── Artifact ◄─ SMSMessage · CallRecord · Contact · BrowserHistoryEntry · BrowserDownload · ApplicationSummary
      │      ├── ValidationResult          (each artifact: Provenance + RawReference + ParserInfo + TimestampInfo)
      │      └── TimelineEvent
```

## The artifact envelope

`Artifact` is an abstract base; the six concrete subclasses add only their type-specific fields (`SMSMessage.address`,
`CallRecord.duration_seconds`, …) and fix `artifact_type`.

| Requirement | Field | Notes |
|---|---|---|
| artifact ID | `id` | assigned by the store |
| artifact type | `artifact_type` | fixed per subclass; also the discriminator for polymorphic loading |
| source file | `provenance.source_file` + `source_sha256` | the file the bytes were read from (a `-wal` for WAL-recovered data) |
| source database | `provenance.source_database` | the database the record belongs to; equals `source_file` for active rows |
| source table | `provenance.source_table` + `source_rowid` | logical location in Review 1 |
| physical location | `provenance.physical` (`PhysicalLocation`) | page / cell / byte offset — `None` in Review 1, required for every recovered state |
| extraction method | `extraction_method` (`ExtractionMethod`) | `ACTIVE_QUERY`, `FILESYSTEM_METADATA` (Review 1); `FREELIST_PAGE`, `FREEBLOCK`, `UNALLOCATED_SPACE`, `WAL_FRAME`, `JOURNAL_PAGE`, `RAW_PAGE_SCAN`, `CARVING` reserved |
| timestamp | `timestamp` (`TimestampInfo`) | raw value as stored + canonical UTC + declared format + plausibility + note |
| status | `status` (`ArtifactStatus`) | see below |
| confidence | `confidence`, `confidence_factors` | `HIGH`/`MEDIUM`/`LOW` plus the explained factors behind it (Review 2 fills them) |
| raw / source reference | `raw` (`RawReference`) | the verbatim source row (Review 1) or the raw record bytes (Review 2), bound to the artifact by a SHA-256 digest |
| metadata | `metadata`, `flags`, `unknown_fields`, `parser` (`ParserInfo`), `phone_key`, `marked_deleted`, `validation_notes` | free-form extras plus structured parse notes |

`UNKNOWN` (cannot be determined) is distinct from `None` (the source stored NULL): `Artifact.build` records unknown field names in
`unknown_fields` and leaves them unset; a model validator rejects an `unknown_fields` entry that names a non-existent field or
one that actually holds a value.

## Status vocabulary

| Status | Meaning | Produced by |
|---|---|---|
| `ACTIVE` | present in the live database view | **Review 1** |
| `RECOVERED` | deleted, fully reconstructed, structurally valid | Review 2 |
| `PARTIAL` | deleted, some fields unrecoverable (marked `UNKNOWN`) | Review 2 |
| `CARVED` | raw-carved *candidate* — never confirmed evidence on its own | Review 2 |
| `CORRUPTED` | damaged/fragmentary remains whose values cannot be trusted | Review 2 |
| `UNRECOVERABLE` | evidence that a record existed but its content is gone | Review 2 |
| `INVALID` | a candidate rejected by validation, kept with the reasons | Review 2 |

`ArtifactStatus` also exposes `is_active`, `is_recovery_state`, `requires_confidence`, `is_candidate`.
`ValidationStatus` (`VALID`/`PARTIAL`/`INVALID`/`UNVERIFIED`) is a separate enum for check outcomes.

## Invariants enforced by the model

They make it impossible to build a recovered artifact that breaks the project's forensic rules:

| Rule | Why |
|---|---|
| `ACTIVE` ⇒ an active extraction method and a row/inventory raw reference; any other status ⇒ a recovery method | status and method can never disagree |
| every non-`ACTIVE` status ⇒ `provenance.physical` **and** raw bytes | recovered data must be traceable to bytes in the evidence |
| `RECOVERED`/`PARTIAL`/`CARVED`/`CORRUPTED` ⇒ `confidence` **and** non-empty `confidence_factors` | "every result explains *why* the confidence was assigned" |
| `CARVED` ⇒ confidence is not `HIGH` | a carved candidate is not confirmed evidence |
| `INVALID` ⇒ `validation_notes` | failed validations are explained, never silent |
| `RawReference.sha256` is computed when omitted and **verified** when supplied | an edited raw row or byte string is detected (`validate` re-checks every stored row) |
| `Provenance`: `source_rowid` ⇒ `source_table` ⇒ `source_database` | a row cannot be cited without its table and database |

Artifacts are frozen. `artifact.evolve(**changes)` returns a new, fully re-validated artifact — the sanctioned way to promote a
candidate:

```python
carved = SMSMessage(status=ArtifactStatus.CARVED, extraction_method=ExtractionMethod.CARVING,
                    confidence=Confidence.LOW, confidence_factors=[factor("pattern_only", "phone-number pattern, no record structure")],
                    provenance=Provenance(..., physical=PhysicalLocation(page_number=12, byte_offset=0xA42F)),
                    raw=RawReference(kind=RawKind.PAGE_BYTES, raw_bytes_hex="…"), parser=…, body="…")
recovered = carved.evolve(status=ArtifactStatus.RECOVERED, extraction_method=ExtractionMethod.FREELIST_PAGE,
                          confidence=Confidence.HIGH, confidence_factors=[factor("corroborated", "number is in contacts")])
```

## The other models

| Model | Key fields and rules |
|---|---|
| `Case` | `id` (uuid hex), `name`, `examiner`, `description`, `created_at`, `tool_version`, detected `layouts` per source |
| `EvidenceSource` | `source_type`; archives **must** record container size + hashes, directories/single files must not; `acquisition_time` is normalised to UTC and rejected if it carries no timezone; `complete` flag |
| `EvidenceFile` | relative normalised `path` (never modified, even padding spaces), `hashes` (`FileHashes`: MD5/SHA-1/SHA-256, each format-checked), `kind`, `times` (must state their *basis*), `preserved_copy`; a zero-length file must carry the hashes of empty input |
| `AnalysisRun` | lifecycle rules: `RUNNING` has no finish/error; `COMPLETED` has a finish and no error; `FAILED` has a finish and an error; a run cannot end before it starts |
| `ValidationResult` | `target_type` (`ValidationTarget`), `check` (one of the 14 `ValidationCheck`s), `status`, mandatory `detail`, `evidence` |
| `TimelineEvent` | canonical UTC `timestamp`; an artifact event needs type/status/artifact id, a file event is filesystem metadata and may carry none of them; `is_recovered` distinguishes recovered events |
| discovery models | `FilesystemScan` (layout, files, databases, orphan sidecars, application directories, issues, category counts), `DiscoveredDatabase` (path, size, SHA-256, `SqliteStatus`, header facts, **at most one** `Sidecar` per kind — WAL / SHM / journal), `Sidecar` (`header_valid` is `true` / `false` / `null` = not determinable), `AndroidAppDirectory`, `ScanIssue`. Immutable; SHA-256 fields are format-checked. See [filesystem_discovery.md](filesystem_discovery.md) |
| inspection models | `DatabaseInspection` (file, header, version, sidecars, engine, integrity, schema entries, tables, issues), `TableInspection` (columns, primary key, indexes, foreign keys, active records), `ActiveRecord` (`state: "ACTIVE"`, rowid, values), `BlobValue`, `SpecialFloat`. They live in `sqlite/inspection.py` because they embed the header and sidecar facts. See [sqlite_inspection.md](sqlite_inspection.md) |
| manifest models | `ManifestEntry` (per-file `original_path`, `relative_path`, `size`, flat `md5`/`sha1`/`sha256`, `kind`, `times`, `preserved_copy`), `ManifestSource` (container hashes, acquisition/ingest times, `complete`), `Manifest` (`case_id`, `analysis_timestamp`, `tool_version`, version 2) |

## Types

`Sha256Hex`/`Sha1Hex`/`Md5Hex` (lowercase hex, exact length), `UtcIso` (`YYYY-MM-DDTHH:MM:SS.mmmZ`, sortable),
`IsoInput` (accepts any timezone-aware ISO 8601, stores canonical UTC), `NonBlankStr` (rejects blank text but never
alters it — evidence paths must survive byte-for-byte), `CaseId`. Android code tables are enums with `from_code`; an
unmapped code becomes `UNRECOGNISED` and the raw integer is kept on the model.

## Persistence

`model.to_record()` yields flat column values; `Model.from_record(row)` is its inverse; `CaseStore` exposes typed access
(`case()`, `sources()`, `evidence_files()`, `runs()`, `get_artifact()`, `add_*`). `Artifact.from_record` picks the right
subclass from `artifact_type`; `artifact_adapter()` does the same for dict/JSON input. `to_record` stores timestamp raw
values as JSON so their type survives (`1709280000000` vs `"garbage"`).

**Adding an artifact type:** add an `ArtifactType` member, subclass `Artifact` with a `Literal` type and its fields,
`register_artifact` it, write its parser (`ArtifactParser.from_row`) and, if it needs a projection table, its insert in
`storage/artifact_writer.py`.

## Tests

`tests/unit/models/` (237 tests) covers types, enums, provenance, every invariant, one valid instance of **every** status,
record and JSON round trips for every artifact class, and the remaining models. Integration tests reload all 373
artifacts of the synthetic case through the typed models and compare them with the stored rows.
