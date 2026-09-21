# Engineering decisions log

Every ambiguity in the specification that was settled by an engineering judgement is recorded here: what was ambiguous, what
was decided, and why it is the most defensible forensic choice. Entries are appended as the build proceeds.

## 2026-09-21 — Baseline (Review 1 foundation, spec Phases 0–3 and the normal side of Phase 4)

**D-001 · Package layout differs from the spec's tree.** The spec lists `acquisition`, `filesystem`, `sqlite`, `artifacts`,
`carving`, `correlation`, `confidence`, `validation`, `timeline`, `reporting`, `models`, `storage`, `cli`. The build adds
`pipeline` (stage registry with dependency-aware reset), `lab` (synthetic evidence + ground truth), `normalization`, and
top-level `readonly`, `workspace`, `errors`. Reason: stages must be re-runnable and invalidate only what depends on them, and
the read-only opener is shared by ingestion, discovery and the SQLite layer. `carving`, `correlation`, `confidence` are added
in Review 2 as specified.

**D-002 · `EvidenceItem` is called `Artifact`.** The spec's `EvidenceItem` (id, artifact_type, status, confidence, source_file,
source_database, source_table, page_number, byte_offset, raw_hash, timestamp, data, recovery_method, validation_notes,
created_at) maps onto `Artifact` (envelope) + typed payload subclasses (`SMSMessage`, `CallRecord`, …), `Provenance` /
`PhysicalLocation` / `RawReference` (source, page, offset, raw hash, raw bytes) and `ExtractionMethod` (recovery method).
Reason: one flat table with dozens of nullable columns per artifact type was explicitly rejected by the spec itself.

**D-003 · One status vocabulary.** `ArtifactStatus` has seven values: the spec's `ACTIVE / RECOVERED / PARTIAL / CORRUPTED /
UNRECOVERABLE`, plus `CARVED` and `INVALID` (the carved-candidate and rejected-candidate states the spec needs elsewhere).
Model invariants (recovered data needs a physical location, raw bytes, a confidence level and its explanation; a carved
candidate is never HIGH) live in the model, not in callers.

**D-004 · Evidence is never opened by SQLite directly.** Even a read-only SQLite connection can create `-shm` files, replay a
WAL or roll back a hot journal. Every SQLite read works on a private scratch copy, hashed as it is copied.

**D-005 · Active view uses SQLite's own verdict on the WAL.** `view_includes_wal` is derived from the frames SQLite validated
(`wal_frames_valid`), not from the header: SQLite applies any `-wal` that exists regardless of the header's journal-mode bytes.

**D-006 · Android collations are approximated.** `LOCALIZED`, `PHONEBOOK`, `UNICODE`, `LOCALE` are registered as binary
comparisons so databases that name them can be read. Consequence: `integrity_check` cannot vouch for indexes using them, so
the result is `partial` (structure verified with `quick_check`), never `ok` and never a false `failed`.

## 2026-09-22 — Review 2 (spec Phases 4A–17)

**D-007 · The spec is treated as approval to build recovery.** Review 1 was scoped by the user to "no deleted-record recovery
yet"; the full 18-phase specification was then supplied with the instruction to continue. Recovery (Phase 4B onward) is built
as new pipeline stages behind the existing seams; the Review 1 stages and their results are unchanged.
