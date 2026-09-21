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

**D-008 · Recovery is staged: recover → carve → correlate → reconstruct.** The `Artifact` model requires a confidence level and
its explanation for every non-active artifact, and the strongest confidence factor is corroboration by *another* artifact. A
recovered row therefore cannot be an `Artifact` the moment it is found. The recovery stage stores a `RecoveredRecord` (where the
bytes are, the raw bytes with their digest, the table the record was fitted to, the values the bytes determine); the
`reconstruct` stage builds the typed artifact once correlation has said what supports it. Nothing downstream reads a
`RecoveredRecord` as evidence.

**D-009 · Ground truth is derived from the bytes, not from the intention to delete.** "The row was deleted" does not mean "the row
is recoverable": a delete followed by `VACUUM` or an overwrite leaves nothing. The evaluation re-encodes every deleted row exactly
as SQLite writes it and searches the file's bytes: the whole cell present → RECOVERED is expected; everything after the first
four bytes present → PARTIAL; neither → UNRECOVERABLE. Recall is measured against what is physically there, so 100% is
attainable and every miss is a genuine defect or a documented layout limit (`docs/sqlite_recovery.md` §7).

**D-010 · Recovery limits set by evidence, not by convenience.** Free space is searched only for tables with ≥ 3 stored columns
(`MIN_SCAN_WIDTH`): a 1–2 column record is too short to be told apart from noise. Rowids longer than 6 varint bytes are not
attempted (a 7–9 byte rowid would put a 2⁴⁸+ id in an application table; the false-positive risk outweighs the gain).
`sqlite_*` tables, virtual tables and `WITHOUT ROWID` tables are not modelled (their cells are not table-leaf cells).

**D-011 · A row must be a possible row of its table.** Found while converting recovered rows on a real Chromium schema: the
residue of a split b-tree root held `08 0b 08 00 00 00 00 00 00 00` — a payload size, a rowid and a header of seven NULL
columns. It parses, it fitted `urls`, and it was reported as a recovered row although four of that table's columns are
`NOT NULL`. Two rules now apply to every candidate: a stored NULL in a `NOT NULL` column (other than the rowid alias) cannot be
a genuine row, since SQLite refuses the insert; and a record in which every column is NULL carries no information and is what
structure bytes followed by zeros look like. Sparse rows with at least one real value are unaffected. The measured recovery
matrix (507/511) is unchanged; the case is pinned by regression tests.

**D-012 · Recovered rows use the active-row parsers.** `ArtifactParser.from_row` builds the payload, timestamp and summary; only
the envelope (status, method, raw bytes, physical location, confidence) differs. A column the bytes did not determine is absent
from the parser's row, so it reads as `UNKNOWN` and is never a default. A parser is used only for a row that means something on
its own: SMS and call-log rows, Chromium `urls` (as a URL-level entry), `visits` and `downloads`. A contact is assembled from
several tables, so a recovered `data` or `raw_contacts` row stays a `GenericRecord` — the values are kept without a claim about
whose they are. A recovered visit holds only a URL id; its URL text is taken from the *active* `urls` row when one exists and
the artifact is flagged `url_from_active_urls_table`; when that row is gone too the URL is `UNKNOWN`.

**D-013 · UNKNOWN is not a malformed timestamp.** The browser parser converted timestamps unconditionally; for a column the
bytes did not determine that produced "non-numeric value". It now converts only when the column is present (as the SMS and call
parsers already did), so a missing timestamp is absent, not flagged as corrupt.

**D-014 · What lifts a whole-cell row to HIGH.** The scorer's threshold is 0.85. A RECOVERED whole cell with a verified source,
exact structure, consistent fields and a plausible timestamp scores 0.82 (MEDIUM) alone; corroboration by another artifact or a
second location for the same record lifts it to HIGH. A PARTIAL row is capped at MEDIUM unless two independent sources
corroborate it. The arithmetic is in `confidence/scorer.py`, and each artifact stores the factor list and a sentence.

**D-015 · A carved hit is never anything but a candidate, and the code says so three times.** The `CarvedCandidate` model's
status is `Literal["CARVED CANDIDATE"]`; the case database has a `CHECK (status = 'CARVED CANDIDATE')`; and a test parses every
module that names `CarvedCandidate` and fails if the same module names `ArtifactStatus.ACTIVE / RECOVERED / PARTIAL / CORRUPTED /
CARVED`. The `carving` package imports nothing that can build an artifact. Confidence for a candidate is assigned later, by the
scorer, with a ceiling of MEDIUM and LOW when nothing corroborates it.

**D-016 · A carve rule reports only what validates.** A ten-digit run in the Android date window is a Unix timestamp; the same run
outside it is not reported, rather than reported as "low quality". The scorer's `value_validity` factor is therefore always
satisfied for an emitted candidate, and `context_valid` (the hit is delimited, not glued to more letters or digits) carries the
variation. A hit inside a database's free space is tagged `container = "sqlite_free_space"`.

**D-017 · Carving skips current data, keeps history.** Inside a database the live cells of the *current* version of each page are
skipped (the parsers own them), while replaced pages, older / stale / uncommitted WAL frames and journal pages are carved: they
hold values the database no longer shows, and for a table the recovery engine cannot model they are the only way to reach them.
The cost is that history often repeats values that are still active; those candidates are corroborated by the active artifact
during correlation instead of being silently dropped.
