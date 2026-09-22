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

**D-018 · Corroboration means "in a different database".** A live SMS row does not corroborate a phone number carved from that
database's own `-wal`: it is the same file's data seen twice. A sidecar resolves to its main file for this purpose. Corroboration
of a recovered record additionally requires an artifact of a *different kind* (a message is corroborated by contacts and the call
log, not by other messages), so the scorer's "two sources" cap for PARTIAL records counts genuinely different witnesses.

**D-019 · An impossible timestamp cancels corroboration, not the link.** A recovered record whose date is outside the Android
window is still linked to the artifacts that share its number (that fact is true and useful), but the edge carries
`corroborated: false` and the record gets no corroboration sentences: a record that is wrong about *when* has not earned credit
for being right about *who*. A record with no timestamp is judged on the rest.

**D-020 · Correlation runs twice, on purpose.** Recovered records only become artifacts (with ids) after they are scored, and
scoring needs corroboration. So correlation is a pure function: pass 1 over active artifacts and recovered *drafts* produces the
sentences; the stage reconstructs and stores the artifacts; pass 2 over the stored artifacts persists the edges with final
`artifact:<id>` refs. No edge is ever rewritten.

**D-021 · Recovery's WAL provenance is re-verified; its journal provenance is not (yet).** ``recover`` persists each WAL
frame's precise status (``committed`` / ``uncommitted`` / ``stale_generation`` / ...) to the ``wal_frames`` table, so
``reconstruct`` can score a WAL-sourced record's ``source_provenance`` factor exactly. The equivalent per-record journal
checksum is not persisted (only a qualitative note is attached to the record's ``issues``), so a journal-sourced record's
``journal_verified`` defaults to true. This is stated as a limitation rather than silently assumed; closing it needs a
``journal_records`` table analogous to ``wal_frames``, deferred to a later phase since no test currently depends on it.

**D-022 · Recovery is opt-in, never bundled into the default pipeline.** ``run_pipeline(store)`` with no explicit stage names
still runs exactly Review 1's four stages (``scan``, ``extract``, ``validate``, ``timeline``); ``recover`` / ``carve`` /
``correlate`` / ``reconstruct`` only run when named explicitly (directly, or via ``FULL_PIPELINE_NAMES``). This is what keeps
every existing Review 1 test and fixture (which calls `run_pipeline(store)` bare) producing exactly the results it always
did, per D-007 -- adding Review 2 must not change what Review 1 reports unless recovery is asked for.

**D-023 · The staged design costs one extra recovery scan at reconstruct time.** ``reconstruct`` (and ``correlate``, to build
draft artifacts for corroboration) need a ``DatabaseContext`` -- the table schema and WAL frame status -- for each database.
Rather than serialise the whole ``RecoveryReport`` between stages, each rebuilds it cheaply from what ``recover`` already
persisted (the database's own schema, plus the ``wal_frames`` table); recovery is proven deterministic (Phase 4), so this is a
correctness-preserving, stage-independent way to reconstruct context without adding a serialisation format for it.

**D-024 · Resetting a stage also cleans up what a later, formally-unrelated stage wrote about its output.** ``reconstruct``'s
own artifacts can be referenced by ``timeline_events.artifact_id`` even though ``timeline`` does not (for D-022's reason)
formally depend on ``reconstruct``. Its reset therefore deletes matching ``timeline_events`` rows itself (not just the stages
the dependency graph would normally cascade to) so that re-running ``recover`` never leaves a foreign-key error or a dangling
reference; the timeline is stale until the user re-runs the ``timeline`` stage, the same way ``validate`` already needs a
manual re-run to see recovered artifacts in a partial pipeline.

**D-025 · `analyze` runs recovery by default; `--no-recover` opts out.** The CLI is where a Review 1 default would matter
most to a user, but recovery only *adds* information (deleted/superseded records, carved candidates, correlation edges) — it
never changes what Review 1's stages report. `analyze` therefore defaults to the full pipeline
(`pipeline.runner.FULL_PIPELINE_NAMES`) and prints a "Deleted-data recovery (Review 2)" panel with the real counts (records
found, reconstructed by status, corroborated, carved candidates, correlation edges); `--no-recover` restores the exact
Review 1 stage list and message. A standalone `recover` command runs just the four Review 2 stages on a case that has
already been scanned and extracted, for someone who wants to add recovery to an existing Review 1 analysis.

**D-026 · The dashboard is read-only and opens its own connection per request.** `CaseStore` wraps one `sqlite3.Connection`,
which is not safe to share across the threads a web server uses; `dashboard.create_app` therefore opens a fresh
`CaseStore.open(case_dir)` per request (a FastAPI dependency, closed when the request finishes) rather than holding one
connection for the app's lifetime. No endpoint calls `run_stage` or writes to the database — the dashboard can only show
what `analyze` / `recover` / `report` already produced, never analyse on its own, so opening it can never change a case's
recorded state.

**D-027 · `web/` lives at the repository root, not inside the installed package.** `dashboard.create_app` locates it via a
path relative to the source file (`parents[3] / "web"`), which works for the way this project is actually run — from a
repository checkout, as the capstone and its tests always do — but would not resolve inside a wheel installed from PyPI
(setuptools `package-data` only bundles files inside the package). Packaging the frontend as installable data is future
work; noted here rather than left as a silent gap.

**D-028 · The report reflects exactly what ran, never what the tool can do.** `ReportModel.recovery["stages_run"]` is read
directly from `CaseStore.last_run(stage)`, one bool per `recover`/`carve`/`correlate`/`reconstruct` — not from whether any
rows happen to exist. A case where recovery ran and found nothing gets "no records were recovered from this evidence,"
not the `NOT PERFORMED (Review 2)` box; a case where it never ran gets that box regardless of what a later run might find.
The four sections (7, 9, 10, 12), the "at a glance" cards, the top banner and the methodology/limitations text all read the
same four booleans, so nothing in the report can show recovery results and the "not performed" disclaimer at once.

**D-029 · The PDF report uses fpdf2's core fonts, sacrificing full Unicode for zero bundled assets.** Embedding a Unicode
TTF (for the "…" and "×" the HTML report uses freely) would add a font file to package and license; fpdf2's built-in
Helvetica is latin-1 only. `pdf._txt` round-trips every string through `encode("latin-1", "replace")`, so an unsupported
character becomes `?` — visible and honest — rather than a crash or silent mojibake. Given the PDF is a condensed,
printable companion to the HTML/JSON report (which keep full fidelity), this was judged an acceptable trade for a capstone
tool with no server-side rendering budget for font subsetting.

**D-030 · The checked-in `synthetic_evidence/` gains genuine deletions; the pytest `synth` fixture does not.**
`SynthSpec.with_deletions` defaults to `False`, so `generate(out, SynthSpec())` — what every Review 1 test's `synth`
fixture calls — is byte-for-byte what it always was; only the CLI's `android-forensics synth` (now `--with-deletions`
by default) and a dedicated evaluation lab opt in. This lets the committed `synthetic_evidence/ground_truth.json` describe
a full Android dump *with* deleted rows and their physically-derived recovery expectation (Phase 13) without touching a
single existing Review 1 assertion, which reads its own fresh, undeleted copy of the same generator.

**D-031 · Deletions are only applied to the two plain-rollback-journal databases.** `mmssms.db` and Chrome's `History` are
both opened without `journal_mode=WAL`, so a delete there matches the well-tested "plain" condition of the single-table
recovery matrix directly. `calllog.db` (WAL mode, already exercising the WAL-history condition) and `contacts2.db`
(multi-table joins, already exercising the app-level `deleted=1` soft-delete flag) are left as `generate()` already builds
them: adding real deletes to a WAL-mode file mid-construction, or to a table three parsers join across, would need
building and proving a second physical-truth method under a tight schedule for no evaluation benefit the existing
recovery-matrix conditions do not already cover. Ground truth for the two chosen tables reuses the exact method
`lab/deletions.py` already established: re-encode the row as SQLite would and search the final bytes.

**D-032 · Ground truth for the lab's deleted rows is derived once, directly, not reused from the recovery matrix.**
`lab/synth._delete_rows_and_truth` reads each table's own `CREATE TABLE` SQL from `sqlite_master` (via
`sqlite.ddl.parse_create_table` and `sqlite.recovery.TableModel`, not a hand-written column list), so it works for any
table's real schema — `sms`, `urls`, `visits`, `downloads` all use one code path — and stays correct if a schema changes.

**D-033 · Coverage is measured, not asserted as a gate.** `coverage.py` (`.coveragerc`: source = `src/android_forensics`,
templates and `__main__` excluded) is run over the full suite for Phase 14 and the number (95.7%, `docs/coverage.txt`) is
reported rather than enforced by a minimum-coverage CI failure — a coverage floor pressures tests into existing just to
touch a line, which is the opposite of this project's testing style (every test states a concrete forensic fact and checks
it). The remaining gaps were read file by file: they are I/O error branches that need a specific, hard-to-provoke failure,
and CLI argument-parsing edges — never a status transition, confidence rule or byte-offset calculation.

**D-034 · A PARTIAL row is calibrated by value, not by rowid.** `experiments/r2_recovery.py`'s confidence-calibration
measurement matches a reconstructed artifact against the deleted row it corresponds to using `lab.evaluation.matches`
(every known field must equal the truth's), the same notion of a match the recovery matrix already uses — never by rowid,
since a PARTIAL row has lost its rowid by definition. Matching by rowid first (an earlier draft of this script) silently
excluded every PARTIAL row from the measurement, understating the sample by roughly 5x; the fix is recorded here so the
same mistake is not repeated in a future evaluation script.

**D-035 · Experiment numbers are asserted to match the docs, not merely eyeballed.** `docs/evaluation.md`'s E6 table
(511 physically recoverable rows, 507 matched, 99.22% recall, 0 false positives) is the literal output of
`experiments/r2_recovery.py` on the seed it runs with, which is the same recovery matrix `tests/integration/
test_recovery_matrix.py` already asserts a minimum recall against — so a regression that would change the documented
number is already caught by the test suite before it could go stale in the docs.
