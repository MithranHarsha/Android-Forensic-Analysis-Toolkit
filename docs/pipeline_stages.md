# The Review 2 pipeline stages (Phase 9)

`pipeline/recovery_stages.py` wires the recovery engine, the carver, the correlation graph and the confidence scorer into
four stages that plug into the existing stage runner (`pipeline/runner.py`): **recover → carve → correlate → reconstruct**.
Each stage reads only what an earlier stage persisted to the case database — never another stage's in-memory state — so any
one of them can be re-run by itself.

## Recovery is opt-in

`run_pipeline(store)` with no explicit stage names still runs exactly Review 1's four stages (`scan`, `extract`, `validate`,
`timeline`) and reports no recovery — every existing Review 1 result is unchanged (D-007, D-022). The four Review 2 stages
run only when asked for: by name (`run_stage(store, "recover")`) or via an explicit list such as
`android_forensics.pipeline.runner.FULL_PIPELINE_NAMES` (`scan, extract, recover, carve, correlate, reconstruct, validate,
timeline` — the order the CLI's full `analyze` uses).

## The four stages

**`recover`** (requires `scan`) — for every database whose header parsed and whose main file has a working copy, runs
`sqlite.recover_db.recover_database` on the main file and its preserved `-wal` / `-journal`, and persists:
* `recovered_records` — one `RecoveredRecord` per row the engine found (via `artifacts.recovered.record_from_row`, which drops
  undetermined columns and binds the raw bytes to their digest);
* `unrecovered_regions` — freed space that held nothing recoverable, with why;
* `wal_frames` — every frame's index, offset, page, commit size and verification status (`parse_wal`, not just the summary);
* `freelist_pages` — every trunk and leaf page, from the database's own freelist walk.

A database with no working copy (`--preserve none`) is skipped, not fabricated, and a `scan_issues` row says so.

**`carve`** (requires `recover`) — for each database, carves the main file's free space (`carving.main_file_exclusions`,
excluding structure, live cells of the *current* page version, and the byte ranges `recover` already reported), then its
`-wal` and `-journal` the same way; every other preserved file is carved whole. Candidates persist to `carved_candidates`,
unscored (`confidence` is `NULL`) — see [carving.md](carving.md).

**`correlate`** (requires `extract`, `carve`) — builds the evidence graph over active artifacts, *draft* reconstructions of
every recovered record not yet turned into an artifact (built in memory only, via `artifacts.recovered.reconstruct` with no
corroboration — never stored), and the carved candidates (see [correlation.md](correlation.md)). It writes two things back:
each recovered record's corroboration sentences (`recovered_records.corroboration_json`, migration 003) for `reconstruct` to
score with, and every carved candidate's confidence (`confidence.scorer.score_carved`) — carved candidates never become
artifacts, so this is also where their score is decided for good.

**`reconstruct`** (requires `correlate`) — turns each recovered record into its typed artifact (or a `GenericRecord`),
scored with the sentences `correlate` wrote (`confidence.scorer.score_recovered`), inserts it and links
`recovered_records.artifact_id` to it. It then runs correlation a **second time**, now over the complete set of stored
artifacts (active + just-reconstructed) and the already-scored carved candidates, and persists the final graph to
`correlations` (D-020: correlation is pure, so running it twice — once for corroboration text, once for the final graph with
real artifact ids — costs nothing but a second pass).

## Rebuilding context without a serialisation format

`reconstruct` (and `correlate`, for its drafts) need a `DatabaseContext` — the table schema and each WAL frame's
verification status — for every database. Rather than pass a `RecoveryReport` between stages, `_database_context` rebuilds
it cheaply each time from what `recover` already persisted (the database's own schema via `sqlite.recovery.build_models`,
plus the `wal_frames` table); recovery is deterministic (Phase 4), so this is correctness-preserving (D-023). A per-record
journal checksum is not yet persisted the same way `wal_frames` is, so a journal-sourced record's `source_provenance` factor
defaults to verified — a stated limitation (D-021), not a silent assumption.

## Resets

Each stage's `reset` undoes exactly what its own `run` persisted, and `run_stage` resets a stage and everything that
(transitively) `requires` it before re-running it — across *all* registered stages, not just whichever list is running, so
resetting `recover` correctly invalidates `carve` → `correlate` → `reconstruct` even in a partial run. `reconstruct`'s reset
also removes matching `timeline_events` rows (D-024): `timeline` does not formally depend on `reconstruct` (so Review 1's
`timeline` behaviour is unaffected when recovery never ran — D-022), but if it *did* run over reconstructed artifacts, a
foreign key would otherwise break on the next `recover`. The timeline stays stale until `timeline` is re-run, the same way
`validate` needs a manual re-run to see recovered artifacts when only part of the pipeline is re-executed.

## Validation

`validation.checks.check_recovery_integrity` re-hashes every recovered record's raw bytes against its stored digest (and, if
reconstructed, checks the linked artifact's raw bytes still match), and confirms every carved row's database status is still
the literal `CARVED CANDIDATE` with confidence never `HIGH` — the model's invariants, checked again at the database level in
case anything ever writes around the model.
