# Forensic methodology (Review 1)

## 1. Authorisation and scope

Examine only evidence you are authorised to examine. The tool performs no acquisition from live devices, no lock bypass,
decryption, credential extraction, exploitation, stealth or persistence.

## 2. Evidence integrity

* Each file is read **once**, through a read-only handle (`O_RDONLY`, plus `O_NOFOLLOW` and — on Linux, when permitted —
  `O_NOATIME`), and hashed with SHA-256 (integrity anchor), SHA-1 and MD5 (compatibility with legacy reference sets only).
  For archives the container is hashed as well as every member. A file whose size, mtime or inode changes while it is read is
  flagged `changed_during_read`. Re-hashing during validation uses the same opener. See [evidence_ingestion.md](evidence_ingestion.md).
* Recorded per file: original path, relative path, size, hashes, times with their **basis** (`fs_stat`, `tar_header_mtime`
  [+ PAX atime/ctime], `zip_extra_field_UT` [UTC], `zip_dos_time (timezone unspecified)`), kind, preserved copy name. Recorded per source: original path/name, source type,
  acquisition time (if supplied with `--acquired-at`), ingest time, tool version.
* `evidence_manifest.json` (case ID, analysis timestamp, tool version, per-file original and relative paths, sizes, hashes) is
  rewritten atomically at each ingest with a `.sha256` sidecar; its SHA-256 is written to the custody log. `verify_manifest`
  re-checks the originals and working copies against it without a case database.
* **Working copies.** Only files the engine must open (SQLite databases and sidecars, small text/XML/JSON) are copied,
  bit-identically, and set to mode 0444. SQLite never opens these: each analysis session copies them again into a scratch
  directory that is deleted afterwards. Even a read-only SQLite connection can create `-shm` files, replay a WAL or roll back
  a hot journal — those effects land on the scratch copy only.
* **Chain of custody.** `custody_log` entries commit to the hash of the previous entry
  (`sha256(prev ‖ time ‖ actor ‖ action ‖ target ‖ detail)`); editing or deleting an entry breaks the chain, which
  validation detects. This shows accidental or naive tampering; it is not a substitute for a signed, externally
  timestamped log.
* **Independent verification.** Recompute `shasum -a 256` on any original and compare with the manifest or report §4.

## 3. Acquisition handling

Zip-slip (`..`), absolute and drive-letter paths, symlinks, hard links, device nodes and encrypted zip members are rejected
or skipped **and recorded**, never followed. Entry/size budgets stop runaway archives; a truncated or budget-limited
acquisition is marked `INCOMPLETE` and fails the `acquisition_completeness` check. Unreadable files/directories are recorded
and the run continues. Reading a file can update its access time on some mounts — use a read-only mount or write blocker
for original media.

## 4. Classification

Files are classified by **content signature first**: SQLite header magic, WAL magic (`0x377f0682/3`), rollback-journal
magic, Android Binary XML (`ABX\0`), image/video/audio/zip signatures; extensions are hints. A database-like name without a
SQLite header is `encrypted_suspect` if its head has entropy ≥ 7.2 bits/byte, otherwise `db_unrecognised` (corrupt or
overwritten). Encrypted files are reported and never opened. Every database-like file gets a **detection status** decided from
its bytes alone — `VALID`, `TRUNCATED`, `CORRUPT_HEADER`, `NOT_SQLITE`, `ENCRYPTED_SUSPECT`, `EMPTY`, `UNREADABLE`, `UNVERIFIED` —
kept apart from the engine's own verdict (`open_status`, `integrity_check`). Sidecars are attached to a database only by SQLite's
naming rule (same directory, `<name>-wal` / `-shm` / `-journal`); anything else is reported as an orphan, never guessed. Full detail:
[filesystem_discovery.md](filesystem_discovery.md).

## 5. Layout detection

The Android directory layout is inferred from the evidence, path by path: the earliest recognised root in a path
(`data/data`, `data/user/N`, `data/user_de/N`, `data/system*`, `data/media/N`, `sdcard`, `storage/emulated/N`, …) defines that
file's dump prefix, so one evidence directory can hold several dumps, and the proportion of supporting paths is reported. No
directory is assumed to exist: absent common roots are listed as informational. Bare `<package>/databases/…` trees and loose files are
handled and labelled as such; no path is invented for an unrecognised layout, and `user_id` is not claimed where the path does not
state one (`/data/data`). Files are grouped into Android application directories.

## 6. The "active view"

An artifact is **ACTIVE** if it is present in the database *as SQLite itself would present it on the phone*: main file plus
committed WAL frames, with a hot rollback journal rolled back. This is obtained by opening the scratch copy read-only (or
read-write on the scratch copy if SQLite must replay/roll back). Each artifact records `view_includes_wal`, which is SQLite's own
verdict — the number of WAL frames it validated for the working copy (`wal_frames_valid`) — and not an inference from the header:
SQLite opens any `-wal` that exists, whatever the header's journal-mode bytes say. The same view is available for any single
database through `SQLiteInspector` ([sqlite_inspection.md](sqlite_inspection.md)), which also reports every table, column, key and
index and returns every active row with its storage class; rows deleted from the database are simply absent from it. Integrity is
`partial`, not `ok` or `failed`, when the only complaints concern indexes that use an Android collation this tool cannot reproduce
and the b-tree structure otherwise checks out. Rows an
application has flagged as deleted but not yet purged (e.g. Android `raw_contacts.deleted = 1`) are reported as ACTIVE with a
visible *marked deleted* flag — they are not "recovered" data.

## 7. Extraction and normalisation

* Tables are matched by schema (weighted column presence; required columns; threshold 0.5; small bonus for a matching table
  name). The score and variant are stored per artifact. Columns absent from a schema variant are `UNKNOWN`.
* Type violations (text in an integer column, blob in a text column, unknown enum codes) become **flags** on the artifact;
  values are not coerced silently.
* Timestamps come from the format the parser *declares* for that column (Unix ms, WebKit µs since 1601, …); the value `0` /
  negative means *unset* and yields no timestamp. Plausibility window: 2008-01-01 … now + 2 days. Out-of-window values are
  kept and flagged, never dropped.
* Rows are streamed: if a page mid-table is damaged, every row before it is kept and the failure is recorded.
* Text is decoded as UTF-8 with replacement; the count of undecodable values is a validation finding.
* SharedPreferences: key names only, values never stored.

## 8. Validation

Outcomes: `VALID`, `PARTIAL`, `INVALID`, `UNVERIFIED`. A check that cannot run (original evidence gone, database
encrypted) is `UNVERIFIED`, not `VALID`. Per-record anomalies are stored individually (capped at 200 per table with the
total in the summary row). See `validation/checks.py` for exact semantics.

## 9. Timeline

Artifact events use the artifact's own timestamp; file events (databases, sidecars, shared_prefs by default; `--timeline-files
all|none`) use file times with their basis and are explicitly *filesystem metadata*, not user activity. All times are UTC.
Zip DOS times carry no timezone and are labelled so.

## 10. Reporting

Every artifact row shows evidence file, table, rowid, SHA-256 and whether WAL frames were included. Sections for
Review 2 capabilities state **NOT PERFORMED**; the recoverability disclaimer is always present. HTML output is escaped
(evidence text is untrusted), terminal output renders evidence text verbatim as plain text (never as Rich markup, which would drop `[backup]` from a file name), CSV cells that could execute as spreadsheet formulas are neutralised with a leading `'`
(originals are preserved verbatim in the JSON), and the report files are hashed in `sha256sums.txt`.

## 11. Examiner checklist

1. Verify the source hash independently before ingest and after the case.
2. Read the `INVALID` / `PARTIAL` / `UNVERIFIED` results and skipped entries before relying on any artifact.
3. Treat `PARTIAL` schema scores and `UNKNOWN` fields as uncertainty, not as absence of data.
4. Corroborate significant findings with a second tool and, for anything that matters, the original device or image.
5. Remember Review 1 says nothing about deleted data.
