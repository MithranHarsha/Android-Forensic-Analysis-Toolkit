# Forensic methodology

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

Every artifact row shows evidence file, table, rowid, SHA-256 and whether WAL frames were included. A section for a
Review 2 capability that did not run (`recover`/`carve`/`correlate` not part of this analysis) states **NOT PERFORMED**
explicitly; one that did run shows the real recovered/carved/correlated rows, each with its confidence and the sentence
that justifies it — never both for the same section. The recoverability disclaimer is always present regardless. HTML
output is escaped (evidence text is untrusted), terminal output renders evidence text verbatim as plain text (never as
Rich markup, which would drop `[backup]` from a file name), CSV cells that could execute as spreadsheet formulas are
neutralised with a leading `'` (originals are preserved verbatim in the JSON), and the report files are hashed in
`sha256sums.txt`.

## 11. Deleted-data recovery, carving and correlation (Review 2)

* **Recovery is page-level, not schema-level.** Every page image (the main file's pages, WAL frames, rollback-journal
  pages) is scanned byte-for-byte for sequences that parse as a record of a known table; live-cell extents are excluded
  first, so nothing already visible through the active view is re-reported. A record whose whole cell survived is
  `RECOVERED`; one whose first bytes were overwritten by SQLite's own freeblock header is `PARTIAL`, with the columns
  the bytes no longer determine explicitly named `UNKNOWN` — never guessed, never defaulted. See
  [sqlite_recovery.md](sqlite_recovery.md).
* **Carving is a last resort, and it says so.** A pattern match in bytes no parser reads (a phone number, a URL, an
  e-mail address, a timestamp, SMS-like text, a loose SQLite-record shape) is a `CarvedCandidate`, status literally
  `CARVED CANDIDATE`. It is never presented as evidence, never reaches `ACTIVE`/`RECOVERED`/`PARTIAL`, and its
  confidence can never be `HIGH`. See [carving.md](carving.md).
* **Correlation corroborates, it does not invent.** A recovered record or carved candidate is linked to an artifact only
  when they share an actual fact (a phone number, a URL, a timestamp, message text) — and only when that artifact comes
  from a genuinely independent source (a different database, not the same file's own data seen twice, and for a
  recovered record, an artifact of a different kind). See [correlation.md](correlation.md).
* **Confidence is computed, never modelled.** A fixed, published set of weighted factors — schema match, structural
  validity, serial-type validity, field consistency, page integrity, source provenance, cross-artifact corroboration,
  timestamp plausibility, raw-byte completeness — combines by a fixed rule into `LOW`/`MEDIUM`/`HIGH`, with hard caps
  (no schema match → `LOW`; `CORRUPTED` → `LOW`; `PARTIAL` capped at `MEDIUM` without two corroborations; a carved
  candidate capped at `MEDIUM`, `LOW` without any). The same bytes always score the same way. Every level ships with the
  factor list and a plain-language sentence.
* **Ground truth for evaluating all of this is physical**, never the recovery algorithm's own output: a deleted row is
  re-encoded exactly as SQLite would write it and searched for in the file's actual bytes. See
  [synthetic_lab.md](synthetic_lab.md) and [evaluation.md](evaluation.md).

## 12. Examiner checklist

1. Verify the source hash independently before ingest and after the case.
2. Read the `INVALID` / `PARTIAL` / `UNVERIFIED` results and skipped entries before relying on any artifact.
3. Treat `PARTIAL` schema scores and `UNKNOWN` fields as uncertainty, not as absence of data.
4. Corroborate significant findings with a second tool and, for anything that matters, the original device or image.
5. A `RECOVERED` or `PARTIAL` record is reconstructed from freed or superseded bytes, not read live — check its
   confidence and the sentence that explains it before relying on it.
6. A `CARVED CANDIDATE` is never evidence on its own. Do not cite one in a finding unless correlation has corroborated
   it with an independent source and that corroboration is stated.
7. The absence of a recovered or carved result is not evidence that nothing was deleted: recoverability depends on the
   acquisition, the filesystem, encryption and how much was subsequently overwritten (`docs/limitations.md`).


## Write protection and handling (operational guidance)

The tool never opens evidence for writing and parses databases only from disposable scratch copies, but **it cannot control the
operating system.** To keep the original provably untouched:

1. **Physical media**: connect through a hardware write blocker; verify the blocker (a known-write test) before use.
2. **Files and images on a workstation**: mount the evidence volume read-only (`mount -o ro,noatime`, or a read-only bind mount /
   `:ro` Docker volume) so even access times are not updated; the Docker image in this repository is designed to run that way
   (`--read-only`, `-v evidence:/evidence:ro`, `--network none`).
3. **Hash first, hash again**: record the acquisition's hash from your acquisition tool; `ingest` records its own and `validate`
   re-checks the originals — a mismatch is an `INVALID` result, not a warning.
4. **Work on a copy** whenever the original is irreplaceable; keep the copy's hash with the case.
5. **Audit trail**: `android-forensics audit-verify CASE` proves the command history has not been edited; record the printed chain
   head in your case notes (or let the signed report carry it) so a later rewrite of the whole log is detectable.
6. **Examiner key hygiene**: keep the report-signing private key off shared servers; use `ANDROID_FORENSICS_KEY_PASSPHRASE`.
