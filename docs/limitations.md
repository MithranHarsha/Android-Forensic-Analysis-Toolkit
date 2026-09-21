# Limitations

## Review 1 scope limits (engineering, not fundamental)

* **No deleted-data recovery, carving, correlation or confidence scoring** — Review 2. The report says so and lists only
  header-level *indicators* of recovery potential.
* **Damaged databases.** If SQLite refuses to open a file (e.g. truncated below its declared size, malformed root page) no
  artifacts are produced from it. It is reported as `unopenable` with a `PARTIAL` header verdict; salvaging such files needs the
  Review 2 page-level parser. If damage is *mid-table* and SQLite can still open the file, rows before the damage are kept.
* **Discovery classifies; it does not parse.** XML, JSON, log and media files are found, counted and hashed as requested, but their
  content is not interpreted (nor is Android Binary XML). Classification reads the first 4 KiB, so a signature deeper in a file is
  missed. The SQLite detection status (`VALID` …) is a header-and-size check, not an integrity check; `ENCRYPTED_SUSPECT` is an entropy
  heuristic and a lead, not a finding. Application directories are recognised from package-shaped names in known locations. See
  [filesystem_discovery.md](filesystem_discovery.md#limitations).
* **Inspection is of the active view, on a copy.** The inspector reads what SQLite returns; it copies the whole database (and WAL) to a
  scratch directory; `inspect()` keeps every requested record in memory (stream with `iter_records` or cap per table beyond ~100,000
  rows). Android's own collations (`LOCALIZED`, `PHONEBOOK`, `UNICODE`, `LOCALE`) are approximated by a plain comparison, so a healthy
  database with an index that uses one gets integrity `partial` (structure verified; index-to-table consistency not) instead of
  `ok`; a collation an app registers itself is unavailable. Shadow tables of virtual tables are recognised only with SQLite ≥ 3.37.
  See [sqlite_inspection.md](sqlite_inspection.md#limitations).
* **Multi-table artifacts.** A contact needs the `raw_contacts`, `data` and `mimetypes` tables; if reading the `data` table
  fails part-way, that contacts extraction stops and is recorded (no partial contact set).
* **Coverage.** SMS/call/contact/browser schemas as documented in [artifact_formats.md](artifact_formats.md); MMS parts,
  messengers, OEM variants, Firefox, Android Binary XML, media EXIF and key stores are not interpreted. Unknown databases are
  catalogued generically (schema, counts, column hints).
* **SharedPreferences.** Key names only. Values are never extracted (they routinely hold tokens and credentials).
* **Phone matching** uses a heuristic key (trailing ten digits of a plausible number), not E.164 parsing with a numbering plan.
  Short codes and alphanumeric senders are deliberately never matched.
* **Times.** Zip archives carry no timezone (DOS time) — shown as UTC and labelled. File-system times depend on how the
  acquisition was extracted and may have been reset. Timestamp plausibility uses a fixed window (2008-01-01 … now + 2 days).
* **Text.** Non-UTF-8 text is decoded with replacement characters and counted; the original bytes are not preserved in Review 1
  output (they remain in the working copy).
* **Scale.** ≈ 16–18 k artifacts/s (≈ 6 MiB Python memory, flat); the HTML report caps each table at 3,000 rows (JSON and CSV are complete); the SQLite
  scratch copy needs free disk space equal to the largest database.
* **Validation on synthetic data only.** See [evaluation.md](evaluation.md#threats-to-validity).
* **Custody log** is hash-chained inside the case database. It detects edits and deletions but is not signed or externally
  time-stamped; an adversary with write access to the whole case could rebuild it.
* **Platform.** Developed and tested on macOS with Python 3.12; the code is portable (Linux/Windows) but only macOS was run.
  File-permission tests are skipped where the OS ignores permissions; some file systems reject non-UTF-8 names.
* **No ADB acquisition.** Live-device acquisition is out of scope; the tool examines acquisitions.
* **Ingestion records content and times only** — not permissions, uid/gid, SELinux labels or extended attributes; nested archives are hashed, not expanded; hard links are skipped; `O_NOATIME` exists only on Linux, so elsewhere reading may update access times (use a read-only mount or write blocker). See [evidence_ingestion.md](evidence_ingestion.md#limitations).

## What is genuinely impossible (regardless of tool quality)

These limits come from Android, the storage medium and cryptography, and no SQLite-level or carving technique removes them:

* **File-based / full-disk encryption without the key.** Modern Android (FBE, from 7.0 and mandatory from 10) encrypts user data
  per-user with keys bound to the lock-screen credential and hardware-backed keystores. An acquisition of ciphertext, or a
  dump taken without the keys, contains no recoverable plaintext. This tool does not attempt key extraction or lock bypass.
* **App-level encryption** (SQLCipher, encrypted message stores): unreadable without the app's key; only reportable.
* **TRIM / garbage collection / wear levelling.** On eMMC/UFS flash, freed blocks are discarded and erased in the background;
  once erased, data is gone from the medium (and often before an image is taken). Filesystem-level recovery of deleted *files*
  is unavailable on most modern devices.
* **Overwriting.** Data overwritten by later writes — reused freelist pages, rewritten WAL frames, vacuumed databases,
  `secure_delete` zero-fill — cannot be reconstructed.
* **Auto-vacuum / VACUUM.** Databases compacted at commit or by `VACUUM` no longer hold DB-file remnants of deleted rows.
* **Missing acquisition content.** A logical acquisition (e.g. backup-based) omits databases, sidecar files and unallocated
  space that a physical/full-filesystem acquisition contains; what was not acquired cannot be analysed.
* **Server-side data** (cloud accounts, provider retention) is outside any device acquisition.

Because recoverability depends on all of these, the absence of recovered data never proves that data never existed.
