# Limitations

## Deployment and platform (0.3)

* **Windows: the CLI and test-suite pass on GitHub's Windows runners (3.11–3.13), but the server's job sandbox is POSIX-only and not run there.** Several protections are POSIX-only or best-effort:
  `O_NOFOLLOW`/`O_NOATIME` evidence opening (best-effort elsewhere), `flock` on the audit log (single-writer assumed), and — for the
  server — resource limits and process-group kills (`server/sandbox.py`). Use Linux or macOS, or the Docker image, for casework.
* **Memory limits for analysis jobs are enforced only where `RLIMIT_AS` works (Linux).** macOS ignores it; rely on container limits.
* **The server is single-node.** The job queue and rate limiter live in the process; authentication is by bearer token or, behind a trusted
  proxy, SSO headers (see deployment.md). It has not been load- or penetration-tested by a third party.
* **Evidence graph memory** grows with the number of artifacts (~4.7 KB each at one million), see [performance.md](performance.md).
* **WAL/journal sidecars are read fully into memory**, capped at 1 GiB (`config.MAX_SIDECAR_BYTES`); larger ones are reported, not parsed.

## Disk images and encryption

* ext4 and f2fs are parsed read-only; **deleted files are not recovered at the file-system level**, only deleted records inside
  SQLite databases. Not supported: ext4 `inline_data`/`meta_bg`, f2fs compression, AFF/AFF4, VMDK/VHD, FAT/exFAT SD-card images.
* ext4 **hash-tree (`dir_index`) directories** are read by linear scan (index nodes look like empty entries), which is correct by design but
  was not exercised by a fixture (the fixtures' directories are too small to be indexed); f2fs double-indirect addressing (files > ~8 GiB)
  is likewise untested.
* The ext4/f2fs readers were validated against images produced by one `mke2fs`/`mkfs.f2fs` version and one Linux kernel
  (6.10) and, for corpora, against public acquisitions listed in [validation.md](validation.md); other kernels/vendors vary.
* **Encrypted `/data` is common on real phones.** Detected and reported (`file_based_encryption_detected`, `ENCRYPTED_SUSPECT`),
  never decrypted; an empty result on encrypted evidence is not evidence of absence.

## Typing debt

`mypy` is clean for every module except the ones listed under `[[tool.mypy.overrides]]` in `pyproject.toml` (annotation-only
mismatches such as `sqlite3.Row` vs `Mapping`, optional narrowing). New code must not add to that list.

## Review 2 scope limits (engineering, not fundamental)

* **Recovery does not attempt every table.** Tables with fewer than three stored columns, `WITHOUT ROWID` tables, virtual
  tables and `sqlite_*` tables are not modelled for free-space scanning (`MIN_SCAN_WIDTH`; too little structure to tell a
  genuine row from coincidence, and `WITHOUT ROWID`/virtual cells are not table-leaf cells). Rowids longer than 6 varint
  bytes are not attempted. See [sqlite_recovery.md §7](sqlite_recovery.md#7-when-recovery-is-expected-to-fail--and-why)
  for the measured effect (three documented sub-100% conditions in the 28-case matrix, all where a neighbouring cell's
  own head is also destroyed).
* **A journal-sourced record's checksum verification is not re-derivable after the fact.** `recover` persists each WAL
  frame's precise status, so a WAL-sourced record's provenance factor is scored exactly; the equivalent per-record
  journal checksum is not persisted the same way, so a journal-sourced record's `source_provenance` factor defaults to
  verified rather than being re-checked at reconstruct time (D-021 in `docs/decisions.md`).
* **The synthetic lab's genuine deletions are limited to two databases.** `mmssms.db` and Chromium `History` (both plain
  rollback-journal mode) carry real `DELETE`s with physical ground truth; `calllog.db` (WAL mode) and `contacts2.db`
  (multi-table) are left as Review 1 already built them, since they already exercise other Review 2-relevant conditions
  (WAL history, the application-level `deleted=1` flag) — see [synthetic_lab.md](synthetic_lab.md) and D-031.
* **Carving is a shape match, not a schema match.** A bare digit run is never called a phone number; a binary integer
  timestamp is not carved on its own; a URL is taken up to the first character it cannot contain, so one stored directly
  against the next text column can be reported too long (`context_valid` flags this). See
  [carving.md](carving.md#limits).
* **Correlation matches by identity of a value, not by meaning.** Two people who share a landline share one `PhoneNumber`
  entity; names are matched across artifacts only through a contact's display name appearing inside a carved record. See
  [correlation.md](correlation.md#limits).
* **Confidence calibration was measured on a small synthetic sample** (93 recovered artifacts across three seeds of one
  lab) — see [evaluation.md](evaluation.md#e7--confidence-calibration-and-processing-cost). It demonstrates the scoring
  mechanism works as designed, not a generalisable precision curve.
* **Recovering a database SQLite cannot open still needs a working copy.** Recovery reads raw file bytes directly, so a
  database ingested with `--preserve none` (hash-only) yields nothing to recover from; this is reported, not silently
  skipped.

## Review 1 scope limits (engineering, not fundamental)

* **Damaged databases.** If SQLite refuses to open a file (e.g. truncated below its declared size, malformed root page) no
  active artifacts are produced from it; page-level recovery still attempts it directly. It is reported as `unopenable` with
  a `PARTIAL` header verdict. If damage is *mid-table* and SQLite can still open the file, rows before the damage are kept.
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
* **Platform.** Developed on macOS; the full test-suite runs in GitHub Actions on Linux, macOS and Windows with Python 3.11, 3.12 and 3.13. Performance and the real-corpus runs were measured on one Apple-silicon Mac.
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
