# Android filesystem discovery

Discovery answers one question about an ingested evidence tree: **what is in it, and where would it sit on the phone?**
It walks the tree, classifies every file by content, finds SQLite databases together with their WAL / SHM / journal files,
groups files into Android application directories, and lists everything odd it meets. It observes only — it never parses
artifact content and does not recover deleted records (Review 2).

Nothing in it assumes that a particular Android directory exists. `/data/data`, `/data/user/0`, `/storage/emulated/0` and
`/sdcard` are recognised when present and reported as *absent* (informationally, never as an error) when not.

## Entry points

| Use | Call | Notes |
|---|---|---|
| Standalone, no case | `android-forensics discover PATH` · `scan_directory(path)` | Reads the directory (read-only), returns a typed `FilesystemScan`. Needs no database. |
| Case pipeline | `android-forensics scan CASE` · stage `scan` (`scan_filesystem(store)`) | Works from the inventory ingestion already hashed and classified, so the evidence is not read twice; persists the result. |
| Pure analysis | `analyze_files(observations, directories)` | No I/O. Both entry points above call it, so their answers agree by construction. |

```python
from android_forensics.filesystem.scanner import scan_directory

scan = scan_directory("./dump")                    # DiscoveryError only if ./dump is missing or not a directory
for db in scan.databases:
    print(db.path, db.size, db.sha256, db.status.value, [s.path for s in db.sidecars])
print(scan.layout.layout, scan.layout.roots_present, scan.layout.roots_absent)
print(scan.category_counts, len(scan.app_directories), len(scan.issues))
```

```bash
android-forensics discover ./dump                  # summary tables
android-forensics discover ./dump --files          # + every file with its classification
android-forensics discover ./dump --json           # the complete scan (FilesystemScan) as JSON
android-forensics discover ./dump --hash-all       # SHA-256 every file, not only databases and their sidecars
```

`scan_directory` hashes (SHA-256) every database and sidecar by default; `hash_all=True` hashes everything;
`include_files=False` drops the per-file list for very large trees while keeping every aggregate.

## What is classified

Classification is by **content signature first**; names are hints (Chrome's `History` has no extension, and a renamed `.jpg`
can be a database). Only the first 4 KiB of a file is read for this.

| Category | File kinds | How it is recognised |
|---|---|---|
| `database` | `sqlite_db`, `db_unrecognised`, `encrypted_suspect` | `SQLite format 3\0` header at offset 0 — **any name**. A database-like name (`.db`, `.sqlite`, `.sqlite3`, `.db3`, `.sqlitedb`, `.sdb`, `.crypt*`, `.enc`, …) without that header is still reported as a database record, with a status saying why it is not one |
| `sqlite_wal` | `sqlite_wal` | name ends `-wal`; header magic `0x377f0682/3` checked and reported (`valid` / `MISMATCH` / empty). A WAL magic under another name is recognised by content |
| `sqlite_shm` | `sqlite_shm` | name ends `-shm` |
| `sqlite_journal` | `sqlite_journal` | name ends `-journal`; magic `d9d505f920a163d7` checked (a zeroed header is normal in PERSIST mode and is noted, not condemned) |
| `xml` | `xml`, `xml_binary` | a `<?xml` prefix (any name), `<` at the start of a file named `.xml`, or printable text named `.xml`. Android Binary XML (`ABX\0`) is classified and flagged as **not parsed** |
| `json` | `json` | `.json` name and a leading `{` or `[` |
| `log` | `log` | printable text named `*.log`, `*.log.N/old/bak/txt`, `logcat*`, `dmesg`, `last_kmsg`, `tombstone_N`, `anr_*`, or living in a `logs`, `logcat`, `anr`, `tombstones`, `dropbox`, `crash` directory. Log content is not parsed |
| `media` | `image`, `video`, `audio` | signatures: JPEG, PNG, GIF, WebP, TIFF, HEIF/AVIF (by brand), MP4/3GP/MOV, M4A, WAV, AVI, Matroska/WebM, Ogg, FLAC, MP3, AMR. If no signature matches, the extension is used and the detail says *"media by extension only"* |
| `other` | `text`, `apk`, `archive`, `empty`, `unknown` | everything else |

A file that cannot be opened is still listed, with `readable = false`, classified by name only, and said to be so.

**Android application directories** are not files but groups of them: `<root>/<package>/…` under `data/data`,
`data/user/N`, `data/user_de/N` (private app data), `Android/{data,media,obb}/<package>` on shared storage, and
`data/app/…/<package>-<suffix>` (installed APKs). A bare `<package>/databases/…` tree (a dump of app directories with no
Android root above them) is recognised too.

## The Android path model

Every path is located independently, so one evidence directory may hold several dumps, prefixed dumps, or fragments.

* **Strong roots** — `data/data`, `data/user/N`, `data/user_de/N`, `data/system*`, `data/misc*`, `data/media/N`, `data/app`,
  `storage/emulated/N`, `storage/self/primary`, `storage/<XXXX-XXXX>` (removable card), `sdcard*`, `mnt/sdcard`, `mnt/user/N`.
  The *earliest* strong marker in a path defines its **acquisition root**; whatever precedes it (`userdata/`, `phoneA/`, an
  examiner's folder name) is the dump's prefix.
* **Weak roots** — `system`, `vendor`, `cache` — count only at the top of a dump. `com.foo/cache/x` is an app's cache directory,
  not a cache partition.
* Anything else is `unrecognised_layout`; no Android location is invented for it.
* Layouts reported: `android_root`, `android_root_with_prefix`, `multiple_roots`, `app_directories`, `loose_files`, with the
  proportion of files supporting the finding.

Each file and database carries `logical_path` (the path *as it would be on the device*, e.g.
`/data/data/com.example.chat/databases/chat.db`), `area` (`app_internal`, `app_internal_de`, `app_external`, `shared_storage`,
`system`, `app_binary`, `system_partition`, `cache_partition`, `app_directory_dump`, `unrecognised_layout`), `android_root`,
`package` and `user_id`.

Deliberate conservatism:

* `user_id` is `None` under `/data/data`. On a device that directory is user 0's, but the *path* does not say so and the tool
  does not claim more than the evidence shows.
* `data/data/<pkg>` and `data/user/0/<pkg>` are the same directory on a device (one is a symlink to the other). If **both** are
  present in the evidence, an `app_directory_alias` issue records whether their contents are identical (compared by SHA-256) or
  **different**, or that they could not be compared. Other users' directories are never treated as aliases.
* Case-sensitivity is not guessed: a sidecar `x.DB-wal` does not attach to `x.db`.

## SQLite detection status

Determined from the file's bytes only — the SQLite engine is not involved. (The engine-level result — did SQLite open it,
`integrity_check`, table catalogue — is a separate stage and a separate column, `databases.open_status`.)

| Status | Meaning |
|---|---|
| `VALID` | SQLite magic and a structurally valid header (power-of-two page size 512–65536, text encoding 1–3, schema format 1–4, payload fractions 64/32/32, usable page size ≥ 480, freelist count within the page count), and a file that is at least as long as the header declares and a whole number of pages. **This is not an integrity guarantee** — it says the header and size are consistent. (A database that has never had a table leaves the text-encoding and schema-format fields both 0; that is valid and noted, not corrupt.) |
| `TRUNCATED` | Header valid, but the file is shorter than the header declares, or ends in the middle of a page |
| `CORRUPT_HEADER` | SQLite magic present but at least one of the header checks above fails; the detail lists which |
| `NOT_SQLITE` | Database-like name, no SQLite magic, ordinary entropy (text, zeros, other format, overwritten) |
| `ENCRYPTED_SUSPECT` | Database-like name, no SQLite magic, entropy ≥ 7.2 bits/byte over the first 4 KiB (at least 1 KiB must exist; a shorter file is `NOT_SQLITE`). Reported and **never opened or decrypted** |
| `EMPTY` | Zero-length file with a database name |
| `UNREADABLE` | The file could not be read (permissions, I/O error) |
| `UNVERIFIED` | Magic present but the header was not inspected (no readable working copy, e.g. ingested with `--preserve none`) |

`is_sqlite` is true for `VALID`, `TRUNCATED`, `CORRUPT_HEADER` and `UNVERIFIED` — files that *are* SQLite files, whatever their
condition. Each status has a human-readable `detail` (for example *"12288 bytes on disk but the header implies 24576"*).

## The database record

For every database-like file:

| Field | |
|---|---|
| `path`, `size`, `sha256` | evidence-relative path, bytes, SHA-256 (`null` only if it could not be read) |
| `status`, `detail` | the detection status and why |
| `logical_path`, `package`, `area`, `user_id` | Android attribution |
| `page_size`, `page_count`, `text_encoding`, `journal_mode`, `freelist_pages` | header facts when the header is valid |
| `sidecars` | at most one each of WAL, SHM, journal: `kind`, `path`, `size`, `sha256`, `header_valid` (`true`/`false`/`null` = not determinable), `note` |
| `evidence_file_id` | link to the ingested inventory (case pipeline) |

**Association rule.** A sidecar belongs to the database with the same directory and name plus `-wal`, `-shm` or `-journal`
(exact, case-sensitive). That is SQLite's own convention, so extension-less databases such as Chrome's `History` and
`History-journal` associate correctly and a sidecar never attaches to a same-named database in another directory.

A sidecar that finds no database is an **orphan**: it is listed (`orphan_sidecars`) with the reason — *no database named …*,
*its base file exists but is not a database (text)*, or *its name does not follow the convention* — and raises an
`orphan_sidecar` issue. Orphans are reported, never attached by guesswork.

## Issues

Problems are data, not exceptions; the scan always finishes.

| Issue | Raised when |
|---|---|
| `database_empty` · `database_truncated` · `database_corrupt_header` · `db_unrecognised` · `encrypted_suspect` · `database_unreadable` | the corresponding status above |
| `orphan_sidecar` · `sidecar_header_invalid` | a sidecar with no database · a WAL/journal whose magic is wrong |
| `binary_xml_not_parsed` | Android Binary XML found |
| `unreadable_file` · `unreadable_directory` · `stat_error` | permissions or I/O errors |
| `vanished` | a file or directory disappeared during the scan |
| `symlink_skipped` · `dangling_symlink` · `special_file_skipped` | symlinks (never followed), sockets/devices/FIFOs (never opened) |
| `app_directory_alias` · `multiple_dumps` · `layout_unrecognised` | layout oddities described above |
| `database_unopenable` · `database_integrity_failure` | **case pipeline only** — SQLite itself refused the file, or `integrity_check` failed. Additive to the byte-level issues: a truncated database may be both `database_truncated` and `database_unopenable` |

## Handling of missing, unreadable, corrupt and unusual input

| Situation | Behaviour |
|---|---|
| Expected directory absent (`data/data`, `sdcard`, …) | Not an error. Listed in `layout.roots_absent`; discovery proceeds with what exists |
| Evidence has only `sdcard`, only one app, or only databases | Scanned normally |
| Empty evidence directory / only empty directories | Empty result; app directories with no files still appear |
| Evidence root missing, or a file | `DiscoveryError` with a clear message (the only condition that stops a scan) |
| Unreadable file | Kept in the inventory (`readable = false`, `sha256 = null`), classified by name, `unreadable_file` / `database_unreadable` issue |
| Unreadable directory | `unreadable_directory` issue; siblings and the rest of the tree are scanned |
| Truncated / zero-length / corrupt / encrypted / non-SQLite database | Still a database record with size and SHA-256 and a precise status |
| Read error while hashing | The file becomes `UNREADABLE`; the scan continues |
| File deleted during the scan | `vanished` issue |
| Symlinks (including dangling), FIFOs, sockets, devices | Reported and skipped; **nothing outside the evidence tree is ever read**, and a FIFO is never opened (which would block) |
| Two dumps, a prefixed dump, bare app directories, a loose file set | Recognised as such; app directories and databases are kept apart per dump |
| Non-UTF-8 or bracketed file names | Bracketed names are kept and shown verbatim. Undecodable bytes are stored as `\xNN` escapes so the path can be stored and displayed |

Files are opened `O_RDONLY | O_NOFOLLOW` (plus `O_NOATIME` on Linux where allowed). The tests hash the whole tree before and
after a scan and check that nothing changed and that no `-shm`/`-wal` files appeared (which opening a database in SQLite can cause;
discovery never opens one).

## Persistence (case pipeline)

The `scan` stage stores: `evidence_files.logical_path / android_root / user_id / package`; the `app_directories` table (package,
path, logical path, root, area, user, well-known application, subdirectories, file / byte / database counts, kind counts);
`databases.sqlite_status / sqlite_status_detail` beside the engine-level `open_status` (produced by running the [SQLite inspector](sqlite_inspection.md) on each database); and `scan_issues` (stage `scan`). Re-running
`scan` replaces these rather than duplicating them and invalidates the stages built on it. The report has an *Android application
directories* section and a Detection / Sidecars column for databases.

## Showing evidence text

File names, package names and message bodies are untrusted and may contain square brackets. Rich would read `[backup]` as a
style tag and silently drop it — displaying `notes.txt` for a file that is really named `[backup]notes.txt` — and `[/]` would
raise. Every table cell and panel in the CLI therefore renders evidence text as plain text (`SafeTable`, `plain_panel`,
`Text`), `--json` output is verbatim, and `tests/integration/test_cli_evidence_text.py` guards it.

## Limitations

* Discovery classifies and describes; it does not parse XML, JSON, logs, media metadata or ABX. Those files are listed and counted.
* `VALID` is a header and size check. A database can be `VALID` here and still fail `integrity_check` in the engine stage.
* Only the first 4 KiB of a file is examined to classify it: a file whose signature lies deeper, or a log with a binary preamble,
  is `unknown` or `other`. Classification by extension is used only when no signature or text heuristic applies, and says so.
* `ENCRYPTED_SUSPECT` is an entropy heuristic over 4 KiB: it can be wrong for compressed or random-looking non-encrypted files, and it
  cannot tell SQLCipher from any other cipher. It is a lead, not a finding.
* Android application directories are recognised from package-shaped names (`com.example.app`) in known locations. An app whose
  directory name is not package-shaped (some OEM system paths) is still classified file by file but is not grouped.
* Permissions, ownership, SELinux labels and extended attributes are not recorded (see `evidence_ingestion.md`).
* A path is attributed to the Android filesystem only as far as the evidence shows; for an unrecognised layout `logical_path`
  is just the evidence-relative path and `area` says `unrecognised_layout`.

## Tests

`tests/unit/test_discovery_classification.py` (kinds, categories, signatures, sidecar naming), `test_android_layout.py` (every root,
user IDs, prefixes, multiple dumps, bare apps, weak roots, lookalike names), `test_discovery_analysis.py` (every status, association,
orphans, aliases, determinism, model invariants), `tests/integration/test_filesystem_scanner.py` (real trees: every requested category,
every kind of damage, missing / unreadable / vanishing / symlinked / special entries, read-only guarantee), `test_scan_stage.py`
(persistence, agreement with the standalone scanner, archive equals directory, re-runs, `discover` CLI) and
`test_cli_evidence_text.py`.
