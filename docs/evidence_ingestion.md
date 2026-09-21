# Evidence ingestion

The ingestion subsystem (`android_forensics/acquisition/`) turns an Android acquisition into a hashed, classified,
timestamped inventory — and a manifest — **without ever writing to the evidence**. It is an ordinary library: the CLI and
the case database are thin layers on top, and it works with nothing but a case ID and a working directory.

```python
from android_forensics.acquisition import ingest_evidence, verify_manifest

result = ingest_evidence("./acquisition.tar.gz", workdir="./work", case_id="0123456789abcdef0123456789abcdef")
result.manifest_path            # ./work/evidence_manifest.json   (+ evidence_manifest.json.sha256)
result.files[0].hashes.sha256   # every file: size, MD5, SHA-1, SHA-256, timestamps, kind
result.issues                   # anything skipped or flagged, with the reason
verify_manifest(result.manifest, result.workspace).ok   # re-check the evidence and the working copies later
```

## Accepted input

| Input | How it is read |
|---|---|
| Directory (an extracted filesystem dump) | recursive walk, sorted (deterministic), symlinks never followed |
| `.zip` | member by member, streamed |
| `.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`, `.tar.xz` | sequential stream (`tarfile` `r:*`), members streamed |
| A single SQLite file | plus its adjacent `-wal`, `-shm`, `-journal` |

The type is detected from content (SQLite magic, then `zipfile`, then `tarfile`), not from the extension. Archives are
never unpacked to disk wholesale: each member is streamed through the hasher, and only files the engine must open are copied.

## What happens to each file

1. **Read once**, through a read-only handle (see below).
2. **Hashed** in the same pass with MD5, SHA-1 and SHA-256 (SHA-256 is the integrity anchor; MD5/SHA-1 are recorded for
   compatibility with legacy reference sets only). Archives get a container hash as well.
3. **Classified** from its first bytes (SQLite, WAL, journal, XML, image, encrypted-looking, …).
4. **Recorded** as an `EvidenceFile`: relative path, size, hashes, kind, timestamps and their basis.
5. **Optionally copied** into the working directory (write-protected, mode 0444) — see *preserve policy*.

Evidence of any size streams through bounded memory: `IngestionSession.run()` yields `EvidenceFile` / `AcquisitionIssue`
objects one at a time (the case database drains it in batches of 1,000); `ingest_evidence` collects them for convenience.

## The working analysis directory

```
<workdir>/
├── evidence/s<N>/   write-protected preserved copies (one directory per ingested source; never mixed or overwritten)
├── scratch/         disposable copies for SQLite sessions
├── reports/         generated reports
└── evidence_manifest.json  (+ .sha256)
```

`Workspace` (`android_forensics/workspace.py`) owns the layout. It is created on demand, is reusable across several
sources (`s1`, `s2`, …), and **must not overlap the evidence in either direction** — evidence inside the workspace, the
workspace inside an evidence directory (it would be ingested into itself) and workspace == evidence are all refused
before anything is written.

**Preserve policy** (`PreservePolicy`): `ANALYSIS` (default) copies SQLite databases and sidecars and small text/XML/JSON —
what the analysis engine has to open; `ALL` copies every file (needs disk space for the whole acquisition); `NONE`
hashes only. Later stages label an unpreserved database `not_preserved` / `UNVERIFIED`, never "encrypted" or "invalid".

## "Never modify the original evidence" — what that means here

* Files are opened with `os.open(O_RDONLY)` only — there is no code path that opens evidence for writing.
* `O_NOFOLLOW`: a path that becomes a symlink between enumeration and open is refused, not followed.
* `O_NOATIME` on Linux when the process owns the file, so reading does not update access times. On other platforms a read
  may update the access time; mount evidence read-only or use a write blocker for original media.
* Symlinks, hard links, sockets and device nodes are recorded as issues and never read. Archive members with `..`, absolute
  or drive-letter paths, encrypted zip members and oversized/over-numerous entries (zip-bomb budgets) are rejected and recorded.
* **Change detection.** Each local file's size, modification time and inode are compared at enumeration, at open and
  after the read. If they differ the file is still listed — with the hash of the bytes actually read — but flagged
  `changed_during_read`, because that hash is not a stable identity for the file.
* Re-verification later (`verify_manifest`, the validation stage) re-hashes originals through the same read-only opener.
* Tests hash and timestamp the whole evidence tree before and after ingestion (including directory mtimes), and ingest
  a tree that is physically read-only (`chmod 555/444`).

Everything skipped or suspicious is an `AcquisitionIssue` (never silently dropped) and makes the acquisition-completeness
validation `PARTIAL`; truncated archives and exceeded budgets mark the source `complete = false` (`INVALID`).

| Issue | Meaning |
|---|---|
| `symlink_skipped`, `special_file_skipped` | not read; never followed |
| `unsafe_path_skipped`, `encrypted_member`, `duplicate_member` | archive entry rejected / flagged |
| `unreadable_directory`, `read_error`, `stat_error`, `member_read_error` | could not be read (permissions, CRC error, …) |
| `changed_during_read` | listed, but its hash is not a stable version |
| `archive_unreadable`, `archive_truncated`, `budget_exceeded` | acquisition **incomplete** |
| `invalid_evidence_entry` | an entry failed model validation |

## Timestamps ("where available")

Each file's times carry a **basis** saying how trustworthy they are.

| Source | mtime | atime / ctime | Basis |
|---|---|---|---|
| directory / single file | `stat` | `stat` (ctime = inode change time on POSIX) | `fs_stat` |
| tar | header (UTC epoch, sub-second if PAX) | from PAX extended headers when present | `tar_header_mtime` |
| zip with Info-ZIP `UT` extra field | UTC epoch | — | `zip_extra_field_UT` |
| zip, DOS time only | local time of unknown zone, 2 s resolution, shown as UTC | — | `zip_dos_time (timezone unspecified)` |

All are stored in the canonical form `YYYY-MM-DDTHH:MM:SS.mmmZ`; an unavailable time is `null`, never a guess.

## The manifest

`evidence_manifest.json` (written atomically; `evidence_manifest.json.sha256` beside it in `sha256sum` format):

```json
{
  "manifest_version": 2,
  "case_id": "0123456789abcdef0123456789abcdef",
  "case_name": "example",
  "analysis_timestamp": "2026-09-21T14:16:50.296Z",
  "tool_name": "android-forensics",
  "tool_version": "0.1.0",
  "sources": [{
    "source_id": 1,
    "original_path": "/evidence/acquisition",
    "original_name": "acquisition",
    "source_type": "directory",
    "container_size": null, "container_md5": null, "container_sha1": null, "container_sha256": null,
    "acquisition_time": null,
    "ingested_at": "2026-09-21T14:16:50.290Z",
    "complete": true,
    "file_count": 2,
    "total_bytes": 28,
    "files": [{
      "original_path": "/evidence/acquisition/data/data/com.example/shared_prefs/prefs.xml",
      "relative_path": "data/data/com.example/shared_prefs/prefs.xml",
      "size": 28,
      "md5": "b591295a9f7b44b7aa7d08317e23f0f7",
      "sha1": "9f432a9bb18f4e0ec85f83101dc89d000851f474",
      "sha256": "92caca3da75a5567d17ee9132400e41a94be432565853d42ddad0138d4eded0f",
      "kind": "xml",
      "times": {"mtime": "2024-03-01T08:00:00.000Z", "atime": "2024-03-01T08:01:00.000Z",
                "ctime": "2026-09-21T14:16:50.100Z", "basis": "fs_stat (ctime = inode change time on POSIX)"},
      "preserved_copy": "evidence/s1/0000001_prefs.xml"
    }]
  }]
}
```

| Requirement | Field |
|---|---|
| case ID | `case_id` |
| analysis timestamp | `analysis_timestamp` (UTC) |
| tool version | `tool_version` (+ `tool_name`) |
| original path | source `original_path`; per file `original_path` — `<dir>/<relative>` for directories, `<archive>!/<member>` for archives, beside the main file for single-file sources |
| relative path | per file `relative_path` |
| file size | per file `size` |
| hashes | per file `md5`, `sha1`, `sha256`; archives also `container_*` |

`verify_manifest(manifest, workspace=None)` re-hashes the original files (or the container) and, if a workspace is given, the
preserved copies. It reports `original_/container_/preserved_` `missing`, `modified` or `unreadable` (a symlink counts as
a change), and `original_unlisted` — a file that now exists in a directory source but is not in the manifest. It needs no
case database. The case flow additionally records the manifest's SHA-256 in the hash-chained custody log.

## In a case

`android-forensics ingest CASE PATH [--acquired-at ISO] [--preserve analysis|all|none]` → `ingest_source(store, …)`, which
runs the same session, persists sources/files/issues in `case.db`, writes the manifest for every source in the case and
extends the custody log (`ingest_started` / `ingest_completed`). `--acquired-at` must carry a timezone; an ambiguous
local time is rejected.

## Performance

Measured by `experiments/r1_extraction_accuracy.py` (E3) on 301 MiB of incompressible data (3 × 100 MiB files plus 3,000
small files), computing MD5, SHA-1 and SHA-256 in one pass: directory ≈ 380 MiB/s; directory copying every file ≈ 275 MiB/s;
zip (stored) ≈ 230 MiB/s; tar ≈ 235 MiB/s (SHA-256 alone runs at ≈ 3 GiB/s here — the three-hash pass and per-file
overhead dominate). Single machine, indicative only.

## Limitations

* Only file content and the times listed above are recorded — not permissions, ownership (uid/gid), SELinux labels or
  extended attributes.
* Nested archives are hashed as files, not expanded. Hard links are treated as links (skipped).
* Access-time preservation is best effort off Linux (see above).
* Ingestion is single-threaded; `ALL` needs disk space for the whole acquisition; live-device acquisition (ADB) is out of scope.
* `ingest_evidence` overwrites `evidence_manifest.json` on each call; to describe several sources in one manifest use
  `make_manifest(case_id, name, [(source, files), …])`.

## Tests

`tests/unit/test_ingestion_units.py` (read-only opener, workspace rules, ZIP/TAR timestamp parsers, manifest writer) and
`tests/integration/test_ingestion_subsystem.py` / `test_ingestion_case.py` — all built from small synthetic files: every input
type agrees on paths, sizes and hashes; the manifest carries every required field; the evidence tree is identical
before and after; workspace overlap and reuse; preserve policies; recursion, hidden/unicode/empty/duplicate names;
timestamps per source type; change-during-read; truncated, corrupt, hostile and unreadable input; and verification of
modified, missing, added and symlink-swapped evidence.
