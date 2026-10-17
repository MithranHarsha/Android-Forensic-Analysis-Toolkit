# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/);
the format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- The test suite segfaulted at interpreter shutdown (PySide6/Shiboken, exit code 139 *after* every test had passed) whenever the
  desktop-app tests ran before another test module, which is the default collection order. The windows those tests build were left
  for Python's garbage collector to free at an arbitrary later moment; they are now destroyed while the application is still alive.

### Changed
- The desktop app's first tab listed *every* artifact — 8,584 of them on the synthetic lab — under the heading "Active data", when only
  340 of those were active and the other 8,244 had been recovered from deleted or superseded bytes. The tab is now "Artifacts", the
  overview leads with a breakdown by status, and a footnote says plainly which statuses were never live in the database.
- `scripts/make_screenshots.py` also captures the desktop window (off-screen, from the real widgets): `… desktop`, `… web`, or both.

### Documentation
- README: the desktop app is described in its own section instead of a paragraph under *Installation*, and is listed among the ways
  the toolkit runs; the architecture diagram shows all three front ends and the commands 0.3 added; `gui/`, `packaging/macos/`,
  `scripts/` and the root documents appear in the project tree; a *Where to read next* table points at the changelog, the threat
  model and the design decisions. Corrected: the number of validation checks (ten, emitting 14 kinds of result — not 15),
  the browser-visit count in the sample `analyze` output (138), and the test and coverage figures.
- The review-stage framing ("Review 1", "Review 2", "Phase 17") is gone from the README and from everything the tool prints: the
  `analyze` panels, `--help` text, and the report banners, which now name what ran — *Full pipeline* or *Extraction only* — rather
  than which review it belonged to. `docs/`, the two PDFs and the committed acceptance report still use the old wording.

## [0.3.0] — deployable release

0.2.0 was never published; everything since 0.1.0 is described here.

### Added
- **Disk images**: raw / Android-sparse / EnCase **E01** (multi-segment, checksummed, stored-hash verification); GPT and MBR; read-only
  **ext2/3/4** and **f2fs** parsers hardened for hostile input (f2fs validated against images written by a real kernel, including the
  NAT-journal override); file-based-encryption detection (`file_based_encryption_*` issues).
- **Chain of custody**: external append-only hash-chained audit log of every command (`audit-verify`), Ed25519 report signing
  (`keygen`, `report --sign`, `verify-report`), build/dependency/plugin stamp in every report.
- **Authenticated multi-case server** (`serve`, `server-token`): roles, token auth, rate limiting and lockout, strict CSP and security
  headers, streamed uploads, sandboxed resource-limited analysis jobs, server audit log, browser UI.
- **Parser plugins** (`--plugin`, entry points) with SHA-256 attribution; **config file**; **structured logging**; **case details** and an
  examiner certification block for court-oriented reports.
- **Assurance**: property-based fuzzing, mutated-image tests, archive-bomb/injection/XSS/control-character tests, sandbox tests, a
  real-browser end-to-end test; cross-tool comparison (`experiments/v2_cross_tool.py`), real-corpus validation
  (`experiments/v1_real_corpus.py`), scaling benchmark (`experiments/b1_scaling.py`).
- **Packaging/ops**: hash-pinned lock files, non-root read-only Docker image, PyInstaller single-file binary, GitHub Actions (lint, types,
  bandit, pip-audit, 3-OS x 3-Python tests, e2e, nightly fuzz, docker, binaries, docs, release), docker-compose + Caddy/nginx/systemd, MkDocs site.

### Changed
- **`--workers N|auto`** runs recovery and carving on several processes (4× on a real corpus) with results identical to a serial run.
- Google Messages (`bugle_db`) parser; HTML report tables capped with whole-case summaries; evidence-graph edges stored as tuples (-31% peak memory).
- `shared_prefs` XML is parsed with `defusedxml`; SQLite evidence copies are opened with a **read-only authorizer**, `trusted_schema=OFF`,
  a heap cap and per-statement deadlines; the CLI console neutralises control characters in evidence text.
- The dashboard frontend ships **inside** the package (wheel/Docker/binary installs now work) and is CSP-clean (no inline script/style).
- Recovery scanning is 7–10x faster on real databases (cell header parsed once per offset, not once per table); the carver's neighbour
  search is O(log n) instead of O(n) per hit; correlation keeps only the facts it needs (~15 GB -> ~4.7 GB per million artifacts).
- WAL/journal sidecars over 1 GiB are reported instead of read into memory.
- Runtime `requirements.txt` no longer lists test tooling (moved to the `dev` extra).

### Added (post-release hardening)
- Native desktop application (`android_forensics.gui`, `android-forensics-gui`, extra `gui`, macOS bundle builder in `packaging/macos/`): case library, drag-and-drop analysis with progress, filterable result tables.
- Single sign-on through a trusted reverse proxy (`--sso-*`), passphrase-from-file for signing keys, HTTP fuzzing of the server, `reconstruct` commits in batches and recovery de-duplication is indexed (the two hot spots GitHub's Windows runners exposed).

### Fixed
- DDL parser raised `IndexError` on malformed `CREATE TABLE` text (found by fuzzing); now always `DdlError`.
- A test opened the shared synthetic evidence with SQLite directly (creating `-shm` files); it now works on a copy.

### Known limitations
- The server's job sandbox is POSIX-only (the rest passes CI on Windows); encrypted `/data` is reported, not decrypted; f2fs compression and ext4 `inline_data` unsupported; the Linux test
  matrix and compose smoke test could not be run in the development environment (see `scripts/test_linux_matrix.sh`).


## [0.2.0] — unreleased (folded into 0.3.0)

### Added
- Review 2 capabilities are now part of the package description and version: deleted/superseded SQLite record
  recovery (freelist, unallocated space, WAL, rollback journal), raw carving, correlation, deterministic confidence.
- Continuous integration (lint, type-check, security scan, dependency audit, 3-OS × 3-Python test matrix, coverage gate).
- `Dockerfile` (non-root, read-only evidence mount), hash-pinned `requirements.lock`, PyInstaller single-file build,
  tagged-release workflow.
- `ruff`, `mypy` (every module, no exemptions: the former 24-module override list was removed and its 61 type errors fixed) and `bandit` configuration in `pyproject.toml`.

### Changed
- `shared_prefs` XML is parsed with `defusedxml` (bandit B314).
- The dashboard frontend now ships **inside** the package (`android_forensics/dashboard/web`), so wheel, Docker and
  binary installs find it. (Fixes limitation D-027.)
- Runtime `requirements.txt` no longer lists test tooling; it moved to the `dev` extra.

## [0.1.0]
- Review 1: evidence ingestion, SQLite discovery/inspection, active artifact extraction, validation, timeline, reporting.
