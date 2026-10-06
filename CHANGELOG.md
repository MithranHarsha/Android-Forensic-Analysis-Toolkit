# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/);
the format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.2.0]

### Added
- Review 2 capabilities are now part of the package description and version: deleted/superseded SQLite record
  recovery (freelist, unallocated space, WAL, rollback journal), raw carving, correlation, deterministic confidence.
- Continuous integration (lint, type-check, security scan, dependency audit, 3-OS × 3-Python test matrix, coverage gate).
- `Dockerfile` (non-root, read-only evidence mount), hash-pinned `requirements.lock`, PyInstaller single-file build,
  tagged-release workflow.
- `ruff`, `mypy` and `bandit` configuration in `pyproject.toml`.

### Changed
- `shared_prefs` XML is parsed with `defusedxml` (bandit B314).
- The dashboard frontend now ships **inside** the package (`android_forensics/dashboard/web`), so wheel, Docker and
  binary installs find it. (Fixes limitation D-027.)
- Runtime `requirements.txt` no longer lists test tooling; it moved to the `dev` extra.

## [0.1.0]
- Review 1: evidence ingestion, SQLite discovery/inspection, active artifact extraction, validation, timeline, reporting.
