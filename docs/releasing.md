# Releasing

The release workflow (`.github/workflows/release.yml`) builds the wheel/sdist, builds single-file binaries on Linux, macOS and Windows,
publishes to PyPI with **trusted publishing** (no stored token) and attaches everything to a GitHub release. Nothing publishes until you
do the one-time setup below and push a tag.

## One-time setup (needs your accounts — it cannot be done for you)

1. **PyPI project.** Create `android-deleted-data-recovery` on <https://pypi.org> (or reserve the name by uploading once by hand).
2. **Trusted publisher.** In the PyPI project: *Settings → Publishing → Add a new publisher* — GitHub, owner `MithranHarsha`,
   repository `Android-Forensic-Analysis-Toolkit`, workflow `release.yml`, environment `pypi`.
3. **GitHub environment.** Repo *Settings → Environments → New environment* named `pypi` (add required reviewers if you want a manual gate).
4. *(Optional)* **Docs site.** *Settings → Pages → Source: GitHub Actions*, then add the repository variable `PAGES_ENABLED=true`.

## Each release

```bash
# 1. version: pyproject.toml + src/android_forensics/__init__.py (tests/unit/test_packaging.py fails if they disagree)
# 2. CHANGELOG.md: move "Unreleased" under the new version
# 3. everything green locally and in CI
git tag -s v0.3.0 -m "0.3.0" && git push origin v0.3.0       # -s signs the tag with your GPG key
```

Then check, in this order: the workflow's `build`, `binaries` and `publish` jobs; `pip install android-deleted-data-recovery==0.3.0` in a clean
virtualenv followed by `android-forensics --version`; and the GitHub release's binaries (`./android-forensics --version`).

## Verifying what you publish
* `pip-audit --require-hashes -r requirements.lock` is part of CI; re-run it just before tagging (new advisories appear daily).
* Regenerate the lock files when dependencies change: `pip-compile --generate-hashes --strip-extras -o requirements.lock pyproject.toml`
  (and the `requirements-dev.lock` variant with `--extra dev --extra docs --extra e2e --extra binary`).
* Compare the wheel's contents with the previous release (`unzip -l`): templates, `dashboard/web/*` and `py.typed` must be present.
* Container image: `docker build -t android-forensics:0.3.0 .` and run `scripts/test_linux_matrix.sh` first if you can.

## Yanking
A bad release is yanked on PyPI (it stays installable by exact version but is not selected by `pip install android-deleted-data-recovery`), the
GitHub release is edited to say why, and a fixed patch version is tagged. Never delete a published version: reports carry the tool version.
