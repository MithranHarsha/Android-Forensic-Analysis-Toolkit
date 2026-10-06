# Examiner's guide

A practical walk-through for someone who has an Android acquisition and needs a defensible report. For design details see the
other documents in this folder; for the web service see [deployment.md](deployment.md).

## 1. Install

```bash
pip install android-deleted-data-recovery            # or:  docker pull / build (see Dockerfile), or download the single-file binary
android-forensics --version
```

Work on a workstation or VM with the evidence mounted **read-only** (or use a hardware write-blocker for original media). The tool
never writes to evidence, but your operating system may update access times when files are read.

## 2. One-time setup (optional but recommended)

```bash
android-forensics keygen                              # an Ed25519 key for signing reports (keep the private key safe)
```

and a `~/.config/android-forensics/config.toml` so your details are filled in automatically:

```toml
cases_dir = "/cases"

[examiner]
name = "Dr. Jane Doe"
title = "Senior Digital Forensic Examiner"
organisation = "State Forensic Laboratory"
accreditation = "ISO/IEC 17025:2017, cert. 1234"

[report]
agency = "City Police Department"
classification = "LAW ENFORCEMENT SENSITIVE"
```

## 3. Examine

```bash
# a directory dump, ZIP/TAR, raw or sparse image, E01 — anything the tool accepts
android-forensics init-case case-2026-042 --detail case_number=2026-042 --detail evidence_description="Pixel 6, S/N …"
android-forensics ingest  case-2026-042 /evidence/userdata.img
android-forensics analyze case-2026-042 --no-report          # scan → extract → recover → carve → correlate → validate → timeline
android-forensics report  case-2026-042 --format html,pdf,json,csv --sign --signer "Dr. Jane Doe"
```

Or in one step for a quick look: `android-forensics analyze /evidence/dump.tar.gz --name quick1`.

Things to look at before you trust a result:

| Command | Why |
|---|---|
| `android-forensics info CASE` | evidence sources, hashes, **scan issues** (encrypted directories, skipped symlinks, unsupported file systems), custody chain |
| `android-forensics validate CASE` | 15 automated checks; read every `INVALID` / `PARTIAL` / `UNVERIFIED` |
| `android-forensics audit-verify CASE` | proves the command history of the case has not been edited |
| `android-forensics artifacts CASE --status RECOVERED --show 1` | one recovered record with its physical location, raw bytes, confidence and the sentence that justifies it |

## 4. Reading the results

Five categories are **never merged**: `ACTIVE` (live in the database), `RECOVERED` (deleted, fully reconstructed), `PARTIAL`
(deleted; some fields lost — shown as `UNKNOWN`, never guessed), `CORRUPTED`, and `CARVED CANDIDATE` (a pattern in raw bytes;
*never* confirmed evidence and never `HIGH` confidence). The confidence level is a fixed, explainable calculation (schema match,
structural validity, provenance, corroboration, completeness, timestamp plausibility) — **not** a probability.

**If the evidence is encrypted** (file-based encryption is the norm on modern phones) the report says so and lists the affected
directories; nothing inside them is parsed. An empty result on encrypted evidence is *not* evidence of absence.

## 5. Verify and hand over

```bash
android-forensics verify-report cases/case-2026-042/reports/report-… --trusted-key jane.pub.pem
```

prints `VALID` only if every file hash matches *and* the Ed25519 signature checks *and* the signer is the key you pinned. Give the
recipient the report directory and your **public** key through a separate channel.

## 6. Add case details for court

```bash
android-forensics case-details case-2026-042 --set requested_by="Det. A. Smith" --set evidence_received_on=2026-09-30 \
    --set statement="I certify that this report accurately describes the examination performed."
```

appear in the report with the examiner's credentials and a signature block. Every change is written to the custody log.

## 7. Troubleshooting

| Symptom | Likely cause / action |
|---|---|
| `0 artifacts` | evidence is encrypted (see `info`), the layout was not recognised (`discover PATH`), or databases are under unusual names — the schema probe scores columns, not file names |
| `filesystem_not_recognised` for a partition | FAT/other/encrypted; extract it separately |
| `acquisition INCOMPLETE` | truncated archive, missing E01 segment, size/entry budget hit — see the issue list; the validation stage will fail loudly |
| `image_hash_mismatch` | the E01's stored hash differs from the recomputed one: the image was altered or damaged after acquisition |
| slow / large memory | see [performance.md](performance.md); `--no-rehash` skips the validation re-hash, `--no-recover` skips Review 2 stages |
| a plugin misbehaves | `--plugin` files are code; see [plugins.md](plugins.md). Failures are recorded as `parser_plugin_error` and do not stop the run |
