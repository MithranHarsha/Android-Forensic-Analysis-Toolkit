# Validation — what has been shown, and what has not

Validation here is a **ladder of evidence of increasing realism**. Each rung is reproducible from this repository; each states what it
can and cannot support. Nothing below is a certification, and nothing is "validated" beyond the specific data listed.

| Rung | Data | Answers | Where |
|---|---|---|---|
| 1 | Synthetic Android lab with exact ground truth | Is the implementation correct against known answers? | [evaluation.md](evaluation.md) (`r1_*`, `r2_*`) |
| 2 | Kernel- and `mkfs`-written ext4/f2fs/E01 fixtures | Do the image/file-system readers return exactly what was written? | `tests/unit/test_ext4_images.py`, `test_f2fs_images.py`, `test_ewf.py` |
| 3 | Fuzzing, mutated images, hostile archives/evidence | Does hostile input produce a declared error instead of a crash, hang or escape? | `tests/security/` |
| 4 | **Cross-tool comparison** on the 28-condition deletion matrix | How does recovery compare with other tools on identical files? | below (V2) |
| 5 | **A real public acquisition** (Android 9, Pixel 3) | Does it work end to end on messy real data, and agree with an independent list? | below (V1) |

## V2 — comparison with reference recovery tools (`experiments/v2_cross_tool.py`)

*Measured with the 0.2.0 development build, before the 0.3.0 scan speed-up; that change was proven result-identical against the original algorithm and the 28-case matrix test still asserts the same recall.*

Four tools see the same 28 matrix cases (12 deletion conditions × positions, record sizes, page sizes, overwrite levels). The ground truth is
**physical**: for each deleted row the lab re-encodes the cell exactly as SQLite wrote it and searches the files for those bytes, so
"recoverable" never depends on any tool. A tool is credited with a row when the row's unique token appears in its output outside the live
data. 511 rows are physically recoverable.

| Tool | Version / mode | Recall of the 511 |
|---|---|---:|
| **this tool** | page-level engine, main file + WAL + journal | **507 (99.2 %)** |
| DC3 SQLite Dissect | 1.0.0, `-c -f` (carve + freelist), WAL/journal aware | 469 (91.8 %) |
| undark | inflex/undark master, `--freespace` | 223 (43.6 %) |
| SQLite `.recover` | sqlite3 3.51.0 | 9 (1.8 %) — it targets *corrupt* databases, not deleted rows; included for context only |

By condition (rows found / recoverable): the other tools lose most heavily on **WAL history** (Dissect 0/25, undark 0/25, `.recover` 0/25
— this tool 25/25), on **rollback-journal** and **UPDATE**-superseded versions (undark 0–16/25), and on **randomly scattered** deletions
(undark 3/25, Dissect 16/25). Dissect matches this tool on most other conditions. Per-case numbers: `experiments/results/v2_cross_tool.csv`.

**How far this can be trusted.**
* The matrix was designed and tuned **alongside this tool**, so the conditions emphasise what it handles; a different author's matrix could
  rank the tools differently. It shows *relative behaviour on these conditions*, not general superiority.
* Token matching credits a tool for finding the bytes, not for presenting a correct, attributed record (this tool also reports status,
  confidence and provenance; the others report text).
* Only recall is comparable across the tools; precision is reported for this tool alone (0 false positives on the matrix, `evaluation.md`).
* Tool versions and options were the defaults a newcomer would use; a specialist might extract more from each.

## V1 — a real acquisition: Digital Corpora *Android 9* (Pixel 3), J. Hickman

Source: <https://digitalcorpora.org/corpora/cell-phones/android-9/> (`android_9.tar.gz`, 4.48 GB; contains `Google Pixel 3.tar`, a logical
extraction of the decrypted `/data` partition, plus the author's documentation and message lists). The accounts and credentials in the
author's documentation are synthetic test data and are not reproduced here. Script: `experiments/v1_real_corpus.py`;
results: `experiments/results/v1_pixel3_android9.json|_fidelity.csv`, `v1_sms_vs_reference.json`.

### Integrity and run profile

| Check | Result |
|---|---|
| Container SHA-256 of `Google Pixel 3.tar` computed by the tool | `4d79fbca…678e15` — **equal to the hash the dataset author publishes** |
| Files / bytes ingested | 28,977 files, 7.4 GB (streamed from the tar; nothing extracted to disk except databases and small text) |
| Databases found | 605: **576 readable**, 26 flagged `encrypted_suspect` (high-entropy, no SQLite header), 3 not SQLite |
| Full pipeline (ingest + hash + scan → … → timeline) | **546 s, 2.6 GB peak** (Apple M-series, 1 core); stage times in `v1_pixel3_android9_run.json` |
| Validation checks | 3,703 → VALID 2,407 · PARTIAL 30 · UNVERIFIED 1,261 · **INVALID 5** (3 files with no SQLite header; 2 FTS4 integrity failures) |
| Artifacts | active 376 (SMS 208, calls 11, contacts 9, browser 23 + 1 download, app summaries 124) · recovered 21,129 · carved candidates 249,372 |
| Confidence of what was recovered | RECOVERED: 12,818 MEDIUM, 6,627 LOW, **1 HIGH**; PARTIAL 672 MEDIUM / 340 LOW; CORRUPTED 671 LOW. Carved: 248,092 LOW, 1,280 MEDIUM, **0 HIGH** (never allowed) |

### Active-extraction fidelity

For every table a parser claimed, the number of ACTIVE artifacts was compared with the row count SQLite itself reports on the same bytes
(WAL and hot journal applied): **11 of 11 tables match, 243 of 243 rows.** (Chrome's `urls` table is compared as "URLs with no visit",
because the browser parser emits one artifact per *visit* plus one per visit-less URL.)

### Messages: agreement with the image author's own list (`SMS Messages.xlsx`)

The list (produced with a commercial tool, with a *Deleted* column) contains 35 distinct SMS.

| Reference messages | Found by this tool |
|---|---|
| 30 live, with a telephony `mmssms.db` source | **30 / 30 ACTIVE** |
| 4 flagged *deleted* | **2 RECOVERED** (`"Got it."`, a Messenger verification code — both from the WAL of Google Play services' `icing_mmssms.db`); 2 not found |
| 1 live, Google-Messages-only | not found |

The 3 misses exist only in `bugle_db`, **Google Messages' private database, for which this tool has no parser** (and the list itself has
empty bodies for them). The tool created **no SMS that is not in the author's list**: of its SMS artifacts, 208 are ACTIVE and exactly 2 are
RECOVERED, and both match the reference — 2 of 2 recovered messages correct, 2 of 4 deleted messages found.

### What the real data taught (and what changed because of it)

| Finding | Action |
|---|---|
| Recovery of 605 databases did not finish in 35 minutes: the byte-offset scan re-parsed each cell header once **per table** (real databases have dozens) | header parsed once per offset; **7–10× faster** on the worst files, identical results (proved against the original on 10,000+ offsets); whole recovery stage now **3 min** |
| The file-based-encryption detector flagged **7 cache directories of a decrypted image** (apps name cache files after base64 SHA digests) | restricted to block-aligned ciphertext lengths directly under an encryption-policy root; regression tests built from the real pattern; the real corpus now yields 0 findings |
| 249k carved candidates | expected for browser/app caches; all `CARVED CANDIDATE`, none HIGH, 99.5 % LOW. Filter by confidence/kind in the report |
| The image holds the data directories of WhatsApp, Telegram, Signal, Viber, Facebook Messenger, TikTok, Snapchat, LINE and Twitter | **no app-specific parsers**: where their databases were readable they were handled generically (tables catalogued; deleted rows as generic records). The plugin API ([plugins.md](plugins.md)) is the route to add them |

### Comparison with reference tools on this corpus — inconclusive

The same recovered content was compared with SQLite Dissect and `.recover` on the 25 databases with the most recovered records. **No claim is
made from it.** Dissect re-emits live data in forms a text-token filter cannot match (blobs, JSON, a 42,000-value map cache), `.recover`
finds nothing on deletions, and with no ground truth for the author's real deletions, "overlap" is not accuracy (75 of this tool's 2,161
deleted-only values were also reported by Dissect; Dissect reported 84,400, most of them evidently re-encoded live data). The raw numbers
remain in the JSON for anyone who wants to build a better comparison.

## What has **not** been validated

* **Other devices and versions.** One Pixel 3 on Android 9. The corpus also offers Android 7, 8, 10, 11 and 13 images; they were not run.
  Samsung, Xiaomi and other OEM schemas are untested.
* **Real encrypted images.** The tool detects and reports encryption; it has never been run on a genuinely FBE-encrypted partition (none
  was available), only on synthetic and fixture data and on the decrypted corpus above.
* **The f2fs reader on a real phone image.** It is validated on images written by a real Linux kernel and by `mkfs.f2fs`; the Pixel
  corpus is a *file-level* extraction, not a partition image.
* **Precision of recovery on real data.** Only SMS can be scored (2 of 2); for everything else there is no ground truth, so false-positive
  rates on real devices are **unknown**. Treat `LOW` as leads, not findings.
* **Windows**, third-party penetration testing, accreditation or any independent review ([standards_alignment.md](standards_alignment.md)).
