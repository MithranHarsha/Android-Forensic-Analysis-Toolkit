# Performance and memory

Measured, not estimated: `experiments/b1_scaling.py` runs the real CLI in a fresh child process and reads that child's **peak
resident set size from the kernel** (`wait4`), so Python-level tracing never distorts the timings. Raw numbers:
`experiments/results/b1_scaling.csv|json`. Machine: Apple M-series, 12 cores, macOS, CPython 3.12, SQLite 3.51, local SSD; times are
wall-clock for the **whole** pipeline (`analyze --no-report`: scan → extract → recover → carve → correlate → reconstruct → validate →
timeline), one worker (the pipeline is single-threaded).

## One SQLite database of N rows (2 % of the rows genuinely deleted)

| Rows | Database | Wall time | Peak memory | Per row |
|---:|---:|---:|---:|---:|
| 10,000 | 1.3 MB | 3.8 s | 131 MB | 0.38 ms |
| 100,000 | 13.0 MB | 38 s | 662 MB | 0.38 ms |
| 300,000 | 39.3 MB | 127 s | 1.7 GB | 0.42 ms |
| 1,000,000 | 131 MB | 558 s (9.3 min) | 4.7 GB | 0.56 ms |

* **Time is close to linear** (0.4–0.6 ms/row for *everything*, including recovery and carving, because the engine reads every page
  in pure Python instead of issuing indexed queries). A typical phone's `mmssms.db` + `calllog.db` + `contacts2.db` + browser history
  is well under 100,000 rows: **about a minute**.
* **Memory is dominated by the in-memory evidence graph** (≈ 4.7 KB per artifact at the million-row scale). A real handset is well
  under 1 GB; a 1M-message database needs ~5 GB of RAM. Size the machine (or the `--job-memory-gb` of the server) accordingly.
* Throughput in MB/s looks low (0.24–0.34 MB/s) because it is *per database byte of a very row-dense table*; it is not what limits
  you on mixed evidence, where most bytes are media and caches that are only hashed.

### Two defects this benchmark found and that are fixed

| Defect | Effect | Fix |
|---|---|---|
| Correlation loaded every artifact as a full model (~17 KB each) just to read a few facts | 1.58 GB peak for a 13 MB database (≈ 15 GB per million rows) | `Subject.slim` keeps only the facts correlation uses → 0.66 GB for the same database |
| The carver scanned every timestamp hit for every phone-number hit (O(n·m)) | carving was half the run time: 18.9 s of 55 s at 100k rows | sorted spans + bisection: 5.7 s (identical results; a property test compares against the naive definition and a scaling test guards the complexity) |

## Parallel recovery and carving (`--workers`)

Recovery and carving are pure functions of one file's bytes, so `analyze` / `recover` accept `--workers N|auto` (env
`ANDROID_FORENSICS_WORKERS`). Results are written by a single process in task order, so **a parallel run produces exactly the same case
content as a serial one** — row ids, ordering and every report (asserted by `tests/integration/test_parallel.py`). The biggest files are
started first so one large database is not the straggler.

Real corpus (Digital Corpora Android 9, 605 databases, 8 workers, Apple M-series):

| Stage | 1 worker | 8 workers | Speed-up |
|---|---:|---:|---:|
| recover | 181 s | 45 s | 4.0× |
| carve | 166 s | 44 s | 3.8× |

Both runs found 21,129 recovered records and 249,372 carved candidates. The other stages (extract, correlate, reconstruct, validate,
timeline) are still single-process, which is why the whole pipeline gains less than the two stages do.

### Memory of the evidence graph
Edges are stored as plain tuples and turned into validated `CorrelationEdge` models only when read or persisted
(`graph.iter_edges()`): at 100,000 rows the correlation stage peaked at **467 MB, down from 681 MB**. Expect roughly 3.3 KB per artifact at
scale (measured only at 100k; the 1M-row figure above predates this change).

## Reports at scale
The HTML report shows at most `html_row_cap` rows (default 3,000) of each recovery table — highest confidence first — plus a summary by
status/method/confidence (and carved kind/confidence) that covers *every* row, with a note saying it is a sample. `report.json` and the CSV
files always contain everything. (Before this, a case with hundreds of thousands of carved candidates would have produced a
multi-hundred-megabyte HTML file.)

### More defects found by running on GitHub's runners
CI on Windows (slow `fsync`, slower CPUs) exposed two more hot spots that were merely tolerable on a fast Mac:

| Defect | Effect | Fix |
|---|---|---|
| `reconstruct` committed one database transaction (one `fsync`) per recovered record | ~8,000 commits for the synthetic lab; minutes on a Windows runner | commits in batches of 500 |
| De-duplication compared every recovered row with every row kept so far (O(n²)) | 32 million comparisons for the lab's 8,000-row `queue` table | index by content and `(table, column, value)`; proved identical to the original on random inputs; a test fails if it turns quadratic again |

## Evidence containers and disk images (streaming)

| Input | Size | Wall time | Peak memory |
|---|---:|---:|---:|
| ext4 image holding one 1 GiB random file, `--preserve none` | 1.30 GB | 4.6 s (287 MB/s) | 70 MB |
| same, `--preserve all` (copies the file into the case) | 1.30 GB | 4.9 s (268 MB/s) | 67 MB |

Ingestion hashes (SHA-256 + SHA-1 + MD5 in one pass) and classifies every file through a fixed-size buffer: memory does not grow
with evidence size. The container (image) is hashed once in addition, which is why 1.3 GB of image + 1 GiB of file takes ~4.6 s.

## Known scaling limits

* `parse_wal` / `parse_journal` read the **whole sidecar into memory**. Phone WALs are megabytes, so anything over
  `config.MAX_SIDECAR_BYTES` (1 GiB) is *reported and not parsed* instead of risking the machine; raise the constant deliberately to
  analyse a genuinely larger one. A streaming parser is future work.
* Directory walking of very large images keeps the visited-inode set and one directory's entries in memory.
* The pipeline is single-threaded; throughput scales with a faster core, not more cores. Several cases can run concurrently
  (`serve --workers N`).
* Windows: not benchmarked (see the platform note in the README).
