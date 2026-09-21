# SQLite internals and deleted-record recovery

> **Status.** Implemented (Phase 4): the page-level reader (`sqlite/pages.py`, `records.py`, `ddl.py`, `parser.py`,
> `freelist.py`), deleted-record recovery (`recovery.py`, `recover_db.py`), WAL analysis (`wal.py`) and rollback-journal
> analysis (`journal.py`), all tested against a deletion lab whose ground truth is derived from the files' own bytes
> (`lab/deletions.py`). §5 documents what was built, byte offset by byte offset, and §6 reports what it recovered — measured.
> Sections 3–4 are the reasoning and the original design it was built from. Nothing here is a claim about any real device.

## 1. File format primer

A SQLite database is an array of fixed-size **pages** (512 … 65536 bytes, a power of two; header value `1` means 65536).
Page numbers start at 1; page 1 begins with the 100-byte **database header** followed by the b-tree page header of
`sqlite_master`. Header fields the tool reads (big-endian):

| Offset | Size | Field | Why it matters |
|---|---|---|---|
| 16 | 2 | page size | required to slice the file |
| 18 / 19 | 1 / 1 | write / read version (2 = WAL) | journal mode |
| 20 | 1 | reserved bytes per page | usable size `U = page − reserved` |
| 24 | 4 | file change counter | staleness of the page count |
| 28 | 4 | database size in pages | truncation check (valid only if version-valid-for == change counter) |
| 32 / 36 | 4 / 4 | first freelist trunk page / total freelist pages | freelist recovery potential |
| 40 | 4 | schema cookie | schema change tracking |
| 52 | 4 | largest root page (≠ 0 ⇒ auto-vacuum) | auto-vacuum reclaims free pages |
| 56 | 4 | text encoding (1 UTF-8, 2 UTF-16le, 3 UTF-16be) | decoding TEXT |
| 64 | 4 | incremental-vacuum flag | vacuum mode |
| 92 / 96 | 4 / 4 | version-valid-for / SQLite version | provenance |

### B-tree pages

The first byte of a b-tree page header gives its type: `0x0D` table leaf, `0x05` table interior, `0x0A` index leaf,
`0x02` index interior. Header: `[0]` type · `[1..2]` first freeblock offset · `[3..4]` cell count · `[5..6]` start of cell
content area · `[7]` fragmented free bytes · (`[8..11]` right-most pointer for interior pages). A **cell pointer array**
of 2-byte offsets follows; cell bodies are written from the end of the page backwards. The gap between the pointer array
and the content area is *unallocated space*.

### Table-leaf cell and record

Cell = `varint payload-size · varint rowid · payload · [4-byte first-overflow-page]`. If the payload exceeds
`X = U − 35` the local part is `K = M + ((P − M) mod (U − 4))` (or `M = ((U−12)·32/255) − 23` if `K > X`) and the rest lives
on a chain of **overflow pages** (`4-byte next page · data`).

Payload = **record**: `varint header-size · one varint serial type per column · column bodies`.

| Serial type | Meaning | Body bytes |
|---|---|---|
| 0 | NULL | 0 |
| 1–4 / 5 / 6 | signed int 8/16/24/32 / 48 / 64 bit | 1,2,3,4 / 6 / 8 |
| 7 | IEEE-754 double | 8 |
| 8 / 9 | integer constant 0 / 1 | 0 |
| 10, 11 | reserved | — |
| N ≥ 12, even | BLOB of `(N−12)/2` bytes | `(N−12)/2` |
| N ≥ 13, odd | TEXT of `(N−13)/2` bytes | `(N−13)/2` |

A row's `INTEGER PRIMARY KEY` is the **rowid** and is stored in the cell header, not in the record (its record column is NULL).

### Freelist

Pages released by deletes are chained from the header: a **trunk page** = `4-byte next trunk · 4-byte leaf count · leaf page
numbers…`; **leaf pages** carry no structure — they keep whatever bytes they held before being freed.

### WAL (write-ahead log)

`file-wal` = 32-byte header (`magic 0x377f0682|3`, format 3007000, page size, checkpoint sequence, **salt-1, salt-2**,
checksums) followed by **frames**: 24-byte frame header (page number, db size in pages *after commit* — non-zero marks a
commit frame, copies of both salts, checksums) + a full page image. A frame is valid only if its salts match the header and
the cumulative checksum holds; the last valid commit frame defines the WAL's committed state. `file-shm` is the volatile
wal-index (its header records `mxFrame`). Checkpointing copies frames into the main file but does **not** erase them; a
restarted WAL writes new salts and overwrites frames from the start, leaving older frames beyond the new end.

### Rollback journal

`file-journal` = header (`d9 d5 05 f9 20 a1 63 d7`, page count, nonce, initial db size, sector size, page size) padded to the
sector size, then records `4-byte page number · page image · 4-byte checksum` of pages **as they were before** the
transaction. The magic is written only when the journal is synced, so an unsynced journal has an all-zero header. Modes:
`DELETE` (file removed after commit), `TRUNCATE`, `PERSIST` (header zeroed, old images left in place), `WAL`.

## 2. What Review 1 reports from this

* Header validity and size-vs-page-count consistency (`truncated`, `trailing data`), stale in-header counts (normal in WAL mode).
* `freelist_page_count`, `first_freelist_trunk`, **auto-vacuum mode**, text encoding, journal mode.
* WAL: magic, page size, checkpoint sequence, salts, **frame slots** (`(size − 32) / (page + 24)`, an upper bound — frame validity
  is *not* checked), whether it matches the database page size; SHM `mxFrame`; journal magic / zeroed header / declared page count.
* These appear in the report as **recovery-potential indicators, explicitly not findings**.
* `SQLiteInspector` additionally supplies the starting points of §4 step 1 and the baseline of step 2: every b-tree root page from
  `sqlite_master` (`schema_entries`, `tables[].root_page`, `indexes[].root_page`), the primary keys and column definitions candidates
  are validated against, and every active row with its rowid — the set recovered rows must be de-duplicated against.

## 3. How data survives deletion (Review 2 reasoning)

| Event | What changes | What may survive |
|---|---|---|
| `DELETE` a row (leaf cell) | cell pointer removed from the array, cell count decremented; the cell's space becomes a **freeblock** — its first 4 bytes are overwritten with *next-freeblock offset + size* (typically clobbering payload-size, rowid and possibly the first serial types) | the remaining record header + column bodies; the **rowid is usually lost** (recoverable only by inference) |
| Delete the last cell(s) in the content area | content-area start moves; bytes become *unallocated* space | often the whole cell, untouched |
| A page becomes empty | page added to the **freelist** as a leaf | for a freelist leaf the old b-tree header, pointer array **and** cells can be fully intact → the best case: complete rows *with rowids* |
| `UPDATE` growing a row | old cell freed, new cell written elsewhere | old version in a freeblock / unallocated space |
| Commit in WAL mode | page images appended as frames | **previous versions of pages** in earlier frames of the same WAL generation, and stale frames from older generations |
| Commit in rollback-journal mode | pre-images written to the journal | journal contents while the file exists (`PERSIST`: after commit too; `DELETE`: only via filesystem-level carving, outside SQLite) |
| `VACUUM` | database rewritten compactly | DB-file remnants are gone; older images may remain in WAL/journal or flash |
| Auto-vacuum (`FULL`) | freed pages are moved out and the file truncated at commit | freelist recovery potential is much reduced |
| `secure_delete` (compile-time or pragma) | freed content is overwritten with zeros | in-page remnants are largely gone; WAL/journal images may still exist |

**Android note.** The SQLite bundled with Android has been built with non-default options in various releases
(auto-vacuum and secure-delete defaults, journal size limits), and apps choose their own pragmas. The tool must **read each
database's actual state** (header auto-vacuum field, freelist count, observed page content) and never assume recoverability.
Flash storage adds TRIM / garbage collection and file-based encryption; those are outside what any SQLite-level analysis
can overcome (see [limitations.md](limitations.md)).

## 4. Review 2 recovery design

Modules (planned, under `android_forensics/sqlite/`): `pages.py`, `records.py`, `freelist.py`, `wal.py`, `journal.py`,
`recovery.py`, all built on a `PageSource` interface (main file, WAL frame, journal record — each with an origin tag and
byte offset) so that recovery treats every page image uniformly and every result carries physical provenance.

1. **Page inventory.** Classify every page: table/index leaf or interior, overflow, freelist trunk/leaf, pointer-map
   (auto-vacuum), lock-byte page, unknown. Walk b-trees from the `sqlite_master` roots to assign owning tables; leaf-type pages
   not reachable are *orphans* (owner inferred later by schema matching).
2. **Live cells** (validation baseline). Parse cells via the pointer array; these must equal the SQLite-engine rows Review 1
   already extracted (a built-in cross-check).
3. **Freeblock and unallocated-space scan.** For each freeblock/gap, attempt record parsing at candidate offsets: read
   `header-size`, then serial types; require `header-size` to be consistent, the type count to match a schema column count (± the
   damaged leading columns), and the summed body lengths to fit the region. Because the first 4 bytes of a freed cell are
   clobbered, also try starting *after* the freeblock header, treating missing leading columns as `UNKNOWN`.
4. **Freelist and orphan pages.** Attempt full page parse first (intact header + pointer array ⇒ complete cells with rowids);
   fall back to the region scan of step 3.
5. **WAL.** Validate frames (salts, checksums, commit boundaries), group by page number, reconstruct historical page versions,
   parse them like live pages and diff against the current state: rows present in an older version but absent now are
   deleted/superseded candidates, ordered by commit position.
6. **Journal.** Parse page records (beyond the header's declared count, since it reflects only the last sync) and treat as
   historical page images.
7. **Overflow.** Follow the chain; if it is broken or overwritten keep the local portion and mark the record `PARTIAL`.
8. **Schema validation of candidates.** Column count; serial type vs declared affinity (an INTEGER column holding a TEXT
   serial type is suspect); TEXT decodability; timestamp plausibility; rowid collision with active rows (de-duplication);
   consistency across fields.
9. **Artifact conversion.** Candidates become `RowSource` objects (`UNKNOWN` for unrecoverable columns) and pass through the
   existing parsers' `from_row`, yielding typed artifacts with `status ∈ {RECOVERED, PARTIAL, CARVED, CORRUPTED, UNRECOVERABLE, INVALID}`,
   `PhysicalLocation` (page, cell/offset, region, raw-bytes hash), method and raw bytes.
10. **Confidence.** Explained factors (schema match, valid record structure, valid serial types, field consistency, page
    integrity, source provenance, timestamp validity, raw-byte completeness, cross-artifact corroboration) → `HIGH` /
    `MEDIUM` / `LOW`, each with a sentence saying *why*. No learned model.
11. **Carving.** Pattern search (phone numbers, URLs, e-mail, timestamps, record-like structures) over raw bytes yields
    `CARVED CANDIDATE`s only, never confirmed evidence until validated and corroborated.

Ground truth for evaluating this comes from the same synthetic generator (`lab/synth.py`), extended with controlled
deletions and overwrites; see [evaluation.md](evaluation.md).


## 5. What was implemented (Phase 4)

### 5.1 Reading pages without SQLite (4A)

| Module | What it does | Offsets and structures used |
|---|---|---|
| `records.py` | varints, serial types, records, payload spill | varint 1–9 bytes (7 bits each, the 9th byte all 8); serial types 0–9 fixed, ≥12 blob/text of `(N-12)/2` / `(N-13)/2` bytes; record = header size varint + serial types + body; local payload `X = U-35` (table leaf), `M = ((U-12)·32/255)-23`, `K = M+((P-M) mod (U-4))` |
| `pages.py` | b-tree pages, cells, overflow chains | page header at 0 (100 on page 1): type byte, first freeblock `[1..2]`, cell count `[3..4]`, content start `[5..6]` (0 = 65536), fragmented bytes `[7]`, right pointer `[8..11]` (interior), cell-pointer array after the 8- or 12-byte header; freeblock `[next:2][size:2]`; table-leaf cell `[payload size][rowid][payload][overflow:4]`; overflow page `[next:4][content: U-4]` |
| `ddl.py` | `CREATE TABLE` → columns, keys, alias, `WITHOUT ROWID`, generated columns | agrees with `PRAGMA table_xinfo` on every hand-written statement and every table of the synthetic Android databases |
| `parser.py` | `SQLiteDatabase`: header, schema from page 1, in-order b-tree walk, live rows, page-role map | page size 512…65536 (`1` = 65536); page count trusted only when version-valid-for equals the change counter; lock-byte page `2³⁰/page size + 1`; pointer-map pages every `U/5 + 1` from page 2 when auto-vacuum |
| `freelist.py` | trunk/leaf walk | header `[32..35]` first trunk, `[36..39]` count; trunk `[0..3]` next, `[4..7]` L, `[8..]` L leaf pointers |

Verified: every row of every table equals SQLite's own answer at all eight page sizes, with overflow chains, interior pages, indexes, composite `WITHOUT ROWID` keys, UTF-16 databases, records that predate `ADD COLUMN`, and files with destroyed pages
(`tests/unit/test_sqlite_pages.py`, 113 tests).

### 5.2 Recovering deleted records (4B)

`recovery.py` scans **every page image** — main-file pages of every role (b-tree, freelist trunk/leaf, orphan), WAL frames, journal pages — for byte sequences that parse as a record *exactly* under some table's schema, then subtracts what the active view (as SQLite presents it, WAL applied) still holds.

Two hypotheses are tested wherever they can apply:

1. **`full`** — `[payload size][rowid][record]` starts here: an untouched cell. Accepted only if the payload size equals `header size + Σ body sizes` *exactly*, the record has as many serial types as the table has stored columns, a rowid-alias column holds NULL, no rowid needs more than 6 varint bytes, and at least 75 % of the columns agree with their declared affinity.
2. **`clobbered`** — a freed cell whose first four bytes SQLite overwrote with a freeblock header. The header of the record is then read under each layout of the lost prefix (payload-size varint 1–2 bytes + rowid varint 1–6 bytes, so the record header starts 2, 3, 4 … bytes into the cell). A layout is accepted only if: every surviving serial type is legal; a surviving header-size byte equals `1 + bytes of all serial types`; the payload size the layout implies has a varint length consistent with the assumed prefix; and the cell **ends where a cell can end** — at the freeblock's end, at an *interior boundary*, at the start of an untouched cell, or fewer than 4 bytes before the block end (fragment bytes). A lost first serial type is inferred only when its size is forced (rowid alias: NULL) or, for a non-alias column, when exactly one cell end is possible *and* the declared affinity (INTEGER/NUMERIC of 1–6 bytes, TEXT, or a column declared BLOB) determines the type; otherwise the value stays `UNKNOWN`.

*Interior boundaries and stale headers.* Freeing cells one after another merges them into one freeblock but leaves each earlier freeblock header where it was, at the boundary between two cells, with `size` equal to the distance from there to the end of the block. When a freed cell borders the unallocated gap SQLite drops it from the chain but again leaves its `[next:2][size:2]` bytes behind, with `size` equal to the cell's length. Both are recognised by that signature, which lets a merged block be split back into its cells.

*What is excluded.* Bytes belonging to a live cell are not free space (a record overlapping one is refused: it is the remnant of an old cell partly overwritten by a new one). `sqlite_*` tables, virtual tables, `WITHOUT ROWID` tables (index-format cells) and tables with fewer than three columns (too little structure to recognise) are not searched for in free space. A cell whose payload spilled to overflow pages is not attempted. Rows equal to an active row are dropped; the same row found in several places is reported once with every location listed (`also_found_at`).

**Statuses.** `RECOVERED`: the whole cell — every field and the rowid. `PARTIAL`: a freed cell — every surviving field, no rowid (the alias column is `UNKNOWN`). `CORRUPTED`: the structure fits exactly but a value fails validation (text that is not valid UTF-8; the value is `UNKNOWN`). `UNRECOVERABLE` is reported for freed space whose content is gone (zero-filled, or not a record of any table): evidence that a record existed, with no content.

### 5.3 WAL and journal (4C)

**WAL** (`wal.py`): header `[0..3]` magic `0x377f0682/3` (checksum byte order), `[8..11]` page size, `[16..23]` salts, `[24..31]` header checksum; frames of `24 + page size` bytes: `[0..3]` page, `[4..7]` commit size, `[8..15]` salts, `[16..23]` cumulative checksum. Frames are `committed`, `uncommitted` (valid, after the last commit frame), `stale_generation` (older salts, checksum chain verified against the previous stale frame), `stale_unverified` (older salts, first of a run), `corrupt` or `empty`. Every non-empty frame is a page version; rows found in one that the active view lacks are recovered with `WAL_FRAME`.

**Rollback journal** (`journal.py`): header `[0..7]` magic `d9d505f920a163d7`, `[8..11]` records in the segment (or `0xFFFFFFFF`), `[12..15]` nonce, `[16..19]` size before the transaction, `[20..23]` sector size, `[24..27]` page size, padded to the sector size; records `[page:4][image][checksum:4]`, checksum = nonce + every 200th byte of the page from `size-200`. A `PERSIST` journal has its header zeroed after a commit: the records are found at a sector boundary and the nonce is *derived* from the first record, then required to hold for the next — that consistency proves the boundary. The checksum only samples every 200th byte, so journal content is also validated against the schema and never trusted on the checksum alone. A hot journal is rolled back in the active view, so its rows are *active* and the main file's modified cells are the ones reported.

### 5.4 Field validation (4D)

Every reconstructed record is decoded strictly (text must be valid in the database encoding), fitted to its table (`≥ 75 %` affinity agreement, alias NULL), and checked by `field_types_valid` against declared column types. A field the bytes do not determine is `UNKNOWN` — a test asserts that no freeblock-recovered row has a rowid or an alias value.

## 6. Measured results

The deletion lab (`lab/deletions.py`) builds an SMS-shaped table (100 rows, 25 deleted unless stated), applies each condition, then derives the *expected* class of every deleted row **from the files' bytes**: each row is re-encoded exactly as SQLite wrote it and searched for — whole cell present → `RECOVERED` expected; only the cell after its first four bytes present → `PARTIAL`; neither → `UNRECOVERABLE`. Expectations therefore never depend on the recovery algorithm. Base databases are built with `secure_delete=ON` and then switched off, so b-tree split residue does not pre-date the condition (`plain_residue` keeps it, to measure that source).

| Case | Condition | Deleted | Expected R / P / U | Reported | Matched | False positives | Recall | Reported as (status) | Source of the remnants |
|---|---|---:|---|---:|---:|---:|---:|---|---|
| plain | plain | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| vacuum | vacuum | 25 | 0 / 0 / 25 | 0 | 0 | 0 | 100% | — | — |
| secure_delete | secure_delete | 25 | 0 / 0 / 25 | 0 | 0 | 0 | 100% | — | — |
| auto_vacuum | auto_vacuum | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| journal_persist | journal_persist | 25 | 25 / 0 / 0 | 25 | 25 | 0 | 100% | RECOVERED 25 | JOURNAL_PAGE |
| journal_truncate | journal_truncate | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| journal_off | journal_off | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| wal_uncheckpointed | wal_uncheckpointed | 25 | 25 / 0 / 0 | 25 | 25 | 0 | 100% | RECOVERED 25 | RAW_PAGE_SCAN |
| wal_checkpointed | wal_checkpointed | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| wal_history | wal_history | 25 | 25 / 0 / 0 | 25 | 25 | 0 | 100% | RECOVERED 25 | WAL_FRAME |
| wal_stale | wal_stale | 25 | 25 / 0 / 0 | 25 | 25 | 0 | 100% | RECOVERED 25 | RAW_PAGE_SCAN |
| update | update | 25 | 0 / 13 / 12 | 13 | 13 | 0 | 100% | PARTIAL 13 | FREEBLOCK |
| plain_first | plain | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| plain_middle | plain | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| plain_last | plain | 25 | 0 / 14 / 11 | 14 | 14 | 0 | 100% | PARTIAL 14 | FREEBLOCK |
| plain_random | plain | 25 | 1 / 24 / 0 | 25 | 25 | 0 | 100% | PARTIAL 24, RECOVERED 1 | FREEBLOCK, UNALLOCATED_SPACE |
| plain_block | plain | 25 | 1 / 13 / 11 | 14 | 14 | 0 | 100% | PARTIAL 13, RECOVERED 1 | FREEBLOCK, UNALLOCATED_SPACE |
| plain_every_other | plain | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| plain_medium | plain | 25 | 1 / 24 / 0 | 25 | 25 | 0 | 100% | PARTIAL 24, RECOVERED 1 | FREEBLOCK, UNALLOCATED_SPACE |
| plain_large | plain | 25 | 17 / 0 / 8 | 17 | 17 | 0 | 100% | RECOVERED 17 | FREELIST_PAGE, UNALLOCATED_SPACE |
| plain_ps1024 | plain | 25 | 1 / 3 / 21 | 3 | 3 | 0 | 75% | PARTIAL 2, RECOVERED 1 | FREEBLOCK, UNALLOCATED_SPACE |
| plain_ps2048 | plain | 25 | 0 / 9 / 16 | 7 | 7 | 0 | 78% | PARTIAL 7 | FREEBLOCK |
| plain_ps8192 | plain | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| plain_ps16384 | plain | 25 | 0 / 25 / 0 | 25 | 25 | 0 | 100% | PARTIAL 25 | FREEBLOCK |
| overwrite_50 | plain | 25 | 0 / 13 / 12 | 12 | 12 | 0 | 92% | PARTIAL 12 | FREEBLOCK |
| overwrite_100 | plain | 25 | 0 / 1 / 24 | 1 | 1 | 0 | 100% | PARTIAL 1 | FREEBLOCK |
| overwrite_200 | plain | 25 | 0 / 1 / 24 | 1 | 1 | 0 | 100% | PARTIAL 1 | FREEBLOCK |
| plain_residue | plain | 25 | 25 / 0 / 0 | 25 | 25 | 0 | 100% | RECOVERED 25 | UNALLOCATED_SPACE |

TOTAL: 507 of 511 physically recoverable rows recovered (99.2%); 0 false positives among 507 reported rows.


**Reading the table.** *Expected R / P / U* is how many of the deleted rows are physically recoverable in full, only partly, or not at all. `vacuum` and `secure_delete` leave nothing (the file is rewritten / the bytes are zeroed) and nothing is reported. Plain deletions leave `PARTIAL` rows (the freeblock header took the rowid); a persistent journal, WAL history and a delete still sitting in the WAL leave whole cells; `journal_truncate` and `journal_off` keep no history so the freeblocks are all there is. The more the freed space is overwritten (`overwrite_*`), the less survives — and the engine's count follows the physical truth down. The three cases below 100 % (`plain_ps1024`, `plain_ps2048`, `overwrite_50`) are layouts where a neighbouring cell's head was destroyed as well, so the end of a freed cell cannot be confirmed and the record is not guessed.

## 7. When recovery is expected to fail — and why

| Condition | Why nothing (or little) can be recovered |
|---|---|
| `VACUUM` | the database is rewritten compactly: freed cells are not copied |
| `secure_delete=ON` | freed content is overwritten with zeros (reported as *unrecoverable* zero-filled regions) |
| auto-vacuum `FULL` | freed *pages* are returned to the file system at commit (freeblock remnants inside kept pages remain) |
| WAL checkpointed and truncated, journal deleted or truncated | the historical images are gone from the files |
| overwritten space | new cells reuse freed space; the original bytes no longer exist |
| flash-level TRIM / garbage collection, file-based encryption | outside any SQLite-level analysis (see `limitations.md`) |
