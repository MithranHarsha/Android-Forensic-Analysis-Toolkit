# SQLite internals and deleted-record recovery

> **Status.** Review 1 implements only the *read side*: header parsing (`sqlite/header.py`), WAL / SHM / journal header
> facts (`sqlite/sidecars.py`), a read-only scratch-copy session (`sqlite/reader.py`) and the normal-inspection engine
> `SQLiteInspector` (`sqlite/inspector.py`, see [sqlite_inspection.md](sqlite_inspection.md)). Everything from §3 onward is the
> **Review 2 design** and is not implemented. Nothing here is a claim about any specific dataset.

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
