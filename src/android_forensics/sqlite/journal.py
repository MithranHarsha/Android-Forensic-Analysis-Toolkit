"""The rollback journal: header, page records and pre-transaction page images (Phase 4C).

Reference: https://www.sqlite.org/fileformat2.html §"The Rollback Journal". Big-endian.

**Header** (padded to the sector size, usually 512)::

    [0..7]  magic d9 d5 05 f9 20 a1 63 d7     [8..11]  page records in this segment (0xFFFFFFFF: from the file size)
    [12..15] nonce (seeds every record checksum) [16..19] database size in pages before the transaction
    [20..23] sector size                       [24..27] page size

**Record**: ``[page number: 4][page image: page size][checksum: 4]``. The checksum is the nonce plus every 200th byte of the
page, counting down from 200 bytes before its end. A record holds the page *as it was before* the interrupted transaction
changed it, so the rows on it are the pre-transaction state.

Two situations matter to a forensic examiner:

* A **hot** journal (valid magic, transaction never committed): SQLite rolls the database back with these pages the next time
  it opens it — so, in the *active view*, the journal's rows are active and the main file's modified cells are the rolled-back
  changes.
* A **persistent** journal (``journal_mode=PERSIST``): after a commit SQLite zeroes the header instead of deleting the file.
  SQLite no longer treats it as a journal, but the page records stay on disk. With the header gone the page size comes from the
  database and the nonce is *derived* from the first record (``nonce = checksum - sum of sampled bytes``) and must then hold for
  every further record — that consistency is what proves a record boundary is real.

The header's record count reflects only the last sync, so records beyond it are read too (up to the first bad checksum).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from android_forensics.readonly import open_readonly

MAGIC = bytes.fromhex("d9d505f920a163d7")
HEADER_FIELDS = 28
SECTOR_SIZES = (512, 1024, 2048, 4096)


@dataclass(frozen=True)
class JournalRecord:
    index: int  # 1-based
    offset: int  # of the record (its page number field)
    page_number: int
    checksum_ok: bool

    def page_offset(self) -> int:
        return self.offset + 4


@dataclass
class JournalInfo:
    path: str
    size: int
    header_valid: bool
    header_zeroed: bool
    page_size: int
    sector_size: int
    nonce: int | None
    declared_records: int | None
    initial_db_pages: int | None
    records: list[JournalRecord] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    data: bytes = field(default=b"", repr=False)

    @property
    def kind(self) -> str:
        if self.size == 0:
            return "empty"
        if self.header_valid:
            return "valid_header"
        return "zeroed_header" if self.header_zeroed else "unrecognised_header"

    def page(self, record: JournalRecord) -> bytes:
        return self.data[record.page_offset(): record.page_offset() + self.page_size]


def _sampled_sum(page: bytes) -> int:
    total = 0
    i = len(page) - 200
    while i > 0:
        total += page[i]
        i -= 200
    return total


def journal_checksum(page: bytes, nonce: int) -> int:
    return (nonce + _sampled_sum(page)) & 0xFFFFFFFF


def parse_journal(path: str | Path, *, db_page_size: int, db_page_count: int | None = None) -> JournalInfo:
    """Parse a ``-journal`` file. ``db_page_size`` (from the database header) is used when the journal's own header is gone."""
    path = Path(path)
    with open_readonly(path) as fh:
        data = fh.read()
    info = JournalInfo(str(path), len(data), False, False, db_page_size, 0, None, None, None, data=data)
    if not data:
        return info
    if data[:8] == MAGIC and len(data) >= HEADER_FIELDS:
        n, nonce, initial, sector, ps = struct.unpack(">5I", data[8:HEADER_FIELDS])
        info.header_valid = True
        info.declared_records = None if n == 0xFFFFFFFF else n
        info.nonce, info.initial_db_pages, info.sector_size = nonce, initial, sector
        if ps != db_page_size:
            info.problems.append(f"journal page size {ps} differs from the database's {db_page_size}")
        info.page_size = ps if ps >= 512 and not ps & (ps - 1) else db_page_size
        if sector < 32 or sector > 65536 or sector & (sector - 1):
            info.problems.append(f"implausible sector size {sector}: assuming 512")
            info.sector_size = 512
        _read_records(info, info.sector_size, nonce, db_page_count)
        return info
    info.header_zeroed = not any(data[:HEADER_FIELDS])
    info.problems.append("journal header is zeroed (journal_mode=PERSIST after a commit, or a never-synced journal)" if info.header_zeroed
                         else "journal header magic invalid")
    _derive_and_read(info, db_page_size, db_page_count)
    return info


def _read_records(info: JournalInfo, start: int, nonce: int, db_page_count: int | None) -> None:
    ps, data = info.page_size, info.data
    slot = ps + 8
    pos, index = start, 0
    while pos + slot <= len(data):
        pgno = struct.unpack_from(">I", data, pos)[0]
        page = data[pos + 4: pos + 4 + ps]
        stored = struct.unpack_from(">I", data, pos + 4 + ps)[0]
        ok = stored == journal_checksum(page, nonce)
        if not ok or pgno == 0 or (db_page_count and pgno > max(db_page_count, info.initial_db_pages or 0) * 2):
            info.problems.append(f"record {index + 1} at offset {pos} does not verify: reading stops")
            break
        index += 1
        info.records.append(JournalRecord(index, pos, pgno, True))
        pos += slot
    if info.declared_records is not None and index != info.declared_records:
        info.problems.append(f"header declares {info.declared_records} records in its segment; {index} verified in the file")


def _derive_and_read(info: JournalInfo, ps: int, db_page_count: int | None) -> None:
    """A journal with no usable header: find where records start and derive the nonce from the first one."""
    data = info.data
    slot = ps + 8
    for sector in SECTOR_SIZES:
        if len(data) < sector + slot:
            continue
        pgno = struct.unpack_from(">I", data, sector)[0]
        if pgno == 0 or (db_page_count and pgno > db_page_count * 2):
            continue
        page = data[sector + 4: sector + 4 + ps]
        stored = struct.unpack_from(">I", data, sector + 4 + ps)[0]
        nonce = (stored - _sampled_sum(page)) & 0xFFFFFFFF
        # the nonce must hold for the next record too — otherwise this is not a record boundary (a lone record is accepted)
        if len(data) >= sector + 2 * slot:
            page2 = data[sector + slot + 4: sector + slot + 4 + ps]
            stored2 = struct.unpack_from(">I", data, sector + slot + 4 + ps)[0]
            pgno2 = struct.unpack_from(">I", data, sector + slot)[0]
            if pgno2 and stored2 != journal_checksum(page2, nonce):
                continue
        info.sector_size, info.nonce = sector, nonce
        _read_records(info, sector, nonce, db_page_count)
        if info.records:
            info.problems.append(f"records located at sector offset {sector}; checksum nonce {nonce:#010x} derived from the first record")
            return
        info.nonce = None
    info.problems.append("no verifiable page records found")
