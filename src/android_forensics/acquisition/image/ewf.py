"""EnCase / libewf E01 (EWF v1) evidence files as an :class:`ImageSource`.

An E01 set is one or more *segment* files (``name.E01``, ``name.E02`` …). Each starts with a 13-byte file header and holds a
chain of sections, each with a 76-byte descriptor (type, offset of the next section, size, Adler-32). The sections that
matter here are:

* ``volume`` / ``disk`` — chunk geometry and total sector count;
* ``sectors`` — the (possibly zlib-compressed) chunks themselves;
* ``table`` — for the preceding ``sectors`` section, one 32-bit offset per chunk (top bit = compressed), relative to the
  table's base offset;
* ``hash`` / ``digest`` — the MD5 (and SHA-1) of the *logical* media recorded when the image was acquired, which
  :meth:`EwfImageSource.verify` re-computes.

Everything is validated: descriptor checksums, section chains (no cycles, always forward, inside the file), chunk offsets and
sizes, per-chunk Adler-32 for stored chunks, and decompressed size (a compressed chunk can never expand beyond one chunk —
no decompression bombs). Reads go through a small LRU cache so memory stays bounded.
"""

from __future__ import annotations

import hashlib
import re
import struct
import zlib
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from android_forensics.acquisition.image.source import EWF_MAGIC, ImageError, ImageSource, RawImageSource

MAX_SECTIONS_PER_SEGMENT = 1_000_000
MAX_CHUNKS = 200_000_000
CACHE_CHUNKS = 64
_COMPRESSED = 0x80000000
_SEGMENT_NAME = re.compile(r"^(?P<stem>.+)\.(?P<ext>[Ee])(?P<num>\d{2})$")


@dataclass(frozen=True)
class _Chunk:
    segment: int
    offset: int       # absolute offset in the segment file
    size: int         # stored size (including the 4-byte Adler for uncompressed chunks)
    compressed: bool


def _segment_paths(first: Path) -> list[Path]:
    m = _SEGMENT_NAME.match(first.name)
    if not m:
        return [first]
    stem, letter = m.group("stem"), m.group("ext")
    paths = [first]
    n = int(m.group("num")) + 1
    while n <= 99:
        nxt = first.with_name(f"{stem}.{letter}{n:02d}")
        if not nxt.is_file():
            break
        paths.append(nxt)
        n += 1
    return paths


class EwfImageSource(ImageSource):
    kind = "E01 (EWF v1)"

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._files: list[RawImageSource] = []
        self._chunks: list[_Chunk] = []
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self.notes: list[str] = []
        self.stored_md5: str | None = None
        self.stored_sha1: str | None = None
        self.chunk_size = 0
        self._size = 0
        self.header_text: str | None = None
        try:
            for p in _segment_paths(self.path):
                self._files.append(RawImageSource(p))
            self._parse()
        except BaseException:
            self.close()
            raise

    # ------------------------------------------------------------------ parsing
    def _parse(self) -> None:
        sectors_per_chunk = bytes_per_sector = sector_count = 0
        for seg_index, f in enumerate(self._files):
            head = f.read_exact(0, 13)
            if head[:8] != EWF_MAGIC:
                raise ImageError(f"{f.path.name}: not an EWF segment")
            (num,) = struct.unpack_from("<H", head, 9)
            if num != seg_index + 1:
                raise ImageError(f"{f.path.name}: segment number {num} found where {seg_index + 1} was expected (missing or reordered segment)")
            off, count, data_span = 13, 0, (0, 0)
            seen: set[int] = set()
            terminated = False
            while True:
                count += 1
                if off in seen or count > MAX_SECTIONS_PER_SEGMENT or off + 76 > f.size:
                    raise ImageError(f"{f.path.name}: section chain is damaged (loop, overrun or past end of file)")
                seen.add(off)
                desc = f.read_exact(off, 76)
                stype = desc[:16].rstrip(b"\0").decode("ascii", "replace")
                nxt, size = struct.unpack_from("<QQ", desc, 16)
                if zlib.adler32(desc[:72]) != struct.unpack_from("<I", desc, 72)[0]:
                    raise ImageError(f"{f.path.name}: section '{stype}' at {off} has a bad descriptor checksum")
                body_len = max(0, size - 76)
                if off + size > f.size or (stype not in ("done", "next") and size < 76):
                    raise ImageError(f"{f.path.name}: section '{stype}' extends beyond the file")
                body_at = off + 76
                if stype in ("volume", "disk") and body_len >= 24:
                    body = f.read_exact(body_at, min(body_len, 1052))
                    _media, chunk_count, sectors_per_chunk, bytes_per_sector, sector_count = struct.unpack_from("<IIIIQ", body, 0)
                    if not (sectors_per_chunk and bytes_per_sector) or sectors_per_chunk * bytes_per_sector > 64 * 1024 * 1024:
                        raise ImageError("implausible EWF chunk geometry")
                    self.chunk_size = sectors_per_chunk * bytes_per_sector
                    if chunk_count > MAX_CHUNKS:
                        raise ImageError("implausible EWF chunk count")
                elif stype == "sectors":
                    data_span = (off, off + size)
                elif stype == "table" and body_len >= 24:
                    self._read_table(seg_index, f, body_at, body_len, data_span)
                elif stype in ("hash", "digest") and body_len >= 16:
                    body = f.read_exact(body_at, min(body_len, 36))
                    self.stored_md5 = body[:16].hex()
                    if stype == "digest" and len(body) >= 36:
                        self.stored_sha1 = body[16:36].hex()
                elif stype in ("header", "header2") and self.header_text is None:
                    try:
                        raw = zlib.decompressobj().decompress(f.read_exact(body_at, min(body_len, 1 << 16)), 1 << 16)
                        self.header_text = raw.decode("utf-16" if stype == "header2" else "latin-1", "replace").replace("\r", "")
                    except (zlib.error, ValueError):
                        pass
                if stype in ("done", "next"):
                    terminated = True
                    if stype == "next" and seg_index == len(self._files) - 1:
                        self.notes.append("last segment ends with a 'next' section: the segment set is incomplete (more segments exist)")
                    break
                if nxt <= off:
                    raise ImageError(f"{f.path.name}: section '{stype}' does not point forward")
                off = nxt
            if not terminated:
                raise ImageError(f"{f.path.name}: no terminating section")
        if not self.chunk_size:
            raise ImageError("EWF image has no volume section")
        declared = sector_count * bytes_per_sector
        available = len(self._chunks) * self.chunk_size
        if declared > available:
            self.notes.append(f"image declares {declared:,} bytes but its chunk tables cover only {available:,}: the remainder is unreadable")
        self._size = min(declared, available) if declared else available

    def _read_table(self, seg: int, f: RawImageSource, at: int, length: int, data_span: tuple[int, int]) -> None:
        n, _pad, base, _pad2, _ck = struct.unpack("<IIQII", f.read_exact(at, 24))
        if n == 0:
            return
        if 24 + 4 * n > length or n > MAX_CHUNKS:
            raise ImageError("EWF table claims more entries than it holds")
        if len(self._chunks) + n > MAX_CHUNKS:
            raise ImageError("implausible EWF chunk count")
        raw = f.read_exact(at + 24, 4 * n)
        entries = struct.unpack(f"<{n}I", raw)
        end_of_data = data_span[1]
        if end_of_data == 0:
            raise ImageError("EWF table with no preceding sectors section")
        for i, e in enumerate(entries):
            compressed = bool(e & _COMPRESSED)
            start = base + (e & ~_COMPRESSED)
            nxt = base + (entries[i + 1] & ~_COMPRESSED) if i + 1 < n else end_of_data
            size = nxt - start
            if start < 0 or size <= 0 or start + size > f.size or size > self.chunk_size * 2 + 4096:
                raise ImageError(f"EWF chunk {len(self._chunks)} has an impossible extent")
            self._chunks.append(_Chunk(seg, start, size, compressed))

    # ------------------------------------------------------------------ reading
    @property
    def size(self) -> int:
        return self._size

    def _chunk(self, index: int) -> bytes:
        cached = self._cache.get(index)
        if cached is not None:
            self._cache.move_to_end(index)
            return cached
        c = self._chunks[index]
        raw = self._files[c.segment].read_exact(c.offset, c.size)
        if c.compressed:
            d = zlib.decompressobj()
            try:
                data = d.decompress(raw, self.chunk_size + 1)
            except zlib.error as exc:
                raise ImageError(f"EWF chunk {index} does not decompress: {exc}") from exc
            if len(data) > self.chunk_size or d.unconsumed_tail:
                raise ImageError(f"EWF chunk {index} decompresses to more than one chunk ({self.chunk_size} bytes)")
        else:
            data, ck = raw[:-4], struct.unpack("<I", raw[-4:])[0]
            if zlib.adler32(data) != ck:
                raise ImageError(f"EWF chunk {index} is corrupt (stored-chunk checksum mismatch)")
        self._cache[index] = data
        if len(self._cache) > CACHE_CHUNKS:
            self._cache.popitem(last=False)
        return data

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= self._size:
            return b""
        end = min(offset + length, self._size)
        out = bytearray()
        pos = offset
        while pos < end:
            idx, inner = divmod(pos, self.chunk_size)
            chunk = self._chunk(idx)
            piece = chunk[inner:inner + (end - pos)]
            if not piece:
                break  # a short final chunk: the rest of the declared size is unreadable
            out += piece
            pos += len(piece)
        return bytes(out)

    def verify(self) -> tuple[bool, str]:
        """Re-compute the logical-media hash and compare with the one stored at acquisition time."""
        if not self.stored_md5:
            return True, "image carries no stored hash; only the container hash can vouch for it"
        md5, sha1 = hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False)
        pos = 0
        try:
            while pos < self._size:
                block = self.read_at(pos, self.chunk_size)
                if not block:
                    break
                md5.update(block)
                sha1.update(block)
                pos += len(block)
        except ImageError as exc:
            return False, f"could not re-read the whole image to verify its stored hash: {exc}"
        ok = md5.hexdigest() == self.stored_md5 and (self.stored_sha1 is None or sha1.hexdigest() == self.stored_sha1)
        if ok:
            return True, f"stored MD5 {self.stored_md5} matches the recomputed logical-media hash"
        return False, f"stored MD5 {self.stored_md5} does NOT match the recomputed hash {md5.hexdigest()}: the image was altered or damaged after acquisition"

    def close(self) -> None:
        for f in self._files:
            f.close()
        self._files = []

    def describe(self) -> str:
        n = len(set(c.segment for c in self._chunks)) or 1
        extra = f"; {'; '.join(self.notes)}" if self.notes else ""
        return f"{self.kind}, {n} segment(s), {self.size:,} logical bytes, chunk size {self.chunk_size}{extra}"
