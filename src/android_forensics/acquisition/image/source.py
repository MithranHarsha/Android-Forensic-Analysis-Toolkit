"""Read-only, random-access byte sources for disk images.

* :class:`RawImageSource` — a plain ``.img`` / ``.dd`` file, opened ``O_RDONLY`` (never for writing).
* :class:`SparseImageSource` — the Android sparse image format (``simg2img`` input; what ``fastboot`` flashes). Chunks of
  type RAW are read through, FILL chunks expand a 4-byte pattern and DONT_CARE chunks read as zeros, so the logical image
  is never materialised on disk.
* :class:`~android_forensics.acquisition.image.ewf.EwfImageSource` — EnCase E01 (EWF v1) evidence files.
"""

from __future__ import annotations

import os
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from android_forensics.errors import IngestionError
from android_forensics.readonly import open_readonly

SPARSE_MAGIC = 0xED26FF3A
EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"
MAX_SPARSE_CHUNKS = 5_000_000


class ImageError(IngestionError):
    """A disk image that cannot be interpreted."""


class ImageSource(ABC):
    """A read-only view of the logical bytes of an image."""

    kind = "raw"

    @property
    @abstractmethod
    def size(self) -> int: ...

    @abstractmethod
    def read_at(self, offset: int, length: int) -> bytes:
        """Up to ``length`` bytes at ``offset``; short only at the end of the image. Never raises for out-of-range input."""

    def read_exact(self, offset: int, length: int) -> bytes:
        """Exactly ``length`` bytes or an :class:`ImageError` (a structure the file system promised is not there)."""
        data = self.read_at(offset, length)
        if len(data) != length:
            raise ImageError(f"short read: wanted {length} bytes at {offset}, image has {len(data)}")
        return data

    def close(self) -> None:  # noqa: B027 - optional hook; most sources hold nothing to release
        pass

    def __enter__(self) -> ImageSource:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def describe(self) -> str:
        return f"{self.kind} image, {self.size:,} bytes"


class RawImageSource(ImageSource):
    kind = "raw"

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._fh = open_readonly(self.path, follow_symlinks=True)  # an image named on the command line may be a symlink
        self._size = os.fstat(self._fh.fileno()).st_size

    @property
    def size(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= self._size:
            return b""
        self._fh.seek(offset)
        return self._fh.read(min(length, self._size - offset))

    def close(self) -> None:
        self._fh.close()


@dataclass(frozen=True)
class _Chunk:
    start: int       # logical byte offset
    length: int      # logical byte length
    kind: str        # "raw" | "fill" | "zero"
    file_offset: int = 0
    fill: bytes = b""


class SparseImageSource(ImageSource):
    kind = "android-sparse"

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._raw = RawImageSource(path)
        self._chunks: list[_Chunk] = []
        self._size = 0
        try:
            self._parse()
        except BaseException:
            self._raw.close()
            raise

    def _parse(self) -> None:
        hdr = self._raw.read_exact(0, 28)
        magic, major, _minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks, _crc = struct.unpack("<IHHHHIIII", hdr)
        if magic != SPARSE_MAGIC or major != 1:
            raise ImageError("not an Android sparse image (bad magic/version)")
        if file_hdr_sz < 28 or chunk_hdr_sz < 12 or blk_sz == 0 or blk_sz % 4 or blk_sz > 1 << 24:
            raise ImageError("implausible Android sparse header")
        if total_chunks > MAX_SPARSE_CHUNKS:
            raise ImageError(f"sparse image declares {total_chunks} chunks (limit {MAX_SPARSE_CHUNKS})")
        pos, out = file_hdr_sz, 0
        for _ in range(total_chunks):
            ch = self._raw.read_at(pos, 12)
            if len(ch) < 12:
                raise ImageError("sparse image truncated inside the chunk table")
            ctype, _res, chunk_blocks, total_sz = struct.unpack("<HHII", ch)
            length = chunk_blocks * blk_sz
            body = pos + chunk_hdr_sz
            if ctype == 0xCAC1:    # RAW
                if total_sz != chunk_hdr_sz + length or body + length > self._raw.size:
                    raise ImageError("sparse RAW chunk extends beyond the file")
                self._chunks.append(_Chunk(out, length, "raw", body))
            elif ctype == 0xCAC2:  # FILL
                self._chunks.append(_Chunk(out, length, "fill", fill=self._raw.read_exact(body, 4)))
            elif ctype == 0xCAC3:  # DONT_CARE
                self._chunks.append(_Chunk(out, length, "zero"))
            elif ctype == 0xCAC4:  # CRC32 (no data)
                length = 0
            else:
                raise ImageError(f"unknown sparse chunk type 0x{ctype:04x}")
            out += length
            pos += total_sz
        if out != total_blks * blk_sz:
            raise ImageError("sparse image: chunks do not add up to the declared size")
        self._size = out

    @property
    def size(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or offset >= self._size:
            return b""
        end = min(offset + length, self._size)
        out = bytearray()
        for c in self._chunks:  # chunk counts are modest; linear scan keeps the code obvious
            if c.length == 0 or c.start + c.length <= offset or c.start >= end:
                continue
            lo, hi = max(offset, c.start), min(end, c.start + c.length)
            n = hi - lo
            if c.kind == "raw":
                out += self._raw.read_at(c.file_offset + (lo - c.start), n)
            elif c.kind == "fill":
                pattern = c.fill * ((n + 3) // 4 + 1)
                skew = (lo - c.start) % 4
                out += pattern[skew:skew + n]
            else:
                out += bytes(n)
        return bytes(out)

    def close(self) -> None:
        self._raw.close()


def open_image(path: Path | str) -> ImageSource:
    """Open ``path`` as the right kind of image source (sparse / EWF / raw)."""
    path = Path(path)
    with open_readonly(path, follow_symlinks=True) as fh:
        head = fh.read(8)
    if len(head) >= 4 and struct.unpack("<I", head[:4])[0] == SPARSE_MAGIC:
        return SparseImageSource(path)
    if head == EWF_MAGIC:
        from android_forensics.acquisition.image.ewf import EwfImageSource

        return EwfImageSource(path)
    return RawImageSource(path)
