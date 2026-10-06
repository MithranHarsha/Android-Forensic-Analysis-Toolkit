from __future__ import annotations

import gzip
import shutil
import struct
import zlib
from pathlib import Path

import pytest

from android_forensics.acquisition.image import open_image
from android_forensics.acquisition.image.ewf import EwfImageSource
from android_forensics.acquisition.image.source import ImageError

FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="module")
def raw_ext4() -> bytes:
    return gzip.decompress((FIX / "ext4_4k_extents.img.gz").read_bytes())


@pytest.fixture()
def multi(tmp_path) -> Path:
    d = tmp_path / "multi"
    d.mkdir()
    for i in range(1, 6):
        (d / f"image.E0{i}").write_bytes(gzip.decompress((FIX / "ewf" / f"ext4_multi.E0{i}.gz").read_bytes()))
    return d


def test_compressed_single_segment_matches_the_raw_image(raw_ext4):
    with open_image(FIX / "ewf" / "ext4_best.E01") as src:
        assert isinstance(src, EwfImageSource) and src.size == len(raw_ext4)
        assert src.read_at(0, src.size) == raw_ext4
        assert src.read_at(32768 - 10, 30) == raw_ext4[32768 - 10:32768 + 20]   # across a chunk boundary
        assert src.read_at(src.size - 5, 100) == raw_ext4[-5:]                   # clipped at the end
        assert src.read_at(src.size, 10) == b"" and src.read_at(-1, 10) == b""
        assert src.header_text and "main" in src.header_text
        ok, detail = src.verify()
        assert ok and "matches" in detail


def test_stored_chunks_across_five_segments(multi, raw_ext4):
    with open_image(multi / "image.E01") as src:
        assert src.read_at(0, src.size) == raw_ext4
        assert src.verify()[0] and "5 segment" in src.describe()


def test_missing_trailing_segment_is_noted_not_silently_complete(multi):
    (multi / "image.E05").unlink()
    with open_image(multi / "image.E01") as src:
        assert any("incomplete" in n or "cover only" in n for n in src.notes)
        assert src.size < 4 * 1024 * 1024
        assert src.stored_md5 is None   # the hash lives in the missing last segment, so there is nothing to verify against


def test_missing_middle_segment_is_noted(multi):
    (multi / "image.E03").unlink()
    with open_image(multi / "image.E01") as src:
        assert any("incomplete" in n for n in src.notes) and src.size <= 2 * 1024 * 1024 + 4096


def _flip(path: Path, offset: int) -> None:
    b = bytearray(path.read_bytes())
    b[offset] ^= 0xFF
    path.write_bytes(bytes(b))


def test_corrupt_compressed_chunk_fails_that_read_and_verification(tmp_path):
    p = tmp_path / "x.E01"
    shutil.copy(FIX / "ewf" / "ext4_best.E01", p)
    _flip(p, 1877 + 76 + 40)             # inside the first compressed chunk
    with open_image(p) as src:
        with pytest.raises(ImageError):
            src.read_at(0, 4096)
        ok, detail = src.verify()
        assert not ok and "could not re-read" in detail


def test_corrupt_stored_chunk_is_caught_by_its_checksum(multi):
    _flip(multi / "image.E01", 1774 + 76 + 1000)
    with open_image(multi / "image.E01") as src, pytest.raises(ImageError, match="checksum"):
        src.read_at(0, 4096)


def test_altered_stored_hash_is_reported_as_mismatch(tmp_path, raw_ext4):
    p = tmp_path / "x.E01"
    shutil.copy(FIX / "ewf" / "ext4_best.E01", p)
    data = p.read_bytes()
    at = data.index(bytes.fromhex("0a7a9bd894701fb336f949611cfb1789"))
    _flip(p, at)
    with open_image(p) as src:
        ok, detail = src.verify()
        assert not ok and "does NOT match" in detail
        assert src.read_at(0, src.size) == raw_ext4   # data itself is intact; only the recorded hash lies


def test_bad_descriptor_checksum_and_truncation_are_rejected(tmp_path):
    p = tmp_path / "x.E01"
    shutil.copy(FIX / "ewf" / "ext4_best.E01", p)
    _flip(p, 13 + 20)                    # inside the first descriptor
    with pytest.raises(ImageError):
        open_image(p)
    shutil.copy(FIX / "ewf" / "ext4_best.E01", p)
    p.write_bytes(p.read_bytes()[:5000])
    with pytest.raises(ImageError):
        open_image(p)


def _relink(path: Path, desc_off: int, **fields: int) -> None:
    """Rewrite a section descriptor with a valid checksum (so only the logic, not the checksum, is under test)."""
    b = bytearray(path.read_bytes())
    typ, nxt, size = struct.unpack_from("<16sQQ", b, desc_off)
    nxt, size = fields.get("nxt", nxt), fields.get("size", size)
    struct.pack_into("<16sQQ", b, desc_off, typ, nxt, size)
    struct.pack_into("<I", b, desc_off + 72, zlib.adler32(bytes(b[desc_off:desc_off + 72])))
    path.write_bytes(bytes(b))


def test_section_chain_loops_and_overruns_are_rejected(tmp_path):
    p = tmp_path / "x.E01"
    shutil.copy(FIX / "ewf" / "ext4_best.E01", p)
    _relink(p, 749, nxt=13)              # volume -> back to the first section (a loop)
    with pytest.raises(ImageError):
        open_image(p)
    shutil.copy(FIX / "ewf" / "ext4_best.E01", p)
    _relink(p, 1877, size=10**12)        # sectors section "extends" far beyond the file
    with pytest.raises(ImageError):
        open_image(p)


def test_decompression_bomb_chunk_is_refused(tmp_path):
    """A chunk whose zlib stream expands to far more than one chunk must not be inflated."""
    p = tmp_path / "x.E01"
    shutil.copy(FIX / "ewf" / "ext4_best.E01", p)
    data = bytearray(p.read_bytes())
    first_chunk = 1877 + 76
    second_chunk = 1877 + 0x1e2
    bomb = zlib.compress(bytes(300_000), 9)  # ~300 B that inflates to ~9 chunks
    assert len(bomb) <= second_chunk - first_chunk
    data[first_chunk:first_chunk + len(bomb)] = bomb
    p.write_bytes(bytes(data))
    with open_image(p) as src, pytest.raises(ImageError, match="more than one chunk"):
        src.read_at(0, 10)
