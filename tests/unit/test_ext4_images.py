from __future__ import annotations

import gzip
import struct
from pathlib import Path

import pytest

from android_forensics.acquisition.image import is_disk_image, open_image
from android_forensics.acquisition.image.ext4 import Ext4Error, Ext4FileSystem, WalkIssue, looks_like_ext
from android_forensics.acquisition.image.partitions import find_filesystems
from android_forensics.acquisition.image.source import ImageError, RawImageSource, SparseImageSource
from tests.tools.make_ext_images import tree

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="module")
def expected(tmp_path_factory) -> dict[str, bytes]:
    root = tmp_path_factory.mktemp("expected")
    tree(root)
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


@pytest.fixture(params=["ext4_4k_extents", "ext2_1k_blockmap"])
def image(request, tmp_path) -> Path:
    out = tmp_path / f"{request.param}.img"
    out.write_bytes(gzip.decompress((FIXTURES / f"{request.param}.img.gz").read_bytes()))
    return out


def read_tree(fs: Ext4FileSystem) -> tuple[dict[str, bytes], list[WalkIssue]]:
    issues: list[WalkIssue] = []
    files = {}
    for e in fs.walk(issues):
        if e.inode.is_file:
            files[e.path] = fs.read_all(e.inode, limit=1 << 30)
    return files, issues


def test_every_file_is_read_byte_for_byte(image, expected):
    with RawImageSource(image) as src:
        fs = Ext4FileSystem(src)
        files, issues = read_tree(fs)
    assert files == expected  # extents AND indirect-block layouts, holes, empty files, multi-block directories
    assert [i.issue_type for i in issues] == []


def test_superblock_facts(image):
    with RawImageSource(image) as src:
        fs = Ext4FileSystem(src)
        assert fs.sb.label == "userdata" and fs.sb.block_size in (1024, 4096) and looks_like_ext(src)


def test_symlinks_and_metadata_are_visible_but_not_followed(image):
    with RawImageSource(image) as src:
        fs = Ext4FileSystem(src)
        entries = {e.path: e.inode for e in fs.walk()}
    link = entries["data/com.example.app/databases/link"]
    assert link.is_symlink and not link.is_file
    big = entries["data/com.example.app/databases/big.bin"]
    assert big.size == 300_000 and big.mtime and big.mtime > 1_600_000_000


def test_partition_detection_bare_image(image):
    with open_image(image) as src:
        locs = find_filesystems(src)
    assert [(loc.index, loc.offset, loc.fstype) for loc in locs] == [(0, 0, "ext")]
    assert is_disk_image(image)


def test_non_images_are_not_images(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00" * 100_000)
    assert not is_disk_image(p)
    p.write_bytes(bytes(range(256)) * 400)
    assert not is_disk_image(p)


def _with_mbr(raw: bytes, start_sector: int = 2048) -> bytes:
    mbr = bytearray(512)
    struct.pack_into("<BBBBBBBBII", mbr, 446, 0, 0, 0, 0, 0x83, 0, 0, 0, start_sector, len(raw) // 512)
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr) + bytes(start_sector * 512 - 512) + raw


def _with_gpt(raw: bytes, name: str = "userdata", start_sector: int = 2048) -> bytes:
    sectors = len(raw) // 512
    hdr = bytearray(512)
    hdr[:8] = b"EFI PART"
    struct.pack_into("<QII", hdr, 72, 2, 128, 128)
    entry = bytearray(128)
    entry[:16] = b"\x01" * 16
    struct.pack_into("<QQ", entry, 32, start_sector, start_sector + sectors - 1)
    entry[56:56 + len(name) * 2] = name.encode("utf-16le")
    table = bytes(entry) + bytes(128 * 127)
    head = bytes(512) + bytes(hdr) + table
    return head + bytes(start_sector * 512 - len(head)) + raw


def test_mbr_and_gpt_partitions(tmp_path):
    raw = gzip.decompress((FIXTURES / "ext4_4k_extents.img.gz").read_bytes())
    for build, expect_name in ((_with_mbr, None), (_with_gpt, "userdata")):
        p = tmp_path / f"{build.__name__}.img"
        p.write_bytes(build(raw))
        with open_image(p) as src:
            locs = find_filesystems(src)
            assert len(locs) == 1 and locs[0].fstype == "ext" and locs[0].offset == 2048 * 512 and locs[0].name == expect_name
            fs = Ext4FileSystem(src, locs[0].offset, locs[0].length)
            assert any(e.path.endswith("small.txt") for e in fs.walk())


def _to_sparse(raw: bytes, blk: int = 4096) -> bytes:
    """Encode as Android sparse: RAW chunks for non-zero blocks, DONT_CARE for zero runs, one FILL chunk."""
    chunks: list[bytes] = []
    n = 0
    i, total = 0, len(raw) // blk
    while i < total:
        zero = raw[i * blk:(i + 1) * blk] == bytes(blk)
        j = i
        while j < total and (raw[j * blk:(j + 1) * blk] == bytes(blk)) == zero:
            j += 1
        count = j - i
        if zero:
            chunks.append(struct.pack("<HHII", 0xCAC3, 0, count, 12))
        else:
            chunks.append(struct.pack("<HHII", 0xCAC1, 0, count, 12 + count * blk) + raw[i * blk:j * blk])
        n += 1
        i = j
    return struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, total, n, 0) + b"".join(chunks)


def test_android_sparse_image_reads_like_the_raw_image(tmp_path, expected):
    raw = gzip.decompress((FIXTURES / "ext4_4k_extents.img.gz").read_bytes())
    p = tmp_path / "userdata.simg"
    p.write_bytes(_to_sparse(raw))
    with open_image(p) as src:
        assert isinstance(src, SparseImageSource) and src.size == len(raw)
        assert src.read_at(0, len(raw)) == raw
        assert src.read_at(1000, 5000) == raw[1000:6000]
        files, _ = read_tree(Ext4FileSystem(src))
    assert files == expected


def test_sparse_fill_chunk_and_malformed_headers(tmp_path):
    blk = 4096
    fill = struct.pack("<HHII", 0xCAC2, 0, 2, 16) + b"\x01\x02\x03\x04"
    p = tmp_path / "f.simg"
    p.write_bytes(struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, 2, 1, 0) + fill)
    with open_image(p) as src:
        assert src.read_at(2, 6) == b"\x03\x04\x01\x02\x03\x04"
    for bad in (struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 0, 1, 1, 0),                       # block size 0
                struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, 1, 99_999_999, 0),             # absurd chunk count
                struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, 1, 1, 0)):                     # chunk table truncated
        p.write_bytes(bad)
        with pytest.raises(ImageError):
            open_image(p)


# ---------------------------------------------------------------------------- hostile images


def _patch(image: Path, offset: int, data: bytes) -> None:
    raw = bytearray(image.read_bytes())
    raw[offset:offset + len(data)] = data
    image.write_bytes(bytes(raw))


@pytest.fixture()
def ext4(tmp_path) -> Path:
    p = tmp_path / "evil.img"
    p.write_bytes(gzip.decompress((FIXTURES / "ext4_4k_extents.img.gz").read_bytes()))
    return p


def test_bad_superblocks_are_rejected_not_crashed_on(ext4):
    base = 1024
    for off, data in ((56, b"\x00\x00"),                              # magic
                      (24, struct.pack("<I", 30)),                    # absurd block size
                      (32, struct.pack("<I", 0)),                     # blocks per group = 0
                      (88, struct.pack("<H", 100))):                  # inode size not a power of two
        raw = ext4.read_bytes()
        _patch(ext4, base + off, data)
        with RawImageSource(ext4) as src, pytest.raises(Ext4Error):
            Ext4FileSystem(src)
        ext4.write_bytes(raw)


def test_inode_table_pointing_outside_the_image_is_an_error_not_a_wild_read(ext4):
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        gdt = fs.sb.first_data_block + 1
    _patch(ext4, gdt * 4096 + 8, struct.pack("<I", 0x7FFFFFFF))
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        issues: list[WalkIssue] = []
        assert list(fs.walk(issues)) == []
        assert issues and issues[0].issue_type == "filesystem_root_unreadable"


def test_extent_pointing_past_the_image_raises_for_that_file_only(ext4):
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        victim = next(e.inode for e in fs.walk() if e.path.endswith("big.bin"))
        ok = next(e.inode for e in fs.walk() if e.path.endswith("small.txt"))
        group, idx = divmod(victim.number - 1, fs.sb.inodes_per_group)
        pos = fs._inode_table(group) * fs.bs + idx * fs.sb.inode_size + 40 + 12 + 8   # first extent's start_lo
    _patch(ext4, pos, struct.pack("<I", 0x0FFFFFFF))
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        entries = {e.path: e.inode for e in fs.walk()}
        with pytest.raises(Ext4Error):
            fs.read_all(entries["data/com.example.app/databases/big.bin"], limit=1 << 30)
        assert fs.read_all(entries["data/com.example.app/databases/small.txt"]) == b"hello android\n"
    assert ok.number


def test_directory_cycle_is_detected(ext4):
    """Point a subdirectory's entry back at the root: the walk must terminate and say so."""
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        sysdir = next(e for e in fs.entries(fs.inode(2)) if e.name == b"system")
        sys_inode = fs.inode(sysdir.inode)
        block = next(iter(fs.runs(sys_inode)))[1]
        raw = bytearray(fs._read_block(block))
        # first entry is '.', second '..'; add a self-referencing child by rewriting '..' to inode 2 and '.' to the root as well
        struct.pack_into("<I", raw, 0, 2)
    _patch(ext4, block * 4096, bytes(raw))
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        issues: list[WalkIssue] = []
        list(fs.walk(issues))   # must terminate


def test_rec_len_garbage_does_not_loop_or_overread(ext4):
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        root_block = next(iter(fs.runs(fs.inode(2))))[1]
    _patch(ext4, root_block * 4096 + 12 + 4, struct.pack("<H", 3))  # '..' rec_len = 3 (illegal)
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        assert [e.name for e in fs.entries(fs.inode(2))] == [b"."]   # keeps what parsed before the damage, then stops (no spin, no over-read)


def test_encrypted_directories_are_reported_not_descended(ext4):
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        data_dir = next(e for e in fs.entries(fs.inode(2)) if e.name == b"data")
        group, idx = divmod(data_dir.inode - 1, fs.sb.inodes_per_group)
        flags_pos = fs._inode_table(group) * fs.bs + idx * fs.sb.inode_size + 32
        flags = struct.unpack("<I", src.read_at(flags_pos, 4))[0]
    _patch(ext4, flags_pos, struct.pack("<I", flags | 0x800))
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        issues: list[WalkIssue] = []
        paths = [e.path for e in fs.walk(issues)]
    assert not any(p.startswith("data/") for p in paths)
    assert any(i.issue_type == "file_based_encryption_detected" and i.path == "data" for i in issues)


def test_truncated_image_is_noted_and_unreachable_files_error(ext4):
    ext4.write_bytes(ext4.read_bytes()[: 1024 * 1024])
    with RawImageSource(ext4) as src:
        fs = Ext4FileSystem(src)
        assert any("shorter" in n for n in fs.notes)
