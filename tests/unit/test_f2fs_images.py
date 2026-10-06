from __future__ import annotations

import gzip
import struct
from pathlib import Path

import pytest

from android_forensics.acquisition.image import is_disk_image, open_image
from android_forensics.acquisition.image.f2fs import (
    ADVISE_ENCRYPT,
    BLOCK,
    DATA_EXIST,
    EXTRA_ATTR,
    INLINE_DATA,
    INLINE_DENTRY,
    F2fsError,
    F2fsFileSystem,
    _crc32_le,
    looks_like_f2fs,
)
from android_forensics.acquisition.image.partitions import find_filesystems
from android_forensics.acquisition.image.source import RawImageSource
from tests.tools.f2fs_tree import expected_files

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "f2fs"
NAMES = ("kernel_clean", "kernel_extra_clean", "kernel_extra_dirty")


@pytest.fixture(scope="module")
def images(tmp_path_factory) -> dict[str, Path]:
    d = tmp_path_factory.mktemp("f2fs")
    out = {}
    for n in NAMES:
        p = d / f"{n}.img"
        p.write_bytes(gzip.decompress((FIX / f"{n}.img.gz").read_bytes()))
        out[n] = p
    return out


@pytest.fixture(scope="module")
def expected() -> dict[str, bytes]:
    return expected_files()


def read_tree(fs: F2fsFileSystem):
    issues, files = [], {}
    for e in fs.walk(issues):
        if e.inode.is_file:
            files[e.path] = fs.read_all(e.inode, 1 << 30)
    return files, issues


@pytest.mark.parametrize("name", NAMES)
def test_every_file_is_read_byte_for_byte_from_a_kernel_written_volume(images, expected, name):
    with RawImageSource(images[name]) as src:
        files, issues = read_tree(F2fsFileSystem(src))
    assert files == expected          # inline data, inline dentries, indirect nodes, hashed multi-block dirs, holes, deletions
    assert issues == []


def test_the_interesting_on_disk_paths_were_actually_exercised(images):
    with RawImageSource(images["kernel_clean"]) as src:
        fs = F2fsFileSystem(src)
        by_path = {e.path: e.inode for e in fs.walk()}
        small = by_path["data/com.example.app/databases/small.txt"]
        assert small.inline & INLINE_DATA and small.inline & DATA_EXIST, "small file should be stored inside its inode"
        big = by_path["data/com.example.app/databases/big.bin"]
        nids = struct.unpack_from("<5I", big.block, 360 + 4 * 923)
        assert nids[0] and nids[1] and nids[2], "20 MB file must need both direct nodes and an indirect node"
        medium = by_path["data/com.example.app/databases/medium.bin"]
        assert not medium.inline & INLINE_DATA
        files_dir = by_path["data/com.example.app/files/f0001.dat"]
        assert files_dir.size == 1                                   # sanity: a real regular file
    with RawImageSource(images["kernel_clean"]) as src:
        fs = F2fsFileSystem(src)
        root = fs.inode(fs.sb.root_ino)
        names = {n for n, _i, _t in fs.entries(root)}
        assert {b"system", b"data"} <= names
        # walk down to the tiny directory and confirm it is an inline dentry directory
        node = root
        for part in (b"data", b"com.example.app", b"tiny"):
            node = fs.inode(next(i for n, i, _t in fs.entries(node) if n == part))
        assert node.is_dir and node.inline & INLINE_DENTRY
        # and the files directory spans many blocks (hashed dentry blocks)
        files = root
        for part in (b"data", b"com.example.app", b"files"):
            files = fs.inode(next(i for n, i, _t in fs.entries(files) if n == part))
        assert files.size > 8 * BLOCK


def test_modern_feature_set_uses_extra_attributes(images):
    with RawImageSource(images["kernel_extra_clean"]) as src:
        fs = F2fsFileSystem(src)
        entry = next(e for e in fs.walk() if e.path.endswith("small.txt"))
        assert entry.inode.inline & EXTRA_ATTR and entry.inode.crtime and entry.inode.mtime
        assert fs.sb.feature & 0x8 and fs.sb.feature & 0x40


def test_live_snapshot_is_flagged_not_clean_and_clean_is_not(images):
    with RawImageSource(images["kernel_extra_dirty"]) as src:
        assert any("not cleanly unmounted" in n for n in F2fsFileSystem(src).notes)
    with RawImageSource(images["kernel_clean"]) as src:
        assert not any("not cleanly" in n for n in F2fsFileSystem(src).notes)


def test_detection_and_partition_table(images, tmp_path):
    assert is_disk_image(images["kernel_clean"])
    with open_image(images["kernel_clean"]) as src:
        assert looks_like_f2fs(src) and [(loc.index, loc.fstype) for loc in find_filesystems(src)] == [(0, "f2fs")]
    # inside a GPT disk
    raw = images["kernel_clean"].read_bytes()
    hdr = bytearray(512)
    hdr[:8] = b"EFI PART"
    struct.pack_into("<QII", hdr, 72, 2, 128, 128)
    entry = bytearray(128)
    entry[:16] = b"\x01" * 16
    struct.pack_into("<QQ", entry, 32, 2048, 2048 + len(raw) // 512 - 1)
    entry[56:56 + 14] = "userdata".encode("utf-16le")
    head = bytes(512) + bytes(hdr) + bytes(entry) + bytes(128 * 127)
    disk = tmp_path / "disk.img"
    disk.write_bytes(head + bytes(2048 * 512 - len(head)) + raw)
    with open_image(disk) as src:
        locs = find_filesystems(src)
        assert len(locs) == 1 and locs[0].fstype == "f2fs" and locs[0].name == "userdata"
        fs = F2fsFileSystem(src, locs[0].offset, locs[0].length)
        assert any(e.path.endswith("small.txt") for e in fs.walk())


# ---------------------------------------------------------------------------- hostile images


def _patch(path: Path, offset: int, data: bytes) -> None:
    raw = bytearray(path.read_bytes())
    raw[offset:offset + len(data)] = data
    path.write_bytes(bytes(raw))


@pytest.fixture()
def victim(images, tmp_path) -> Path:
    p = tmp_path / "v.img"
    p.write_bytes(images["kernel_clean"].read_bytes())
    return p


def _cp_start(path: Path) -> tuple[int, int, int]:
    with RawImageSource(path) as src:
        fs = F2fsFileSystem(src)
        return fs.sb.cp_blkaddr, fs.sb.blocks_per_seg, fs.cp_start


def test_checkpoint_crc_is_enforced_and_the_other_pack_is_used(victim):
    cp, bps, chosen = _cp_start(victim)
    _patch(victim, chosen * BLOCK + 40, b"\xff\xff")                       # corrupt the newest pack's header
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        assert fs.cp_start != chosen                                       # fell back to the older, intact pack
    other = cp if chosen != cp else cp + bps
    _patch(victim, other * BLOCK + 40, b"\xff\xff")
    with RawImageSource(victim) as src, pytest.raises(F2fsError, match="no valid checkpoint"):
        F2fsFileSystem(src)


def test_a_node_whose_footer_does_not_match_is_rejected_not_trusted(victim):
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        ino, addr = fs._nat_lookup(fs.sb.root_ino)
    _patch(victim, addr * BLOCK + 4072, struct.pack("<I", 12345))        # footer nid no longer matches
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        issues = []
        assert list(fs.walk(issues)) == []
        assert issues and issues[0].issue_type == "filesystem_root_unreadable" and "does not describe itself" in issues[0].detail


def test_nat_journal_entries_override_the_nat_block(victim):
    """Zero a file's NAT entry on disk, put the right entry in the checkpoint's journal: the file must still be readable."""
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        target = next(e.inode for e in fs.walk() if e.path.endswith("medium.bin"))
        nid = target.number
        ino, addr = fs._nat_lookup(nid)
        block_off, idx = divmod(nid, 455)
        nat_addr = fs.sb.nat_blkaddr + 2 * block_off - (block_off & 511)
        if fs._nat_bitmap[block_off // 8] & (0x80 >> (block_off % 8)):
            nat_addr += 512
        summary_block = fs.cp_start + fs.cp_start_sum
        compact = bool(fs.cp_flags & 0x04)
    _patch(victim, nat_addr * BLOCK + idx * 9, bytes(9))                # the on-disk NAT now says "unallocated"
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        with pytest.raises(F2fsError):
            fs.inode(nid)
    off = 0 if compact else 3584
    entry = struct.pack("<HIBII", 1, nid, 0, ino, addr)                  # n_nats=1, then one journal entry
    _patch(victim, summary_block * BLOCK + off, entry)
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        assert fs._nat_journal == {nid: (ino, addr)}
        assert fs.read_all(fs.inode(nid)) == expected_files()["data/com.example.app/databases/medium.bin"]


def test_absurd_journal_is_ignored(victim):
    _, _, chosen = _cp_start(victim)
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        summary_block, compact = fs.cp_start + fs.cp_start_sum, bool(fs.cp_flags & 0x04)
    _patch(victim, summary_block * BLOCK + (0 if compact else 3584), struct.pack("<H", 60000))
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        assert fs._nat_journal == {} and any("NAT journal claims" in n for n in fs.notes)
    assert chosen


def test_encrypted_directories_are_reported_not_descended(victim):
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        data_dir = next(i for n, i, _t in fs.entries(fs.inode(fs.sb.root_ino)) if n == b"data")
        _ino, addr = fs._nat_lookup(data_dir)
    raw = victim.read_bytes()
    _patch(victim, addr * BLOCK + 2, bytes([raw[addr * BLOCK + 2] | ADVISE_ENCRYPT]))
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        issues = []
        paths = [e.path for e in fs.walk(issues)]
    assert not any(p.startswith("data/") for p in paths) and "system/packages.xml" in paths
    assert any(i.issue_type == "file_based_encryption_detected" and i.path == "data" for i in issues)


def test_pointer_outside_the_main_area_fails_one_file_only(victim):
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        e = next(e for e in fs.walk() if e.path.endswith("medium.bin"))
        _ino, addr = fs._nat_lookup(e.inode.number)
        base = 360 + 4 * (2 if e.inode.inline & EXTRA_ATTR else 0)
    _patch(victim, addr * BLOCK + base, struct.pack("<I", 0x7FFFFFF0))
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        by_path = {e.path: e.inode for e in fs.walk()}
        with pytest.raises(F2fsError, match="outside the main area"):
            fs.read_all(by_path["data/com.example.app/databases/medium.bin"])
        assert fs.read_all(by_path["data/com.example.app/databases/small.txt"]) == b"hello android\n"


def test_truncated_image_is_noted_and_does_not_crash(victim):
    victim.write_bytes(victim.read_bytes()[: 30 * 1024 * 1024])
    with RawImageSource(victim) as src:
        fs = F2fsFileSystem(src)
        assert any("shorter" in n for n in fs.notes)
        issues = []
        list(fs.walk(issues))     # whatever is reachable is returned; the rest becomes per-file errors


def test_crc_helper_matches_a_real_checkpoint(images):
    with RawImageSource(images["kernel_clean"]) as src:
        fs = F2fsFileSystem(src)
        head = fs._block(fs.cp_start)
        crc_off = struct.unpack_from("<I", head, 164)[0]
        assert _crc32_le(0xF2F52010, head[:crc_off]) == struct.unpack_from("<I", head, crc_off)[0]
