"""A read-only f2fs parser — the file system of most current Android phones' ``/data``.

Layout recap (all little-endian, 4 KiB blocks, 512 blocks per segment)::

    superblock (block 0, at +1024) │ checkpoint (2 packs) │ SIT │ NAT │ SSA │ main area (nodes + data)

* Files are reached through **nodes**: a node id (nid) is turned into a block address by the **NAT** (node address table). The
  NAT on disk can be *behind*: recent NAT updates live in a small **journal** inside the checkpoint pack's data summary block, and
  those entries override the NAT block. Ignoring the journal would read stale (or no) nodes, so it is applied.
* The newest *valid* checkpoint pack wins (valid = both copies of its header agree and the CRC matches).
* Every node block read is cross-checked against its footer (nid and ino) and the checkpoint version, so a stale or foreign block
  is rejected instead of being trusted.
* An inode holds its first data addresses inline, then up to two direct nodes, two indirect nodes and one double-indirect node.
  Small files can live *inside* the inode (inline data) and small directories inside theirs (inline dentry); both are handled.

Not supported (reported, never guessed): compressed files (the ``compression`` feature), multi-device volumes, quota/verity
semantics. fscrypt-encrypted inodes are *detected* (names and contents are ciphertext) and never read.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass

from android_forensics.acquisition.image.ext4 import MAX_PATH_DEPTH, WalkEntry, WalkIssue
from android_forensics.acquisition.image.source import ImageError, ImageSource

F2FS_MAGIC = 0xF2F52010
BLOCK = 4096
BLOCK_SHIFT = 12
ADDRS_PER_BLOCK = 1018
NIDS_PER_BLOCK = 1018
DEF_ADDRS_PER_INODE = 923
DEFAULT_INLINE_XATTR_ADDRS = 50
NAT_ENTRIES_PER_BLOCK = BLOCK // 9            # 455
NAT_JOURNAL_ENTRIES = 38
SUM_ENTRIES_BYTES = 7 * 512                   # 3584: where the journal starts inside a summary block
NR_DENTRY_IN_BLOCK = 214
SLOT = 8
NULL_ADDR, NEW_ADDR, COMPRESS_ADDR = 0, 0xFFFFFFFF, 0xFFFFFFFE
MAX_DIR_BLOCKS = 1 << 20

# i_inline
INLINE_XATTR, INLINE_DATA, INLINE_DENTRY, DATA_EXIST, EXTRA_ATTR = 0x01, 0x02, 0x04, 0x08, 0x20
# i_advise
ADVISE_ENCRYPT, ADVISE_ENC_NAME = 0x04, 0x08
# checkpoint flags
CP_LARGE_NAT_BITMAP, CP_COMPACT_SUM, CP_UMOUNT, CP_NAT_BITS = 0x400, 0x04, 0x01, 0x80
# superblock features
FEATURE_ENCRYPT, FEATURE_EXTRA_ATTR, FEATURE_FLEX_XATTR, FEATURE_COMPRESSION = 0x1, 0x8, 0x40, 0x2000
S_IFMT, S_IFREG, S_IFDIR, S_IFLNK = 0xF000, 0x8000, 0x4000, 0xA000


class F2fsError(ImageError):
    pass


def _crc32_le(seed: int, data: bytes) -> int:
    """Linux ``crc32_le`` (no pre/post inversion), expressed with zlib's inverted CRC."""
    return zlib.crc32(data, seed ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


@dataclass(frozen=True)
class F2fsInode:
    number: int
    mode: int
    size: int
    links: int
    advise: int
    inline: int
    atime: int | None
    ctime: int | None
    mtime: int | None
    crtime: int | None
    block: bytes          # the 4096-byte inode node

    @property
    def is_dir(self) -> bool:
        return self.mode & S_IFMT == S_IFDIR

    @property
    def is_file(self) -> bool:
        return self.mode & S_IFMT == S_IFREG

    @property
    def is_symlink(self) -> bool:
        return self.mode & S_IFMT == S_IFLNK

    @property
    def encrypted(self) -> bool:
        return bool(self.advise & ADVISE_ENCRYPT)


@dataclass(frozen=True)
class F2fsSuper:
    block_count: int
    log_blocks_per_seg: int
    segment_count_main: int
    cp_blkaddr: int
    nat_blkaddr: int
    main_blkaddr: int
    root_ino: int
    feature: int
    label: str
    uuid: str
    version: str
    segment_count_nat: int

    @property
    def blocks_per_seg(self) -> int:
        return 1 << self.log_blocks_per_seg


def parse_superblock(raw: bytes) -> F2fsSuper:
    if len(raw) < 3072:
        raise F2fsError("superblock truncated")
    if struct.unpack_from("<I", raw, 0)[0] != F2FS_MAGIC:
        raise F2fsError("f2fs magic not found")
    log_block = struct.unpack_from("<I", raw, 16)[0]
    log_seg = struct.unpack_from("<I", raw, 20)[0]
    if log_block != BLOCK_SHIFT:
        raise F2fsError(f"unsupported f2fs block size 2^{log_block}")
    if log_seg != 9:
        raise F2fsError(f"unsupported blocks-per-segment 2^{log_seg}")
    block_count = struct.unpack_from("<Q", raw, 36)[0]
    seg_nat, seg_ssa, seg_main = struct.unpack_from("<III", raw, 60)
    seg0, cp_blk, sit_blk, nat_blk, ssa_blk, main_blk, root, _node_ino, _meta_ino = struct.unpack_from("<9I", raw, 72)
    label = raw[124:124 + 1024].decode("utf-16le", "replace").split("\0")[0]
    version = raw[1668:1668 + 256].split(b"\0")[0].decode("ascii", "replace")
    feature = struct.unpack_from("<I", raw, 2180)[0]
    if block_count == 0 or seg_main == 0 or main_blk == 0 or not (0 < root < (1 << 24)):
        raise F2fsError("implausible f2fs geometry")
    if main_blk + seg_main * (1 << log_seg) > block_count + (1 << log_seg) * 4:
        raise F2fsError("main area extends beyond the declared block count")
    return F2fsSuper(block_count, log_seg, seg_main, cp_blk, nat_blk, main_blk, root, feature, label, raw[108:124].hex(), version, seg_nat)


def looks_like_f2fs(src: ImageSource, base: int = 0) -> bool:
    raw = src.read_at(base + 1024, 4)
    return len(raw) == 4 and struct.unpack("<I", raw)[0] == F2FS_MAGIC


class F2fsFileSystem:
    def __init__(self, src: ImageSource, base: int = 0, length: int | None = None):
        self.src, self.base = src, base
        self.sb = parse_superblock(src.read_exact(base + 1024, 3072))
        self.notes: list[str] = []
        avail = length if length is not None else src.size - base
        self.total_blocks = min(self.sb.block_count, avail // BLOCK)
        if self.sb.block_count * BLOCK > avail:
            self.notes.append(f"image is shorter than the file system declares ({avail:,} < {self.sb.block_count * BLOCK:,} bytes): "
                              "files stored beyond the end are unreadable")
        if self.sb.feature & FEATURE_COMPRESSION:
            self.notes.append("volume uses f2fs compression: compressed files cannot be read and are reported individually")
        if self.sb.feature & FEATURE_ENCRYPT:
            self.notes.append("volume has the encrypt feature: encrypted directories/files cannot be read without keys")
        self._pick_checkpoint()
        self._nat_journal: dict[int, tuple[int, int]] = self._read_nat_journal()
        self._inode_cache: dict[int, F2fsInode] = {}

    # ------------------------------------------------------------------ low level
    def _block(self, n: int) -> bytes:
        if n < 0 or n >= self.total_blocks:
            raise F2fsError(f"block {n} is outside the file system ({self.total_blocks} blocks)")
        return self.src.read_exact(self.base + n * BLOCK, BLOCK)

    def _main_block(self, addr: int) -> bytes:
        lo = self.sb.main_blkaddr
        hi = lo + self.sb.segment_count_main * self.sb.blocks_per_seg
        if not lo <= addr < hi:
            raise F2fsError(f"block address {addr} is outside the main area [{lo}, {hi})")
        return self._block(addr)

    # ------------------------------------------------------------------ checkpoint
    def _pick_checkpoint(self) -> None:
        best: tuple[int, int, bytes] | None = None
        for pack in (0, 1):
            start = self.sb.cp_blkaddr + pack * self.sb.blocks_per_seg
            try:
                head = self._block(start)
                (ver,) = struct.unpack_from("<Q", head, 0)
                crc_off = struct.unpack_from("<I", head, 164)[0]
                total = struct.unpack_from("<I", head, 136)[0]
                if not (192 <= crc_off <= BLOCK - 4) or not (2 <= total <= self.sb.blocks_per_seg):
                    continue
                if _crc32_le(F2FS_MAGIC, head[:crc_off]) != struct.unpack_from("<I", head, crc_off)[0]:
                    continue
                tail = self._block(start + total - 1)
                if struct.unpack_from("<Q", tail, 0)[0] != ver:
                    continue   # an interrupted checkpoint: the two copies of the header disagree
            except F2fsError:
                continue
            if best is None or ver > best[0]:
                best = (ver, start, head)
        if best is None:
            raise F2fsError("no valid checkpoint pack found (damaged or not a clean f2fs volume)")
        self.cp_ver, self.cp_start, cp = best
        self.cp_flags = struct.unpack_from("<I", cp, 132)[0]
        self.cp_pack_total = struct.unpack_from("<I", cp, 136)[0]
        self.cp_start_sum = struct.unpack_from("<I", cp, 140)[0]
        sit_bytes = struct.unpack_from("<I", cp, 156)[0]
        nat_bytes = struct.unpack_from("<I", cp, 160)[0]
        crc_off = struct.unpack_from("<I", cp, 164)[0]
        bitmap = cp[192:crc_off]
        if self.cp_flags & CP_LARGE_NAT_BITMAP:
            self._nat_bitmap = bitmap[:nat_bytes]
        else:
            self._nat_bitmap = bitmap[sit_bytes:sit_bytes + nat_bytes]
        if not self.cp_flags & CP_UMOUNT:
            self.notes.append("volume was not cleanly unmounted (checkpoint lacks the umount flag): recent changes may be missing "
                              "because the roll-forward recovery of fsync'd data was NOT performed")

    def _read_nat_journal(self) -> dict[int, tuple[int, int]]:
        """NAT entries held in the checkpoint's data summary block: {nid: (ino, block_addr)}; they override NAT blocks."""
        try:
            blk = self._block(self.cp_start + self.cp_start_sum)
        except F2fsError:
            self.notes.append("checkpoint summary block unreadable: the NAT journal could not be applied (some files may be missing)")
            return {}
        off = 0 if self.cp_flags & CP_COMPACT_SUM else SUM_ENTRIES_BYTES
        (n,) = struct.unpack_from("<H", blk, off)
        if n > NAT_JOURNAL_ENTRIES:
            self.notes.append(f"NAT journal claims {n} entries (max {NAT_JOURNAL_ENTRIES}): ignored")
            return {}
        out: dict[int, tuple[int, int]] = {}
        for i in range(n):
            nid, _ver, ino, addr = struct.unpack_from("<IBII", blk, off + 2 + i * 13)
            out[nid] = (ino, addr)
        return out

    # ------------------------------------------------------------------ NAT
    def _nat_lookup(self, nid: int) -> tuple[int, int]:
        """(ino, block_addr) for ``nid``."""
        if nid in self._nat_journal:
            return self._nat_journal[nid]
        block_off, idx = divmod(nid, NAT_ENTRIES_PER_BLOCK)
        seg_off = block_off >> self.sb.log_blocks_per_seg
        addr = self.sb.nat_blkaddr + (seg_off << self.sb.log_blocks_per_seg << 1) + (block_off & (self.sb.blocks_per_seg - 1))
        if block_off // 8 < len(self._nat_bitmap) and self._nat_bitmap[block_off // 8] & (0x80 >> (block_off % 8)):  # f2fs bitmaps are MSB-first
            addr += self.sb.blocks_per_seg           # the second copy of this NAT block is the current one
        if block_off >= self.sb.segment_count_nat * (self.sb.blocks_per_seg // 2):
            raise F2fsError(f"node id {nid} is beyond the NAT")
        raw = self._block(addr)
        _ver, ino, blk = struct.unpack_from("<BII", raw, idx * 9)
        return ino, blk

    def node(self, nid: int, expect_ino: int | None = None) -> bytes:
        ino, addr = self._nat_lookup(nid)
        if addr == NULL_ADDR:
            raise F2fsError(f"node {nid} is not allocated")
        blk = self._main_block(addr)
        f_nid, f_ino = struct.unpack_from("<II", blk, 4072)
        (f_cpver,) = struct.unpack_from("<Q", blk, 4072 + 12)
        if f_nid != nid or f_ino != ino or (expect_ino is not None and f_ino != expect_ino):
            raise F2fsError(f"node {nid} at block {addr} does not describe itself (footer nid/ino mismatch): stale or forged block")
        if f_cpver > self.cp_ver:
            raise F2fsError(f"node {nid} is newer than the checkpoint (cp_ver {f_cpver} > {self.cp_ver})")
        return blk

    # ------------------------------------------------------------------ inodes
    def inode(self, number: int) -> F2fsInode:
        cached = self._inode_cache.get(number)
        if cached is not None:
            return cached
        blk = self.node(number)
        if number != struct.unpack_from("<I", blk, 4076)[0]:
            raise F2fsError(f"node {number} is not an inode")
        mode, advise, inline = struct.unpack_from("<HBB", blk, 0)
        links = struct.unpack_from("<I", blk, 12)[0]
        size = struct.unpack_from("<Q", blk, 16)[0]
        atime, ctime, mtime = struct.unpack_from("<QQQ", blk, 32)
        crtime = None
        if inline & EXTRA_ATTR:
            (extra,) = struct.unpack_from("<H", blk, 360)
            if extra >= 24:
                crtime = struct.unpack_from("<Q", blk, 372)[0]
        ino = F2fsInode(number, mode, size, links, advise, inline, atime or None, ctime or None, mtime or None, crtime or None, blk)
        if len(self._inode_cache) < 100_000:
            self._inode_cache[number] = ino
        return ino

    def _geometry(self, ino: F2fsInode) -> tuple[int, int, int]:
        """(first data slot in i_addr, number of inline addresses, inline-data byte capacity)."""
        extra_words = struct.unpack_from("<H", ino.block, 360)[0] // 4 if ino.inline & EXTRA_ATTR else 0
        xattr_words = 0
        if ino.inline & INLINE_XATTR:
            xattr_words = (struct.unpack_from("<H", ino.block, 362)[0] if self.sb.feature & FEATURE_FLEX_XATTR and ino.inline & EXTRA_ATTR
                           else DEFAULT_INLINE_XATTR_ADDRS)
        n_addrs = DEF_ADDRS_PER_INODE - extra_words - xattr_words
        if n_addrs <= 1 or extra_words > DEF_ADDRS_PER_INODE:
            raise F2fsError(f"inode {ino.number} has an impossible address area")
        return extra_words, n_addrs, 4 * (n_addrs - 1)

    # ------------------------------------------------------------------ data addresses
    def _addr_of(self, ino: F2fsInode, index: int, cache: dict[int, bytes]) -> int:
        base, n_inode, _cap = self._geometry(ino)
        blk = ino.block
        nid = lambda i: struct.unpack_from("<I", blk, 360 + 4 * (DEF_ADDRS_PER_INODE + i))[0]  # noqa: E731

        def dnode(n: int) -> bytes:
            if n not in cache:
                if len(cache) > 256:
                    cache.clear()
                cache[n] = self.node(n, ino.number)
            return cache[n]

        if index < n_inode:
            return struct.unpack_from("<I", blk, 360 + 4 * (base + index))[0]
        index -= n_inode
        for slot in (0, 1):
            if index < ADDRS_PER_BLOCK:
                n = nid(slot)
                return NULL_ADDR if n == 0 else struct.unpack_from("<I", dnode(n), 4 * index)[0]
            index -= ADDRS_PER_BLOCK
        per_ind = NIDS_PER_BLOCK * ADDRS_PER_BLOCK
        for slot in (2, 3):
            if index < per_ind:
                n = nid(slot)
                if n == 0:
                    return NULL_ADDR
                child = struct.unpack_from("<I", dnode(n), 4 * (index // ADDRS_PER_BLOCK))[0]
                return NULL_ADDR if child == 0 else struct.unpack_from("<I", dnode(child), 4 * (index % ADDRS_PER_BLOCK))[0]
            index -= per_ind
        n = nid(4)
        if n == 0 or index >= NIDS_PER_BLOCK * per_ind:
            return NULL_ADDR
        mid = struct.unpack_from("<I", dnode(n), 4 * (index // per_ind))[0]
        if mid == 0:
            return NULL_ADDR
        rest = index % per_ind
        child = struct.unpack_from("<I", dnode(mid), 4 * (rest // ADDRS_PER_BLOCK))[0]
        return NULL_ADDR if child == 0 else struct.unpack_from("<I", dnode(child), 4 * (rest % ADDRS_PER_BLOCK))[0]

    def open_file(self, ino: F2fsInode) -> F2fsFileReader:
        return F2fsFileReader(self, ino)

    def read_all(self, ino: F2fsInode, limit: int = 256 * 1024 * 1024) -> bytes:
        if ino.size > limit:
            raise F2fsError(f"inode {ino.number} is {ino.size:,} bytes (limit {limit:,})")
        r = self.open_file(ino)
        out = bytearray()
        while chunk := r.read(1 << 20):
            out += chunk
        return bytes(out)

    # ------------------------------------------------------------------ directories
    @staticmethod
    def _parse_dentries(bitmap: bytes, entries: bytes, names: bytes, count: int) -> list[tuple[bytes, int, int]]:
        out: list[tuple[bytes, int, int]] = []
        i = 0
        while i < count:
            if not bitmap[i // 8] & (1 << (i % 8)):
                i += 1
                continue
            _hash, ino, name_len, ftype = struct.unpack_from("<IIHB", entries, i * 11)
            if name_len == 0 or name_len > 255 or i * SLOT + name_len > len(names):
                i += 1
                continue
            out.append((names[i * SLOT:i * SLOT + name_len], ino, ftype))
            i += -(-name_len // SLOT)
        return out

    def entries(self, directory: F2fsInode) -> list[tuple[bytes, int, int]]:
        if not directory.is_dir:
            raise F2fsError(f"inode {directory.number} is not a directory")
        out: list[tuple[bytes, int, int]] = []
        if directory.inline & INLINE_DENTRY:
            base, _n, cap = self._geometry(directory)
            nr = cap * 8 // ((11 + SLOT) * 8 + 1)
            bm_size = (nr + 7) // 8
            area = directory.block[360 + 4 * (base + 1):360 + 4 * (base + 1) + cap]
            bitmap = area[:bm_size]
            reserved = cap - ((11 + SLOT) * nr + bm_size)
            ents = area[bm_size + reserved:bm_size + reserved + 11 * nr]
            names = area[bm_size + reserved + 11 * nr:bm_size + reserved + 11 * nr + SLOT * nr]
            return self._parse_dentries(bitmap, ents, names, nr)
        nblocks = min(-(-directory.size // BLOCK), MAX_DIR_BLOCKS)
        cache: dict[int, bytes] = {}
        for idx in range(nblocks):
            addr = self._addr_of(directory, idx, cache)
            if addr in (NULL_ADDR, NEW_ADDR):
                continue
            blk = self._main_block(addr)
            out += self._parse_dentries(blk[:27], blk[30:30 + 11 * NR_DENTRY_IN_BLOCK],
                                        blk[30 + 11 * NR_DENTRY_IN_BLOCK:30 + 19 * NR_DENTRY_IN_BLOCK], NR_DENTRY_IN_BLOCK)
        return out

    def root_names(self) -> set[str]:
        try:
            return {n.decode("utf-8", "replace") for n, _i, _t in self.entries(self.inode(self.sb.root_ino))}
        except ImageError:
            return set()

    def walk(self, issues: list[WalkIssue] | None = None) -> Iterator[WalkEntry]:
        issues = issues if issues is not None else []
        try:
            root = self.inode(self.sb.root_ino)
        except ImageError as exc:
            issues.append(WalkIssue("/", "filesystem_root_unreadable", str(exc)))
            return
        if not root.is_dir:
            issues.append(WalkIssue("/", "filesystem_root_unreadable", "root inode is not a directory"))
            return
        visited = {root.number}
        stack: list[tuple[F2fsInode, str, int]] = [(root, "", 0)]
        while stack:
            directory, prefix, depth = stack.pop()
            if directory.encrypted:
                n = 0
                try:
                    n = len([e for e in self.entries(directory) if e[0] not in (b".", b"..")])
                except ImageError:
                    pass
                issues.append(WalkIssue(prefix or "/", "file_based_encryption_detected",
                                        f"directory is fscrypt-encrypted ({n} entries with ciphertext names); not descended; this tool never decrypts"))
                continue
            try:
                entries = self.entries(directory)
            except ImageError as exc:
                issues.append(WalkIssue(prefix or "/", "directory_unreadable", str(exc)))
                continue
            children: list[tuple[F2fsInode, str]] = []
            for raw_name, nid, _ftype in entries:
                if raw_name in (b".", b".."):
                    continue
                name = raw_name.decode("utf-8", "surrogateescape")
                path = f"{prefix}/{name}" if prefix else name
                if "/" in name or "\0" in name:
                    issues.append(WalkIssue(path, "unsafe_path_skipped", "directory entry name contains '/' or NUL"))
                    continue
                try:
                    ino = self.inode(nid)
                except ImageError as exc:
                    issues.append(WalkIssue(path, "inode_unreadable", str(exc)))
                    continue
                if ino.is_dir:
                    if ino.number in visited:
                        issues.append(WalkIssue(path, "directory_cycle_skipped", f"inode {ino.number} was already visited (cycle or hard-linked directory)"))
                        continue
                    if depth + 1 > MAX_PATH_DEPTH:
                        issues.append(WalkIssue(path, "path_too_deep", f"deeper than {MAX_PATH_DEPTH} levels"))
                        continue
                    visited.add(ino.number)
                    stack.append((ino, path, depth + 1))
                else:
                    children.append((ino, path))
            yield from (WalkEntry(p, i) for i, p in sorted(children, key=lambda c: c[1]))  # type: ignore[arg-type]


class F2fsFileReader:
    """Sequential bounded reader over one inode's contents (holes and NEW_ADDR blocks read as zeros)."""

    def __init__(self, fs: F2fsFileSystem, ino: F2fsInode):
        self.fs, self.ino, self.size, self.pos = fs, ino, ino.size, 0
        self._cache: dict[int, bytes] = {}
        self._inline: bytes | None = None
        if ino.inline & INLINE_DATA:
            base, _n, cap = fs._geometry(ino)
            if ino.size > cap:
                raise F2fsError(f"inline-data inode {ino.number} claims {ino.size} bytes but holds at most {cap}")
            start = 360 + 4 * (base + 1)
            self._inline = ino.block[start:start + ino.size] if ino.inline & DATA_EXIST or ino.size else b""

    def read(self, n: int = -1) -> bytes:
        remaining = self.size - self.pos
        if remaining <= 0:
            return b""
        n = remaining if n is None or n < 0 else min(n, remaining, 4 * 1024 * 1024)
        if self._inline is not None:
            chunk = self._inline[self.pos:self.pos + n]
            self.pos += n
            return chunk + bytes(n - len(chunk))
        out = bytearray()
        while len(out) < n:
            idx, inner = divmod(self.pos, BLOCK)
            take = min(n - len(out), BLOCK - inner)
            addr = self.fs._addr_of(self.ino, idx, self._cache)
            if addr in (NULL_ADDR, NEW_ADDR):
                out += bytes(take)
            elif addr == COMPRESS_ADDR:
                raise F2fsError(f"inode {self.ino.number} is stored compressed (f2fs compression is not supported)")
            else:
                out += self.fs._main_block(addr)[inner:inner + take]
            self.pos += take
        return bytes(out)
