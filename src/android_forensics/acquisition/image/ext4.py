"""A read-only ext2/3/4 parser — enough to enumerate and read every regular file of an Android ``userdata`` image.

Design rules (all inputs are hostile):

* nothing is ever written; the image is read through :class:`ImageSource`;
* every block number, count, length and inode number from disk is range-checked before use;
* directory walks are cycle-guarded and depth-limited; extent trees are depth- and size-limited;
* a damaged structure raises :class:`Ext4Error` for *that file or directory* — the caller records an issue and carries on;
* the journal is **not** replayed: if the file system was not cleanly unmounted this is reported, because metadata may
  lag behind the journal (and that is itself forensically interesting).

Not supported (reported, never guessed): ``meta_bg`` layouts, ``inline_data`` files, compression. fscrypt-encrypted
inodes are *detected* (so the examiner learns the evidence is encrypted) but never read.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass

from android_forensics.acquisition.image.source import ImageError, ImageSource

EXT_MAGIC = 0xEF53
ROOT_INODE = 2
MAX_EXTENT_DEPTH = 5
MAX_EXTENTS_PER_FILE = 2_000_000
MAX_DIR_BYTES = 256 * 1024 * 1024
MAX_PATH_DEPTH = 64
MAX_GROUPS = 4_000_000

# incompat feature bits
INC_COMPRESSION, INC_FILETYPE, INC_RECOVER, INC_JOURNAL_DEV, INC_META_BG = 0x1, 0x2, 0x4, 0x8, 0x10
INC_EXTENTS, INC_64BIT, INC_MMP, INC_FLEX_BG = 0x40, 0x80, 0x100, 0x200
INC_EA_INODE, INC_DIRDATA, INC_CSUM_SEED, INC_LARGEDIR, INC_INLINE_DATA, INC_ENCRYPT, INC_CASEFOLD = 0x400, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000
_SUPPORTED_INCOMPAT = (INC_FILETYPE | INC_RECOVER | INC_EXTENTS | INC_64BIT | INC_MMP | INC_FLEX_BG | INC_EA_INODE | INC_DIRDATA
                       | INC_CSUM_SEED | INC_LARGEDIR | INC_INLINE_DATA | INC_ENCRYPT | INC_CASEFOLD)

# inode flags
FL_ENCRYPT, FL_INDEX, FL_EXTENTS, FL_INLINE_DATA = 0x800, 0x1000, 0x80000, 0x10000000

S_IFMT, S_IFREG, S_IFDIR, S_IFLNK = 0xF000, 0x8000, 0x4000, 0xA000


class Ext4Error(ImageError):
    pass


@dataclass(frozen=True)
class Ext4Inode:
    number: int
    mode: int
    uid: int
    gid: int
    size: int
    links: int
    flags: int
    atime: int | None
    ctime: int | None
    mtime: int | None
    crtime: int | None
    dtime: int | None
    i_block: bytes

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
        return bool(self.flags & FL_ENCRYPT)


@dataclass(frozen=True)
class DirEntry:
    name: bytes
    inode: int
    file_type: int  # 0 unknown, 1 reg, 2 dir, 3 chr, 4 blk, 5 fifo, 6 sock, 7 symlink


@dataclass
class WalkEntry:
    path: str
    inode: Ext4Inode


@dataclass
class WalkIssue:
    path: str
    issue_type: str
    detail: str


@dataclass
class Superblock:
    inodes_count: int
    blocks_count: int
    block_size: int
    first_data_block: int
    blocks_per_group: int
    inodes_per_group: int
    inode_size: int
    feature_compat: int
    feature_incompat: int
    feature_ro_compat: int
    desc_size: int
    label: str
    uuid: str
    last_mounted: str
    mount_time: int
    write_time: int


def _ts(base: int, extra: int | None) -> int | None:
    t = struct.unpack("<i", struct.pack("<I", base & 0xFFFFFFFF))[0]
    if extra:
        t += (extra & 3) << 32
    return t if t != 0 else None


def parse_superblock(raw: bytes) -> Superblock:
    if len(raw) < 1024:
        raise Ext4Error("superblock truncated")
    (inodes, blocks_lo, _r, _f, _fi, first_data, log_bs) = struct.unpack_from("<IIIIIII", raw, 0)
    (blocks_per_group, _fpg, inodes_per_group, mtime, wtime) = struct.unpack_from("<IIIII", raw, 32)
    (magic,) = struct.unpack_from("<H", raw, 56)
    if magic != EXT_MAGIC:
        raise Ext4Error("ext2/3/4 magic (0xEF53) not found")
    (rev,) = struct.unpack_from("<I", raw, 76)
    inode_size = struct.unpack_from("<H", raw, 88)[0] if rev >= 1 else 128
    compat, incompat, ro_compat = struct.unpack_from("<III", raw, 92)
    uuid = raw[104:120].hex()
    label = raw[120:136].split(b"\0")[0].decode("utf-8", "replace")
    last_mounted = raw[136:200].split(b"\0")[0].decode("utf-8", "replace")
    blocks_hi = struct.unpack_from("<I", raw, 336)[0] if incompat & INC_64BIT else 0
    desc_size = struct.unpack_from("<H", raw, 254)[0] if incompat & INC_64BIT else 32
    if log_bs > 6:
        raise Ext4Error(f"implausible block size exponent {log_bs}")
    block_size = 1024 << log_bs
    if inode_size < 128 or inode_size > block_size or inode_size & (inode_size - 1):
        raise Ext4Error(f"implausible inode size {inode_size}")
    if blocks_per_group == 0 or blocks_per_group > block_size * 8 or inodes_per_group == 0 or inodes_per_group > block_size * 8:
        raise Ext4Error("implausible blocks/inodes per group")
    if incompat & INC_64BIT and (desc_size < 64 or desc_size > 1024 or desc_size & (desc_size - 1)):
        raise Ext4Error(f"implausible group descriptor size {desc_size}")
    return Superblock(
        inodes_count=inodes, blocks_count=blocks_lo | (blocks_hi << 32), block_size=block_size, first_data_block=first_data,
        blocks_per_group=blocks_per_group, inodes_per_group=inodes_per_group, inode_size=inode_size, feature_compat=compat,
        feature_incompat=incompat, feature_ro_compat=ro_compat, desc_size=desc_size, label=label, uuid=uuid,
        last_mounted=last_mounted, mount_time=mtime, write_time=wtime,
    )


def looks_like_ext(src: ImageSource, base: int = 0) -> bool:
    raw = src.read_at(base + 1024 + 56, 2)
    return len(raw) == 2 and struct.unpack("<H", raw)[0] == EXT_MAGIC


class Ext4FileSystem:
    def __init__(self, src: ImageSource, base: int = 0, length: int | None = None):
        self.src, self.base = src, base
        self.sb = parse_superblock(src.read_exact(base + 1024, 1024))
        self.bs = self.sb.block_size
        inc = self.sb.feature_incompat
        if inc & INC_META_BG:
            raise Ext4Error("meta_bg group-descriptor layout is not supported")
        if inc & INC_JOURNAL_DEV:
            raise Ext4Error("this is an external journal device, not a file system")
        unknown = inc & ~_SUPPORTED_INCOMPAT & ~INC_META_BG & ~INC_JOURNAL_DEV
        if unknown:
            raise Ext4Error(f"unsupported incompatible feature flags 0x{unknown:x}")
        avail = (length if length is not None else src.size - base)
        self.blocks = self.sb.blocks_count
        if self.blocks == 0:
            raise Ext4Error("file system declares zero blocks")
        self.notes: list[str] = []
        if self.blocks * self.bs > avail:
            self.notes.append(
                f"image is shorter than the file system declares ({avail:,} bytes available, {self.blocks * self.bs:,} declared): "
                "files stored beyond the end are unreadable")
            self.blocks = avail // self.bs
        self.groups = -(-(self.sb.blocks_count - self.sb.first_data_block) // self.sb.blocks_per_group)
        if self.groups <= 0 or self.groups > MAX_GROUPS:
            raise Ext4Error(f"implausible block group count {self.groups}")
        if self.groups * self.sb.inodes_per_group < self.sb.inodes_count:
            raise Ext4Error("inode counts are inconsistent")
        if inc & INC_RECOVER:
            self.notes.append("file system was not cleanly unmounted (journal needs recovery); the journal was NOT replayed, "
                              "so metadata may lag behind what the device last wrote")
        if inc & INC_ENCRYPT:
            self.notes.append("file system has the fscrypt 'encrypt' feature enabled; encrypted files cannot be read without keys")
        self._gdt_cache: dict[int, int] = {}

    # ---------------------------------------------------------------- raw access
    def _read_block(self, n: int) -> bytes:
        if n < 0 or n >= self.blocks:
            raise Ext4Error(f"block {n} is outside the file system ({self.blocks} blocks)")
        return self.src.read_exact(self.base + n * self.bs, self.bs)

    # ---------------------------------------------------------------- inodes
    def _inode_table(self, group: int) -> int:
        if group in self._gdt_cache:
            return self._gdt_cache[group]
        gdt_block = self.sb.first_data_block + 1
        off = gdt_block * self.bs + group * self.sb.desc_size
        raw = self.src.read_exact(self.base + off, min(self.sb.desc_size, 64) if self.sb.desc_size >= 64 else 32)
        lo = struct.unpack_from("<I", raw, 8)[0]
        hi = struct.unpack_from("<I", raw, 0x28)[0] if len(raw) >= 0x2C else 0
        table = lo | (hi << 32)
        if table == 0 or table >= self.blocks:
            raise Ext4Error(f"group {group} has an invalid inode table location ({table})")
        self._gdt_cache[group] = table
        return table

    def inode(self, number: int) -> Ext4Inode:
        if number < 1 or number > self.sb.inodes_count:
            raise Ext4Error(f"inode {number} is out of range")
        group, index = divmod(number - 1, self.sb.inodes_per_group)
        table = self._inode_table(group)
        raw = self.src.read_exact(self.base + table * self.bs + index * self.sb.inode_size, self.sb.inode_size)
        mode, uid_lo, size_lo, atime, ctime, mtime, dtime, gid_lo, links, _blocks, flags = struct.unpack_from("<HHIIIIIHHII", raw, 0)
        i_block = raw[40:100]
        size_hi = struct.unpack_from("<I", raw, 108)[0]
        extra = {"ctime": None, "mtime": None, "atime": None, "crtime": None}
        crtime = None
        if self.sb.inode_size > 128:
            (isize,) = struct.unpack_from("<H", raw, 128)
            if isize >= 24 and self.sb.inode_size >= 152:
                extra["ctime"], extra["mtime"], extra["atime"] = struct.unpack_from("<III", raw, 132)
                crtime = _ts(struct.unpack_from("<I", raw, 144)[0], struct.unpack_from("<I", raw, 148)[0])
            elif isize >= 4:
                extra["ctime"], extra["mtime"], extra["atime"] = struct.unpack_from("<III", raw, 132) if self.sb.inode_size >= 144 else (None,) * 3
        size = size_lo | (size_hi << 32)
        return Ext4Inode(
            number=number, mode=mode, uid=uid_lo, gid=gid_lo, size=size, links=links, flags=flags, atime=_ts(atime, extra["atime"]),
            ctime=_ts(ctime, extra["ctime"]), mtime=_ts(mtime, extra["mtime"]), crtime=crtime, dtime=_ts(dtime, None), i_block=i_block,
        )

    # ---------------------------------------------------------------- block mapping
    def _extents(self, i_block: bytes) -> list[tuple[int, int, int, bool]]:
        """(logical_block, physical_block, count, initialised) runs, sorted by logical block."""
        runs: list[tuple[int, int, int, bool]] = []
        stack: list[tuple[bytes, int]] = [(i_block, 0)]
        while stack:
            node, depth = stack.pop()
            magic, entries, _mx, node_depth = struct.unpack_from("<HHHH", node, 0)
            if magic != 0xF30A:
                raise Ext4Error("bad extent header magic")
            if node_depth > MAX_EXTENT_DEPTH or depth > MAX_EXTENT_DEPTH:
                raise Ext4Error("extent tree too deep")
            if 12 + entries * 12 > len(node):
                raise Ext4Error("extent node claims more entries than fit")
            for i in range(entries):
                off = 12 + i * 12
                if node_depth == 0:
                    lblk, length, hi, lo = struct.unpack_from("<IHHI", node, off)
                    init = length <= 32768
                    count = length if init else length - 32768
                    runs.append((lblk, lo | (hi << 32), count, init))
                    if len(runs) > MAX_EXTENTS_PER_FILE:
                        raise Ext4Error("file has an implausible number of extents")
                else:
                    _lblk, leaf_lo, leaf_hi, _un = struct.unpack_from("<IIHH", node, off)
                    stack.append((self._read_block(leaf_lo | (leaf_hi << 32)), depth + 1))
        runs.sort(key=lambda r: r[0])
        return runs

    def _blockmap(self, i_block: bytes) -> Iterator[tuple[int, int, int, bool]]:
        ptrs = struct.unpack("<15I", i_block)
        per = self.bs // 4
        lblk = 0
        for p in ptrs[:12]:
            if p:
                yield (lblk, p, 1, True)
            lblk += 1

        def walk(block: int, level: int, base: int) -> Iterator[tuple[int, int, int, bool]]:
            if block == 0:
                return
            data = self._read_block(block)
            for i, p in enumerate(struct.unpack(f"<{per}I", data)):
                if level == 1:
                    if p:
                        yield (base + i, p, 1, True)
                else:
                    span = per ** (level - 1)
                    yield from walk(p, level - 1, base + i * span)

        for level, p in ((1, ptrs[12]), (2, ptrs[13]), (3, ptrs[14])):
            yield from walk(p, level, lblk)
            lblk += per ** level

    def runs(self, ino: Ext4Inode) -> Iterator[tuple[int, int, int, bool]]:
        if ino.flags & FL_INLINE_DATA:
            raise Ext4Error("inline-data files are not supported")
        if ino.flags & FL_EXTENTS:
            return iter(self._extents(ino.i_block))
        return self._blockmap(ino.i_block)

    # ---------------------------------------------------------------- file data
    def open_file(self, ino: Ext4Inode) -> Ext4FileReader:
        return Ext4FileReader(self, ino)

    def read_all(self, ino: Ext4Inode, limit: int = MAX_DIR_BYTES) -> bytes:
        if ino.size > limit:
            raise Ext4Error(f"inode {ino.number} is {ino.size:,} bytes (limit {limit:,})")
        r = self.open_file(ino)
        out = bytearray()
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                return bytes(out)
            out += chunk

    # ---------------------------------------------------------------- directories
    def entries(self, directory: Ext4Inode) -> list[DirEntry]:
        if not directory.is_dir:
            raise Ext4Error(f"inode {directory.number} is not a directory")
        data = self.read_all(directory)
        out: list[DirEntry] = []
        for off in range(0, len(data), self.bs):
            block = data[off:off + self.bs]
            pos = 0
            while pos + 8 <= len(block):
                ino, rec_len, name_len, ftype = struct.unpack_from("<IHBB", block, pos)
                if rec_len < 8 or rec_len % 4 or pos + rec_len > len(block) or name_len + 8 > rec_len:
                    break  # damaged block: keep what was parsed so far, stop at the damage
                if ino != 0 and name_len:
                    out.append(DirEntry(block[pos + 8:pos + 8 + name_len], ino, ftype))
                pos += rec_len
        return out

    def walk(self, issues: list[WalkIssue] | None = None) -> Iterator[WalkEntry]:
        """Every non-directory entry reachable from the root, depth-first, with a ``/``-joined path.

        Problems that affect a subtree (unreadable directory, cycle, encrypted directory) are appended to ``issues``.
        """
        issues = issues if issues is not None else []
        try:
            root = self.inode(ROOT_INODE)
        except ImageError as exc:
            issues.append(WalkIssue("/", "filesystem_root_unreadable", str(exc)))
            return
        if not root.is_dir:
            issues.append(WalkIssue("/", "filesystem_root_unreadable", "root inode is not a directory"))
            return
        visited = {ROOT_INODE}
        stack: list[tuple[Ext4Inode, str, int]] = [(root, "", 0)]
        while stack:
            directory, prefix, depth = stack.pop()
            if directory.encrypted:
                n = 0
                try:
                    n = len([e for e in self.entries(directory) if e.name not in (b".", b"..")])
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
            children: list[tuple[Ext4Inode, str]] = []
            for e in entries:
                if e.name in (b".", b".."):
                    continue
                name = e.name.decode("utf-8", "surrogateescape")
                path = f"{prefix}/{name}" if prefix else name
                if "/" in name or "\0" in name:
                    issues.append(WalkIssue(path, "unsafe_path_skipped", "directory entry name contains '/' or NUL"))
                    continue
                try:
                    ino = self.inode(e.inode)
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
            yield from (WalkEntry(p, i) for i, p in sorted(children, key=lambda c: c[1]))


class Ext4FileReader:
    """A sequential, bounded reader over one inode's data (holes and uninitialised extents read as zeros)."""

    def __init__(self, fs: Ext4FileSystem, ino: Ext4Inode):
        self.fs, self.ino = fs, ino
        self.size = ino.size
        self.pos = 0
        self._runs = iter(fs.runs(ino))
        self._cur: tuple[int, int, int, bool] | None = None
        self._next_unread_lblk = 0
        self._advance()

    def _advance(self) -> None:
        while True:
            try:
                run = next(self._runs)
            except StopIteration:
                self._cur = None
                return
            if run[0] < self._next_unread_lblk or run[2] <= 0:
                continue  # overlapping/regressing/empty run: ignore (never read data twice)
            self._cur = run
            return

    def read(self, n: int = -1) -> bytes:
        bs = self.fs.bs
        remaining = self.size - self.pos
        if remaining <= 0:
            return b""
        n = remaining if n is None or n < 0 else min(n, remaining)
        n = min(n, 4 * 1024 * 1024)
        out = bytearray()
        while len(out) < n:
            blk, inner = divmod(self.pos, bs)
            want = n - len(out)
            if self._cur is not None and blk >= self._cur[0] + self._cur[2]:
                self._next_unread_lblk = self._cur[0] + self._cur[2]
                self._advance()
                continue
            if self._cur is None or blk < self._cur[0]:
                gap_end = (self._cur[0] * bs) if self._cur is not None else self.size
                take = min(want, gap_end - self.pos, self.size - self.pos)
                out += bytes(take)
            else:
                lblk, pblk, count, init = self._cur
                run_end = (lblk + count) * bs
                take = min(want, run_end - self.pos, self.size - self.pos)
                if init:
                    if pblk + count > self.fs.blocks:
                        raise Ext4Error(f"extent of inode {self.ino.number} points beyond the file system")
                    out += self.fs.src.read_exact(self.fs.base + (pblk + (blk - lblk)) * bs + inner, take)
                else:
                    out += bytes(take)
            self.pos += take
            if take == 0:  # defensive: never spin
                break
        return bytes(out)
