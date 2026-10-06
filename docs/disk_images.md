# Disk images (raw, sparse, E01)

`ingest` / `analyze` accept, besides directory dumps, ZIP and TAR archives and single databases:

| Input | How it is recognised | Notes |
|---|---|---|
| Raw partition image (`userdata.img`, `.dd`) | ext2/3/4 magic at offset 1080, or f2fs magic at offset 1024 | read directly, never mounted |
| Raw whole-disk image | GPT (512 or 4096-byte sectors) or MBR | each partition is examined; GPT names (`userdata`) are kept |
| Android **sparse** image | `0xED26FF3A` | RAW / FILL / DONT_CARE chunks are expanded lazily; nothing is materialised on disk |
| **EnCase E01** (EWF v1), multi-segment | `EVF\x09\x0d\x0a\xff\x00` | `.E01 … .E99` found automatically; chunk and descriptor checksums verified; **stored MD5/SHA-1 re-computed and compared** |

The image is hashed as a container (SHA-256/SHA-1/MD5) like an archive, so validation can re-hash it later.

## What is read

Two hostile-input-hardened, read-only parsers cover the file systems Android uses for `/data`; both stream every regular file
through the same hash → classify → preserve path as a directory dump.

**ext2/3/4** — extents and classic block maps, sparse files (holes read as zeros), uninitialised extents, multi-block / hashed
directories, 64-bit layouts.

**f2fs** (the default on most current phones) — superblock and the newest *valid* checkpoint pack (CRC and both header copies
checked), the NAT with its block-copy bitmap **and the NAT journal in the checkpoint** (journal entries override stale NAT blocks),
node footers cross-checked against the NAT (`nid`/`ino`) and the checkpoint version so a stale or forged node is rejected,
direct / indirect / double-indirect addressing, **inline data** and **inline directories**, multi-block hashed directories, extra
inode attributes (`extra_attr`, `flexible_inline_xattr`, creation time) and sparse files. It was developed against images written
by a **real Linux kernel** and by `mkfs.f2fs`/`sload.f2fs`; the committed fixtures decode byte-for-byte to the tree the kernel
was asked to write (`tests/unit/test_f2fs_images.py`).

If the image is an Android `/data` partition (its root holds `data` and e.g. `system`/`misc`/`app`) its paths are prefixed with
`data/` so they match a directory dump of `/data`; override with `--mount-point`.

Results from an image are **identical** to those from a directory of the same files — tests compare extracted bytes, active
artifacts and recovered deleted records (`tests/integration/test_disk_image_ingest.py`).

## What is reported, never guessed

| Situation | Issue recorded |
|---|---|
| fscrypt-encrypted directory / file (file-based encryption) | `file_based_encryption_detected`; contents are not read, names are ciphertext. **The tool never decrypts.** |
| ext4 journal needs recovery / f2fs checkpoint without the umount flag | `filesystem_note`: the journal / fsync roll-forward was **not** replayed, recent changes may be missing |
| image shorter than the file system claims | `filesystem_note`; unreachable files fail individually |
| symlinks, devices, FIFOs, sockets | `symlink_skipped` / `special_file_skipped` |
| directory cycles, absurd depth, corrupt inode/extent | `directory_cycle_skipped`, `path_too_deep`, `member_read_error` — one file or subtree, never the whole acquisition |
| partition with a file system this build cannot read (FAT, encrypted, raw) | `filesystem_not_recognised` / `filesystem_unsupported`, acquisition marked **incomplete** |
| E01 with a missing segment or stored hash mismatch | `image_incomplete` / `image_hash_mismatch`, acquisition marked **incomplete** |

## Limits (be aware)

* Only live files are enumerated. Deleted *files* (unlinked inodes, free blocks) are not recovered at the file-system level; the
  tool recovers deleted *records inside SQLite databases*, which is where Android's user data lives.
* ext4: `inline_data` files and `meta_bg` layouts are not supported. f2fs: **compressed** files (the `compression` feature),
  multi-device volumes and double-indirect addressing beyond what the fixtures cover (files > ~8 GiB) are untested; compressed
  files are reported individually, never guessed.
* **Encrypted `/data` is the norm on real phones.** An image taken without the keys decodes to ciphertext names and contents; the
  tool reports `file_based_encryption_detected` for each encrypted directory/file and produces *no* artifacts for them. It never
  decrypts. Plan acquisitions (e.g. a full-file-system extraction from an unlocked device) accordingly.
* Images from a live device may be internally inconsistent (f2fs written during acquisition); inconsistencies are surfaced as
  per-file errors, not hidden.
