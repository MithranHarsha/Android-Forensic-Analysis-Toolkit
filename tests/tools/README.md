# Fixture generators

* `make_ext_images.py` — ext2/ext4 images with real `mke2fs` (Docker).
* `f2fs_kernel_fixture.sh`, `f2fs_kernel_fixture_extra.sh` — f2fs images written by a **real Linux kernel**: run inside a
  privileged Debian container (`docker run --rm --privileged -v "$PWD:/w" debian:bookworm-slim bash /w/<script>`); they loop-mount an
  f2fs volume, create the test tree (inline data, an inline-dentry directory, a 20 MB file that needs indirect nodes, a 1500-file
  hashed directory, sparse holes, deletions) and snapshot the volume cleanly unmounted and live. The `_extra` variant formats with
  `extra_attr,inode_checksum,inode_crtime,flexible_inline_xattr,…` like modern Android.
* E01 fixtures were produced with `ewfacquire` (libewf, `ewf-tools`) from the ext images.

The committed fixtures are gzip-compressed; tests decompress them to a temporary directory.
