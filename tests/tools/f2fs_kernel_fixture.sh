set -e
apt-get update -qq >/dev/null; apt-get install -y -qq f2fs-tools python3 >/dev/null 2>&1
cd /w; rm -f kernel_clean.img kernel_dirty.img; truncate -s 100M kernel.img
mkfs.f2fs -f -l userdata kernel.img >/dev/null
mkdir -p /mnt/f; mount -t f2fs -o loop,inline_data,inline_dentry kernel.img /mnt/f
python3 - <<'PY'
import os, random
root = "/mnt/f"
def w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f: f.write(data)
w(f"{root}/system/packages.xml", b"<packages><package name='com.example.app'/></packages>\n")
w(f"{root}/data/com.example.app/databases/small.txt", b"hello android\n")           # inline data
w(f"{root}/data/com.example.app/databases/empty.bin", b"")
w(f"{root}/data/com.example.app/databases/medium.bin", bytes((i * 5 + 1) % 253 for i in range(50_000)))
big = bytes((i * 7 + 3) % 251 for i in range(20_000_000))                           # > inode + direct nodes -> indirect node
w(f"{root}/data/com.example.app/databases/big.bin", big)
with open(f"{root}/data/com.example.app/databases/sparse.bin", "wb") as f:           # a real hole
    f.write(b"HEAD"); f.seek(900_000); f.write(b"TAIL")
os.symlink("small.txt", f"{root}/data/com.example.app/databases/link")
for i in range(1500):                                                                # forces multi-block hashed directories
    w(f"{root}/data/com.example.app/files/f{i:04d}.dat", bytes([i % 251]) * (i % 97))
for i in range(0, 1500, 7):                                                          # genuine deletions
    os.unlink(f"{root}/data/com.example.app/files/f{i:04d}.dat")
os.makedirs(f"{root}/data/com.example.app/tiny", exist_ok=True)                      # inline dentry directory
for n in ("a", "b", "c"): w(f"{root}/data/com.example.app/tiny/{n}.txt", n.encode() * 10)
PY
sync
cp kernel.img kernel_dirty.img         # snapshot of a LIVE (mounted) volume: valid checkpoint, no umount flag
umount /mnt/f
cp kernel.img kernel_clean.img
rm kernel.img
fsck.f2fs kernel_clean.img 2>&1 | grep -E "FSCK|Done|corrupt" | tail -3
ls -la kernel_*.img
