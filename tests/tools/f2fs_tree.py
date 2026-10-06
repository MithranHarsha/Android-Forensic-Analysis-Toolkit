"""The exact tree written into the kernel-made f2fs fixtures (keep in step with f2fs_kernel_fixture*.sh)."""

from __future__ import annotations


def expected_files() -> dict[str, bytes]:
    exp: dict[str, bytes] = {
        "system/packages.xml": b"<packages><package name='com.example.app'/></packages>\n",
        "data/com.example.app/databases/small.txt": b"hello android\n",
        "data/com.example.app/databases/empty.bin": b"",
        "data/com.example.app/databases/medium.bin": bytes((i * 5 + 1) % 253 for i in range(50_000)),
        "data/com.example.app/databases/big.bin": bytes((i * 7 + 3) % 251 for i in range(20_000_000)),
    }
    sparse = bytearray(900_004)
    sparse[0:4], sparse[900_000:900_004] = b"HEAD", b"TAIL"
    exp["data/com.example.app/databases/sparse.bin"] = bytes(sparse)
    for i in range(1500):
        if i % 7:   # every 7th file was deleted
            exp[f"data/com.example.app/files/f{i:04d}.dat"] = bytes([i % 251]) * (i % 97)
    for n in ("a", "b", "c"):
        exp[f"data/com.example.app/tiny/{n}.txt"] = n.encode() * 10
    return exp
