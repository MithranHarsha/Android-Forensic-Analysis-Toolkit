"""``python -m android_forensics.server.limited_exec --cpu N --as BYTES --fsize BYTES -- cmd args…``

Applies resource limits, then replaces itself with ``cmd`` (so the limits bind the real work). POSIX only."""

from __future__ import annotations

import argparse
import os
import sys

try:
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]


def apply(cpu: int, address_space: int, fsize: int, nofile: int) -> list[str]:
    notes: list[str] = []
    if resource is None:  # pragma: no cover
        return ["resource limits unavailable on this platform"]
    for name, which, value in (("CPU", resource.RLIMIT_CPU, cpu), ("AS", resource.RLIMIT_AS, address_space),
                               ("FSIZE", resource.RLIMIT_FSIZE, fsize), ("NOFILE", resource.RLIMIT_NOFILE, nofile),
                               ("CORE", resource.RLIMIT_CORE, 0)):
        try:
            soft, hard = resource.getrlimit(which)
            new = value if hard == resource.RLIM_INFINITY else min(value, hard)
            resource.setrlimit(which, (new, new if name != "CPU" else min(new + 30, hard if hard != resource.RLIM_INFINITY else new + 30)))
        except (ValueError, OSError) as exc:
            notes.append(f"RLIMIT_{name} not applied on this platform ({exc})")
    return notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cpu", type=int, required=True)
    ap.add_argument("--as", dest="address_space", type=int, required=True)
    ap.add_argument("--fsize", type=int, required=True)
    ap.add_argument("--nofile", type=int, default=2048)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    ns = ap.parse_args(argv)
    cmd = ns.command[1:] if ns.command and ns.command[0] == "--" else ns.command
    if not cmd:
        ap.error("no command given")
    for note in apply(ns.cpu, ns.address_space, ns.fsize, ns.nofile):
        print(f"[limits] {note}", flush=True)
    os.execvp(cmd[0], cmd)  # nosec B606 - cmd is built by the server


if __name__ == "__main__":
    sys.exit(main())
