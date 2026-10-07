"""Ordered, bounded, process-based parallel map for the heavy per-database stages (recovery, carving).

Recovery and carving are pure functions of one file's bytes, so databases can be processed on separate cores. Two properties matter
more than speed in a forensic tool and are kept:

* **Determinism** — results come back in *task order* whatever order the workers finish in, and the caller writes the case database
  from a single process, so row ids, ordering and therefore every report are byte-identical to a serial run (a test asserts it).
* **Bounded memory** — at most ``workers * 4`` tasks are in flight, so a slow database writer cannot let thousands of finished
  reports pile up in memory.

``workers <= 1`` (the default) runs in-process with no pickling at all.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from typing import Any, TypeVar

T = TypeVar("T")
R = TypeVar("R")
MAX_AUTO_WORKERS = 8


def resolve_workers(value: int | str | None) -> int:
    """``None`` / ``1`` -> 1; ``"auto"`` -> cores - 1 (at most 8); any other positive integer as given."""
    if value in (None, "", 0, 1, "1"):
        return 1
    if value == "auto":
        return max(1, min(MAX_AUTO_WORKERS, (os.cpu_count() or 2) - 1))
    n = int(value)
    if n < 1:
        raise ValueError("workers must be a positive integer or 'auto'")
    return n


def ordered_map(fn: Callable[[T], R], tasks: Iterable[T], workers: int, cost: Callable[[T], float] | None = None) -> Iterator[R]:
    """``fn`` applied to every task, yielded in *task order*. ``fn`` and the tasks/results must be picklable when ``workers > 1``.

    ``cost`` (e.g. the file size) lets the pool start the most expensive tasks first so one huge database does not become the
    straggler everyone waits for; results are still handed back in the original order, so nothing downstream can tell. Finished
    results wait in memory only until their turn comes."""
    if workers <= 1:
        for t in tasks:
            yield fn(t)
        return
    items = list(tasks)
    n = len(items)
    order = sorted(range(n), key=lambda i: -cost(items[i])) if cost else list(range(n))   # sorted() is stable: ties keep task order
    window = workers * 2
    running: dict[Future[Any], int] = {}
    done: dict[int, Any] = {}
    submit = iter(order)
    next_out = 0
    with ProcessPoolExecutor(max_workers=workers) as pool:
        def top_up() -> None:
            while len(running) < window:
                idx = next(submit, None)
                if idx is None:
                    return
                running[pool.submit(fn, items[idx])] = idx

        top_up()
        while next_out < n:
            while next_out in done:
                yield done.pop(next_out)
                next_out += 1
            if next_out >= n:
                break
            finished, _ = wait(running, return_when=FIRST_COMPLETED)
            for f in finished:
                done[running.pop(f)] = f.result()
            top_up()
