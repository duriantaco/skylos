"""Run hook lookups in parallel without outliving the hook's deadline."""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from typing import Any

PENDING = object()
MAX_PARALLEL = 16


def run_parallel(
    tasks: list[Callable[[], Any]], deadline: float, *, workers: int = MAX_PARALLEL
) -> list[Any]:
    """Run ``tasks`` on daemon threads until done or ``deadline``. A task
    still running then reads as :data:`PENDING`, a task that raised as
    ``None``, and no thread can keep the hook process alive."""
    results: list[Any] = [PENDING] * len(tasks)
    if not tasks:
        return results
    jobs: queue.Queue = queue.Queue()
    for index, task in enumerate(tasks):
        jobs.put((index, task))
    lock = threading.Lock()
    finished = threading.Event()
    left = [len(tasks)]

    def work() -> None:
        while True:
            try:
                index, task = jobs.get_nowait()
            except queue.Empty:
                return
            value = PENDING
            if time.monotonic() < deadline:
                try:
                    value = task()
                except Exception:  # noqa: BLE001
                    value = None
            with lock:
                results[index] = value
                left[0] -= 1
                if left[0] == 0:
                    finished.set()

    for _ in range(min(workers, len(tasks))):
        threading.Thread(target=work, daemon=True).start()
    finished.wait(max(0.0, deadline - time.monotonic()))
    with lock:
        return list(results)


__all__ = ["MAX_PARALLEL", "PENDING", "run_parallel"]
