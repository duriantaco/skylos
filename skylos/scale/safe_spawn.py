"""Start worker processes without the scanned checkout on ``sys.path``.

On macOS (and on Linux from Python 3.14) a process pool starts each worker,
the resource tracker and the forkserver as ``python -c ...``. For ``-c``
Python puts the working directory first on ``sys.path``, and the child
imports stdlib modules (``json``, ``threading``, ``pickle`` ...) before
multiprocessing swaps in the parent's ``sys.path``; the resource tracker
never swaps it at all. ``skylos .`` runs inside the checkout it scans, so a
checkout holding ``json/`` or ``types.py`` would have its code run by the
scanner. ``PYTHONSAFEPATH`` (Python 3.11+) stops the child adding that entry.
"""

from __future__ import annotations

import contextlib
import os
import threading
from collections.abc import Iterator

SAFE_PATH_VAR = "PYTHONSAFEPATH"

_lock = threading.Lock()
_holders = 0
_previous: str | None = None


@contextlib.contextmanager
def no_cwd_imports_in_children() -> Iterator[None]:
    """Keep ``PYTHONSAFEPATH`` set for every child started inside the block.

    Hold it for the pool's whole life: workers start lazily on ``submit``.
    Nested and concurrent blocks share the setting, and the variable gets its
    old value back when the last block exits, so later subprocesses (a
    project's own test run, say) see the user's environment unchanged.
    """
    global _holders, _previous
    with _lock:
        if _holders == 0:
            _previous = os.environ.get(SAFE_PATH_VAR)
            if not _previous:
                os.environ[SAFE_PATH_VAR] = "1"
        _holders += 1
    try:
        yield
    finally:
        with _lock:
            _holders -= 1
            if _holders == 0:
                if _previous is None:
                    os.environ.pop(SAFE_PATH_VAR, None)
                else:
                    os.environ[SAFE_PATH_VAR] = _previous
                _previous = None
