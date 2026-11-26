"""Select live terminal progress or periodic, line-oriented scan updates."""

from contextlib import contextmanager
from threading import Event, Thread

from skylos.ui.scan_progress import ScanProgress

_HEARTBEAT_SECONDS = 10


@contextmanager
def scan_progress_output(console, *, mode, human, stream, project_root=None):
    if mode == "off" or (mode == "auto" and not human):
        yield None
        return

    progress = ScanProgress(console, project_root=project_root)
    if mode == "auto" and console.is_interactive is True:
        with progress:
            yield progress
        return

    # A slow operation may have no callbacks at all. Keep the timer independent
    # of file completions so long-running phases are visible in CI logs.
    stopped = Event()

    def emit():
        try:
            print(progress.status_text(), file=stream, flush=True)
        except (OSError, ValueError):
            stopped.set()

    def heartbeat():
        while not stopped.wait(_HEARTBEAT_SECONDS):
            emit()

    if mode == "plain":
        emit()
    thread = Thread(target=heartbeat, name="skylos-scan-progress", daemon=True)
    thread.start()
    try:
        yield progress
    finally:
        stopped.set()
        thread.join(timeout=1)
