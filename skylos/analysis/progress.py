"""Progress callbacks shared by the static analysis passes."""

from contextlib import contextmanager
from pathlib import Path


def forward_activity(source, target):
    """Forward optional file activity through an ordinary progress wrapper."""
    for name in ("file_started", "file_finished", "parallel_activity"):
        hook = getattr(source, name, None)
        if callable(hook):
            setattr(target, name, hook)
    return target


@contextmanager
def active_file(callback, path):
    """Mark the interval spent working on one file in the current process."""
    started = getattr(callback, "file_started", None)
    finished = getattr(callback, "file_finished", None)
    if started is not None:
        started(path)
    try:
        yield
    finally:
        if finished is not None:
            finished(path)


def start_phase(callback, name, total=1):
    if callback is not None:
        callback(0, total, Path(f"PHASE: {name}"))


def counted_items(items, callback, phase, total, *, interval=1, path_of=None):
    """Count an item after its consumer finishes, including on loop continue."""
    if callback is None or not total:
        return items

    marker = Path(f"PHASE: {phase}")
    callback(0, total, marker)
    with_paths = path_of is not None and callable(getattr(callback, "file_started", None))

    def completed():
        for done, item in enumerate(items, 1):
            if with_paths:
                with active_file(callback, path_of(item)):
                    yield item
            else:
                yield item
            if done == 1 or done % interval == 0 or done == total:
                callback(done, total, marker)

    return completed()
