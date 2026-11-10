from threading import Event, Thread
from time import sleep


def test_worker_completion():
    done = Event()
    worker = Thread(target=done.set)
    worker.start()
    sleep(0.05)
    assert done.is_set()
    worker.join(timeout=1)
