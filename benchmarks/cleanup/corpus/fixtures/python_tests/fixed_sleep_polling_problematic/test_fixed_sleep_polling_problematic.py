from threading import Event, Thread
from time import sleep


def test_job_completes():
    complete = Event()
    worker = Thread(target=complete.set)
    worker.start()
    sleep(0.05)
    assert complete.is_set()
    worker.join(timeout=1)
