from threading import Event, Thread


def test_worker_completion():
    done = Event()
    worker = Thread(target=done.set)
    worker.start()
    assert done.wait(timeout=1)
    worker.join(timeout=1)
