from threading import Event, Thread


def test_job_completes():
    complete = Event()
    worker = Thread(target=complete.set)
    worker.start()
    assert complete.wait(timeout=1)
    worker.join(timeout=1)
