from threading import Event
from time import sleep


def test_constant(items, stop):
    for item in items:
        if stop:
            break
        assert True


def test_duplicate(items, stop, payload):
    for item in items:
        if stop:
            continue
        count = len(payload)
        assert count == 3
        assert count == 3


def test_completion(items, stop):
    for item in items:
        if stop:
            break
        complete = Event()
        sleep(0.05)
        assert complete.is_set()
