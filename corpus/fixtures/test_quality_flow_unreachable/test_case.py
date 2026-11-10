from threading import Event
from time import sleep


def test_constant(items):
    for item in items:
        break
        assert True


def test_duplicate(items, payload):
    for item in items:
        continue
        count = len(payload)
        assert count == 3
        assert count == 3


def test_completion(items):
    for item in items:
        break
        complete = Event()
        sleep(0.05)
        assert complete.is_set()
