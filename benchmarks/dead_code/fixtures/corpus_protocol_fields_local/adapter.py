import record_api as unittest
from concurrent.futures import Future


def attach(job, journal):
    class Entry(unittest.TestCase):
        runTest = staticmethod(lambda: None)
        format_note = staticmethod(lambda: None)

    def complete(done):
        if done.exception() is not None:
            journal.append(Entry().shortDescription())

    job.add_done_callback(complete)


journal = []
job = Future()
attach(job, journal)
job.set_exception(ValueError("job failed"))
print(journal)
