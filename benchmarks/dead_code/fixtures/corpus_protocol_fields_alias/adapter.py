import unittest as checks
from concurrent.futures import Future


class Observer:
    def attach(self, job, journal):
        def invoke_record(self):
            return None

        class Entry(checks.TestCase):
            runTest = invoke_record
            format_note = staticmethod(lambda: None)

        def complete(done):
            if (exception := done.exception()) is not None:
                entry = Entry()
                journal.append((entry.shortDescription(), exception))

        job.add_done_callback(complete)


journal = []
job = Future()
Observer().attach(job, journal)
job.set_exception(ValueError("job failed"))
print(journal)
