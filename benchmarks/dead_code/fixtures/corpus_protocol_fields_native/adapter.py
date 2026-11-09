import asyncio
from unittest import TestCase


class Journal:
    def __init__(self):
        self.entries = []

    def record(self, entry, exception):
        self.entries.append((str(entry), entry.shortDescription(), exception))


def attach(job, label, journal):
    class Entry(TestCase):
        runTest = staticmethod(lambda: None)
        format_note = staticmethod(lambda: None)

        def __str__(self):
            return label

    def publish(exception):
        journal.record(Entry(), exception)

    def complete(done):
        if not done.cancelled() and (exception := done.exception()) is not None:
            publish(exception)

    job.add_done_callback(complete)


async def perform():
    raise ValueError("job failed")


event_loop = asyncio.new_event_loop()
journal = Journal()
job = event_loop.create_task(perform())
attach(job, "sample", journal)
try:
    event_loop.run_until_complete(job)
except ValueError:
    pass
event_loop.close()
print(journal.entries)
