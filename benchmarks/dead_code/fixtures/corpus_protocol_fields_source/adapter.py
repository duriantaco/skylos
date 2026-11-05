class RecordProtocol:
    def __init__(self):
        selected = getattr(self, "render_summary")
        self.caption = selected.__doc__

    def describe(self):
        return self.caption


def publish(journal):
    class Entry(RecordProtocol):
        render_summary = staticmethod(lambda: None)
        format_note = staticmethod(lambda: None)

    journal.append(Entry().describe())


journal = []
publish(journal)
print(journal)
