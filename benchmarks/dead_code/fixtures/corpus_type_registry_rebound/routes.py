class Inbox:
    def __init__(self):
        self.handlers = {}

    def subscribe(self, kind):
        def save(callback):
            self.handlers[kind] = callback
            return callback

        return save

    def handle(self, value):
        callback = self.handlers.get(type(value))
        return callback(value) if callback is not None else None
