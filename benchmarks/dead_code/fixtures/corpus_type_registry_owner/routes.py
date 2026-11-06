class Router:
    def __init__(self):
        self.handlers = {}

    def register(self, kind):
        def attach(callback):
            self.handlers[kind] = callback
            return callback

        return attach

    def apply(self, message):
        callback = self.handlers.get(type(message))
        return callback(message) if callback is not None else None
