class Envelope:
    pass


class Note(Envelope):
    pass


class Router:
    def __init__(self):
        self.callbacks = {}

    def register(self, kind):
        def attach(function):
            self.callbacks[kind] = function
            return function

        return attach

    def deliver(self, value):
        for owner in type(value).__mro__:
            function = self.callbacks.get(owner)
            if function is not None:
                return function(value)
        return None
