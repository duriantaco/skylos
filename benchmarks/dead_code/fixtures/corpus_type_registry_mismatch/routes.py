class HandlerSet:
    def __init__(self):
        self.entries = {}

    def for_type(self, kind):
        def bind(function):
            self.entries[kind] = function
            return function

        return bind

    def send(self, value):
        function = self.entries.get(type(value))
        if function is not None:
            return function(value)
        return None
