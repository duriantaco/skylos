def channel():
    table = {}

    def register(kind):
        def wrap(function):
            table[kind] = function
            return function

        return wrap

    def send(value):
        function = table.get(type(value))
        if function is not None:
            return function(value)
        return None

    return register, send
