class RouteSet:
    def __init__(self):
        self.routes = {}

    def register(self, kind):
        def attach(callback):
            self.routes[kind] = callback
            return callback

        return attach

    def fork(self):
        another = RouteSet()
        another.routes = self.routes.copy()
        return another

    def dispatch(self, value):
        return self.routes[type(value)](value)
