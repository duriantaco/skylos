class Transit:
    def __init__(self, reactor=None, clock=None):
        if reactor is None:
            from twisted.internet import reactor
        self._reactor = reactor
        if clock is None:
            from twisted.internet import task as clock
        self._clock = clock

    def start(self):
        return self._reactor, self._clock


def route(task, recommend_fn=None):
    if recommend_fn is None:
        from netpkg.skills import recommend as recommend_fn
    return recommend_fn(task)


def stale(task, picker=None):
    if picker is None:
        from netpkg.skills import pick_unused
    return task


def shadowed(task, chooser=None):
    if chooser is None:
        from netpkg.skills import pick_shadowed as chooser
    chooser = len
    return chooser(task)
