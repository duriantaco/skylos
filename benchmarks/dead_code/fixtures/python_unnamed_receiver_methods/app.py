import sys
from typing import Protocol
from xmlrpc.server import SimpleXMLRPCServer


class Cache:
    def __init__(self):
        self.items = {}

    def get(self, key):
        return self.items.get(key)

    def is_cached(self, key):
        return key in self.items

    def _evict(self, key):
        self.items.pop(key, None)

    def by_literal(self):
        return 1

    def handle_open(self):
        return 2

    def _named_in_table(self):
        return 3

    def _through_proxy(self):
        return 4

    def _as_callback(self):
        return 5

    def register(self, registry):
        registry.append(self._as_callback)


class Holder:
    def __init__(self):
        self.cache = Cache()

    def use(self):
        return self.cache.get("k")


class Proxy:
    def __init__(self, target):
        self._target = target

    def __getattr__(self, name):
        return getattr(self._target, name)


class Sink(Protocol):
    def _flush(self): ...


class FileSink:
    def _flush(self):
        return None

    def write(self, text):
        return len(text)


class First:
    def launch(self):
        return 1


class Second:
    def launch(self):
        return 2


class Shipped:
    def describe(self):
        return "served to remote callers by name"


TABLE = {"table": "_named_in_table"}


def dispatch(cache, kind, key):
    getattr(cache, "handle_" + kind)()
    return getattr(cache, TABLE[key])()


def run(registry):
    holder = Holder()
    cache = holder.cache
    cache.register(registry)
    getattr(cache, "by_literal")()
    dispatch(cache, "open", "table")
    Proxy(cache)._through_proxy()
    sys.stdout = FileSink()
    registry.extend([First(), Second()])
    SimpleXMLRPCServer(("localhost", 0)).register_instance(Shipped())
    return holder.use()


print(run([]))
