import functools

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def _expose(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return str(fn(*args, **kwargs))

    return mcp.tool(name=fn.__name__)(wrapper)


def _expose_inline(fn):
    @mcp.tool(name=fn.__name__)
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return str(fn(*args, **kwargs))

    return wrapper


def _expose_keep(fn):
    mcp.tool(name=fn.__name__)(fn)
    return fn


def expose_as(label):
    def decorate(fn):
        return mcp.tool(name=label)(fn)

    return decorate


def _logged(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        print(fn.__name__)
        return fn(*args, **kwargs)

    return wrapper


def _cached(fn):
    return functools.lru_cache(maxsize=None)(fn)


def _identity(fn):
    return fn


def _late(fn):
    def wrapper(*args, **kwargs):
        return mcp.tool(name="late")(fn)(*args, **kwargs)

    return wrapper


@_expose
def open_tab(url):
    return url


@_expose_inline
def close_tab(tab):
    return tab


@_expose_keep
def list_tabs():
    return []


@expose_as("reload")
def reload_tab(tab):
    return tab


@_logged
def unused_logged():
    return 1


@_cached
def unused_cached():
    return 2


@_identity
def unused_identity():
    return 3


@_late
def unused_late():
    return 4


@staticmethod
def unused_static():
    return 5


@functools.lru_cache(maxsize=8)
def unused_lru():
    return 6
