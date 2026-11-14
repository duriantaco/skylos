from toolpkg.server import _logged, _expose
from toolpkg import server


@_expose
def remote_click(x, y):
    return x + y


@server._expose
def remote_scroll(dy):
    return dy


@_logged
def unused_remote_logged():
    return 0
