from netpkg.quiet import version
from netpkg.shell import prompt
from netpkg.transit import Transit, route, shadowed, stale

print(Transit().start(), route("a"), stale("b"), shadowed("c"), prompt(), version())
