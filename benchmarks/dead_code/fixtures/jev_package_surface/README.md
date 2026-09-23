# Orchidkit

A small installed command package. After installation, `orchid` reads the
packaged pipeline profile map and dispatches a value through the selected
handler. Backend factories are exposed through the `orchidkit.backends`
entry-point group for hosts that load the package as a plugin.

For example, `orchid "  Cedar  " --profile morning` prints the processed
value. The `tests/` directory contains a focused transformation check.
