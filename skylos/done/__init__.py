"""Done gate: decide whether a change is finished, with evidence.

``skylos done`` compares a change with its base (the merge base of a PR, the
start of an agent session, or HEAD), runs the checks that can block it, and
writes a receipt (``skylos.done-receipt/v1``) that Skylos Cloud can store.

Everything that decides pass or fail runs here, locally or in CI. Settings
come from ``[tool.skylos.done]`` in the base's pyproject.toml, never from the
working tree, so the change under review cannot loosen its own gate.
"""
