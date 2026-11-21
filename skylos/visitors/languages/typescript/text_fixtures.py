"""Test fixtures that tools read as text, not as modules.

The folder names are data in the plugin table (``plugin_facts``, the
``text_fixture_dirs`` of the ``jscodeshift`` row).

jscodeshift's ``defineTest`` reads ``__testfixtures__/<name>.input.<ext>`` and
compares the transform's result with ``<name>.output.<ext>``; snapshot and
transform suites keep their inputs in ``__fixtures__``. Their code is data:
an ``export`` or an unused function in a fixture is part of the expected text,
and nothing imports the file as a module. Dead-code checks therefore report
nothing inside these folders. Their imports still count as edges, so a
fixture a test does import keeps its own imports live.
"""

from __future__ import annotations

import os

from .plugin_facts import text_fixture_directories

TEXT_FIXTURE_DIRECTORIES = text_fixture_directories()


def is_text_fixture(path) -> bool:
    """Whether ``path`` lies inside a ``__testfixtures__``/``__fixtures__`` folder."""
    parts = os.fspath(path).replace(os.sep, "/").split("/")
    return any(part in TEXT_FIXTURE_DIRECTORIES for part in parts[:-1])
