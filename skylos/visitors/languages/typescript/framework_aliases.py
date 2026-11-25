"""Module aliases a framework defines without a tsconfig ``paths`` entry.

The aliases are data in the plugin table (``plugin_facts``, the ``aliases``
of a row). SvelteKit writes ``$lib`` into the generated
``.svelte-kit/tsconfig.json``, which is absent from a checkout; its default
target is ``src/lib`` of the SvelteKit project (``kit.files.lib``). Svelte 5
rune modules are named ``x.svelte.ts``/``x.svelte.js`` and imported as
``$lib/x.svelte``, so the lookup appends source extensions to the full
specifier.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache

from .resolve import _read_json_file

_DEPENDENCY_FIELDS = ("dependencies", "devDependencies")
_IMPLICIT_LIB_VERSIONS = re.compile(r"[~^]?[12](?:\.(?:\d+|[xX*])){0,2}")
_VITE_CONFIG_OPTION = re.compile(r"\s(?:--config|-c)(?:\s|=)")


def _sveltekit_row():
    from .plugin_facts import plugin_named

    return plugin_named("sveltekit")


@lru_cache(maxsize=4096)
def sveltekit_root(directory: str) -> str | None:
    """The enclosing package when it declares a Kit version with implicit lib."""
    row = _sveltekit_row()
    if row is None:
        return None
    current = os.path.abspath(directory)
    while True:
        manifest = os.path.join(current, "package.json")
        if os.path.lexists(manifest):
            if os.path.islink(manifest) or not os.path.isfile(manifest):
                return None
            data = _read_json_file(manifest)
            scripts = data.get("scripts")
            if isinstance(scripts, dict) and any(
                isinstance(command, str)
                and "vite" in command.split()
                and _VITE_CONFIG_OPTION.search(command)
                for command in scripts.values()
            ):
                return None
            versions = [
                data[field][name]
                for field in _DEPENDENCY_FIELDS
                if isinstance(data.get(field), dict)
                for name in row.enabler_names & data[field].keys()
            ]
            if versions and all(
                isinstance(version, str) and _IMPLICIT_LIB_VERSIONS.fullmatch(version)
                for version in versions
            ):
                return current
            return None
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def resolve_sveltekit_alias(source: str, importer: str) -> str | None:
    """Resolve legacy aliases when a separate config-bound resolver cannot."""
    from skylos.deadcode.sveltekit import supersedes_default_library
    from skylos.deadcode.sveltekit_aliases import resolve_default_sveltekit_library

    row = _sveltekit_row()
    aliases = (row.skylos.get("aliases") or {}) if row is not None else {}
    for alias, target in aliases.items():
        if source != alias and not source.startswith(alias + "/"):
            continue
        root = sveltekit_root(os.path.dirname(os.path.abspath(importer)))
        if root is None:
            return None
        if supersedes_default_library(root):
            return None
        return resolve_default_sveltekit_library(
            source, importer, root, os.path.join(root, target)
        )
    return None
