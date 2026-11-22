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
from functools import lru_cache

from .glob_patterns import expand_braces
from .resolve import _SOURCE_FILE_SUFFIXES, _read_json_file

_DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "peerDependencies")


def _sveltekit_row():
    from .plugin_facts import plugin_named

    return plugin_named("sveltekit")


@lru_cache(maxsize=4096)
def sveltekit_root(directory: str) -> str | None:
    """The SvelteKit project holding ``directory`` (first enclosing
    ``package.json`` that declares an enabler or has a Svelte config)."""
    row = _sveltekit_row()
    if row is None:
        return None
    config_names = [
        name for pattern in row.enable_files for name in expand_braces(pattern)
    ]
    current = os.path.abspath(directory)
    while True:
        manifest = os.path.join(current, "package.json")
        if os.path.isfile(manifest):
            data = _read_json_file(manifest)
            if any(
                isinstance(data.get(field), dict)
                and any(name in data[field] for name in row.enabler_names)
                for field in _DEPENDENCY_FIELDS
            ) or any(os.path.isfile(os.path.join(current, name)) for name in config_names):
                return current
            return None
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def resolve_sveltekit_alias(source: str, importer: str) -> str | None:
    row = _sveltekit_row()
    aliases = (row.skylos.get("aliases") or {}) if row is not None else {}
    for alias, target in aliases.items():
        if source != alias and not source.startswith(alias + "/"):
            continue
        root = sveltekit_root(os.path.dirname(os.path.abspath(importer)))
        if root is None:
            return None
        relative = source[len(alias) + 1 :] if source != alias else ""
        if ".." in relative.split("/"):
            return None
        base = os.path.normpath(os.path.join(root, target, relative))
        for candidate in (base, *(base + suffix for suffix in _SOURCE_FILE_SUFFIXES)):
            if os.path.isfile(candidate):
                return candidate
        return None
    return None
