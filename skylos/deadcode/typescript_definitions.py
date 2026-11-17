"""Keep parsed TS/JS declaration sites when legacy simple names collide.

This preserves the existing conservative name-based liveness of a same-file
collision group; it does not infer new references between different files or
claim lexical disambiguation of callbacks with the same name.
"""

from collections import defaultdict
from pathlib import Path

_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"})


def definition_key(definition, definitions):
    base = f"{definition.filename}:{definition.name}"
    if base not in definitions:
        return base
    key = f"{base}:{definition.type}:{definition.line}"
    if key in definitions:
        key = f"{key}:{len(definitions)}"
    return key


class SameFileDefinitions:
    def __init__(self, definitions):
        groups = defaultdict(list)
        for definition in definitions.values():
            if (
                definition.type != "import"
                and Path(definition.filename).suffix.lower() in _SUFFIXES
            ):
                groups[(str(definition.filename), definition.name)].append(definition)
        self.groups = {
            identity: values for identity, values in groups.items() if len(values) > 1
        }

    def targets(self, file, name):
        return self.groups.get((str(file), name))
