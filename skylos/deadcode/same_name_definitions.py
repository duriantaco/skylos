"""Same-named definitions in Java, Kotlin, Rust and Dart.

These visitors name a definition by its simple or class-qualified name
(``Util``, ``Util.clean``, ``count``), so two files, packages or crates can
produce the same name, and overloads share one. They used to overwrite each
other in the definition map, which silently dropped all but one. Each now
keeps its own entry. A reference to the shared name reaches the members its
file can see: members in its own file, then (JVM) members in its package or
named by its imports, then (Rust) members in its crate. With no such
evidence it reaches every member, which is what the merged definition got.
Overloads in one file keep sharing one definition: Skylos has no argument
types to tell ``format(int)`` from ``format(String)``.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.visitors.languages.kotlin._lex import mask_comments_and_strings

NAME_RESOLVED_FAMILIES = frozenset({"jvm", "rust", "dart"})
_JVM_PACKAGE = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)", re.MULTILINE)
_JVM_IMPORT = re.compile(
    r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*(?:\.\*)?)", re.MULTILINE
)
_PACKAGE_READ_LIMIT = 65536


def same_name_definition_key(definition, definitions):
    """A map key that keeps same-named definitions from other files.

    Overloads in one file still share a key, as before: name-only
    resolution gives them the same liveness, and one finding per overload
    set avoids repeating a finding the call graph cannot separate.
    """
    key = definition.name
    existing = definitions.get(key)
    if existing is None or str(existing.filename) == str(definition.filename):
        return key
    return f"{definition.filename}:{definition.name}"


class SameNameGroups:
    def __init__(self, definitions, family_of, *, scan_root=None):
        self.family_of = family_of
        try:
            self._scan_root = (
                Path(scan_root).resolve(strict=True) if scan_root is not None else None
            )
        except (OSError, TypeError, ValueError):
            self._scan_root = None
        by_name = defaultdict(list)
        for key, definition in definitions.items():
            if definition.type == "import":
                continue
            if family_of(definition.filename) not in NAME_RESOLVED_FAMILIES:
                continue
            by_name[definition.name].append((key, definition))
        self.groups = {
            name: members for name, members in by_name.items() if len(members) > 1
        }
        self.simple_names = {
            members[0][1].simple_name for members in self.groups.values()
        }
        self._headers = {}
        self._crates = {}

    def __bool__(self):
        return bool(self.groups)

    def targets(self, name, ref_file, ref_family):
        members = self.groups.get(name)
        if not members:
            return None
        compatible = [
            definition
            for _key, definition in members
            if ref_family is None or self.family_of(definition.filename) == ref_family
        ]
        if not compatible:
            return None
        return self._visible(compatible, ref_file, ref_family)

    def resolve(self, candidates, ref_file, ref_family):
        """Targets when ambiguous candidates are all one group's members."""
        if len(candidates) < 2:
            return None
        name = candidates[0].name
        if name not in self.groups:
            return None
        if any(candidate.name != name for candidate in candidates):
            return None
        return self.targets(name, ref_file, ref_family)

    def _visible(self, members, ref_file, ref_family):
        same_file = [m for m in members if str(m.filename) == str(ref_file)]
        if same_file:
            return same_file
        if ref_family == "jvm":
            package, imports = self._header(ref_file)
            visible = [
                member
                for member in members
                if self._jvm_visible(member, package, imports)
            ]
            if visible:
                return visible
        if ref_family == "rust":
            crate = self._crate(ref_file)
            same_crate = [m for m in members if self._crate(m.filename) == crate]
            if crate is not None and same_crate:
                return same_crate
        return members

    def _jvm_visible(self, member, package, imports):
        member_package = self._header(member.filename)[0]
        if member_package is None:
            return False
        if package is not None and member_package == package:
            return True
        owner = member.name.split(".", 1)[0]
        return (
            f"{member_package}.{owner}" in imports
            or f"{member_package}.*" in imports
            or member_package in imports
        )

    def _header(self, filename):
        """The package and imports a JVM source file declares.

        Comments and string literals are blanked first, so a commented-out
        or quoted ``import b.Util;`` is not an import.
        """
        key = str(filename)
        if self._scan_root is None:
            return None, set()
        if key not in self._headers:
            text = (
                read_project_text_no_symlink(
                    self._scan_root,
                    key,
                    max_bytes=_PACKAGE_READ_LIMIT,
                    errors="ignore",
                    prefix=True,
                )
                or ""
            )
            text = mask_comments_and_strings(text)
            package = None
            match = _JVM_PACKAGE.search(text)
            if match:
                package = match.group(1).rstrip(".")
            imports = set()
            for found in _JVM_IMPORT.finditer(text):
                name = found.group(1)
                if name.endswith(".*"):
                    imports.add(name)
                    imports.add(name[:-2])
                else:
                    imports.add(name)
            self._headers[key] = (package, imports)
        return self._headers[key]

    def _crate(self, filename):
        directory = Path(str(filename)).parent
        key = str(directory)
        if key not in self._crates:
            crate = None
            for candidate in (directory, *directory.parents):
                if (candidate / "Cargo.toml").is_file():
                    crate = str(candidate)
                    break
            self._crates[key] = crate
        return self._crates[key]
