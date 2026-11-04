"""Decide whether attribute loads elsewhere can read a module or class variable.

An attribute load ``x.NAME`` used to keep every variable named ``NAME`` alive.
This module keeps that only when the receiver could be the variable's owner:

* a module variable is reachable through the module itself (import alias or
  dotted path), a module that star-imports it, Django's ``settings`` object,
  or an unknown receiver (parameter, local, call result) when the module
  object can reach one: it is imported as a module, named by a string, or the
  project loads modules dynamically;
* a class variable of a class whose bases are all project classes is reachable
  through ``self``/``cls`` of a related class (same hierarchy), the class or a
  subclass by name, or an unknown receiver. Classes with external or
  unresolved bases, decorators, keywords or an enclosing scope keep the old
  name-only behaviour, because code we cannot see may read their attributes.

``self.NAME`` in an unrelated class, ``other_module.NAME``, and literals are
proof that a load reads a different object.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field

_DYNAMIC_ATTRIBUTE_HOOKS = ("__getattr__", "__getattribute__")
_SETTINGS_READERS = ("django.conf.settings",)


@dataclass
class ReceiverFacts:
    receivers: dict = field(default_factory=lambda: defaultdict(set))
    module_objects: set = field(default_factory=set)
    star_sources: dict = field(default_factory=lambda: defaultdict(set))
    module_strings: set = field(default_factory=set)
    nested_classes: set = field(default_factory=set)
    dynamic: bool = False

    def add(self, module, payload):
        if not isinstance(payload, dict):
            return
        for attr, kind, target in payload.get("receivers", ()):
            self.receivers[attr].add((kind, target))
        self.module_objects.update(payload.get("module_objects", ()))
        if module:
            self.star_sources[module].update(payload.get("star_sources", ()))
        self.module_strings.update(payload.get("module_strings", ()))
        self.nested_classes.update(payload.get("nested_classes", ()))
        if payload.get("dynamic"):
            self.dynamic = True


def _dotted_suffixes(name):
    parts = name.split(".")
    return [".".join(parts[index:]) for index in range(len(parts))]


class _DottedIndex:
    """Names that equal, end with, or are a dotted suffix of a query."""

    def __init__(self, names):
        self.names = set(names)
        self.by_suffix = defaultdict(set)
        for name in self.names:
            for suffix in _dotted_suffixes(name):
                self.by_suffix[suffix].add(name)
        self.cache = {}

    def matches(self, query):
        if query in self.cache:
            return self.cache[query]
        found = set(self.by_suffix.get(query, ()))
        for suffix in _dotted_suffixes(query):
            if suffix in self.names:
                found.add(suffix)
        self.cache[query] = found
        return found


class AttributeReceiverEvidence:
    def __init__(self, facts, defs, module_names_by_file):
        self.facts = facts
        self.defs = defs
        self.module_by_file = {
            str(path): module for path, module in (module_names_by_file or {}).items()
        }
        self.modules = set(self.module_by_file.values())
        self._module_index = _DottedIndex(self.modules)
        self._classes = {
            name: definition
            for name, definition in defs.items()
            if definition.type == "class" and _is_python(definition)
        }
        self._class_index = _DottedIndex(self._classes)
        self._base_cache = {}
        self._closed_cache = {}
        self._children = defaultdict(set)
        for name in self._classes:
            for base in self._project_bases(name):
                self._children[base].add(name)
        self._dynamic_classes = {
            definition.name.rsplit(".", 1)[0]
            for definition in defs.values()
            if definition.type == "method"
            and definition.simple_name in _DYNAMIC_ATTRIBUTE_HOOKS
        }
        self._dynamic_modules = {
            definition.name.rsplit(".", 1)[0]
            for definition in defs.values()
            if definition.type == "function"
            and definition.simple_name in _DYNAMIC_ATTRIBUTE_HOOKS
        }
        self._memo = defaultdict(dict)
        self._escaped = self._escaped_modules()
        self._verdicts = {}

    def rules_out(self, definition):
        """True when every same-named attribute load reads another object."""
        key = (definition.name, str(definition.filename))
        if key not in self._verdicts:
            self._verdicts[key] = self._rules_out(definition)
        return self._verdicts[key]

    def _rules_out(self, definition):
        if definition.type != "variable" or "." not in definition.name:
            return False
        if not _is_python(definition):
            return False
        owner, attr = definition.name.rsplit(".", 1)
        accesses = self.facts.receivers.get(attr)
        if not accesses:
            return False
        if self.module_by_file.get(str(definition.filename)) == owner:
            reach = self._reaches_module_variable
        elif owner in self._classes and self._is_closed(owner):
            reach = self._reaches_class_variable
        else:
            return False
        return not any(reach(owner, kind, target) for kind, target in accesses)

    def _reaches_module_variable(self, module, kind, target):
        if kind == "literal":
            return False
        if kind == "self":
            return module in self._escaped and self._family_is_dynamic(target)
        if kind == "name":
            if target.startswith(_SETTINGS_READERS):
                return True
            resolved = self._module_named(target)
            if resolved is not None:
                if resolved == module or module in self._star_closure(resolved):
                    return True
                return resolved in self._dynamic_modules and module in self._escaped
            if target in self._classes:
                return False
        return module in self._escaped

    def _reaches_class_variable(self, owner, kind, target):
        if kind == "literal":
            return False
        if kind == "self":
            return self._related(target, owner) or self._family_is_dynamic(target)
        if kind == "name":
            if target in self._classes:
                return owner == target or owner in self._ancestors(target)
            resolved = self._module_named(target)
            if resolved is not None:
                return resolved in self._dynamic_modules
            if target.startswith(_SETTINGS_READERS):
                return False
        return True

    def _module_named(self, target):
        if target in self.modules:
            return target
        matches = self._module_index.matches(target)
        if len(matches) == 1:
            return next(iter(matches))
        return None

    def _star_closure(self, module):
        return self._remember("star", module, self._compute_star_closure)

    def _remember(self, kind, key, compute):
        cache = self._memo[kind]
        if key not in cache:
            cache[key] = compute(key)
        return cache[key]

    def _compute_star_closure(self, module):
        seen = set()
        pending = [module]
        while pending:
            current = pending.pop()
            for source in self.facts.star_sources.get(current, ()):
                resolved = self._module_named(source) or source
                if resolved not in seen:
                    seen.add(resolved)
                    pending.append(resolved)
        return seen

    def _escaped_modules(self):
        if self.facts.dynamic:
            return set(self.modules)
        escaped = set()
        for name in self.facts.module_objects:
            escaped.update(self._module_index.matches(name))
        for text in self.facts.module_strings:
            if "." in text:
                escaped.update(self._module_index.matches(text))
            elif text in self.modules:
                escaped.add(text)
        changed = True
        while changed:
            changed = False
            for module in list(escaped):
                for source in self._star_closure(module):
                    if source in self.modules and source not in escaped:
                        escaped.add(source)
                        changed = True
        return escaped

    def _project_bases(self, name):
        if name in self._base_cache:
            return self._base_cache[name]
        bases = []
        unresolved = []
        definition = self._classes.get(name)
        for base in getattr(definition, "base_classes", None) or ():
            if base in ("object", "builtins.object"):
                continue
            if base in self._classes:
                bases.append(base)
                continue
            matches = self._class_index.matches(base)
            if len(matches) == 1:
                bases.append(next(iter(matches)))
            else:
                unresolved.append(base)
        self._base_cache[name] = bases
        self._base_cache[("unresolved", name)] = unresolved
        return bases

    def _unresolved_bases(self, name):
        self._project_bases(name)
        return self._base_cache[("unresolved", name)]

    def _ancestors(self, name):
        return self._remember("ancestors", name, self._compute_ancestors)

    def _compute_ancestors(self, name):
        seen = set()
        pending = list(self._project_bases(name))
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            pending.extend(self._project_bases(current))
        return seen

    def _descendants(self, name):
        return self._remember("descendants", name, self._compute_descendants)

    def _compute_descendants(self, name):
        seen = set()
        pending = list(self._children.get(name, ()))
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            pending.extend(self._children.get(current, ()))
        return seen

    def _is_closed(self, name, active=frozenset()):
        if name in self._closed_cache:
            return self._closed_cache[name]
        if name in active:
            return False
        definition = self._classes.get(name)
        node = getattr(definition, "node", None)
        closed = (
            isinstance(node, ast.ClassDef)
            and name not in self.facts.nested_classes
            and not node.decorator_list
            and not node.keywords
            and not self._unresolved_bases(name)
            and all(
                self._is_closed(base, active | {name})
                for base in self._project_bases(name)
            )
        )
        self._closed_cache[name] = closed
        return closed

    def _family(self, name):
        return {name} | self._ancestors(name) | self._descendants(name)

    def _family_is_dynamic(self, name):
        return self._remember("dynamic", name, self._compute_family_is_dynamic)

    def _compute_family_is_dynamic(self, name):
        if name not in self._classes:
            return True
        family = self._family(name)
        if family & self._dynamic_classes:
            return True
        return any(self._unresolved_bases(member) for member in family)

    def _related(self, reader, owner):
        return self._remember("related", (reader, owner), self._compute_related)

    def _compute_related(self, pair):
        reader, owner = pair
        if reader not in self._classes:
            return True
        reader_side = {reader} | self._descendants(reader)
        owner_side = {owner} | self._descendants(owner)
        if reader_side & owner_side:
            return True
        owner_names = {member.rsplit(".", 1)[-1] for member in owner_side}
        for member in {reader} | self._ancestors(reader):
            for base in self._unresolved_bases(member):
                if base.rsplit(".", 1)[-1] in owner_names:
                    return True
        return False


def _is_python(definition):
    return str(definition.filename).endswith((".py", ".pyi", ".pyw"))
