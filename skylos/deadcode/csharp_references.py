"""Bind C# value/attribute references using their lexical namespace context."""

from __future__ import annotations

import os


_GLOBAL_USINGS_KEY = "@global-usings"


def _arity_matches(definition, arity: int) -> bool:
    accepted = [arity]
    if getattr(definition, "csharp_is_extension", False):
        accepted.append(arity + 1)
    minimum = getattr(definition, "csharp_min_arity", None)
    maximum = getattr(definition, "csharp_max_arity", None)
    for value in accepted:
        if minimum is None:
            if getattr(definition, "csharp_arity", None) == value:
                return True
        elif minimum <= value and (maximum is None or value <= maximum):
            return True
    return False


class CSharpReferenceIndex:
    def __init__(self, by_name: dict, contexts_by_file: dict) -> None:
        self.by_name = by_name
        self.contexts_by_file = contexts_by_file
        self._handled: set[tuple[str, str]] = set()
        self._project_usings: list[tuple[str, dict]] = []
        self._extensions: dict[str, list] = {}
        for path, file_context in contexts_by_file.items():
            if not isinstance(file_context, dict):
                continue
            for value in file_context.get(_GLOBAL_USINGS_KEY, ()):
                if self._valid_context(value):
                    self._project_usings.append((os.path.dirname(str(path)), value))
        for definitions in by_name.values():
            for definition in definitions:
                if getattr(definition, "csharp_is_extension", False):
                    self._extensions.setdefault(definition.simple_name, []).append(
                        definition
                    )

    def _with_project_usings(self, value: dict, file: str) -> dict:
        directory = os.path.dirname(str(file))
        merged = None
        for root, shared in self._project_usings:
            if directory != root and not directory.startswith(root + os.sep):
                continue
            if merged is None:
                merged = dict(value)
                merged["usings"] = list(value.get("usings", []))
                merged["static_usings"] = list(value.get("static_usings", []))
                merged["aliases"] = dict(value.get("aliases", {}))
            for name in shared.get("usings", []):
                if name not in merged["usings"]:
                    merged["usings"].append(name)
            for name in shared.get("static_usings", []):
                if name not in merged["static_usings"]:
                    merged["static_usings"].append(name)
            for alias, target in shared.get("aliases", {}).items():
                merged["aliases"].setdefault(alias, target)
        if merged is None:
            return value
        return merged

    def _contexts(self, reference: str, file: str) -> list[dict]:
        file_context = self.contexts_by_file.get(str(file), {})
        if not isinstance(file_context, dict):
            return []
        values = file_context.get(reference, [])
        if not isinstance(values, (list, tuple)):
            return []
        return [
            self._with_project_usings(value, file)
            for value in values
            if self._valid_context(value)
        ]

    def _mark_extension_call(self, reference: str, context: dict) -> None:
        spelling = str(context.get("spelling") or "")
        _receiver, separator, member = spelling.rpartition(".")
        if not separator:
            return
        _name, separator, arity = reference.rpartition("#")
        if not separator or not arity.isdigit():
            return
        for definition in self._extensions.get(member, ()):
            if not _arity_matches(definition, int(arity)):
                continue
            definition.references += 1
            owner_name = definition.name.rpartition(".")[0]
            if str(context.get("owner") or "") == owner_name:
                continue
            for owner in self.by_name.get(owner_name, []):
                if owner.type == "class":
                    owner.references = max(1, owner.references)

    @staticmethod
    def _valid_context(value) -> bool:
        if not isinstance(value, dict):
            return False
        for key in ("owner", "namespace", "spelling"):
            if value.get(key) is not None and not isinstance(value[key], str):
                return False
        aliases = value.get("aliases", {})
        if not isinstance(aliases, dict) or not all(
            isinstance(key, str) and isinstance(target, str)
            for key, target in aliases.items()
        ):
            return False
        for key in ("usings", "static_usings"):
            items = value.get(key, [])
            if not isinstance(items, (list, tuple)) or not all(
                isinstance(item, str) for item in items
            ):
                return False
        return True

    def mark(self, reference: str, file: str) -> bool:
        if reference.startswith("@type:"):
            # C# type-position lookup is independent of a same-named value
            # member/parameter; the existing type resolver handles this edge.
            return False
        if not reference.startswith(("@attribute:", "@type:")):
            self._mark_static_receivers(reference, file)
        if reference.startswith("@attribute:"):
            spelling = reference.removeprefix("@attribute:")
            attribute = True
        elif reference.startswith("@member:"):
            spelling = reference.removeprefix("@member:")
            attribute = False
        else:
            contexts = self._contexts(reference, file)
            for context in contexts:
                receiver_type = context.get("receiver_type")
                if context.get("receiver_shadowed"):
                    self._mark_extension_call(reference, context)
                if not context.get("receiver_shadowed") or not isinstance(
                    receiver_type, str
                ):
                    continue
                spelling = context.get("spelling", "")
                _receiver, separator, member = spelling.partition(".")
                if not separator:
                    continue
                bound = dict(context)
                bound["receiver_shadowed"] = False
                bound["spelling"] = f"{receiver_type}.{member}"
                _name, separator, arity = reference.rpartition("#")
                if separator and arity.isdigit():
                    bound.setdefault("arity", int(arity))
                matches = self._resolve(bound["spelling"], bound, attribute=False)
                for definition in matches:
                    definition.references += 1
                self.mark_owners(matches, reference, file, contexts=[bound])
            if contexts and all(value.get("receiver_shadowed") for value in contexts):
                return True
            return False

        key = (str(file), reference)
        if key in self._handled:
            return True
        self._handled.add(key)
        contexts = self._contexts(reference, file)
        for context in contexts:
            matches = self._resolve(spelling, context, attribute=attribute)
            for definition in matches:
                definition.references += 1
            self.mark_owners(matches, reference, file, contexts=[context])
        # An unresolved marker is not an ordinary bare-name reference.
        return True

    def _mark_static_receivers(self, reference: str, file: str) -> None:
        for context in self._contexts(reference, file):
            if context.get("receiver_shadowed"):
                continue
            spelling = context.get("spelling", "")
            receiver, separator, _member = spelling.rpartition(".")
            if not separator:
                continue
            bound = dict(context)
            bound.pop("arity", None)
            matches = self._resolve(receiver, bound, attribute=False)
            if len(matches) == 1 and matches[0].type == "class":
                matches[0].references += 1
                bound["spelling"] = receiver
                self.mark_owners(matches, "@type:" + receiver, file, contexts=[bound])

    def _resolve(self, spelling: str, context: dict, *, attribute: bool) -> list:
        if not attribute and context.get("receiver_shadowed"):
            return []
        spelling = spelling.removeprefix("global::").replace("::", ".")
        aliases = context.get("aliases", {})
        first, separator, rest = spelling.partition(".")
        if first in aliases:
            spelling = str(aliases[first]).removeprefix("global::")
            if separator:
                spelling += "." + rest
            tiers = [[spelling]]
        else:
            tiers = []
            owner = str(context.get("owner") or "")
            while owner:
                tiers.append([f"{owner}.{spelling}"])
                owner = owner.rpartition(".")[0]
            namespace = str(context.get("namespace") or "")
            while namespace:
                tiers.append([f"{namespace}.{spelling}"])
                namespace = namespace.rpartition(".")[0]
            tiers.append(
                [f"{namespace}.{spelling}" for namespace in context.get("usings", [])]
                + [f"{owner}.{spelling}" for owner in context.get("static_usings", [])]
            )
            tiers.append([spelling])

        for names in tiers:
            matches = []
            seen = set()
            for name in names:
                variants = [name]
                if attribute and not name.endswith("Attribute"):
                    variants.append(name + "Attribute")
                for variant in variants:
                    for definition in self.by_name.get(variant, []):
                        if attribute and definition.type != "class":
                            continue
                        arity = context.get("arity")
                        if not attribute and isinstance(arity, int):
                            if definition.type != "method":
                                continue
                            if not _arity_matches(definition, arity):
                                continue
                        if id(definition) not in seen:
                            seen.add(id(definition))
                            matches.append(definition)
            if matches:
                # Conflicting imports require more type evidence.
                if len(matches) == 1 or len({item.name for item in matches}) == 1:
                    return matches
                return []
        return []

    def mark_owners(
        self, definitions, reference: str, file: str, *, contexts=None
    ) -> None:
        if contexts is None:
            contexts = self._contexts(reference, file)
        for definition in definitions:
            eligible = []
            for context in contexts:
                if not isinstance(context, dict) or context.get("receiver_shadowed"):
                    continue
                spelling = context.get("spelling") or reference.split(":", 1)[-1]
                spelling, separator, arity = spelling.rpartition("#")
                if not separator or not arity.isdigit():
                    spelling = context.get("spelling") or reference.split(":", 1)[-1]
                bound_context = dict(context)
                _name, separator, arity = reference.rpartition("#")
                if separator and arity.isdigit():
                    bound_context.setdefault("arity", int(arity))
                targets = self._resolve(
                    spelling,
                    bound_context,
                    attribute=reference.startswith("@attribute:"),
                )
                if definition in targets or getattr(
                    definition, "csharp_is_extension", False
                ):
                    eligible.append(context)
            name = definition.name.rpartition(".")[0]
            while name:
                owners = [
                    value
                    for value in self.by_name.get(name, [])
                    if value.type == "class"
                ]
                if not owners:
                    break
                external = any(
                    str(context.get("owner") or "") != name for context in eligible
                )
                if external:
                    for owner in owners:
                        owner.references = max(1, owner.references)
                name = name.rpartition(".")[0]
