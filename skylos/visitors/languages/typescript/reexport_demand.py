"""Bounded export demand through statically resolved ECMAScript re-exports."""

from collections import Counter, defaultdict, deque


_MAX_EXPORT_DEMAND_ITEMS = 100_000
_ALL = "*"
_STAR = "**star**"
_SOURCE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")


def build_reexport_demand(raw_imports, definitions, resolve, context):
    """Return precise demand or None before mutating any definition.

    Local source references and the syntactic file graph are independent of
    this graph. Unknown providers/identities decline this negative proof.
    """
    if context is None:
        return None
    files = context["files"]
    consumed = defaultdict(set)
    requests = defaultdict(set)
    importers = defaultdict(set)
    wildcard = defaultdict(set)
    named = defaultdict(lambda: defaultdict(list))
    stars = defaultdict(set)
    namespaces = defaultdict(lambda: defaultdict(set))
    reexports = defaultdict(list)
    by_file = defaultdict(list)
    for definition in definitions.values():
        if definition.type != "import":
            by_file[str(definition.filename)].append(definition)
    total = 0
    for importer, imports in raw_imports.items():
        importer = str(importer)
        for item in imports:
            if item.get("opaque_local_exports"):
                return None
            total += 1
            if total > _MAX_EXPORT_DEMAND_ITEMS:
                return None
            target = resolve(item["source"], importer)
            if target:
                importers[target].add(importer)
            if item.get("is_reexport"):
                if not target or target not in files or item.get("opaque_reexport"):
                    return None
                reexports[importer].append(item)
                for value in item["names"]:
                    if not _known_name(value):
                        return None
                    if value == "*":
                        wildcard[importer].add(target)
                        stars[importer].add(target)
                    elif value.startswith("* as "):
                        name = value.split(" as ", 1)[1]
                        namespaces[importer][name].add(target)
                        wildcard[importer].add(target)
                    else:
                        original, _, alias = value.partition(" as ")
                        named[importer][alias or original].append((target, original))
                        if len(named[importer][alias or original]) > 1:
                            return None
            elif target:
                if item.get("consume_all_exports"):
                    requests[target].add((_ALL,))
                paths = item.get("export_paths")
                if paths:
                    total += len(paths)
                    if total > _MAX_EXPORT_DEMAND_ITEMS:
                        return None
                    for path in paths:
                        if not path or not all(_known_name(part) for part in path):
                            return None
                        requests[target].add(tuple(path))
                    continue
                for value in item["names"]:
                    if not _known_name(value):
                        return None
                    original = value.partition(" as ")[0]
                    if value == item.get("default_import"):
                        original = "default"
                    if original == "*":
                        requests[target].add((_ALL,))
                    else:
                        requests[target].add((original,))
    # A source-only export with no source consumer may itself be public. Known
    # package, framework, script and browser entry points are also roots.
    for exporter in reexports:
        if exporter in context["roots"] or not importers.get(exporter):
            requests[exporter].add((_ALL,))
        if len(stars[exporter]) > 1:
            # Competing star identities require full module binding resolution.
            return None
    local_names = {
        file: {
            d.simple_name
            for d in values
            if d.is_exported and "default_export" not in d.confidence_factors
        }
        for file, values in by_file.items()
    }
    pending = deque((file, path) for file, paths in requests.items() for path in paths)
    visited = set()
    while pending:
        file, path = pending.popleft()
        if (file, path) in visited:
            continue
        visited.add((file, path))
        if len(visited) > _MAX_EXPORT_DEMAND_ITEMS:
            return None
        name, *tail = path
        consumed[file].add(name)
        targets = []
        if name in {_ALL, _STAR}:
            targets.extend(
                (target, (original,))
                for alias, pairs in named[file].items()
                if name == _ALL or alias != "default"
                for target, original in pairs
            )
            targets.extend(
                (target, (_ALL,))
                for values in namespaces[file].values()
                for target in values
            )
            targets.extend((target, (_STAR,)) for target in stars[file])
            for definition in by_file[file]:
                if definition.is_exported and (
                    name == _ALL
                    or "default_export" not in definition.confidence_factors
                ):
                    consumed[file].add(definition.simple_name)
            if name == _ALL:
                consumed[file].update(named[file])
                consumed[file].update(namespaces[file])
        elif name in named[file]:
            targets.extend(
                (target, (original, *tail)) for target, original in named[file][name]
            )
        elif name in namespaces[file]:
            targets.extend(
                (target, tuple(tail) or (_ALL,)) for target in namespaces[file][name]
            )
        elif name != "default" and name not in local_names.get(file, ()):
            targets.extend((target, path) for target in stars[file])
        if name == "default":
            consumed[file].update(
                d.simple_name
                for d in by_file[file]
                if "default_export" in d.confidence_factors
            )
        for target, selected in targets:
            if selected not in requests[target]:
                requests[target].add(selected)
                pending.append((target, selected))
    discarded_refs = Counter()
    for file, items in reexports.items():
        if _ALL not in consumed[file]:
            for item in items:
                discarded_refs.update(
                    (value, file) for value in item.get("reexport_reference_names", ())
                )
    # All input/iteration guards have finished before reference counters change.
    for file, names in consumed.items():
        names.discard(_ALL)
        names.discard(_STAR)
        for definition in by_file[file]:
            if definition.simple_name in names or definition.name in names:
                definition.references += 1
    return consumed, wildcard, importers, discarded_refs


def _known_name(name):
    if not isinstance(name, str) or not name or "\\" in name:
        return False
    if name == "*":
        return True
    parts = name.split(" as ")
    return len(parts) <= 2 and all(part == "*" or part.isidentifier() for part in parts)


def remove_reexport_only_refs(references, discarded):
    """Subtract exact parser-recorded occurrences, preserving independent reads."""
    remaining = Counter(discarded)
    result = []
    for name, file in references:
        key = (name, str(file))
        if remaining[key]:
            remaining[key] -= 1
        else:
            result.append((name, file))
    return result


def add_enumerated_reexport_reads(raw_imports, definitions, resolve, roots, consumed):
    """Credit source bindings read through a complete module namespace.

    This adds positive evidence even when a closed-program proof is unavailable.
    Every credited binding has an unambiguous resolved export path. Missing or
    competing bindings, namespace-export syntax and exhausted budgets add no
    new evidence. Star exports exclude default and respect explicit overrides.
    """
    if not roots:
        return
    local = defaultdict(lambda: defaultdict(list))
    objects = {}
    for definition in definitions.values():
        if (
            not definition.is_exported
            or definition.type in {"import", "method"}
            or not str(definition.filename).endswith(_SOURCE_SUFFIXES)
            or str(definition.filename).endswith(".d.ts")
            or {"type-only declaration", "ambient declaration"}.intersection(
                definition.framework_signals
            )
        ):
            continue
        identity = id(definition)
        if identity in objects:
            continue
        objects[identity] = definition
        export = (
            "default"
            if "default_export" in definition.confidence_factors
            else definition.simple_name
        )
        local[str(definition.filename)][export].append(identity)
    named = defaultdict(lambda: defaultdict(list))
    stars = defaultdict(list)
    unknown = set()
    count = 0
    for file, imports in raw_imports.items():
        file = str(file)
        for item in imports:
            if item.get("opaque_local_exports"):
                unknown.add(file)
            if not item.get("is_reexport"):
                continue
            count += 1
            if count > _MAX_EXPORT_DEMAND_ITEMS:
                return
            if item.get("opaque_reexport"):
                unknown.add(file)
                continue
            target = resolve(item["source"], file)
            for spelling in item["names"]:
                if not _known_name(spelling) or spelling.startswith("* as "):
                    unknown.add(file)
                elif spelling == "*":
                    stars[file].append(target)
                else:
                    original, _, alias = spelling.partition(" as ")
                    named[file][alias or original].append((target, original))
    surfaces = defaultdict(set)
    for file, bindings in local.items():
        surfaces[file].update(bindings)
    for file, bindings in named.items():
        surfaces[file].update(bindings)
    changed = True
    while changed:
        changed = False
        for file, sources in stars.items():
            for source in sources:
                additions = surfaces.get(source, set()) - {"default"} - surfaces[file]
                if additions:
                    count += len(additions)
                    if count > _MAX_EXPORT_DEMAND_ITEMS:
                        return
                    surfaces[file].update(additions)
                    changed = True
    unavailable = object()
    ambiguous = object()

    def binding(file, export, seen, depth=0):
        nonlocal count
        count += 1
        if count > _MAX_EXPORT_DEMAND_ITEMS or depth > 64:
            return unavailable
        if not file:
            return unavailable
        identity = (file, export)
        if identity in seen:
            return frozenset()
        seen = seen | {identity}
        locals_here = local.get(file, {}).get(export, ())
        if locals_here:
            return frozenset(locals_here) if len(locals_here) == 1 else ambiguous
        indirect = named.get(file, {}).get(export, ())
        if indirect:
            if len(indirect) != 1:
                return ambiguous
            target, original = indirect[0]
            return binding(target, original, seen, depth + 1)
        if export == "default":
            return frozenset()
        if file in unknown:
            return unavailable
        matches = set()
        for target in stars.get(file, ()):
            found = binding(target, export, seen, depth + 1)
            if found is unavailable or found is ambiguous:
                return found
            matches.update(found)
            if len(matches) > 1:
                return ambiguous
        return frozenset(matches)

    evidence = set()
    for file in sorted(roots):
        for export in sorted(surfaces.get(file, ())):
            found = binding(file, export, frozenset())
            if count > _MAX_EXPORT_DEMAND_ITEMS:
                return
            if found is unavailable or found is ambiguous or len(found) != 1:
                continue
            evidence.update(found)
    for identity in evidence:
        definition = objects[identity]
        definition.references = max(definition.references, 1)
        consumed[str(definition.filename)].add(definition.simple_name)
