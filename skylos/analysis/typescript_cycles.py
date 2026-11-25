"""SKY-CIRC for JS/TS: load-time import cycles between project files.

An edge is a literal ``import``, ``export ... from`` or top-level
``require()`` whose specifier resolves to another scanned JS/TS file or a
Vue/Svelte/Astro component script. Erased requests (``import type``,
``export type``, clauses whose every specifier is ``type``) and lazy loads
(``import()``, a ``require()`` inside a function body) do not run when the
importer is evaluated, so they cannot form a load-time cycle. Each strongly
connected component is reported once, with its shortest cycle through the
first file in path order.
"""

from __future__ import annotations

import os
from collections import defaultdict, deque

from skylos.analysis.circular_deps import CIRCULAR_DEPENDENCY_SEVERITY


def _strongly_connected(nodes, successors):
    """Tarjan's algorithm without recursion; components in discovery order."""
    index_of, low, on_stack = {}, {}, set()
    stack, components, counter = [], [], 0
    for start in nodes:
        if start in index_of:
            continue
        work = [(start, iter(successors.get(start, ())))]
        index_of[start] = low[start] = counter
        counter += 1
        stack.append(start)
        on_stack.add(start)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in index_of:
                    index_of[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(successors.get(child, ()))))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index_of[child])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index_of[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(component)
    return components


def _shortest_cycle(start, members, successors):
    parents = {start: None}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for child in successors.get(node, ()):
            if child not in members:
                continue
            if child == start:
                path = [node]
                while parents[path[-1]] is not None:
                    path.append(parents[path[-1]])
                return list(reversed(path))
            if child not in parents:
                parents[child] = node
                queue.append(child)
    return [start]


def _display_name(path, root):
    try:
        relative = os.path.relpath(path, root)
    except ValueError:
        return path
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return path
    return relative.replace(os.sep, "/")


_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")


def _runtime_import_sites(module_requests, resolver):
    """Return source lines for each resolved load-time import edge.

    Declaration files never run, so they are not nodes of the load graph.
    """
    nodes = {
        path
        for path in set(module_requests.files) | set(module_requests.component_files)
        if not path.endswith(_DECLARATION_SUFFIXES)
    }
    sites = defaultdict(set)
    for request in module_requests.requests:
        if not request.loads_at_startup or request.importer not in nodes:
            continue
        target = resolver.resolve(request.source, request.importer)
        if target is None or target == request.importer or target not in nodes:
            continue
        sites[request.importer, target].add(request.line)
    return sites


def find_typescript_cycles(module_requests, resolver, project_root):
    """Return SKY-CIRC findings, one per JS/TS strongly connected component."""
    root = os.path.realpath(str(project_root))
    sites = _runtime_import_sites(module_requests, resolver)
    if not sites:
        return []
    names = {}
    successors = defaultdict(set)
    incoming = defaultdict(int)
    for importer, target in sites:
        names.setdefault(importer, _display_name(importer, root))
        names.setdefault(target, _display_name(target, root))
        successors[importer].add(target)
        incoming[target] += 1
    ordered = sorted(names, key=lambda path: names[path])
    ordered_successors = {
        node: sorted(successors.get(node, ()), key=lambda path: names[path])
        for node in ordered
    }

    findings = []
    for component in _strongly_connected(ordered, ordered_successors):
        if len(component) < 2:
            continue
        members = set(component)
        start = min(component, key=lambda path: names[path])
        path = _shortest_cycle(start, members, ordered_successors)
        cycle = [names[node] for node in path]
        # Same heuristic as the Python graph: the file with the fewest
        # dependents relative to its own dependencies is the cheapest to cut.
        best = min(
            path,
            key=lambda node: incoming[node] - len(successors.get(node, ())),
        )
        location = min(
            (importer, min(sites[importer, target]))
            for importer, target in zip(path, path[1:] + path[:1])
        )
        component_edges = [
            (importer, target)
            for importer in component
            for target in ordered_successors[importer]
            if target in members
        ]
        locations = sorted(
            (importer, line, target)
            for importer, target in component_edges
            for line in sites[importer, target]
        )
        finding = {
            "rule_id": "SKY-CIRC",
            "kind": "circular_dependency",
            "category": "ARCHITECTURE",
            "severity": CIRCULAR_DEPENDENCY_SEVERITY,
            "message": f"Circular dependency: {' → '.join(cycle)} → {cycle[0]}",
            "cycle": cycle,
            "cycle_length": len(cycle),
            "cycle_edges": sorted(
                [names[importer], names[target]] for importer, target in component_edges
            ),
            "suggested_break": names[best],
            "file": location[0],
            "line": location[1],
            "related_locations": [
                {
                    "file": importer,
                    "start_line": line,
                    "end_line": line,
                    "message": f"{names[importer]} imports {names[target]}",
                }
                for importer, line, target in locations
            ],
        }
        if len(component) > len(path):
            finding["component_files"] = sorted(names[node] for node in component)
        findings.append(finding)
    findings.sort(key=lambda item: (item["cycle_length"], item["cycle"]))
    return findings
