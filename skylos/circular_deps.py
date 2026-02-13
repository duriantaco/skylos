from __future__ import annotations
import ast
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Any
from collections import defaultdict


@dataclass
class ModuleDependency:
    from_module: str
    to_module: str
    import_line: int
    import_type: str
    imported_names: List[str] = field(default_factory=list)


@dataclass
class CircularDependency:
    cycle: List[str]
    suggested_break: str
    severity: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": "SKY-CIRC",
            "kind": "circular_dependency",
            "category": "ARCHITECTURE",
            "severity": self.severity,
            "message": f"Circular dependency: {' → '.join(self.cycle)} → {self.cycle[0]}",
            "cycle": self.cycle,
            "cycle_length": len(self.cycle),
            "suggested_break": self.suggested_break,
        }


class DependencyGraphBuilder(ast.NodeVisitor):
    def __init__(self, module_name: str, file_path: str, known_modules: Set[str]):
        self.module_name = module_name
        self.file_path = file_path
        self.known_modules = known_modules
        self.dependencies: List[ModuleDependency] = []

    def generic_visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            module = alias.name.split(".")[0]
            if self._is_internal_module(alias.name):
                self.dependencies.append(
                    ModuleDependency(
                        from_module=self.module_name,
                        to_module=alias.name.split(".")[0],
                        import_line=node.lineno,
                        import_type="import",
                        imported_names=[alias.asname or alias.name],
                    )
                )

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and node.level == 0:
            module = node.module.split(".")[0]
            if self._is_internal_module(node.module):
                names = [a.name for a in node.names if a.name != "*"]
                self.dependencies.append(
                    ModuleDependency(
                        from_module=self.module_name,
                        to_module=module,
                        import_line=node.lineno,
                        import_type="from_import",
                        imported_names=names,
                    )
                )
        elif node.level > 0:
            # relative import can create cycles we need to resolve relative imports properly
            # for now just track as potential issues
            pass

    def _is_internal_module(self, module: str) -> bool:
        root = module.split(".")[0]
        return root in self.known_modules


class CircularDependencyAnalyzer:
    def __init__(self):
        self.modules: Dict[str, str] = {}
        self.dependencies: Dict[str, Set[str]] = defaultdict(set)
        self.all_deps: List[ModuleDependency] = []
        self.known_modules: Set[str] = set()

    def add_file(self, tree: ast.AST, file_path: str, module_name: str):
        self.modules[module_name] = file_path
        root_module = module_name.split(".")[0]
        self.known_modules.add(root_module)

    def build_graph_from_raw_imports(self, raw_imports_by_module: Dict[str, list]):
        for module_name in self.modules:
            root = module_name.split(".")[0]
            self.known_modules.add(root)

        for module_name, raw_imports in raw_imports_by_module.items():
            file_path = self.modules.get(module_name, "")
            for import_module, line, import_type, names in raw_imports:
                root = import_module.split(".")[0]
                if root in self.known_modules:
                    dep = ModuleDependency(
                        from_module=module_name,
                        to_module=root,
                        import_line=line,
                        import_type=import_type,
                        imported_names=names,
                    )
                    self.dependencies[dep.from_module].add(dep.to_module)
                    self.all_deps.append(dep)

    def build_graph(self, trees: Dict[str, ast.AST]):
        for module_name in self.modules:
            root = module_name.split(".")[0]
            self.known_modules.add(root)

        for module_name, file_path in self.modules.items():
            if module_name in trees:
                builder = DependencyGraphBuilder(
                    module_name, file_path, self.known_modules
                )
                builder.visit(trees[module_name])

                for dep in builder.dependencies:
                    self.dependencies[dep.from_module].add(dep.to_module)
                    self.all_deps.append(dep)

    def find_cycles(self) -> List[List[str]]:
        index_counter = [0]
        stack = []
        lowlinks = {}
        index = {}
        on_stack = {}
        sccs = []

        def strongconnect(node):
            index[node] = index_counter[0]
            lowlinks[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack[node] = True

            for successor in self.dependencies.get(node, []):
                if successor not in index:
                    strongconnect(successor)
                    lowlinks[node] = min(lowlinks[node], lowlinks[successor])
                elif on_stack.get(successor, False):
                    lowlinks[node] = min(lowlinks[node], index[successor])

            if lowlinks[node] == index[node]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.append(w)
                    if w == node:
                        break
                if len(scc) > 1:
                    sccs.append(scc)

        for node in self.modules:
            if node not in index:
                strongconnect(node)

        return sccs

    def find_simple_cycles(self) -> List[List[str]]:
        cycles = []
        visited = set()

        def dfs(node, path, path_set):
            if node in path_set:
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                min_idx = cycle.index(min(cycle[:-1]))
                normalized = cycle[min_idx:-1] + cycle[:min_idx]
                return [normalized]

            if node in visited:
                return []

            found_cycles = []
            path.append(node)
            path_set.add(node)

            for neighbor in self.dependencies.get(node, []):
                found_cycles.extend(dfs(neighbor, path, path_set))

            path.pop()
            path_set.remove(node)
            visited.add(node)

            return found_cycles

        for node in self.modules:
            visited.clear()
            found = dfs(node, [], set())
            for cycle in found:
                if cycle not in cycles:
                    cycles.append(cycle)

        unique_cycles = []
        seen = set()
        for cycle in cycles:
            key = tuple(sorted(cycle))
            if key not in seen:
                seen.add(key)
                unique_cycles.append(cycle)

        return unique_cycles

    def suggest_break_point(self, cycle: List[str]) -> str:
        if not cycle:
            return ""

        incoming_counts = {}
        for module in cycle:
            count = 0
            for other_deps in self.dependencies.values():
                if module in other_deps:
                    count += 1
            incoming_counts[module] = count

        best = cycle[0]
        best_score = float("inf")

        for module in cycle:
            outgoing = len(self.dependencies.get(module, set()))
            incoming = incoming_counts[module]
            score = incoming - outgoing
            if score < best_score:
                best_score = score
                best = module

        return best

    def analyze(self) -> List[CircularDependency]:
        cycles = self.find_simple_cycles()

        findings = []
        for cycle in cycles:
            severity = (
                "HIGH" if len(cycle) > 3 else "MEDIUM" if len(cycle) > 2 else "LOW"
            )
            suggested = self.suggest_break_point(cycle)

            findings.append(
                CircularDependency(
                    cycle=cycle,
                    suggested_break=suggested,
                    severity=severity,
                )
            )

        findings.sort(key=lambda f: len(f.cycle))

        return findings

    def get_findings(self) -> List[Dict[str, Any]]:
        return [cd.to_dict() for cd in self.analyze()]

    def get_core_infrastructure(self) -> Set[str]:
        cycles = self.find_simple_cycles()
        module_cycle_count = defaultdict(int)

        for cycle in cycles:
            for module in cycle:
                module_cycle_count[module] += 1

        return {m for m, count in module_cycle_count.items() if count >= 2}

    def get_summary(self) -> Dict[str, Any]:
        cycles = self.find_simple_cycles()

        return {
            "total_modules": len(self.modules),
            "total_cycles": len(cycles),
            "max_cycle_length": max((len(c) for c in cycles), default=0),
            "avg_cycle_length": sum(len(c) for c in cycles) / len(cycles)
            if cycles
            else 0,
            "core_infrastructure": list(self.get_core_infrastructure()),
        }


class CircularDependencyRule:
    rule_id = "SKY-CIRC"
    name = "Circular Dependencies"
    severity = "MEDIUM"
    category = "architecture"

    def __init__(self, max_cycles: int = -1):
        self.max_cycles = max_cycles
        self._analyzer = CircularDependencyAnalyzer()
        self._trees: Dict[str, ast.AST] = {}
        self._raw_imports: Dict[str, list] = {}

    def add_file(self, tree: ast.AST, file_path: str, module_name: str):
        self._analyzer.add_file(tree, file_path, module_name)
        self._trees[module_name] = tree

    def add_file_imports(self, file_path: str, module_name: str, raw_imports: list):
        self._analyzer.add_file(None, file_path, module_name)
        self._raw_imports[module_name] = raw_imports

    def analyze(self) -> List[Dict[str, Any]]:
        if self._raw_imports:
            self._analyzer.build_graph_from_raw_imports(self._raw_imports)
        else:
            self._analyzer.build_graph(self._trees)
        return self._analyzer.get_findings()

    def check(self) -> Tuple[bool, str]:
        findings = self.analyze()

        if self.max_cycles < 0:
            return True, f"Found {len(findings)} circular dependencies (warning)"

        if len(findings) > self.max_cycles:
            return (
                False,
                f"Found {len(findings)} circular dependencies (max: {self.max_cycles})",
            )

        return (
            True,
            f"Circular dependency check passed ({len(findings)} <= {self.max_cycles})",
        )


def analyze_circular_dependencies(
    file_module_pairs: List[Tuple[str, str, ast.AST]],
) -> List[Dict[str, Any]]:
    rule = CircularDependencyRule()

    for file_path, module_name, tree in file_module_pairs:
        rule.add_file(tree, file_path, module_name)

    return rule.analyze()
