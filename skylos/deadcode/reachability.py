"""Conservative source ownership for ordinary Python function reachability.

References are edges, not roots. Unknown bindings, unsupported owners and real
external-use evidence remain conservative. No target modules are imported.
"""

from __future__ import annotations

import ast
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from skylos.core.grep_verify_common import _grep_line_number, _grep_line_path
from skylos.deadcode._reachability_bindings import (
    FUNCTION_NODES,
    FunctionNode,
    ModuleInfo,
    bound_names,
    import_bindings,
)
from skylos.deadcode._reachability_graph import (
    ReferenceGraph,
    SourceIndex,
    SourceReference,
)
from skylos.deadcode._reachability_visitor import SourceVisitor
from skylos.deadcode._reachability_receivers import bind_classes, stable_receivers
from skylos.deadcode._reachability_scopes import bind_nested_functions
from skylos.deadcode.python_ast import ParsedPythonFile, parse_python_files

if TYPE_CHECKING:
    from skylos.visitors.base import Definition

_ROOT_MARKERS = {
    "framework_root",
    "package_entrypoint",
    "test_entrypoint",
    "top_level_execution",
    "coverage_hit",
    "trace_hit",
    "grep_verify",
    "reachable_from_root",
}
_EXTERNAL_EVIDENCE = (
    "is_exported",
    "decorators",
    "dynamic_signals",
    "framework_signals",
    "is_closure",
    "is_lambda",
)
_MAX_FILES = 4096
_MAX_NODES = 2_000_000
_UNREACHABLE_REASON = (
    "No reachable entrypoint or unresolved external use; references occur only "
    "within unreachable Python function groups."
)
DefinitionLocations = dict[tuple[Path, int, str], list[tuple[str, "Definition"]]]


def _path(value: str | Path, root: Path) -> Path:
    path = Path(value)
    return (root / path if not path.is_absolute() else path).resolve()


def _source_reference_count(definition: Definition) -> int:
    """Exclude the analyzer's tracked global simple-name attribute hints."""
    return max(
        0,
        getattr(definition, "references", 0)
        - getattr(definition, "_attr_name_ref_count", 0),
    )


class PythonReachabilityReport:
    def __init__(self, definitions: Mapping[str, Definition], root: Path) -> None:
        self.project_root = root
        self.complete = True
        self.incomplete_reasons: list[str] = []
        self.unreachable_keys: set[str] = set()
        self.reachable_keys: set[str] = set()
        self.proven_reachable_keys: set[str] = set()
        self.protected_keys: set[str] = set()
        self.protected_callback_keys: set[str] = set()
        self.reasons: dict[str, str] = {}
        self._definitions = definitions
        self.index = SourceIndex()
        self.graph = ReferenceGraph()

    def refresh(
        self,
        definitions: Mapping[str, Definition] | None = None,
        *,
        additional_roots: Iterable[str] = (),
    ) -> PythonReachabilityReport:
        """Recompute callback or grep roots while retaining the source graph."""
        if definitions is not None:
            self._definitions = definitions
        roots, proven_roots = self._current_roots(additional_roots)
        candidates = self.index.candidates.keys()
        reached = self.graph.traverse(roots, candidates, uncertainty=True)
        self.reachable_keys = reached.intersection(candidates)
        self.proven_reachable_keys = self.graph.traverse(
            proven_roots,
            candidates,
            uncertainty=False,
        ).intersection(candidates)
        exposed_receivers = set(self.graph.receiver_roots)
        for owner in reached:
            exposed_receivers.update(self.graph.receiver_edges.get(owner, ()))
        self.protected_keys = (
            self.graph.traverse(
                exposed_receivers, candidates, uncertainty=True
            ).intersection(candidates)
            - self.proven_reachable_keys
        )
        # A nested callback can be used by a decorator or an unsupported
        # deferred owner (for example a lambda) without a proven invocation.
        callbacks = self.reachable_keys.intersection(self.index.nested_parents)
        callbacks -= self.proven_reachable_keys
        self.protected_callback_keys = (
            self.graph.traverse(callbacks, candidates, uncertainty=True).intersection(
                candidates
            )
            - self.proven_reachable_keys
        )
        self.unreachable_keys = set(candidates) - reached if self.complete else set()
        self.reasons = {key: _UNREACHABLE_REASON for key in self.unreachable_keys}
        return self

    def _current_roots(self, additional: Iterable[str]) -> tuple[set[str], set[str]]:
        proven = self.graph.roots | set(additional)
        roots = proven | self.graph.uncertain_roots
        for key, original in self.index.candidates.items():
            definition = self._definitions.get(key, original)
            markers = getattr(definition, "heuristic_refs", {}) or {}
            if _ROOT_MARKERS.intersection(markers):
                proven.add(key)
            if self._needs_conservative_root(key, definition, markers):
                roots.add(key)
        return roots | proven, proven

    def _needs_conservative_root(
        self,
        key: str,
        definition: Definition,
        markers: Mapping[str, float],
    ) -> bool:
        external = any(
            getattr(definition, attr, False)
            for attr in _EXTERNAL_EVIDENCE
            if key not in self.index.nested_parents
            or attr not in {"is_closure", "decorators"}
        )
        class_key = self.index.method_classes.get(key)
        if class_key is not None:
            owning_class = self.index.classes[class_key].definition
            external |= any(
                getattr(owning_class, attr, False) for attr in _EXTERNAL_EVIDENCE
            )
            external |= definition.simple_name.startswith(
                "__"
            ) and definition.simple_name.endswith("__")
        callback = any(name.startswith("dead_code_liveness:") for name in markers)
        return (
            external
            or callback
            or key in self.index.uncertain_nested_keys
            or self._unaccounted_reference(key, definition)
        )

    def _unaccounted_reference(self, key: str, definition: Definition) -> bool:
        references = max(
            self.index.initial_references.get(key, 0),
            _source_reference_count(definition),
        )
        unknown_caller = any(
            len(self.index.by_name.get(caller, ())) != 1
            for caller in getattr(definition, "called_by", ())
        )
        return references > self.graph.observed[key] or unknown_caller

    def filter_grep_results(
        self,
        finding: Mapping[str, Any],
        raw_results: dict[str, Any],
    ) -> dict[str, Any]:
        """Discard source matches only for candidates proved unreachable."""
        target = self._finding_target(finding)
        if target is None:
            return raw_results
        name = self.index.candidates[target].simple_name
        return {
            strategy: [
                value for value in values if self._relevant_hit(value, name, target)
            ]
            if isinstance(values, list)
            else values
            for strategy, values in raw_results.items()
        }

    def _finding_target(self, finding: Mapping[str, Any]) -> str | None:
        try:
            file = _path(finding.get("file", ""), self.project_root)
        except (ValueError, OSError, RuntimeError):
            return None
        target = self.index.by_location.get((file, finding.get("line")))
        return target if target in self.unreachable_keys else None

    def _relevant_hit(self, value: Any, name: str, target: str) -> bool:
        references = self._hit_references(value, name, target)
        return not references or not all(
            ref.target is not None
            and (ref.target != target or ref.owner in self.unreachable_keys)
            for ref in references
        )

    def _hit_references(
        self, value: Any, name: str, target: str
    ) -> list[SourceReference] | None:
        if not isinstance(value, str):
            return None
        source, line = _grep_line_path(value), _grep_line_number(value)
        if not source or not line:
            return None
        try:
            path = _path(source, self.project_root)
        except (ValueError, OSError, RuntimeError):
            return None
        return [
            ref
            for ref in self.graph.references.get((path, line), ())
            if ref.name in {name, "*"} or ref.target == target
        ]


def _source_paths(files: Iterable[str | Path], root: Path) -> tuple[list[Path], bool]:
    selected = []
    complete = True
    for value in files:
        path = Path(value)
        if path.suffix != ".py":
            continue
        try:
            if path.is_symlink():
                raise ValueError("symlink source")
            path = path.resolve()
            path.relative_to(root)
            selected.append(path)
        except (OSError, ValueError, RuntimeError):
            complete = False
    return sorted(set(selected)), complete


def _canonical_modules(
    module_names: Mapping[str | Path, str] | None,
    root: Path,
) -> dict[Path, str] | None:
    if module_names is None:
        return None
    canonical = {}
    for path, identity in module_names.items():
        if not isinstance(identity, str):
            continue
        try:
            canonical[_path(path, root)] = identity
        except (OSError, ValueError, RuntimeError):
            continue
    return canonical


def _definition_module_identity(
    module: ModuleInfo,
    locations: DefinitionLocations,
) -> str | None:
    identities = set()
    for node in module.tree.body:
        if not isinstance(node, FUNCTION_NODES):
            continue
        matches = locations.get((module.path, node.lineno, node.name), ())
        if len(matches) == 1:
            identity, separator, _name = matches[0][1].name.rpartition(".")
            if separator:
                identities.add(identity)
    return next(iter(identities)) if len(identities) == 1 else None


def _load_modules(
    report: PythonReachabilityReport,
    parsed: list[ParsedPythonFile],
    locations: DefinitionLocations,
    module_names: dict[Path, str] | None,
) -> bool:
    node_count = 0
    missing_identity = False
    for source in parsed:
        node_count += sum(1 for _ in ast.walk(source.tree))
        if node_count > _MAX_NODES:
            _incomplete(report, "Python reachability AST limit exceeded")
            return False
        module = ModuleInfo(source.path, source.tree)
        identity = (
            _definition_module_identity(module, locations)
            if module_names is None
            else module_names.get(source.path)
        )
        if identity is not None:
            module.names.add(identity)
        else:
            missing_identity = True
        report.index.modules[source.path] = module
    if missing_identity:
        _incomplete(
            report,
            "Python reachability has sources without canonical module identities",
        )
    return True


def _definition_locations(
    definitions: Mapping[str, Definition], root: Path
) -> DefinitionLocations:
    indexed: DefinitionLocations = defaultdict(list)
    for key, definition in definitions.items():
        if getattr(definition, "type", "") not in {"function", "method"}:
            continue
        try:
            file = _path(definition.filename, root)
        except (ValueError, OSError, RuntimeError):
            continue
        indexed[file, definition.line, definition.simple_name].append((key, definition))
    return indexed


def _bind_function(
    report: PythonReachabilityReport,
    module: ModuleInfo,
    node: FunctionNode,
    counts: Counter[str],
    locations: DefinitionLocations,
) -> None:
    matches = locations.get((module.path, node.lineno, node.name), ())
    if len(matches) != 1 or counts[node.name] != 1:
        return
    key, definition = matches[0]
    index = report.index
    index.add_function(module, node, key, definition)
    module.bindings[node.name] = ("symbol", key)
    if node.decorator_list or node.name in {"__getattr__", "__dir__"}:
        report.graph.uncertain_roots.add(key)


def _bind_module_imports(module: ModuleInfo, counts: Counter[str]) -> None:
    for node in module.tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module.bindings.update(
                {
                    name: binding
                    for name, binding in import_bindings(node, module).items()
                    if counts[name] == 1
                }
            )


def _bind_module(
    report: PythonReachabilityReport, module: ModuleInfo, locations: DefinitionLocations
) -> None:
    counts = bound_names(module.tree.body).counts
    for node in module.tree.body:
        if isinstance(node, FUNCTION_NODES):
            _bind_function(report, module, node, counts, locations)
    for name in counts:
        module.bindings.setdefault(name, None)
    _bind_module_imports(module, counts)
    for name in module.names:
        if name:
            report.index.module_names[name].append(module)


def _incomplete(report: PythonReachabilityReport, reason: str) -> None:
    report.complete = False
    report.incomplete_reasons.append(reason)


def analyze_python_reachability(
    definitions: Mapping[str, Definition],
    files: Iterable[str | Path],
    project_root: str | Path,
    *,
    module_names: Mapping[str | Path, str] | None = None,
) -> PythonReachabilityReport:
    """Resolve function groups using analyzer identities or Definition metadata.

    Missing module identities disable negative conclusions. This pass does not
    independently infer source roots from directory names.
    """
    root = Path(project_root).resolve()
    if root.is_file():
        root = root.parent
    report = PythonReachabilityReport(definitions, root)
    selected, report.complete = _source_paths(files, root)
    if len(selected) > _MAX_FILES:
        _incomplete(report, "Python reachability source limit exceeded")
        return report
    parsed = parse_python_files(selected)
    if len(parsed) != len(selected):
        _incomplete(report, "Python reachability has unreadable or unparsed sources")
    locations = _definition_locations(definitions, root)
    canonical = _canonical_modules(module_names, root)
    if not _load_modules(report, parsed, locations, canonical):
        return report
    for module in report.index.modules.values():
        _bind_module(report, module, locations)
    bind_classes(report.index, definitions)
    bind_nested_functions(report.index, locations)
    for module in report.index.modules.values():
        module.bindings = stable_receivers(
            report.index, module, module.tree.body, module.bindings
        )
    for module in report.index.modules.values():
        SourceVisitor(report.index, report.graph, module).visit(module.tree)
    return report.refresh()
