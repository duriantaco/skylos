"""Compare prepared source snapshots without Git, analyzer or command policy."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import hashlib
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Mapping, Sequence

from skylos.verification.behavior import compare_python_behavior

_MAX_COMPARISONS = 128


@dataclass(frozen=True)
class SourceSnapshot:
    """Decoded Python sources and hashes of original Python/environment bytes.

    Paths are repository-relative POSIX names. Hashes remain evidence supplied
    by the snapshot loader; Python change selection uses the source contents.
    Copying the mappings prevents later caller edits from changing this input.
    """

    sources: Mapping[str, str]
    hashes: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", MappingProxyType(dict(self.sources)))
        object.__setattr__(self, "hashes", MappingProxyType(dict(self.hashes)))


@dataclass(frozen=True)
class ComparisonScope:
    """A selected repository-relative file or directory within the snapshots."""

    selected: str = "."
    directory: bool = True
    line_range: tuple[int, int] | None = None
    exclude_folders: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        path = PurePosixPath(self.selected)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Comparison scope must be repository-relative")
        object.__setattr__(self, "selected", path.as_posix())
        object.__setattr__(self, "exclude_folders", frozenset(self.exclude_folders))
        if self.line_range is not None:
            bounds = tuple(self.line_range)
            if (
                len(bounds) != 2
                or any(type(value) is not int for value in bounds)
                or bounds[0] < 1
                or bounds[1] < bounds[0]
            ):
                raise ValueError("Invalid line range")
            object.__setattr__(self, "line_range", bounds)

    def contains(self, name: str) -> bool:
        matches = (
            (self.selected == "." or name.startswith(self.selected + "/"))
            if self.directory
            else name == self.selected
        )
        return matches and not any(
            part in self.exclude_folders for part in PurePosixPath(name).parts[:-1]
        )


def _new_result(status: str = "unchanged") -> dict:
    return {
        "schema_version": 1,
        "status": status,
        "comparisons": [],
        "reasons": [],
        "changed_files": [],
        "selection": "affected_python_functions",
        "runtime_witness": False,
        "limits": {
            "functions": _MAX_COMPARISONS,
            "paths_per_function": 64,
            "helper_depth": 8,
        },
        "assumptions": [
            "Affected-function selection follows static imports and name references; dynamic loading and runtime rebinding are outside impact discovery.",
        ],
    }


def is_environment_file(name: str) -> bool:
    path = PurePosixPath(name)
    filename = path.name
    return filename in {
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "Pipfile",
        "Pipfile.lock",
        "setup.py",
        "setup.cfg",
        "pdm.lock",
        "pixi.lock",
        "pixi.toml",
        ".python-version",
        ".gitmodules",
        "environment.yml",
        "environment.yaml",
    } or (
        (filename.startswith("requirements") or "requirements" in path.parts[:-1])
        and filename.endswith((".txt", ".in"))
    )


@dataclass
class _Function:
    digest: str
    start: int
    end: int
    references: set[str]


@dataclass
class _Source:
    functions: dict[str, _Function] = field(default_factory=dict)
    imports: dict[str, str] = field(default_factory=dict)
    dependencies: set[str] = field(default_factory=set)
    structure: str = ""
    digest: str = ""
    error: str | None = None


def _digest(node) -> str:
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def _module(path: str) -> str:
    parts = list(PurePosixPath(path).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _index(path: str, source: str) -> _Source:
    info = _Source(digest=hashlib.sha256(source.encode()).hexdigest())
    try:
        tree = ast.parse(source, filename=path)
        info.digest = _digest(tree)
        residual = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = (
                    node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                )
                if (
                    node.decorator_list
                    or node.returns
                    or node.args.defaults
                    or any(value is not None for value in node.args.kw_defaults)
                    or any(argument.annotation for argument in arguments)
                    or getattr(node, "type_params", [])
                ):
                    info.error = "Function definition headers are outside the supported behavior model"
                if node.name in info.functions:
                    info.error = (
                        "Duplicate function definitions prevent automatic selection"
                    )
                info.functions[node.name] = _Function(
                    _digest(node),
                    min([node.lineno] + [d.lineno for d in node.decorator_list]),
                    node.end_lineno or node.lineno,
                    {name for child in ast.walk(node) if (name := _dotted(child))},
                )
            else:
                residual.append(node)
                if not isinstance(
                    node, (ast.Import, ast.ImportFrom, ast.Pass)
                ) and not (
                    isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    info.error = "Module bindings or statements are outside the supported behavior model"
        info.structure = _digest(ast.Module(body=residual, type_ignores=[]))
        # Imports anywhere in a file conservatively contribute dependency edges.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    info.dependencies.add(alias.name)
                    info.imports[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    package = _module(path).split(".")
                    if PurePosixPath(path).name != "__init__.py":
                        package = package[:-1]
                    module = ".".join(
                        package[: max(0, len(package) - node.level + 1)]
                        + ([module] if module else [])
                    )
                info.dependencies.add(module)
                for alias in node.names:
                    imported = f"{module}.{alias.name}".strip(".")
                    info.imports[alias.asname or alias.name] = imported
                    info.dependencies.add(imported)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        info.error = f"Cannot index Python source: {type(exc).__name__}"
    return info


def _matches_module(module: str, imported: str) -> bool:
    # Unknown import roots must broaden impact, never hide a changed dependency.
    module, imported = module.casefold(), imported.casefold()
    return bool(imported) and (
        module == imported
        or module.endswith("." + imported)
        or imported.startswith(module + ".")
        or module.startswith(imported + ".")
    )


def compare_source_changes(
    before: SourceSnapshot,
    after: SourceSnapshot,
    *,
    scope: ComparisonScope | None = None,
    scopes: Sequence[ComparisonScope] | None = None,
) -> dict:
    """Return modeled changes and unsupported coverage for prepared sources.

    Callers own snapshot acquisition, revision metadata, display and exit
    policy. No filesystem access, Git invocation or static analyzer runs here.
    Multiple scopes are a union, with line ranges and exclusions applied per
    scope. Selected functions share one impact graph and comparison budget.
    """
    if scope is not None and scopes is not None:
        raise ValueError("Specify either scope or scopes, not both")
    selections = (
        tuple(dict.fromkeys(scopes))
        if scopes is not None
        else (scope or ComparisonScope(),)
    )
    if not selections:
        raise ValueError("At least one comparison scope is required")

    def in_scope(name: str) -> bool:
        return any(selection.contains(name) for selection in selections)

    result = _new_result()
    before_hashes, after_hashes = before.hashes, after.hashes
    before, after = before.sources, after.sources
    files = before.keys() | after.keys()
    raw_changed = {name for name in files if before.get(name) != after.get(name)}
    environment_changes = sorted(
        name
        for name in before_hashes.keys() | after_hashes.keys()
        if is_environment_file(name)
        and before_hashes.get(name) != after_hashes.get(name)
    )
    if not raw_changed and not environment_changes:
        result["status"] = "unchanged"
        return result
    # A known unsupported edit in a file target needs no repository-wide graph.
    # This also keeps selected-file comparison cheap for code outside the model.
    single_scope = selections[0] if len(selections) == 1 else None
    if (
        single_scope is not None
        and not single_scope.directory
        and single_scope.selected in raw_changed
        and in_scope(single_scope.selected)
    ):
        selected, bounds = single_scope.selected, single_scope.line_range
        left = _index(selected, before.get(selected, ""))
        right = _index(selected, after.get(selected, ""))
        if (left.error or right.error) and left.digest != right.digest:
            result.update(
                status="unknown",
                changed_files=[selected],
                reasons=[f"{selected}: {left.error or right.error}"],
            )
            for symbol in sorted(left.functions.keys() | right.functions.keys())[
                :_MAX_COMPARISONS
            ]:
                a, b = left.functions.get(symbol), right.functions.get(symbol)
                if bounds and not any(
                    node and node.start <= bounds[1] and node.end >= bounds[0]
                    for node in (a, b)
                ):
                    continue
                result["comparisons"].append(
                    compare_python_behavior(before, after, file=selected, symbol=symbol)
                )
            return result
    old = {name: _index(name, source) for name, source in before.items()}
    new = {
        name: old[name]
        if name in old and before.get(name) == source
        else _index(name, source)
        for name, source in after.items()
    }
    empty = _index("empty.py", "")
    # Line changes alone do not alter the behavior model.
    changed = {
        name
        for name in raw_changed
        if name not in before
        or name not in after
        or old.get(name, empty).digest != new.get(name, empty).digest
    }
    result["changed_files"] = sorted(changed)
    affected_modules = set(changed)
    if environment_changes:
        affected_modules.update(name for name in files if in_scope(name))
    modules = {name: _module(name) for name in files}
    identities, descendants = {}, {}
    for name, module in modules.items():
        parts = module.casefold().split(".")
        for start in range(len(parts)):
            suffix = parts[start:]
            identities.setdefault(".".join(suffix), set()).add(name)
            for end in range(1, len(suffix) + 1):
                descendants.setdefault(".".join(suffix[:end]), set()).add(name)
    dependents = {}
    for name in files:
        dependencies = (
            old.get(name, empty).dependencies | new.get(name, empty).dependencies
        )
        for dependency in dependencies:
            parts = dependency.casefold().split(".")
            targets = set(descendants.get(dependency.casefold(), ()))
            for end in range(1, len(parts) + 1):
                targets.update(identities.get(".".join(parts[:end]), ()))
            for target in targets:
                dependents.setdefault(target, set()).add(name)
    pending = list(affected_modules)
    while pending:
        for caller in dependents.get(pending.pop(), ()):
            if caller not in affected_modules:
                affected_modules.add(caller)
                pending.append(caller)
    functions = {
        (name, symbol)
        for name in files
        for symbol in old.get(name, empty).functions.keys()
        | new.get(name, empty).functions.keys()
    }
    by_symbol = {}
    for key in functions:
        by_symbol.setdefault(key[1], []).append(key)
    edges = {key: set() for key in functions}
    for key in functions:
        name, symbol = key
        for index in (old, new):
            info = index.get(name, empty)
            function = info.functions.get(symbol)
            if function is None:
                continue
            for reference in function.references:
                if (name, reference) in functions:
                    edges[key].add((name, reference))
                head, _, tail = reference.partition(".")
                if head in info.imports:
                    qualified = info.imports[head] + ("." + tail if tail else "")
                    module, _, member = qualified.rpartition(".")
                    edges[key].update(
                        candidate
                        for candidate in by_symbol.get(member, ())
                        if _matches_module(modules[candidate[0]], module)
                    )
    affected = set()
    for name in affected_modules:
        left, right = old.get(name, empty), new.get(name, empty)
        broad = (
            name not in changed
            or left.structure != right.structure
            or left.error
            or right.error
        )
        for symbol in left.functions.keys() | right.functions.keys():
            a, b = left.functions.get(symbol), right.functions.get(symbol)
            if broad or a is None or b is None or a.digest != b.digest:
                affected.add((name, symbol))
    while True:
        expanded = affected | {key for key, refs in edges.items() if refs & affected}
        if expanded == affected:
            break
        affected = expanded

    # New helpers are checked by inlining them into surviving affected callers.
    def selected_function(key):
        nodes = [index.get(key[0], empty).functions.get(key[1]) for index in (old, new)]
        return any(
            selection.contains(key[0])
            and (
                selection.line_range is None
                or any(
                    node
                    and node.start <= selection.line_range[1]
                    and node.end >= selection.line_range[0]
                    for node in nodes
                )
            )
            for selection in selections
        )

    existing = {
        key
        for key in affected
        if key[1] in old.get(key[0], empty).functions
        and key[1] in new.get(key[0], empty).functions
        and selected_function(key)
    }
    reached = set(existing)
    while True:
        expanded = reached | set().union(*(edges[key] for key in reached))
        if expanded == reached:
            break
        reached = expanded
    candidates = []
    for name, symbol in sorted(affected):
        if not selected_function((name, symbol)):
            continue
        a = old.get(name, empty).functions.get(symbol)
        if a is None and (name, symbol) in reached:
            continue
        candidates.append((name, symbol))
    reasons = []
    if environment_changes and any(in_scope(name) for name in files):
        reasons.append(
            "Dependency or Python environment files changed: "
            + ", ".join(environment_changes)
        )
    for name in sorted(affected_modules):
        if in_scope(name):
            left, right = old.get(name, empty), new.get(name, empty)
            if left.error or right.error:
                reasons.append(f"{name}: {left.error or right.error}")
            elif name in changed and not left.functions and not right.functions:
                reasons.append(
                    f"{name}: changes outside supported module-level functions"
                )
    if len(candidates) > _MAX_COMPARISONS:
        reasons.append(f"Affected function budget exhausted (limit {_MAX_COMPARISONS})")
    for name, symbol in candidates[:_MAX_COMPARISONS]:
        result["comparisons"].append(
            compare_python_behavior(before, after, file=name, symbol=symbol)
        )
    states = {comparison["status"] for comparison in result["comparisons"]}
    result["reasons"] = reasons
    result["status"] = (
        "unknown"
        if reasons or "unknown" in states
        else "different"
        if "different" in states
        else "equivalent"
        if states
        else "unchanged"
    )
    return result
