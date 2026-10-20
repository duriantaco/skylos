import ast
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from skylos.rules.base import SkylosRule
from skylos.rules.quality._receivers import _bound_names, _scope_bindings
from skylos.rules.quality.class_size import (
    _declaration_calls,
    _is_declarative_class,
    _read_source,
)

try:
    from skylos_fast import analyze_coupling as _fast_analyze_coupling
except ImportError:
    _fast_analyze_coupling = None

BUILTIN_TYPES = frozenset(
    {
        "int",
        "str",
        "float",
        "bool",
        "bytes",
        "list",
        "dict",
        "set",
        "tuple",
        "frozenset",
        "type",
        "object",
        "None",
        "complex",
        "bytearray",
        "memoryview",
        "range",
        "slice",
        "property",
        "classmethod",
        "staticmethod",
        "Exception",
        "BaseException",
        "ValueError",
        "TypeError",
        "KeyError",
        "IndexError",
        "AttributeError",
        "RuntimeError",
        "StopIteration",
        "OSError",
        "IOError",
        "FileNotFoundError",
        "NotImplementedError",
    }
)

TYPING_WRAPPERS = frozenset(
    {
        "Optional",
        "Union",
        "List",
        "Dict",
        "Set",
        "Tuple",
        "FrozenSet",
        "Type",
        "ClassVar",
        "Final",
        "Literal",
        "Annotated",
        "Callable",
        "Iterator",
        "Iterable",
        "Generator",
        "AsyncIterator",
        "AsyncIterable",
        "Awaitable",
        "Coroutine",
        "Sequence",
        "MutableSequence",
        "Mapping",
        "MutableMapping",
        "Any",
    }
)

FRAMEWORK_EXPECTED_COUPLING = frozenset(
    {
        "models.Model",
        "models.Manager",
        "admin.ModelAdmin",
        "forms.ModelForm",
        "forms.Form",
        "views.View",
        "serializers.ModelSerializer",
        "serializers.Serializer",
        "viewsets.ModelViewSet",
        "viewsets.ViewSet",
        "permissions.BasePermission",
        "TestCase",
        "SimpleTestCase",
    }
)


def _extract_type_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    if node is None:
        return names

    if isinstance(node, ast.Name):
        if node.id not in BUILTIN_TYPES and node.id not in TYPING_WRAPPERS:
            names.add(node.id)

    elif isinstance(node, ast.Attribute):
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        full = ".".join(reversed(parts))
        names.add(full)

    elif isinstance(node, ast.Subscript):
        names.update(_extract_type_names(node.value))
        names.update(_extract_type_names(node.slice))

    elif isinstance(node, ast.Tuple):
        for elt in node.elts:
            names.update(_extract_type_names(elt))

    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        names.update(_extract_type_names(node.left))
        names.update(_extract_type_names(node.right))

    elif isinstance(node, ast.Constant) and node.value is None:
        pass

    elif isinstance(node, ast.List):
        for elt in node.elts:
            names.update(_extract_type_names(elt))

    return names


class _ClassInfo:
    __slots__ = (
        "name",
        "lineno",
        "col_offset",
        "bases",
        "decorators",
        "type_deps",
        "instantiation_deps",
        "attribute_deps",
        "import_deps",
        "decorator_deps",
        "protocol_abc_deps",
        "is_protocol",
        "is_abc",
        "is_dataclass",
        "methods",
        "node",
    )

    def __init__(self, name: str, lineno: int, col_offset: int):
        self.name = name
        self.lineno = lineno
        self.col_offset = col_offset
        self.bases: set[str] = set()
        self.decorators: set[str] = set()
        self.type_deps: set[str] = set()
        self.instantiation_deps: set[str] = set()
        self.attribute_deps: set[str] = set()
        self.import_deps: set[str] = set()
        self.decorator_deps: set[str] = set()
        self.protocol_abc_deps: set[str] = set()
        self.is_protocol = False
        self.is_abc = False
        self.is_dataclass = False
        self.methods: list[str] = []
        self.node = None


def _get_decorator_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return None


def _first_pass_collect(tree):
    classes: dict[str, _ClassInfo] = {}
    module_imports: dict[str, str] = {}
    known_classes: set[str] = set()
    counts = Counter(
        node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
    )

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            key = (
                node.name
                if counts[node.name] == 1
                else f"{node.name}@{node.lineno}:{node.col_offset}"
            )
            info = _ClassInfo(key, node.lineno, node.col_offset)
            info.node = node
            known_classes.add(key)

            for base in node.bases:
                for name in _extract_type_names(base):
                    info.bases.add(name)

            for dec in node.decorator_list:
                dec_name = _get_decorator_name(dec)
                if dec_name:
                    info.decorators.add(dec_name)
                    if dec_name in ("dataclass", "dataclasses.dataclass"):
                        info.is_dataclass = True

            for base in node.bases:
                if isinstance(base, ast.Name):
                    if base.id == "Protocol":
                        info.is_protocol = True
                    elif base.id in ("ABC", "ABCMeta"):
                        info.is_abc = True
                elif isinstance(base, ast.Attribute):
                    if base.attr == "Protocol":
                        info.is_protocol = True
                    elif base.attr in ("ABC", "ABCMeta"):
                        info.is_abc = True

            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    info.methods.append(item.name)

            classes[key] = info

        elif isinstance(node, ast.Import):
            for alias in node.names:
                module_imports[alias.asname or alias.name] = alias.name

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for alias in node.names:
                    module_imports[alias.asname or alias.name] = (
                        f"{node.module}.{alias.name}"
                    )

    return classes, module_imports, known_classes


def _carries_class_family(expression, name):
    """A decorator-style application still refers to its input source class.

    ``C = decorate(C)`` is the explicit spelling of ``@decorate class C``.
    Follow nested applications and keyword arguments, without inferring a
    family from a function's spelling or a string that happens to name C.
    """
    pending = [expression]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Name) and node.id == name:
            return True
        if isinstance(node, ast.Call):
            # Instantiating the class also retains its source family. Nested
            # decorator applications can carry that family through the callee.
            pending.append(node.func)
            pending.extend(node.args)
            for keyword in node.keywords:
                pending.append(keyword.value)
        elif isinstance(node, ast.Subscript):
            # A generic class alias keeps the source class behind its subscript.
            pending.append(node.value)
    return False


def _class_family_rebindings(statements):
    preserved = Counter()
    pending = list(statements)
    while pending:
        node = pending.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        targets = []
        value = None
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            targets = [node.target]
            value = node.value
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if isinstance(node, ast.AnnAssign) and value is None:
                # A type-only annotation does not replace the runtime class.
                preserved[target.id] += 1
            elif _carries_class_family(value, target.id):
                preserved[target.id] += 1
        pending.extend(ast.iter_child_nodes(node))
    return preserved


def _second_pass_analyze(tree, classes, known_classes):
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    identities = {info.node: name for name, info in classes.items()}
    scopes = (
        ast.Module,
        ast.ClassDef,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    bindings = {}
    definitions = {}
    globals_by_scope = {}
    first_iterators = {}
    binding_counts = {}
    family_rebindings = {}
    for scope in ast.walk(tree):
        if not isinstance(scope, scopes):
            continue
        if isinstance(scope, ast.Lambda):
            names = {
                argument.arg
                for argument in (
                    *scope.args.posonlyargs,
                    *scope.args.args,
                    *scope.args.kwonlyargs,
                )
            }
            names.update(
                argument.arg
                for argument in (scope.args.vararg, scope.args.kwarg)
                if argument is not None
            )
            first_iterators[scope] = {
                child
                for value in (*scope.args.defaults, *scope.args.kw_defaults)
                if value is not None
                for child in ast.walk(value)
            }
        elif isinstance(
            scope, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            names = {
                child.id
                for generator in scope.generators
                for child in ast.walk(generator.target)
                if isinstance(child, ast.Name)
            }
            first_iterators[scope] = set(ast.walk(scope.generators[0].iter))
        elif isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names = _bound_names(scope)
            outside = [
                *scope.decorator_list,
                *scope.args.defaults,
                *scope.args.kw_defaults,
                scope.returns,
            ]
            outside.extend(
                argument.annotation
                for argument in (
                    *scope.args.posonlyargs,
                    *scope.args.args,
                    *scope.args.kwonlyargs,
                )
            )
            first_iterators[scope] = {
                child
                for value in outside
                if value is not None
                for child in ast.walk(value)
            }
        else:
            names = _scope_bindings(scope).names
        bindings[scope] = names
        if isinstance(
            scope, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            binding_counts[scope] = _scope_bindings(scope).counts
            family_rebindings[scope] = _class_family_rebindings(scope.body)
        definitions[scope] = {}
        globals_by_scope[scope] = set()
    for statement in ast.walk(tree):
        if isinstance(statement, ast.Global):
            scope = parents.get(statement)
            while scope not in bindings and scope is not None:
                scope = parents.get(scope)
            if scope is not None:
                globals_by_scope[scope].update(statement.names)
    for child, identity in identities.items():
        parent = parents.get(child)
        while parent is not None and parent not in bindings:
            parent = parents.get(parent)
        if parent is not None:
            definitions[parent].setdefault(child.name, []).append(identity)

    def resolve(name, at):
        parts = name.split(".")
        scope = parents.get(at)
        while scope is not None and scope not in bindings:
            scope = parents.get(scope)
        function_scope = False
        identity = None
        while scope is not None:
            if scope in bindings:
                if at in first_iterators.get(scope, ()):
                    scope = parents.get(scope)
                    continue
                if parts[0] in globals_by_scope[scope] and scope is not tree:
                    scope = tree
                    continue
                if isinstance(
                    scope,
                    (
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                        ast.Lambda,
                        ast.ListComp,
                        ast.SetComp,
                        ast.DictComp,
                        ast.GeneratorExp,
                    ),
                ):
                    function_scope = True
                # Function bodies do not close over their class namespace.
                if not (function_scope and isinstance(scope, ast.ClassDef)):
                    candidates = definitions[scope].get(parts[0], ())
                    if candidates:
                        # Conditional/repeated definitions in ONE lexical
                        # binding still represent one dependency family.
                        # Other lexical scopes retain their own identities.
                        identity = candidates[-1]
                        if binding_counts[scope][parts[0]] - family_rebindings[scope][
                            parts[0]
                        ] != len(candidates):
                            # An ordinary rebinding is not the old class. For
                            # eager module/class expressions use their source
                            # prefix; deferred method bodies see the final scope.
                            statements = scope.body
                            if not function_scope:
                                statement = at
                                while parents.get(statement) is not scope:
                                    statement = parents.get(statement)
                                    if statement is None:
                                        return None
                                if statement in statements:
                                    statements = statements[
                                        : statements.index(statement) + 1
                                    ]
                            direct = [
                                candidate
                                for candidate in candidates
                                if classes[candidate].node in statements
                            ]
                            if not direct:
                                return None
                            identity = direct[-1]
                            declaration = classes[identity].node
                            suffix = statements[statements.index(declaration) + 1 :]
                            suffix_counts = _scope_bindings(
                                ast.Module(body=suffix, type_ignores=[])
                            ).counts[parts[0]]
                            retained_family = _class_family_rebindings(suffix)[parts[0]]
                            if suffix_counts > retained_family:
                                return None
                        break
                    if parts[0] in bindings[scope]:
                        return None
            scope = parents.get(scope)
        if identity is None:
            return None
        for part in parts[1:]:
            candidates = definitions[classes[identity].node].get(part, ())
            if not candidates:
                return None
            identity = candidates[-1]
        return identity

    def owned_nodes(node):
        pending = list(reversed(node.body))
        while pending:
            child = pending.pop()
            if isinstance(child, ast.ClassDef):
                continue
            yield child
            pending.extend(reversed(list(ast.iter_child_nodes(child))))

    for class_name, info in classes.items():
        node = info.node
        info.bases = {
            resolved
            for base in node.bases
            for name in _extract_type_names(base)
            if (resolved := resolve(name, node)) is not None and resolved != class_name
        }
        for child in owned_nodes(node):
            if isinstance(child, ast.AnnAssign) and child.annotation:
                for name in _extract_type_names(child.annotation):
                    resolved = resolve(name, child)
                    if resolved is not None and resolved != class_name:
                        info.type_deps.add(resolved)

            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.returns:
                    for name in _extract_type_names(child.returns):
                        resolved = resolve(name, child)
                        if resolved is not None and resolved != class_name:
                            info.type_deps.add(resolved)

                for arg in (
                    child.args.posonlyargs + child.args.args + child.args.kwonlyargs
                ):
                    if arg.annotation:
                        for name in _extract_type_names(arg.annotation):
                            resolved = resolve(name, child)
                            if resolved is not None and resolved != class_name:
                                info.type_deps.add(resolved)

                for dec in child.decorator_list:
                    dec_name = _get_decorator_name(dec)
                    resolved = resolve(dec_name, child) if dec_name else None
                    if resolved is not None and resolved != class_name:
                        info.decorator_deps.add(resolved)

            if isinstance(child, ast.Call):
                callee = _get_decorator_name(child.func)
                resolved = resolve(callee, child) if callee else None
                if resolved is not None and resolved != class_name:
                    info.instantiation_deps.add(resolved)

            if isinstance(child, ast.Attribute):
                if isinstance(child.value, ast.Name):
                    resolved = resolve(child.value.id, child)
                    if resolved is not None and resolved != class_name:
                        info.attribute_deps.add(resolved)


def _compute_metrics(classes, known_classes):
    coupling_graph: dict[str, dict[str, set[str]]] = {}

    for class_name, info in classes.items():
        dep_breakdown: dict[str, set[str]] = {
            "inheritance": info.bases & known_classes,
            "type_hints": info.type_deps & known_classes,
            "instantiation": info.instantiation_deps,
            "attribute_access": info.attribute_deps,
            "decorator": info.decorator_deps,
            "protocol_abc": set(),
        }

        coupling_graph[class_name] = dep_breakdown

    afferent: dict[str, set[str]] = {name: set() for name in classes}
    for class_name, breakdown in coupling_graph.items():
        for dep_type, deps in breakdown.items():
            for dep in deps:
                if dep in afferent:
                    afferent[dep].add(class_name)

    result_classes: dict[str, dict[str, Any]] = {}
    for class_name, info in classes.items():
        breakdown = coupling_graph.get(class_name, {})
        all_efferent = set()
        for deps in breakdown.values():
            all_efferent.update(deps)

        ce = len(all_efferent)
        ca = len(afferent.get(class_name, set()))
        total = ce + ca

        result_classes[class_name] = {
            "efferent_coupling": ce,
            "afferent_coupling": ca,
            "total_coupling": total,
            "efferent_classes": sorted(all_efferent),
            "afferent_classes": sorted(afferent.get(class_name) or set()),
            "breakdown": {k: sorted(v) for k, v in breakdown.items()},
            "instability": ce / (ca + ce) if (ca + ce) > 0 else 0.0,
            "is_protocol": info.is_protocol,
            "is_abc": info.is_abc,
            "is_dataclass": info.is_dataclass,
            "line": info.lineno,
            "methods": info.methods,
        }

    coupling_graph_out = {}
    for name, bd in coupling_graph.items():
        combined = set()
        for values in bd.values():
            combined.update(values)
        coupling_graph_out[name] = sorted(combined)

    return {
        "classes": result_classes,
        "coupling_graph": coupling_graph_out,
    }


def analyze_coupling(tree: ast.AST, filename: str) -> dict[str, Any]:
    classes, module_imports, known_classes = _first_pass_collect(tree)
    _second_pass_analyze(tree, classes, known_classes)
    return _compute_metrics(classes, known_classes)


def _needs_scope_resolution(tree):
    """Older native analyzers need Python's lexical proof for these cases."""
    classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    names = {node.name for node in classes}
    if len(names) != len(classes) or any(node not in tree.body for node in classes):
        return True
    module_counts = _scope_bindings(tree).counts
    if any(module_counts[name] != 1 for name in names):
        return True
    for node in ast.walk(tree):
        if isinstance(
            node,
            (
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
                ast.Global,
                ast.Nonlocal,
            ),
        ):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _bound_names(node) & names:
                return True
            if any(
                argument.annotation is not None for argument in node.args.posonlyargs
            ):
                return True
        if isinstance(node, ast.ClassDef) and _scope_bindings(node).names & names:
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in names:
                return True
    return False


def _normalize_coupling_result(result: dict[str, Any]) -> dict[str, Any]:
    """Remove sibling edges produced by older optional native extensions.

    Sharing an abstract base establishes two inheritance edges to that base,
    not a dependency between its subclasses. Keep the legacy breakdown key
    for consumers, and retain any sibling independently referenced by a real
    inheritance, type, call, decorator or attribute edge.
    """
    classes = result.get("classes", {})
    if not any(
        info.get("breakdown", {}).get("protocol_abc") for info in classes.values()
    ):
        return result

    graph = {}
    afferent = {name: set() for name in classes}
    for name, info in classes.items():
        breakdown = info.get("breakdown", {})
        breakdown["protocol_abc"] = []
        dependencies = set().union(*(set(values) for values in breakdown.values()))
        graph[name] = sorted(dependencies)
        for dependency in dependencies:
            if dependency in afferent:
                afferent[dependency].add(name)

    for name, info in classes.items():
        ce, ca = len(graph[name]), len(afferent[name])
        info.update(
            efferent_classes=graph[name],
            afferent_classes=sorted(afferent[name]),
            efferent_coupling=ce,
            afferent_coupling=ca,
            total_coupling=ce + ca,
            instability=ce / (ce + ca) if ce + ca else 0.0,
        )
    result["coupling_graph"] = graph
    return result


class CBORule(SkylosRule):
    rule_id = "SKY-Q701"
    name = "Coupling Between Objects"

    def __init__(self, low_threshold=4, high_threshold=8):
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold
        self._file_cache: dict[str, dict] = {}

    def _get_file_analysis(self, context: dict) -> dict:
        filename = context.get("filename", "")
        if filename not in self._file_cache:
            self._file_cache[filename] = {}
        return self._file_cache[filename]

    def visit_node(
        self, node: ast.AST, context: dict[str, Any]
    ) -> Optional[list[dict[str, Any]]]:
        if isinstance(node, ast.Module):
            # One rule instance may be reused across scans of edited files.
            self._file_cache.pop(context.get("filename", ""), None)
            return None
        if not isinstance(node, ast.ClassDef) or _is_declarative_class(node):
            return None

        filename = context.get("filename", "")

        if filename not in self._file_cache:
            self._file_cache[filename] = {"_analyzed": False}

        file_data = self._file_cache[filename]
        if not file_data.get("_analyzed"):
            file_data["_analyzed"] = True
            try:
                source = context.get("source")
                if not isinstance(source, str):
                    source = _read_source(filename, context.get("project_root"))
                if source is None:
                    return None
                tree = ast.parse(source)
                file_data["_declaration_calls"] = _declaration_calls(tree)
                if _fast_analyze_coupling is not None:
                    result = _normalize_coupling_result(
                        _fast_analyze_coupling(source, filename)
                    )
                    if _needs_scope_resolution(tree):
                        result = analyze_coupling(tree, filename)
                else:
                    result = analyze_coupling(tree, filename)
                file_data.update(result)
            except Exception:
                return None

        classes = file_data.get("classes", {})
        class_data = classes.get(node.name) or classes.get(
            f"{node.name}@{node.lineno}:{node.col_offset}"
        )
        if not class_data:
            return None
        if _is_declarative_class(
            node, file_data.get("_declaration_calls", frozenset())
        ):
            return None

        ce = class_data["efferent_coupling"]

        if ce <= self.low_threshold:
            return None

        if ce > self.high_threshold:
            severity = "HIGH"
        elif ce > self.low_threshold:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        breakdown_parts = []
        for dep_type, deps in class_data["breakdown"].items():
            if deps:
                breakdown_parts.append(f"{dep_type}={len(deps)}")
        if breakdown_parts:
            breakdown_str = ", ".join(breakdown_parts)
        else:
            breakdown_str = "none"

        return [
            {
                "rule_id": self.rule_id,
                "kind": "quality",
                "severity": severity,
                "type": "class",
                "name": node.name,
                "simple_name": node.name,
                "value": ce,
                "threshold": self.low_threshold,
                "efferent_coupling": ce,
                "afferent_coupling": class_data["afferent_coupling"],
                "coupling_scope": "file",
                "afferent_coupling_scope": "file",
                "instability": round(class_data["instability"], 3),
                "coupling_breakdown": breakdown_str,
                "message": (
                    f"Class '{node.name}' has high coupling within this file "
                    f"(Ce={ce}, file-local Ca={class_data['afferent_coupling']}). "
                    f"Breakdown: {breakdown_str}. Consider reducing dependencies."
                ),
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
