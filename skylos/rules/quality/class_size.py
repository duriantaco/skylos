import ast
from pathlib import Path

from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    read_text_no_symlink,
)
from skylos.rules.base import SkylosRule
from skylos.rules.quality._test_code import (
    is_collected_test_class,
    is_python_test_file,
)
from skylos.rules.quality._pytest_collection import (
    collected_pytest_classes,
    is_collected_pytest_file,
    pytest_collection_config,
)
from skylos.rules.quality._overload_groups import redundant_overload_definitions
from skylos.rules.quality._provider_context import project_local_provider
from skylos.rules.quality._code_lines import code_lines
from skylos.rules.quality._receivers import (
    _scope_bindings,
    class_method_nodes,
    context_method_kinds,
    method_receiver,
    receiver_usage,
    resolve_method_kinds,
)
from skylos.rules.quality._scope import (
    is_non_production_python,
    is_sample_or_build_python,
)

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_BLOCKS = (ast.stmt, ast.excepthandler, ast.match_case)
_DECLARATION_FACTORIES = {
    "pydantic": frozenset({"Field"}),
    "dataclasses": frozenset({"field"}),
    "attrs": frozenset({"field"}),
    "attr": frozenset({"field", "ib", "attrib"}),
    "enum": frozenset({"auto"}),
}


def _dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _declaration_calls(module, *, filename=None, project_root=None):
    """Only unchanged imports of known field/enum declaration factories."""
    bindings = _scope_bindings(module)
    candidates = {}
    for item in module.body:
        if isinstance(item, ast.ImportFrom) and not item.level:
            if any(alias.name == "*" for alias in item.names):
                return frozenset()
            if item.module not in _DECLARATION_FACTORIES or project_local_provider(
                item.module, filename=filename, project_root=project_root
            ):
                continue
            for alias in item.names:
                if alias.name in _DECLARATION_FACTORIES.get(item.module, ()):
                    local = alias.asname or alias.name
                    candidates[local] = local
        elif isinstance(item, ast.Import):
            for alias in item.names:
                if alias.name in _DECLARATION_FACTORIES and not project_local_provider(
                    alias.name, filename=filename, project_root=project_root
                ):
                    local = alias.asname or alias.name
                    for factory in _DECLARATION_FACTORIES[alias.name]:
                        candidates[f"{local}.{factory}"] = local
    mutated = {
        _dotted_name(child.value)
        for child in ast.walk(module)
        if isinstance(child, ast.Attribute)
        and isinstance(child.ctx, (ast.Store, ast.Del))
    }
    shadowed = {
        child.id
        for child in ast.walk(module)
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del))
    }
    shadowed.update(
        child.arg for child in ast.walk(module) if isinstance(child, ast.arg)
    )
    return frozenset(
        name
        for name, local in candidates.items()
        if bindings.counts[local] == 1
        and local not in mutated
        and local not in shadowed
    )


def _declaration_body(body):
    return [
        item
        for item in body
        if not (
            isinstance(item, ast.Expr)
            and isinstance(item.value, ast.Constant)
            and isinstance(item.value.value, str)
        )
    ]


def _stub_body(body):
    body = _declaration_body(body)
    return bool(body) and all(
        isinstance(item, ast.Pass)
        or (
            isinstance(item, ast.Expr)
            and isinstance(item.value, ast.Constant)
            and item.value.value is Ellipsis
        )
        for item in body
    )


def _plain_field_value(value, declaration_calls):
    """A declaration expression, with no embedded implementation scope."""
    return value is None or not any(
        isinstance(
            child,
            (
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
                ast.Await,
                ast.Yield,
                ast.YieldFrom,
                ast.NamedExpr,
            ),
        )
        or isinstance(child, ast.Call)
        and _dotted_name(child.func) not in declaration_calls
        for child in ast.walk(value)
    )


def _declaration_field(value, declaration_calls):
    # A Name/Attribute can hold an arbitrary descriptor. Only literal values
    # or unchanged imports of actual field factories establish a data field.
    return (
        value is None
        or _literal_value(value)
        or (
            isinstance(value, ast.Call)
            and _dotted_name(value.func) in declaration_calls
            and _plain_field_value(value, declaration_calls)
        )
    )


def _record_initializer(method):
    """A constructor that only stores supplied fields or literal defaults."""
    if method.name != "__init__" or method.decorator_list:
        return False
    args = (*method.args.posonlyargs, *method.args.args)
    if not args:
        return False
    receiver = args[0].arg
    parameters = {arg.arg for arg in (*args[1:], *method.args.kwonlyargs)}
    body = _declaration_body(method.body)
    if not body:
        return False
    for statement in body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            return False
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if not all(
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == receiver
            and not _is_dunder(target.attr)
            for target in targets
        ):
            return False
        value = statement.value
        if not (
            isinstance(value, ast.Name)
            and value.id in parameters
            or _literal_value(value)
        ):
            return False
    return True


def _is_declarative_class(node, declaration_calls=frozenset()):
    """Source-only schemas, interfaces and plain records have no behavior to split.

    Unknown decorators, metaclasses, branches and real method bodies retain the
    original checks. Inherited behavior is not charged to a declaration here.
    """
    if (
        node.decorator_list
        or node.keywords
        or any(not _plain_field_value(base, frozenset()) for base in node.bases)
    ):
        return False
    local_names = _scope_bindings(node).names
    declaration_calls = frozenset(
        name for name in declaration_calls if name.split(".", 1)[0] not in local_names
    )
    for statement in _declaration_body(node.body):
        if isinstance(statement, (ast.Pass, ast.Import, ast.ImportFrom)):
            continue
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is Ellipsis
        ):
            continue
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            if all(
                isinstance(target, ast.Name) for target in targets
            ) and _declaration_field(statement.value, declaration_calls):
                continue
        if isinstance(statement, _FUNCTIONS) and not statement.decorator_list:
            if _stub_body(statement.body) or (
                not node.bases and _record_initializer(statement)
            ):
                continue
        if isinstance(statement, ast.ClassDef) and _is_declarative_class(
            statement, declaration_calls
        ):
            continue
        return False
    return True


def _literal_value(value):
    if isinstance(value, ast.Constant):
        return True
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return all(_literal_value(item) for item in value.elts)
    if isinstance(value, ast.Dict):
        return all(
            key is not None and _literal_value(key) and _literal_value(item)
            for key, item in zip(value.keys, value.values)
        )
    return (
        isinstance(value, ast.UnaryOp)
        and isinstance(value.op, (ast.UAdd, ast.USub))
        and isinstance(value.operand, ast.Constant)
        and isinstance(value.operand.value, (int, float, complex))
    )


def _implementation_lines(module, source, declaration_calls=frozenset()):
    """Keep real implementation, collapsing only source-proven declarations.

    A multiline literal is one data declaration, rather than hundreds of lines
    of executable logic. Scalar assignment lines keep their existing weight.
    """
    lines = code_lines(module, source)
    removed = set()
    pending = list(module.body)
    while pending:
        item = pending.pop()
        declaration = isinstance(item, ast.ClassDef) and _is_declarative_class(
            item, declaration_calls
        )
        literal = (
            isinstance(item, (ast.Assign, ast.AnnAssign))
            and isinstance(item.value, (ast.List, ast.Tuple, ast.Set, ast.Dict))
            and _literal_value(item.value)
        )
        if declaration:
            removed.update(range(item.lineno, item.end_lineno + 1))
        elif literal:
            # Retain the closing line too: another statement may follow a
            # literal on that line after a semicolon.
            removed.update(range(item.lineno + 1, item.end_lineno))
        elif not isinstance(item, _FUNCTIONS):
            # A class may contain both real methods and literal catalogs.
            # Its namespace does not turn the same literal assignment into
            # implementation work. Keep method bodies intact while applying
            # the existing data-only proof to statements in the class body.
            pending.extend(
                child
                for child in ast.iter_child_nodes(item)
                if isinstance(child, _BLOCKS)
            )
    return len(lines - removed)


def _read_source(filename: str, project_root=None) -> str | None:
    if not filename:
        return None

    try:
        if project_root is None:
            return read_text_no_symlink(filename, max_bytes=2_000_000, errors="ignore")
        return read_project_text_no_symlink(
            project_root, filename, max_bytes=2_000_000, errors="ignore"
        )
    except (OSError, ValueError, RuntimeError):
        return None


def _module_definitions(
    module: ast.Module, redundant=frozenset(), declaration_calls=frozenset()
) -> tuple[int, int]:
    """Classes, and functions or methods, defined outside any function body.

    A function's nested helpers and local classes belong to that function,
    not to the file's surface.
    """
    classes = functions = 0
    pending = list(module.body)
    while pending:
        child = pending.pop()
        if isinstance(child, _FUNCTIONS):
            functions += child not in redundant
        elif isinstance(child, ast.ClassDef):
            if _is_declarative_class(child, declaration_calls):
                continue
            classes += 1
            pending.extend(child.body)
        else:
            pending.extend(
                item
                for item in ast.iter_child_nodes(child)
                if isinstance(item, _BLOCKS)
            )
    return classes, functions


def _is_dunder(name: str) -> bool:
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _base_name(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_test_class(node: ast.ClassDef, class_patterns=("Test",)) -> bool:
    return is_collected_test_class(
        node.name,
        [_base_name(base) for base in node.bases],
        method_names=[
            item.name
            for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        ],
        opted_out=_opts_out_of_collection(node),
        class_patterns=class_patterns,
    )


def _overload_stubs(module: ast.Module) -> set[ast.AST]:
    """Import-proven typing signatures with a real local implementation.

    A rebound module import or class-local decorator name leaves the metric
    unchanged. Property getters/setters still count as before.
    """
    bindings = _scope_bindings(module)
    aliases = {}
    pending = list(module.body)
    while pending:
        node = pending.pop()
        if (
            isinstance(node, ast.ImportFrom)
            and not node.level
            and node.module in {"typing", "typing_extensions"}
        ):
            aliases.update(
                {
                    alias.asname or alias.name: "function"
                    for alias in node.names
                    if alias.name == "overload"
                }
            )
        elif isinstance(node, ast.Import):
            aliases.update(
                {
                    alias.asname or alias.name: "module"
                    for alias in node.names
                    if alias.name in {"typing", "typing_extensions"}
                }
            )
        elif not isinstance(node, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
            pending.extend(ast.iter_child_nodes(node))
    aliases = {
        name: kind for name, kind in aliases.items() if bindings.counts[name] == 1
    }
    mutated = {
        child.value.id
        for child in ast.walk(module)
        if isinstance(child, ast.Attribute)
        and isinstance(child.ctx, (ast.Store, ast.Del))
        and isinstance(child.value, ast.Name)
    }
    result = set()
    for cls in module.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        class_aliases = {
            name: kind
            for name, kind in aliases.items()
            if name not in _scope_bindings(cls).names and name not in mutated
        }
        methods = list(class_method_nodes(cls))
        decorated = {
            method
            for method in methods
            if any(
                (
                    isinstance(decorator, ast.Name)
                    and class_aliases.get(decorator.id) == "function"
                )
                or (
                    isinstance(decorator, ast.Attribute)
                    and decorator.attr == "overload"
                    and isinstance(decorator.value, ast.Name)
                    and class_aliases.get(decorator.value.id) == "module"
                )
                for decorator in method.decorator_list
            )
        }
        implementations = {method.name for method in methods if method not in decorated}
        for method in decorated:
            body = method.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                body = body[1:]
            if (
                method.name in implementations
                and len(body) == 1
                and (
                    isinstance(body[0], ast.Pass)
                    or (
                        isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and body[0].value.value is Ellipsis
                    )
                )
            ):
                result.add(method)
    return result


def _opts_out_of_collection(node: ast.ClassDef) -> bool:
    """``__test__ = False`` in the class body."""
    for item in node.body:
        targets = (
            item.targets
            if isinstance(item, ast.Assign)
            else [getattr(item, "target", None)]
        )
        value = getattr(item, "value", None)
        if (
            isinstance(item, (ast.Assign, ast.AnnAssign))
            and any(isinstance(t, ast.Name) and t.id == "__test__" for t in targets)
            and isinstance(value, ast.Constant)
            and value.value is False
        ):
            return True
    return False


class GodFileRule(SkylosRule):
    rule_id = "SKY-Q502"
    name = "God File"

    def __init__(
        self,
        max_lines=500,
        max_definitions=40,
        max_top_level_definitions=25,
    ):
        self.max_lines = max_lines
        self.max_definitions = max_definitions
        self.max_top_level_definitions = max_top_level_definitions

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename", "")
        if is_non_production_python(filename, context.get("project_root")):
            return None
        source = context.get("source")
        if not isinstance(source, str):
            source = _read_source(filename, context.get("project_root"))
        code_line_count = len(code_lines(node, source))
        declaration_calls = _declaration_calls(
            node, filename=filename, project_root=context.get("project_root")
        )
        implementation_line_count = _implementation_lines(
            node, source, declaration_calls
        )

        redundant = redundant_overload_definitions(node, filename=filename)
        top_level_definitions = sum(
            1
            for item in node.body
            if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and item not in redundant
            and not (
                isinstance(item, ast.ClassDef)
                and _is_declarative_class(item, declaration_calls)
            )
        )
        class_count, function_count = _module_definitions(
            node, redundant, declaration_calls
        )
        total_definitions = class_count + function_count

        metrics = [
            (
                "code_lines",
                implementation_line_count,
                self.max_lines,
                (
                    "implementation code lines, excluding literal data and declarations"
                    if implementation_line_count != code_line_count
                    else "code lines, not counting blank, comment or docstring lines"
                ),
            ),
            (
                "total_definitions",
                total_definitions,
                self.max_definitions,
                "classes, functions and methods outside function bodies",
            ),
            (
                "top_level_definitions",
                top_level_definitions,
                self.max_top_level_definitions,
                "top-level definitions",
            ),
        ]
        violations = [
            metric for metric in metrics if metric[2] > 0 and metric[1] > metric[2]
        ]
        if not violations:
            return None

        primary_metric, value, threshold, _label = max(
            violations,
            key=lambda metric: metric[1] / metric[2],
        )
        worst_ratio = value / threshold if threshold else 1.0
        severity = "HIGH" if worst_ratio >= 1.5 or len(violations) >= 2 else "MEDIUM"

        basename = Path(filename).name if filename else "<module>"
        module_name = context.get("mod") or basename
        violation_summary = ", ".join(
            f"{actual} {label} (limit: {limit})"
            for _metric, actual, limit, label in violations
        )

        return [
            {
                "rule_id": self.rule_id,
                "kind": "quality",
                "severity": severity,
                "type": "module",
                "name": module_name,
                "simple_name": basename,
                "value": value,
                "threshold": threshold,
                "metric": primary_metric,
                "code_lines": code_line_count,
                "implementation_code_lines": implementation_line_count,
                "total_definitions": total_definitions,
                "top_level_definitions": top_level_definitions,
                "class_count": class_count,
                "function_count": function_count,
                "message": (
                    f"File '{basename}' is a god file candidate: {violation_summary}. "
                    "Consider splitting it by responsibility."
                ),
                "file": filename,
                "basename": basename,
                "line": 1,
                "col": 0,
            }
        ]


class GodClassRule(SkylosRule):
    """Too many methods or instance attributes for one class.

    Dunder methods implement protocols (``__len__``, ``__getitem__``, ...);
    a mapping or sequence type needs them all, so they are not counted
    toward the method limit. Import-proven overload signatures with a local
    implementation do not add runtime methods either.
    """

    rule_id = "SKY-Q501"
    name = "God Class"

    def __init__(self, max_methods=20, max_attributes=15):
        self.max_methods = max_methods
        self.max_attributes = max_attributes
        self._method_kinds = {}
        self._skip_file = False
        self._pytest_config = None
        self._collected_file = False
        self._collected_classes = set()
        self._overload_stubs = set()
        self._declaration_calls = frozenset()

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self._declaration_calls = _declaration_calls(
                node,
                filename=context.get("filename"),
                project_root=context.get("project_root"),
            )
            self._pytest_config = pytest_collection_config(context.get("project_root"))
            self._collected_file = is_collected_pytest_file(
                context.get("filename", ""),
                context.get("project_root"),
                context.get("source"),
            )
            self._collected_classes = (
                collected_pytest_classes(node, self._pytest_config)
                if self._pytest_config is not None
                else set()
            )
            self._overload_stubs = _overload_stubs(node)
            self._skip_file = is_sample_or_build_python(
                context.get("filename"), context.get("project_root")
            )
            self._method_kinds = (
                {} if self._skip_file else context_method_kinds(node, context)
            )
            return None
        if self._skip_file or not isinstance(node, ast.ClassDef):
            return None
        if _is_declarative_class(node, self._declaration_calls):
            return None

        # A test class groups many cases (and their fixtures) by design;
        # its size is not a design defect.
        if self._collected_file and node in self._collected_classes:
            return None
        # Keep the existing convention-based branch alongside configured scope.
        class_patterns = (
            self._pytest_config.python_classes
            if self._pytest_config is not None
            else ("Test",)
        )
        if _is_test_class(node, class_patterns) and is_python_test_file(
            context.get("filename", ""),
            context.get("project_root"),
            context.get("source"),
        ):
            return None

        method_count = 0
        dunder_count = 0
        attributes = set()

        kinds = self._method_kinds or resolve_method_kinds(node)
        for item in class_method_nodes(node):
            if item in self._overload_stubs:
                continue
            if _is_dunder(item.name):
                dunder_count += 1
            else:
                method_count += 1

            if method_receiver(item, instance_only=True, kinds=kinds) is not None:
                attributes.update(receiver_usage(item, kinds=kinds).writes)

        findings = []

        if method_count > self.max_methods:
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": "MEDIUM",
                    "type": "class",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": method_count,
                    "threshold": self.max_methods,
                    "dunder_methods": dunder_count,
                    "message": (
                        f"Class '{node.name}' has {method_count} methods "
                        f"(limit: {self.max_methods}); dunder protocol methods "
                        "are not counted. Consider splitting into smaller classes."
                    ),
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

        if len(attributes) > self.max_attributes:
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": "MEDIUM",
                    "type": "class",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": len(attributes),
                    "threshold": self.max_attributes,
                    "message": f"Class '{node.name}' has {len(attributes)} attributes (limit: {self.max_attributes}). Consider splitting into smaller classes.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

        return findings if findings else None
