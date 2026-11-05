"""Static Robot Framework Library/Variables imports, without importing Robot.

Only settings in Robot data files supply providers. Resolution is restricted to
the importing file's directory and project source roots; a matching basename
somewhere else in the project is not evidence of a Python import.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from skylos.core.file_discovery import discover_source_files
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.deadcode._reachability_bindings import bound_names
from skylos.deadcode.python_ast import ParsedPythonFile

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_DECO = "robot.api.deco."
_STANDARD_LIBRARIES = {
    "BuiltIn",
    "Collections",
    "DateTime",
    "Dialogs",
    "OperatingSystem",
    "Process",
    "Remote",
    "Screenshot",
    "String",
    "Telnet",
    "XML",
}
_DYNAMIC_METHODS = {
    "get_keyword_names",
    "getKeywordNames",
    "run_keyword",
    "runKeyword",
    "get_keyword_arguments",
    "getKeywordArguments",
    "get_keyword_documentation",
    "getKeywordDocumentation",
    "get_keyword_tags",
    "getKeywordTags",
    "get_keyword_types",
    "getKeywordTypes",
}
_LISTENER_METHODS = {
    "close",
    "log_message",
    "message",
    "library_import",
    "resource_import",
    "variables_import",
    "output_file",
    "log_file",
    "report_file",
    "xunit_file",
    "debug_file",
} | {
    f"{phase}_{event}"
    for phase in ("start", "end")
    for event in (
        "suite",
        "test",
        "keyword",
        "user_keyword",
        "library_keyword",
        "invalid_keyword",
        "for",
        "for_iteration",
        "while",
        "while_iteration",
        "group",
        "if",
        "if_branch",
        "try",
        "try_branch",
        "var",
        "break",
        "continue",
        "return",
        "error",
        "body_item",
    )
}
_VARIABLE = re.compile(r"\$\{([^}]+)\}")
_VALUE_VARIABLE = re.compile(r"[$@&]\{([^}]+)\}\s*=?\Z")
_EXTENDED_VARIABLE = re.compile(r"[$@&]\{([^{}\n]*)\}")
_LIBRARY_OPTIONS = (
    "scope",
    "version",
    "converters",
    "doc_format",
    "listener",
    "auto_keywords",
)
_UNKNOWN = object()
_UNSET = object()


def _normalize(name: str) -> str:
    return re.sub(r"[\s_]", "", name).casefold()


def _setting_name(name: str) -> str:
    # Settings and section names retain internal spaces and underscores. Only
    # variable/keyword names use Robot's underscore-insensitive normalization.
    return " ".join(name.split()).casefold()


@dataclass
class _Document:
    path: Path
    imports: list[tuple[str, str]] = field(default_factory=list)
    variables: dict[str, str | None] = field(default_factory=dict)
    has_sections: bool = False
    method_calls: set[tuple[str, str]] = field(default_factory=set)
    written_variables: set[str] = field(default_factory=set)
    variable_names: set[str] = field(default_factory=set)
    guard_names: set[str] = field(default_factory=set)


def _method_references(text):
    for match in _EXTENDED_VARIABLE.finditer(text):
        offset = match.start()
        while offset and text[offset - 1] == "\\":
            offset -= 1
        if (match.start() - offset) % 2:
            continue
        base, separator, expression = match[1].partition(".")
        if not separator or not re.fullmatch(r"[\w\s]+", base):
            continue
        try:
            value = ast.parse("_robot_value." + expression.strip(), mode="eval").body
        except (SyntaxError, ValueError, RecursionError):
            continue
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id == "_robot_value"
        ):
            yield _normalize(base), value.func.attr


def _document(root: Path, path: Path, *, guard_values=None) -> _Document | None:
    text = read_project_text_no_symlink(root, path, max_bytes=512_000)
    if text is None:
        return None
    document = _Document(path)
    section = ""
    pending: list[str] = []
    frames = []
    condition_writes = set()
    suite_writes = set()

    def scalar(value, depth=0):
        if depth > 16:
            return _UNKNOWN
        if not isinstance(value, str):
            return (
                value
                if isinstance(value, (bool, int, float, complex)) or value is None
                else _UNKNOWN
            )
        value = value.strip()
        if len(value) > 512:
            return _UNKNOWN
        if value.startswith("${") and value.endswith("}"):
            value = value[2:-1]
            normalized = _normalize(value)
            document.guard_names.add(normalized)
            if guard_values is None or normalized in condition_writes:
                return _UNKNOWN
            if normalized in guard_values:
                return scalar(guard_values[normalized], depth + 1)
            if "*" in guard_values:
                return _UNKNOWN
            if normalized in document.variable_names:
                return _UNKNOWN
            if normalized in {"true", "false", "none"}:
                return normalized == "true" if normalized != "none" else None
        try:
            literal = ast.literal_eval(value)
        except (ValueError, TypeError, SyntaxError, RecursionError):
            return _UNKNOWN
        return (
            literal
            if isinstance(literal, (bool, int, float, complex)) or literal is None
            else _UNKNOWN
        )

    def truth(value):
        literal = scalar(value)
        return None if literal is _UNKNOWN else bool(literal)

    def empty_sequence(value):
        match = re.fullmatch(r"[@&]\{([^{}]+)\}", value)
        if match is None:
            return False
        name = _normalize(match[1])
        document.guard_names.add(name)
        if guard_values is None:
            return False
        if name in condition_writes:
            return False
        if name in guard_values:
            value = guard_values[name]
            return isinstance(value, (list, tuple, dict, set, frozenset)) and not value
        if "*" in guard_values:
            return False
        return name == "empty" and name not in document.variable_names

    def written(cell, persistent=False, setter=False):
        if setter:
            # BuiltIn setters accept both $name and escaped ${name}. Keep
            # this conversion local to write arguments, never ordinary cells.
            if cell.startswith("\\"):
                cell = cell[1:]
            if len(cell) > 1 and cell[0] in "$@&" and cell[1] != "{":
                cell = f"{cell[0]}{{{cell[1:]}}}"
        if match := _VALUE_VARIABLE.fullmatch(cell):
            name = match[1].split(":", 1)[0]
            # An extended assignment can replace an object's method too.
            if re.fullmatch(r"[\w\s]+(?:\.[\w]+)?", name):
                name = _normalize(name.split(".", 1)[0])
                document.written_variables.add(name)
                condition_writes.add(name)
                if persistent:
                    suite_writes.add(name)

    def inline_if(cells, enabled):
        selected = []
        offset = 0
        remaining = enabled
        while offset < len(cells):
            token = cells[offset]
            if token == "ELSE":
                if remaining:
                    selected.extend(cells[offset + 1 :])
                break
            if token not in {"IF", "ELSE IF"} or offset + 1 >= len(cells):
                break
            condition = cells[offset + 1]
            end = next(
                (
                    i
                    for i in range(offset + 2, len(cells))
                    if cells[i] in {"ELSE", "ELSE IF"}
                ),
                len(cells),
            )
            value = truth(condition)
            if remaining:
                selected.append(condition)
                if value is not False:
                    selected.extend(cells[offset + 2 : end])
            remaining = remaining and value is not True
            offset = end
        return selected

    def step_cells(cells):
        """Native uppercase controls only; unknown predicates stay possible."""
        enabled = not frames or frames[-1]["active"]
        token = cells[0]
        if token == "END":
            if frames:
                frames.pop()
            return []
        if token in {"ELSE", "ELSE IF"}:
            if not frames or frames[-1]["kind"] != "IF":
                return []
            frame = frames[-1]
            possible = frame["parent"] and frame["remaining"]
            value = truth(cells[1]) if token == "ELSE IF" and len(cells) > 1 else True
            frame["active"] = possible and value is not False
            frame["remaining"] = frame["remaining"] and value is not True
            return cells[1:] if possible else []
        offset = 0
        while offset < len(cells) and _VALUE_VARIABLE.fullmatch(cells[offset]):
            offset += 1
        if offset and offset < len(cells) and cells[offset] == "IF":
            if enabled:
                for assignment in cells[:offset]:
                    written(assignment)
            return inline_if(cells[offset:], enabled)
        if token == "IF" and len(cells) > 2:
            return inline_if(cells, enabled)
        if token in {"IF", "WHILE"}:
            condition = truth(cells[1]) if len(cells) > 1 else None
            frames.append(
                {
                    "kind": token,
                    "parent": enabled,
                    "active": enabled and condition is not False,
                    "remaining": condition is not True,
                }
            )
            # Conditions are evaluated before their branch, not inside it.
            return cells[1:] if enabled else []
        if token == "FOR":
            position = next(
                (
                    i
                    for i, cell in enumerate(cells)
                    if cell in {"IN", "IN RANGE", "IN ZIP", "IN ENUMERATE"}
                ),
                None,
            )
            empty = False
            if position is not None:
                arguments = cells[position + 1 :]
                if cells[position] == "IN":
                    empty = not arguments or all(
                        empty_sequence(arg) for arg in arguments
                    )
                elif cells[position] in {"IN ZIP", "IN ENUMERATE"}:
                    sequences = [
                        arg
                        for arg in arguments
                        if not re.match(r"(?:mode|start|fill)=", arg)
                    ]
                    empty = bool(sequences) and all(
                        empty_sequence(arg) for arg in sequences
                    )
                elif cells[position] == "IN RANGE" and 1 <= len(arguments) <= 3:
                    try:
                        numbers = [scalar(arg) for arg in arguments]
                        if all(isinstance(number, (int, float)) for number in numbers):
                            start, stop, stride = (
                                (0, numbers[0], 1)
                                if len(numbers) == 1
                                else (
                                    numbers[0],
                                    numbers[1],
                                    numbers[2] if len(numbers) == 3 else 1,
                                )
                            )
                            empty = (
                                not stride or start >= stop
                                if stride >= 0
                                else start <= stop
                            )
                    except (ValueError, TypeError, SyntaxError, RecursionError):
                        pass
                if enabled and not empty:
                    for variable in cells[1:position]:
                        written(variable)
            frames.append(
                {"kind": "FOR", "parent": enabled, "active": enabled and not empty}
            )
            return cells[1:] if enabled else []
        if token in {"TRY", "GROUP"}:
            # Even blocks with unknown outcomes consume their own END, rather
            # than accidentally ending an enclosing constant-dead branch.
            frames.append({"kind": token, "parent": enabled, "active": enabled})
            return cells[1:] if enabled else []
        return cells if enabled else []

    def flush():
        if section in {"settings", "setting"} and len(pending) > 1:
            kind = _setting_name(pending[0])
            if kind in {"library", "variables", "resource"}:
                document.imports.append((kind, pending[1]))
        elif section in {"variables", "variable"} and pending:
            if name := _VALUE_VARIABLE.fullmatch(pending[0]):
                document.variable_names.add(_normalize(name[1].split(":", 1)[0]))
            if match := _VARIABLE.fullmatch(pending[0]):
                # Robot's variable table keeps the first definition. Reserve
                # unsupported/empty values too, so a later duplicate cannot
                # turn an unknown provider into a different proven import.
                document.variables.setdefault(
                    _normalize(match[1]), pending[1] if len(pending) == 2 else None
                )

    for line in text.splitlines():
        indented = bool(line[:1].isspace())
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cells = (
            [part.strip() for part in re.split(r"(?<!\\)\|", line)[1:-1]]
            if line.startswith("|") and line.endswith("|")
            else re.split(r"\t+| {2,}", line)
        )
        if line.startswith("|"):
            indented = bool(cells and not cells[0])
            while cells and not cells[0]:
                cells.pop(0)
        for offset, cell in enumerate(cells):
            if cell.startswith("#"):
                cells = cells[:offset]
                break
        if not cells:
            continue
        if re.fullmatch(r"\*{3,}\s*[^*]+\s*\*{3,}", cells[0]):
            frames.clear()
            flush()
            pending = []
            section = _setting_name(cells[0].strip("* "))
            document.has_sections |= section in {
                "settings",
                "setting",
                "variables",
                "variable",
                "test cases",
                "test case",
                "tasks",
                "task",
                "keywords",
                "keyword",
            }
        elif cells[0] == "...":
            pending.extend(cells[1:])
        else:
            flush()
            pending = cells
        if section in {"test cases", "test case", "tasks", "task"} and indented:
            selected = step_cells(cells)
            for cell in selected:
                document.method_calls.update(_method_references(cell))
            if not selected:
                continue
            candidate = cells[0]
            assignment_kind = _normalize(candidate).rsplit(".", 1)[-1]
            setter = assignment_kind in {
                "var",
                "settestvariable",
                "setsuitevariable",
                "setglobalvariable",
                "setlocalvariable",
            }
            if setter and len(cells) > 1:
                candidate = cells[1]
            persistent = assignment_kind in {
                "setsuitevariable",
                "setglobalvariable",
            } or (
                assignment_kind == "var"
                and any(
                    re.fullmatch(r"scope=(?:SUITE|GLOBAL)", cell, re.I)
                    for cell in cells[2:]
                )
            )
            written(candidate, persistent=persistent, setter=setter)
        elif section in {"test cases", "test case", "tasks", "task"}:
            frames.clear()
            condition_writes.clear()
            condition_writes.update(suite_writes)
    flush()
    return document if document.has_sections else None


def _guard_exports(providers, module, node, exports, wanted):
    """Immutable source facts only; unresolved suppliers cannot prove a guard."""
    if not wanted:
        return {}
    cache = getattr(providers, "_guard_export_cache", None)
    if cache is None:
        cache = providers._guard_export_cache = {}
    key = module.path, node.lineno if node else None, tuple(sorted(wanted))
    if key in cache:
        return cache[key]
    members = providers.members(module, node)
    facts = {}
    seen = set()
    blocked = getattr(providers, "_guard_blocked_cache", None)
    if blocked is None:
        blocked = providers._guard_blocked_cache = {}
    raw_writes = getattr(providers, "_guard_writes_by_name", None)
    if raw_writes is None:
        raw_writes = providers._guard_writes_by_name = defaultdict(list)
        for source in providers.modules.values():
            for reference, name in source.class_writes:
                raw_writes[_normalize(name)].append((source, reference))

    def immutable(value):
        return (
            value is None
            or isinstance(value, (bool, int, float, complex, str))
            or (isinstance(value, tuple) and all(immutable(item) for item in value))
        )

    for name, (owner, _) in members.items():
        normalized = _normalize(name)
        if normalized == "*":
            facts["*"] = _UNKNOWN
        if normalized not in wanted or normalized not in exports:
            continue
        value = owner.values.get(name, _UNKNOWN)
        if not immutable(value):
            value = _UNKNOWN
        if owner.path not in blocked:
            names = set()
            for item in ast.walk(providers.modules[owner.path].node):
                if isinstance(item, (ast.Global, ast.Nonlocal)):
                    names.update(_normalize(n) for n in item.names)
                elif (
                    isinstance(item, ast.Call)
                    and isinstance(item.func, ast.Name)
                    and item.func.id in {"globals", "locals", "vars", "exec", "eval"}
                ):
                    names.add("*")
            blocked[owner.path] = names
        if normalized in blocked[owner.path] or "*" in blocked[owner.path]:
            value = _UNKNOWN
        if isinstance(owner.node, ast.ClassDef):
            lineage = providers.lineage(module, node) if node is not None else None
            if lineage is None or any(
                _receiver_is_rewritten(cls, name)
                or {"__new__", "__getattr__", "__getattribute__"}.intersection(
                    bound_names(cls.body).counts
                )
                for _, cls in lineage
            ):
                value = _UNKNOWN
        for source, reference in [
            *raw_writes.get(normalized, ()),
            *raw_writes.get("*", ()),
        ]:
            if isinstance(reference, tuple):
                namespace = reference[0]
            else:
                namespace, _ = providers.resolve(reference, source.path.parent)
            if namespace is not None and namespace.path == owner.path:
                value = _UNKNOWN
                break
        if normalized in seen:
            facts[normalized] = _UNKNOWN
        else:
            facts[normalized] = value
            seen.add(normalized)
    cache[key] = facts
    return facts


def _expand(value: str, variables: dict[str, str | None]) -> str | None:
    for _ in range(16):
        if not _VARIABLE.search(value):
            return None if re.search(r"[$@&%]\{", value) else value
        missing = False

        def replace(match):
            nonlocal missing
            replacement = variables.get(_normalize(match[1]))
            if replacement is None:
                missing = True
                return match[0]
            return replacement

        updated = _VARIABLE.sub(replace, value)
        if missing or updated == value:
            return None
        value = updated
    return None


def _literal(node):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return _UNKNOWN


def _qualified(node, bindings):
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.Attribute):
        parent = _qualified(node.value, bindings)
        return f"{parent}.{node.attr}" if parent else None
    return None


@dataclass
class _Scope:
    path: Path
    node: Any
    members: dict[str, ast.AST] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)
    bindings: dict[str, str | None] = field(default_factory=dict)
    decorators: dict[int, list[tuple[str | None, ast.AST]]] = field(
        default_factory=dict
    )
    not_keywords: set[int] = field(default_factory=set)
    explicit_keywords: set[int] = field(default_factory=set)
    bases: dict[int, list[ast.ClassDef | str | None]] = field(default_factory=dict)
    class_bindings: dict[int, dict[str, str | None]] = field(default_factory=dict)
    class_sources: dict[int, dict] = field(default_factory=dict)
    classes: dict[str, Any] = field(default_factory=dict)
    instances: dict[str, Any] = field(default_factory=dict)
    library_factories: dict[str, ast.Call] = field(default_factory=dict)
    changed_attributes: set[str] = field(default_factory=set)
    class_writes: list[tuple[Any, str]] = field(default_factory=list)


@dataclass
class _Instance:
    owner: Any
    writes: set[str] = field(default_factory=set)


def _class_reference(value, scope):
    if isinstance(value, ast.Name) and value.id in scope.classes:
        return scope.classes[value.id]
    return _qualified(value, scope.bindings)


def _provider_changed(provider, scope):
    parts = provider.split(".")
    return provider in scope.changed_attributes or any(
        ".".join(parts[:index]) + ".*" in scope.changed_attributes
        for index in range(1, len(parts))
    )


def _native_library_factory(value, scope):
    if not isinstance(value, ast.Call):
        return None
    if _qualified(value.func, scope.bindings) != _DECO + "library":
        return None
    if isinstance(value.func, ast.Attribute) and _provider_changed(
        _DECO + "library", scope
    ):
        return None
    if any(isinstance(arg, ast.Starred) for arg in value.args) or len(value.args) > len(
        _LIBRARY_OPTIONS
    ):
        return None
    names = set(_LIBRARY_OPTIONS[: len(value.args)])
    for keyword in value.keywords:
        if keyword.arg not in _LIBRARY_OPTIONS or keyword.arg in names:
            return None
        names.add(keyword.arg)
    scope_argument = value.args[0] if value.args else None
    for keyword in value.keywords:
        if keyword.arg == "scope":
            scope_argument = keyword.value
    if scope_argument is not None:
        option = _literal(scope_argument)
        # library(SomeClass) applies the decorator directly; it does not make
        # a decorator factory. Unknown scope expressions may also be classes.
        if option is not None and not isinstance(option, str):
            return None
    return value


def _library_application(value, scope):
    if not isinstance(value, ast.Call) or len(value.args) != 1 or value.keywords:
        return None
    reference = _class_reference(value.args[0], scope)
    if not isinstance(reference, tuple):
        return None
    decorator = None
    if _qualified(value.func, scope.bindings) == _DECO + "library":
        if not isinstance(value.func, ast.Attribute) or not _provider_changed(
            _DECO + "library", scope
        ):
            decorator = value.func
    elif isinstance(value.func, ast.Name):
        decorator = scope.library_factories.get(value.func.id)
    else:
        decorator = _native_library_factory(value.func, scope)
    return (reference, decorator) if decorator is not None else None


def _record_write(scope, receiver, name):
    if isinstance(receiver, ast.Name):
        if instance := scope.instances.get(receiver.id):
            instance.writes.add(name)
    if reference := _class_reference(receiver, scope):
        scope.class_writes.append((reference, name))
    if provider := _qualified(receiver, scope.bindings):
        scope.changed_attributes.add(provider + "." + name)


def _receiver_root(value):
    while isinstance(value, ast.Attribute):
        value = value.value
    return value.id if isinstance(value, ast.Name) else None


def _replace_receiver_root(value, root):
    if isinstance(value, ast.Name):
        return root
    return ast.Attribute(
        value=_replace_receiver_root(value.value, root),
        attr=value.attr,
        ctx=ast.Load(),
    )


def _receiver_spelling(value):
    parts = []
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    return ".".join([value.id, *reversed(parts)])


def _reference_expression(spelling):
    parts = spelling.split(".")
    value = ast.Name(id=parts[0], ctx=ast.Load())
    for part in parts[1:]:
        value = ast.Attribute(value=value, attr=part, ctx=ast.Load())
    return value


def _visible_writes(scope, statement):
    """Refuse visible patches even in conditional or deferred Python bodies."""
    nodes = list(ast.walk(statement))
    assignments = []
    writes = []
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(node.value, (ast.Name, ast.Attribute)) and _receiver_root(
                node.value
            ):
                assignments.extend(
                    (target.id, node.value)
                    for target in targets
                    if isinstance(target, ast.Name)
                )
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            writes.append((node.value, node.attr))
        elif isinstance(node, ast.Subscript) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            value = node.value
            if isinstance(value, ast.Attribute) and value.attr == "__dict__":
                writes.append((value.value, "*"))
            elif (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "vars"
                and len(value.args) == 1
            ):
                writes.append((value.args[0], "*"))
        elif isinstance(node, ast.Call):
            if _library_application(node, scope) is None:
                for argument in [*node.args, *(item.value for item in node.keywords)]:
                    if isinstance(argument, (ast.Name, ast.Attribute)):
                        writes.append((argument, "*"))
                    elif isinstance(argument, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                        writes.extend(
                            (item, "*")
                            for item in ast.walk(argument)
                            if isinstance(item, ast.Name)
                        )
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and len(node.args) >= 2
            ):
                name = _literal(node.args[1])
                writes.append((node.args[0], name if isinstance(name, str) else "*"))
            elif isinstance(node.func, ast.Attribute) and node.func.attr in {
                "update",
                "__setitem__",
                "__delitem__",
                "clear",
                "pop",
                "popitem",
                "setdefault",
            }:
                value = node.func.value
                if isinstance(value, ast.Attribute) and value.attr == "__dict__":
                    writes.append((value.value, "*"))
                elif (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id == "vars"
                    and len(value.args) == 1
                ):
                    writes.append((value.args[0], "*"))
    if not writes:
        return
    shadowed = set()
    if isinstance(statement, _FUNCTIONS):
        shadowed = set(bound_names(statement.body).counts)
        shadowed.update(
            arg.arg for arg in ast.walk(statement.args) if isinstance(arg, ast.arg)
        )
        shadowed.difference_update(
            name
            for node in nodes
            if isinstance(node, ast.Global)
            for name in node.names
        )
    aliases = {
        name: {name}
        for name in set(scope.classes) | set(scope.instances) | set(scope.bindings)
        if name not in shadowed
    }
    for _ in range(min(len(assignments) + 1, 24)):
        grew = False
        for target, source in assignments:
            values = aliases.setdefault(target, set())
            previous = len(values)
            for original in tuple(aliases.get(_receiver_root(source), ())):
                value = _replace_receiver_root(source, _reference_expression(original))
                values.add(_receiver_spelling(value))
            grew |= previous != len(values)
        if sum(len(values) for values in aliases.values()) > 4096:
            break
        if not grew:
            break
    if grew:
        for name in aliases:
            _record_write(scope, ast.Name(id=name, ctx=ast.Load()), "*")
        return
    for receiver, name in writes:
        if root := _receiver_root(receiver):
            for original in aliases.get(root, ()):
                value = _replace_receiver_root(
                    receiver, _reference_expression(original)
                )
                _record_write(scope, value, name)


def _library_option(decorator, name, default=None):
    if not isinstance(decorator, ast.Call):
        return default
    for keyword in decorator.keywords:
        if keyword.arg == name:
            return _literal(keyword.value)
    index = _LIBRARY_OPTIONS.index(name)
    return _literal(decorator.args[index]) if len(decorator.args) > index else default


def _assignment_values(target, value):
    if isinstance(target, ast.Name):
        return {target.id: value}
    if (
        isinstance(target, (ast.Tuple, ast.List))
        and isinstance(value, (tuple, list))
        and len(target.elts) == len(value)
        and not any(isinstance(item, ast.Starred) for item in target.elts)
    ):
        values = {}
        for child, item in zip(target.elts, value):
            values.update(_assignment_values(child, item))
        return values
    return {}


def _scope(path, node, bindings=None, classes=None):
    scope = _Scope(
        path, node, bindings=dict(bindings or {}), classes=dict(classes or {})
    )
    for statement in node.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            for alias in statement.names:
                name = alias.asname or (
                    alias.name.split(".")[0]
                    if isinstance(statement, ast.Import)
                    else alias.name
                )
                provider = (
                    (alias.name if alias.asname else alias.name.split(".")[0])
                    if isinstance(statement, ast.Import)
                    else (
                        "." * statement.level
                        + ".".join(
                            part for part in (statement.module, alias.name) if part
                        )
                    )
                )
                scope.members[name] = statement
                scope.bindings[name] = (
                    None if _provider_changed(provider, scope) else provider
                )
                scope.classes.pop(name, None)
                scope.instances.pop(name, None)
                scope.library_factories.pop(name, None)
        elif isinstance(statement, (*_FUNCTIONS, ast.ClassDef)):
            _visible_writes(scope, statement)
            if isinstance(statement, ast.ClassDef):
                scope.class_bindings[statement.lineno] = scope.bindings.copy()
                scope.class_sources[statement.lineno] = scope.classes.copy()
                bases = []
                for base in statement.bases:
                    local = (
                        scope.members.get(base.id)
                        if isinstance(base, ast.Name)
                        else None
                    )
                    if isinstance(local, ast.ClassDef):
                        bases.append(local)
                    elif (
                        isinstance(base, ast.Name)
                        and base.id == "object"
                        and base.id not in scope.bindings
                    ):
                        bases.append("builtins.object")
                    else:
                        bases.append(_qualified(base, scope.bindings))
                scope.bases[statement.lineno] = bases
                scope.classes[statement.name] = (scope, statement)
            else:
                scope.classes.pop(statement.name, None)
            scope.instances.pop(statement.name, None)
            scope.library_factories.pop(statement.name, None)
            scope.decorators[statement.lineno] = [
                (
                    _qualified(
                        deco.func if isinstance(deco, ast.Call) else deco,
                        scope.bindings,
                    ),
                    deco,
                )
                for deco in statement.decorator_list
            ]
            scope.members[statement.name] = statement
            scope.bindings[statement.name] = None
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            if isinstance(statement, ast.AnnAssign) and statement.value is None:
                continue
            _visible_writes(scope, statement)
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            application = _library_application(statement.value, scope)
            if application and len(targets) == 1 and isinstance(targets[0], ast.Name):
                reference, decorator = application
                owner, cls = reference
                owner.decorators.setdefault(cls.lineno, []).insert(
                    0, (_DECO + "library", decorator)
                )
                name = targets[0].id
                scope.members[name] = cls
                scope.classes[name] = reference
                scope.bindings[name] = None
                scope.instances.pop(name, None)
                scope.library_factories.pop(name, None)
                continue
            assigned_values = {}
            literal = _literal(statement.value)
            for target in targets:
                assigned_values.update(_assignment_values(target, literal))
            for target in targets:
                if isinstance(target, ast.Attribute):
                    _record_write(scope, target.value, target.attr)
                elif isinstance(target, ast.Subscript) and isinstance(
                    target.value, ast.Attribute
                ):
                    _record_write(scope, target.value.value, "*")
                if isinstance(target, ast.Attribute) and isinstance(
                    target.value, ast.Name
                ):
                    member = scope.members.get(target.value.id)
                    if isinstance(member, _FUNCTIONS):
                        if (
                            target.attr == "robot_not_keyword"
                            and _literal(statement.value) is not False
                        ):
                            scope.not_keywords.add(member.lineno)
                        elif target.attr == "robot_name":
                            scope.explicit_keywords.add(member.lineno)
            for name in bound_names([statement]).counts:
                direct = any(
                    isinstance(target, ast.Name) and target.id == name
                    for target in targets
                )
                class_reference = (
                    _class_reference(statement.value, scope) if direct else None
                )
                instance = (
                    scope.instances.get(statement.value.id)
                    if direct and isinstance(statement.value, ast.Name)
                    else None
                )
                if direct and isinstance(statement.value, ast.Call):
                    if constructor := _class_reference(statement.value.func, scope):
                        instance = _Instance(constructor)
                factory = (
                    _native_library_factory(statement.value, scope) if direct else None
                )
                scope.members[name] = statement
                scope.values[name] = assigned_values.get(name, _UNKNOWN)
                scope.bindings[name] = (
                    _qualified(statement.value, scope.bindings)
                    if any(
                        isinstance(target, ast.Name) and target.id == name
                        for target in targets
                    )
                    else None
                )
                for mapping, value in (
                    (scope.classes, class_reference),
                    (scope.instances, instance),
                    (scope.library_factories, factory),
                ):
                    if value is not None:
                        mapping[name] = value
                    else:
                        mapping.pop(name, None)
        else:
            _visible_writes(scope, statement)
            if isinstance(statement, ast.Delete):
                for target in statement.targets:
                    if isinstance(target, ast.Attribute):
                        _record_write(scope, target.value, target.attr)
            if isinstance(statement, ast.Expr) and isinstance(
                statement.value, ast.Call
            ):
                call = statement.value
                if application := _library_application(call, scope):
                    (owner, cls), decorator = application
                    owner.decorators.setdefault(cls.lineno, []).insert(
                        0, (_DECO + "library", decorator)
                    )
                if (
                    isinstance(call.func, ast.Name)
                    and call.func.id in {"setattr", "delattr"}
                    and len(call.args) >= 2
                ):
                    name = _literal(call.args[1])
                    _record_write(
                        scope, call.args[0], name if isinstance(name, str) else "*"
                    )
                if (
                    _qualified(call.func, scope.bindings) == _DECO + "not_keyword"
                    and call.args
                ):
                    argument = call.args[0]
                    member = (
                        scope.members.get(argument.id)
                        if isinstance(argument, ast.Name)
                        else None
                    )
                    if isinstance(member, _FUNCTIONS):
                        scope.not_keywords.add(member.lineno)
                if (
                    isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "__all__"
                ):
                    scope.values["__all__"] = _UNKNOWN
            for name in bound_names([statement]).counts:
                scope.members.pop(name, None)
                scope.values[name] = _UNKNOWN
                scope.bindings[name] = None
                scope.classes.pop(name, None)
                scope.instances.pop(name, None)
                scope.library_factories.pop(name, None)
    return scope


class _Providers:
    def __init__(self, definitions, parsed, root):
        self.root = root
        self.modules = {}
        self.definitions = defaultdict(list)
        self.class_scopes = {}
        self.lineages = {}
        self.variable_exports = {}
        self._module_cache = {}
        self._resolution_cache = {}
        self._local_reference_cache = {}
        self._mutation_indexes = None
        for module in parsed:
            path = module.path.resolve()
            if path.is_relative_to(root):
                self.modules[path] = _scope(path, module.tree)
        for module in self.modules.values():
            for node in ast.walk(module.node):
                if isinstance(node, _FUNCTIONS):
                    # Function globals are looked up when called, after any
                    # later module-level rebinding has taken place.
                    _visible_writes(module, node)
        for definition in definitions.values():
            path = Path(definition.filename).resolve()
            if path in self.modules:
                self.definitions[path, definition.line].append(definition)
        self.source_roots = [root, root / "src", root / "lib", root / "python"]

    def module(self, name, parent):
        key = name, parent
        if key in self._module_cache:
            return self._module_cache[key]
        candidates = set()
        for base in [parent, *self.source_roots]:
            for relative in (name + ".py", name + "/__init__.py"):
                path = (base / relative).resolve()
                if path in self.modules:
                    candidates.add(path)
        result = self.modules[next(iter(candidates))] if len(candidates) == 1 else None
        self._module_cache[key] = result
        return result

    def resolve(self, name, parent):
        key = name, parent
        if key not in self._resolution_cache:
            self._resolution_cache[key] = self._resolve(name, parent)
        return self._resolution_cache[key]

    def _resolve(self, name, parent):
        if name.endswith(".py") or "/" in name or "\\" in name:
            path = (parent / name.replace("\\", "/")).resolve()
            scope = self.modules.get(path) or self.modules.get(path / "__init__.py")
            return (scope, None) if scope else (None, None)
        if name.startswith("."):
            level = len(name) - len(name.lstrip("."))
            name = name[level:]
            for _ in range(level - 1):
                parent = parent.parent
        if not all(part.isidentifier() for part in name.split(".")):
            return None, None
        module = self.module(name.replace(".", "/"), parent)
        if module:
            return module, None
        module_name, _, class_name = name.rpartition(".")
        if module_name:
            module = self.module(module_name.replace(".", "/"), parent)
            node = module.members.get(class_name) if module else None
            if isinstance(node, ast.ClassDef):
                return module, node
        return None, None

    def local_reference(self, reference, parent):
        """Whether a dotted write can name a module in this parsed snapshot."""
        key = reference, parent
        if key in self._local_reference_cache:
            return self._local_reference_cache[key]
        name = reference
        if name.startswith("."):
            level = len(name) - len(name.lstrip("."))
            name = name[level:]
            for _ in range(level - 1):
                parent = parent.parent
        parts = name.split(".")
        result = False
        if len(parts) <= 24 and all(part.isidentifier() for part in parts):
            for base in [parent, *self.source_roots]:
                for offset in range(1, len(parts) + 1):
                    path = base.joinpath(*parts[:offset])
                    if (
                        path.with_suffix(".py") in self.modules
                        or path / "__init__.py" in self.modules
                    ):
                        result = True
                        break
                if result:
                    break
        self._local_reference_cache[key] = result
        return result

    def mutation_indexes(self):
        """Resolve each source-owned mutation owner once for all method checks."""
        if self._mutation_indexes is not None:
            return self._mutation_indexes
        classes = defaultdict(set)
        instances = defaultdict(set)
        namespaces = defaultdict(set)
        resolved = {}
        for source in self.modules.values():
            for reference, name in source.class_writes:
                if isinstance(reference, tuple):
                    owner, cls = reference
                    classes[owner.path, cls.lineno].add(name)
                    continue
                key = reference, source.path.parent
                if key not in resolved:
                    destination = None
                    if self.local_reference(reference, source.path.parent):
                        owner, cls = self.resolve(reference, source.path.parent)
                        if owner and cls:
                            destination = classes, (owner.path, cls.lineno)
                        elif owner:
                            destination = namespaces, owner.path
                        elif instance := _reference_instance(self, source, reference):
                            destination = instances, id(instance)
                    resolved[key] = destination
                destination = resolved[key]
                if destination is not None:
                    index, owner_key = destination
                    index[owner_key].add(name)
        self._mutation_indexes = classes, instances, namespaces
        return self._mutation_indexes

    def selected_class(self, module, *, library):
        stem = module.path.stem
        if stem == "__init__":
            stem = module.path.parent.name
        node = module.members.get(stem)
        if isinstance(node, ast.ClassDef):
            return node
        if library:
            decorated = {
                id(node): node
                for node in module.members.values()
                if isinstance(node, ast.ClassDef)
                and any(
                    provider == _DECO + "library"
                    for provider, _ in module.decorators.get(node.lineno, ())
                )
            }
            if len(decorated) == 1:
                return next(iter(decorated.values()))
        return None

    def class_scope(self, module, node):
        key = module.path, node.lineno
        if key not in self.class_scopes:
            self.class_scopes[key] = _scope(
                module.path,
                node,
                module.class_bindings.get(node.lineno, {}),
                module.class_sources.get(node.lineno, {}),
            )
        return self.class_scopes[key]

    def members(self, module, node):
        if node is None:
            return {name: (module, item) for name, item in module.members.items()}
        members = {}
        for owner, cls in reversed(self.lineage(module, node) or [(module, node)]):
            scope = self.class_scope(owner, cls)
            members.update(
                {name: (scope, item) for name, item in scope.members.items()}
            )
        return members

    def bases(self, module, node):
        bases = []
        for provider in module.bases.get(node.lineno, ()):
            if isinstance(provider, ast.ClassDef):
                bases.append((module, provider))
            elif provider == "builtins.object":
                continue
            elif provider:
                # Relative imports are resolved against the defining package.
                parent, base_node = self.resolve(provider, module.path.parent)
                if parent and base_node:
                    bases.append((parent, base_node))
                else:
                    return None
            else:
                return None
        return bases

    def lineage(self, module, node, seen=()):
        """C3 order for source-owned bases; unknown parents prove no inheritance."""
        key = module.path, node.lineno
        if key in self.lineages:
            return self.lineages[key]
        if key in seen or len(seen) >= 16:
            return None
        bases = self.bases(module, node)
        if bases is None:
            return None
        sequences = [self.lineage(parent, cls, (*seen, key)) for parent, cls in bases]
        if any(sequence is None for sequence in sequences):
            return None
        sequences = [list(sequence) for sequence in sequences] + [list(bases)]
        result = [(module, node)]
        while sequences := [sequence for sequence in sequences if sequence]:
            candidate = None
            for sequence in sequences:
                head = sequence[0]
                head_key = head[0].path, head[1].lineno
                if not any(
                    (owner.path, cls.lineno) == head_key
                    for other in sequences
                    for owner, cls in other[1:]
                ):
                    candidate = head
                    break
            if candidate is None:
                return None
            result.append(candidate)
            key_to_remove = candidate[0].path, candidate[1].lineno
            for sequence in sequences:
                if (sequence[0][0].path, sequence[0][1].lineno) == key_to_remove:
                    sequence.pop(0)
        self.lineages[key] = result
        return result

    def auto_keywords(self, module, node):
        if node is None:
            return module.values.get("ROBOT_AUTO_KEYWORDS", _UNSET)
        lineage = self.lineage(module, node)
        for owner, cls in lineage or [(module, node)]:
            value = self.own_auto_keywords(owner, cls)
            if value is not _UNSET:
                return value
        return _UNSET if lineage is not None else _UNKNOWN

    def own_auto_keywords(self, module, node):
        if any(
            isinstance(reference, tuple)
            and reference[1] is node
            and name in {"ROBOT_AUTO_KEYWORDS", "*"}
            for reference, name in module.class_writes
        ):
            return _UNKNOWN
        for provider, decorator in module.decorators.get(node.lineno, ()):
            if provider == _DECO + "library":
                return _library_option(decorator, "auto_keywords", False)
        scope = self.class_scope(module, node)
        if "ROBOT_AUTO_KEYWORDS" in scope.values:
            return scope.values["ROBOT_AUTO_KEYWORDS"]
        return _UNSET

    def self_listener(self, module, node):
        if node is None:
            return False
        for owner, cls in self.lineage(module, node) or [(module, node)]:
            for provider, decorator in owner.decorators.get(cls.lineno, ()):
                if provider == _DECO + "library" and isinstance(decorator, ast.Call):
                    value = _library_option(decorator, "listener")
                    if value is not None:
                        return isinstance(value, str) and value.casefold() == "self"
        return False

    def targets(self, scope, node, kind, name=None):
        for definition in self.definitions.get((scope.path, node.lineno), ()):
            if definition.type in kind and (
                name is None or definition.simple_name == name
            ):
                yield definition


def _dynamic_names(owner, method, members, global_bindings):
    returns = [item for item in method.body if isinstance(item, ast.Return)]
    if len(returns) != 1:
        return None
    expression = returns[0].value
    value = _literal(expression)
    if isinstance(value, (list, tuple)) and all(
        isinstance(item, str) for item in value
    ):
        return set(value)
    if not isinstance(expression, ast.ListComp) or len(expression.generators) != 1:
        return None
    generator = expression.generators[0]
    receiver = [*method.args.posonlyargs, *method.args.args]
    local_names = bound_names(method.body).counts
    if (
        not receiver
        or "dir" in global_bindings
        or "dir" in local_names
        or receiver[0].arg in local_names
        or any(arg.arg == "dir" for arg in [*receiver, *method.args.kwonlyargs])
        or generator.is_async
        or not isinstance(generator.target, ast.Name)
        or not isinstance(expression.elt, ast.Name)
        or expression.elt.id != generator.target.id
        or not isinstance(generator.iter, ast.Call)
        or not isinstance(generator.iter.func, ast.Name)
        or generator.iter.func.id != "dir"
        or len(generator.iter.args) != 1
        or generator.iter.keywords
        or not isinstance(generator.iter.args[0], ast.Name)
        or generator.iter.args[0].id != receiver[0].arg
        or len(generator.ifs) != 1
    ):
        return None
    condition = generator.ifs[0]
    if (
        isinstance(condition, ast.Call)
        and isinstance(condition.func, ast.Attribute)
        and isinstance(condition.func.value, ast.Name)
        and condition.func.value.id == generator.target.id
        and condition.func.attr == "startswith"
        and len(condition.args) == 1
        and not condition.keywords
        and isinstance(prefix := _literal(condition.args[0]), str)
    ):
        return {name for name in members if name.startswith(prefix)}
    return None


def _library_targets(providers, module, node):
    if node:
        yield from providers.targets(module, node, {"class"})
    policy = providers.auto_keywords(module, node)
    auto = policy is _UNSET or (policy is not _UNKNOWN and bool(policy))
    includes = module.values.get("__all__") if node is None else None
    if includes is _UNKNOWN or (
        includes is not None and not isinstance(includes, (list, tuple, set))
    ):
        return
    members = providers.members(module, node)
    listener = providers.self_listener(module, node)
    dynamic = next(
        (
            members.get(name)
            for name in ("get_keyword_names", "getKeywordNames")
            if name in members
        ),
        None,
    )
    dynamic_names = None
    if dynamic and isinstance(dynamic[1], _FUNCTIONS):
        dynamic_names = _dynamic_names(
            dynamic[0],
            dynamic[1],
            members,
            providers.modules[dynamic[0].path].bindings,
        )
    for name, (owner, member) in members.items():
        if not isinstance(member, _FUNCTIONS):
            continue
        decorators = {
            provider for provider, _ in owner.decorators.get(member.lineno, ())
        }
        if "property" in {getattr(deco, "id", None) for deco in member.decorator_list}:
            continue
        protocol = (
            name == "__init__"
            or (dynamic and name in _DYNAMIC_METHODS)
            or (listener and name in _LISTENER_METHODS)
        )
        keyword = (
            member.lineno in owner.explicit_keywords
            or _DECO + "keyword" in decorators
            or (auto is True and not name.startswith("_"))
        )
        if dynamic and (dynamic_names is None or name not in dynamic_names):
            keyword = False
        elif dynamic_names is not None and name in dynamic_names:
            keyword = True
        if member.lineno in owner.not_keywords or _DECO + "not_keyword" in decorators:
            keyword = False
        if includes is not None and name not in includes:
            keyword = False
        if protocol or keyword:
            yield from providers.targets(owner, member, {"method", "function"}, name)


def _variable_targets(providers, module, node):
    if node:
        yield from providers.targets(module, node, {"class"})
    members = providers.members(module, node)
    for name in ("get_variables", "getVariables"):
        if name in members:
            owner, getter = members[name]
            if isinstance(getter, _FUNCTIONS):
                yield from providers.targets(
                    owner, getter, {"function", "method"}, name
                )
            return
    scope = providers.class_scope(module, node) if node else module
    includes = scope.values.get("__all__")
    if includes is _UNKNOWN or (
        includes is not None and not isinstance(includes, (list, tuple, set))
    ):
        return
    for name, (owner, member) in members.items():
        if name.startswith("_") or (includes is not None and name not in includes):
            continue
        kinds = (
            {"variable", "import"}
            if node
            else {"variable", "import", "function", "class"}
        )
        yield from providers.targets(owner, member, kinds, name)


def _object_exports(providers, module, node):
    key = module.path, node.lineno if node else None
    if key in providers.variable_exports:
        return providers.variable_exports[key]
    members = providers.members(module, node)
    if any(name in members for name in ("get_variables", "getVariables")):
        providers.variable_exports[key] = None
        return None
    scope = providers.class_scope(module, node) if node else module
    includes = scope.values.get("__all__")
    if "__all__" in scope.values and (
        not isinstance(includes, (list, tuple, set))
        or not all(isinstance(name, str) for name in includes)
    ):
        providers.variable_exports[key] = None
        return None
    result = {}
    for name, (owner, _) in members.items():
        if name.startswith("_") or (includes is not None and name not in includes):
            continue
        normalized = _normalize(name)
        instance = owner.instances.get(name)
        if normalized in result:
            result[normalized] = None
        else:
            result[normalized] = (owner, instance) if instance is not None else None
    providers.variable_exports[key] = result
    return result


def _instance_class(providers, scope, reference):
    if isinstance(reference, tuple):
        return reference
    if not providers.local_reference(reference, scope.path.parent):
        return None, None
    module, cls = providers.resolve(reference, scope.path.parent)
    return (module, cls) if module and cls else (None, None)


def _reference_instance(providers, scope, reference):
    parts = reference.split(".")
    if len(parts) > 24:
        return None
    for offset in range(len(parts), 0, -1):
        module, cls = providers.resolve(".".join(parts[:offset]), scope.path.parent)
        if module is None:
            continue
        owner = providers.class_scope(module, cls) if cls else module
        remaining = parts[offset:]
        for index, name in enumerate(remaining):
            if index == len(remaining) - 1:
                return owner.instances.get(name)
            member = owner.members.get(name)
            if not isinstance(member, ast.ClassDef):
                break
            owner = providers.class_scope(owner, member)
        return None
    return None


def _receiver_is_rewritten(cls, method):
    for function in cls.body:
        if not isinstance(function, _FUNCTIONS):
            continue
        if any(
            isinstance(item, ast.Name) and item.id == "staticmethod"
            for item in function.decorator_list
        ):
            continue
        arguments = [*function.args.posonlyargs, *function.args.args]
        if not arguments:
            continue
        aliases = {arguments[0].arg}
        nodes = list(ast.walk(function))
        for _ in range(min(len(nodes), 24)):
            previous = len(aliases)
            for node in nodes:
                if (
                    isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Name)
                    and node.value.id in aliases
                ):
                    aliases.update(
                        target.id
                        for target in node.targets
                        if isinstance(target, ast.Name)
                    )
            if len(aliases) == previous:
                break
        for node in nodes:
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if (
                    node.attr in {method, "__class__"}
                    and isinstance(node.value, ast.Name)
                    and node.value.id in aliases
                ):
                    return True
            if isinstance(node, ast.Subscript) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                value = node.value
                if (
                    isinstance(value, ast.Attribute)
                    and value.attr == "__dict__"
                    and isinstance(value.value, ast.Name)
                    and value.value.id in aliases
                ):
                    return True
            if not isinstance(node, ast.Call):
                continue
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and len(node.args) >= 2
            ):
                receiver, name = node.args[:2]
                value = _literal(name)
                if (
                    isinstance(receiver, ast.Name)
                    and receiver.id in aliases
                    and (
                        value is _UNKNOWN
                        or isinstance(value, str)
                        and value in {method, "__class__"}
                    )
                ):
                    return True
            if any(
                isinstance(arg, ast.Name) and arg.id in aliases for arg in node.args
            ):
                # Passing the receiver away can install an instance-level method.
                return True
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Attribute
            ):
                receiver = node.func.value
                if (
                    receiver.attr == "__dict__"
                    and isinstance(receiver.value, ast.Name)
                    and receiver.value.id in aliases
                ):
                    return True
    return False


def _object_method_targets(providers, scope, instance, method):
    if method in instance.writes or "*" in instance.writes:
        return
    module, cls = _instance_class(providers, scope, instance.owner)
    if module is None:
        return
    lineage = providers.lineage(module, cls)
    if lineage is None:
        return
    members = providers.members(module, cls)
    if any(name in members for name in ("__new__", "__getattribute__", "__getattr__")):
        return
    keys = {(owner.path, node.lineno) for owner, node in lineage}
    for owner, node in lineage:
        if node.keywords or any(
            provider != _DECO + "library"
            for provider, _ in owner.decorators.get(node.lineno, ())
        ):
            return
        if _receiver_is_rewritten(node, method):
            return
    class_writes, instance_writes, namespace_writes = providers.mutation_indexes()
    if instance_writes.get(id(instance), set()) & {method, "*"}:
        return
    if any(class_writes.get(key, set()) & {method, "*"} for key in keys):
        return
    if any(
        "*" in namespace_writes.get(path, ())
        for path in {scope.path, *(owner.path for owner, _ in lineage)}
    ):
        return
    selected = members.get(method)
    if selected is None or not isinstance(selected[1], _FUNCTIONS):
        return
    owner, function = selected
    for provider, decorator in owner.decorators.get(function.lineno, ()):
        if provider in {
            _DECO + "keyword",
            "builtins.staticmethod",
            "builtins.classmethod",
            "builtins.property",
        }:
            continue
        if (
            isinstance(decorator, ast.Name)
            and decorator.id in {"staticmethod", "classmethod", "property"}
            and decorator.id not in owner.bindings
        ):
            continue
        return
    yield from providers.targets(owner, function, {"method", "function"}, method)


def find_robot_framework_targets(
    definitions: dict[str, Any],
    parsed_files: Iterable[ParsedPythonFile],
    root: Path,
    *,
    exclude_folders=None,
) -> list[tuple[Any, str]]:
    documents = {}
    for path in discover_source_files(
        root, {".robot", ".resource"}, exclude_folders=exclude_folders
    ):
        if document := _document(root, path):
            documents[path.resolve()] = document
    active = {path for path in documents if path.suffix.lower() == ".robot"}
    if not active:
        return []
    providers = _Providers(definitions, parsed_files, root)
    found = {}

    def add(module, node, kind):
        if module is None:
            return
        node = node or providers.selected_class(module, library=kind == "library")
        targets = _library_targets if kind == "library" else _variable_targets
        for target in targets(providers, module, node):
            found[id(target)] = target, f"robot_{kind}"

    def variables(document, seen=()):
        if document.path in seen or len(seen) >= 16:
            return {}
        values = {**document.variables, "curdir": str(document.path.parent), "/": "/"}
        for kind, name in document.imports:
            if kind != "resource" or (name := _expand(name, values)) is None:
                continue
            resource = documents.get((document.path.parent / name).resolve())
            if resource:
                inherited = variables(resource, (*seen, document.path))
                for key, value in inherited.items():
                    if key not in {"curdir", "/"} and key not in values:
                        values[key] = (
                            _expand(value, inherited) if value is not None else None
                        )
        return values

    def object_calls(document):
        if not document.method_calls:
            return
        closure = {}
        pending = [document]
        while pending:
            current = pending.pop()
            if current.path in closure:
                continue
            closure[current.path] = current
            values = variables(current)
            for kind, name in current.imports:
                if kind != "resource":
                    continue
                expanded = _expand(name, values)
                resource = (
                    documents.get((current.path.parent / expanded).resolve())
                    if expanded
                    else None
                )
                if resource is None:
                    return
                pending.append(resource)
        exports = {}
        blocked = set()
        guard_values = {}
        for current in closure.values():
            blocked.update(current.variable_names)
            values = variables(current)
            for kind, name in current.imports:
                if kind != "variables":
                    continue
                expanded = _expand(name, values)
                if not expanded or expanded.lower().endswith(
                    (".yaml", ".yml", ".json")
                ):
                    return
                module, node = providers.resolve(expanded, current.path.parent)
                if module is None:
                    return
                node = node or providers.selected_class(module, library=False)
                bindings = _object_exports(providers, module, node)
                if bindings is None:
                    return
                for name, value in _guard_exports(
                    providers, module, node, bindings, document.guard_names
                ).items():
                    if name in guard_values and guard_values[name] != value:
                        guard_values[name] = _UNKNOWN
                    else:
                        guard_values[name] = value
                for name, instance in bindings.items():
                    if name in exports and exports[name] != instance:
                        exports[name] = None
                    else:
                        exports[name] = instance
        # Variable-table values outrank imported variables. Unknown or typed
        # declarations must not fall back to a similarly named native constant.
        table_values = variables(document)
        for name in blocked.intersection(document.guard_names):
            value = table_values.get(name)
            guard_values[name] = value if isinstance(value, str) else _UNKNOWN
        selected_document = _document(root, document.path, guard_values=guard_values)
        if selected_document is None:
            return
        blocked.update(selected_document.written_variables)
        for name, method in selected_document.method_calls:
            if name in blocked or not (exported := exports.get(name)):
                continue
            scope, instance = exported
            for target in _object_method_targets(providers, scope, instance, method):
                found[id(target)] = target, "robot_variables"

    builtin, _ = providers.resolve("robot.libraries.BuiltIn", root)
    add(builtin, None, "library")
    pending = list(active)
    while pending:
        document = documents[pending.pop()]
        values = variables(document)
        for kind, name in document.imports:
            name = _expand(name, values)
            if name is None:
                continue
            if kind == "variables" and name.lower().endswith(
                (".yaml", ".yml", ".json")
            ):
                continue
            if kind == "resource":
                path = (document.path.parent / name).resolve()
                if path in documents and path not in active:
                    active.add(path)
                    pending.append(path)
                continue
            if kind == "library" and name in _STANDARD_LIBRARIES:
                module, node = providers.resolve(f"robot.libraries.{name}", root)
            else:
                module, node = providers.resolve(name, document.path.parent)
            add(module, node, kind)
    for document in documents.values():
        if document.path in active:
            object_calls(document)
    return list(found.values())
