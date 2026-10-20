import ast
import codecs
import math
import operator
import re
import string
import urllib.parse
from collections import defaultdict
from pathlib import Path

from skylos.audit.redaction import REDACTION, redact_text
from skylos.rules.base import SkylosRule
from skylos.rules.quality._scope import (
    is_non_production_function_scope,
    is_non_production_python,
)
from skylos.rules.quality.logic_foundation import (
    _exception_type_names,
    _handler_body_is_trivial,
    _handler_has_real_work,
)
from skylos.rules.quality.logic_security import _qualified_call_name
from skylos.rules.quality._ast_visit import IterativeNodeVisitor
from skylos.rules.quality._provider_context import project_local_provider
from skylos.rules.quality._overload_groups import _mutated_names, overload_groups


_SENSITIVE_LITERAL_KEYWORDS = (
    "api_key",
    "apikey",
    "auth",
    "bearer",
    "credential",
    "password",
    "passwd",
    "private_key",
    "secret",
    "token",
)


def _string_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _looks_sensitive_literal(value: str) -> bool:
    if redact_text(value) != value:
        return True

    lowered = value.lower()
    if any(keyword in lowered for keyword in _SENSITIVE_LITERAL_KEYWORDS):
        return True

    # Entropy over a whole sentence mistakes ordinary prose for a credential.
    # Keep the format and keyword checks above for whitespace-bearing secrets,
    # and still mask opaque credentials surrounded by or embedded in whitespace.
    return any(_is_opaque_sensitive_token(part) for part in value.split())


def _is_opaque_sensitive_token(value: str) -> bool:
    if len(value) < 24:
        return False

    has_upper = any(char.isupper() for char in value)
    has_lower = any(char.islower() for char in value)
    has_digit = any(char.isdigit() for char in value)
    has_symbol = any(char in "_-./+=" for char in value)
    return (
        sum((has_upper, has_lower, has_digit, has_symbol)) >= 3
        and _string_entropy(value) >= 3.5
    )


def _duplicate_string_display(value: str) -> str:
    if _looks_sensitive_literal(value):
        return REDACTION
    return value if len(value) <= 40 else value[:37] + "..."


def _duplicate_string_function_scopes(module: ast.Module) -> dict[int, int | None]:
    """Identify function *body* scopes without names or source in the evidence.

    Defaults and decorators run in the enclosing scope. Class bodies have their
    own namespace, even when the class is nested in a function. AST identity
    distinguishes methods with the same name and nested or async functions.
    """
    scopes: dict[int, int | None] = {}
    stack: list[tuple[ast.AST, int | None]] = [(module, None)]
    while stack:
        current, function_scope = stack.pop()
        scopes[id(current)] = function_scope
        for field, value in ast.iter_fields(current):
            child_scope = function_scope
            if field == "body":
                if isinstance(
                    current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                ):
                    child_scope = id(current)
                elif isinstance(current, ast.ClassDef):
                    child_scope = None
            if isinstance(value, ast.AST):
                stack.append((value, child_scope))
            elif isinstance(value, list):
                stack.extend(
                    (child, child_scope)
                    for child in value
                    if isinstance(child, ast.AST)
                )
    return scopes


def _duplicate_string_occurrence_role(
    node: ast.Constant,
    parent_map: dict[int, ast.AST],
    membership_cache: dict[int, tuple[set[int], ...]],
) -> str:
    parent = parent_map.get(id(node))
    if isinstance(parent, ast.Call):
        members = membership_cache.get(id(parent))
        if members is None:
            members = ({id(argument) for argument in parent.args},)
            membership_cache[id(parent)] = members
        if id(node) in members[0]:
            return "call_argument"
    if isinstance(parent, ast.keyword) and parent.value is node:
        if isinstance(parent_map.get(id(parent)), ast.Call):
            return "call_keyword"
    if isinstance(parent, ast.Dict):
        members = membership_cache.get(id(parent))
        if members is None:
            members = (
                {id(key) for key in parent.keys},
                {id(value) for value in parent.values},
            )
            membership_cache[id(parent)] = members
        if id(node) in members[0]:
            return "dict_key"
        if id(node) in members[1]:
            return "dict_value"
    if isinstance(parent, ast.Subscript) and parent.slice is node:
        return "subscript_key"
    if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
        return "assignment_value"
    if isinstance(parent, ast.Return) and parent.value is node:
        return "return_value"
    if isinstance(parent, ast.Compare):
        return "comparison"
    return "other"


def _duplicate_string_context(
    value: str,
    nodes: list[ast.Constant],
    parent_map: dict[int, ast.AST],
    function_scopes: dict[int, int | None],
    membership_cache: dict[int, tuple[set[int], ...]],
) -> dict:
    """Bounded presentation evidence; never serialize a literal or a symbol."""
    roles: dict[str, int] = {}
    scopes = set()
    outside_functions = 0
    complete = True
    for node in nodes:
        role = _duplicate_string_occurrence_role(node, parent_map, membership_cache)
        roles[role] = roles.get(role, 0) + 1
        if id(node) not in function_scopes:
            complete = False
        scope = function_scopes.get(id(node))
        if scope is None:
            outside_functions += 1
        else:
            scopes.add(scope)
    identifier_like = value.isidentifier()
    return {
        "version": 1,
        "scope_complete": complete,
        "occurrence_count": len(nodes),
        "distinct_function_count": len(scopes),
        "non_function_occurrences": outside_functions,
        "identifier_like": identifier_like,
        # This describes syntax, not a proof that an arbitrary called API
        # requires the value. Consumers can keep mixed and unknown roles visible.
        "all_occurrences_contract_tokens": identifier_like
        and set(roles)
        <= {"call_argument", "call_keyword", "dict_key", "subscript_key"},
        "role_counts": roles,
    }


_DUPLICATE_STRING_PATH_PREFIXES = (
    "benchmarks/",
    "corpus/",
    "docs/",
    "editors/",
    "scripts/",
    "skylos/",
    "test/",
    "tests/",
)

_DUPLICATE_STRING_PATH_SUFFIXES = (
    ".cfg",
    ".css",
    ".go",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".md",
    ".php",
    ".py",
    ".rs",
    ".toml",
    ".ts",
    ".tsx",
    ".xml",
    ".yaml",
    ".yml",
)

_DUPLICATE_STRING_SCHEMA_VALUES = frozenset(
    {
        "ai",
        "ai_agent",
        "ai_authored",
        "basename",
        "category",
        "col",
        "confidence",
        "CRITICAL",
        "cwe",
        "dead_code",
        "debt",
        "dismissed",
        "error",
        "failed",
        "FAIL",
        "file",
        "findings",
        "fingerprint",
        "HIGH",
        "INFO",
        "kind",
        "line",
        "LOW",
        "MEDIUM",
        "message",
        "name",
        "PASS",
        "passed",
        "primary_dimension",
        "priority_score",
        "quality",
        "rule_id",
        "security",
        "secrets",
        "severity",
        "signal_count",
        "signals",
        "simple_name",
        "snoozed",
        "snoozed_until",
        "standard_refs",
        "success",
        "system",
        "threshold",
        "triage",
        "type",
        "value",
        "WARN",
    }
)


def _is_rule_identifier_literal(value: str) -> bool:
    return re.fullmatch(r"(?:SKY-[A-Z]\d{3,4}|CUSTOM-[A-Z0-9_-]+)", value) is not None


def _looks_like_filesystem_path_literal(value: str) -> bool:
    stripped = value.strip()
    normalized = stripped.replace("\\", "/")

    if "/" not in normalized:
        return False

    if normalized.startswith(("http://", "https://")):
        return False

    if normalized.startswith("/"):
        return normalized.endswith(_DUPLICATE_STRING_PATH_SUFFIXES)

    if normalized.endswith("/"):
        return True

    if normalized.startswith(_DUPLICATE_STRING_PATH_PREFIXES):
        return True

    last_segment = normalized.rsplit("/", 1)[-1]
    return last_segment.endswith(_DUPLICATE_STRING_PATH_SUFFIXES)


def _looks_like_markup_fragment(value: str) -> bool:
    stripped = value.strip()
    if re.search(r"</?[A-Za-z][^>]*>", stripped):
        return True
    return bool(re.search(r"\sdata-[A-Za-z0-9_-]+\s*=", stripped))


def _is_duplicate_string_noise(value: str) -> bool:
    stripped = value.strip()

    if stripped in _DUPLICATE_STRING_SCHEMA_VALUES:
        return True

    if _is_rule_identifier_literal(stripped):
        return True

    if _looks_like_filesystem_path_literal(stripped):
        return True

    return _looks_like_markup_fragment(value)


_REGISTRY_TOKEN_RE = re.compile(r"[A-Za-z0-9_.+-]+")


def _is_python_registry_name(value: str) -> bool:
    """Python's own registries define this exact token as a standard name.

    Codec names, codec error handlers and URL schemes are fixed by standards
    and the runtime; a named constant for "utf-8" or "https" only adds
    indirection. The live registries are asked, so codecs or schemes that
    the running Python knows are included and nothing is hard-coded.
    """
    if not _REGISTRY_TOKEN_RE.fullmatch(value):
        return False
    if value in urllib.parse.uses_netloc or value in urllib.parse.uses_relative:
        return True
    for lookup in (codecs.lookup, codecs.lookup_error):
        try:
            lookup(value)
        except (LookupError, ValueError):
            continue
        return True
    return False


def _is_fstring_fragment(node: ast.AST, parent_map: dict[int, ast.AST]) -> bool:
    # The constant pieces of an f-string, its format specs included, are
    # not literals a constant could replace; the f-string is one expression.
    return isinstance(parent_map.get(id(node)), ast.JoinedStr)


def _is_literal_type_member(node: ast.AST, parent_map: dict[int, ast.AST]) -> bool:
    """``Literal[...]`` members are type-checked values, not magic strings."""
    current = node
    while True:
        parent = parent_map.get(id(current))
        if parent is None or isinstance(parent, ast.stmt):
            return False
        if (
            isinstance(parent, ast.Subscript)
            and parent.value is not current
            and _call_name(parent.value).rsplit(".", 1)[-1] == "Literal"
        ):
            return True
        current = parent


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}

    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for element in target.elts:
            names.update(_target_names(element))
        return names

    return set()


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr

    return ""


def _is_container_literal(node: ast.AST) -> bool:
    if isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
        return True

    if isinstance(node, ast.Call):
        call_name = _call_name(node.func)
        return call_name in {"dict", "frozenset", "list", "set", "tuple"}

    return False


def _target_names_are_constant_like(target_names: set[str]) -> bool:
    return any(name.isupper() or name.startswith("_") for name in target_names)


def _is_declaration_level_assignment(
    parent: ast.AST, parent_map: dict[int, ast.AST]
) -> bool:
    # Module and class bodies both declare tables once; a class-level
    # lookup table is the same single declaration as a module-level one.
    grandparent = parent_map.get(id(parent))
    return isinstance(grandparent, (ast.Module, ast.ClassDef))


def _assignment_targets(parent: ast.Assign | ast.AnnAssign) -> set[str]:
    if isinstance(parent, ast.Assign):
        target_names: set[str] = set()
        for target in parent.targets:
            target_names.update(_target_names(target))
        return target_names

    return _target_names(parent.target)


def _assignment_value(parent: ast.Assign | ast.AnnAssign) -> ast.AST | None:
    return parent.value


def _is_declarative_assignment(parent: ast.Assign | ast.AnnAssign) -> bool:
    value = _assignment_value(parent)
    if value is None:
        return False

    if _is_container_literal(value):
        return True

    return _target_names_are_constant_like(_assignment_targets(parent))


def _is_local_scope_node(node: ast.AST) -> bool:
    return isinstance(
        node,
        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
    )


def _receiver_shape(node: ast.AST) -> tuple | None:
    if isinstance(node, ast.Name):
        return ("name", node.id)
    if isinstance(node, ast.Attribute):
        base = _receiver_shape(node.value)
        if base is not None:
            return ("attribute", base, node.attr)
    return None


def _receiver_scope(node: ast.AST, parent_map: dict[int, ast.AST]) -> int | None:
    class_field = (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in {"self", "cls"}
    )
    current = node
    while parent := parent_map.get(id(current)):
        if class_field and isinstance(parent, ast.ClassDef):
            return id(parent)
        if not class_field and isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            return id(parent)
        if isinstance(parent, ast.Module):
            return id(parent)
        current = parent
    return None


def _mapping_receiver_key(
    node: ast.AST, parent_map: dict[int, ast.AST]
) -> tuple[int | None, tuple] | None:
    shape = _receiver_shape(node)
    if shape is None:
        return None
    return (_receiver_scope(node, parent_map), shape)


def _is_mapping_annotation(node: ast.AST) -> bool:
    if isinstance(node, ast.Subscript):
        return _is_mapping_annotation(node.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_mapping_annotation(node.left) or _is_mapping_annotation(node.right)
    if isinstance(node, ast.Name):
        return node.id in {"dict", "Dict", "Mapping", "MutableMapping"}
    return isinstance(node, ast.Attribute) and node.attr in {
        "Dict",
        "Mapping",
        "MutableMapping",
    }


def _bound_receiver_keys(
    target: ast.AST, parent_map: dict[int, ast.AST]
) -> set[tuple[int | None, tuple]]:
    if isinstance(target, (ast.Tuple, ast.List)):
        return {
            key
            for element in target.elts
            for key in _bound_receiver_keys(element, parent_map)
        }
    if isinstance(target, ast.Starred):
        return _bound_receiver_keys(target.value, parent_map)
    key = _mapping_receiver_key(target, parent_map)
    keys = {key} if key is not None else set()
    if isinstance(target, ast.Attribute) and target.attr in {
        "get",
        "pop",
        "setdefault",
        "__class__",
        "__getattribute__",
        "__getattr__",
    }:
        receiver = _mapping_receiver_key(target.value, parent_map)
        if receiver is not None:
            keys.add(receiver)
    return keys


def _mapping_receiver_evidence(
    tree: ast.Module, parent_map: dict[int, ast.AST], call_facts=None
) -> set[tuple[int | None, tuple]]:
    receivers: set[tuple[int | None, tuple]] = set()
    rebound: set[tuple[int | None, tuple]] = set()

    def mapping_value(value):
        if isinstance(value, (ast.Dict, ast.DictComp)):
            return True
        if not isinstance(value, ast.Call) or call_facts is None:
            return False
        return call_facts().is_mapping_constructor(value.func)

    for node in ast.walk(tree):
        candidate: ast.AST | None = None
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, str):
                candidate = node.value
        elif isinstance(node, ast.AnnAssign):
            if _is_mapping_annotation(node.annotation):
                candidate = node.target
            if node.value is not None and not mapping_value(node.value):
                rebound.update(_bound_receiver_keys(node.target, parent_map))
        elif isinstance(node, ast.arg):
            # ``**kwargs`` is always a dict; an annotation can prove others.
            arguments = parent_map.get(id(node))
            if (isinstance(arguments, ast.arguments) and arguments.kwarg is node) or (
                node.annotation is not None and _is_mapping_annotation(node.annotation)
            ):
                candidate = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                keys = _bound_receiver_keys(target, parent_map)
                if mapping_value(node.value):
                    receivers.update(keys)
                else:
                    rebound.update(keys)
        elif isinstance(
            node,
            (ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor, ast.comprehension),
        ):
            rebound.update(_bound_receiver_keys(node.target, parent_map))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            scope = _receiver_scope(node, parent_map)
            if scope is not None:
                rebound.add((scope, ("name", node.name)))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    rebound.update(_bound_receiver_keys(item.optional_vars, parent_map))
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                rebound.update(_bound_receiver_keys(target, parent_map))
        if isinstance(candidate, ast.arg):
            # A parameter's annotation belongs to its containing function.
            scope = _receiver_scope(node, parent_map)
            if scope is not None:
                receivers.add((scope, ("name", node.arg)))
            continue
        if candidate is not None:
            key = _mapping_receiver_key(candidate, parent_map)
            if key is not None:
                receivers.add(key)
    return receivers - rebound


_TYPING_NAMED_DECLARATIONS = frozenset(
    {"TypeVar", "ParamSpec", "TypeVarTuple", "NewType"}
)


class _TypingLiteralCalls:
    """Recognize imported typing operations without trusting their spelling."""

    def __init__(self, tree, modules=None, filename=None, project_root=None):
        modules = _TYPING_MODULES if modules is None else modules
        package = _literal_module_package(filename)
        self.scopes = _ModuleCallables(tree)
        self.bindings = defaultdict(set)
        self.changed_modules = set()
        self.changed_members = set()
        self.dynamic_namespace = False
        self.marker_mutations = None
        local_providers = {}

        def external_module(module):
            if module not in modules:
                return None
            provider = module.split(".", 1)[0]
            if provider not in local_providers:
                local_providers[provider] = project_local_provider(
                    provider, filename, project_root
                )
            return None if local_providers[provider] else module

        for node in ast.walk(tree):
            scope = self.scopes.scope_of.get(node, tree)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = external_module(alias.name)
                    value = (module, None) if module else None
                    self._bind(alias.asname or alias.name.split(".")[0], scope, value)
            elif isinstance(node, ast.ImportFrom):
                module = node.module
                if node.level:
                    parts = package.split(".") if package else []
                    if node.level <= len(parts):
                        prefix = parts[: len(parts) - node.level + 1]
                        module = ".".join([*prefix, *([module] if module else [])])
                    else:
                        module = None
                else:
                    module = external_module(module)
                for alias in node.names:
                    if alias.name == "*":
                        self.dynamic_namespace = True
                    value = (module, alias.name) if module in modules else None
                    self._bind(alias.asname or alias.name, scope, value)
            elif isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                self._bind(node.id, scope, None)
            elif isinstance(node, (*_FUNCTION_NODES, ast.ClassDef)):
                self._bind(node.name, scope, None)
                if isinstance(node, _FUNCTION_NODES):
                    self._bind_parameters(node)
            elif isinstance(node, ast.Lambda):
                self._bind_parameters(node)
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
                if node.name:
                    self._bind(node.name, scope, None)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                self._bind(node.rest, scope, None)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"exec", "eval", "globals", "locals"}:
                    self.dynamic_namespace = True

        for key, values in self.bindings.items():
            if self.scopes.value_refs.get(key):
                # Includes objects nested in registries/containers, returned
                # or yielded, not only direct call arguments and assignments.
                self.changed_members.update(
                    value for value in values if value and value[1] is not None
                )

        # Imported objects passed around or assigned through can be mutated.
        # Track individual exports too: an escaped Integer is not proof that
        # the separate Column callable changed, but a mutated Column is.
        for node in ast.walk(tree):
            expressions = []
            if isinstance(node, ast.Attribute) and node.attr == "__dict__":
                expression = node.value
                while isinstance(expression, (ast.Attribute, ast.Subscript)):
                    expression = expression.value
                expressions.append(expression)
            elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                expression = node.value
                while isinstance(expression, (ast.Attribute, ast.Subscript)):
                    expression = expression.value
                expressions.append(expression)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                expressions.append(node.value)
            elif isinstance(node, ast.Call):
                expressions.extend([*node.args, *(kw.value for kw in node.keywords)])
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                root = node.value
                while isinstance(root, (ast.Attribute, ast.Subscript)):
                    root = root.value
                if isinstance(root, ast.Name) and root.id == "__builtins__":
                    self.changed_modules.add("builtins")
            for expression in expressions:
                if isinstance(expression, ast.Name):
                    values = self._values(expression)
                    for value in values:
                        if not value:
                            continue
                        if value[1] is None:
                            self.changed_modules.add(value[0])
                        else:
                            self.changed_members.add(value)

    def _bind(self, name, scope, value):
        target = self.scopes.resolve(name, scope)
        self.bindings[(target, name)].add(value)

    def _bind_parameters(self, node):
        args = node.args
        for arg in [
            *args.posonlyargs,
            *args.args,
            *args.kwonlyargs,
            args.vararg,
            args.kwarg,
        ]:
            if arg is not None:
                self._bind(arg.arg, node, None)

    def _values(self, node):
        scope = self.scopes.scope_of.get(node)
        target = self.scopes.resolve(node.id, scope)
        return self.bindings.get((target, node.id), ())

    def member(self, expression, modules=None):
        if self.dynamic_namespace:
            return None
        if isinstance(expression, ast.Name):
            root, attribute = expression, None
        elif isinstance(expression, ast.Attribute) and isinstance(
            expression.value, ast.Name
        ):
            root, attribute = expression.value, expression.attr
        else:
            return None
        values = self._values(root)
        if not values or None in values:
            return None
        members = set()
        for module, imported in values:
            if modules is not None and module not in modules:
                return None
            if module in self.changed_modules:
                return None
            if attribute is not None:
                if imported is not None:
                    return None
                if (module, attribute) in self.changed_members:
                    return None
                members.add(attribute)
            else:
                if (module, imported) in self.changed_members:
                    return None
                members.add(imported)
        return next(iter(members)) if len(members) == 1 else None

    def is_builtin_reference(self, expression, name):
        if self.dynamic_namespace or "builtins" in self.changed_modules:
            return False
        if isinstance(expression, ast.Name) and expression.id == name:
            scope = self.scopes.scope_of.get(expression)
            if self.scopes.resolve(name, scope) is None:
                return True
        return self.member(expression, {"builtins"}) == name

    def is_marker(self, expression, name, modules):
        """Direct decorators consume a definition, not an escaping marker.

        The general callable resolver intentionally rejects bare imported
        values. For a known declaration marker, additionally prove unchanged
        imports and reject actual escapes or mutations instead.
        """
        if self.dynamic_namespace:
            return False
        if isinstance(expression, ast.Name):
            root, imported = expression, name
        elif (
            isinstance(expression, ast.Attribute)
            and isinstance(expression.value, ast.Name)
            and expression.attr == name
        ):
            root, imported = expression.value, None
        else:
            return False
        if self.marker_mutations is None:
            self.marker_mutations = _mutated_names(self.scopes.module)
        values = self._values(root)
        return (
            root.id not in self.marker_mutations
            and "*" not in self.marker_mutations
            and bool(values)
            and None not in values
            and all(
                module in modules
                and member == imported
                and module not in self.changed_modules
                for module, member in values
            )
        )

    def is_mapping_constructor(self, expression, seen=()):
        if self.is_builtin_reference(expression, "dict"):
            return True
        if self.member(expression, {"collections"}) in {
            "defaultdict",
            "OrderedDict",
            "UserDict",
        }:
            return True
        if not isinstance(expression, ast.Name) or len(seen) >= 8:
            return False
        scope = self.scopes.resolve(expression.id, self.scopes.scope_of.get(expression))
        key = (scope, expression.id)
        if key in seen or self.scopes.assigned.get(key) or self.scopes.aliases.get(key):
            return False
        classes = self.scopes.classes.get(key, ())
        if len(classes) != 1:
            return False
        definition = classes[0]
        for reference in self.scopes.value_refs.get(key, ()):
            parent = self.scopes.parents.get(reference)
            if not (
                isinstance(parent, ast.ClassDef)
                and any(base is reference for base in parent.bases)
            ):
                # A class object stored, passed, annotated through or mutated
                # is no longer proof of an unchanged dict implementation.
                return False
        if (
            definition.decorator_list
            or definition.keywords
            or len(definition.bases) != 1
        ):
            return False
        for statement in definition.body:
            if isinstance(statement, ast.Pass) or (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            if (
                isinstance(statement, ast.Assign)
                and isinstance(statement.value, ast.Constant)
                and all(
                    isinstance(target, ast.Name) and not target.id.startswith("__")
                    for target in statement.targets
                )
            ):
                continue
            # A custom initializer, method, descriptor or class-body action
            # can rebind lookup methods on an instance. Only plain subclasses
            # establish unchanged dict dispatch without an escape analysis.
            return False
        overrides = self.scopes.bound.get(definition, ())
        if set(overrides) & {
            "get",
            "pop",
            "setdefault",
            "__new__",
            "__init_subclass__",
            "__getattribute__",
            "__getattr__",
            "__contains__",
        }:
            return False
        return self.is_mapping_constructor(definition.bases[0], (*seen, key))

    def is_type_literal(self, node, parent_map):
        call = parent_map.get(id(node))
        if not isinstance(call, ast.Call) or not call.args or call.args[0] is not node:
            return False
        member = self.member(call.func, _TYPING_MODULES)
        if member == "cast":
            try:
                ast.parse(node.value, mode="eval")
            except (SyntaxError, ValueError):
                return False
            return True
        if member in _TYPING_NAMED_DECLARATIONS:
            assignment = parent_map.get(id(call))
            if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                return False
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            return (
                len(targets) == 1
                and isinstance(targets[0], ast.Name)
                and targets[0].id == node.value
            )
        return False


def _literal_module_package(filename):
    """Qualify relative imports from at most sixteen regular package parents."""
    if not filename or not Path(filename).is_absolute():
        return ""
    current = Path(filename).parent
    parts = []
    for _ in range(16):
        marker = current / "__init__.py"
        if current.is_symlink() or marker.is_symlink() or not marker.is_file():
            break
        parts.append(current.name)
        current = current.parent
    return ".".join(reversed(parts))


_CLI_LITERAL_DECLARATIONS = frozenset(
    {
        "add_argument",
        "addoption",
        "_addoption",
        "add_option",
        "add_base_argument",
        "option",
        "argument",
    }
)
_CLI_STANDARD_ACTIONS = frozenset(
    {
        "store",
        "store_const",
        "store_true",
        "store_false",
        "append",
        "append_const",
        "count",
        "help",
        "version",
        "extend",
    }
)
_CLI_DOCUMENTATION_KEYWORDS = frozenset({"help", "short_help", "help_group", "metavar"})
_CATALOG_LITERAL_ARGUMENTS = {
    "gettext": {0},
    "gettext_lazy": {0},
    "gettext_noop": {0},
    "ugettext": {0},
    "ugettext_lazy": {0},
    "ugettext_noop": {0},
    "dgettext": {1},
    "dcgettext": {1},
    "ngettext": {0, 1},
    "ngettext_lazy": {0, 1},
    "ungettext": {0, 1},
    "ungettext_lazy": {0, 1},
    "dngettext": {1, 2},
    "dcngettext": {1, 2},
    "pgettext": {1},
    "pgettext_lazy": {1},
    "npgettext": {1, 2},
    "npgettext_lazy": {1, 2},
}
_DUPLICATE_LITERAL_API_MODULES = frozenset(
    {
        "typing",
        "typing_extensions",
        "operator",
        "gettext",
        "django.utils.translation",
        "flask_babel",
        "sqlalchemy",
        "sqlalchemy.sql",
        "sqlalchemy.sql.schema",
        "sqlalchemy.sql.expression",
        "builtins",
        "collections",
        "types",
        "celery.utils.dispatch",
        "celery.utils.dispatch.signal",
        "django.dispatch",
        "django.dispatch.dispatcher",
        "argparse",
        "starlette.types",
        "asgiref.typing",
    }
)


_ASGI_EVENT_TYPES = frozenset(
    {
        "http.request",
        "http.disconnect",
        "http.response.start",
        "http.response.body",
        "http.response.trailers",
        "websocket.connect",
        "websocket.accept",
        "websocket.receive",
        "websocket.send",
        "websocket.disconnect",
        "websocket.close",
        "lifespan.startup",
        "lifespan.startup.complete",
        "lifespan.startup.failed",
        "lifespan.shutdown",
        "lifespan.shutdown.complete",
        "lifespan.shutdown.failed",
    }
)


class _ProtocolLiteralRoles:
    """Bounded, binding-aware proofs for literal fields of known protocols."""

    def __init__(self, module, context, calls):
        self.module = module
        self.context = context
        self.calls = calls
        self.mutated = None
        self.sources = None
        self.local_asgi = {}

    def argparse_destination(self, node, parents):
        keyword = parents.get(id(node))
        call = parents.get(id(keyword))
        if not (
            isinstance(keyword, ast.keyword)
            and keyword.arg == "dest"
            and node.value.isidentifier()
            and isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "add_argument"
            and isinstance(call.func.value, ast.Name)
        ):
            return False
        if self.mutated is None:
            self.mutated = _mutated_names(self.module)
        facts = self.calls()
        scopes = facts.scopes

        def parser_receiver(expression, seen=()):
            if not isinstance(expression, ast.Name) or len(seen) >= 8:
                return False
            scope = scopes.resolve(expression.id, scopes.scope_of.get(expression))
            key = (scope, expression.id)
            if (
                key in seen
                or expression.id in self.mutated
                or "*" in self.mutated
                or scopes.binding_counts[key] != 1
                or scopes.aliases.get(key)
            ):
                return False
            values = scopes.assigned.get(key, ())
            if len(values) != 1 or not isinstance(values[0], ast.Call):
                return False
            constructor = values[0]
            if constructor.lineno >= expression.lineno:
                return False
            # A parser passed to another consumer or accessed through an
            # unknown operation may have had add_argument replaced.
            if any(
                not (
                    isinstance(scopes.parents.get(reference), ast.Attribute)
                    and scopes.parents[reference].value is reference
                    and isinstance(
                        scopes.parents.get(scopes.parents[reference]), ast.Call
                    )
                    and scopes.parents[scopes.parents[reference]].func
                    is scopes.parents[reference]
                    and scopes.parents[reference].attr
                    in {
                        "add_argument",
                        "add_argument_group",
                        "add_mutually_exclusive_group",
                        "parse_args",
                        "parse_known_args",
                        "print_help",
                        "format_help",
                    }
                )
                for reference in scopes.value_refs.get(key, ())
            ):
                return False
            if facts.member(constructor.func, {"argparse"}) == "ArgumentParser":
                return True
            return (
                isinstance(constructor.func, ast.Attribute)
                and constructor.func.attr
                in {"add_argument_group", "add_mutually_exclusive_group"}
                and parser_receiver(constructor.func.value, (*seen, key))
            )

        return parser_receiver(call.func.value)

    def _annotation_member(self, annotation):
        if not isinstance(annotation, (ast.Name, ast.Attribute)):
            return None
        facts = self.calls()
        # A checkout of the protocol provider is local source, not an external
        # import. Prove the actual aliases instead of trusting its package name.
        root = annotation.value if isinstance(annotation, ast.Attribute) else annotation
        if not isinstance(root, ast.Name):
            return None
        scope = facts.scopes.resolve(root.id, facts.scopes.scope_of.get(root))
        if scope is not self.module:
            return None
        if self.sources is None:
            from skylos.rules.quality._argument_contracts import ArgumentContracts

            self.sources = ArgumentContracts(self.module, self.context, {})
        source = self.sources.main
        imported = source.imports.get(root.id)
        if imported is None or not source.stable(root.id):
            return None
        statement, alias = imported
        if statement.lineno >= annotation.lineno:
            return None
        if isinstance(statement, ast.ImportFrom) and not statement.level:
            module, member = statement.module, alias.name
            if isinstance(annotation, ast.Attribute):
                return None
        elif isinstance(statement, ast.Import) and isinstance(
            annotation, ast.Attribute
        ):
            module, member = alias.name, annotation.attr
            if not alias.asname:
                return None
        else:
            return None
        if member not in {
            "starlette.types": {"Send", "Message"},
            "asgiref.typing": {"ASGISendCallable"},
        }.get(module, ()):
            return None
        if not project_local_provider(
            module.split(".", 1)[0],
            self.context.get("filename"),
            self.context.get("project_root"),
        ):
            return member
        if module != "starlette.types" or not isinstance(statement, ast.ImportFrom):
            return None
        if module not in self.local_asgi:
            provider = self.sources._module(source, statement)
            self.local_asgi[module] = self._asgi_aliases(provider)
        return member if self.local_asgi[module] else None

    def _asgi_aliases(self, source):
        if source is None:
            return False
        facts = _TypingLiteralCalls(
            source.tree,
            {"typing", "collections.abc"},
            source.filename,
            self.context.get("project_root"),
        )
        aliases = {
            statement.targets[0].id: statement.value
            for statement in source.tree.body
            if isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        }
        message, send = aliases.get("Message"), aliases.get("Send")

        def typing_member(expression):
            root = (
                expression.value
                if isinstance(expression, ast.Attribute)
                else expression
            )
            if not isinstance(root, ast.Name) or not source.stable(root.id):
                return None
            imported = source.imports.get(root.id)
            if imported is None:
                return None
            statement, alias = imported
            if statement.lineno >= expression.lineno:
                return None
            if isinstance(statement, ast.ImportFrom) and not statement.level:
                module, member = statement.module, alias.name
                if isinstance(expression, ast.Attribute):
                    return None
            elif isinstance(statement, ast.Import) and isinstance(
                expression, ast.Attribute
            ):
                module, member = alias.name, expression.attr
            else:
                return None
            if module not in {"typing", "collections.abc"} or project_local_provider(
                module.split(".", 1)[0],
                source.filename,
                self.context.get("project_root"),
            ):
                return None
            return member

        if not all(source.stable(name) for name in ("Message", "Send")):
            return False
        if not (
            isinstance(message, ast.Subscript)
            and typing_member(message.value) == "MutableMapping"
            and isinstance(message.slice, ast.Tuple)
            and len(message.slice.elts) == 2
            and facts.is_builtin_reference(message.slice.elts[0], "str")
            and typing_member(message.slice.elts[1]) == "Any"
            and isinstance(send, ast.Subscript)
            and typing_member(send.value) == "Callable"
            and isinstance(send.slice, ast.Tuple)
            and len(send.slice.elts) == 2
        ):
            return False
        parameters, result = send.slice.elts
        return (
            isinstance(parameters, ast.List)
            and len(parameters.elts) == 1
            and isinstance(parameters.elts[0], ast.Name)
            and parameters.elts[0].id == "Message"
            and isinstance(result, ast.Subscript)
            and typing_member(result.value) == "Awaitable"
            and isinstance(result.slice, ast.Constant)
            and result.slice.value is None
        )

    def asgi_discriminator(self, node, parents):
        if node.value not in _ASGI_EVENT_TYPES:
            return False
        mapping = parents.get(id(node))
        if not isinstance(mapping, ast.Dict) or not any(
            value is node and isinstance(key, ast.Constant) and key.value == "type"
            for key, value in zip(mapping.keys, mapping.values)
        ):
            return False
        parent = parents.get(id(mapping))
        if isinstance(parent, ast.AnnAssign) and parent.value is mapping:
            return self._annotation_member(parent.annotation) == "Message"
        if not (
            isinstance(parent, ast.Call)
            and len(parent.args) == 1
            and parent.args[0] is mapping
            and not parent.keywords
            and isinstance(parent.func, ast.Name)
        ):
            return False
        scopes = self.calls().scopes
        scope = scopes.resolve(parent.func.id, scopes.scope_of.get(parent.func))
        if (
            not isinstance(scope, _FUNCTION_NODES)
            or (scope, parent.func.id) in scopes.receiver_writes
        ):
            return False
        parameter = next(
            (
                argument
                for argument in (
                    *scope.args.posonlyargs,
                    *scope.args.args,
                    *scope.args.kwonlyargs,
                )
                if argument.arg == parent.func.id
            ),
            None,
        )
        return parameter is not None and self._annotation_member(
            parameter.annotation
        ) in {"Send", "ASGISendCallable"}


_SCHEMA_LITERAL_MODULES = frozenset(
    {
        "sqlalchemy",
        "sqlalchemy.sql",
        "sqlalchemy.sql.schema",
        "sqlalchemy.sql.expression",
    }
)
_TRANSLATION_LITERAL_MODULES = frozenset(
    {"gettext", "django.utils.translation", "flask_babel"}
)
_SIGNAL_LITERAL_MODULES = frozenset(
    {
        "celery.utils.dispatch",
        "celery.utils.dispatch.signal",
        "django.dispatch",
        "django.dispatch.dispatcher",
    }
)


def _overload_default_literals(module, filename, calls):
    """Repeated defaults describe one callable, not independent runtime values.

    Keep distinct signature-only defaults, incomplete groups and unknown
    decorators. Collapse only the same named literal default also present on
    the concrete implementation of an import-proven overload group.
    """
    result = set()

    def defaults(function):
        positional = (*function.args.posonlyargs, *function.args.args)
        pairs = list(
            zip(
                positional[len(positional) - len(function.args.defaults) :],
                function.args.defaults,
            )
        )
        pairs.extend(zip(function.args.kwonlyargs, function.args.kw_defaults))
        return {
            argument.arg: value
            for argument, value in pairs
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        }

    def imported_marker(function):
        facts = calls()
        for decorator in function.decorator_list:
            if isinstance(decorator, ast.Name):
                values = facts._values(decorator)
                marker = "overload"
            elif (
                isinstance(decorator, ast.Attribute)
                and isinstance(decorator.value, ast.Name)
                and decorator.attr == "overload"
            ):
                values = facts._values(decorator.value)
                marker = None
            else:
                continue
            # The grouping helper already rejects mutation and escaped marker
            # bindings. Its decorator reference is a call, not an export; the
            # import resolver here additionally rejects local provider names.
            if (
                values
                and None not in values
                and all(
                    module_name in _TYPING_MODULES
                    and member == marker
                    and module_name not in facts.changed_modules
                    for module_name, member in values
                )
            ):
                return True
        return False

    for group in overload_groups(module, filename=filename):
        if group.implementation is None:
            continue
        anchor = defaults(group.implementation)
        if not anchor:
            continue
        for signature in group.signatures:
            if not imported_marker(signature):
                continue
            for name, value in defaults(signature).items():
                if name in anchor and value.value == anchor[name].value:
                    result.add(id(value))
    return result


def _is_signal_field_collection(node, parent_map, calls):
    """Only the documented field-name collection of a resolved Signal API."""
    collection = parent_map.get(id(node))
    if not isinstance(collection, (ast.Set, ast.List, ast.Tuple)):
        return False
    keyword = parent_map.get(id(collection))
    if not isinstance(keyword, ast.keyword) or keyword.arg != "providing_args":
        return False
    call = parent_map.get(id(keyword))
    return (
        isinstance(call, ast.Call)
        and calls().member(call.func, _SIGNAL_LITERAL_MODULES) == "Signal"
    )


def _is_collection_wrapper(call, calls):
    if any(
        calls.is_builtin_reference(call.func, name)
        for name in ("dict", "list", "set", "tuple", "frozenset")
    ):
        return True
    if calls.member(call.func, {"collections"}) in {
        "OrderedDict",
        "defaultdict",
        "deque",
        "Counter",
    }:
        return True
    return calls.member(call.func, {"types"}) == "MappingProxyType"


def _is_cli_declaration_literal(node, parent_map):
    """Recognize the argument slot, never just an identifier's spelling.

    Parser wrappers share argparse's declarations, so accept their public
    declaration shape too: a known method and a flag or explicit destination.
    User actions and defaults remain ordinary values, as do arbitrary calls
    with an ``action`` keyword.
    """
    keyword = parent_map.get(id(node))
    if not isinstance(keyword, ast.keyword):
        return False
    call = parent_map.get(id(keyword))
    if not isinstance(call, ast.Call):
        return False
    if _call_name(call.func).rsplit(".", 1)[-1] not in _CLI_LITERAL_DECLARATIONS:
        return False
    has_flag = any(
        isinstance(arg, ast.Constant)
        and isinstance(arg.value, str)
        and arg.value.startswith("-")
        and len(arg.value) > 1
        for arg in call.args
    )
    has_destination = any(
        kw.arg == "dest"
        and isinstance(kw.value, ast.Constant)
        and isinstance(kw.value.value, str)
        for kw in call.keywords
    )
    if not (has_flag or has_destination):
        return False
    if keyword.arg == "action":
        return node.value in _CLI_STANDARD_ACTIONS
    # A destination keyword alone is not proof of a Namespace declaration:
    # custom same-named APIs can consume it as an ordinary application value.
    return keyword.arg in _CLI_DOCUMENTATION_KEYWORDS


def _is_imported_literal_contract(node, parent_map, calls):
    parent = parent_map.get(id(node))
    if not isinstance(parent, ast.Call):
        return False
    member = calls.member(parent.func, {"operator"})
    if member in {"itemgetter", "attrgetter"}:
        # operator selectors name fields just like obj["field"].
        return any(argument is node for argument in parent.args)
    if calls.member(parent.func, _SCHEMA_LITERAL_MODULES) in {
        "Column",
        "Table",
        "column",
        "table",
    }:
        # These constructors declare persistent/schema identifiers. Like dict
        # keys, repeating a field name in distinct schemas needs no constant.
        return bool(parent.args) and parent.args[0] is node
    positions = _CATALOG_LITERAL_ARGUMENTS.get(
        calls.member(parent.func, _TRANSLATION_LITERAL_MODULES), ()
    )
    # gettext extraction needs a literal at these exact msgid positions;
    # replacing one with a constant can remove it from the translation catalog.
    return any(
        position < len(parent.args) and parent.args[position] is node
        for position in positions
    )


_INTERPRETER_PROTOCOL_NAMES = frozenset(
    name
    for builtin in (object, type, str, bytes, list, tuple, dict, set, int, float)
    for name in builtin.__dict__
    if name.startswith("__") and name.endswith("__")
)
_PERCENT_PLACEHOLDER = re.compile(
    r"%(?:\([^)]+\))?[#0 +\-]*(?:\d+|\*)?(?:\.(?:\d+|\*))?[hlL]?[diouxXeEfFgGcrsa%]"
)


def _is_reflection_field_literal(node, parent_map, calls, attribute_names):
    if node.value not in attribute_names:
        return False
    # Private state names can benefit from a shared constant. Interpreter
    # protocol names, unlike arbitrary private slots, have fixed spellings.
    if node.value.startswith("_") and node.value not in _INTERPRETER_PROTOCOL_NAMES:
        return False
    call = parent_map.get(id(node))
    if not isinstance(call, ast.Call):
        return False
    position = _reflection_field_position(call.func, calls)
    return (
        position is not None
        and len(call.args) > position
        and call.args[position] is node
    )


def _reflection_field_position(expression, calls):
    """Resolve immutable builtin attribute operations, including bound aliases.

    A string passed to object.__setattr__.__get__(obj) names the same field
    as obj.field. Unknown setters and reassigned aliases keep their literals.
    """
    if calls.dynamic_namespace or "builtins" in calls.changed_modules:
        return None
    if not hasattr(calls, "_reflection_aliases"):
        aliases = defaultdict(list)
        for (scope, name), values in calls.scopes.assigned.items():
            aliases[(calls.scopes.resolve(name, scope), name)].extend(values)
        calls._reflection_aliases = aliases
        calls._reflection_cache = {}

    def resolve(value, seen=()):
        if value in calls._reflection_cache:
            return calls._reflection_cache[value]
        if len(seen) >= 8:
            return None
        for name in ("getattr", "hasattr", "setattr", "delattr"):
            if calls.is_builtin_reference(value, name):
                return (1, False)
        if (
            isinstance(value, ast.Attribute)
            and value.attr in {"__getattribute__", "__setattr__", "__delattr__"}
            and calls.is_builtin_reference(value.value, "object")
        ):
            return (1, True)
        if isinstance(value, ast.Name):
            scope = calls.scopes.resolve(value.id, calls.scopes.scope_of.get(value))
            key = (scope, value.id)
            values = calls._reflection_aliases.get(key, ())
            if (
                key in seen
                or key in calls.scopes.receiver_unknown_bindings
                or len(values) != 1
            ):
                return None
            assigned = values[0]
            statement = calls.scopes.parents.get(assigned)
            if (
                not isinstance(statement, (ast.Assign, ast.AnnAssign))
                or calls.scopes.parents.get(statement) is not scope
                or assigned.lineno >= value.lineno
            ):
                return None
            return resolve(assigned, (*seen, key))
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "__get__"
            and len(value.args) == 1
            and not value.keywords
            and not isinstance(value.args[0], ast.Starred)
            and resolve(value.func.value, seen) == (1, True)
        ):
            return (0, False)
        return None

    result = resolve(expression)
    calls._reflection_cache[expression] = result
    return result[0] if result is not None else None


def _is_mapping_membership_key(node, parent_map, mapping_receivers):
    comparison = parent_map.get(id(node))
    if not (
        isinstance(comparison, ast.Compare)
        and comparison.left is node
        and len(comparison.ops) == 1
        and isinstance(comparison.ops[0], (ast.In, ast.NotIn))
    ):
        return False
    receiver = comparison.comparators[0]
    return (
        isinstance(receiver, (ast.Dict, ast.DictComp))
        or _mapping_receiver_key(receiver, parent_map) in mapping_receivers
    )


def _is_format_structure_literal(node, parent_map):
    parent = parent_map.get(id(node))
    if (
        isinstance(parent, ast.BinOp)
        and isinstance(parent.op, ast.Mod)
        and parent.left is node
    ):
        rest, count = _PERCENT_PLACEHOLDER.subn("", node.value)
        return count > 0 and not any(character.isalnum() for character in rest)
    if not (
        isinstance(parent, ast.Attribute)
        and parent.value is node
        and parent.attr == "format"
    ):
        return False
    call = parent_map.get(id(parent))
    if not isinstance(call, ast.Call) or call.func is not parent:
        return False
    try:
        parts = list(string.Formatter().parse(node.value))
    except ValueError:
        return False
    return any(field is not None for _, field, _, _ in parts) and not any(
        character.isalnum() for literal, _, _, _ in parts for character in literal
    )


def _all_class_field_declarations(nodes, parent_map):
    """Independent classes declaring the same field are a catalog, not logic.

    Do not drop just one declaration from a mixed group: a declared name plus
    repeated runtime defaults can still have a real consistency problem.
    """
    fields = set()
    classes = set()
    for node in nodes:
        assignment = parent_map.get(id(node))
        if (
            not isinstance(assignment, (ast.Assign, ast.AnnAssign))
            or assignment.value is not node
        ):
            return False
        owner = parent_map.get(id(assignment))
        if not isinstance(owner, ast.ClassDef):
            return False
        names = _assignment_targets(assignment)
        if len(names) != 1:
            return False
        fields.update(names)
        classes.add(id(owner))
    return len(fields) == 1 and len(classes) == len(nodes)


class DuplicateStringLiteralRule(SkylosRule):
    rule_id = "SKY-L027"
    name = "Duplicate String Literal"

    def __init__(self, threshold=3):
        self.threshold = threshold

    def _is_docstring(self, node, parent_map):
        parent = parent_map.get(id(node))
        if parent is None:
            return False
        if isinstance(parent, ast.Expr):
            grandparent = parent_map.get(id(parent))
            if grandparent is not None and isinstance(
                grandparent,
                (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                body = grandparent.body
                if body and body[0] is parent:
                    return True
        return False

    def _is_structural_key_literal(self, node, parent_map, membership_cache=None):
        parent = parent_map.get(id(node))
        if isinstance(parent, ast.Subscript) and parent.slice is node:
            return True
        if isinstance(parent, ast.Dict):
            if membership_cache is None:
                return node in parent.keys
            members = membership_cache.get(id(parent))
            if members is None:
                members = (
                    {id(key) for key in parent.keys},
                    {id(value) for value in parent.values},
                )
                membership_cache[id(parent)] = members
            return id(node) in members[0]
        return False

    def _is_mapping_lookup_key(self, node, parent_map, mapping_receivers):
        parent = parent_map.get(id(node))
        if (
            not isinstance(parent, ast.Call)
            or not parent.args
            or parent.args[0] is not node
        ):
            return False
        func = parent.func
        if not isinstance(func, ast.Attribute) or func.attr not in {
            "get",
            "setdefault",
            "pop",
        }:
            return False
        return _mapping_receiver_key(func.value, parent_map) in mapping_receivers

    def _is_annotation_literal(self, node, parent_map):
        current = node
        type_alias_node = getattr(ast, "TypeAlias", None)

        while True:
            parent = parent_map.get(id(current))
            if parent is None:
                return False

            if isinstance(parent, ast.arg) and parent.annotation is current:
                return True

            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if parent.returns is current:
                    return True

            if isinstance(parent, ast.AnnAssign) and parent.annotation is current:
                return True

            if (
                type_alias_node is not None
                and isinstance(parent, type_alias_node)
                and parent.value is current
            ):
                return True

            current = parent

    def _is_declarative_table_literal(self, node, parent_map, calls=None):
        current = node
        in_collection = False
        wrappers = []

        while True:
            parent = parent_map.get(id(current))
            if parent is None:
                return False

            if _is_local_scope_node(parent):
                return False

            if isinstance(parent, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
                in_collection = True
            elif isinstance(parent, ast.Call):
                wrappers.append(parent)

            if isinstance(parent, (ast.Assign, ast.AnnAssign)):
                if not _is_declaration_level_assignment(parent, parent_map):
                    return False
                if _is_declarative_assignment(parent):
                    return True
                # A collection argument is not proof of a declaration: an
                # arbitrary wrapper may send messages, execute SQL, or do any
                # other runtime work. Only known collection constructors keep
                # the literal's catalog role through the wrapper.
                return (
                    in_collection
                    and bool(wrappers)
                    and calls is not None
                    and all(_is_collection_wrapper(call, calls()) for call in wrappers)
                )

            current = parent

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename", "")
        basename = Path(filename).name

        # Test inputs and expectations repeat by design; examples and
        # benchmarks are not maintained as shipped code.
        if is_non_production_python(filename, context.get("project_root")):
            return None

        parent_map = {}
        for parent in ast.walk(node):
            for child in ast.iter_child_nodes(parent):
                parent_map[id(child)] = parent
        typing_calls = None
        membership_cache = {}
        protocol_roles = None
        precision_occurrences = defaultdict(list)

        def call_facts():
            nonlocal typing_calls
            if typing_calls is None:
                typing_calls = _TypingLiteralCalls(
                    node,
                    _DUPLICATE_LITERAL_API_MODULES,
                    filename,
                    context.get("project_root"),
                )
            return typing_calls

        mapping_receivers = _mapping_receiver_evidence(node, parent_map, call_facts)
        overload_defaults = _overload_default_literals(node, filename, call_facts)
        attribute_names = {
            child.attr for child in ast.walk(node) if isinstance(child, ast.Attribute)
        }
        attribute_names.update(
            child.name
            for child in ast.walk(node)
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and isinstance(parent_map.get(id(child)), ast.ClassDef)
        )
        for definition in ast.walk(node):
            if not isinstance(definition, ast.ClassDef):
                continue
            for statement in definition.body:
                if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                if not any(
                    isinstance(target, ast.Name) and target.id == "__slots__"
                    for target in targets
                ):
                    continue
                value = statement.value
                members = (
                    value.elts
                    if isinstance(value, (ast.Tuple, ast.List, ast.Set))
                    else [value]
                )
                attribute_names.update(
                    member.value
                    for member in members
                    if isinstance(member, ast.Constant)
                    and isinstance(member.value, str)
                )

        string_occurrences = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if id(child) in overload_defaults:
                    continue
                if len(child.value) < 5:
                    continue
                if self._is_docstring(child, parent_map):
                    continue
                if _is_fstring_fragment(child, parent_map):
                    continue
                if self._is_structural_key_literal(child, parent_map, membership_cache):
                    continue
                if self._is_mapping_lookup_key(child, parent_map, mapping_receivers):
                    continue
                if _is_mapping_membership_key(child, parent_map, mapping_receivers):
                    continue
                if _is_format_structure_literal(child, parent_map):
                    continue
                if self._is_annotation_literal(child, parent_map):
                    continue
                if _is_literal_type_member(child, parent_map):
                    continue
                if _is_cli_declaration_literal(child, parent_map):
                    continue
                if child.value in _ASGI_EVENT_TYPES or (
                    isinstance(parent_map.get(id(child)), ast.keyword)
                    and parent_map[id(child)].arg == "dest"
                ):
                    if protocol_roles is None:
                        protocol_roles = _ProtocolLiteralRoles(
                            node, context, call_facts
                        )
                    reason = None
                    if protocol_roles.argparse_destination(child, parent_map):
                        reason = "argparse_namespace_destination"
                    elif protocol_roles.asgi_discriminator(child, parent_map):
                        reason = "typed_asgi_event_discriminator"
                    if reason is not None:
                        precision_occurrences[child.value].append((child, reason))
                        continue
                if _is_signal_field_collection(child, parent_map, call_facts):
                    continue
                parent = parent_map.get(id(child))
                if (
                    isinstance(parent, ast.Call)
                    and parent.args
                    and parent.args[0] is child
                ):
                    if call_facts().is_type_literal(child, parent_map):
                        continue
                if isinstance(parent, ast.Call):
                    if _is_imported_literal_contract(child, parent_map, call_facts()):
                        continue
                    if _is_reflection_field_literal(
                        child, parent_map, call_facts(), attribute_names
                    ):
                        continue
                if self._is_declarative_table_literal(child, parent_map, call_facts):
                    continue
                if _is_duplicate_string_noise(child.value):
                    continue
                key = child.value
                if key not in string_occurrences:
                    string_occurrences[key] = []
                string_occurrences[key].append(child)

        findings = []
        collector = context.get("precision_exclusions")
        if isinstance(collector, list):
            for value, excluded in precision_occurrences.items():
                remaining = string_occurrences.get(value, ())
                if len(excluded) + len(remaining) < self.threshold:
                    continue
                collector.append(
                    {
                        "rule_id": self.rule_id,
                        "file": filename,
                        "line": min(
                            occurrence.lineno
                            for occurrence in (
                                *remaining,
                                *(item[0] for item in excluded),
                            )
                        ),
                        "reason": "protocol_literal_roles",
                        "evidence": {
                            "literal": _duplicate_string_display(value),
                            "before_occurrences": len(excluded) + len(remaining),
                            "after_occurrences": len(remaining),
                            "finding_removed": len(remaining) < self.threshold,
                            "excluded": [
                                {"line": occurrence.lineno, "role": reason}
                                for occurrence, reason in excluded
                            ],
                        },
                    }
                )
        function_scopes = None
        for value, nodes in string_occurrences.items():
            count = len(nodes)
            if count < self.threshold:
                continue
            if _is_python_registry_name(value):
                continue
            if _all_class_field_declarations(nodes, parent_map):
                continue
            severity = "MEDIUM" if count >= 6 else "LOW"
            display = _duplicate_string_display(value)
            if function_scopes is None:
                function_scopes = _duplicate_string_function_scopes(node)
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": severity,
                    "type": "string",
                    "name": display,
                    "simple_name": display,
                    "value": count,
                    "threshold": self.threshold,
                    "message": f"String literal '{display}' repeated {count} times (threshold: {self.threshold}).",
                    "file": filename,
                    "basename": basename,
                    "line": nodes[0].lineno,
                    "col": nodes[0].col_offset,
                    "literal_context": _duplicate_string_context(
                        value, nodes, parent_map, function_scopes, membership_cache
                    ),
                }
            )

        return findings if findings else None


class TooManyReturnsRule(SkylosRule):
    rule_id = "SKY-L028"
    name = "Too Many Returns"

    def __init__(self, threshold=5):
        self.threshold = threshold

    def _count_returns(self, func_node):
        count = 0
        stack = list(func_node.body)
        while stack:
            child = stack.pop()
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Return):
                count += 1
            for attr in ("body", "orelse", "finalbody", "handlers", "cases"):
                block = getattr(child, attr, None)
                if block and isinstance(block, list):
                    stack.extend(block)
        return count

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        if is_non_production_function_scope(context):
            return None

        count = self._count_returns(node)
        if count <= self.threshold:
            return None

        severity = "MEDIUM" if count >= 9 else "LOW"
        filename = context.get("filename", "")

        return [
            {
                "rule_id": self.rule_id,
                "kind": "structure",
                "severity": severity,
                "type": "function",
                "name": node.name,
                "simple_name": node.name,
                "value": count,
                "threshold": self.threshold,
                "message": f"Function has {count} return statements (limit: {self.threshold}). Consider simplifying control flow.",
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]


_BOOLEAN_TRAP_ALLOWED_NAMES = {
    "inplace",
    "reverse",
    "recursive",
    "verbose",
    "debug",
    "force",
    "dry_run",
    "strict",
}


def _property_setter_value_arg(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    positional_args: list[ast.arg],
) -> ast.arg | None:
    setter_decorators = (
        decorator
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Attribute) and decorator.attr == "setter"
    )
    is_matching_setter = any(
        (isinstance(decorator.value, ast.Name) and decorator.value.id == node.name)
        or (
            isinstance(decorator.value, ast.Attribute)
            and decorator.value.attr == node.name
        )
        for decorator in setter_decorators
    )
    if not is_matching_setter:
        return None

    if len(positional_args) < 2:
        return None

    return positional_args[1]


class _BooleanTypeBindings(IterativeNodeVisitor):
    """Names bound in one scope; nested function bodies have their own scope."""

    def __init__(self):
        self.names = set()
        self.global_names = set()

    def visit_Global(self, node):
        self.global_names.update(node.names)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_FunctionDef(self, node):
        self.names.add(node.name)
        for expression in [
            *node.decorator_list,
            *node.args.defaults,
            *node.args.kw_defaults,
        ]:
            if expression is not None:
                self.visit(expression)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.names.add(node.name)
        for expression in [*node.bases, *node.decorator_list]:
            self.visit(expression)

    def visit_Lambda(self, node):
        return None

    def visit_Import(self, node):
        self.names.update(
            alias.asname or alias.name.split(".")[0] for alias in node.names
        )

    def visit_ImportFrom(self, node):
        self.names.update(alias.asname or alias.name for alias in node.names)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_ListComp(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.visit(child.target)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp


_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)
_COMPREHENSION_NODES = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_SCOPE_NODES = (
    ast.Module,
    *_FUNCTION_NODES,
    ast.Lambda,
    ast.ClassDef,
    *_COMPREHENSION_NODES,
)
_TYPING_MODULES = frozenset({"typing", "typing_extensions"})
# Stubs (@overload) and declared overrides (@override) take their parameter
# list from another definition.
_SIGNATURE_MARKERS = frozenset({"overload", "override"})
_BOOL_ANNOTATION_TEXTS = frozenset({"bool", "builtins.bool"})
_MAX_BOOLEAN_BINDING_DEPTH = 64


def _bool_annotation_text(annotation):
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return annotation.value.strip()
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Attribute) and isinstance(annotation.value, ast.Name):
        return f"{annotation.value.id}.{annotation.attr}"
    return None


def _has_name_decorator(func, name):
    return any(
        isinstance(decorator, ast.Name) and decorator.id == name
        for decorator in func.decorator_list
    )


def _callee_call(node, parents):
    """The call that invokes ``node`` in place, also via ``a if c else b``."""
    current = node
    parent = parents.get(current)
    while (isinstance(parent, ast.IfExp) and current is not parent.test) or (
        isinstance(parent, ast.BoolOp)
    ):
        current = parent
        parent = parents.get(current)
    if isinstance(parent, ast.Call) and parent.func is current:
        return parent
    return None


class _ModuleCallables:
    """Per-module facts on whether a def's parameter list is its own API.

    A def whose function object escapes (passed, stored, returned or
    registered) has its signature set by the consumer; an override's is
    set by its base; an @overload stub's by the implementation. Names are
    resolved with Python's scope rules within this module only.
    """

    def __init__(self, tree):
        self.module = tree
        self.parents = {}
        self.scope_of = {}
        self.bound = defaultdict(set)
        self.global_names = defaultdict(set)
        self.nonlocal_names = defaultdict(set)
        self.classes = defaultdict(list)
        self.functions = defaultdict(list)
        self.assigned = defaultdict(list)
        self.parameter_names = defaultdict(set)
        self.binding_counts = defaultdict(int)
        self.unknown_namespaces = set()
        self.attribute_writes = defaultdict(list)
        self.attribute_mutations = []
        self.attribute_dictionary_writes = []
        self.marker_names = set()
        self.typing_modules = set()
        self.identity_class_decorators = set()
        self.value_refs = defaultdict(list)
        self.aliases = defaultdict(set)
        self.name_calls = defaultdict(list)
        self.attribute_calls = defaultdict(list)
        self.attribute_refs = defaultdict(list)
        self._receiver_binding_events = []
        self._bases = {}
        self._subclasses = defaultdict(list)
        name_loads, attribute_loads = self._index(tree)
        self.receiver_writes = set()
        self.receiver_unknown_bindings = set()
        for scope, name, unknown in self._receiver_binding_events:
            key = (self.resolve(name, scope), name)
            self.binding_counts[key] += 1
            self.receiver_writes.add(key)
            if unknown:
                self.receiver_unknown_bindings.add(key)
        self._collect_references(name_loads, attribute_loads)
        self._link_classes()

    def _index(self, tree):
        """One pass: parent, evaluation scope and bindings of every node."""
        parents, scope_of, bound = self.parents, self.scope_of, self.bound
        name_loads, attribute_loads = [], []
        pending = [(child, tree, tree) for child in ast.iter_child_nodes(tree)]
        while pending:
            node, scope, parent = pending.pop()
            parents[node] = parent
            scope_of[node] = scope
            kind = type(node)
            if kind is ast.Name:
                if type(node.ctx) is ast.Load:
                    name_loads.append(node)
                else:
                    # A comprehension's walrus target binds in its enclosing
                    # scope, unlike an ordinary iteration target.
                    if isinstance(parent, ast.NamedExpr):
                        while isinstance(scope, _COMPREHENSION_NODES):
                            scope = scope_of.get(scope, tree)
                        scope_of[node] = scope
                    bound[scope].add(node.id)
                    self._receiver_binding_events.append(
                        (
                            scope,
                            node.id,
                            not isinstance(parent, (ast.Assign, ast.AnnAssign)),
                        )
                    )
                continue
            if kind is ast.Constant:
                continue
            if kind is ast.Attribute:
                if type(node.ctx) is ast.Load:
                    attribute_loads.append(node)
                else:
                    self.attribute_writes[node.attr].append(node)
                pending.append((node.value, scope, node))
                continue
            # Decorators, defaults, annotations and class bases run in the
            # enclosing scope; only the body runs in the def's own scope.
            if kind in _FUNCTION_NODES:
                bound[scope].add(node.name)
                self.functions[(scope, node.name)].append(node)
                self._receiver_binding_events.append((scope, node.name, True))
                self._bind_parameters(node)
                outer = [*node.decorator_list, node.args]
                if node.returns is not None:
                    outer.append(node.returns)
                outer.extend(getattr(node, "type_params", ()))
                pending.extend((child, scope, node) for child in outer)
                pending.extend((child, node, node) for child in node.body)
                continue
            if kind is ast.Lambda:
                self._bind_parameters(node)
                pending.append((node.args, scope, node))
                pending.append((node.body, node, node))
                continue
            if kind is ast.ClassDef:
                bound[scope].add(node.name)
                self.classes[(scope, node.name)].append(node)
                outer = [
                    *node.decorator_list,
                    *node.bases,
                    *node.keywords,
                    *getattr(node, "type_params", ()),
                ]
                pending.extend((child, scope, node) for child in outer)
                pending.extend((child, node, node) for child in node.body)
                continue
            inner = node if kind in _COMPREHENSION_NODES else scope
            pending.extend(
                (child, inner, node)
                for child in ast.iter_child_nodes(node)
                if not isinstance(child, ast.expr_context)
            )
            self._bind_statement(node, kind, scope)
        return name_loads, attribute_loads

    def _bind_parameters(self, func):
        args = func.args
        for arg in [
            *args.posonlyargs,
            *args.args,
            *args.kwonlyargs,
            args.vararg,
            args.kwarg,
        ]:
            if arg is not None:
                self.bound[func].add(arg.arg)
                self.parameter_names[func].add(arg.arg)

    def _bind_statement(self, node, kind, scope):
        if kind is ast.Assign or kind is ast.AnnAssign:
            if node.value is not None:
                targets = node.targets if kind is ast.Assign else [node.target]
                for target in targets:
                    if type(target) is ast.Name:
                        self.assigned[(scope, target.id)].append(node.value)
        elif kind is ast.Import:
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                self.bound[scope].add(name)
                self._receiver_binding_events.append((scope, name, True))
                if alias.name in _TYPING_MODULES:
                    self.typing_modules.add(alias.asname or alias.name)
        elif kind is ast.ImportFrom:
            for alias in node.names:
                if alias.name == "*":
                    self.unknown_namespaces.add(scope)
                    continue
                self.bound[scope].add(alias.asname or alias.name)
                self._receiver_binding_events.append(
                    (scope, alias.asname or alias.name, True)
                )
                if (
                    not node.level
                    and node.module in _TYPING_MODULES
                    and alias.name in _SIGNATURE_MARKERS
                ):
                    self.marker_names.add(alias.asname or alias.name)
                if (
                    not node.level
                    and node.module in _TYPING_MODULES
                    and alias.name == "final"
                ):
                    self.identity_class_decorators.add(
                        (scope, alias.asname or alias.name)
                    )
        elif kind is ast.ExceptHandler:
            if node.name:
                self.bound[scope].add(node.name)
                self._receiver_binding_events.append((scope, node.name, True))
        elif kind is ast.Global:
            self.global_names[scope].update(node.names)
        elif kind is ast.Nonlocal:
            self.nonlocal_names[scope].update(node.names)
        elif kind is ast.MatchAs or kind is ast.MatchStar:
            if node.name:
                self.bound[scope].add(node.name)
                self._receiver_binding_events.append((scope, node.name, True))
        elif kind is ast.MatchMapping:
            if node.rest:
                self.bound[scope].add(node.rest)
                self._receiver_binding_events.append((scope, node.rest, True))
        elif (
            kind is ast.Subscript
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "__dict__"
        ):
            self.attribute_dictionary_writes.append((node.value.value, node.slice))
        elif kind is ast.Call and isinstance(node.func, ast.Name):
            if node.func.id in {"exec", "eval", "globals"}:
                self.unknown_namespaces.add(self.module)
                self.unknown_namespaces.add(scope)
            elif node.func.id in {"locals", "vars"} and not node.args:
                self.unknown_namespaces.add(scope)
            elif node.func.id in {"setattr", "delattr", "vars"} and node.args:
                self.attribute_mutations.append(node)
        elif kind is ast.Call and isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "__dict__"
            ):
                self.attribute_dictionary_writes.append((node.func.value.value, None))

    def resolve(self, name, scope):
        """The scope whose binding ``name`` refers to, or None (builtin)."""
        current, first = scope, True
        while current is not None:
            # Class bodies are visible only to code directly inside them.
            if first or not isinstance(current, ast.ClassDef):
                if name in self.global_names.get(current, ()):
                    module_names = self.bound.get(self.module, ())
                    return self.module if name in module_names else None
                if name in self.bound.get(current, ()) and name not in (
                    self.nonlocal_names.get(current, ())
                ):
                    return current
            first = False
            current = self.scope_of.get(current)
        return None

    def _collect_references(self, name_loads, attribute_loads):
        for node in name_loads:
            target = self.resolve(node.id, self.scope_of[node])
            if target is None:
                continue
            key = (target, node.id)
            call = _callee_call(node, self.parents)
            if call is not None:
                self.name_calls[key].append(call)
                continue
            parent = self.parents.get(node)
            if (
                isinstance(parent, ast.Assign)
                and parent.value is node
                and self.scope_of.get(parent) is target
                and all(isinstance(t, ast.Name) for t in parent.targets)
            ):
                # ``wait = get`` re-exports the same def under another name
                # in the same namespace; calls through it are still calls.
                self.aliases[key].update(t.id for t in parent.targets)
                continue
            self.value_refs[key].append(node)
        for node in attribute_loads:
            call = _callee_call(node, self.parents)
            if call is not None:
                self.attribute_calls[node.attr].append((call, node))
            else:
                self.attribute_refs[node.attr].append(node)

    def _link_classes(self):
        for definitions in self.classes.values():
            for cls in definitions:
                bases = []
                for base in cls.bases:
                    if not isinstance(base, ast.Name):
                        continue
                    target = self.resolve(base.id, self.scope_of[base])
                    bases.extend(
                        candidate
                        for candidate in self.classes.get((target, base.id), ())
                        if candidate is not cls
                    )
                self._bases[cls] = bases
                for base in bases:
                    self._subclasses[base].append(cls)

    def _closure(self, cls, links):
        order, seen = [], {cls}
        pending = list(reversed(links.get(cls, ())))
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            order.append(current)
            pending.extend(reversed(links.get(current, ())))
        return order

    def _defines(self, cls, name):
        return name in self.bound.get(cls, ())

    def _names_for(self, scope, name):
        names, pending = {name}, [name]
        while pending:
            for alias in self.aliases.get((scope, pending.pop()), ()):
                if alias not in names:
                    names.add(alias)
                    pending.append(alias)
        return names

    def _dispatch_classes(self, cls, name):
        """Classes whose ``name`` a lookup on ``cls`` (or a subclass) can reach."""
        result = set()
        for candidate in [cls, *self._closure(cls, self._bases)]:
            if self._defines(candidate, name):
                result.add(candidate)
                break
        result.update(
            sub
            for sub in self._closure(cls, self._subclasses)
            if self._defines(sub, name)
        )
        return result

    def _class_named(self, name, scope, *, strict=False):
        target = self.resolve(name, scope)
        definitions = tuple(self.classes.get((target, name), ())) if target else ()
        if strict and (len(definitions) != 1 or (target, name) in self.receiver_writes):
            return ()
        return definitions

    def _receiver(self, expr, seen=frozenset(), *, strict=False):
        """(classes, is_class) for a receiver this module can type, else ((), False)."""
        if strict and len(seen) >= _MAX_BOOLEAN_BINDING_DEPTH:
            return (), False
        # Call evidence needs a positive identity. Keep the older, broader
        # value-reference lookup for functions whose signatures escape to users.
        if strict and isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
            classes, is_class = self._receiver(expr.func, seen, strict=True)
            return (classes, False) if is_class else ((), False)
        if strict and isinstance(expr, ast.Attribute):
            current, depth = expr, 0
            while isinstance(current, ast.Attribute):
                depth += 1
                if depth > _MAX_BOOLEAN_BINDING_DEPTH:
                    return (), False
                current = current.value
            return self._field_receiver(expr, seen)
        if not isinstance(expr, ast.Name) or expr.id in seen:
            return (), False
        scope = self.scope_of.get(expr)
        target = self.resolve(expr.id, scope) if scope is not None else None
        if target is None:
            return (), False
        if (target, expr.id) in self.classes:
            return self._class_named(expr.id, scope, strict=strict), True
        if not strict and not isinstance(target, _FUNCTION_NODES):
            return (), False
        if isinstance(target, _FUNCTION_NODES):
            args = target.args
            positional = [*args.posonlyargs, *args.args]
            owner = self.scope_of.get(target)
            parameters = [*positional, *args.kwonlyargs]
            if strict and (
                any(arg.arg == expr.id for arg in parameters)
                and (target, expr.id) in self.receiver_writes
            ):
                return (), False
            if (
                positional
                and positional[0].arg == expr.id
                and isinstance(owner, ast.ClassDef)
                and not _has_name_decorator(target, "staticmethod")
            ):
                return (owner,), _has_name_decorator(target, "classmethod")
            parameter = next(
                (arg for arg in parameters if arg.arg == expr.id),
                None,
            )
            if parameter is not None:
                annotation = parameter.annotation
                if isinstance(annotation, ast.Constant) and isinstance(
                    annotation.value, str
                ):
                    name = annotation.value.strip()
                elif isinstance(annotation, ast.Name):
                    name = annotation.id
                else:
                    return (), False
                return self._class_named(name, owner, strict=strict), False
        found = []
        if strict and (target, expr.id) in self.receiver_unknown_bindings:
            return (), False
        for value in self.assigned.get((target, expr.id), ()):
            # ``o = cls(...)`` / ``o = Plugin(...)`` constructs an instance.
            if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)):
                return (), False
            classes, is_class = self._receiver(
                value.func, seen | {expr.id}, strict=strict
            )
            if not classes or strict and not is_class:
                return (), False
            found.extend(classes)
        return tuple(found), False

    def _field_receiver(self, expr, seen):
        """A stable constructor field can retain its local class annotation.

        Unknown writes, descriptors and replacement assignments retain the
        signature-only policy. This does not guess types from attribute names.
        """
        owners, is_class = self._receiver(expr.value, seen, strict=True)
        if len(owners) != 1 or is_class:
            return (), False
        owner = owners[0]
        marker = (owner, expr.attr)
        if marker in seen or owner.bases or not self._stable_class_identity(owner):
            return (), False
        if any(
            self._defines(owner, hook)
            for hook in ("__getattribute__", "__setattr__", "__delattr__")
        ):
            return (), False
        if self._defines(owner, expr.attr):
            return (), False
        writes = []
        for target in self.attribute_writes.get(expr.attr, ()):
            classes, class_receiver = self._receiver(
                target.value, seen | {marker}, strict=True
            )
            if not classes:
                return (), False
            if owner not in classes:
                continue
            if class_receiver or classes != (owner,):
                return (), False
            writes.append(target)
        for call in self.attribute_mutations:
            known_attribute = False
            if call.func.id != "vars" and len(call.args) >= 2:
                attribute = call.args[1]
                if isinstance(attribute, ast.Constant) and attribute.value != expr.attr:
                    continue
                known_attribute = isinstance(attribute, ast.Constant)
            classes, _ = self._receiver(call.args[0], seen | {marker}, strict=True)
            if owner in classes or known_attribute and not classes:
                return (), False
        if self._dictionary_mutation(owner, expr.attr, seen | {marker}):
            return (), False
        if len(writes) != 1:
            return (), False
        target = writes[0]
        assignment = self.parents.get(target)
        method = self.scope_of.get(target)
        if (
            not isinstance(assignment, (ast.Assign, ast.AnnAssign))
            or assignment.value is None
            or not isinstance(method, _FUNCTION_NODES)
            or method.name != "__init__"
            or method.decorator_list
            or self.scope_of.get(method) is not owner
            or assignment not in method.body
        ):
            return (), False
        if any(
            isinstance(child, ast.Return)
            for statement in method.body[: method.body.index(assignment)]
            for child in ast.walk(statement)
        ):
            return (), False
        classes, is_class = self._receiver(
            assignment.value, seen | {marker}, strict=True
        )
        return (classes, False) if classes and not is_class else ((), False)

    def _dictionary_mutation(self, owner, name, seen=frozenset()):
        for receiver, attribute in self.attribute_dictionary_writes:
            if isinstance(attribute, ast.Constant) and attribute.value != name:
                continue
            classes, _ = self._receiver(receiver, seen, strict=True)
            if not classes or any(
                cls is owner or owner in self._closure(cls, self._bases)
                for cls in classes
            ):
                return True
        return False

    def _stable_method_binding(self, owner, name):
        if not self._stable_class_identity(owner) or not self._plain_method_lookup(
            owner
        ):
            return False
        for target in self.attribute_writes.get(name, ()):
            classes, _ = self._receiver(target.value, strict=True)
            if not classes or any(
                cls is owner or owner in self._closure(cls, self._bases)
                for cls in classes
            ):
                return False
        for call in self.attribute_mutations:
            known_attribute = False
            if call.func.id != "vars" and len(call.args) >= 2:
                attribute = call.args[1]
                if isinstance(attribute, ast.Constant) and attribute.value != name:
                    continue
                known_attribute = isinstance(attribute, ast.Constant)
            classes, _ = self._receiver(call.args[0], strict=True)
            if (
                known_attribute
                and not classes
                or any(
                    cls is owner or owner in self._closure(cls, self._bases)
                    for cls in classes
                )
            ):
                return False
        return not self._dictionary_mutation(owner, name)

    def _plain_method_lookup(self, owner):
        return not any(
            self._defines(cls, "__getattribute__")
            for cls in (owner, *self._closure(owner, self._bases))
        )

    def _stable_class_identity(self, owner, seen=frozenset()):
        if owner.keywords or owner in seen or len(seen) >= _MAX_BOOLEAN_BINDING_DEPTH:
            return False
        for decorator in owner.decorator_list:
            if not isinstance(decorator, ast.Name):
                return False
            target = self.resolve(decorator.id, self.scope_of.get(decorator))
            key = (target, decorator.id)
            if (
                key not in self.identity_class_decorators
                or self.binding_counts.get(key) != 1
            ):
                return False
        for base in owner.bases:
            if not isinstance(base, ast.Name):
                return False
            scope = self.scope_of.get(base)
            if base.id == "object" and self.resolve(base.id, scope) is None:
                continue
            classes = self._class_named(base.id, scope, strict=True)
            if len(classes) != 1 or not self._stable_class_identity(
                classes[0], seen | {owner}
            ):
                return False
        return True

    def _stable_callable(self, func):
        scope = self.scope_of.get(func)
        key = (scope, func.name)
        if (
            self.functions.get(key) != [func]
            or self.binding_counts.get(key) != 1
            or self.classes.get(key)
            or func.name in self.parameter_names.get(scope, ())
            or scope in self.unknown_namespaces
            or self.module in self.unknown_namespaces
        ):
            return False
        if isinstance(scope, ast.ClassDef):
            for name in self._names_for(scope, func.name):
                for reference in self.attribute_refs.get(name, ()):
                    classes, _ = self._receiver(reference.value, strict=True)
                    if any(
                        scope in self._dispatch_classes(cls, name) for cls in classes
                    ):
                        # A newly resolved field may expose a callback binding
                        # the legacy signature policy could not identify. Keep
                        # its declaration advice without promoting bare calls.
                        return False
        return all(
            isinstance(decorator, ast.Name)
            and decorator.id in {"staticmethod", "classmethod"}
            and self.resolve(decorator.id, scope) is None
            for decorator in func.decorator_list
        )

    def _stable_call_names(self, func):
        """Single-definition names and unchanged local aliases of that def."""
        scope = self.scope_of.get(func)
        names = {func.name}
        pending = [func.name]
        while pending:
            for alias in self.aliases.get((scope, pending.pop()), ()):
                key = (scope, alias)
                values = self.assigned.get(key, ())
                if (
                    alias in names
                    or self.binding_counts.get(key) != 1
                    or self.functions.get(key)
                    or self.classes.get(key)
                    or alias in self.parameter_names.get(scope, ())
                    or len(values) != 1
                    or not isinstance(values[0], ast.Name)
                    or values[0].id not in names
                ):
                    continue
                names.add(alias)
                pending.append(alias)
        return names

    def has_signature_marker(self, func):
        for decorator in func.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id in self.marker_names:
                return True
            if (
                isinstance(decorator, ast.Attribute)
                and decorator.attr in _SIGNATURE_MARKERS
                and isinstance(decorator.value, ast.Name)
                and decorator.value.id in self.typing_modules
            ):
                return True
        return False

    def overrides_local_base(self, func):
        cls = self.scope_of.get(func)
        if not isinstance(cls, ast.ClassDef):
            return False
        return any(
            self._defines(base, func.name) for base in self._closure(cls, self._bases)
        )

    def is_value_referenced(self, func):
        scope = self.scope_of.get(func)
        if scope is None:
            return False
        # ``@name.setter`` on def ``name`` refers to the earlier binding.
        own = {
            id(node)
            for decorator in func.decorator_list
            for node in ast.walk(decorator)
        }
        names = self._names_for(scope, func.name)
        for name in names:
            if any(
                id(ref) not in own for ref in self.value_refs.get((scope, name), ())
            ):
                return True
        if not isinstance(scope, ast.ClassDef):
            return False
        for name in names:
            for node in self.attribute_refs.get(name, ()):
                if id(node) in own:
                    continue
                classes, _ = self._receiver(node.value)
                if any(scope in self._dispatch_classes(cls, name) for cls in classes):
                    return True
        return False

    def needs_call_evidence(self, func):
        scope = self.scope_of.get(func)
        nested = isinstance(scope, (*_FUNCTION_NODES, ast.Lambda))
        return nested or func.name.startswith("_")

    def positional_bool_calls(self, func, index, *, strict=False):
        """Static bindings of bare Boolean literals to parameter ``index``."""
        if strict and not self._stable_callable(func):
            return []
        scope = self.scope_of.get(func)
        names = (
            self._stable_call_names(func)
            if strict
            else self._names_for(scope, func.name)
        )
        calls = [
            (call, 0, {"binding": "local_definition", "callee": name})
            for name in names
            for call in self.name_calls.get((scope, name), ())
            if not strict or isinstance(call.func, ast.Name) and call.func.id == name
        ]
        if isinstance(scope, ast.ClassDef):
            static = _has_name_decorator(func, "staticmethod")
            classmethod_ = _has_name_decorator(func, "classmethod")
            for name in names:
                for call, node in self.attribute_calls.get(name, ()):
                    if strict and (
                        call.func is not node
                        or not self._stable_method_binding(scope, name)
                    ):
                        continue
                    classes, is_class = self._receiver(node.value, strict=True)
                    if strict and not all(
                        self._stable_class_identity(cls)
                        and self._plain_method_lookup(cls)
                        for cls in classes
                    ):
                        continue
                    if not classes or not all(
                        self._dispatch_classes(cls, name) == {scope}
                        if strict
                        else scope in self._dispatch_classes(cls, name)
                        for cls in classes
                    ):
                        continue
                    # ``obj.m(x)`` and ``cls.cm(x)`` bind the first parameter.
                    bound = classmethod_ or (not static and not is_class)
                    calls.append(
                        (
                            call,
                            1 if bound else 0,
                            {
                                "binding": "constructor_field"
                                if isinstance(node.value, ast.Attribute)
                                else "static_receiver",
                                "callee": node.attr,
                                "receiver_classes": sorted(
                                    {cls.name for cls in classes}
                                ),
                            },
                        )
                    )
        evidence = {}
        positional_parameters = [*func.args.posonlyargs, *func.args.args]
        parameter = positional_parameters[index]
        for call, offset, binding in calls:
            position = index - offset
            if position < 0:
                continue
            positional = []
            for arg in call.args:
                if isinstance(arg, ast.Starred):
                    break
                positional.append(arg)
            if position < len(positional):
                arg = positional[position]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, bool):
                    if (
                        strict
                        and parameter not in func.args.posonlyargs
                        and any(
                            keyword.arg == parameter.arg for keyword in call.keywords
                        )
                    ):
                        continue
                    if (
                        strict
                        and not func.args.vararg
                        and not any(isinstance(item, ast.Starred) for item in call.args)
                        and len(call.args) + offset > len(positional_parameters)
                    ):
                        continue
                    evidence[(arg.lineno, arg.value)] = {
                        "kind": "positional_boolean_literal",
                        "line": arg.lineno,
                        "value": arg.value,
                        **binding,
                    }
        return [evidence[key] for key in sorted(evidence)]


class BooleanTrapRule(SkylosRule):
    rule_id = "SKY-L029"
    name = "Boolean Trap"

    # These contracts exclude bool instances. Numeric/object annotations do
    # not: bool is an int subclass, and object explicitly includes bool.
    _NON_BOOLEAN_BUILTINS = frozenset(
        {
            "str",
            "bytes",
            "bytearray",
            "memoryview",
            "list",
            "tuple",
            "set",
            "frozenset",
            "dict",
            "range",
            "slice",
            "type",
        }
    )
    _KNOWN_BUILTINS = _NON_BOOLEAN_BUILTINS | {"bool", "int", "object"}
    _GENERIC_BUILTINS = frozenset({"list", "tuple", "set", "frozenset", "dict", "type"})

    def __init__(self):
        self._parents = {}
        self._module = None
        self._callables = None
        self._non_production = False
        self._bool_annotation_cache = {}
        self._intact_cache = {}

    def _module_callables(self):
        # Built on the first candidate parameter only: a module without
        # one pays for no parent map or scope index.
        if self._callables is None and self._module is not None:
            self._callables = _ModuleCallables(self._module)
            self._parents = self._callables.parents
        return self._callables

    @staticmethod
    def _definition_effect_nodes(node):
        pending = [node]
        while pending:
            node = pending.pop()
            yield node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                # Bodies do not run at declaration time; defaults, annotations
                # and decorators do. Class bodies still execute normally.
                expressions = [node.args]
                if not isinstance(node, ast.Lambda):
                    expressions.extend(node.decorator_list)
                    if node.returns is not None:
                        expressions.append(node.returns)
            else:
                expressions = list(ast.iter_child_nodes(node))
            pending.extend(reversed(expressions))

    @classmethod
    def _module_namespace_may_change(cls, statement, name):
        def root_name(expression):
            while isinstance(expression, (ast.Attribute, ast.Subscript)):
                expression = expression.value
            return expression.id if isinstance(expression, ast.Name) else None

        for node in cls._definition_effect_nodes(statement):
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if root_name(node) == name:
                    return True
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                # A captured type attribute is independent of later module
                # mutations; an alias of the module itself can mutate it.
                if isinstance(node.value, ast.Name) and node.value.id == name:
                    return True
            if isinstance(node, ast.Call):
                if root_name(node.func) == name:
                    return True
                if any(
                    isinstance(arg, ast.Name)
                    and arg.id == name
                    or root_name(arg) == name
                    and any(
                        isinstance(child, ast.Attribute) and child.attr == "__dict__"
                        for child in ast.walk(arg)
                    )
                    for arg in [*node.args, *(kw.value for kw in node.keywords)]
                ):
                    return True
        return False

    def _builtin_namespace_is_intact(self, location):
        # The proof rescans every statement before ``location``; it depends
        # only on the tree, so one answer per location serves the module.
        key = id(location)
        if key not in self._intact_cache:
            self._intact_cache[key] = self._scan_builtin_namespace(location)
        return self._intact_cache[key]

    def _scan_builtin_namespace(self, location):
        prefixes = []
        current = location
        while current in self._parents:
            parent = self._parents[current]
            for field in ("body", "orelse", "finalbody"):
                statements = getattr(parent, field, None)
                if isinstance(statements, list) and current in statements:
                    prefixes.append(statements[: statements.index(current)])
            current = parent

        module_aliases = {"__builtins__"}
        for statements in reversed(prefixes):
            for statement in statements:
                for node in self._definition_effect_nodes(statement):
                    if isinstance(node, ast.Import):
                        module_aliases.update(
                            alias.asname or alias.name
                            for alias in node.names
                            if alias.name == "builtins"
                        )
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id in {"exec", "eval", "globals", "locals"}
                    ):
                        # Dynamic namespace access refutes a positive builtin
                        # identity proof. Do not interpret or execute its input.
                        return False
                if any(
                    self._module_namespace_may_change(statement, alias)
                    for alias in module_aliases
                ):
                    return False
        return True

    def _builtin_annotation_type(self, annotation, location, seen=()):
        if len(seen) >= 12:
            return None
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            try:
                expression = ast.parse(annotation.value, mode="eval").body
            except (SyntaxError, ValueError):
                return None
            return self._builtin_annotation_type(
                expression, location, (*seen, "quoted")
            )
        if isinstance(annotation, ast.Subscript):
            origin = self._builtin_annotation_type(annotation.value, location, seen)
            return origin if origin in self._GENERIC_BUILTINS else None
        if isinstance(annotation, ast.Name):
            name, attribute = annotation.id, None
        elif (
            isinstance(annotation, ast.Attribute)
            and isinstance(annotation.value, ast.Name)
            and annotation.attr in self._KNOWN_BUILTINS
        ):
            name, attribute = annotation.value.id, annotation.attr
        else:
            return None
        if attribute is not None and not self._builtin_namespace_is_intact(location):
            return None
        marker = (name, id(location))
        if marker in seen:
            return None
        current = location
        in_function = False
        while current in self._parents:
            parent = self._parents[current]
            if isinstance(parent, ast.ClassDef) and in_function:
                current = parent
                continue
            scope_bindings = None
            if isinstance(
                parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                scope_bindings = _BooleanTypeBindings()
                for statement in parent.body:
                    scope_bindings.visit(statement)
            for field in ("body", "orelse", "finalbody"):
                statements = getattr(parent, field, None)
                if not isinstance(statements, list) or current not in statements:
                    continue
                for statement in reversed(statements[: statements.index(current)]):
                    if attribute is not None and self._module_namespace_may_change(
                        statement, name
                    ):
                        return None
                    bindings = _BooleanTypeBindings()
                    bindings.visit(statement)
                    if name not in bindings.names and "*" not in bindings.names:
                        continue
                    if (
                        isinstance(statement, (ast.Assign, ast.AnnAssign))
                        and attribute is None
                    ):
                        targets = (
                            statement.targets
                            if isinstance(statement, ast.Assign)
                            else [statement.target]
                        )
                        if any(
                            isinstance(target, ast.Name) and target.id == name
                            for target in targets
                        ):
                            return self._builtin_annotation_type(
                                statement.value, statement, (*seen, marker)
                            )
                    if isinstance(statement, ast.ImportFrom) and not statement.level:
                        if (
                            attribute is None
                            and statement.module == "builtins"
                            and self._builtin_namespace_is_intact(statement)
                        ):
                            return next(
                                (
                                    alias.name
                                    for alias in statement.names
                                    if alias.name in self._KNOWN_BUILTINS
                                    and (alias.asname or alias.name) == name
                                ),
                                None,
                            )
                        return None
                    if isinstance(statement, ast.Import):
                        is_builtin_module = any(
                            alias.name == "builtins"
                            and (alias.asname or alias.name) == name
                            for alias in statement.names
                        )
                        return attribute if is_builtin_module else None
                    return None
            if scope_bindings is not None and name in scope_bindings.global_names:
                # Annotation expressions obey the defining scope's global
                # declaration. Skip intervening closure/class bindings, while
                # retaining any earlier assignment found in this scope above.
                while current in self._parents and not isinstance(
                    self._parents[current], ast.Module
                ):
                    current = self._parents[current]
                continue
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                in_function = True
                args = parent.args
                parameters = [
                    *args.posonlyargs,
                    *args.args,
                    *args.kwonlyargs,
                    args.vararg,
                    args.kwarg,
                ]
                if any(arg is not None and arg.arg == name for arg in parameters):
                    return None
                bindings = scope_bindings or _BooleanTypeBindings()
                if name in bindings.names or "*" in bindings.names:
                    return None
            current = parent
        if (
            name in self._KNOWN_BUILTINS
            and attribute is None
            and self._builtin_namespace_is_intact(location)
        ):
            return name
        return None

    def _boolean_type(self, annotation, location):
        # Only these spellings can name the builtin; any other annotation
        # skips the scope proof, which rescans the enclosing statements.
        text = _bool_annotation_text(annotation)
        if text not in _BOOL_ANNOTATION_TEXTS:
            return False
        key = (text, id(location))
        if key not in self._bool_annotation_cache:
            self._module_callables()
            self._bool_annotation_cache[key] = (
                self._builtin_annotation_type(annotation, location) == "bool"
            )
        return self._bool_annotation_cache[key]

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self._parents = {}
            self._module = node
            self._callables = None
            self._bool_annotation_cache = {}
            self._intact_cache = {}
            # A test or example signature is not an API others call.
            self._non_production = is_non_production_python(
                context.get("filename"), context.get("project_root")
            )
            return None
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        if self._non_production:
            return None

        func_name = node.name
        if func_name.startswith("__") and func_name.endswith("__"):
            return None

        args = node.args
        positional_args = [*args.posonlyargs, *args.args]
        setter_value_arg = _property_setter_value_arg(node, positional_args)

        num_defaults = len(args.defaults)
        num_positional = len(positional_args)

        findings = []
        candidates = []
        filename = context.get("filename", "")

        for i, arg in enumerate(positional_args):
            arg_name = arg.arg
            if arg_name in ("self", "cls"):
                continue
            if arg is setter_value_arg:
                continue
            is_bool_trap = False

            if arg.annotation is not None:
                # An annotation is evaluated in the defining scope, so this
                # function's own parameters do not shadow builtin bool here.
                is_bool_trap = self._boolean_type(arg.annotation, node)

            # A literal Boolean default is independent signature evidence.
            # An incompatible annotation does not remove that runtime value.
            if not is_bool_trap and num_defaults > 0:
                default_index = i - (num_positional - num_defaults)
                if 0 <= default_index < num_defaults:
                    default = args.defaults[default_index]
                    if isinstance(default, ast.Constant) and isinstance(
                        default.value, bool
                    ):
                        is_bool_trap = True

            if is_bool_trap:
                candidates.append((i, arg))

        if not candidates:
            return None

        callables = self._module_callables()
        needs_evidence = False
        if callables is not None:
            if (
                callables.has_signature_marker(node)
                or callables.overrides_local_base(node)
                or callables.is_value_referenced(node)
            ):
                return None
            # A private or nested def is not an API: only a call in this
            # module that passes a bare literal shows a trap to fix.
            needs_evidence = callables.needs_call_evidence(node)

        for i, arg in candidates:
            arg_name = arg.arg
            # Familiar public flags keep the existing signature exemption.
            # Private flags need an actual bare literal call to be advice.
            if arg_name in _BOOLEAN_TRAP_ALLOWED_NAMES and not needs_evidence:
                continue
            positional_only = i < len(args.posonlyargs)
            evidence = (
                callables.positional_bool_calls(
                    node,
                    i,
                    strict=not needs_evidence
                    or arg_name in _BOOLEAN_TRAP_ALLOWED_NAMES,
                )
                if callables
                else []
            )
            if needs_evidence and not evidence:
                continue
            message = f"Boolean parameter '{arg_name}' permits positional calls, which can obscure their meaning. Prefer named calls; consider keyword-only arguments when the public or callback contract permits it."
            if positional_only:
                message = f"Boolean parameter '{arg_name}' is positional-only, so calls cannot name it. Consider a descriptive enum or a separate named operation when the public or callback contract permits it."
            if evidence:
                sites = ", ".join(
                    f"{site['value']} at line {site['line']}" for site in evidence[:3]
                )
                if len(evidence) > 3:
                    sites += f" (+{len(evidence) - 3} more)"
                message = f"Boolean parameter '{arg_name}' is called positionally with {sites}; the bare literal does not say what it controls. Pass it by keyword, or make the parameter keyword-only."
                if positional_only:
                    message = f"Boolean parameter '{arg_name}' is called positionally with {sites}; the bare literal does not say what it controls. This parameter is positional-only; consider a descriptive enum or a separate named operation when the contract permits it."
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": "LOW",
                    "type": "function",
                    "name": f"{func_name}.{arg_name}",
                    "simple_name": arg_name,
                    "value": arg_name,
                    "threshold": 0,
                    "message": message,
                    "file": filename,
                    "basename": Path(filename).name,
                    "line": arg.lineno if hasattr(arg, "lineno") else node.lineno,
                    "col": arg.col_offset
                    if hasattr(arg, "col_offset")
                    else node.col_offset,
                }
            )
            if evidence:
                findings[-1]["call_evidence"] = evidence

        return findings if findings else None


class BroadExceptionRule(SkylosRule):
    rule_id = "SKY-L030"
    name = "Broad Exception with Trivial Handler"

    _BROAD_EXCEPTION_TYPES = {"Exception", "BaseException"}

    def visit_node(self, node, context):
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            return None

        broad_types = [
            exc_name
            for exc_name in _exception_type_names(node.type)
            if exc_name in self._BROAD_EXCEPTION_TYPES
        ]
        if not broad_types:
            return None
        if _handler_has_real_work(node.body):
            return None
        if not _handler_body_is_trivial(node.body):
            return None
        # Empty handlers are already reported by SKY-L007. A placeholder
        # return is a separate broad-exception fallback worth reporting here.
        if not any(isinstance(stmt, ast.Return) for stmt in node.body):
            return None

        exc_name = ", ".join(sorted(set(broad_types)))

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "HIGH",
                "type": "block",
                "name": "except",
                "simple_name": "except",
                "value": "broad",
                "threshold": 0,
                "message": f"Catching broad '{exc_name}' with a trivial handler silently hides bugs. Narrow the exception type or add logging/re-raise.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]


_NO_EFFECT_EXPR_TYPES = (
    ast.BinOp,
    ast.BoolOp,
    ast.Compare,
    ast.Dict,
    ast.IfExp,
    ast.List,
    ast.Name,
    ast.Set,
    ast.Tuple,
    ast.UnaryOp,
)

_PURE_DISCARDED_CALLS = {
    "uuid.uuid1",
    "uuid.uuid3",
    "uuid.uuid4",
    "uuid.uuid5",
}

_UNKNOWN_EXPRESSION = object()
_RAISING_EXPRESSION = object()
_LITERAL_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.BitOr: operator.or_,
    ast.BitAnd: operator.and_,
    ast.BitXor: operator.xor,
}
_LITERAL_COMPARISONS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
    ast.In: lambda left, right: left in right,
    ast.NotIn: lambda left, right: left not in right,
}


def _bounded_literal(value):
    if isinstance(value, int):
        return value.bit_length() <= 256
    if isinstance(value, (str, bytes, list, tuple, set, dict)):
        return len(value) <= 256
    return True


def _literal_expression_value(node, budget=None):
    """Evaluate only small built-in literals, never target objects or calls."""
    if budget is None:
        budget = [128]
    budget[0] -= 1
    if budget[0] < 0:
        return _UNKNOWN_EXPRESSION
    if isinstance(node, ast.Constant):
        return node.value if _bounded_literal(node.value) else _UNKNOWN_EXPRESSION
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [_literal_expression_value(child, budget) for child in node.elts]
        if any(value is _RAISING_EXPRESSION for value in values):
            return _RAISING_EXPRESSION
        if any(value is _UNKNOWN_EXPRESSION for value in values):
            return _UNKNOWN_EXPRESSION
        constructor = {ast.List: list, ast.Tuple: tuple, ast.Set: set}[type(node)]
        try:
            return constructor(values)
        except TypeError:
            return _RAISING_EXPRESSION
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            return _UNKNOWN_EXPRESSION
        keys = [_literal_expression_value(child, budget) for child in node.keys]
        values = [_literal_expression_value(child, budget) for child in node.values]
        if any(value is _RAISING_EXPRESSION for value in [*keys, *values]):
            return _RAISING_EXPRESSION
        if any(value is _UNKNOWN_EXPRESSION for value in [*keys, *values]):
            return _UNKNOWN_EXPRESSION
        try:
            return dict(zip(keys, values))
        except TypeError:
            return _RAISING_EXPRESSION
    if isinstance(node, ast.UnaryOp):
        operand = _literal_expression_value(node.operand, budget)
        if operand is _UNKNOWN_EXPRESSION or operand is _RAISING_EXPRESSION:
            return operand
        operation = {
            ast.UAdd: operator.pos,
            ast.USub: operator.neg,
            ast.Invert: operator.invert,
            ast.Not: operator.not_,
        }.get(type(node.op))
        operands = [operand]
    elif isinstance(node, ast.BinOp):
        operands = [
            _literal_expression_value(node.left, budget),
            _literal_expression_value(node.right, budget),
        ]
        if any(value is _RAISING_EXPRESSION for value in operands):
            return _RAISING_EXPRESSION
        if any(value is _UNKNOWN_EXPRESSION for value in operands):
            return _UNKNOWN_EXPRESSION
        operation = _LITERAL_BINARY_OPERATORS.get(type(node.op))
        if isinstance(node.op, ast.Mod) and isinstance(operands[0], (str, bytes)):
            # A short format string can request an arbitrarily large allocation.
            return _UNKNOWN_EXPRESSION
        if isinstance(node.op, ast.Mult):
            for sequence, count in (operands, operands[::-1]):
                if isinstance(sequence, (str, bytes, list, tuple)) and isinstance(
                    count, int
                ):
                    if len(sequence) * max(0, count) > 256:
                        return _UNKNOWN_EXPRESSION
    elif isinstance(node, ast.Compare):
        if len(node.ops) != 1:
            return _UNKNOWN_EXPRESSION
        operands = [
            _literal_expression_value(node.left, budget),
            _literal_expression_value(node.comparators[0], budget),
        ]
        if any(value is _RAISING_EXPRESSION for value in operands):
            return _RAISING_EXPRESSION
        if any(value is _UNKNOWN_EXPRESSION for value in operands):
            return _UNKNOWN_EXPRESSION
        operation = _LITERAL_COMPARISONS.get(type(node.ops[0]))
    else:
        return _UNKNOWN_EXPRESSION
    if operation is None:
        return _UNKNOWN_EXPRESSION
    try:
        result = operation(*operands)
    except (ArithmeticError, TypeError, ValueError):
        return _RAISING_EXPRESSION
    return result if _bounded_literal(result) else _UNKNOWN_EXPRESSION


def _scope_import_bindings(scope):
    bindings = {}

    def record(name, target=None):
        if name in bindings and bindings[name] != target:
            bindings[name] = None
        else:
            bindings[name] = target

    class Bindings(IterativeNodeVisitor):
        def visit_Name(self, node):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                record(node.id)

        def visit_Import(self, node):
            for alias in node.names:
                record(alias.asname or alias.name.split(".")[0], alias.name)

        def visit_ImportFrom(self, node):
            for alias in node.names:
                record(
                    alias.asname or alias.name,
                    f"{node.module}.{alias.name}" if not node.level else None,
                )

        def visit_FunctionDef(self, node):
            record(node.name)
            for expression in [
                *node.decorator_list,
                *node.args.defaults,
                *node.args.kw_defaults,
            ]:
                if expression is not None:
                    self.visit(expression)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            record(node.name)
            for expression in [*node.bases, *node.keywords, *node.decorator_list]:
                self.visit(expression)

        def visit_Lambda(self, node):
            for expression in [*node.args.defaults, *node.args.kw_defaults]:
                if expression is not None:
                    self.visit(expression)

        def visit_ListComp(self, node):
            # Targets are comprehension-local; walruses in evaluated expressions
            # can bind in the containing scope.
            for generator in node.generators:
                self.visit(generator.iter)
                for condition in generator.ifs:
                    self.visit(condition)
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                self.visit(node.value)
            else:
                self.visit(node.elt)

        visit_SetComp = visit_ListComp
        visit_DictComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp

        def visit_ExceptHandler(self, node):
            if node.name:
                record(node.name)
            self.generic_visit(node)

    visitor = Bindings()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for argument in [
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
            scope.args.vararg,
            scope.args.kwarg,
        ]:
            if argument is not None:
                record(argument.arg)
    for statement in scope.body:
        visitor.visit(statement)
    return bindings


def _exception_probe_expressions(module):
    parents = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    bindings = {}
    global_writes = set()
    for function in ast.walk(module):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        declared_globals = set()
        stack = list(function.body)
        while stack:
            child = stack.pop()
            if isinstance(child, ast.Global):
                declared_globals.update(child.names)
            elif not isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                stack.extend(ast.iter_child_nodes(child))
        global_writes.update(declared_globals & _scope_import_bindings(function).keys())

    def resolve_import(name, node):
        in_function = False
        while node is not None:
            if isinstance(
                node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                if not (in_function and isinstance(node, ast.ClassDef)):
                    if isinstance(node, ast.Module) and name in global_writes:
                        return None
                    if node not in bindings:
                        bindings[node] = _scope_import_bindings(node)
                    scope_bindings = bindings[node]
                    if "*" in scope_bindings:
                        return None
                    if name in scope_bindings:
                        return scope_bindings[name]
                in_function |= isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            node = parents.get(node)
        return None

    helper_overwritten = False
    for node in ast.walk(module):
        if not (
            isinstance(node, ast.Attribute)
            and node.attr == "raises"
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            continue
        receiver = _qualified_call_name(node.value)
        if not receiver:
            continue
        root, _, suffix = receiver.partition(".")
        target = resolve_import(root, node)
        if target and ".".join(filter(None, (target, suffix))) == "pytest":
            helper_overwritten = True
            break

    probes = set()
    for node in ast.walk(module):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        for item in node.items:
            call = item.context_expr
            if not isinstance(call, ast.Call):
                continue
            name = _qualified_call_name(call.func)
            if not name:
                continue
            root, _, suffix = name.partition(".")
            target = resolve_import(root, node)
            if (
                helper_overwritten
                or not target
                or ".".join(filter(None, (target, suffix))) != "pytest.raises"
            ):
                continue
            stack = list(node.body)
            while stack:
                child = stack.pop()
                if isinstance(
                    child,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
                ):
                    continue
                if isinstance(child, ast.Expr):
                    probes.add(id(child))
                stack.extend(ast.iter_child_nodes(child))
    return probes


def _contains_possible_effect(node):
    return any(
        isinstance(
            child, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr)
        )
        for child in ast.walk(node)
    )


class NoEffectStatementRule(SkylosRule):
    rule_id = "SKY-L033"
    name = "No-Effect Statement"

    def __init__(self):
        self._exception_probes = set()

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self._exception_probes = _exception_probe_expressions(node)
            return None
        if not isinstance(node, ast.Expr):
            return None

        value = node.value
        issue_name = "expression"
        issue_value = "no_effect"
        message = (
            "Expression statement has no effect because its result is discarded. "
            "Assign/use the result or remove the statement."
        )

        if isinstance(value, ast.Constant):
            if isinstance(value.value, str) or value.value is ...:
                return None
            if value.value is None:
                return None
        elif isinstance(value, (ast.Await, ast.Yield, ast.YieldFrom)):
            return None
        elif isinstance(value, ast.Call):
            call_name = _qualified_call_name(value.func)
            if call_name not in _PURE_DISCARDED_CALLS:
                return None
            if id(node) in self._exception_probes:
                return None
            issue_name = call_name
            issue_value = "discarded_result"
            message = (
                f"Return value from '{call_name}()' is discarded. "
                "Assign/use the result or remove the call."
            )
        elif not isinstance(value, _NO_EFFECT_EXPR_TYPES):
            return None
        elif _contains_possible_effect(value):
            return None
        else:
            literal_value = _literal_expression_value(value)
            if literal_value is _RAISING_EXPRESSION:
                return None
            if literal_value is _UNKNOWN_EXPRESSION:
                if id(node) in self._exception_probes:
                    return None
                if not isinstance(value, ast.Compare):
                    return None
                issue_value = "discarded_comparison"
                message = (
                    "Comparison result is discarded. Check whether an assignment "
                    "or assertion was intended."
                )

        filename = context.get("filename", "")
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "LOW",
                "type": "statement",
                "name": issue_name,
                "simple_name": issue_name,
                "value": issue_value,
                "threshold": 0,
                "message": message,
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
