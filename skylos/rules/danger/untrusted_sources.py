"""Name the untrusted source behind a Python taint finding.

The Python taint checkers treat every function parameter as tainted, which is
right for a review but says nothing about *where* the data comes from. This
module recognises the same "real" sources the agent-hook policy
(``skylos.commands.hook_policy``) accepts -- parameters of a web-route / CLI /
MCP-tool entry point, ``request.*``, ``input()``, ``sys.argv``,
``os.environ`` / ``os.getenv`` and ``sys.stdin`` -- and turns them into a
``security_evidence`` packet (``source`` / ``sink`` / ``path``) that SARIF
``codeFlows`` and evidence contracts can use.

A finding gets a packet only when such a source reaches the sink expression.
The constants below must stay in sync with ``hook_policy``; a test checks it.
"""

from __future__ import annotations

import ast
from typing import Any

ROUTE_DECORATOR_NAMES = frozenset(
    {
        # web frameworks
        "route", "get", "post", "put", "patch", "delete", "head", "options",
        "websocket", "api_route", "api_view", "view_config", "action",
        # CLIs (click / typer)
        "command", "group", "callback", "argument", "option",
        # MCP / agent tools: arguments come from the model
        "tool", "resource", "prompt",
    }
)  # fmt: skip
_CLI_DECORATORS = frozenset({"command", "group", "callback", "argument", "option"})
_TOOL_DECORATORS = frozenset({"tool", "resource", "prompt"})
REQUEST_ANNOTATIONS = frozenset(
    {"Request", "HttpRequest", "WebSocket", "UploadFile", "HTTPConnection"}
)
REQUEST_NAMES = frozenset({"request", "req"})
SOURCE_CALLS = frozenset(
    {"input", "raw_input", "os.getenv", "os.environ.get", "sys.stdin.read",
     "sys.stdin.readline", "sys.stdin.readlines"}
)  # fmt: skip
SOURCE_ATTRS = frozenset({"sys.argv", "os.environ", "sys.stdin"})

_MAX_PROPAGATION_ROUNDS = 4
_MAX_SOURCES = 4


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _params(func: ast.AST) -> list[ast.arg]:
    args = func.args  # type: ignore[attr-defined]
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if args.vararg:
        params.append(args.vararg)
    if args.kwarg:
        params.append(args.kwarg)
    return params


def entrypoint_decorator(func: ast.AST) -> str | None:
    """Return the dotted decorator that makes ``func`` an entry point."""
    for decorator in getattr(func, "decorator_list", []) or []:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute):
            name = target.attr
        elif isinstance(target, ast.Name):
            name = target.id
        else:
            continue
        if name in ROUTE_DECORATOR_NAMES:
            return _dotted(target) or name
    return None


def _entrypoint_kind(decorator: str) -> str:
    last = decorator.rsplit(".", 1)[-1]
    if last in _CLI_DECORATORS:
        return "CLI parameter"
    if last in _TOOL_DECORATORS:
        return "MCP/agent tool argument"
    return "route parameter"


def _annotation_is_request(annotation: ast.AST | None) -> bool:
    if annotation is None:
        return False
    for node in ast.walk(annotation):
        if isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            name = node.value
        else:
            continue
        if name in REQUEST_ANNOTATIONS:
            return True
    return False


def _target_names(targets: list[ast.AST]) -> list[str]:
    names = []
    for target in targets:
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                names.append(node.id)
    return names


def _assign_parts(node: ast.AST) -> tuple[ast.AST | None, list[str]]:
    if isinstance(node, ast.Assign):
        return node.value, _target_names(node.targets)
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return node.value, _target_names([node.target])
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return node.iter, _target_names([node.target])
    if isinstance(node, ast.withitem):
        targets = [node.optional_vars] if node.optional_vars is not None else []
        return node.context_expr, _target_names(targets)
    if isinstance(node, ast.NamedExpr):
        return node.value, _target_names([node.target])
    return None, []


def _module_level_nodes(tree: ast.AST):
    stack = list(getattr(tree, "body", []) or [])
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _attribute_source(node: ast.Attribute, request_names: set[str]) -> str | None:
    dotted = _dotted(node)
    segments = dotted.split(".") if dotted else []
    if any(seg in request_names for seg in segments[:-1]):
        return f"request data `{dotted}`"
    if dotted in SOURCE_ATTRS or any(
        dotted.startswith(src + ".") for src in SOURCE_ATTRS
    ):
        return f"`{dotted}`"
    return None


def _call_source(node: ast.Call) -> str | None:
    name = _dotted(node.func)
    if name in SOURCE_CALLS:
        return f"`{name}()`"
    if name.endswith(".parse_args"):
        return f"CLI arguments `{name}()`"
    return None


def _node_source(
    node: ast.AST, origins: dict[str, str], request_names: set[str]
) -> str | None:
    if isinstance(node, ast.Name):
        return origins.get(node.id)
    if isinstance(node, ast.Attribute):
        return _attribute_source(node, request_names)
    if isinstance(node, ast.Call):
        return _call_source(node)
    return None


def _direct_sources(
    node: ast.AST, origins: dict[str, str], request_names: set[str]
) -> list[str]:
    """Source labels referenced anywhere inside ``node``, in source order."""
    found: list[str] = []
    stack = [node]
    while stack:
        sub = stack.pop()
        label = _node_source(sub, origins, request_names)
        if label is None:
            stack.extend(reversed(list(ast.iter_child_nodes(sub))))
            continue
        if label not in found:
            found.append(label)
        if isinstance(sub, ast.Call):
            # input(prompt) / os.getenv(name): arguments may name more sources.
            stack.extend(reversed([*sub.args, *(k.value for k in sub.keywords)]))

    return found


class _FunctionSources:
    """Untrusted names in one function (or the module) and where they came from."""

    def __init__(self, func: ast.AST | None, module: ast.AST | None):
        self.func = func
        self.request_names: set[str] = set(REQUEST_NAMES)
        # name -> human label of the original untrusted source
        self.origins: dict[str, str] = {}
        body: list[ast.AST] = []
        if func is not None:
            decorator = entrypoint_decorator(func)
            fname = getattr(func, "name", "<lambda>")
            for param in _params(func):
                if _annotation_is_request(param.annotation):
                    self.request_names.add(param.arg)
                if decorator and param.arg not in {"self", "cls"}:
                    kind = _entrypoint_kind(decorator)
                    self.origins[param.arg] = (
                        f"{kind} `{param.arg}` of `{fname}` (@{decorator})"
                    )
            body = list(ast.walk(func))
        elif module is not None:
            body = list(_module_level_nodes(module))
        self._propagate(body)

    def _propagate(self, body: list[ast.AST]) -> None:
        assigns = [
            parts
            for parts in (_assign_parts(node) for node in body)
            if parts[0] is not None
        ]
        for _ in range(_MAX_PROPAGATION_ROUNDS):
            if not any(self._propagate_one(*parts) for parts in assigns):
                break

    def _propagate_one(self, value: ast.AST, targets: list[str]) -> bool:
        fresh = [name for name in targets if name not in self.origins]
        if not fresh:
            return False
        labels = _direct_sources(value, self.origins, self.request_names)
        if not labels:
            return False
        for name in fresh:
            self.origins[name] = labels[0]
        return True

    def sources_in(self, expr: ast.AST) -> list[str]:
        return _direct_sources(expr, self.origins, self.request_names)

    def derived_names_in(self, expr: ast.AST) -> list[str]:
        names = []
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name) and sub.id in self.origins:
                if sub.id not in names:
                    names.append(sub.id)
        return names


class UntrustedSourceIndex:
    """Caches per-function source facts for one file."""

    def __init__(self, module: ast.AST | None = None):
        self.module = module
        self._cache: dict[int, _FunctionSources] = {}

    def for_function(self, func: ast.AST | None) -> _FunctionSources:
        key = id(func)
        facts = self._cache.get(key)
        if facts is None:
            facts = _FunctionSources(func, self.module if func is None else None)
            self._cache[key] = facts
        return facts

    def evidence(
        self,
        func: ast.AST | None,
        expr: ast.AST | None,
        *,
        sink: str,
        missing_guard: str,
        evidence_kind: str,
    ) -> dict[str, Any] | None:
        """Return a ``security_evidence`` packet, or None without a real source.

        The packet is deliberately free of file paths and line numbers: review
        decisions hash it into the finding context, so it must stay stable when
        lines shift or the file is analysed from a temporary snapshot. SARIF
        anchors these textual steps at the finding location.
        """
        if expr is None:
            return None
        facts = self.for_function(func)
        labels = facts.sources_in(expr)
        if not labels:
            return None
        labels = labels[:_MAX_SOURCES]
        path = [
            f"untrusted `{name}` from {facts.origins[name]}"
            for name in facts.derived_names_in(expr)[:_MAX_SOURCES]
        ]
        if not path:
            path = [f"untrusted input from {labels[0]}"]
        path.append(f"reaches {sink}")
        return {
            "evidence_kind": evidence_kind,
            "source": labels[0],
            "sources": labels,
            "sink": sink,
            "path": path,
            "guards_seen": [],
            "guards_missing": [missing_guard],
            "analysis_complete": False,
        }
