"""Which agent-hook findings block the agent, and which are only notes.

``skylos verify`` reports every high/critical security finding. Its taint
rules treat *every* function parameter as tainted, so an ordinary helper such
as ``def load(path): return open(path).read()`` is reported as path traversal.
That is useful in a review, but blocking an agent on it trains the agent (and
the user) to ignore Skylos. The hook therefore blocks only on:

a. secrets;
b. security findings with evidence of a real untrusted source reaching the
   sink (a web-route / CLI / MCP-tool parameter, ``request.*``, ``input()``,
   ``sys.argv``, ``os.environ``, ``sys.stdin``) — checked here on the AST;
c. sinks that are dangerous whatever the input: unsafe deserialization,
   Trojan Source, and code/command execution (``eval``/``exec``/
   ``os.system``/``shell=True``/``yaml.load``) with a non-constant argument;
d. hallucinated dependencies, APIs and references, and violations of the
   project's own AI contract.

Everything else is returned as a non-blocking note.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Iterable

HALLUCINATION_RULES = frozenset(
    {"SKY-D222", "SKY-D224", "SKY-D225", "SKY-L012", "SKY-L023"}
)
HALLUCINATION_VIBES = frozenset(
    {"dependency_hallucination", "api_signature_hallucination", "hallucinated_reference"}
)
# The project's own AI contract: the user asked for these to be enforced.
CONTRACT_RULES = frozenset({"SKY-A105"})

# (c) dangerous regardless of where the data comes from.
ALWAYS_BLOCK_RULES = frozenset(
    {
        "SKY-D204",  # pickle deserialization
        "SKY-D205",  # pickle.loads
        "SKY-D233",  # unsafe deserialization
        "SKY-D294",  # GitHub Actions template injection (source is inherent)
        "SKY-D344",  # Trojan Source bidi characters
        # Security controls switched off: agents add these to silence an
        # error, and they are unsafe whatever the input.
        "SKY-D210",  # TLS verification disabled (verify=False, CERT_NONE, ...)
        "SKY-G210",  # Go InsecureSkipVerify
        "SKY-D232",  # JWT signature verification disabled / unsafe algorithm
        "SKY-D246",  # JS/TS JWT decode without verification
    }
)
# (c) code / command execution: block unless every argument is a constant.
NON_CONSTANT_BLOCK_RULES = frozenset(
    {
        "SKY-D201",  # eval
        "SKY-D202",  # exec
        "SKY-D203",  # os.system
        "SKY-D206",  # yaml.load
        "SKY-D209",  # subprocess shell=True
    }
)
# (b) source-to-sink rules: block only with untrusted-source evidence.
TAINT_RULES = frozenset(
    {
        "SKY-D211",  # SQL injection
        "SKY-D212",  # command injection
        "SKY-D215",  # path traversal
        "SKY-D216",  # SSRF
        "SKY-D217",  # raw SQL execution
        "SKY-D230",  # open redirect
        "SKY-D234",  # mass assignment
        "SKY-D235",  # remote command execution sink
        "SKY-D245",  # dynamic require
        "SKY-D281",  # server action SQL injection
    }
)

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
REQUEST_ANNOTATIONS = frozenset(
    {"Request", "HttpRequest", "WebSocket", "UploadFile", "HTTPConnection"}
)
REQUEST_NAMES = frozenset({"request", "req"})
_SOURCE_CALLS = frozenset(
    {"input", "raw_input", "os.getenv", "os.environ.get", "sys.stdin.read",
     "sys.stdin.readline", "sys.stdin.readlines"}
)  # fmt: skip
_SOURCE_ATTRS = frozenset({"sys.argv", "os.environ", "sys.stdin"})
_NON_PY_SOURCE_RE = re.compile(
    r"\b(?:req|request|params|query|body|argv|process\.env|searchParams|"
    r"headers|cookies|formData|getParameter|\$_(?:GET|POST|REQUEST|COOKIE))\b"
)
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def classify_findings(
    findings: list[dict[str, Any]], path: Path, text: str | None
) -> None:
    """Set ``blocking`` (bool) and ``why`` on each finding, in place."""
    facts: _SourceFacts | None = None
    need_ast = path.suffix.lower() in {".py", ".pyi", ".pyw"} and any(
        _needs_ast(f) for f in findings
    )
    if need_ast and text is not None:
        facts = _SourceFacts.parse(text)
    for finding in findings:
        blocking, why = _decide(finding, facts, path)
        finding["blocking"] = blocking
        finding["why"] = why


def _needs_ast(finding: dict[str, Any]) -> bool:
    rule = str(finding.get("rule_id") or "")
    return rule in NON_CONSTANT_BLOCK_RULES or rule in TAINT_RULES


def _decide(
    finding: dict[str, Any], facts: "_SourceFacts | None", path: Path
) -> tuple[bool, str]:
    rule = str(finding.get("rule_id") or "")
    category = str(finding.get("category") or "")
    if category == "secret" or rule.startswith("SKY-S"):
        return True, "secret"
    if rule in HALLUCINATION_RULES or finding.get("vibe") in HALLUCINATION_VIBES:
        return True, "hallucination"
    if rule in CONTRACT_RULES:
        return True, "contract"
    if category != "security":
        return False, "note"
    if rule in ALWAYS_BLOCK_RULES:
        return True, "dangerous-sink"
    line = int(finding.get("line") or 0)
    if rule in NON_CONSTANT_BLOCK_RULES:
        if facts is None:
            return _non_python_evidence(finding), "dangerous-sink"
        if facts.call_has_non_constant_args(line):
            return True, "dangerous-sink"
        # A constant argument can still come from a real source below.
        if facts.line_uses_untrusted(line):
            return True, "untrusted-source"
        return False, "constant-argument"
    if rule in TAINT_RULES:
        if facts is None:
            if _non_python_evidence(finding):
                return True, "untrusted-source"
            return False, "no-source-evidence"
        if facts.line_uses_untrusted(line):
            return True, "untrusted-source"
        return False, "no-source-evidence"
    return False, "note"


def _non_python_evidence(finding: dict[str, Any]) -> bool:
    """For languages without an AST check here, trust explicit source evidence."""
    metadata = finding.get("metadata")
    evidence = metadata.get("security_evidence") if isinstance(metadata, dict) else None
    if not isinstance(evidence, dict):
        return False
    source = str(evidence.get("source") or "")
    return bool(_NON_PY_SOURCE_RE.search(source))


# --------------------------------------------------------------------------
# Python source facts
# --------------------------------------------------------------------------


class _SourceFacts:
    def __init__(self, tree: ast.Module | None):
        self.tree = tree
        self._functions: list[ast.AST] = []
        self._untrusted: dict[int, set[str]] = {}
        self._request_names: dict[int, set[str]] = {}
        self._calls_by_line: dict[int, list[ast.Call]] | None = None
        if tree is not None:
            self._functions = [
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]

    @classmethod
    def parse(cls, text: str) -> "_SourceFacts":
        try:
            return cls(ast.parse(text))
        except (SyntaxError, ValueError, RecursionError):
            return cls(None)

    # -- sinks on a line ----------------------------------------------------

    def _calls_on_line(self, line: int) -> list[ast.Call]:
        if self.tree is None:
            return []
        if self._calls_by_line is None:
            index: dict[int, list[ast.Call]] = {}
            for node in ast.walk(self.tree):
                if isinstance(node, ast.Call):
                    end = getattr(node, "end_lineno", None) or node.lineno
                    # Cap multi-line spans so a huge call cannot blow up the index.
                    for number in range(node.lineno, min(end, node.lineno + 50) + 1):
                        index.setdefault(number, []).append(node)
            self._calls_by_line = index
        return self._calls_by_line.get(line, [])

    def call_has_non_constant_args(self, line: int) -> bool:
        calls = [c for c in self._calls_on_line(line) if _is_exec_sink(c)]
        if not calls:
            # Unknown shape: stay conservative only if nothing on the line is constant.
            calls = self._calls_on_line(line)
            if not calls:
                return True
        for call in calls:
            args = list(call.args) + [
                kw.value for kw in call.keywords if kw.arg in {None, "args", "cmd", "source", "stream"}
            ]
            if not args:
                continue
            if any(not _is_constant(arg) for arg in args):
                return True
        return False

    def line_uses_untrusted(self, line: int) -> bool:
        if self.tree is None:
            return False
        func = self._enclosing(line)
        untrusted, request_names = self._untrusted_names(func)
        for call in self._calls_on_line(line):
            for node in [*call.args, *(kw.value for kw in call.keywords)]:
                if _references(node, untrusted, request_names):
                    return True
        return False

    # -- scopes -------------------------------------------------------------

    def _enclosing(self, line: int) -> ast.AST | None:
        best = None
        for func in self._functions:
            end = getattr(func, "end_lineno", None) or func.lineno
            start = min([func.lineno, *(d.lineno for d in func.decorator_list)])
            if start <= line <= end:
                if best is None or func.lineno >= best.lineno:
                    best = func
        return best

    def _untrusted_names(self, func: ast.AST | None) -> tuple[set[str], set[str]]:
        key = id(func)
        if key in self._untrusted:
            return self._untrusted[key], self._request_names[key]
        untrusted: set[str] = set()
        request_names = set(REQUEST_NAMES)
        body: Iterable[ast.AST] = ()
        if func is not None:
            params = _params(func)
            if _is_entrypoint(func):
                untrusted.update(p.arg for p in params if p.arg not in {"self", "cls"})
            for param in params:
                if _annotation_is_request(param.annotation):
                    request_names.add(param.arg)
            body = list(ast.walk(func))
        elif self.tree is not None:
            body = list(_module_level_nodes(self.tree))
        # Propagate through simple assignments until nothing changes.
        assigns = [
            node
            for node in body
            if isinstance(
                node,
                (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor,
                 ast.withitem, ast.NamedExpr),
            )
        ]  # fmt: skip
        for _ in range(4):
            changed = False
            for node in assigns:
                value, targets = _assign_parts(node)
                if value is None or not _references(value, untrusted, request_names):
                    continue
                for name in targets:
                    if name not in untrusted:
                        untrusted.add(name)
                        changed = True
            if not changed:
                break
        self._untrusted[key] = untrusted
        self._request_names[key] = request_names
        return untrusted, request_names


def _module_level_nodes(tree: ast.Module):
    stack = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _params(func: ast.AST) -> list[ast.arg]:
    args = func.args  # type: ignore[attr-defined]
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if args.vararg:
        params.append(args.vararg)
    if args.kwarg:
        params.append(args.kwarg)
    return params


def _is_entrypoint(func: ast.AST) -> bool:
    for decorator in func.decorator_list:  # type: ignore[attr-defined]
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = (
            target.attr
            if isinstance(target, ast.Attribute)
            else target.id
            if isinstance(target, ast.Name)
            else ""
        )
        if name in ROUTE_DECORATOR_NAMES:
            return True
    return False


def _annotation_is_request(annotation: ast.AST | None) -> bool:
    if annotation is None:
        return False
    for node in ast.walk(annotation):
        name = (
            node.attr
            if isinstance(node, ast.Attribute)
            else node.id
            if isinstance(node, ast.Name)
            else node.value
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            else None
        )
        if name in REQUEST_ANNOTATIONS:
            return True
    return False


def _assign_parts(node: ast.AST) -> tuple[ast.AST | None, list[str]]:
    if isinstance(node, ast.Assign):
        return node.value, _target_names(node.targets)
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return node.value, _target_names([node.target])
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return node.iter, _target_names([node.target])
    if isinstance(node, ast.withitem):
        return node.context_expr, _target_names(
            [node.optional_vars] if node.optional_vars is not None else []
        )
    if isinstance(node, ast.NamedExpr):
        return node.value, _target_names([node.target])
    return None, []


def _target_names(targets: list[ast.AST]) -> list[str]:
    names = []
    for target in targets:
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                names.append(node.id)
    return names


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _references(node: ast.AST, untrusted: set[str], request_names: set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in untrusted:
            return True
        if isinstance(sub, ast.Attribute):
            dotted = _dotted(sub)
            segments = dotted.split(".") if dotted else []
            if any(seg in request_names for seg in segments[:-1]):
                return True
            if dotted in _SOURCE_ATTRS or any(
                dotted.startswith(src + ".") for src in _SOURCE_ATTRS
            ):
                return True
        if isinstance(sub, ast.Call):
            name = _dotted(sub.func)
            if name in _SOURCE_CALLS or name.endswith(".parse_args"):
                return True
    return False


_EXEC_SINKS = frozenset(
    {"eval", "exec", "os.system", "os.popen", "yaml.load", "yaml.unsafe_load"}
)


def _is_exec_sink(call: ast.Call) -> bool:
    name = _dotted(call.func)
    if name in _EXEC_SINKS:
        return True
    if name.startswith("subprocess.") or name.split(".")[-1] in {
        "run", "call", "check_call", "check_output", "Popen", "getoutput",
        "getstatusoutput",
    }:  # fmt: skip
        return any(
            kw.arg == "shell"
            and not (isinstance(kw.value, ast.Constant) and not kw.value.value)
            for kw in call.keywords
        ) or name in {"subprocess.getoutput", "subprocess.getstatusoutput"}
    return False


def _is_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_constant(e) for e in node.elts)
    if isinstance(node, ast.BinOp):
        return _is_constant(node.left) and _is_constant(node.right)
    if isinstance(node, ast.Name) and node.id.isupper():
        return True  # module-level CONSTANT
    return False


# --------------------------------------------------------------------------
# Presentation helpers shared by post-edit, stop and recheck
# --------------------------------------------------------------------------


def dedupe_by_line(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge findings on the same file line into one item (D203+D212, dup S101)."""
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for finding in findings:
        key = (str(finding.get("path")), int(finding.get("line") or 0))
        groups.setdefault(key, []).append(finding)
    merged = []
    for items in groups.values():
        items.sort(
            key=lambda f: (
                not f.get("blocking", True),
                f.get("why") != "untrusted-source",  # the most specific message
                _SEVERITY_ORDER.get(str(f.get("severity")).upper(), 4),
            )
        )
        lead = dict(items[0])
        rules = []
        for item in items:
            rule = str(item.get("rule_id") or "")
            if rule and rule not in rules:
                rules.append(rule)
        lead["rule_id"] = "/".join(rules)
        lead["blocking"] = any(item.get("blocking", True) for item in items)
        merged.append(lead)
    return merged
