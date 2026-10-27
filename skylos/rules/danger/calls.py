import ast
import re
from skylos.rules.base import SkylosRule
from .pickle_provenance import safe_pickle_loads
from skylos.security.command_guard import scan_shell_command
from skylos.security.sensitive_data import first_sensitive_name
from skylos.security.command_guard_types import (
    DATA_EXFIL_RULE,
    DESTRUCTIVE_RULE,
    REMOTE_SCRIPT_RULE,
    SCOPE_VIOLATION_RULE,
)

# Command-guard risks that make even a fixed shell command dangerous:
# exfiltration, remote script execution, broad deletion, credential reads.
_DANGEROUS_COMMAND_RULES = frozenset(
    risk.rule_id
    for risk in (
        DATA_EXFIL_RULE,
        REMOTE_SCRIPT_RULE,
        DESTRUCTIVE_RULE,
        SCOPE_VIOLATION_RULE,
    )
)

DANGEROUS_CALLS = {
    "eval": ("SKY-D201", "HIGH", "Use of eval()"),
    "exec": ("SKY-D202", "HIGH", "Use of exec()"),
    "os.system": (
        "SKY-D203",
        "CRITICAL",
        "Use of os.system()",
        {"constant_command_severity": "LOW"},
    ),
    "pickle.load": (
        "SKY-D204",
        "CRITICAL",
        "Untrusted deserialization via pickle.load",
    ),
    "pickle.loads": (
        "SKY-D205",
        "CRITICAL",
        "pickle.loads can execute code; only deserialize bytes from trusted sources",
    ),
    "yaml.load": ("SKY-D206", "HIGH", "yaml.load without SafeLoader"),
    "hashlib.md5": (
        "SKY-D207",
        "MEDIUM",
        "Weak hash (MD5)",
        {"security_optout": True},
    ),
    "hashlib.sha1": (
        "SKY-D208",
        "MEDIUM",
        "Weak hash (SHA1)",
        {"security_optout": True},
    ),
    "random.random": (
        "SKY-D250",
        "MEDIUM",
        "Weak random source; use secrets or os.urandom for security-sensitive values",
        {"weak_random": True},
    ),
    "random.randint": (
        "SKY-D250",
        "MEDIUM",
        "Weak random source; use secrets or os.urandom for security-sensitive values",
        {"weak_random": True},
    ),
    "random.randrange": (
        "SKY-D250",
        "MEDIUM",
        "Weak random source; use secrets or os.urandom for security-sensitive values",
        {"weak_random": True},
    ),
    "random.choice": (
        "SKY-D250",
        "MEDIUM",
        "Weak random source; use secrets or os.urandom for security-sensitive values",
        {"weak_random": True},
    ),
    "random.choices": (
        "SKY-D250",
        "MEDIUM",
        "Weak random source; use secrets or os.urandom for security-sensitive values",
        {"weak_random": True},
    ),
    "random.randbytes": (
        "SKY-D250",
        "MEDIUM",
        "Weak random source; use secrets or os.urandom for security-sensitive values",
        {"weak_random": True},
    ),
    "random.getrandbits": (
        "SKY-D250",
        "MEDIUM",
        "Weak random source; use secrets or os.urandom for security-sensitive values",
        {"weak_random": True},
    ),
    "subprocess.*": (
        "SKY-D209",
        "HIGH",
        "subprocess call with shell=True",
        {"kw_equals": {"shell": True}, "constant_command_severity": "LOW"},
    ),
    # TLS verification off is a deployment hazard: like D346 (debug mode),
    # it is not reported in test modules (``production_only``), where it is
    # how tests reach local servers with self-signed certificates.
    "requests.*": (
        "SKY-D210",
        "HIGH",
        "requests call with verify=False",
        {"kw_equals": {"verify": False}, "production_only": True},
    ),
    "httpx.*": (
        "SKY-D210",
        "HIGH",
        "httpx call with verify=False",
        {"kw_equals": {"verify": False}, "production_only": True},
    ),
    "ssl._create_unverified_context": (
        "SKY-D210",
        "HIGH",
        "TLS context disables certificate verification",
        {"production_only": True},
    ),
    "flask.Flask.run": (
        "SKY-D346",
        "HIGH",
        "Flask debug mode enabled",
        {"kw_equals": {"debug": True}},
    ),
    "logging.config.listen": (
        "SKY-D347",
        "MEDIUM",
        "logging.config.listen() starts an unauthenticated config listener",
    ),
    "logging.config.config.listen": (
        "SKY-D347",
        "MEDIUM",
        "logging.config.listen() starts an unauthenticated config listener",
    ),
    "tempfile.mktemp": (
        "SKY-D348",
        "HIGH",
        "tempfile.mktemp() creates a race-prone temporary filename",
    ),
    "marshal.loads": (
        "SKY-D233",
        "CRITICAL",
        "Untrusted deserialization via marshal.loads",
    ),
    "shelve.open": (
        "SKY-D233",
        "HIGH",
        "Untrusted deserialization via shelve.open",
    ),
    "jsonpickle.decode": (
        "SKY-D233",
        "CRITICAL",
        "Untrusted deserialization via jsonpickle.decode",
    ),
    "dill.loads": (
        "SKY-D233",
        "CRITICAL",
        "Untrusted deserialization via dill.loads",
    ),
    "dill.load": (
        "SKY-D233",
        "CRITICAL",
        "Untrusted deserialization via dill.load",
    ),
    ".exec_command": (
        "SKY-D235",
        "HIGH",
        "Remote command execution via exec_command (e.g., paramiko SSH)",
    ),
}


def _resolve_expr_name(node: ast.AST, aliases=None, assigned_calls=None):
    aliases = aliases or {}
    assigned_calls = assigned_calls or {}
    if isinstance(node, ast.Name):
        return assigned_calls.get(node.id) or aliases.get(node.id) or node.id
    if isinstance(node, ast.Attribute):
        base = _resolve_expr_name(node.value, aliases, assigned_calls)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Call):
        return _qualified_name_from_call(node, aliases, assigned_calls)
    return None


def _qualified_name_from_call(node: ast.Call, aliases=None, assigned_calls=None):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(_resolve_expr_name(func, aliases, assigned_calls) or func.id)
        parts.reverse()
        return ".".join(parts)
    if isinstance(func, ast.Call):
        base = _qualified_name_from_call(func, aliases, assigned_calls)
        if base:
            parts.reverse()
            return ".".join([base, *parts])
    return None


def _matches_rule(name, rule_key):
    if not name:
        return False
    if rule_key.startswith("."):
        return name.endswith(rule_key)
    if rule_key.endswith(".*"):
        return name.startswith(rule_key[:-2] + ".")
    return name == rule_key


def _declares_non_security_use(node: ast.Call) -> bool:
    """``hashlib.md5(data, usedforsecurity=False)``: the caller states the hash
    is a cache key / checksum, and FIPS builds enforce that it is not used for
    security. There is nothing for a reviewer to change."""
    for kw in node.keywords:
        if (
            kw.arg == "usedforsecurity"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
        ):
            return True
    return False


def _constant_str_value(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        parts = [_constant_str_value(value) for value in node.values]
        return None if None in parts else "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_str_value(node.left)
        right = _constant_str_value(node.right)
        return None if left is None or right is None else left + right
    return None


def _has_shell_expansion(command: str) -> bool:
    # A quoted script passed to a shell/eval can expand on its second parse.
    if re.search(r"\b(?:eval|bash|dash|ksh|sh|zsh)\b", command) and any(
        marker in command for marker in ("$", "`")
    ):
        return True
    quote = None
    escaped = False
    for char in command:
        if escaped:
            escaped = False
        elif quote == "'":
            if char == "'":
                quote = None
        elif char == "\\":
            escaped = True
        elif char in {"$", "`"}:
            return True
        elif quote:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
    return False


def _call_severity(node: ast.Call, severity: str, opts) -> str:
    """``os.system("twine upload dist/*")``: a fixed command string has no
    input to inject, so it is reported at the lower severity the rule sets.
    Formatted, concatenated or variable commands, and fixed commands that
    delete broadly, exfiltrate or run remote scripts, keep the rule severity."""
    lowered = opts.get("constant_command_severity") if opts else None
    if not lowered or len(node.args) > 1:
        return severity
    command = node.args[0] if node.args else None
    if command is None:
        for kw in node.keywords:
            if kw.arg == "command":
                command = kw.value
    text = _constant_str_value(command)
    if text is None or _has_shell_expansion(text):
        return severity
    if any(
        risk.rule_id in _DANGEROUS_COMMAND_RULES for risk in scan_shell_command(text)
    ):
        return severity
    return lowered


def _call_low_risk_context(node: ast.Call, severity: str, rule_severity: str, opts):
    """Evidence that a true call finding is low-risk where it occurs: a fixed
    shell command (Bandit rates these low), or a weak hash over data that is
    neither a credential nor an identity (CodeQL reports only those)."""
    if not opts:
        return None
    if opts.get("constant_command_severity") and severity != rule_severity:
        return {
            "reason": "constant-shell-command",
            "detail": "the command is a fixed string with no input",
        }
    if opts.get("security_optout"):
        names = _hash_input_names(node)
        if names is None:
            return None
        sensitive = first_sensitive_name(names)
        if sensitive is None:
            return {
                "reason": "non-sensitive-hash-input",
                "detail": "the hashed data is not a credential, identity or certificate",
            }
    return None


def _expression_names(node: ast.AST | None) -> list[str]:
    names = []
    if node is None:
        return names
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.append(child.id)
        elif isinstance(child, ast.Attribute):
            names.append(child.attr)
        elif isinstance(child, ast.Subscript):
            key = child.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                names.append(key.value)
        elif isinstance(child, ast.Call):
            for arg in child.args[:1]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if (
                        isinstance(child.func, ast.Attribute)
                        and child.func.attr == "get"
                    ):
                        names.append(arg.value)
    return names


def _enclosing_scope(node: ast.AST) -> ast.AST | None:
    current = getattr(node, "parent", None)
    last = node
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return current
        last = current
        current = getattr(current, "parent", None)
    return last


def _bound_value_names(scope: ast.AST, name: str) -> list[str]:
    names = []
    for child in ast.walk(scope):
        if isinstance(child, ast.Assign):
            targets = child.targets
        elif isinstance(child, (ast.AugAssign, ast.AnnAssign)):
            targets = [child.target]
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            names.extend(_expression_names(child.value))
    return names


def _hash_object_name(node: ast.Call) -> str | None:
    parent = getattr(node, "parent", None)
    if isinstance(parent, ast.Assign) and len(parent.targets) == 1:
        target = parent.targets[0]
        if isinstance(target, ast.Name):
            return target.id
    return None


def _hash_input_names(node: ast.Call) -> list[str] | None:
    """Names that feed the hashed bytes: the call's data argument, values
    assigned to those names in the same scope, and ``.update()`` arguments on
    the hash object. None when the data cannot be read from the code."""
    data = list(node.args[:1])
    for kw in node.keywords:
        if kw.arg in {"string", "data"}:
            data.append(kw.value)
    scope = _enclosing_scope(node)
    parent = getattr(node, "parent", None)
    if (
        isinstance(parent, ast.Attribute)
        and parent.attr == "update"
        and isinstance(getattr(parent, "parent", None), ast.Call)
    ):
        data.extend(parent.parent.args[:1])
    hash_object = _hash_object_name(node)
    if hash_object is not None and scope is not None:
        for child in ast.walk(scope):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "update"
                and isinstance(child.func.value, ast.Name)
                and child.func.value.id == hash_object
            ):
                data.extend(child.args[:1])
    if not data:
        return None
    names = []
    for expression in data:
        names.extend(_expression_names(expression))
    if scope is not None:
        for name in list(names):
            names.extend(_bound_value_names(scope, name))
    return names


_UNVERIFIED_SSL_PROTOCOLS = frozenset(
    {
        "PROTOCOL_TLS",
        "PROTOCOL_SSLv23",
        "PROTOCOL_SSLv2",
        "PROTOCOL_SSLv3",
        "PROTOCOL_TLSv1",
        "PROTOCOL_TLSv1_1",
        "PROTOCOL_TLSv1_2",
    }
)
_VERIFYING_CONTEXT_SETUP = frozenset({"verify_mode", "check_hostname"})


def _protocol_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _context_is_configured(node: ast.Call) -> bool:
    """The context is later given a verification mode, or a certificate to
    serve, which makes it a server context that does not verify peers."""
    target = _hash_object_name(node)
    scope = _enclosing_scope(node)
    if target is None or scope is None:
        return False
    for child in ast.walk(scope):
        if isinstance(child, ast.Assign):
            for assigned in child.targets:
                if (
                    isinstance(assigned, ast.Attribute)
                    and assigned.attr in _VERIFYING_CONTEXT_SETUP
                    and isinstance(assigned.value, ast.Name)
                    and assigned.value.id == target
                ):
                    return True
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "load_cert_chain"
            and isinstance(child.func.value, ast.Name)
            and child.func.value.id == target
        ):
            return True
    return False


def _tls_verification_disabled(node: ast.Call, name: str) -> str | None:
    """``ssl.SSLContext(ssl.PROTOCOL_TLS)`` starts with ``CERT_NONE`` and no
    hostname check (only ``PROTOCOL_TLS_CLIENT`` verifies by default), and
    ``ignore_https_errors=True`` makes a browser accept any certificate."""
    for kw in node.keywords:
        if (
            kw.arg == "ignore_https_errors"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
        ):
            return "Browser accepts any TLS certificate (ignore_https_errors=True)"
    if name != "ssl.SSLContext":
        return None
    protocol = None
    if node.args:
        protocol = node.args[0]
    for kw in node.keywords:
        if kw.arg == "protocol":
            protocol = kw.value
    if (
        protocol is not None
        and _protocol_name(protocol) not in _UNVERIFIED_SSL_PROTOCOLS
    ):
        return None
    if _context_is_configured(node):
        return None
    return "TLS context does not verify certificates or host names"


def _kw_equals(node: ast.Call, requirements):
    if not requirements:
        return True
    kw_map = {}
    for kw in node.keywords or []:
        if kw.arg:
            if isinstance(kw.value, ast.Constant):
                kw_map[kw.arg] = kw.value.value

    for key, expected in requirements.items():
        val = kw_map.get(key)
        if val != expected:
            return False
    return True


def _is_safe_yaml_loader(value: ast.AST, aliases=None) -> bool:
    name = _resolve_expr_name(value, aliases)
    if not name:
        return False
    return name.split(".")[-1] in {"SafeLoader", "CSafeLoader"}


def _yaml_load_without_safeloader(node: ast.Call, aliases=None):
    for kw in node.keywords or []:
        if kw.arg == "Loader":
            if _is_safe_yaml_loader(kw.value, aliases):
                return False
    if len(node.args) >= 2 and _is_safe_yaml_loader(node.args[1], aliases):
        return False
    return True


_WEAK_RANDOM_SECURITY_KEYWORDS = {
    "api_key",
    "apikey",
    "auth",
    "cookie",
    "credential",
    "csrf",
    "jwt",
    "nonce",
    "otp",
    "password",
    "passwd",
    "pwd",
    "salt",
    "secret",
    "session",
    "signature",
    "signing",
    "token",
}


def _identifier_tokens(name: str | None) -> set[str]:
    raw = str(name or "").strip()
    if not raw:
        return set()
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", raw)
    return {part.lower() for part in re.split(r"[^A-Za-z0-9]+|_", snake) if part}


def _name_looks_security_sensitive(name: str | None) -> bool:
    tokens = _identifier_tokens(name)
    if not tokens:
        return False
    if "api" in tokens and "key" in tokens:
        return True
    return bool(tokens & _WEAK_RANDOM_SECURITY_KEYWORDS)


def _target_looks_security_sensitive(target: ast.AST) -> bool:
    if isinstance(target, ast.Name):
        return _name_looks_security_sensitive(target.id)
    if isinstance(target, ast.Attribute):
        return _name_looks_security_sensitive(target.attr)
    if isinstance(target, ast.Subscript):
        if isinstance(target.slice, ast.Constant) and isinstance(
            target.slice.value, str
        ):
            return _name_looks_security_sensitive(target.slice.value)
        return _target_looks_security_sensitive(target.value)
    return False


def _enclosing_function_name(node: ast.AST) -> str | None:
    current = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = getattr(current, "parent", None)
    return None


def _weak_random_has_security_context(
    node: ast.Call, current_symbol: str | None = None
) -> bool:
    if _name_looks_security_sensitive(current_symbol):
        return True

    function_name = _enclosing_function_name(node)
    if _name_looks_security_sensitive(function_name):
        return True

    current: ast.AST = node
    while True:
        parent = getattr(current, "parent", None)
        if parent is None:
            return False

        if isinstance(parent, ast.Assign):
            return any(_target_looks_security_sensitive(t) for t in parent.targets)

        if isinstance(parent, ast.AnnAssign):
            return _target_looks_security_sensitive(parent.target)

        if isinstance(parent, ast.keyword):
            if _name_looks_security_sensitive(parent.arg):
                return True
            current = parent
            continue

        if isinstance(parent, ast.Return):
            return _name_looks_security_sensitive(_enclosing_function_name(parent))

        if isinstance(
            parent,
            (
                ast.BinOp,
                ast.BoolOp,
                ast.Call,
                ast.Compare,
                ast.FormattedValue,
                ast.IfExp,
                ast.JoinedStr,
                ast.UnaryOp,
            ),
        ):
            current = parent
            continue

        return False


# App factories / constructors whose ``.run(debug=True)`` starts the Werkzeug
# development server with the interactive debugger enabled.
_FLASK_APP_FACTORIES = frozenset(
    {"Flask", "create_app", "make_app", "build_app", "get_app", "Dash", "APIFlask"}
)
_FLASK_APP_RECEIVER_NAMES = frozenset({"app", "application", "flask_app"})


def _is_test_module(filename) -> bool:
    normalized = str(filename or "").replace("\\", "/")
    base = normalized.rsplit("/", 1)[-1]
    if base.startswith("test_") or base.endswith("_test.py") or base == "conftest.py":
        return True
    return "/tests/" in f"/{normalized}" or "/test/" in f"/{normalized}"


def _is_flask_style_debug_run(node: ast.Call, name: str | None, filename) -> bool:
    """``app.run(debug=True)`` when ``app`` is not resolvable to ``flask.Flask``.

    Agents typically write ``app = create_app()`` (application factory) or
    import ``app`` from the package; the receiver then does not resolve to
    ``flask.Flask`` and the table rule above misses it. Also covers
    ``socketio.run(app, debug=True)`` (Flask-SocketIO runs Werkzeug too).
    """
    if not name or not _kw_equals(node, {"debug": True}):
        return False
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "run":
        return False
    if _is_test_module(filename):
        return False
    segments = name.split(".")
    receiver = segments[-2] if len(segments) >= 2 else ""
    if receiver in _FLASK_APP_FACTORIES:
        return True
    if receiver == "socketio" or name.endswith("SocketIO.run"):
        return True
    receiver_node = node.func.value
    if isinstance(receiver_node, ast.Name):
        if receiver_node.id in _FLASK_APP_RECEIVER_NAMES and receiver not in {
            "uvicorn",
            "hypercorn",
        }:
            return True
        return False
    if isinstance(receiver_node, ast.Call):
        callee = receiver_node.func
        callee_name = (
            callee.attr
            if isinstance(callee, ast.Attribute)
            else callee.id
            if isinstance(callee, ast.Name)
            else ""
        )
        return callee_name in _FLASK_APP_FACTORIES
    return False


class DangerousCallsRule(SkylosRule):
    rule_id = "SKY-D200"
    name = "Dangerous Function Calls"

    def __init__(self):
        self.aliases: dict[str, str] = {}
        self.assigned_calls_by_scope: dict[int, dict[str, str]] = {}
        self._parents_annotated = False
        self._safe_pickle_loads = set()

    def _annotate_parents(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            child.parent = node
            self._annotate_parents(child)

    def _scope_key(self, node: ast.AST) -> int:
        current = node
        while current is not None:
            if isinstance(
                current,
                (
                    ast.Module,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                ),
            ):
                return id(current)
            current = getattr(current, "parent", None)
        return 0

    def _assigned_calls_for(self, node: ast.AST) -> dict[str, str]:
        return self.assigned_calls_by_scope.setdefault(self._scope_key(node), {})

    def _track_import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local] = alias.name

    def _track_import_from(self, node: ast.ImportFrom) -> None:
        if not node.module:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            self.aliases[local] = f"{node.module}.{alias.name}"

    def _track_assign(self, node: ast.Assign) -> None:
        if not isinstance(node.value, ast.Call):
            return
        assigned_calls = self._assigned_calls_for(node)
        call_name = _qualified_name_from_call(node.value, self.aliases, assigned_calls)
        if not call_name:
            return
        for target in node.targets:
            if isinstance(target, ast.Name):
                assigned_calls[target.id] = call_name

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self.aliases.clear()
            self.assigned_calls_by_scope.clear()
            self._annotate_parents(node)
            self._parents_annotated = True
            self._safe_pickle_loads = safe_pickle_loads(node, context.get("filename"))
            self.assigned_calls_by_scope.setdefault(id(node), {})
            return None
        if isinstance(node, ast.Import):
            self._track_import(node)
            return None
        if isinstance(node, ast.ImportFrom):
            self._track_import_from(node)
            return None
        if isinstance(node, ast.Assign):
            self._track_assign(node)
            return None
        if not isinstance(node, ast.Call):
            return None

        name = _qualified_name_from_call(
            node, self.aliases, self._assigned_calls_for(node)
        )
        if not name:
            return None

        findings = []

        for rule_key, tup in DANGEROUS_CALLS.items():
            if not _matches_rule(name, rule_key):
                continue

            if rule_key == "pickle.loads" and id(node) in self._safe_pickle_loads:
                continue

            rule_id = tup[0]
            severity = tup[1]
            message = tup[2]
            opts = tup[3] if len(tup) > 3 else None

            if rule_key == "yaml.load":
                if not _yaml_load_without_safeloader(node, self.aliases):
                    continue

            if opts and "kw_equals" in opts:
                if not _kw_equals(node, opts["kw_equals"]):
                    continue

            if (
                opts
                and opts.get("production_only")
                and _is_test_module(context.get("filename"))
            ):
                continue

            if opts and opts.get("weak_random"):
                if not _weak_random_has_security_context(node):
                    continue

            if opts and opts.get("security_optout"):
                if _declares_non_security_use(node):
                    continue

            finding = {
                "rule_id": rule_id,
                "severity": _call_severity(node, severity, opts),
                "message": message,
                "file": context.get("filename"),
                "line": node.lineno,
                "col": node.col_offset,
            }
            low_risk = _call_low_risk_context(node, finding["severity"], severity, opts)
            if low_risk is not None:
                finding["low_risk_context"] = low_risk
            findings.append(finding)
            break

        if not findings and not _is_test_module(context.get("filename")):
            unverified = _tls_verification_disabled(node, name)
            if unverified is not None:
                findings.append(
                    {
                        "rule_id": "SKY-D210",
                        "severity": "HIGH",
                        "message": unverified,
                        "file": context.get("filename"),
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                )

        if not findings and _is_flask_style_debug_run(
            node, name, context.get("filename")
        ):
            findings.append(
                {
                    "rule_id": "SKY-D346",
                    "severity": "HIGH",
                    "message": (
                        "Flask debug mode enabled: run(debug=True) exposes the "
                        "interactive Werkzeug debugger (remote code execution)"
                    ),
                    "file": context.get("filename"),
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

        return findings if findings else None
