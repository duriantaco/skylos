import ast
import re
from skylos.rules.base import SkylosRule

DANGEROUS_CALLS = {
    "eval": ("SKY-D201", "HIGH", "Use of eval()"),
    "exec": ("SKY-D202", "HIGH", "Use of exec()"),
    "os.system": ("SKY-D203", "CRITICAL", "Use of os.system()"),
    "pickle.load": (
        "SKY-D204",
        "CRITICAL",
        "Untrusted deserialization via pickle.load",
    ),
    "pickle.loads": (
        "SKY-D205",
        "CRITICAL",
        "Untrusted deserialization via pickle.loads",
    ),
    "yaml.load": ("SKY-D206", "HIGH", "yaml.load without SafeLoader"),
    "hashlib.md5": ("SKY-D207", "MEDIUM", "Weak hash (MD5)"),
    "hashlib.sha1": ("SKY-D208", "MEDIUM", "Weak hash (SHA1)"),
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
        {"kw_equals": {"shell": True}},
    ),
    "requests.*": (
        "SKY-D210",
        "HIGH",
        "requests call with verify=False",
        {"kw_equals": {"verify": False}},
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


class DangerousCallsRule(SkylosRule):
    rule_id = "SKY-D200"
    name = "Dangerous Function Calls"

    def __init__(self):
        self.aliases: dict[str, str] = {}
        self.assigned_calls_by_scope: dict[int, dict[str, str]] = {}
        self._parents_annotated = False

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
        if isinstance(node, ast.Module) and not self._parents_annotated:
            self._annotate_parents(node)
            self._parents_annotated = True
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

            if opts and opts.get("weak_random"):
                if not _weak_random_has_security_context(node):
                    continue

            findings.append(
                {
                    "rule_id": rule_id,
                    "severity": severity,
                    "message": message,
                    "file": context.get("filename"),
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )
            break

        return findings if findings else None
