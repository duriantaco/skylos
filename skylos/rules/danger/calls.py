import ast
import bisect
import re
from .weak_random_context import private_model_slug_evidence
from skylos.rules.base import SkylosRule
from .pickle_provenance import safe_pickle_loads
from .source_owned_code import source_owned_code_calls
from .yaml_loader_provenance import yaml_loader_classes, yaml_load_call_name
from .untrusted_sources import UntrustedSourceIndex, _unsafe_import_roots
from .import_proof import provider_binding_is_stable
from .tls_provenance import tls_verification_disabled as _tls_verification_disabled
from .flow_env import ValueFlow, _scope_bindings, _scope_children
from .module_namespace import module_name_for, module_rebinding
from .builtin_bindings import builtin_references
from .callable_bindings import callable_names
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
    "eval": (
        "SKY-D201",
        "HIGH",
        "Use of eval()",
        {"constant_argument": "code"},
    ),
    "exec": (
        "SKY-D202",
        "HIGH",
        "Use of exec()",
        {"constant_argument": "code"},
    ),
    "os.system": (
        "SKY-D203",
        "CRITICAL",
        "Use of os.system()",
        {"constant_command_severity": "LOW", "constant_argument": "command"},
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
        {"constant_argument": "data"},
    ),
    "yaml.load": (
        "SKY-D206",
        "HIGH",
        "yaml.load without SafeLoader",
        {"constant_argument": "stream"},
    ),
    "yaml.load_all": (
        "SKY-D206",
        "HIGH",
        "yaml.load_all without SafeLoader",
        {"constant_argument": "stream"},
    ),
    "pickle.Unpickler.load": (
        "SKY-D204",
        "CRITICAL",
        "Untrusted deserialization via pickle.Unpickler without a restricted find_class",
    ),
    "cloudpickle.load": (
        "SKY-D204",
        "CRITICAL",
        "Untrusted deserialization via cloudpickle.load (pickle format)",
    ),
    "cloudpickle.loads": (
        "SKY-D205",
        "CRITICAL",
        "cloudpickle.loads can execute code; only deserialize bytes from trusted sources",
    ),
    "pandas.read_pickle": (
        "SKY-D204",
        "CRITICAL",
        "pandas.read_pickle unpickles the file; only read files from trusted sources",
    ),
    "yaml.unsafe_load": (
        "SKY-D206",
        "HIGH",
        "yaml.unsafe_load can construct arbitrary Python objects",
    ),
    "yaml.unsafe_load_all": (
        "SKY-D206",
        "HIGH",
        "yaml.unsafe_load_all can construct arbitrary Python objects",
    ),
    "yaml.full_load": (
        "SKY-D206",
        "HIGH",
        "yaml.full_load uses FullLoader, which is not safe for untrusted input",
    ),
    "yaml.full_load_all": (
        "SKY-D206",
        "HIGH",
        "yaml.full_load_all uses FullLoader, which is not safe for untrusted input",
    ),
    "ruamel.yaml.YAML": (
        "SKY-D206",
        "HIGH",
        "ruamel.yaml YAML(typ='unsafe') can construct arbitrary Python objects",
        {"ruamel_unsafe_type": True},
    ),
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
    "os.popen": (
        "SKY-D203",
        "CRITICAL",
        "Use of os.popen()",
        {"constant_command_severity": "LOW", "command_positional_args": 3},
    ),
    "subprocess.*": (
        "SKY-D209",
        "HIGH",
        "subprocess call with shell=True",
        {
            "kw_equals": {"shell": True},
            "constant_command_severity": "LOW",
            "constant_argument": "command",
        },
    ),
    "subprocess.getoutput": (
        "SKY-D209",
        "HIGH",
        "subprocess.getoutput runs its command through the shell",
        {"constant_command_severity": "LOW"},
    ),
    "subprocess.getstatusoutput": (
        "SKY-D209",
        "HIGH",
        "subprocess.getstatusoutput runs its command through the shell",
        {"constant_command_severity": "LOW"},
    ),
    "asyncio.create_subprocess_shell": (
        "SKY-D209",
        "HIGH",
        "asyncio.create_subprocess_shell runs its command through the shell",
        {"constant_command_severity": "LOW"},
    ),
    "asyncio.subprocess.create_subprocess_shell": (
        "SKY-D209",
        "HIGH",
        "asyncio.create_subprocess_shell runs its command through the shell",
        {"constant_command_severity": "LOW"},
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
    "marshal.load": (
        "SKY-D233",
        "CRITICAL",
        "Untrusted deserialization via marshal.load",
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
    "dill.Unpickler.load": (
        "SKY-D233",
        "CRITICAL",
        "Untrusted deserialization via dill.Unpickler without a restricted find_class",
    ),
    ".exec_command": (
        "SKY-D235",
        "HIGH",
        "Remote command execution via exec_command (e.g., paramiko SSH)",
    ),
}

_WEAK_RANDOM_FINDING = (
    "SKY-D250",
    "MEDIUM",
    "Weak random source; use secrets or os.urandom for security-sensitive values",
    {"weak_random": True},
)
_WEAK_RANDOM_FUNCTIONS = (
    "random",
    "randint",
    "randrange",
    "choice",
    "choices",
    "randbytes",
    "getrandbits",
    "uniform",
    "triangular",
    "normalvariate",
    "gauss",
    "lognormvariate",
    "expovariate",
    "vonmisesvariate",
    "gammavariate",
    "betavariate",
    "binomialvariate",
    "paretovariate",
    "weibullvariate",
    "sample",
)
DANGEROUS_CALLS.update(
    {
        f"{owner}.{function}": _WEAK_RANDOM_FINDING
        for owner in ("random", "random.Random")
        for function in _WEAK_RANDOM_FUNCTIONS
        if f"{owner}.{function}" not in DANGEROUS_CALLS
    }
)


def track_import_aliases(aliases: dict, node: ast.Import) -> None:
    """``import a.b`` binds ``a`` to the package ``a``; only ``import a.b as
    c`` binds a name to the submodule."""
    for alias in node.names:
        if alias.asname:
            aliases[alias.asname] = alias.name
        else:
            top = alias.name.split(".", 1)[0]
            aliases[top] = top


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


_RNG_UNKNOWN = frozenset({"?"})
_RNG_CONSTRUCTORS = frozenset(
    {"random.Random", "random.SystemRandom", "secrets.SystemRandom"}
)


class _RandomBindingFlow(ValueFlow):
    """Binding identities for D250 only; value taint remains a separate flow."""

    def __init__(self, scope, owner, outer, max_steps):
        self.owner = owner
        self.snapshots = {}
        self.bindings = {}
        self._at = 0
        super().__init__(
            scope,
            self._expression,
            outer=outer,
            top=_RNG_UNKNOWN,
            read=lambda name, labels: (
                labels | _RNG_UNKNOWN
                if (id(scope), name) in owner.mutated_outer
                else labels
            ),
            max_steps=max_steps,
        )

    def _expression(self, node, value):
        if isinstance(node, ast.Attribute):
            labels = set()
            for base in value(node.value):
                plain = base.removeprefix("@")
                if plain in {"random", "secrets"} or plain in _RNG_CONSTRUCTORS:
                    qualified = f"{base}.{node.attr}"
                    if (
                        qualified.removeprefix("@") in _RNG_CONSTRUCTORS
                        or node.attr in _WEAK_RANDOM_FUNCTIONS
                    ):
                        labels.add(qualified)
                        continue
                labels.add("?")
            return labels
        if isinstance(node, ast.Call):
            labels = set()
            for constructor in value(node.func):
                if constructor in _RNG_CONSTRUCTORS and self.owner.stable(constructor):
                    labels.add("@" + constructor)
                else:
                    labels.add("?")
            return labels or _RNG_UNKNOWN
        return _RNG_UNKNOWN

    def _statement(self, node):
        previous = self._at
        self._at = getattr(node, "lineno", 0)
        try:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                snapshot = self.snapshots.setdefault(id(node), {})
                for name, labels in self.state.names.items():
                    snapshot[name] = snapshot.get(name, frozenset()) | labels
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    if isinstance(node, ast.Import):
                        name = alias.asname or alias.name.split(".", 1)[0]
                        qualified = alias.name if alias.asname else name
                    else:
                        name = alias.asname or alias.name
                        qualified = (
                            f"{node.module}.{alias.name}" if not node.level else "?"
                        )
                    labels = (
                        frozenset({qualified})
                        if qualified in {"random", "secrets"}
                        or qualified in _RNG_CONSTRUCTORS
                        or qualified
                        in {f"random.{part}" for part in _WEAK_RANDOM_FUNCTIONS}
                        else _RNG_UNKNOWN
                    )
                    self._bind(name, labels)
                return True
            return super()._statement(node)
        finally:
            self._at = previous

    def _bind(self, name, labels):
        # An opaque replacement cannot attest that an imported weak provider
        # became safe. Parameters and local shadows have no such inherited fact.
        if labels == _RNG_UNKNOWN:
            old = self._current(name)
            labels |= frozenset(
                part
                for part in old
                if part == "random" or part.startswith("@random.Random")
            )
        super()._bind(name, labels)
        self.bindings.setdefault(name, []).append((self._at, frozenset(labels)))

    def _call_mutation(self, node):
        # Drawing bytes changes generator state, not the provider identity.
        if isinstance(node.func, ast.Attribute) and (
            node.func.attr in _WEAK_RANDOM_FUNCTIONS
            or node.func.attr in {"Random", "SystemRandom"}
        ):
            return
        super()._call_mutation(node)


class _RandomBindings:
    """Bounded, cached scope facts; never changes other dangerous-call rules."""

    def __init__(self, module, filename, project_root):
        self.module = module
        self.filename = filename
        self.project_root = project_root
        self._ready = True
        self.flows = {}
        self.providers = {}
        self.remaining = 200000
        self.mutated_outer = set()
        self._index_outer_mutations()

    def __getstate__(self):
        # The flow cache holds the local outer() closure and is keyed by id(),
        # so rebuild it from the module after the worker result is unpickled.
        return {
            "module": self.module,
            "filename": self.filename,
            "project_root": self.project_root,
        }

    def __setstate__(self, state):
        self.module = state["module"]
        self.filename = state["filename"]
        self.project_root = state["project_root"]
        self._ready = False

    def _ensure_ready(self):
        if not self._ready:
            self.__init__(self.module, self.filename, self.project_root)

    def _index_outer_mutations(self):
        for scope in ast.walk(self.module):
            if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            locals_, declared = _scope_bindings(scope)
            written = set()
            for part in _scope_children(scope):
                if isinstance(part, ast.Name) and isinstance(
                    part.ctx, (ast.Store, ast.Del)
                ):
                    if part.id in declared:
                        written.add(part.id)
                elif isinstance(part, (ast.Attribute, ast.Subscript)) and isinstance(
                    part.ctx, (ast.Store, ast.Del)
                ):
                    root = part.value
                    while isinstance(root, (ast.Attribute, ast.Subscript)):
                        root = root.value
                    if isinstance(root, ast.Name) and root.id not in locals_:
                        written.add(root.id)
            # Global/nonlocal stores and writes through an outer instance can
            # invalidate a constructor fact between definition and invocation.
            # Do not use an unchanged-looking module binding as safe proof.
            parent = getattr(scope, "parent", None)
            while parent is not None:
                if isinstance(
                    parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    self.mutated_outer.update((id(parent), name) for name in written)
                parent = getattr(parent, "parent", None)

    def stable(self, qualified):
        self._ensure_ready()
        if qualified not in self.providers:
            self.providers[qualified] = provider_binding_is_stable(
                qualified, self.module, self.filename, self.project_root
            )
        return self.providers[qualified]

    def _scope(self, node):
        self._ensure_ready()
        while node is not None:
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
            node = getattr(node, "parent", None)
        return self.module

    def _flow(self, scope):
        self._ensure_ready()
        if id(scope) in self.flows:
            return self.flows[id(scope)]
        self.flows[id(scope)] = None
        if self.remaining <= 0:
            return None
        if isinstance(scope, ast.Module):

            def outer(name):
                return _RNG_UNKNOWN
        else:
            anchor = scope
            parent = getattr(scope, "parent", None)
            while parent is not None and not isinstance(
                parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                if isinstance(parent, ast.ClassDef):
                    anchor = parent
                parent = getattr(parent, "parent", None)
            parent_flow = self._flow(parent or self.module)
            if parent_flow is None:
                return None
            parent_engine = parent_flow[0]
            snapshot = parent_engine.snapshots.get(id(anchor), {})

            def outer(name):
                labels = snapshot.get(name, parent_engine._absent(name))
                # A closure can run after a later assignment, or before it.
                # Keep both reachable provider identities rather than trusting
                # the final text assignment as an initialization guarantee.
                for line, assigned in parent_engine.bindings.get(name, ()):
                    if line > anchor.lineno:
                        labels |= assigned
                if (id(parent_engine.scope), name) in self.mutated_outer:
                    labels |= _RNG_UNKNOWN
                return labels

        engine = _RandomBindingFlow(scope, self, outer, min(60000, self.remaining))
        watched = [
            part.func for part in _scope_children(scope) if isinstance(part, ast.Call)
        ]
        results = engine.run(watched)
        self.remaining -= engine._steps
        if results is None:
            return None
        result = (engine, results)
        self.flows[id(scope)] = result
        return result

    def call_name(self, node, legacy):
        self._ensure_ready()
        scope = self._scope(node)
        flow = self._flow(scope)
        if flow is None:
            return legacy
        engine, results = flow
        labels = results.get(id(node.func))
        if labels is None:
            return legacy
        for label in sorted(labels):
            plain = label.removeprefix("@")
            owner, _, method = plain.rpartition(".")
            if (
                owner in {"random", "random.Random"}
                and method in _WEAK_RANDOM_FUNCTIONS
            ):
                if label.startswith("@") or plain == legacy or self.stable(plain):
                    return f"random.{method}"
        if (
            labels
            and "?" not in labels
            and all(
                label.startswith(("@random.SystemRandom.", "@secrets.SystemRandom."))
                for label in labels
            )
        ):
            return ""
        root = node.func
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in engine._locals:
            # A parameter or a local binding shadows an outer import. Unknown
            # does not certify safety, but neither identifies the random API.
            return ""
        return legacy


def _random_callable_aliases(module):
    cached = getattr(module, "_skylos_random_callable_aliases", None)
    if cached is not None:
        return cached
    aliases = set()
    copies = {}
    for part in ast.walk(module):
        if isinstance(part, ast.Assign):
            targets, value = part.targets, part.value
        elif isinstance(part, ast.AnnAssign):
            targets, value = [part.target], part.value
        else:
            continue
        names = {
            item.id
            for target in targets
            for item in ast.walk(target)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store)
        }
        if isinstance(value, ast.Attribute) and value.attr in _WEAK_RANDOM_FUNCTIONS:
            aliases.update(names)
        elif isinstance(value, ast.Name):
            copies.setdefault(value.id, set()).update(names)
    pending = list(aliases)
    while pending:
        for name in copies.get(pending.pop(), ()):
            if name not in aliases:
                aliases.add(name)
                pending.append(name)
    module._skylos_random_callable_aliases = aliases
    return aliases


def _weak_random_call_name(node, legacy, module, filename, project_root=None):
    if module is None:
        return legacy
    candidate = (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in _WEAK_RANDOM_FUNCTIONS
        or legacy.startswith("random.")
    )
    if not candidate and isinstance(node.func, ast.Name):
        candidate = node.func.id in _random_callable_aliases(module)
    if not candidate:
        return legacy
    key = (str(filename), str(project_root))
    cached = getattr(module, "_skylos_random_bindings", None)
    if cached is None:
        cached = module._skylos_random_bindings = {}
    if key not in cached:
        cached[key] = _RandomBindings(module, filename, project_root)
    return cached[key].call_name(node, legacy)


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
    if not lowered or len(node.args) > opts.get("command_positional_args", 1):
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


def _call_low_risk_context(
    node: ast.Call,
    severity: str,
    rule_severity: str,
    opts,
    filename=None,
    project_root=None,
):
    """Evidence that a true call finding is low-risk where it occurs: a fixed
    shell command (Bandit rates these low), a weak hash over data that is
    neither a credential nor an identity (CodeQL reports only those), or a
    code, data or command argument that every path builds from literals."""
    if not opts:
        return None
    if opts.get("constant_command_severity") and severity != rule_severity:
        return {
            "reason": "constant-shell-command",
            "detail": "the command is a fixed string with no input",
        }
    if opts.get("security_optout"):
        names = _hash_input_names(node, opts.get("hash_data_index", 0))
        if names is None:
            return None
        sensitive = first_sensitive_name(names)
        if sensitive is None:
            return {
                "reason": "non-sensitive-hash-input",
                "detail": "the hashed data is not a credential, identity or certificate",
            }
    kind = opts.get("constant_argument")
    if kind and _constant_argument_safely_proved(node, kind, filename, project_root):
        return {
            "reason": "constant-argument",
            "detail": "every value that reaches the argument is built from literals",
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


def _hash_input_names(node: ast.Call, data_index: int = 0) -> list[str] | None:
    """Names that feed the hashed bytes: the call's data argument, values
    assigned to those names in the same scope, and ``.update()`` arguments on
    the hash object. None when the data cannot be read from the code.
    ``data_index`` is the data argument's position (1 for ``hashlib.new``)."""
    data = list(node.args[data_index : data_index + 1])
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


_HASHLIB_NEW_WEAK = {"md5": "hashlib.md5", "sha1": "hashlib.sha1"}


def _hashlib_new_weak_rule(node: ast.Call, name: str | None) -> str | None:
    """``hashlib.new("md5", data)`` is ``hashlib.md5(data)``: the rule key of
    the weak constructor a literal algorithm name selects, or None."""
    if name != "hashlib.new":
        return None
    algorithm = None
    if node.args:
        algorithm = node.args[0]
    for kw in node.keywords:
        if kw.arg == "name":
            algorithm = kw.value
    if not (isinstance(algorithm, ast.Constant) and isinstance(algorithm.value, str)):
        return None
    return _HASHLIB_NEW_WEAK.get(algorithm.value.lower())


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


_SAFE_YAML_LOADERS = frozenset(
    {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
)
_NATIVE_SAFE_YAML_LOADERS = frozenset(
    {
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
        "yaml.BaseLoader",
        "yaml.CBaseLoader",
        "yaml.loader.SafeLoader",
        "yaml.loader.BaseLoader",
        "yaml.cyaml.CSafeLoader",
        "yaml.cyaml.CBaseLoader",
    }
)


def _yaml_import_context(value: ast.AST):
    tree = value
    function = None
    while getattr(tree, "parent", None) is not None:
        if function is None and isinstance(
            tree, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            function = tree
        tree = tree.parent
    if not isinstance(tree, ast.Module):
        return None, None, None
    index = getattr(tree, "_skylos_yaml_direct_imports", None)
    if index is None:
        index = UntrustedSourceIndex(tree)
        tree._skylos_yaml_direct_imports = index
    return tree, function, index


_YAML_PROOF_NODE_LIMIT = 50000
_IMPORT_MACHINERY_MODULES = frozenset({"builtins", "importlib", "imp"})
_IMPORT_HOOK_NAMES = frozenset({"__import__", "__builtins__"})
_CODE_RUNNER_NAMES = frozenset({"exec", "eval", "compile"})
_SYS_IMPORT_STATE = frozenset({"modules", "_getframe", "settrace", "setprofile"})


def _non_import_binding_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return list(node.names)
    if isinstance(node, ast.MatchMapping):
        if node.rest:
            return [node.rest]
        return []
    if isinstance(node, ast.alias):
        return []
    name = getattr(node, "name", None)
    if isinstance(name, str):
        return [name]
    return []


def _sys_attribute_reaches_imports(attribute: str | None) -> bool:
    return (
        attribute is None
        or attribute in _SYS_IMPORT_STATE
        or attribute.startswith("__")
    )


class _YamlLoaderNamespace:
    """One capped pass over a module for the YAML loader proofs: the absolute
    ``from`` imports that bind each name and the names bound any other way
    (assignment, parameter, definition, handler or match name, ``del``,
    ``global``/``nonlocal``, module or relative import).

    ``refused`` when the module can reach the import machinery: a name,
    attribute or string ``__import__``/``__builtins__``; an import of
    ``builtins``, ``importlib`` or ``imp``; a star import; a name ``exec``,
    ``eval`` or ``compile``; or a sys module reference (any ``import sys
    [as X]``, ``from ... import sys`` or ``X.sys``) that is not the receiver
    of an ordinary attribute, such as ``sys.modules``, ``sys._getframe``,
    ``sys.settrace``, ``sys.setprofile``, a ``sys`` dunder, ``getattr(sys,
    ...)`` or ``vars(sys)``. Also refused past the scan cap. A refused module
    proves no loader safe. ``model.modules()``, ``app.exec()``,
    ``setattr(cfg, ...)`` and ``sys.argv`` do not refuse."""

    def __init__(self, tree: ast.Module):
        self.imports: dict[str, set[str]] = {}
        self.other: set[str] = set()
        self.refused = False
        self.rebinding = {}
        self.sys_names: set[str] = set()
        self.name_loads: dict[str, list[int]] = {}
        self.sys_attributes: list[int] = []
        self.receivers: dict[int, str] = {}
        for count, node in enumerate(ast.walk(tree)):
            if count >= _YAML_PROOF_NODE_LIMIT:
                self.refused = True
                return
            self._record(node)
        if not self.refused:
            self.refused = self._sys_reference_escapes()

    def _record(self, node: ast.AST) -> None:
        if isinstance(node, ast.ImportFrom):
            self._record_from_import(node)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in _IMPORT_MACHINERY_MODULES:
                    self.refused = True
                if alias.name == "sys" or (root == "sys" and not alias.asname):
                    self.sys_names.add(alias.asname or root)
                self.other.add(alias.asname or root)
        elif isinstance(node, ast.Name):
            if node.id in _IMPORT_HOOK_NAMES:
                self.refused = True
            if isinstance(node.ctx, ast.Load):
                if node.id in _CODE_RUNNER_NAMES:
                    self.refused = True
                self.name_loads.setdefault(node.id, []).append(id(node))
            else:
                self.other.add(node.id)
        elif isinstance(node, ast.Attribute):
            if node.attr in _IMPORT_HOOK_NAMES:
                self.refused = True
            self.receivers[id(node.value)] = node.attr
            if node.attr == "sys" and isinstance(node.ctx, ast.Load):
                self.sys_attributes.append(id(node))
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str) and node.value in _IMPORT_HOOK_NAMES:
                self.refused = True
        else:
            self.other.update(_non_import_binding_names(node))

    def _record_from_import(self, node: ast.ImportFrom) -> None:
        if (node.module or "").split(".", 1)[0] in _IMPORT_MACHINERY_MODULES:
            self.refused = True
        for alias in node.names:
            if alias.name == "*" or alias.name in _IMPORT_HOOK_NAMES:
                self.refused = True
            if node.module == "sys" and _sys_attribute_reaches_imports(alias.name):
                self.refused = True
            local = alias.asname or alias.name
            if alias.name == "sys":
                self.sys_names.add(local)
            if node.level or not node.module:
                self.other.add(local)
            else:
                qualified = f"{node.module}.{alias.name}"
                self.imports.setdefault(local, set()).add(qualified)

    def _sys_reference_escapes(self) -> bool:
        references = list(self.sys_attributes)
        for name in self.sys_names:
            references.extend(self.name_loads.get(name, ()))
        return any(
            _sys_attribute_reaches_imports(self.receivers.get(reference))
            for reference in references
        )

    def fallback_targets(self, tree: ast.Module, name: str, module_name=None):
        """What every binding of ``name`` imports, as in ``try: from yaml
        import CSafeLoader as SafeLoader`` / ``except ImportError: from yaml
        import SafeLoader``; empty when any binding is not an absolute
        ``from`` import, or when globals or ``name`` can be written at run
        time."""
        if self.refused or name in self.other or name not in self.imports:
            return frozenset()
        verdict = self.rebinding.get(module_name)
        if verdict is None:
            unsafe, unknown_global_write = _unsafe_import_roots(tree)
            dynamic, rebound = module_rebinding(tree, module_name)
            verdict = (unknown_global_write or dynamic, frozenset(unsafe) | rebound)
            self.rebinding[module_name] = verdict
        dynamic, written = verdict
        if dynamic or name in written:
            return frozenset()
        return frozenset(self.imports[name])


def _yaml_loader_namespace(tree: ast.Module) -> _YamlLoaderNamespace:
    namespace = getattr(tree, "_skylos_yaml_loader_namespace", None)
    if namespace is None:
        namespace = _YamlLoaderNamespace(tree)
        tree._skylos_yaml_loader_namespace = namespace
    return namespace


def _is_safe_yaml_loader(
    value: ast.AST, aliases=None, filename=None, project_root=None
) -> bool:
    tree, function, index = _yaml_import_context(value)
    if index is None:
        return False
    name = _resolve_expr_name(value)
    resolved = index.resolved_import(function, name) if name else None
    targets = frozenset()
    if resolved is not None:
        targets = frozenset({resolved})
    elif isinstance(value, ast.Name):
        targets = _yaml_loader_namespace(tree).fallback_targets(
            tree, value.id, module_name_for(filename)
        )
    return (
        bool(targets)
        and targets <= _NATIVE_SAFE_YAML_LOADERS
        and all(
            provider_binding_is_stable(
                target, tree, filename or "<tree-only>", project_root
            )
            for target in targets
        )
    )


def _is_native_safe_yaml_loader(
    value: ast.AST, aliases, filename=None, project_root=None
) -> bool:
    """A native data-only loader, including a proven builtin getattr fallback."""
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "getattr"
        and len(value.args) in {2, 3}
        and not value.keywords
    ):
        tree, function, index = _yaml_import_context(value)
        if index is None:
            return False
        builtin_getattrs = getattr(tree, "_skylos_yaml_builtin_getattrs", None)
        if builtin_getattrs is None:
            builtin_getattrs = builtin_references(tree, {"getattr"})
            tree._skylos_yaml_builtin_getattrs = builtin_getattrs
        if id(value.func) not in builtin_getattrs:
            return False
        if not provider_binding_is_stable(
            "builtins.getattr", tree, filename or "<tree-only>", project_root
        ):
            return False
        module, attr = value.args[0], value.args[1]
        name = _resolve_expr_name(module)
        if not name or index.resolved_import(function, name) != "yaml":
            return False
        if not (isinstance(attr, ast.Constant) and attr.value in _SAFE_YAML_LOADERS):
            return False
        if not provider_binding_is_stable(
            f"yaml.{attr.value}", tree, filename or "<tree-only>", project_root
        ):
            return False
        return len(value.args) == 2 or _is_native_safe_yaml_loader(
            value.args[2], aliases, filename, project_root
        )
    if not isinstance(value, (ast.Name, ast.Attribute)):
        return False
    return _is_safe_yaml_loader(value, aliases, filename, project_root)


def _yaml_loader_rebinding(
    module, name: str, aliases, filename=None, project_root=None
) -> bool | None:
    """How the module binds ``name`` other than by import.

    True when every such binding assigns a native safe loader, False when
    any other statement binds it (``SafeLoader = yaml.UnsafeLoader``, a
    parameter, a loop target), None when only imports bind it."""
    if not isinstance(module, ast.Module):
        return None
    namespace = _yaml_loader_namespace(module)
    if (
        not namespace.refused
        and name not in namespace.imports
        and name not in namespace.other
    ):
        return None
    assigned = set()
    verdict = None
    for child in ast.walk(module):
        if not isinstance(child, ast.Assign) or len(child.targets) != 1:
            continue
        target = child.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            assigned.add(id(target))
            if not _is_native_safe_yaml_loader(
                child.value, aliases, filename, project_root
            ):
                return False
            verdict = True
    for child in ast.walk(module):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if child.name == name:
                return False
        elif isinstance(child, ast.Name) and not isinstance(child.ctx, ast.Load):
            if child.id == name and id(child) not in assigned:
                return False
        elif isinstance(child, ast.arg) and child.arg == name:
            return False
        elif isinstance(child, ast.ExceptHandler) and child.name == name:
            return False
        elif isinstance(child, (ast.MatchAs, ast.MatchStar)) and child.name == name:
            return False
        elif isinstance(child, ast.Import):
            if any(
                (alias.asname or alias.name.split(".")[0]) == name
                for alias in child.names
            ):
                return False
        elif isinstance(child, ast.ImportFrom):
            for alias in child.names:
                if (alias.asname or alias.name) != name:
                    continue
                qualified = f"{child.module}.{alias.name}"
                if (
                    child.level
                    or qualified not in _NATIVE_SAFE_YAML_LOADERS
                    or not provider_binding_is_stable(
                        qualified, module, filename or "<tree-only>", project_root
                    )
                ):
                    return False
    if verdict is not None:
        namespace = getattr(module, "_skylos_yaml_assignment_namespace", None)
        if namespace is None:
            namespace = module_rebinding(module, module_name_for(filename))
            module._skylos_yaml_assignment_namespace = namespace
        dynamic, rebound = namespace
        if dynamic or name in rebound:
            return False
    return verdict


def _is_safe_loader_argument(
    value: ast.AST,
    aliases,
    loader_classes,
    filename=None,
    project_root=None,
    module=None,
) -> bool:
    if module is None:
        module = _module_of(value)
    if module is not None:
        namespace = _yaml_loader_namespace(module)
        if namespace.refused:
            return False
        if (
            isinstance(value, ast.Name)
            and value.id not in namespace.imports
            and value.id not in namespace.other
        ):
            return False
    safe_classes, local_classes = loader_classes
    if isinstance(value, ast.Name) and value.id in local_classes:
        return value.id in safe_classes
    if isinstance(value, ast.Name):
        rebinding = _yaml_loader_rebinding(
            module, value.id, aliases, filename, project_root
        )
        if rebinding is not None:
            return rebinding
    return _is_native_safe_yaml_loader(value, aliases, filename, project_root)


def _yaml_load_without_safeloader(
    node: ast.Call,
    aliases=None,
    loader_classes=(frozenset(), frozenset()),
    filename=None,
    project_root=None,
    module=None,
):
    for kw in node.keywords or []:
        if kw.arg == "Loader":
            if _is_safe_loader_argument(
                kw.value, aliases, loader_classes, filename, project_root, module
            ):
                return False
    if len(node.args) >= 2 and _is_safe_loader_argument(
        node.args[1], aliases, loader_classes, filename, project_root, module
    ):
        return False
    return True


_UNKNOWN = "unknown"
_OPAQUE = "constant"
_MUTABLE = "mutable"
_UNKNOWN_LABELS = frozenset({_UNKNOWN})
_OPAQUE_LABELS = frozenset({_OPAQUE})
_MAX_EXACT_VALUES = 8
_MAX_EXACT_LENGTH = 4096
_CONSTANT_ARGUMENT_KEYWORDS = {
    "code": frozenset(),
    "data": frozenset({"data"}),
    "stream": frozenset({"stream"}),
    "command": frozenset({"command", "args"}),
}
_CANDIDATE_KEYWORDS = frozenset({"data", "stream", "command", "args"})
_CONSTANT_SINK_NAMES = frozenset(
    {
        "Popen",
        "call",
        "check_call",
        "check_output",
        "eval",
        "exec",
        "getoutput",
        "getstatusoutput",
        "load",
        "load_all",
        "loads",
        "run",
        "system",
    }
)
_PURE_BUILTINS = frozenset(
    {
        "abs",
        "ascii",
        "bin",
        "bool",
        "bytes",
        "chr",
        "dict",
        "float",
        "frozenset",
        "hex",
        "int",
        "len",
        "list",
        "max",
        "min",
        "oct",
        "ord",
        "repr",
        "round",
        "set",
        "sorted",
        "str",
        "tuple",
    }
)
_CONTAINER_BUILTINS = frozenset({"dict", "list", "set", "sorted"})
_PURE_IMPORTED_FUNCTIONS = frozenset(
    {
        "base64.a85decode",
        "base64.a85encode",
        "base64.b16decode",
        "base64.b16encode",
        "base64.b32decode",
        "base64.b32encode",
        "base64.b64decode",
        "base64.b64encode",
        "base64.b85decode",
        "base64.b85encode",
        "base64.decodebytes",
        "base64.encodebytes",
        "base64.standard_b64decode",
        "base64.standard_b64encode",
        "base64.urlsafe_b64decode",
        "base64.urlsafe_b64encode",
        "binascii.a2b_base64",
        "binascii.a2b_hex",
        "binascii.b2a_base64",
        "binascii.b2a_hex",
        "binascii.hexlify",
        "binascii.unhexlify",
    }
)
_PURE_IMPORTED_NAMES = frozenset(
    name.rsplit(".", 1)[-1] for name in _PURE_IMPORTED_FUNCTIONS
)
_TEXT_METHODS = frozenset(
    {
        "capitalize",
        "casefold",
        "center",
        "decode",
        "encode",
        "endswith",
        "expandtabs",
        "format",
        "hex",
        "join",
        "ljust",
        "lower",
        "lstrip",
        "partition",
        "removeprefix",
        "removesuffix",
        "replace",
        "rjust",
        "rpartition",
        "rsplit",
        "rstrip",
        "split",
        "splitlines",
        "startswith",
        "strip",
        "swapcase",
        "title",
        "upper",
        "zfill",
    }
)
_EXACT_TEXT_METHODS = frozenset(
    {
        "decode",
        "encode",
        "lower",
        "lstrip",
        "removeprefix",
        "removesuffix",
        "replace",
        "rstrip",
        "strip",
        "upper",
    }
)
_CONTAINER_READ_METHODS = frozenset({"copy", "get", "items", "keys", "values"})
_FRAME_ACCESS = frozenset(
    {
        "_getframe",
        "ag_frame",
        "cr_frame",
        "currentframe",
        "f_back",
        "f_locals",
        "f_trace",
        "getinnerframes",
        "getouterframes",
        "gi_frame",
        "setprofile",
        "settrace",
        "tb_frame",
    }
)
_BUILTIN_NAMESPACES = frozenset({"builtins", "__builtins__"})
_CODE_ESCAPES = frozenset(
    {
        "__import__",
        "breakpoint",
        "compile",
        "delattr",
        "eval",
        "exec",
        "getattr",
        "globals",
        "input",
        "locals",
        "open",
        "setattr",
        "vars",
    }
)


def _exact_labels(value) -> frozenset:
    if isinstance(value, (str, bytes)) and len(value) > _MAX_EXACT_LENGTH:
        return _OPAQUE_LABELS
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value.bit_length() > _MAX_EXACT_LENGTH
    ):
        return _OPAQUE_LABELS
    if value is None or isinstance(value, (str, bytes, int, float, complex)):
        return frozenset({("value", type(value).__name__, value)})
    return _OPAQUE_LABELS


def _exact_values(labels: frozenset):
    """The exact constants ``labels`` stand for, or None if any is unknown."""
    if not labels or not all(isinstance(label, tuple) for label in labels):
        return None
    return [label[2] for label in labels]


def _without_exact(labels: frozenset) -> frozenset:
    return frozenset(label for label in labels if not isinstance(label, tuple))


def _bounded_labels(values) -> frozenset:
    labels = frozenset()
    for value in values:
        labels |= _exact_labels(value)
    if len(labels) > _MAX_EXACT_VALUES:
        return _without_exact(labels) | _OPAQUE_LABELS
    return labels


def _product(left, right):
    if len(left) * len(right) > _MAX_EXACT_VALUES:
        return None
    return [(a, b) for a in left for b in right]


def _constant_elements(labels: frozenset) -> frozenset:
    """Items iterated or unpacked from a value with these labels."""
    if _UNKNOWN in labels:
        return _UNKNOWN_LABELS
    elements = _without_exact(labels)
    if len(elements) != len(labels):
        elements |= _OPAQUE_LABELS
    return elements


def _constant_collect(node: ast.AST, labels: frozenset) -> frozenset:
    if _UNKNOWN in labels:
        return _UNKNOWN_LABELS
    return labels | {_MUTABLE}


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _binding_names(module: ast.AST):
    """How often each name is bound anywhere in the module, and the names
    bound only by imports."""
    counts: dict[str, int] = {}
    imported: dict[str, int] = {}

    def bind(name):
        counts[name] = counts.get(name, 0) + 1

    type_params = tuple(
        node
        for node in (
            getattr(ast, "TypeVar", None),
            getattr(ast, "ParamSpec", None),
            getattr(ast, "TypeVarTuple", None),
        )
        if node is not None
    )
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                bind(local)
                imported[local] = imported.get(local, 0) + 1
        elif isinstance(node, ast.arg):
            bind(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bind(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bind(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bind(node.rest)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bind(name)
        elif type_params and isinstance(node, type_params):
            bind(node.name)
    import_only = frozenset(
        name for name, count in imported.items() if counts.get(name) == count
    )
    return counts, import_only


def _module_reaches_frames_or_builtins(module: ast.AST) -> tuple[bool, bool]:
    """``(frames, builtins)``: the module touches frame objects (whose locals
    other code can write), or the builtins namespace (where builtins can be
    replaced)."""
    frames = False
    builtins = False
    for node in ast.walk(module):
        if isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Attribute):
            name = node.attr
            if node.attr in {"stack", "trace"} and _dotted_name(node.value) == (
                "inspect"
            ):
                frames = True
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            if any(alias.name in _BUILTIN_NAMESPACES for alias in node.names) or (
                isinstance(node, ast.ImportFrom) and node.module in _BUILTIN_NAMESPACES
            ):
                builtins = True
            continue
        else:
            continue
        if name in _FRAME_ACCESS:
            frames = True
        if name in _BUILTIN_NAMESPACES:
            builtins = True
    return frames, builtins


class _ConstantContext:
    """Module facts the constant-argument proof trusts: whether code can
    replace frame locals or builtins at run time, how often each name is
    bound, and the import bindings of pure standard-library codecs. Module
    globals are never trusted: another module can assign them."""

    def __init__(self, module, filename, project_root):
        self.module = module
        self.filename = filename
        self.project_root = project_root
        self.module_name = None
        if filename:
            self.module_name = module_name_for(filename)
        self._locals_dynamic = None
        self._globals = None
        self._bindings = None
        self._reach = None
        self.flows = {}
        self.pure_calls = {}

    def locals_dynamic(self) -> bool:
        """Code can write frame locals or replace names behind the module."""
        if self._locals_dynamic is None:
            runners = frozenset(
                id(node)
                for node in ast.walk(self.module)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"exec", "eval"}
            )
            dynamic, _ = module_rebinding(
                self.module, self.module_name, isolated_code_calls=runners
            )
            self._locals_dynamic = dynamic or self.reach()[0]
        return self._locals_dynamic

    def globals_rebinding(self):
        if self._globals is None:
            self._globals = module_rebinding(self.module, self.module_name)
        return self._globals

    def bindings(self):
        if self._bindings is None:
            self._bindings = _binding_names(self.module)
        return self._bindings

    def reach(self):
        if self._reach is None:
            self._reach = _module_reaches_frames_or_builtins(self.module)
        return self._reach

    def builtin_is_trusted(self, name: str) -> bool:
        if name not in _PURE_BUILTINS or self.bindings()[0].get(name, 0):
            return False
        if self.reach()[1]:
            return False
        dynamic, rebound = self.globals_rebinding()
        return not dynamic and name not in rebound

    def pure_function(self, func: ast.AST, scope: ast.AST) -> bool:
        dotted = _dotted_name(func)
        if not dotted or dotted.rsplit(".", 1)[-1] not in _PURE_IMPORTED_NAMES:
            return False
        if not dotted or dotted.split(".", 1)[0] not in self.bindings()[1]:
            return False
        key = (id(scope), dotted)
        cached = self.pure_calls.get(key)
        if cached is not None:
            return cached
        index = getattr(self.module, "_skylos_yaml_direct_imports", None)
        if index is None:
            index = UntrustedSourceIndex(self.module)
            self.module._skylos_yaml_direct_imports = index
        function = None
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = scope
        resolved = index.resolved_import(function, dotted)
        result = bool(
            resolved in _PURE_IMPORTED_FUNCTIONS
            and provider_binding_is_stable(
                resolved,
                self.module,
                self.filename or "<tree-only>",
                self.project_root,
            )
        )
        self.pure_calls[key] = result
        return result

    def static_labels(self, node: ast.AST) -> frozenset:
        """Labels of an expression that reads no name."""
        if isinstance(node, ast.Name):
            return _UNKNOWN_LABELS
        if isinstance(node, ast.NamedExpr):
            return _UNKNOWN_LABELS
        if isinstance(node, ast.IfExp):
            return self.static_labels(node.body) | self.static_labels(node.orelse)
        if isinstance(node, ast.BoolOp):
            labels = frozenset()
            for item in node.values:
                labels |= self.static_labels(item)
            return labels
        if isinstance(
            node,
            (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp, ast.Lambda),
        ):
            return _UNKNOWN_LABELS
        return _constant_evaluate(self, self.module, node, self.static_labels)


def _constant_context(module, filename, project_root) -> _ConstantContext:
    key = (str(filename), str(project_root))
    cache = getattr(module, "_skylos_constant_arguments", None)
    if cache is None:
        cache = {}
        module._skylos_constant_arguments = cache
    context = cache.get(key)
    if context is None:
        context = _ConstantContext(module, filename, project_root)
        cache[key] = context
    return context


def _formatted_text(value, conversion: int):
    if conversion == ord("r"):
        return repr(value)
    if conversion == ord("a"):
        return ascii(value)
    return str(value)


def _joined_labels(node: ast.JoinedStr, value) -> frozenset:
    texts = [""]
    exact = True
    for part in node.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            pieces = [part.value]
        elif isinstance(part, ast.FormattedValue):
            labels = value(part.value)
            if _UNKNOWN in labels:
                return _UNKNOWN_LABELS
            if part.format_spec is not None:
                if _UNKNOWN in value(part.format_spec):
                    return _UNKNOWN_LABELS
                exact = False
                continue
            values = _exact_values(labels)
            if values is None:
                exact = False
                continue
            pieces = [_formatted_text(item, part.conversion) for item in values]
        else:
            return _UNKNOWN_LABELS
        if exact:
            pairs = _product(texts, pieces)
            if pairs is None:
                exact = False
                continue
            texts = [left + right for left, right in pairs]
            if any(len(text) > _MAX_EXACT_LENGTH for text in texts):
                exact = False
    if not exact:
        return _OPAQUE_LABELS
    return _bounded_labels(texts)


def _binary_labels(node: ast.BinOp, value) -> frozenset:
    left = value(node.left)
    right = value(node.right)
    if _UNKNOWN in left or _UNKNOWN in right:
        return _UNKNOWN_LABELS
    if isinstance(node.op, ast.Add):
        left_values = _exact_values(left)
        right_values = _exact_values(right)
        if left_values is not None and right_values is not None:
            pairs = _product(left_values, right_values)
            if pairs is not None and all(
                type(a) is type(b) and isinstance(a, (str, bytes)) for a, b in pairs
            ):
                return _bounded_labels(a + b for a, b in pairs)
    combined = left | right
    if _MUTABLE in combined:
        return combined | _OPAQUE_LABELS
    return _OPAQUE_LABELS


def _subscript_labels(node: ast.Subscript, value) -> frozenset:
    base = value(node.value)
    index = node.slice
    if isinstance(index, ast.Slice):
        parts = [index.lower, index.upper, index.step]
        bounds = []
        for part in parts:
            if part is None:
                bounds.append([None])
                continue
            labels = value(part)
            if _UNKNOWN in labels:
                return _UNKNOWN_LABELS
            bounds.append(_exact_values(labels))
        if _UNKNOWN in base:
            return _UNKNOWN_LABELS
        if _MUTABLE in base:
            return base
        values = _exact_values(base)
        if values is None or any(
            bound is None
            or len(bound) != 1
            or not isinstance(bound[0], (int, type(None)))
            or isinstance(bound[0], bool)
            for bound in bounds
        ):
            return _OPAQUE_LABELS
        if not all(isinstance(item, (str, bytes)) for item in values):
            return _OPAQUE_LABELS
        cut = slice(bounds[0][0], bounds[1][0], bounds[2][0])
        try:
            return _bounded_labels(item[cut] for item in values)
        except (TypeError, ValueError):
            return _OPAQUE_LABELS
    key = value(index)
    if _UNKNOWN in base or _UNKNOWN in key:
        return _UNKNOWN_LABELS
    if _MUTABLE in base:
        return base
    values = _exact_values(base)
    keys = _exact_values(key)
    if (
        values is None
        or keys is None
        or len(keys) != 1
        or not isinstance(keys[0], int)
        or isinstance(keys[0], bool)
        or not all(isinstance(item, str) for item in values)
    ):
        return _OPAQUE_LABELS
    try:
        return _bounded_labels(item[keys[0]] for item in values)
    except IndexError:
        return frozenset()


def _exact_text_method(method: str, receivers, arguments):
    results = []
    for receiver in receivers:
        if method == "replace" and len(arguments) >= 2:
            new = arguments[1]
            if isinstance(new, (str, bytes)) and len(receiver) * max(len(new), 1) > (
                8 * _MAX_EXACT_LENGTH
            ):
                return None
        results.append(getattr(receiver, method)(*arguments))
    return results


def _method_labels(context, scope, node: ast.Call, value, arguments) -> frozenset:
    method = node.func.attr
    receiver = value(node.func.value)
    if _UNKNOWN in receiver or not receiver:
        return _UNKNOWN_LABELS
    if _MUTABLE in receiver:
        if method in _CONTAINER_READ_METHODS:
            return receiver | arguments
        return _UNKNOWN_LABELS
    if method not in _TEXT_METHODS:
        return _UNKNOWN_LABELS
    receivers = _exact_values(receiver)
    if receivers is not None and not all(
        isinstance(item, (str, bytes)) for item in receivers
    ):
        return _UNKNOWN_LABELS
    if receivers is None or method not in _EXACT_TEXT_METHODS or node.keywords:
        return _OPAQUE_LABELS
    exact_arguments = []
    for argument in node.args:
        values = _exact_values(value(argument))
        if values is None or len(values) != 1:
            return _OPAQUE_LABELS
        exact_arguments.append(values[0])
    try:
        results = _exact_text_method(method, receivers, exact_arguments)
    except (TypeError, ValueError, LookupError, UnicodeError):
        return _UNKNOWN_LABELS
    if results is None:
        return _OPAQUE_LABELS
    return _bounded_labels(results)


def _builtin_labels(name: str, node: ast.Call, value, arguments) -> frozenset:
    if name in _CONTAINER_BUILTINS:
        return arguments | {_MUTABLE}
    if name in {"tuple", "frozenset"}:
        return _without_exact(arguments) | _OPAQUE_LABELS
    if name in {"str", "repr", "ascii"} and len(node.args) == 1 and not node.keywords:
        values = _exact_values(value(node.args[0]))
        if values is not None and all(
            isinstance(item, (str, bytes, int, float, bool, type(None)))
            for item in values
        ):
            converted = {"str": str, "repr": repr, "ascii": ascii}[name]
            return _bounded_labels(converted(item) for item in values)
    return _OPAQUE_LABELS


def _call_labels(context, scope, node: ast.Call, value) -> frozenset:
    arguments = frozenset()
    for argument in node.args:
        arguments |= value(argument)
    for keyword in node.keywords:
        arguments |= value(keyword.value)
    if _UNKNOWN in arguments:
        return _UNKNOWN_LABELS
    func = node.func
    if isinstance(func, ast.Attribute) and context.pure_function(func, scope):
        return _OPAQUE_LABELS
    if isinstance(func, ast.Attribute):
        return _method_labels(context, scope, node, value, arguments)
    if isinstance(func, ast.Name) and context.builtin_is_trusted(func.id):
        return _builtin_labels(func.id, node, value, arguments)
    if isinstance(func, ast.Name) and context.pure_function(func, scope):
        return _OPAQUE_LABELS
    return _UNKNOWN_LABELS


def _constant_evaluate(context, scope, node: ast.AST, value) -> frozenset:
    """Labels for the constant-argument proof: exact constants, ``constant``
    (built from literals, exact value not kept), ``mutable`` (a builtin
    container built from literals; its item labels are included) or
    ``unknown``."""
    if isinstance(node, ast.Constant):
        return _exact_labels(node.value)
    if isinstance(node, ast.JoinedStr):
        return _joined_labels(node, value)
    if isinstance(node, ast.BinOp):
        return _binary_labels(node, value)
    if isinstance(node, (ast.UnaryOp, ast.Compare)):
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
        else:
            operands = [node.operand]
        for operand in operands:
            if _UNKNOWN in value(operand):
                return _UNKNOWN_LABELS
        return _OPAQUE_LABELS
    if isinstance(node, ast.Tuple):
        labels = frozenset()
        for item in node.elts:
            labels |= value(item)
        if _UNKNOWN in labels:
            return _UNKNOWN_LABELS
        return _without_exact(labels) | _OPAQUE_LABELS
    if isinstance(node, (ast.List, ast.Set)):
        labels = frozenset({_MUTABLE})
        for item in node.elts:
            labels |= value(item)
        if _UNKNOWN in labels:
            return _UNKNOWN_LABELS
        return labels
    if isinstance(node, ast.Dict):
        labels = frozenset({_MUTABLE})
        for key, item in zip(node.keys, node.values):
            if key is not None:
                labels |= value(key)
            labels |= value(item)
        if _UNKNOWN in labels:
            return _UNKNOWN_LABELS
        return labels
    if isinstance(node, ast.Starred):
        return value(node.value)
    if isinstance(node, ast.Subscript):
        return _subscript_labels(node, value)
    if isinstance(node, ast.Call):
        return _call_labels(context, scope, node, value)
    return _UNKNOWN_LABELS


def _constant_argument_node(node: ast.Call, keywords) -> ast.AST | None:
    if any(isinstance(argument, ast.Starred) for argument in node.args) or any(
        keyword.arg is None for keyword in node.keywords
    ):
        return None
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in keywords:
            return keyword.value
    return None


def _constant_scope(node: ast.AST) -> ast.AST | None:
    current = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return current
        if isinstance(current, (ast.Lambda, ast.ClassDef)):
            return None
        current = getattr(current, "parent", None)
    return None


def _scope_escapes(scope: ast.AST):
    """``(escaping, shared_items, rebound)``: names read other than as
    ``name[key]`` or referenced from a nested scope; names whose item is used
    other than as the base of a store, so a mutable item may be aliased; and
    names nested scopes declare ``nonlocal``."""
    escaping = set()
    shared_items = set()
    rebound = set()
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        current = pending.pop()
        if isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            for part in ast.walk(current):
                if isinstance(part, ast.Name):
                    escaping.add(part.id)
                elif isinstance(part, ast.Nonlocal):
                    rebound.update(part.names)
            continue
        if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
            parent = getattr(current, "parent", None)
            if not (isinstance(parent, ast.Subscript) and parent.value is current):
                escaping.add(current.id)
            else:
                top = parent
                while (
                    isinstance(getattr(top, "parent", None), ast.Subscript)
                    and isinstance(top.parent.ctx, ast.Load)
                    and top.parent.value is top
                ):
                    top = top.parent
                holder = getattr(top, "parent", None)
                if not (
                    isinstance(holder, ast.Subscript)
                    and holder.value is top
                    and isinstance(holder.ctx, (ast.Store, ast.Del))
                ) and isinstance(top.ctx, ast.Load):
                    shared_items.add(current.id)
        pending.extend(ast.iter_child_nodes(current))
    return frozenset(escaping), frozenset(shared_items), frozenset(rebound)


def _constant_flow_results(context: _ConstantContext, scope: ast.AST, required=None):
    key = id(scope)
    cached = context.flows.get(key)
    if cached is not None and (required is None or id(required) in cached[0]):
        return cached[1]
    candidates = []
    if required is not None:
        candidates.append(required)
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        current = pending.pop()
        if isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        if isinstance(current, ast.Call):
            name = _call_attribute_name(current)
            if name in _CONSTANT_SINK_NAMES:
                argument = _constant_argument_node(current, _CANDIDATE_KEYWORDS)
                if argument is not None:
                    candidates.append(argument)
        pending.extend(ast.iter_child_nodes(current))
    escaping, shared_items, rebound = _scope_escapes(scope)

    def outer(name):
        return _UNKNOWN_LABELS

    def read(name, labels):
        if name in rebound:
            return _UNKNOWN_LABELS
        if (name in escaping or name in shared_items) and _MUTABLE in labels:
            return labels | _UNKNOWN_LABELS
        return labels

    def read_item(name, labels):
        if name in shared_items and _MUTABLE in labels:
            return labels | _UNKNOWN_LABELS
        return labels

    def evaluate(node, value):
        return _constant_evaluate(context, scope, node, value)

    flow = ValueFlow(
        scope,
        evaluate,
        outer=outer,
        top=_UNKNOWN_LABELS,
        element=_constant_elements,
        collect=_constant_collect,
        read=read,
        read_item=read_item,
        opaque=escaping,
    )
    results = flow.run(candidates)
    context.flows[key] = (frozenset(id(node) for node in candidates), results)
    return results


def _constant_code_is_closed(node: ast.Call, codes, context) -> bool:
    """Fixed code that cannot reach data from outside it: it reads no name
    bound in this module, no code-running or input builtin and no dunder
    attribute, and no name at all when a namespace is passed, since the
    namespace can supply it."""
    namespaces = len(node.args) > 1 or any(
        keyword.arg in {"globals", "locals"} for keyword in node.keywords
    )
    mode = "exec"
    if _call_attribute_name(node) == "eval":
        mode = "eval"
    for code in codes:
        if isinstance(code, bytes):
            try:
                code = code.decode("utf-8")
            except UnicodeDecodeError:
                return False
        if not isinstance(code, str):
            return False
        try:
            tree = ast.parse(code, mode=mode)
        except (SyntaxError, ValueError):
            continue
        except (MemoryError, RecursionError):
            return False
        for part in ast.walk(tree):
            if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Load):
                if (
                    namespaces
                    or part.id in _CODE_ESCAPES
                    or context.bindings()[0].get(part.id, 0)
                ):
                    return False
            elif isinstance(part, ast.Attribute) and part.attr.startswith("__"):
                return False
    return True


def _constant_argument_safely_proved(node, kind, filename, project_root) -> bool:
    """The constant-argument proof only ever hides a finding, so any failure
    to complete it keeps the finding listed."""
    try:
        return _constant_argument_proved(node, kind, filename, project_root)
    except Exception:
        return False


def _shell_text_is_inert(text: str) -> bool:
    if _has_shell_expansion(text):
        return False
    return not any(
        risk.rule_id in _DANGEROUS_COMMAND_RULES for risk in scan_shell_command(text)
    )


def _constant_argument_proved(
    node: ast.Call, kind: str, filename, project_root
) -> bool:
    """Every assignment that reaches the code, data or command argument of
    ``node`` inside its function is built from literals: no parameter, global,
    closure variable, attribute, unknown call or escaped container. At module
    level only an argument that reads no name qualifies. Code must be fixed
    text that reads nothing from outside it, and a command fixed text with no
    shell expansion or command-guard risk."""
    keywords = _CONSTANT_ARGUMENT_KEYWORDS.get(kind)
    if keywords is None:
        return False
    argument = _constant_argument_node(node, keywords)
    module = _module_of(node)
    scope = _constant_scope(node)
    if argument is None or module is None or scope is None:
        return False
    context = _constant_context(module, filename, project_root)
    if isinstance(scope, ast.Module):
        labels = context.static_labels(argument)
    else:
        results = _constant_flow_results(context, scope, argument)
        if results is None:
            return False
        labels = results.get(id(argument))
    if not labels or _UNKNOWN in labels or context.locals_dynamic():
        return False
    if kind == "code":
        codes = _exact_values(labels)
        return codes is not None and _constant_code_is_closed(node, codes, context)
    if kind != "command":
        return True
    texts = _exact_values(labels)
    if texts is None or not all(isinstance(text, str) for text in texts):
        return False
    return all(_shell_text_is_inert(text) for text in texts)


def _ruamel_unsafe_type(node: ast.Call) -> bool:
    """``YAML(typ="unsafe")``: ruamel.yaml's legacy loader that builds
    arbitrary Python objects. The default round-trip and ``safe`` types do
    not."""
    for kw in node.keywords:
        if kw.arg != "typ":
            continue
        values = [kw.value]
        if isinstance(kw.value, (ast.List, ast.Tuple)):
            values = kw.value.elts
        return any(
            isinstance(value, ast.Constant) and value.value == "unsafe"
            for value in values
        )
    return False


def _unpickler_import_names(module: ast.Module) -> dict[str, str]:
    names = {}
    for child in ast.walk(module):
        if isinstance(child, ast.Import):
            for alias in child.names:
                if alias.asname:
                    names[alias.asname] = alias.name
                else:
                    top = alias.name.split(".", 1)[0]
                    names[top] = top
        elif isinstance(child, ast.ImportFrom) and child.module and not child.level:
            for alias in child.names:
                if alias.name != "*":
                    names[alias.asname or alias.name] = f"{child.module}.{alias.name}"
    return names


_UNPICKLER_BASES = {
    "pickle.Unpickler": "pickle.Unpickler",
    "_pickle.Unpickler": "pickle.Unpickler",
    "dill.Unpickler": "dill.Unpickler",
}


def unrestricted_unpickler_classes(module) -> dict[str, str]:
    """Module classes that inherit an unpickler without overriding
    ``find_class``, mapped to the library unpickler they behave as.

    A subclass that defines ``find_class`` follows the documented way to
    restrict which globals a pickle may load and is not reported."""
    if not isinstance(module, ast.Module):
        return {}
    imports = _unpickler_import_names(module)
    classes = [
        statement for statement in module.body if isinstance(statement, ast.ClassDef)
    ]
    counts = {}
    for klass in classes:
        counts[klass.name] = counts.get(klass.name, 0) + 1
    found: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for klass in classes:
            if klass.name in found or counts[klass.name] != 1:
                continue
            if any(
                isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                and member.name == "find_class"
                for member in klass.body
            ):
                continue
            for base in klass.bases:
                dotted = _resolve_expr_name(base, imports)
                library = _UNPICKLER_BASES.get(dotted or "")
                if library is None and isinstance(base, ast.Name):
                    library = found.get(base.id)
                if library is not None:
                    found[klass.name] = library
                    changed = True
                    break
    return found


def unpickler_load_name(name: str | None, classes: dict[str, str]) -> str | None:
    """``Sub(f).load()`` on an unrestricted subclass reads like the library
    unpickler's ``load``."""
    if not name or not classes:
        return name
    head, _, method = name.rpartition(".")
    if method == "load" and head in classes:
        return f"{classes[head]}.load"
    return name


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


_SESSION_STORES = frozenset({"session"})
_COOKIE_SETTERS = frozenset({"set_cookie", "set_signed_cookie"})
_COOKIE_JARS = frozenset({"cookies", "COOKIES"})
_WEAK_RANDOM_FLOW_HOPS = 4


def _is_session_store(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _SESSION_STORES
    if isinstance(node, ast.Attribute):
        return node.attr in _SESSION_STORES
    return False


def _target_looks_security_sensitive(target: ast.AST) -> bool:
    if isinstance(target, ast.Name):
        return _name_looks_security_sensitive(target.id)
    if isinstance(target, ast.Attribute):
        return _name_looks_security_sensitive(target.attr)
    if isinstance(target, ast.Subscript):
        if _is_session_store(target.value):
            return True
        if isinstance(target.slice, ast.Constant) and isinstance(
            target.slice.value, str
        ):
            return _name_looks_security_sensitive(target.slice.value)
        if isinstance(target.slice, ast.Name) and _name_looks_security_sensitive(
            target.slice.id
        ):
            return True
        if isinstance(target.slice, ast.Attribute) and _name_looks_security_sensitive(
            target.slice.attr
        ):
            return True
        return _target_looks_security_sensitive(target.value)
    return False


def _enclosing_function(node: ast.AST) -> ast.AST | None:
    current = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = getattr(current, "parent", None)
    return None


def _enclosing_function_name(node: ast.AST) -> str | None:
    function = _enclosing_function(node)
    if function is None:
        return None
    return function.name


def _reads_cookie_jar(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Attribute) and child.attr in _COOKIE_JARS
        for child in ast.walk(node)
    )


def _call_attribute_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return None


_MODULE_FLOW_BUDGET = 200000


def _rebound_names(statement: ast.AST) -> list[str]:
    if isinstance(statement, ast.Assign):
        return [
            target.id for target in statement.targets if isinstance(target, ast.Name)
        ]
    if (
        isinstance(statement, ast.AnnAssign)
        and statement.value is not None
        and isinstance(statement.target, ast.Name)
    ):
        return [statement.target.id]
    return []


class _ModuleCalls:
    """One pass over a module: how often each name is defined, names bound
    other than by a definition, direct call sites by callee name, and a work
    budget shared by the weak random flow walks in the module."""

    def __init__(self, module: ast.AST):
        self.definitions: dict[str, int] = {}
        self.rebound: set[str] = set()
        self.calls: dict[str, list[ast.Call]] = {}
        self.blocks = {}
        self.budget = _MODULE_FLOW_BUDGET
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.definitions[node.name] = self.definitions.get(node.name, 0) + 1
            elif isinstance(node, ast.Name):
                if not isinstance(node.ctx, ast.Load):
                    self.rebound.add(node.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    self.rebound.add(alias.asname or alias.name.split(".", 1)[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.calls.setdefault(node.func.id, []).append(node)

    def spend(self, amount: int = 1) -> bool:
        self.budget -= amount
        return self.budget >= 0

    def block_index(self, parent: ast.AST, field: str):
        """Positions of a block's statements and, per name, the positions of
        statements that rebind it."""
        key = (id(parent), field)
        cached = self.blocks.get(key)
        if cached is None:
            block = getattr(parent, field)
            positions = {id(item): position for position, item in enumerate(block)}
            rebinds: dict[str, list[int]] = {}
            for position, item in enumerate(block):
                for name in _rebound_names(item):
                    rebinds.setdefault(name, []).append(position)
            cached = (positions, rebinds)
            self.blocks[key] = cached
        return cached


def _module_calls(module: ast.AST) -> _ModuleCalls:
    index = getattr(module, "_skylos_module_calls", None)
    if index is None:
        index = _ModuleCalls(module)
        module._skylos_module_calls = index
    return index


def _scope_name_loads(scope: ast.AST) -> dict[str, list[ast.Name]]:
    """Loads of each name in ``scope``, excluding nested function and class
    bodies, cached on the scope node."""
    cached = getattr(scope, "_skylos_weak_random_loads", None)
    if cached is not None:
        return cached
    loads: dict[str, list[ast.Name]] = {}
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        current = pending.pop()
        if isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
        ):
            continue
        if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
            loads.setdefault(current.id, []).append(current)
        pending.extend(ast.iter_child_nodes(current))
    scope._skylos_weak_random_loads = loads
    return loads


def _rebinding_cutoff(statement: ast.AST, name: str, index: _ModuleCalls):
    """End of the first later statement in an enclosing block that rebinds
    ``name`` unconditionally; uses after it read the new value."""
    cutoff = None
    current = statement
    while current is not None and not isinstance(
        current,
        (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef, ast.Module),
    ):
        parent = getattr(current, "parent", None)
        if parent is None:
            break
        for field in ("body", "orelse", "finalbody"):
            block = getattr(parent, field, None)
            if not isinstance(block, list):
                continue
            positions, rebinds = index.block_index(parent, field)
            position = positions.get(id(current))
            if position is None:
                continue
            later = rebinds.get(name, ())
            following = bisect.bisect_right(later, position)
            if following < len(later):
                sibling = block[later[following]]
                end = (sibling.end_lineno, sibling.end_col_offset)
                if cutoff is None or end < cutoff:
                    cutoff = end
        current = parent
    return cutoff


def _name_reaches_security_use(
    target: ast.AST, statement: ast.AST, hops: int, seen: set, follow=None, spend=None
) -> bool:
    """Later reads of a local name bound to a weak random value."""
    if hops <= 0 or not isinstance(target, ast.Name):
        return False
    scope = _enclosing_scope(statement)
    module = _module_of(statement)
    if scope is None or module is None:
        return False
    key = (id(scope), target.id, id(statement))
    if key in seen:
        return False
    seen.add(key)
    index = _module_calls(module)
    start = (statement.end_lineno, statement.end_col_offset)
    cutoff = _rebinding_cutoff(statement, target.id, index)
    for load in _scope_name_loads(scope).get(target.id, ()):
        if not (spend or index.spend)():
            return False
        position = (load.lineno, load.col_offset)
        if position < start:
            continue
        if cutoff is not None and position >= cutoff:
            continue
        if (follow or _weak_random_value_reaches_security_use)(load, hops - 1, seen):
            return True
    return False


def _module_of(node: ast.AST) -> ast.AST | None:
    current = node
    while getattr(current, "parent", None) is not None:
        current = current.parent
    if isinstance(current, ast.Module):
        return current
    return None


def _result_reaches_security_use(
    function: ast.AST | None, hops: int, seen: set
) -> bool:
    """Calls of a module-level helper that returns a weak random value."""
    if hops <= 0 or not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    module = getattr(function, "parent", None)
    if not isinstance(module, ast.Module):
        return False
    key = ("result", id(function))
    if key in seen:
        return False
    seen.add(key)
    index = _module_calls(module)
    if index.definitions.get(function.name) != 1 or function.name in index.rebound:
        return False
    for call in index.calls.get(function.name, ()):
        if not index.spend():
            return False
        if _weak_random_value_reaches_security_use(call, hops - 1, seen):
            return True
    return False


def _weak_random_value_reaches_security_use(
    node: ast.AST, hops: int, seen: set
) -> bool:
    """Whether the value of ``node`` flows, within its function, through
    string conversion, slicing, formatting and encoding calls into a
    credential-named store, keyword or return, the session, a cookie value,
    or an equality check against a request cookie."""
    current: ast.AST = node
    while True:
        parent = getattr(current, "parent", None)
        if parent is None:
            return False

        if isinstance(parent, ast.Assign):
            if current is not parent.value:
                return False
            if any(_target_looks_security_sensitive(t) for t in parent.targets):
                return True
            return any(
                _name_reaches_security_use(t, parent, hops, seen)
                for t in parent.targets
            )

        if isinstance(parent, ast.AnnAssign):
            if current is not parent.value:
                return False
            if _target_looks_security_sensitive(parent.target):
                return True
            return _name_reaches_security_use(parent.target, parent, hops, seen)

        if isinstance(parent, ast.AugAssign):
            if current is not parent.value:
                return False
            if _target_looks_security_sensitive(parent.target):
                return True
            return _name_reaches_security_use(parent.target, parent, hops, seen)

        if isinstance(parent, ast.NamedExpr):
            if _target_looks_security_sensitive(parent.target):
                return True
            statement = parent
            while statement is not None and not isinstance(statement, ast.stmt):
                statement = getattr(statement, "parent", None)
            if statement is not None and _name_reaches_security_use(
                parent.target, statement, hops, seen
            ):
                return True
            current = parent
            continue

        if isinstance(parent, ast.keyword):
            if _name_looks_security_sensitive(parent.arg):
                return True
            call = getattr(parent, "parent", None)
            if (
                parent.arg == "value"
                and isinstance(call, ast.Call)
                and _call_attribute_name(call) in _COOKIE_SETTERS
            ):
                return True
            current = parent
            continue

        if isinstance(parent, ast.Return):
            function = _enclosing_function(parent)
            if function is not None and _name_looks_security_sensitive(function.name):
                return True
            return _result_reaches_security_use(function, hops, seen)

        if isinstance(parent, ast.Call):
            name = _call_attribute_name(parent)
            if current is not parent.func:
                if name in _COOKIE_SETTERS and any(
                    arg is current for arg in parent.args[1:2]
                ):
                    return True
                if name == "compare_digest" and any(
                    _reads_cookie_jar(arg) for arg in parent.args if arg is not current
                ):
                    return True
            current = parent
            continue

        if isinstance(parent, ast.Compare):
            operands = [parent.left, *parent.comparators]
            if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in parent.ops) and any(
                _reads_cookie_jar(operand)
                for operand in operands
                if operand is not current
            ):
                return True
            current = parent
            continue

        if isinstance(parent, ast.Subscript):
            if current is not parent.value:
                return False
            current = parent
            continue

        if isinstance(parent, ast.Attribute):
            call = getattr(parent, "parent", None)
            if not (isinstance(call, ast.Call) and call.func is parent):
                return False
            current = parent
            continue

        if isinstance(parent, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            if current is not parent.elt:
                return False
            current = parent
            continue

        if isinstance(
            parent,
            (
                ast.BinOp,
                ast.BoolOp,
                ast.FormattedValue,
                ast.IfExp,
                ast.JoinedStr,
                ast.UnaryOp,
            ),
        ):
            current = parent
            continue

        return False


def _weak_random_has_security_context(
    node: ast.Call, current_symbol: str | None = None
) -> bool:
    if private_model_slug_evidence(node):
        return True
    if _name_looks_security_sensitive(current_symbol):
        return True

    function_name = _enclosing_function_name(node)
    if _name_looks_security_sensitive(function_name):
        return True

    return _weak_random_value_reaches_security_use(node, _WEAK_RANDOM_FLOW_HOPS, set())


def _client_nonce_material_reaches_return(node: ast.Call, context) -> bool:
    """Additional, conservative proof for the standard client-nonce spelling.

    Only returned material counts. Unknown transforms and functions containing
    a cryptographic generator defer this additional recall; existing weak-random
    findings are never suppressed by this proof.
    """
    function = _enclosing_function(node)
    if function is None or function.name.strip("_") != "cnonce":
        return False
    module, _, imports = _yaml_import_context(node)
    if module is None or imports is None or function not in module.body:
        return False
    from .native_function_snapshot import (
        native_function_snapshot_is_stable,
        nonce_builtin_references,
        nonce_imported_provider_is_stable,
    )

    source_name = _dotted_name(node.func)
    source_provider = (
        imports.resolved_import(function, source_name) if source_name else None
    )
    if not source_provider or not (
        nonce_imported_provider_is_stable(
            source_provider,
            module,
            context.get("filename"),
            context.get("project_root"),
        )
    ):
        return False

    strong_generators = {
        "secrets.token_bytes",
        "secrets.token_hex",
        "secrets.token_urlsafe",
        "os.urandom",
        "random.SystemRandom",
    }
    for part in ast.walk(function):
        if isinstance(part, ast.Call):
            dotted = _dotted_name(part.func)
            if (
                dotted
                and imports.resolved_import(function, dotted) in strong_generators
            ):
                return False

    transparent_providers = {
        "hashlib.md5",
        "hashlib.sha1",
        "hashlib.sha224",
        "hashlib.sha256",
        "hashlib.sha384",
        "hashlib.sha512",
        "base64.b64encode",
        "base64.urlsafe_b64encode",
        "binascii.hexlify",
    }
    transparent_methods = {"encode", "decode", "hex", "hexdigest", "digest", "to_bytes"}
    primitive_builtins = nonce_builtin_references(
        module,
        function,
        context.get("filename"),
        context.get("project_root"),
        {"str", "bytes", "hex", "range"},
    )
    builtin_calls = primitive_builtins
    # Defer this additional recall when other, opaque entropy could contribute.
    # This deliberately covers only parameterless primitive nonce builders.
    args = function.args
    if (
        function.decorator_list
        or args.posonlyargs
        or args.args
        or args.kwonlyargs
        or args.vararg
        or args.kwarg
    ):
        return False
    parts = list(ast.walk(function))
    if len(parts) > 2048 or any(
        isinstance(
            part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        )
        and part is not function
        for part in parts
    ):
        return False
    bound = {
        part.id
        for part in parts
        if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)
    }
    calls = [part for part in parts if isinstance(part, ast.Call)]
    callee_parts = set()
    for call in calls:
        head = call.func
        while isinstance(head, ast.Attribute):
            callee_parts.add(id(head))
            head = head.value
        dotted = _dotted_name(call.func)
        if isinstance(head, ast.Name) and (
            id(head) in primitive_builtins
            or dotted
            and imports.resolved_import(function, dotted)
        ):
            callee_parts.add(id(head))
    if any(
        isinstance(part, ast.Name)
        and isinstance(part.ctx, ast.Load)
        and part.id not in bound
        and id(part) not in callee_parts
        or isinstance(part, ast.Attribute)
        and id(part) not in callee_parts
        for part in parts
    ):
        return False
    weak_providers = {"random." + name for name in _WEAK_RANDOM_FUNCTIONS}
    for call in calls:
        dotted = _dotted_name(call.func)
        provider = imports.resolved_import(function, dotted) if dotted else None
        method = call.func if isinstance(call.func, ast.Attribute) else None
        if provider == "time.ctime":
            if not native_function_snapshot_is_stable(
                provider, module, context.get("filename"), context.get("project_root")
            ) and not nonce_imported_provider_is_stable(
                provider, module, context.get("filename"), context.get("project_root")
            ):
                return False
        elif (
            provider in weak_providers
            or provider in transparent_providers
            or id(call.func) in primitive_builtins
        ):
            continue
        elif method is None or not (
            method.attr in transparent_methods
            and provider is None
            or method.attr == "join"
            and isinstance(method.value, ast.Constant)
            and isinstance(method.value.value, (str, bytes))
        ):
            return False
    budget = [512]

    def spend():
        budget[0] -= 1
        return budget[0] >= 0

    def follow(current, hops, seen):
        while (parent := getattr(current, "parent", None)) is not None:
            if not spend():
                return False
            if isinstance(parent, ast.Return):
                return _enclosing_function(parent) is function
            if isinstance(parent, (ast.Assign, ast.AnnAssign)):
                if current is not parent.value:
                    return False
                targets = (
                    parent.targets
                    if isinstance(parent, ast.Assign)
                    else [parent.target]
                )
                return any(
                    _name_reaches_security_use(t, parent, hops, seen, follow, spend)
                    for t in targets
                )
            if isinstance(parent, ast.Call):
                dotted = _dotted_name(parent.func)
                provider = imports.resolved_import(function, dotted) if dotted else None
                method = parent.func if isinstance(parent.func, ast.Attribute) else None
                transparent = (
                    id(parent.func) in builtin_calls
                    or provider in transparent_providers
                    and (
                        nonce_imported_provider_is_stable(
                            provider,
                            module,
                            context.get("filename", "<tree-only>"),
                            context.get("project_root"),
                        )
                        or native_function_snapshot_is_stable(
                            provider,
                            module,
                            context.get("filename", "<tree-only>"),
                            context.get("project_root"),
                        )
                    )
                    or method is not None
                    and (
                        method.attr in transparent_methods
                        and current is parent.func
                        or method.attr == "join"
                        and isinstance(method.value, ast.Constant)
                        and isinstance(method.value.value, (str, bytes))
                    )
                )
                if not transparent:
                    return False
            elif isinstance(parent, ast.Attribute):
                if parent.attr not in transparent_methods or not isinstance(
                    getattr(parent, "parent", None), ast.Call
                ):
                    return False
            elif isinstance(parent, ast.Subscript):
                if current is not parent.value and not (
                    current is parent.slice
                    and isinstance(parent.value, ast.Constant)
                    and isinstance(parent.value.value, (str, bytes))
                ):
                    return False
            elif isinstance(parent, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                if current is not parent.elt:
                    return False
            elif isinstance(parent, (ast.Tuple, ast.List)):
                if current not in parent.elts:
                    return False
            elif isinstance(parent, ast.IfExp):
                if current is parent.test:
                    return False
            elif not isinstance(
                parent, (ast.BinOp, ast.FormattedValue, ast.JoinedStr, ast.UnaryOp)
            ):
                return False
            current = parent
        return False

    return follow(node, _WEAK_RANDOM_FLOW_HOPS, set())


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
        self._source_owned_code = frozenset()
        self._module = None
        self._unpickler_classes = {}
        self._safe_yaml_loaders = None
        self._yaml_filename = None
        self._yaml_project_root = None

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

    def _yaml_loader_classes(self):
        if self._safe_yaml_loaders is None:
            self._safe_yaml_loaders = yaml_loader_classes(
                self._module, self._yaml_filename, self._yaml_project_root
            )
        return self._safe_yaml_loaders

    def _assigned_calls_for(self, node: ast.AST) -> dict[str, str]:
        return self.assigned_calls_by_scope.setdefault(self._scope_key(node), {})

    def _track_import(self, node: ast.Import) -> None:
        track_import_aliases(self.aliases, node)

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
            self._source_owned_code = source_owned_code_calls(
                node, context.get("filename"), context.get("project_root")
            )
            self._module = node
            self._unpickler_classes = unrestricted_unpickler_classes(node)
            self._yaml_filename = context.get("filename")
            self._yaml_project_root = context.get("project_root")
            self._safe_yaml_loaders = None
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
        name = yaml_load_call_name(node, self._module) or name
        name = unpickler_load_name(name, self._unpickler_classes)
        findings = []
        for candidate in callable_names(
            node,
            name,
            self._module,
            context.get("filename"),
            context.get("project_root"),
        ):
            findings.extend(self._call_findings(node, context, candidate))
        return findings or None

    def _call_findings(self, node, context, name):
        if not name:
            return []

        findings = []
        weak_hash_key = _hashlib_new_weak_rule(node, name)
        rule_name = weak_hash_key or name
        random_name = _weak_random_call_name(
            node,
            name,
            self._module,
            context.get("filename"),
            context.get("project_root"),
        )

        for rule_key, tup in DANGEROUS_CALLS.items():
            if tup[0] == "SKY-D210":
                # TLS checks need scoped provider/configuration evidence,
                # including aliases and visible local lookalikes.
                continue
            candidate = random_name if tup[0] == "SKY-D250" else rule_name
            if not _matches_rule(candidate, rule_key):
                continue

            if rule_key == "pickle.loads" and id(node) in self._safe_pickle_loads:
                continue

            if rule_key in {"exec", "eval"} and id(node) in self._source_owned_code:
                continue

            rule_id = tup[0]
            severity = tup[1]
            message = tup[2]
            opts = tup[3] if len(tup) > 3 else None
            if weak_hash_key is not None:
                opts = {**opts, "hash_data_index": 1}

            if rule_key in {"yaml.load", "yaml.load_all"}:
                if not _yaml_load_without_safeloader(
                    node,
                    self.aliases,
                    self._yaml_loader_classes(),
                    context.get("filename"),
                    context.get("project_root"),
                    self._module,
                ):
                    continue

            if opts and opts.get("ruamel_unsafe_type"):
                if not _ruamel_unsafe_type(node):
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
                if not _weak_random_has_security_context(
                    node
                ) and not _client_nonce_material_reaches_return(node, context):
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
            low_risk = _call_low_risk_context(
                node,
                finding["severity"],
                severity,
                opts,
                context.get("filename"),
                context.get("project_root"),
            )
            if low_risk is not None:
                finding["low_risk_context"] = low_risk
            if opts and opts.get("weak_random"):
                evidence = private_model_slug_evidence(node)
                if evidence:
                    finding["security_evidence"] = evidence
            findings.append(finding)
            break

        if not findings and not _is_test_module(context.get("filename")):
            unverified = _tls_verification_disabled(
                node,
                name,
                filename=context.get("filename"),
                project_root=context.get("project_root"),
            )
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

        return findings
