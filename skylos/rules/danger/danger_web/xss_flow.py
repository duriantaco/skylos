from __future__ import annotations
import ast
import re
import sys
from skylos.rules.danger.danger_web.html_context import (
    ATTR_SAFE,
    CLEAN,
    RAW,
    TEXT_SAFE,
    URL_SAFE,
    hole_requirements,
    safe_url_prefix,
    split_parts,
)
from skylos.rules.danger.danger_web.url_patterns import FLAG_NAMES, url_pattern_is_safe
from skylos.rules.danger.taint import TaintVisitor, XSS_SANITIZERS
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex

# Template-source sinks: the first argument (or ``source=``) is compiled as a
# Jinja template, so untrusted text there is template code, not data.
_TEMPLATE_SOURCE_SINKS = frozenset(
    {"render_template_string", "flask.render_template_string", "from_string"}
)

_QUOTE_ESCAPING_SANITIZERS = frozenset(
    {"html.escape", "markupsafe.escape", "markupsafe.Markup.escape", "Markup.escape"}
)
_NUMBER_BUILTINS = frozenset(
    {"int", "float", "bool", "complex", "len", "ord", "id", "hash"}
)
_SAME_START_METHODS = frozenset(
    {"strip", "lstrip", "rstrip", "lower", "upper", "casefold"}
)
_EXITS = (ast.Return, ast.Raise, ast.Continue, ast.Break)
_NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_TYPE_PARAMETERS = frozenset({"TypeVar", "ParamSpec", "TypeVarTuple"})
_MAX_HELPER_DEPTH = 8
_NAME_FIELDS = {
    ast.FunctionDef: "name",
    ast.AsyncFunctionDef: "name",
    ast.ClassDef: "name",
    ast.arg: "arg",
    ast.ExceptHandler: "name",
    ast.MatchAs: "name",
    ast.MatchStar: "name",
    ast.MatchMapping: "rest",
}
_DISPLAYS = (ast.List, ast.Tuple, ast.Set, ast.Dict)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_MAX_HELPER_ROUNDS = 6
_REGEX_TESTS = frozenset({"match", "fullmatch", "search"})


def _qualified_name_from_call(node: ast.Call):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)
    if isinstance(func, ast.Name):
        return func.id
    return None


def _qualified_name_from_call_target(node: ast.AST):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Call):
        return _qualified_name_from_call_target(node.func)
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _is_interpolated_string(node: ast.AST):
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


def _const_str_value(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# Tags that make a string HTML. Angle-bracket markers used as plain-text
# protocol delimiters (``<search>``, ``<answer>``, ``<think>`` in LLM output,
# XML payloads) are not rendered by a browser as markup the user sees.
_HTML_TAG_RE = re.compile(
    r"<\s*/?\s*(?:html|head|body|div|span|p|a|b|i|u|em|strong|br|hr|img|script|"
    r"style|iframe|form|input|button|textarea|select|option|label|table|thead|"
    r"tbody|tr|td|th|ul|ol|li|h[1-6]|pre|code|blockquote|section|article|nav|"
    r"header|footer|main|title|meta|link|svg|video|audio|source|object|embed|"
    r"small|sup|sub|dl|dt|dd|center|font|marquee)(?=[\s>/])",
    re.IGNORECASE,
)


def _text_contains_html(text: str) -> bool:
    return ("<" in text) and (">" in text) and bool(_HTML_TAG_RE.search(text))


def _const_contains_html(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _text_contains_html(node.value)
    return False


def _parts_have_html(parts) -> bool:
    return any(part[0] == "text" and _text_contains_html(part[1]) for part in parts)


def _own_nodes(func: ast.AST):
    """Nodes of ``func``'s body, not descending into nested scopes."""
    stack = list(func.body)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _NESTED_SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def _bound_names(node: ast.AST):
    """Names that ``node`` itself binds or declares in its scope."""
    if isinstance(node, ast.Name):
        return [name for name in (node.id,) if not isinstance(node.ctx, ast.Load)]
    if isinstance(node, ast.alias):
        return [node.asname or node.name.split(".")[0]]
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return list(node.names)
    field = _NAME_FIELDS.get(type(node))
    if field is None and type(node).__name__ in _TYPE_PARAMETERS:
        field = "name"
    if field is None:
        return []
    return [name for name in (getattr(node, field),) if name]


def _binding_counts(tree: ast.AST) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in ast.walk(tree):
        for name in _bound_names(node):
            counts[name] = counts.get(name, 0) + 1
    return counts


def _statements(tree: ast.AST):
    """Every statement in the module, without walking into expressions."""
    stack = list(getattr(tree, "body", []))
    while stack:
        node = stack.pop()
        yield node
        for field in ("body", "orelse", "finalbody", "handlers", "cases"):
            block = getattr(node, field, None)
            if isinstance(block, list):
                stack.extend(block)


def _import_pairs(node: ast.AST):
    """``(local name, qualified name)`` for each name an import binds."""
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname:
                yield alias.asname, alias.name
            else:
                yield alias.name.split(".")[0], alias.name.split(".")[0]
    elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
        for alias in node.names:
            yield alias.asname or alias.name, f"{node.module}.{alias.name}"


def _imported_names(tree: ast.AST) -> dict[str, set[str]]:
    """Local name -> qualified names any import in the module binds it to."""
    imported: dict[str, set[str]] = {}
    for node in _statements(tree):
        for local, target in _import_pairs(node):
            imported.setdefault(local, set()).add(target)
    return imported


def _dotted_prefixes(names) -> frozenset[str]:
    prefixes = set()
    for name in names:
        parts = name.split(".")
        prefixes.update(".".join(parts[:end]) for end in range(1, len(parts) + 1))
    return frozenset(prefixes)


def _target_roots(target: ast.AST):
    """Local names an assignment to ``target`` writes or mutates."""
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for element in target.elts for name in _target_roots(element)]
    if isinstance(target, ast.Starred):
        return _target_roots(target.value)
    return [name for name in (_chain_root(target),) if name]


def _chain_root(node: ast.AST):
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _unstarred(arg: ast.AST) -> ast.AST:
    if isinstance(arg, ast.Starred):
        return arg.value
    return arg


def _aliased_roots(value: ast.AST) -> set[str]:
    """Locals whose object ``value`` may be (``b = a``, ``b = a[0]``,
    ``b, c = a, d``), so a change through the new name reaches them."""
    if isinstance(value, (ast.Tuple, ast.List)):
        return {name for element in value.elts for name in _aliased_roots(element)}
    return {name for name in (_chain_root(_unstarred(value)),) if name}


def _is_startswith_call(test: ast.AST) -> bool:
    return (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Attribute)
        and test.func.attr == "startswith"
        and len(test.args) == 1
        and not test.keywords
    )


def _startswith_prefixes(test: ast.AST):
    if not _is_startswith_call(test):
        return None
    arg = test.args[0]
    values = [arg]
    if isinstance(arg, ast.Tuple):
        values = arg.elts
    if not values or not all(_const_str_value(value) is not None for value in values):
        return None
    return [value.value for value in values]


def _exit_branch(stmt: ast.AST):
    """For ``if`` with exactly one branch that never falls through, whether
    the code after it runs only when the test held (True) or failed (False)."""
    if not isinstance(stmt, ast.If):
        return None
    body_exits = bool(stmt.body) and isinstance(stmt.body[-1], _EXITS)
    else_exits = bool(stmt.orelse) and isinstance(stmt.orelse[-1], _EXITS)
    if body_exits == else_exits:
        return None
    return else_exits


class _Scope:
    """How to read names while measuring a value: the visitor's environment
    on the scan path, or a helper's flow-insensitive one. ``strict`` scopes
    prove a value safe, so expressions they do not model keep the lowest
    level of the names in them."""

    def __init__(self, lookup, func, strict: bool):
        self.lookup = lookup
        self.func = func
        self.strict = strict


class _LayeredLookup:
    """Names bound inside a comprehension, over the enclosing lookup."""

    def __init__(self, outer):
        self.outer = outer
        self.bound: dict[str, int] = {}

    def bind(self, name: str, level: int) -> None:
        self.bound[name] = min(self.bound.get(name, CLEAN), level)

    def lookup(self, name: str) -> int:
        if name in self.bound:
            return self.bound[name]
        return self.outer(name)


class _HelperEnv:
    """A helper's locals, each at the lowest level any write can give it."""

    def __init__(self, checker, levels: dict, func: ast.AST):
        self.checker = checker
        self.levels = levels
        self.scope = _Scope(self.lookup, func, True)

    def lookup(self, name: str) -> int:
        if name in self.levels:
            return self.levels[name]
        return self.checker._module_lookup(name)

    def lower(self, names, level: int) -> bool:
        changed = False
        for name in names:
            if level < self.lookup(name):
                self.levels[name] = level
                changed = True
        return changed


class _XSSFlowChecker(TaintVisitor):
    SAFE_MARK_FUNCS = {"Markup", "mark_safe"}

    def __init__(self, tree, file_path, findings, sanitizers=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.untrusted_sources = UntrustedSourceIndex(tree)
        self._tree = tree
        self._counts = None
        self._imports = None
        self._stable_builtins: dict[str, bool] = {}
        self._sanitizer_prefixes = _dotted_prefixes(self.sanitizers)
        self._helpers = None
        self._parents = None
        self._summaries: dict = {}
        self._in_progress: set = set()
        self._checked_cache: dict = {}
        self._local_counts: dict = {}
        self._url_checkers: dict = {}
        self._checking_urls: set = set()

    def _template_source_arg(self, node: ast.Call, qn: str):
        last = qn.split(".")[-1]
        if last == "from_string":
            # jinja2.Environment().from_string(src) / env.from_string(src);
            # require a receiver that looks like a Jinja environment.
            if not isinstance(node.func, ast.Attribute):
                return None
            receiver = (_qualified_name_from_call_target(node.func.value) or "").lower()
            if "env" not in receiver and "jinja" not in receiver:
                return None
        elif last != "render_template_string":
            return None
        if node.args:
            return node.args[0]
        for kw in node.keywords:
            if kw.arg == "source":
                return kw.value
        return None

    def _check_template_injection(self, node: ast.Call, qn: str) -> None:
        tmpl = self._template_source_arg(node, qn)
        if tmpl is None or isinstance(tmpl, ast.Constant):
            return
        evidence = self.untrusted_sources.evidence(
            self._current_function(),
            tmpl,
            sink=f"`{qn}()` template source",
            missing_guard="pass user input as a template variable, not template text",
            evidence_kind="python_ssti_taint",
        )
        if evidence is None:
            return
        # Operator-controlled configuration is not attacker input here.
        if all(
            "os.environ" in label or "os.getenv" in label
            for label in evidence.get("sources", [])
        ):
            return
        self.findings.append(
            {
                "rule_id": "SKY-D349",
                "severity": "CRITICAL",
                "message": (
                    "Server-side template injection: untrusted input "
                    f"({evidence['source']}) is compiled as template source by "
                    f"{qn.split('.')[-1]}(). Pass it as a context variable instead."
                ),
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
                "symbol": self._current_symbol(),
                "security_evidence": evidence,
            }
        )

    def _template_is_unsafe_literal(self, node: ast.AST):
        s = _const_str_value(node)
        if not s:
            return False
        low = s.lower()
        if "|safe" in low:
            return True
        if "{% autoescape false %}" in low:
            return True
        return False

    def _set(self, name, level):
        if level is True:
            level = RAW
        elif level is False:
            level = CLEAN
        if not self.env_stack:
            self._push()
        self.env_stack[-1][name] = level

    def _get(self, name):
        for env in reversed(self.env_stack):
            if name in env:
                return env[name]
        return CLEAN

    def _module_lookup(self, name: str) -> int:
        if self.env_stack:
            return self.env_stack[0].get(name, CLEAN)
        return CLEAN

    def _scope(self) -> _Scope:
        return _Scope(self._get, self._current_function(), False)

    def visit_Assign(self, node):
        level = self._level(node.value, self._scope())
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._set(target.id, level)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and isinstance(node.target, ast.Name):
            self._set(node.target.id, self._level(node.value, self._scope()))
        self.generic_visit(node)

    def is_tainted(self, node):
        return self._level(node, self._scope()) == RAW

    def _module_binding_counts(self) -> dict[str, int]:
        if self._counts is None:
            self._counts = _binding_counts(self._tree)
        return self._counts

    def _builtin_is_stable(self, name: str) -> bool:
        """``name`` still means the builtin: nothing in the module binds it,
        writes it on another module, or can rebind globals dynamically."""
        if name not in self._stable_builtins:
            self._stable_builtins[name] = bool(
                not self._module_binding_counts().get(name)
                and self._import_names_are_stable(name)
                and self._sanitizer_is_unpatched(name)
            )
        return self._stable_builtins[name]

    def _may_import(self, dotted: str, wanted: frozenset) -> bool:
        """Some import binds ``dotted``'s first name to a module or member
        in ``wanted`` (a set of dotted prefixes): a cheap test that runs
        before resolving the name in full."""
        if self._imports is None:
            self._imports = _imported_names(self._tree)
        root = dotted.split(".")[0]
        return any(target in wanted for target in self._imports.get(root, ()))

    def _level(self, node: ast.AST | None, scope: _Scope) -> int:
        """How far ``node``'s value is made safe for HTML (see html_context)."""
        if node is None or isinstance(node, ast.Constant):
            return CLEAN
        if isinstance(node, (ast.Await, ast.Starred)):
            return self._level(node.value, scope)
        parts = split_parts(node)
        if parts is not None:
            return self._parts_level(parts, scope)
        if isinstance(node, ast.Call):
            return self._call_level(node, scope)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            if _chain_root(node) == self.request_obj:
                return RAW
            return self._level(node.value, scope)
        if isinstance(node, ast.Name):
            return scope.lookup(node.id)
        if not scope.strict:
            return CLEAN
        return self._strict_level(node, scope)

    def _strict_level(self, node: ast.AST, scope: _Scope) -> int:
        if isinstance(node, ast.IfExp):
            return min(self._level(node.body, scope), self._level(node.orelse, scope))
        if isinstance(node, ast.BoolOp):
            return min(self._level(value, scope) for value in node.values)
        if _is_truth_value(node):
            return CLEAN
        if isinstance(node, _DISPLAYS):
            return self._container_level(node, scope)
        if isinstance(node, _COMPREHENSIONS):
            return self._comprehension_level(node, scope)
        return self._subtree_level(node, scope)

    def _subtree_level(self, node: ast.AST, scope: _Scope) -> int:
        """Lowest level of any name or call inside an expression the
        helper analysis does not model."""
        level = CLEAN
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                if child.id == self.request_obj:
                    return RAW
                level = min(level, scope.lookup(child.id))
            elif isinstance(child, ast.Call) and child is not node:
                level = min(level, self._call_level(child, scope))
        return level

    def _container_level(self, node: ast.AST, scope: _Scope) -> int:
        """Lowest level of a display's items. Printing a container shows
        each item's ``repr``, whose added quotes are only safe in text."""
        if isinstance(node, ast.Dict):
            items = [item for item in (*node.keys, *node.values) if item is not None]
        else:
            items = node.elts
        level = min((self._level(item, scope) for item in items), default=CLEAN)
        if level == CLEAN:
            return CLEAN
        return min(level, TEXT_SAFE)

    def _comprehension_level(self, node: ast.AST, scope: _Scope) -> int:
        """Lowest level of the items a comprehension makes, with each loop
        variable at the level of what it iterates over."""
        layer = _LayeredLookup(scope.lookup)
        inner = _Scope(layer.lookup, scope.func, True)
        for generator in node.generators:
            level = self._level(generator.iter, inner)
            for name in _target_roots(generator.target):
                layer.bind(name, level)
        if isinstance(node, ast.DictComp):
            elements = [node.key, node.value]
        else:
            elements = [node.elt]
        level = min(self._level(element, inner) for element in elements)
        if isinstance(node, ast.GeneratorExp) or level == CLEAN:
            return level
        return min(level, TEXT_SAFE)

    def _hole_levels(self, parts, scope: _Scope) -> list[int]:
        levels = []
        for part in parts:
            if part[0] != "value":
                continue
            if part[2]:
                levels.append(CLEAN)
            else:
                levels.append(min((self._level(n, scope) for n in part[1]), default=CLEAN))
        return levels

    def _parts_level(self, parts, scope: _Scope) -> int:
        levels = self._hole_levels(parts, scope)
        lowest = min(levels, default=CLEAN)
        if _parts_have_html(parts) and _context_failure(parts, levels) is not None:
            return RAW
        return lowest

    def _html_failure(self, node: ast.AST, scope: _Scope):
        """``(level, spot)`` of the first value in HTML built by ``node``
        that is not escaped enough for where it lands, else None."""
        parts = split_parts(node)
        if parts is None or not _parts_have_html(parts):
            return None
        return _context_failure(parts, self._hole_levels(parts, scope))

    def _known_call_level(self, node: ast.Call, scope: _Scope):
        """Level of a call to an input source, an escape or a builtin that
        always returns a number; None for any other call."""
        func = node.func
        if isinstance(func, ast.Name) and func.id in self.sources:
            return RAW
        sanitizer = self._sanitizer_name(node, scope.func)
        if sanitizer is not None:
            return self._escaped_level(node, sanitizer, scope)
        if (
            isinstance(func, ast.Name)
            and func.id in _NUMBER_BUILTINS
            and self._builtin_is_stable(func.id)
        ):
            return CLEAN
        return None

    def _call_level(self, node: ast.Call, scope: _Scope) -> int:
        known = self._known_call_level(node, scope)
        if known is not None:
            return known
        func = node.func
        arg_levels = [self._level(arg, scope) for arg in node.args]
        kw_levels = [self._level(kw.value, scope) for kw in node.keywords]
        levels = arg_levels + kw_levels
        if isinstance(func, ast.Attribute):
            levels.append(self._level(func.value, scope))
        lowest = min(levels, default=CLEAN)
        if lowest < CLEAN and _call_tail(func) == "unescape":
            return RAW
        helper_level = self._helper_call_level(node, arg_levels, kw_levels)
        if helper_level is None:
            return lowest
        if helper_level > lowest and not self._import_names_are_stable(func.id):
            return lowest
        return helper_level

    def _sanitizer_name(self, node: ast.Call, func: ast.AST | None):
        """The escape ``node`` calls: by its qualified name, or through a
        name that an import binds and the module cannot swap out, as in
        ``from html import escape`` or ``import html as h``."""
        call_name = _qualified_name_from_call(node)
        if not call_name:
            return None
        if call_name in self.sanitizers:
            if self._root_is_rebound(call_name, func):
                return None
            return call_name
        if not self._may_import(call_name, self._sanitizer_prefixes):
            return None
        if not self._import_names_are_stable(call_name):
            return None
        resolved = self.untrusted_sources.resolved_import(func, call_name)
        if resolved in self.sanitizers and self._sanitizer_is_unpatched(resolved):
            return resolved
        return None

    def _root_is_rebound(self, call_name: str, func: ast.AST | None) -> bool:
        """``html`` in ``html.escape`` is bound in scope to something other
        than an import (a parameter, a local), so it is not the module."""
        root = call_name.split(".")[0]
        if not self._module_binding_counts().get(root):
            return False
        return self.untrusted_sources.resolved_import(func, call_name) is None

    def _escapes_quotes(self, node: ast.Call, sanitizer: str) -> bool:
        if sanitizer not in _QUOTE_ESCAPING_SANITIZERS:
            return False
        if any(isinstance(arg, ast.Starred) for arg in node.args):
            return False
        if sanitizer != "html.escape":
            return True
        if any(kw.arg is None for kw in node.keywords):
            return False
        quote = None
        if len(node.args) > 1:
            quote = node.args[1]
        for kw in node.keywords:
            if kw.arg == "quote":
                quote = kw.value
        return quote is None or (isinstance(quote, ast.Constant) and bool(quote.value))

    def _escaped_level(self, node: ast.Call, sanitizer: str, scope: _Scope) -> int:
        if not node.args:
            return CLEAN
        strength = TEXT_SAFE
        if self._escapes_quotes(node, sanitizer):
            strength = ATTR_SAFE
            if self._scheme_safe(node.args[0], node, scope.func):
                strength = URL_SAFE
        return max(strength, self._level(node.args[0], scope))

    def _scheme_safe(self, value: ast.AST, node: ast.AST, func: ast.AST | None) -> bool:
        """``value``, read at ``node``, cannot start with a scheme that runs
        script: a name a scheme allowlist guards there, a local bound once to
        a URL-checking helper's result, or a call to such a helper."""
        base = self._url_text_base(value)
        if isinstance(base, ast.Name):
            if base.id in self._scheme_checked(node, func):
                return True
            binding = self._single_local_binding(base.id, func)
            if binding is None:
                return False
            base = self._url_text_base(binding.value)
        return self._returns_checked_url(base, func)

    def _returns_checked_url(self, call: ast.AST, func: ast.AST | None) -> bool:
        """``call`` runs a module-level helper whose every ``return`` gives
        None, a constant that cannot run script, or a scheme-checked value."""
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            return False
        name = call.func.id
        helper = self._module_helpers().get(name)
        if not isinstance(helper, ast.FunctionDef):
            return False
        if func is not None and self._function_counts(func).get(name):
            return False
        if not self._import_names_are_stable(name):
            return False
        key = id(helper)
        if key in self._url_checkers:
            return self._url_checkers[key]
        if key in self._checking_urls or len(self._checking_urls) >= _MAX_HELPER_DEPTH:
            return False
        self._checking_urls.add(key)
        try:
            verdict = True
            for node in _own_nodes(helper):
                if isinstance(node, ast.Return) and not self._returns_safe_url(node, helper):
                    verdict = False
                    break
        finally:
            self._checking_urls.discard(key)
        self._url_checkers[key] = verdict
        return verdict

    def _returns_safe_url(self, node: ast.Return, helper: ast.AST) -> bool:
        if node.value is None:
            return True
        if isinstance(node.value, ast.Constant):
            return safe_url_prefix(str(node.value.value))
        return self._scheme_safe(node.value, node, helper)

    def _function_counts(self, func: ast.AST) -> dict[str, int]:
        key = id(func)
        if key not in self._local_counts:
            self._local_counts[key] = _binding_counts(func)
        return self._local_counts[key]

    def _single_local_binding(self, name: str, func: ast.AST | None):
        """The one plain assignment to ``name`` in ``func`` when nothing else
        binds it there (no parameter, loop target, ``global`` or nested
        definition of that name)."""
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        if self._function_counts(func).get(name) != 1:
            return None
        for node in _own_nodes(func):
            if _assigns_only(node, name):
                return node
        return None

    def _url_text_base(self, node: ast.AST) -> ast.AST:
        """``node`` without ``str(...)``, ``.strip()``, ``.lower()`` and
        similar wrappers, which keep where a URL's scheme or path starts."""
        while isinstance(node, ast.Call):
            inner = self._same_start_operand(node)
            if inner is None:
                return node
            node = inner
        return node

    def _url_text_root(self, node: ast.AST):
        """The name behind ``str(p)``, ``p.strip()``, ``p.lower()`` and
        similar, which keep where a URL's scheme or path starts."""
        base = self._url_text_base(node)
        if isinstance(base, ast.Name):
            return base.id
        return None

    def _same_start_operand(self, call: ast.Call):
        """``p`` for ``str(p)`` or ``p.strip()``-like calls, else None."""
        func = call.func
        if call.keywords:
            return None
        if isinstance(func, ast.Name) and func.id == "str" and len(call.args) == 1:
            if self._builtin_is_stable("str"):
                return call.args[0]
            return None
        if isinstance(func, ast.Attribute) and func.attr in _SAME_START_METHODS and not call.args:
            return func.value
        return None

    def _guard_names(self, test: ast.AST, holds: bool, func: ast.AST | None) -> set[str]:
        """Names a ``test`` that came out ``holds`` proves start with a
        scheme or path that cannot run script (``url.startswith(("https://",
        "/"))``, ``URL_RE.fullmatch(url)``). Blocklists such as
        ``not url.startswith("javascript:")`` prove nothing."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._guard_names(test.operand, not holds, func)
        if isinstance(test, ast.BoolOp):
            groups = [self._guard_names(value, holds, func) for value in test.values]
            if isinstance(test.op, ast.And) == holds:
                return set().union(*groups)
            return set.intersection(*groups)
        if isinstance(test, ast.Compare):
            return self._match_object_guard(test, holds, func)
        if not holds:
            return set()
        regex = self._regex_test(test, func)
        if regex is not None:
            return self._regex_guard(*regex)
        prefixes = _startswith_prefixes(test)
        if not prefixes:
            return set()
        if not all(safe_url_prefix(prefix) for prefix in prefixes):
            return set()
        root = self._url_text_root(test.func.value)
        if root is None:
            return set()
        return {root}

    def _match_object_guard(self, test: ast.Compare, holds: bool, func: ast.AST | None) -> set[str]:
        """``URL_RE.match(url) is not None`` and ``... is None``: a regex test
        gives a match object or None, so comparing it with None is the test."""
        if len(test.ops) != 1 or not _is_none(test.comparators[0]):
            return set()
        if self._regex_test(test.left, func) is None:
            return set()
        if isinstance(test.ops[0], ast.IsNot):
            return self._guard_names(test.left, holds, func)
        if isinstance(test.ops[0], ast.Is):
            return self._guard_names(test.left, not holds, func)
        return set()

    def _regex_guard(self, pattern: str, flags: int, method: str, subject: ast.AST) -> set[str]:
        if not url_pattern_is_safe(pattern, flags, method):
            return set()
        root = self._url_text_root(subject)
        if root is None:
            return set()
        return {root}

    def _regex_test(self, test: ast.AST, func: ast.AST | None):
        """``(pattern, flags, method, subject)`` for ``re.match(p, s)``-style
        calls and ``compiled.match(s)`` on a pattern compiled from a
        constant, else None."""
        if not isinstance(test, ast.Call):
            return None
        if any(isinstance(arg, ast.Starred) for arg in test.args):
            return None
        method = _call_tail(test.func)
        if method not in _REGEX_TESTS:
            return None
        if isinstance(test.func, ast.Attribute):
            compiled = self._compiled_pattern(test.func.value, func)
            if compiled is not None:
                if len(test.args) != 1 or test.keywords:
                    return None
                return compiled[0], compiled[1], method, test.args[0]
        if self._re_member(test.func, func) != f"re.{method}":
            return None
        args = _regex_arguments(test, ("pattern", "string", "flags"))
        if args is None or "pattern" not in args or "string" not in args:
            return None
        pattern = _const_str_value(args["pattern"])
        flags = self._regex_flags(args.get("flags"), func)
        if pattern is None or flags is None:
            return None
        return pattern, flags, method, args["string"]

    def _compiled_pattern(self, node: ast.AST, func: ast.AST | None):
        """``(pattern, flags)`` of ``re.compile(constant, flags)``, written
        in place or bound once at module level to a name ``func`` does not
        rebind."""
        if isinstance(node, ast.Call):
            return self._compile_call(node, func)
        if not isinstance(node, ast.Name):
            return None
        if func is not None and self._function_counts(func).get(node.id):
            return None
        if self._module_binding_counts().get(node.id) != 1:
            return None
        if not self._import_names_are_stable(node.id):
            return None
        for stmt in getattr(self._tree, "body", []):
            if _assigns_only(stmt, node.id) and isinstance(stmt.value, ast.Call):
                return self._compile_call(stmt.value, None)
        return None

    def _compile_call(self, call: ast.Call, func: ast.AST | None):
        if self._re_member(call.func, func) != "re.compile":
            return None
        if any(isinstance(arg, ast.Starred) for arg in call.args):
            return None
        args = _regex_arguments(call, ("pattern", "flags"))
        if args is None or "pattern" not in args:
            return None
        pattern = _const_str_value(args["pattern"])
        flags = self._regex_flags(args.get("flags"), func)
        if pattern is None or flags is None:
            return None
        return pattern, flags

    def _re_member(self, node: ast.AST, func: ast.AST | None):
        """The ``re`` module member ``node`` names through an import the
        module cannot swap out, else None."""
        dotted = _dotted_name(node)
        if not dotted:
            return None
        resolved = self.untrusted_sources.resolved_import(func, dotted)
        if not resolved or resolved.split(".")[0] != "re" or resolved.count(".") != 1:
            return None
        if not self._import_names_are_stable(dotted):
            return None
        if not self._sanitizer_is_unpatched(resolved):
            return None
        return resolved

    def _regex_flags(self, node: ast.AST | None, func: ast.AST | None):
        """The flags ``node`` spells with ``re.I``-style names joined by
        ``|``; None for anything else."""
        if node is None:
            return 0
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self._regex_flags(node.left, func)
            right = self._regex_flags(node.right, func)
            if left is None or right is None:
                return None
            return left | right
        member = self._re_member(node, func)
        if member is None:
            return None
        name = member.split(".")[1]
        if name not in FLAG_NAMES:
            return None
        return int(getattr(re, name))

    def _parent_map(self) -> dict:
        if self._parents is None:
            self._parents = {
                id(child): parent
                for parent in ast.walk(self._tree)
                for child in ast.iter_child_nodes(parent)
            }
        return self._parents

    def _guards_at(self, child: ast.AST, parent: ast.AST, func: ast.AST) -> set:
        """``(name, where the test is)`` for names guarded at ``child`` by
        ``parent``: the branch of an ``if`` it sits in, and earlier ``if``
        statements that return or raise."""
        guarded = set()
        if isinstance(parent, (ast.If, ast.IfExp)):
            if any(item is child for item in _as_list(parent.body)):
                guarded |= _placed(self._guard_names(parent.test, True, func), parent.test)
            elif any(item is child for item in _as_list(parent.orelse)):
                guarded |= _placed(self._guard_names(parent.test, False, func), parent.test)
        for block in _blocks_holding(parent, child):
            for stmt in block[: _index_of(block, child)]:
                holds = _exit_branch(stmt)
                if holds is not None:
                    guarded |= _placed(self._guard_names(stmt.test, holds, func), stmt.test)
        return guarded

    def _scheme_checked(self, node: ast.AST, func: ast.AST | None) -> frozenset:
        """Names in ``func`` that a scheme allowlist guards at ``node``: its
        parameters, and locals bound once before the test."""
        if func is None:
            return frozenset()
        key = (id(node), id(func))
        if key not in self._checked_cache:
            self._checked_cache[key] = self._compute_scheme_checked(node, func)
        return self._checked_cache[key]

    def _compute_scheme_checked(self, node: ast.AST, func: ast.AST) -> frozenset:
        parents = self._parent_map()
        guarded = set()
        child = node
        while child is not func:
            parent = parents.get(id(child))
            if parent is None or (isinstance(parent, _NESTED_SCOPES) and parent is not func):
                return frozenset()
            guarded |= self._guards_at(child, parent, func)
            child = parent
        checked = set()
        for name, position in guarded:
            if self._is_unrebound_param(name, func) or self._bound_before(name, func, position):
                checked.add(name)
        return frozenset(checked)

    def _bound_before(self, name: str, func: ast.AST, position) -> bool:
        binding = self._single_local_binding(name, func)
        if binding is None:
            return False
        return (binding.lineno, binding.col_offset) < position

    def _is_unrebound_param(self, name: str, func: ast.AST) -> bool:
        arguments = func.args
        params = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
        if name not in {param.arg for param in params}:
            return False
        return _binding_counts(func).get(name) == 1

    def _module_helpers(self) -> dict:
        """Undecorated module-level functions bound once and never rebound,
        so a call by their name always runs that body."""
        if self._helpers is not None:
            return self._helpers
        counts = self._module_binding_counts()
        self._helpers = {}
        for stmt in getattr(self._tree, "body", []):
            if (
                isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                and not stmt.decorator_list
                and counts.get(stmt.name) == 1
                and not any(
                    isinstance(node, (ast.Yield, ast.YieldFrom))
                    for node in _own_nodes(stmt)
                )
            ):
                self._helpers[stmt.name] = stmt
        return self._helpers

    def _helper_call_level(self, node: ast.Call, arg_levels, kw_levels):
        """What the module-level function ``node`` calls returns, given the
        levels of its arguments; None when it is not such a function."""
        if not isinstance(node.func, ast.Name):
            return None
        helper = self._module_helpers().get(node.func.id)
        if helper is None:
            return None
        levels = self._bind_arguments(helper, node, arg_levels, kw_levels)
        if levels is None:
            return None
        key = (id(helper), tuple(sorted(levels.items())))
        if key in self._summaries:
            return self._summaries[key]
        if key in self._in_progress or len(self._in_progress) >= _MAX_HELPER_DEPTH:
            return None
        self._in_progress.add(key)
        try:
            level = self._return_level(helper, levels)
        finally:
            self._in_progress.discard(key)
        self._summaries[key] = level
        return level

    def _defaults(self, arguments: ast.arguments) -> dict:
        positional = [*arguments.posonlyargs, *arguments.args]
        defaults = {}
        offset = len(positional) - len(arguments.defaults)
        for param, default in zip(positional[offset:], arguments.defaults):
            defaults[param.arg] = default
        for param, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
            if default is not None:
                defaults[param.arg] = default
        return defaults

    def _bind_arguments(self, helper: ast.AST, call: ast.Call, arg_levels, kw_levels):
        """Level of each of ``helper``'s parameters for ``call``, or None when
        the binding is not known (``*args``/``**kwargs`` at the call)."""
        if any(isinstance(arg, ast.Starred) for arg in call.args):
            return None
        arguments = helper.args
        positional = [*arguments.posonlyargs, *arguments.args]
        if len(arg_levels) > len(positional) and arguments.vararg is None:
            return None
        bound = {param.arg: level for param, level in zip(positional, arg_levels)}
        if arguments.vararg is not None:
            bound[arguments.vararg.arg] = min(arg_levels[len(positional) :], default=CLEAN)
        if not _bind_keywords(arguments, call, kw_levels, bound):
            return None
        if not self._bind_defaults(arguments, bound):
            return None
        return bound

    def _bind_defaults(self, arguments: ast.arguments, bound: dict) -> bool:
        """Give parameters the call left out their default's level; False
        if one has no value."""
        defaults = self._defaults(arguments)
        module_scope = _Scope(self._module_lookup, None, False)
        for param in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]:
            if param.arg not in bound and param.arg not in defaults:
                return False
            if param.arg not in bound:
                bound[param.arg] = self._level(defaults[param.arg], module_scope)
        return True

    def _return_level(self, helper: ast.AST, params: dict):
        """Lowest level any ``return`` in ``helper`` can give, with every
        local at the lowest level any of its assignments can give it; None
        when the locals do not settle within a few passes."""
        env = self._helper_env(helper, params)
        if env is None:
            return None
        level = CLEAN
        for node in _own_nodes(helper):
            if isinstance(node, ast.Return) and node.value is not None:
                level = min(level, self._level(node.value, env.scope))
        return level

    def _helper_env(self, helper: ast.AST, params: dict):
        env = _HelperEnv(self, dict(params), helper)
        bindings, calls = _helper_flows(helper, env)
        groups = _alias_groups(bindings)
        changed = True
        rounds = 0
        while changed:
            rounds += 1
            if rounds > _MAX_HELPER_ROUNDS:
                return None
            changed = False
            for targets, value in bindings:
                changed |= env.lower(targets, self._level(value, env.scope))
            for call in calls:
                for name, level in self._writes_into(call, env.scope):
                    changed |= env.lower(groups.get(name, {name}), level)
        return env

    def _writes_into(self, call: ast.Call, scope: _Scope):
        """``(name, level)`` for each local container a call may change in
        place (its receiver, or a container passed to it), with the lowest
        level of the other operands that could be written into it
        (``parts.append(x)``, ``fill(parts, x)``)."""
        operands = [_unstarred(arg) for arg in call.args]
        operands.extend(kw.value for kw in call.keywords)
        if isinstance(call.func, ast.Attribute):
            operands.append(call.func.value)
        levels = [self._level(operand, scope) for operand in operands]
        writes = []
        for index, operand in enumerate(operands):
            root = _chain_root(operand)
            others = levels[:index] + levels[index + 1 :]
            if root:
                writes.append((root, min(others, default=CLEAN)))
        return writes

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name_from_call(node)

        if qn and node.args:
            func_name = qn.split(".")[-1]
            if func_name in self.SAFE_MARK_FUNCS:
                arg0 = node.args[0]
                if self._level(arg0, self._scope()) == RAW:
                    self.findings.append(
                        {
                            "rule_id": "SKY-D226",
                            "severity": "CRITICAL",
                            "message": "Possible XSS: untrusted content marked safe",
                            "file": str(self.file_path),
                            "line": node.lineno,
                            "col": node.col_offset,
                            "symbol": self._current_symbol(),
                        }
                    )

        sink_name = qn or (
            node.func.attr if isinstance(node.func, ast.Attribute) else None
        )
        if sink_name:
            self._check_template_injection(node, sink_name)

        if qn and qn.split(".")[-1] == "render_template_string" and node.args:
            tmpl = node.args[0]
            if self._template_is_unsafe_literal(tmpl):
                self.findings.append(
                    {
                        "rule_id": "SKY-D227",
                        "severity": "HIGH",
                        "message": "Possible XSS: unsafe inline template disables escaping",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if node.value is not None:
            failure = self._html_failure(node.value, self._scope())
            if failure is not None:
                self.findings.append(
                    {
                        "rule_id": "SKY-D228",
                        "severity": "HIGH",
                        "message": _unescaped_message(*failure),
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )
        self.generic_visit(node)


def _bind_keywords(arguments, call: ast.Call, kw_levels, bound: dict) -> bool:
    named = {param.arg for param in arguments.args}
    named |= {param.arg for param in arguments.kwonlyargs}
    extra = []
    for kw, level in zip(call.keywords, kw_levels):
        if kw.arg is None or kw.arg in bound:
            return False
        if kw.arg in named:
            bound[kw.arg] = level
        elif arguments.kwarg is not None:
            extra.append(level)
        else:
            return False
    if arguments.kwarg is not None:
        bound[arguments.kwarg.arg] = min(extra, default=CLEAN)
    return True


def _dotted_name(node: ast.AST):
    """``a.b.c`` for a chain of attributes on a plain name, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _assigns_only(node: ast.AST, name: str) -> bool:
    """``node`` is ``name = value`` or ``name: T = value`` and binds nothing else."""
    if isinstance(node, ast.Assign):
        return len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name
    if isinstance(node, ast.AnnAssign):
        return node.value is not None and isinstance(node.target, ast.Name) and node.target.id == name
    return False


def _placed(names, test: ast.AST) -> set:
    position = (test.lineno, test.col_offset)
    return {(name, position) for name in names}


def _regex_arguments(call: ast.Call, names):
    """``call``'s arguments by parameter name, or None for an unknown or
    repeated keyword or too many positional arguments."""
    if len(call.args) > len(names):
        return None
    bound = dict(zip(names, call.args))
    for kw in call.keywords:
        if kw.arg is None or kw.arg not in names or kw.arg in bound:
            return None
        bound[kw.arg] = kw.value
    return bound


def _is_truth_value(node: ast.AST) -> bool:
    if isinstance(node, (ast.Compare, ast.Lambda)):
        return True
    return isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)


def _call_tail(func: ast.AST):
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _blocks_holding(parent: ast.AST, child: ast.AST):
    for field in ("body", "orelse", "finalbody"):
        block = getattr(parent, field, None)
        if isinstance(block, list) and any(stmt is child for stmt in block):
            yield block


def _index_of(block: list, child: ast.AST) -> int:
    return next(index for index, stmt in enumerate(block) if stmt is child)


def _as_list(value):
    if isinstance(value, list):
        return value
    return [value]


def _context_failure(parts, levels):
    for level, (needed, spot) in zip(levels, hole_requirements(parts)):
        if level < needed:
            return level, spot
    return None


def _unescaped_message(level: int, spot: str) -> str:
    if level == RAW:
        return "XSS (HTML built from unescaped user input)"
    return (
        f"XSS (user input is HTML-escaped but lands in {spot}, "
        "where that escaping does not stop script)"
    )


def _helper_flows(helper: ast.AST, env: _HelperEnv):
    """``(bindings, calls)`` in ``helper``: each binding is (local names
    written, value node); calls may change containers in place. Names bound
    in ways not modelled start at RAW."""
    bindings = []
    calls = []
    for node in _own_nodes(helper):
        flow = _binding_flow(node)
        if flow is not None:
            bindings.append(flow)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar, ast.MatchMapping)):
            env.lower(_bound_names(node), RAW)
        if isinstance(node, ast.Call):
            calls.append(node)
    for targets, _ in bindings:
        for name in targets:
            env.levels.setdefault(name, env.lookup(name))
    bindings.sort(key=lambda flow: (flow[1].lineno, flow[1].col_offset))
    calls.sort(key=lambda call: (call.lineno, call.col_offset))
    return bindings, calls


def _binding_flow(node: ast.AST):
    if isinstance(node, ast.Assign):
        targets = [name for target in node.targets for name in _target_roots(target)]
        return targets, node.value
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
        return _target_roots(node.target), node.value
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return _target_roots(node.target), node.iter
    if isinstance(node, ast.withitem) and node.optional_vars is not None:
        return _target_roots(node.optional_vars), node.context_expr
    if isinstance(node, ast.NamedExpr):
        return _target_roots(node.target), node.value
    return None


def _alias_groups(bindings) -> dict:
    """Names that may refer to the same object (``b = a``), so a change made
    through one is seen through the other."""
    groups: dict[str, set] = {}
    for targets, value in bindings:
        linked = set(targets) | _aliased_roots(value)
        merged = set(linked)
        for name in linked:
            merged |= groups.get(name, set())
        for name in merged:
            groups[name] = merged
    return groups


def scan(tree, file_path, findings):
    try:
        checker = _XSSFlowChecker(
            tree, file_path, findings, sanitizers=XSS_SANITIZERS
        )
        checker.visit(tree)
    except Exception as e:
        print(f"XSS analysis failed for {file_path}: {e}", file=sys.stderr)
