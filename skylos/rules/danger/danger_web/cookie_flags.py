"""SKY-D252: a response cookie written with the ``secure`` flag turned off by
a literal ``False``.

Werkzeug/Flask, Django and Starlette responses share one ``set_cookie``
signature: ``(key, value, max_age, expires, path, domain, secure, httponly,
samesite)``, so ``secure`` and ``httponly`` are positions 6 and 7 or their
keywords. A cookie is reported only when ``secure`` is the literal ``False``:
the browser then sends it over plain HTTP whatever it holds. A flag that is
absent, ``True`` or computed is not reported, so a default the framework or
configuration may set is never guessed at. An explicit ``httponly=False`` on
its own is not reported: it is the deliberate way to let page scripts read a
cookie (CSRF double-submit tokens, UI state), and whether that exposes a
secret depends on the value, which the call does not prove. The httpOnly
state is still recorded in the evidence.

``http.cookiejar.CookieJar.set_cookie(cookie)`` takes a single cookie object,
so a call needs a key and a value (two or more arguments) to be a response
cookie write. Like TLS verification and debug mode, the flags describe a
deployment: test modules are not reported, as tests set plain cookies on
local test clients.
"""

from __future__ import annotations

import ast
import sys

from skylos.rules.danger.calls import _is_test_module

_COOKIE_WRITERS = frozenset({"set_cookie", "set_signed_cookie"})
_FLAG_POSITIONS = {"set_cookie": {"secure": 6, "httponly": 7}}
_FLAGS = (("httpOnly", "httponly"), ("secure", "secure"))


def _literal_state(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and node.value is True:
        return "true"
    if isinstance(node, ast.Constant) and node.value is False:
        return "false"
    return "unknown"


def _star_before(call: ast.Call, position: int) -> bool:
    return any(isinstance(arg, ast.Starred) for arg in call.args[: position + 1])


def _flag_state(call: ast.Call, method: str, keyword: str) -> str:
    for kw in call.keywords:
        if kw.arg == keyword:
            return _literal_state(kw.value)
    position = _FLAG_POSITIONS.get(method, {}).get(keyword)
    if position is not None and _star_before(call, position):
        return "unknown"
    if position is not None and len(call.args) > position:
        return _literal_state(call.args[position])
    if any(kw.arg is None for kw in call.keywords):
        return "unknown"
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return "unknown"
    return "absent"


def cookie_option_states(call: ast.Call) -> dict[str, str] | None:
    """``{"httpOnly": state, "secure": state}`` for a response cookie write
    with a key and a value, else None. States are ``absent``, ``false``,
    ``true`` or ``unknown`` (computed, or possibly supplied by ``**kwargs``)."""
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr not in _COOKIE_WRITERS:
        return None
    if len(call.args) + len(call.keywords) < 2:
        return None
    return {label: _flag_state(call, func.attr, keyword) for label, keyword in _FLAGS}


def _finding(call: ast.Call, states: dict[str, str], file_path, symbol: str) -> dict:
    summary = ", ".join(f"{label}={states[label]}" for label, _ in _FLAGS)
    sink = f"`{ast.unparse(call.func)}()` Set-Cookie response header"
    return {
        "rule_id": "SKY-D252",
        "severity": "MEDIUM",
        "message": (
            f"Cookie is written with secure turned off by a literal False "
            f"({summary}). Set secure=True so the browser never sends the "
            "cookie over plain HTTP."
        ),
        "file": str(file_path),
        "line": call.lineno,
        "col": call.col_offset,
        "symbol": symbol,
        "metadata": {
            "security_evidence": {
                "evidence_kind": "cookie_security_options",
                "source": "cookie options at the response write",
                "sink": sink,
                "path": ["cookie options", summary, "Set-Cookie response"],
                "guards_seen": [
                    f"{label}=true"
                    for label, state in states.items()
                    if state == "true"
                ],
                "guards_missing": ["secure=true"],
                "options": dict(states),
                "confidence_reason": (
                    "A literal secure=False at the cookie write lets the "
                    "browser send the cookie over plain HTTP."
                ),
                "test_hint": (
                    "Assert the emitted Set-Cookie header has the Secure attribute."
                ),
                "fix_shape": "pass secure=True to the cookie write",
                "analysis_complete": True,
            }
        },
    }


class _CookieWriteChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.symbols = ["<module>"]

    def _visit_scope(self, node):
        self.symbols.append(node.name)
        self.generic_visit(node)
        self.symbols.pop()

    visit_FunctionDef = _visit_scope
    visit_AsyncFunctionDef = _visit_scope
    visit_ClassDef = _visit_scope

    def visit_Call(self, node: ast.Call):
        states = cookie_option_states(node)
        if states is not None and states["secure"] == "false":
            self.findings.append(
                _finding(node, states, self.file_path, self.symbols[-1])
            )
        self.generic_visit(node)


def scan(tree, file_path, findings, *, project_root=None):
    if not isinstance(tree, ast.Module) or _is_test_module(file_path):
        return
    try:
        _CookieWriteChecker(file_path, findings).visit(tree)
    except Exception as error:
        print(f"Cookie flag analysis failed for {file_path}: {error}", file=sys.stderr)
