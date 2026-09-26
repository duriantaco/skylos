from __future__ import annotations
import ast
import re
import sys
from skylos.rules.danger.taint import TaintVisitor, XSS_SANITIZERS
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex

# Template-source sinks: the first argument (or ``source=``) is compiled as a
# Jinja template, so untrusted text there is template code, not data.
_TEMPLATE_SOURCE_SINKS = frozenset(
    {"render_template_string", "flask.render_template_string", "from_string"}
)


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


def _const_contains_html(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        s = node.value
        return ("<" in s) and (">" in s) and bool(_HTML_TAG_RE.search(s))
    return False


class _XSSFlowChecker(TaintVisitor):
    SAFE_MARK_FUNCS = {"Markup", "mark_safe"}

    def __init__(self, tree, file_path, findings, sanitizers=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.untrusted_sources = UntrustedSourceIndex(tree)

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

    def _binop_has_html_const(self, node: ast.AST):
        if _const_contains_html(node):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._binop_has_html_const(node.left) or self._binop_has_html_const(
                node.right
            )
        return False

    def _html_built_with_taint(self, node: ast.AST):
        if isinstance(node, ast.JoinedStr):
            has_html = False
            for v in node.values:
                if isinstance(v, ast.Constant) and _const_contains_html(v):
                    has_html = True
                    break
            if not has_html:
                return False

            for v in node.values:
                if isinstance(v, ast.FormattedValue) and self.is_tainted(v.value):
                    return True
            return False

        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            left_html = _const_contains_html(node.left)
            right_html = _const_contains_html(node.right)
            any_html = (
                left_html
                or right_html
                or self._binop_has_html_const(node.left)
                or self._binop_has_html_const(node.right)
            )

            if not any_html:
                return False
            return self.is_tainted(node.left) or self.is_tainted(node.right)

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            base = node.func.value
            if _const_contains_html(base):
                for a in node.args:
                    if self.is_tainted(a):
                        return True
            return False
        return False

    def visit_Call(self, node: ast.Call):
        qn = _qualified_name_from_call(node)

        if qn and node.args:
            func_name = qn.split(".")[-1]
            if func_name in self.SAFE_MARK_FUNCS:
                arg0 = node.args[0]
                if self._html_built_with_taint(arg0) or self.is_tainted(arg0):
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
            if self._html_built_with_taint(node.value):
                self.findings.append(
                    {
                        "rule_id": "SKY-D228",
                        "severity": "HIGH",
                        "message": "XSS (HTML built from unescaped user input)",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )
        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _XSSFlowChecker(
            tree, file_path, findings, sanitizers=XSS_SANITIZERS
        )
        checker.visit(tree)
    except Exception as e:
        print(f"XSS analysis failed for {file_path}: {e}", file=sys.stderr)
