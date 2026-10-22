import ast
import os
import io
import re
import tokenize
from functools import lru_cache
from pathlib import Path

from skylos.rules import secret_shapes
from skylos.rules.base import SkylosRule
from skylos.rules.quality._function_defaults import (
    annotation_accepts_ellipsis,
    ellipsis_type_bindings,
    function_handles_ellipsis_parameter,
    is_ellipsis_literal,
    iter_arg_defaults as _iter_arg_defaults,
)
from skylos.rules.quality._protocols import (
    protocol_method_ids,
    type_checking_function_ids,
)
from skylos.rules.quality.logic_foundation import _string_literal_value
from skylos.rules.vibe_dictionary import DEFAULT_VIBE_DICTIONARY


DEBUG_FUNCTIONS = {"breakpoint", "ic"}
DEBUG_METHOD_CALLS = {
    ("pdb", "set_trace"),
    ("ipdb", "set_trace"),
    ("pudb", "set_trace"),
    ("code", "interact"),
}

_DEBUG_OUTPUT_MARKER = re.compile(
    r"^\s*(?:\[(?:DEBUG|DBG)\]|(?:DEBUG|DBG)(?:\s*[:=]|\s*$))", re.IGNORECASE
)


@lru_cache(maxsize=4096)
def _basename(filename):
    return str(filename).replace("\\", "/").rsplit("/", 1)[-1]


@lru_cache(maxsize=4096)
def _is_test_file(filename):
    base = _basename(filename)
    if base.startswith("test_") or base.endswith("_test.py") or base == "conftest.py":
        return True
    return False


def _is_raw_state_dump(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"locals", "globals", "vars"}
    ) or (isinstance(node, ast.Attribute) and node.attr == "__dict__")


def _print_diagnostic_evidence(node: ast.Call, context: dict) -> str | None:
    """Output alone is not evidence of abandoned debugging."""
    if node.args:
        first = node.args[0]
        prefix = _string_literal_value(first)
        if isinstance(first, ast.JoinedStr) and first.values:
            prefix = _string_literal_value(first.values[0])
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Mod):
            prefix = _string_literal_value(first.left)
        elif (
            isinstance(first, ast.Call)
            and isinstance(first.func, ast.Attribute)
            and first.func.attr == "format"
        ):
            prefix = _string_literal_value(first.func.value)
        marker = _DEBUG_OUTPUT_MARKER.match(prefix) if prefix is not None else None
        if marker and not (
            isinstance(first, ast.JoinedStr)
            and marker.group().strip().lower() in {"debug", "dbg"}
            and any(isinstance(part, ast.FormattedValue) for part in first.values)
        ):
            # A literal fragment ending at DEBUG is not a token boundary:
            # f'DEBUG{version}' may be an ordinary identifier or filename.
            return "explicit debug label"

    for argument in node.args:
        if _is_raw_state_dump(argument):
            return "raw state dump"
        if not isinstance(argument, ast.JoinedStr):
            continue
        if any(
            isinstance(part, ast.FormattedValue) and _is_raw_state_dump(part.value)
            for part in argument.values
        ):
            return "raw state dump"
        source = context.get("source", context.get("_source"))
        if not isinstance(source, str):
            continue
        cached = context.get("_debug_output_source_lines")
        if cached is None or cached[0] != source:
            cached = (source, source.splitlines(keepends=True))
            context["_debug_output_source_lines"] = cached
        lines = cached[1]
        for part in argument.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            line = getattr(part.value, "end_lineno", None)
            column = getattr(part.value, "end_col_offset", None)
            if line is None or column is None or not 0 < line <= len(lines):
                continue
            # AST columns count UTF-8 bytes. Inspect the actual debug '=';
            # f'{value=}' and f'value={value!r}' otherwise have identical ASTs.
            last_line = getattr(argument, "end_lineno", line)
            suffix = lines[line - 1].encode("utf-8")[column:]
            if last_line > line:
                suffix += "".join(lines[line:last_line]).encode("utf-8")
            if re.match(rb"\s*(?:\)\s*)*=\s*[!}:]", suffix):
                return "f-string debug expression"
    return None


class DebugLeftoverRule(SkylosRule):
    rule_id = "SKY-L009"
    name = "Debug Leftover"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Call):
            return None

        filename = context.get("filename", "")

        func = node.func
        func_name = None
        is_method = False
        method_obj = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr
            is_method = True
            if isinstance(func.value, ast.Name):
                method_obj = func.value.id

        if not func_name:
            return None

        matched = False
        severity = "LOW"
        debug_name = func_name
        message = f"Debug leftover '{debug_name}()' found. Remove before shipping."

        is_output = (not is_method and func_name in {"print", "pprint"}) or (
            (method_obj, func_name) in {("pprint", "pprint"), ("builtins", "print")}
        )
        if is_output:
            evidence = _print_diagnostic_evidence(node, context)
            if evidence is None:
                return None
            matched = True
            debug_name = f"{method_obj}.{func_name}" if is_method else func_name
            message = (
                f"Possible debug output '{debug_name}()' ({evidence}). "
                "Review before shipping."
            )

        if not is_method and func_name in DEBUG_FUNCTIONS:
            matched = True
            if func_name in ("breakpoint", "ic"):
                severity = "HIGH"
            else:
                severity = "LOW"
            debug_name = func_name
            message = f"Debug leftover '{debug_name}()' found. Remove before shipping."

        if is_method and method_obj:
            for obj, method in DEBUG_METHOD_CALLS:
                if method_obj == obj and func_name == method:
                    matched = True
                    severity = "HIGH"
                    debug_name = f"{obj}.{method}"
                    message = f"Debug leftover '{debug_name}()' found. Remove before shipping."
                    break

        if not matched:
            return None

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": severity,
                "type": "call",
                "name": debug_name,
                "simple_name": debug_name,
                "value": "debug",
                "threshold": 0,
                "message": message,
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]


# Identifier components can name security controls and credentials. Keep the
# generic token word separate: token_stream may describe an ordinary lexer.
_SECURITY_TODO_RE = re.compile(
    r"#\s*(?:TODO|FIXME|HACK|XXX|TEMP)\b[:\s].*?(?:\b|(?<=_))"
    r"(?:authenticat\w*|authori[sz]\w*|permission\w*|credential\w*|sanitiz\w*"
    r"|validat\w*|escap\w*|encrypt\w*|decrypt\w*|inject\w*|oauth\w*|firewall\w*"
    r"|rate.?limit\w*|brute.?forc\w*|vulnerab\w*|exploit\w*|insecure\w*"
    r"|disabl\w*|bypass\w*|hardcod\w*|csrf\w*|hack\w*|workaround\w*"
    r"|auth(?:n|z|s)?|logins?|passwords?|secrets?|(?<!\w)tokens?(?!\w)"
    r"|(?:access|refresh|bearer|auth|id|session)[_-]tokens?"
    r"|xss(?:filter|protection)\w*|xss"
    r"|ssl(?:context)?|sqli|tls|verif(?:y|ies|ied|ying|ication)|cert(?:s|ificates?)?"
    r"|cors|sessions?|cookies?|jwts?|api.?keys?|acls?|rbac"
    r"|security|unsafe|temporary|fixme)(?=\W|_|$)",
    re.IGNORECASE,
)

# Generic maintenance words are useful candidates, but do not establish a
# security claim by themselves (e.g. a formatter's "HACK ... workaround").
# Keep candidate discovery intact and require an independent security subject
# when the candidate contains only those words.
_GENERIC_TODO_SUBJECT_RE = re.compile(
    r"\b(?:disabl(?:e[ds]?|ing)|bypass(?:es|ed|ing)?"
    r"|hardcod(?:e[ds]?|ing)|hack(?:s|ed|ing|y|ish)?|workarounds?"
    r"|temporary|fixme)(?=\W|_|$)",
    re.IGNORECASE,
)

# Preserve security subjects that used to match through a generic verb. Keep
# these concepts explicit so maintenance-word filtering cannot erase known
# authentication, cryptographic or transport-security work.
_SECURITY_TODO_SUBJECTS = {
    "authentication_factor": re.compile(
        r"(?<![a-z0-9])(?:mfa|2fa|otp|totp|hotp|webauthn|passkeys?)(?![a-z0-9])", re.I
    ),
    "cryptographic_signature": re.compile(
        r"(?<![a-z0-9])(?:signatures?|signing[ _-]+keys?|hmac|cryptograph\w*)(?![a-z0-9])", re.I
    ),
    "transport_security": re.compile(
        r"(?<![a-z0-9])(?:https|dnssec|ipsec|mtls|ssh)(?![a-z0-9])", re.I
    ),
}


def _has_security_todo_subject(line: str) -> bool:
    subject = re.sub(
        r"^\s*#\s*(?:TODO|FIXME|HACK|XXX|TEMP)\b[:\s]*",
        "",
        line,
        flags=re.IGNORECASE,
    )
    specific = _GENERIC_TODO_SUBJECT_RE.sub("", subject)
    # Reuse the existing vocabulary, so new security subjects are expanded in
    # one place. The synthetic marker is only the regex's required prefix.
    return (
        _SECURITY_TODO_RE.search(f"# TODO: {specific}") is not None
        or any(pattern.search(specific) for pattern in _SECURITY_TODO_SUBJECTS.values())
    )


class SecurityTodoRule(SkylosRule):
    rule_id = "SKY-L010"
    name = "Security TODO Marker"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename", "")
        # Inspect the same source snapshot as the AST. The filename is only a
        # diagnostic label and must never cause an additional filesystem read.
        src = context.get("source")
        if not isinstance(src, str):
            src = context.get("_source")
        if not isinstance(src, str):
            return None

        fragments = [
            (token.start[0], token.start[1], token.string)
            for token in tokenize.generate_tokens(io.StringIO(src).readline)
            if token.type == tokenize.COMMENT
        ]
        # Genuine docstrings can record unfinished security work too. Keep
        # those markers visible without scanning unrelated runtime strings.
        source_lines = src.split("\n")
        for scope in ast.walk(node):
            if not isinstance(
                scope, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ) or not scope.body:
                continue
            first = scope.body[0]
            if not (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                continue
            docstring = first.value
            text = ast.get_source_segment(src, docstring)
            if text is None:
                # Without positioned source, preserve the older conservative
                # text scan rather than silently dropping docstring markers.
                fragments.extend((i, 0, line) for i, line in enumerate(source_lines, 1))
                break
            prefix = source_lines[docstring.lineno - 1].encode("utf-8")
            column = len(prefix[: docstring.col_offset].decode("utf-8"))
            fragments.extend(
                (docstring.lineno + offset, column if offset == 0 else 0, line)
                for offset, line in enumerate(text.split("\n"))
            )

        findings = []
        reported_lines = set()
        for i, column, line in sorted(fragments):
            m = _SECURITY_TODO_RE.search(line)
            if m and _has_security_todo_subject(line) and i not in reported_lines:
                reported_lines.add(i)
                comment = m.group(0).strip()
                if len(comment) > 120:
                    comment = comment[:117] + "..."
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "MEDIUM",
                        "type": "comment",
                        "name": "security_todo",
                        "simple_name": "security_todo",
                        "value": "unfulfilled",
                        "threshold": 0,
                        "message": f"Security-related TODO left in code: {comment}",
                        "file": filename,
                        "basename": Path(filename).name,
                        "line": i,
                        "col": column + m.start(),
                    }
                )

        return findings if findings else None


class DisabledSecurityRule(SkylosRule):
    rule_id = "SKY-L011"
    name = "Disabled Security Control"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(
            node, (ast.Call, ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign)
        ):
            return None

        filename = context.get("filename", "")

        if _is_test_file(filename):
            return None

        findings = []
        basename = _basename(filename)
        disabled_patterns = self.vibe_dictionary.disabled_security_patterns
        dangerous_calls = self.vibe_dictionary.dangerous_calls
        dangerous_decorators = self.vibe_dictionary.dangerous_decorators
        dangerous_assignments = self.vibe_dictionary.dangerous_assignments

        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in disabled_patterns:
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "HIGH",
                                "type": "call",
                                "name": kw.arg,
                                "simple_name": kw.arg,
                                "value": "disabled",
                                "threshold": 0,
                                "message": disabled_patterns[kw.arg],
                                "file": filename,
                                "basename": basename,
                                "line": kw.value.lineno,
                                "col": kw.value.col_offset,
                            }
                        )

            func = node.func
            func_name = None
            if isinstance(func, ast.Attribute):
                func_name = func.attr
            elif isinstance(func, ast.Name):
                func_name = func.id
            if func_name in dangerous_calls:
                msg = dangerous_calls[func_name]
                if msg:
                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": "HIGH",
                            "type": "call",
                            "name": func_name,
                            "simple_name": func_name,
                            "value": "disabled",
                            "threshold": 0,
                            "message": msg,
                            "file": filename,
                            "basename": basename,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_name = None
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                if dec_name in dangerous_decorators:
                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": "HIGH",
                            "type": "decorator",
                            "name": dec_name,
                            "simple_name": dec_name,
                            "value": "disabled",
                            "threshold": 0,
                            "message": dangerous_decorators[dec_name],
                            "file": filename,
                            "basename": basename,
                            "line": dec.lineno,
                            "col": dec.col_offset,
                        }
                    )

        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in dangerous_assignments:
                expected_val, msg = dangerous_assignments[target.id]
                if msg is None:
                    pass
                elif target.id == "ALLOWED_HOSTS":
                    if isinstance(node.value, ast.List):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and elt.value == "*":
                                findings.append(
                                    {
                                        "rule_id": self.rule_id,
                                        "kind": "logic",
                                        "severity": "HIGH",
                                        "type": "assignment",
                                        "name": target.id,
                                        "simple_name": target.id,
                                        "value": "wildcard",
                                        "threshold": 0,
                                        "message": msg,
                                        "file": filename,
                                        "basename": basename,
                                        "line": node.lineno,
                                        "col": node.col_offset,
                                    }
                                )
                elif (
                    isinstance(node.value, ast.Constant)
                    and node.value.value == expected_val
                ):
                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": "MEDIUM",
                            "type": "assignment",
                            "name": target.id,
                            "simple_name": target.id,
                            "value": "insecure",
                            "threshold": 0,
                            "message": msg,
                            "file": filename,
                            "basename": basename,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        return findings if findings else None


class UnfinishedGenerationRule(SkylosRule):
    rule_id = "SKY-L026"
    name = "Unfinished Generation"

    def __init__(self):
        self._protocol_method_ids: set[int] = set()
        self._type_checking_function_ids: set[int] = set()
        self._ellipsis_type_names: set[str] = set()
        self._ellipsis_type_modules: set[str] = set()
        self._declared_contract_ids: set[int] = set()
        self._parents: dict[int, ast.AST] = {}
        self._scope_bindings: dict[int, set[str]] = {}
        self._implementation_comments: list[tuple[int, str]] = []
        self._runtime_bindings: dict[int, dict] = {}
        self._runtime_contracts: dict[int, tuple[str, bool]] = {}

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self._parents = {
                id(child): parent
                for parent in ast.walk(node)
                for child in ast.iter_child_nodes(parent)
            }
            self._scope_bindings = {}
            self._runtime_bindings = {}
            self._implementation_comments = _unfinished_comment_markers(context)
            self._protocol_method_ids = protocol_method_ids(node)
            self._type_checking_function_ids = type_checking_function_ids(node)
            self._declared_contract_ids = _declared_function_contracts(node)
            (
                self._ellipsis_type_names,
                self._ellipsis_type_modules,
            ) = ellipsis_type_bindings(node)
            self._runtime_contracts = _empty_callable_runtime_contracts(node, self)
            return None
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        node_id = id(node)
        if node_id in self._type_checking_function_ids or (
            node_id not in self._runtime_contracts
            and (
                node_id in self._protocol_method_ids
                or node_id in self._declared_contract_ids
            )
        ):
            return None

        filename = context.get("filename", "")

        basename = Path(filename).name
        if filename.endswith(".pyi"):
            return None
        if basename.startswith("test_") or basename.startswith("conftest"):
            return None

        default_findings = _ellipsis_default_findings(
            node,
            filename=filename,
            basename=basename,
            ellipsis_type_names=self._ellipsis_type_names,
            ellipsis_type_modules=self._ellipsis_type_modules,
        )

        body = node.body
        if not body:
            return default_findings or None

        stmts = body
        if isinstance(body[0], ast.Expr) and _string_literal_value(body[0].value):
            stmts = body[1:]

        if len(stmts) > 1:
            return default_findings or None

        stmt = stmts[0] if stmts else body[0]
        marker = _unfinished_generation_marker(stmt) if stmts else "implicit None"
        marker_line = stmt.lineno

        if not marker:
            return default_findings or None
        if (
            isinstance(stmt, ast.Return)
            and isinstance(stmt.value, ast.Call)
            and not self._is_builtin_name(
                _dotted_name(stmt.value.func), node, include_function_scope=True
            )
        ):
            # A locally defined list()/dict() may do real work. Its spelling
            # cannot establish that the function returns an empty collection.
            return default_findings or None

        unfinished = _explicit_unfinished_evidence(
            node, stmt, self._implementation_comments
        )
        contradiction = self._return_contract_contradiction(node, marker)
        runtime_contract, runtime_uncertain = self._runtime_contracts.get(
            node_id, (None, False)
        )
        if not unfinished and not contradiction and not runtime_contract:
            # Missing implementation is not itself evidence of a defect:
            # optional hooks, null objects and interface methods use these
            # exact bodies legitimately, including outside ABC/Protocol.
            return default_findings or None

        evidence = runtime_contract or contradiction or unfinished
        uncertain = (
            runtime_uncertain
            if runtime_contract
            else bool(contradiction and not self._decorators_preserve_result(node))
        )
        message = (
            f"Function '{node.name}' has only `{marker}` in its body. "
            f"{runtime_contract or contradiction}"
            if runtime_contract or contradiction
            else (
                f"Function '{node.name}' is explicitly marked unfinished "
                f"({unfinished}) and has only `{marker}` in its body."
            )
        )
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "function",
                "name": node.name,
                "simple_name": node.name,
                "value": marker,
                "threshold": 0,
                "message": message,
                "evidence": evidence,
                **(
                    {
                        "verification_status": "unverified",
                        "usage_uncertainty": (
                            "Other dependencies or decorators may supply the runtime "
                            "behavior; the empty callable does not establish it."
                        ),
                    }
                    if uncertain
                    else {}
                ),
                "file": filename,
                "basename": basename,
                "line": marker_line,
                "col": stmt.col_offset,
                "vibe_category": "incomplete_generation",
            },
            *default_findings,
        ]

    def _is_builtin_name(self, name, node, *, include_function_scope=False):
        if any(
            getattr(parameter, "name", None) == name
            for parameter in getattr(node, "type_params", ())
        ):
            return False
        scope = node if include_function_scope else self._parents.get(id(node))
        while scope is not None:
            if isinstance(
                scope,
                (
                    ast.Module,
                    ast.ClassDef,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.Lambda,
                ),
            ):
                scope_id = id(scope)
                if scope_id not in self._scope_bindings:
                    self._scope_bindings[scope_id] = _lexical_binding_names(scope)
                if (
                    name in self._scope_bindings[scope_id]
                    or "*" in self._scope_bindings[scope_id]
                ):
                    return False
            scope = self._parents.get(id(scope))
        return name in _CONCRETE_RETURN_BUILTINS or name in {
            "staticmethod",
            "classmethod",
            "property",
        }

    def _decorators_preserve_result(self, node):
        return all(
            self._resolved_symbol(
                decorator.func if isinstance(decorator, ast.Call) else decorator
            )
            in {
                "builtins.staticmethod",
                "builtins.classmethod",
                "builtins.property",
                "functools.cache",
                "functools.lru_cache",
                "functools.wraps",
                "abc.abstractmethod",
            }
            for decorator in node.decorator_list
        )

    def _resolved_symbol(self, expression, seen=None):
        targets, uncertain = self._possible_symbols(expression, seen)
        return next(iter(targets)) if len(targets) == 1 and not uncertain else None

    def _possible_symbols(self, expression, seen=None):
        """Keep bounded may-targets; a conflicting write is not safety proof."""
        seen = set() if seen is None else seen
        if expression is None or id(expression) in seen or len(seen) >= 24:
            return set(), True
        seen = seen | {id(expression)}
        if isinstance(expression, ast.Attribute):
            receivers, uncertain = self._possible_symbols(expression.value, seen)
            targets = set()
            for target in receivers:
                if isinstance(target, str):
                    targets.add(f"{target}.{expression.attr}")
                elif isinstance(target, ast.ClassDef):
                    if id(target) not in self._runtime_bindings:
                        self._runtime_bindings[id(target)] = _runtime_contract_bindings(
                            target
                        )
                    member = self._runtime_bindings[id(target)].get(expression.attr)
                    values, partial = self._binding_targets(member, seen)
                    targets.update(values)
                    uncertain |= partial
                else:
                    uncertain = True
            return targets, uncertain
        if not isinstance(expression, ast.Name):
            return {expression}, False

        child, scope = expression, self._parents.get(id(expression))
        in_function = False
        while scope is not None:
            if isinstance(
                scope,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                # Defaults and decorators execute outside their declaration's
                # body, and a method's free names do not resolve in its class.
                evaluated_inside = isinstance(scope, ast.Module) or child in scope.body
                if evaluated_inside and not (
                    in_function and isinstance(scope, ast.ClassDef)
                ):
                    if id(scope) not in self._runtime_bindings:
                        self._runtime_bindings[id(scope)] = _runtime_contract_bindings(
                            scope
                        )
                    bindings = self._runtime_bindings[id(scope)]
                    if expression.id in bindings:
                        targets, partial = self._binding_targets(
                            bindings[expression.id], seen
                        )
                        return targets, partial or "*" in bindings
                    if "*" in bindings:
                        return set(), True
                in_function |= evaluated_inside and isinstance(
                    scope, (ast.FunctionDef, ast.AsyncFunctionDef)
                )
            child, scope = scope, self._parents.get(id(scope))
        if expression.id in {
            "PermissionError",
            "staticmethod",
            "classmethod",
            "property",
        }:
            return {f"builtins.{expression.id}"}, False
        return set(), True

    def _binding_targets(self, binding, seen):
        candidates = binding if isinstance(binding, tuple) else (binding,)
        targets, uncertain = set(), len(candidates) > 1
        for target in candidates:
            if target is None:
                uncertain = True
            elif isinstance(target, (ast.Name, ast.Attribute)):
                values, partial = self._possible_symbols(target, seen)
                targets.update(values)
                uncertain |= partial
            else:
                targets.add(target)
        return targets, uncertain

    def _return_contract_contradiction(self, node, marker):
        annotation = node.returns
        actual = _STUB_RETURN_TYPES.get(marker)
        if actual is None:
            return None
        if self._resolved_symbol(annotation) in {
            "typing.NoReturn",
            "typing.Never",
            "typing_extensions.NoReturn",
            "typing_extensions.Never",
        }:
            evidence = (
                "Its declared return contract forbids returning, but this body "
                f"returns {'None' if actual == 'None' else 'an empty ' + actual}."
            )
            if not self._decorators_preserve_result(node):
                evidence += " Verify whether its decorators enforce that contract."
            return evidence
        if isinstance(annotation, ast.Subscript):
            annotation = annotation.value
        if (
            not isinstance(annotation, ast.Name)
            or annotation.id not in _CONCRETE_RETURN_BUILTINS
            or not self._is_builtin_name(annotation.id, node)
        ):
            return None

        if actual == annotation.id:
            return None
        evidence = (
            f"Its declared return type is `{annotation.id}`, but this body "
            f"returns {'None' if actual == 'None' else 'an empty ' + actual}."
        )
        if not self._decorators_preserve_result(node):
            evidence += " Verify whether its decorators supply the declared result."
        return evidence


_CONCRETE_RETURN_BUILTINS = {
    "bool",
    "int",
    "float",
    "complex",
    "str",
    "bytes",
    "bytearray",
    "list",
    "tuple",
    "set",
    "frozenset",
    "dict",
    "range",
    "memoryview",
}
_STUB_RETURN_TYPES = {
    "pass": "None",
    "...": "None",
    "implicit None": "None",
    "return": "None",
    "return None": "None",
    'return ""': "str",
    "return list": "list",
    "return dict": "dict",
    "return set": "set",
    "return tuple": "tuple",
}
_IMPLEMENTATION_TODO_RE = re.compile(
    r"^\s*(?:#\s*)?(?:TODO|FIXME)(?:\([^\n)]*\))?\s*:?\s*"
    r"(?:implement\b|(?:finish|complete)\s+(?:(?:the|this)\s+)?"
    r"(?:implementation|function|method|stub|logic|behavior)\b"
    r"|replace\s+(?:this\s+)?(?:stub|placeholder)\b)",
    re.IGNORECASE,
)
_TEMPORARILY_UNFINISHED_RE = re.compile(
    r"^\s*(?:not\s+(?:implemented|done|finished|completed)\s+yet\b"
    r"|implementation\s+(?:pending|unfinished)\b)",
    re.IGNORECASE,
)
_SUBCLASS_CONTRACT_RE = re.compile(r"\b(?:subclasses?|override)\b", re.IGNORECASE)


def _unfinished_comment_markers(context):
    source = context.get("source", context.get("_source"))
    if not isinstance(source, str):
        return []
    markers = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if (
                token.type == tokenize.COMMENT
                and _IMPLEMENTATION_TODO_RE.match(token.string)
                and not _SUBCLASS_CONTRACT_RE.search(token.string)
            ):
                markers.append((token.start[0], token.string.lstrip("# ")))
    except (IndentationError, tokenize.TokenError):
        return []
    return markers


def _explicit_unfinished_evidence(node, stmt, comments):
    docstring = ast.get_docstring(node, clean=True) or ""
    for line in docstring.splitlines():
        if (
            _IMPLEMENTATION_TODO_RE.match(line)
            or _TEMPORARILY_UNFINISHED_RE.match(line)
        ) and not _SUBCLASS_CONTRACT_RE.search(line):
            return line.strip()[:160]
    for line, comment in comments:
        if node.lineno <= line <= getattr(node, "end_lineno", node.lineno):
            return comment[:160]
    if isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Call):
        for argument in stmt.exc.args:
            text = _string_literal_value(argument)
            if text and (
                _IMPLEMENTATION_TODO_RE.match(text)
                or _TEMPORARILY_UNFINISHED_RE.match(text)
            ):
                return text.strip()[:160]
    return None


def _runtime_contract_bindings(scope):
    """Bindings in one runtime scope, invalidating conflicting declarations."""
    bindings = {}

    def record(name, target=None):
        if name not in bindings:
            bindings[name] = target
            return
        old = bindings[name]
        candidates = old if isinstance(old, tuple) else (old,)
        if not any(value is target or value == target for value in candidates):
            # Keep a bounded set of possible targets and uncertainty, rather
            # than treating rebinding as proof that the old no-op disappeared.
            bindings[name] = (
                (*candidates[:12], target)
                if len(candidates) < 13
                else (*candidates[:12], None)
            )

    class Bindings(ast.NodeVisitor):
        def visit_Name(self, node):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                record(node.id)

        def visit_Assign(self, node):
            self.visit(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    record(target.id, node.value)
                else:
                    self.visit(target)

        def visit_AnnAssign(self, node):
            if node.value is not None:
                self.visit(node.value)
            if isinstance(node.target, ast.Name):
                record(node.target.id, node.value)
            else:
                self.visit(node.target)

        def visit_Import(self, node):
            for alias in node.names:
                record(
                    alias.asname or alias.name.split(".")[0],
                    alias.name if alias.asname else alias.name.split(".")[0],
                )

        def visit_ImportFrom(self, node):
            for alias in node.names:
                record(
                    alias.asname or alias.name,
                    f"{node.module}.{alias.name}" if not node.level else None,
                )

        def visit_FunctionDef(self, node):
            record(node.name, node)
            for expression in [
                *node.decorator_list,
                *node.args.defaults,
                *node.args.kw_defaults,
            ]:
                if expression is not None:
                    self.visit(expression)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            record(node.name, node)
            for expression in [*node.decorator_list, *node.bases, *node.keywords]:
                self.visit(expression)

        def visit_Lambda(self, node):
            for expression in [*node.args.defaults, *node.args.kw_defaults]:
                if expression is not None:
                    self.visit(expression)

        def visit_ListComp(self, node):
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
    # Include pattern captures, exception bindings, dynamic scope access and
    # global/nonlocal declarations even when their syntax has no Store Name.
    for name in _lexical_binding_names(scope):
        bindings.setdefault(name, None)
    for nested in ast.walk(scope):
        if isinstance(nested, (ast.Global, ast.Nonlocal)):
            for name in nested.names:
                if name in bindings:
                    record(name)
    return bindings


_UNKNOWN_STUB_VALUE = object()
_UNAWAITED_STUB_VALUE = object()


def _stub_result(node, rule):
    # typing.overload replaces the declaration with a callable that raises.
    if any(
        rule._resolved_symbol(
            decorator.func if isinstance(decorator, ast.Call) else decorator
        )
        in {"typing.overload", "typing_extensions.overload"}
        for decorator in node.decorator_list
    ):
        return _UNKNOWN_STUB_VALUE
    body = node.body
    if body and isinstance(body[0], ast.Expr) and _string_literal_value(body[0].value):
        body = body[1:]
    if not body:
        return None
    if len(body) != 1:
        return _UNKNOWN_STUB_VALUE
    marker = _unfinished_generation_marker(body[0])
    return {
        "pass": None,
        "...": None,
        "return": None,
        "return None": None,
        'return ""': "",
        "return list": [],
        "return tuple": (),
        "return dict": {},
        "return set": set(),
    }.get(marker, _UNKNOWN_STUB_VALUE)


def _dependency_callback(call):
    if call.args:
        return call.args[0]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == "dependency"),
        None,
    )


def _denial_exception(statement, rule):
    if not isinstance(statement, ast.Raise):
        return False
    exception = statement.exc
    constructor = exception.func if isinstance(exception, ast.Call) else exception
    resolved = rule._resolved_symbol(constructor)
    if resolved == "builtins.PermissionError":
        return True
    if resolved not in {
        "fastapi.HTTPException",
        "fastapi.exceptions.HTTPException",
        "starlette.exceptions.HTTPException",
    } or not isinstance(exception, ast.Call):
        return False
    status = (
        exception.args[0]
        if exception.args
        else next(
            (
                keyword.value
                for keyword in exception.keywords
                if keyword.arg == "status_code"
            ),
            None,
        )
    )
    return isinstance(status, ast.Constant) and status.value in {401, 403}


def _branch_denies(statements, rule):
    # A direct raise is unconditional if no earlier direct exit bypasses it.
    for statement in statements:
        if _denial_exception(statement, rule):
            return True
        if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return False
        if not isinstance(
            statement,
            (
                ast.Expr,
                ast.Assign,
                ast.AnnAssign,
                ast.AugAssign,
                ast.Pass,
                ast.Assert,
                ast.Import,
                ast.ImportFrom,
            ),
        ) or any(
            isinstance(child, (ast.Yield, ast.YieldFrom))
            for child in ast.walk(statement)
        ):
            # Earlier branching, loops, contexts and generators can exit
            # before the raise. Their mere presence cannot prove denial.
            return False
    return False


def _dependency_always_denies(function, rule, seen=None):
    seen = set() if seen is None else seen
    if id(function) in seen or len(seen) >= 12:
        return False
    seen = seen | {id(function)}
    # A decorator may replace the callable or erase its dependency signature.
    # Original defaults cannot prove enforcement by the replacement.
    if function.decorator_list:
        return False
    if _branch_denies(function.body, rule):
        return True
    for default in [*function.args.defaults, *function.args.kw_defaults]:
        if not isinstance(default, ast.Call) or rule._resolved_symbol(
            default.func
        ) not in {
            "fastapi.Depends",
            "fastapi.Security",
        }:
            continue
        callback = rule._resolved_symbol(_dependency_callback(default))
        if isinstance(callback, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            _dependency_always_denies(callback, rule, seen)
        ):
            return True
    return False


def _stub_predicate_value(
    expression,
    function,
    replacement,
    rule,
    seen=None,
    *,
    awaited=False,
    unawaited=None,
):
    """Evaluate only builtin literal predicates, replacing this local call."""
    seen = set() if seen is None else seen
    if id(expression) in seen or len(seen) >= 48:
        return _UNKNOWN_STUB_VALUE
    seen = seen | {id(expression)}
    if isinstance(expression, ast.Await):
        return _stub_predicate_value(
            expression.value,
            function,
            replacement,
            rule,
            seen,
            awaited=True,
            unawaited=unawaited,
        )
    if isinstance(expression, ast.Call):
        targets, _ = rule._possible_symbols(expression.func)
        if function not in targets:
            return _UNKNOWN_STUB_VALUE
        if isinstance(function, ast.AsyncFunctionDef) and not awaited:
            if unawaited is not None:
                unawaited.add(id(expression))
            return _UNAWAITED_STUB_VALUE
        return replacement
    if isinstance(expression, ast.Name):
        targets, _ = rule._possible_symbols(expression)
        for target in targets:
            if isinstance(target, ast.AST):
                value = _stub_predicate_value(
                    target,
                    function,
                    replacement,
                    rule,
                    seen,
                    awaited=awaited,
                    unawaited=unawaited,
                )
                if value is not _UNKNOWN_STUB_VALUE:
                    return value
        return _UNKNOWN_STUB_VALUE
    if isinstance(expression, ast.Constant):
        if expression.value is None or isinstance(expression.value, (bool, int, str)):
            return expression.value
        return _UNKNOWN_STUB_VALUE
    if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
        value = _stub_predicate_value(
            expression.operand,
            function,
            replacement,
            rule,
            seen,
            unawaited=unawaited,
        )
        return _UNKNOWN_STUB_VALUE if value is _UNKNOWN_STUB_VALUE else not value
    if isinstance(expression, ast.BoolOp):
        unknown = False
        for operand in expression.values:
            value = _stub_predicate_value(
                operand,
                function,
                replacement,
                rule,
                seen,
                unawaited=unawaited,
            )
            if value is _UNKNOWN_STUB_VALUE:
                unknown = True
            elif isinstance(expression.op, ast.And) and not value:
                return False
            elif isinstance(expression.op, ast.Or) and value:
                return True
        if unknown:
            return _UNKNOWN_STUB_VALUE
        return isinstance(expression.op, ast.And)
    if isinstance(expression, ast.Compare):
        left = _stub_predicate_value(
            expression.left,
            function,
            replacement,
            rule,
            seen,
            unawaited=unawaited,
        )
        if left is _UNKNOWN_STUB_VALUE:
            return left
        for operator, right_node in zip(expression.ops, expression.comparators):
            right = _stub_predicate_value(
                right_node,
                function,
                replacement,
                rule,
                seen,
                unawaited=unawaited,
            )
            if right is _UNKNOWN_STUB_VALUE:
                return right
            if isinstance(operator, ast.Is):
                matches = left is right
            elif isinstance(operator, ast.IsNot):
                matches = left is not right
            elif isinstance(operator, ast.Eq):
                matches = left == right
            elif isinstance(operator, ast.NotEq):
                matches = left != right
            else:
                return _UNKNOWN_STUB_VALUE
            if not matches:
                return False
            left = right
        return True
    return _UNKNOWN_STUB_VALUE


def _predicate_local_functions(expression, rule, seen=None):
    seen = set() if seen is None else seen
    if id(expression) in seen or len(seen) >= 48:
        return {}
    seen = seen | {id(expression)}
    if isinstance(expression, ast.Name):
        targets, uncertain = rule._possible_symbols(expression)
        found = {}
        for target in targets:
            if isinstance(target, ast.AST):
                for callback, partial in _predicate_local_functions(
                    target, rule, seen
                ).items():
                    found[callback] = found.get(callback, False) or uncertain or partial
        return found
    if isinstance(expression, ast.Call):
        targets, uncertain = rule._possible_symbols(expression.func)
        return {
            target: uncertain
            for target in targets
            if isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
    found = {}
    for child in ast.iter_child_nodes(expression):
        for callback, partial in _predicate_local_functions(child, rule, seen).items():
            found[callback] = found.get(callback, False) or partial
    return found


def _security_dependency_contracts(module, rule):
    contracts = {}
    for node in ast.walk(module):
        if not isinstance(node, ast.Call):
            continue
        constructors, constructor_uncertain = rule._possible_symbols(node.func)
        if not constructors & {"fastapi.Security", "fastapi.param_functions.Security"}:
            continue
        callbacks, callback_uncertain = rule._possible_symbols(
            _dependency_callback(node)
        )
        for callback in callbacks:
            if not isinstance(callback, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _stub_result(callback, rule) is _UNKNOWN_STUB_VALUE:
                continue
            if _dependency_always_denies(callback, rule):
                continue
            scopes = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "scopes"),
                None,
            )
            required = (
                [
                    item.value
                    for item in scopes.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                ]
                if isinstance(scopes, (ast.List, ast.Tuple, ast.Set))
                else []
            )
            extra_behavior = (
                constructor_uncertain
                or callback_uncertain
                or callback.decorator_list
                or any(
                    isinstance(item, ast.Call)
                    for item in [*callback.args.defaults, *callback.args.kw_defaults]
                )
            )
            evidence = (
                (
                    "It may be registered"
                    if constructor_uncertain or callback_uncertain
                    else "It is registered"
                )
                + f" as a FastAPI Security dependency at line {node.lineno}"
                + (f" requiring scopes {required!r}" if required else "")
                + ". This empty body performs no authentication or scope check"
                + (
                    "; verify enforcement by its other dependencies or decorators."
                    if extra_behavior
                    else " and cannot reject any caller."
                )
            )
            contracts[id(callback)] = evidence, bool(extra_behavior)
    return contracts


def _empty_callable_runtime_contracts(module, rule):
    contracts = _security_dependency_contracts(module, rule)
    for node in ast.walk(module):
        if not isinstance(node, ast.If):
            continue
        denies_when = (
            True
            if _branch_denies(node.body, rule)
            else False
            if _branch_denies(node.orelse, rule)
            else None
        )
        if denies_when is None:
            continue
        for callback, binding_uncertain in _predicate_local_functions(
            node.test, rule
        ).items():
            result = _stub_result(callback, rule)
            if result is _UNKNOWN_STUB_VALUE:
                continue
            unawaited = set()
            actual = _stub_predicate_value(
                node.test, callback, result, rule, unawaited=unawaited
            )
            if actual is _UNKNOWN_STUB_VALUE or bool(actual) == denies_when:
                continue
            # The placeholder must affect this branch. A dead `False and ...`
            # guard does not provide evidence that the local call is defective.
            alternatives = [
                _stub_predicate_value(node.test, callback, value, rule)
                for value in (True, False)
            ]
            if not unawaited and not any(
                value is not _UNKNOWN_STUB_VALUE and bool(value) == denies_when
                for value in alternatives
            ):
                continue
            uncertain = binding_uncertain or not rule._decorators_preserve_result(
                callback
            )
            evidence = (
                "Its unawaited coroutine is truthy and bypasses"
                if unawaited
                else "Its placeholder result bypasses"
            ) + f" the permission-denial branch at line {node.lineno}."
            if uncertain:
                evidence += " Verify alternate bindings or decorators that may supply an enforcing result."
            contracts[id(callback)] = evidence, uncertain
    return contracts


def _lexical_binding_names(scope):
    """Conservative bindings in one scope; nested bodies do not shadow it."""

    class Bindings(ast.NodeVisitor):
        def __init__(self):
            self.names = set()

        def visit_Name(self, node):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                self.names.add(node.id)

        def visit_FunctionDef(self, node):
            self.names.add(node.name)
            for expression in [*node.decorator_list, *node.args.defaults]:
                self.visit(expression)
            for expression in node.args.kw_defaults:
                if expression is not None:
                    self.visit(expression)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            self.names.add(node.name)
            for expression in [*node.decorator_list, *node.bases]:
                self.visit(expression)
            for keyword in node.keywords:
                self.visit(keyword.value)

        def visit_Lambda(self, node):
            for expression in [*node.args.defaults, *node.args.kw_defaults]:
                if expression is not None:
                    self.visit(expression)

        def visit_Import(self, node):
            self.names.update(
                alias.asname or alias.name.split(".")[0] for alias in node.names
            )

        def visit_ImportFrom(self, node):
            self.names.update(alias.asname or alias.name for alias in node.names)

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id in {
                "exec",
                "globals",
                "locals",
            }:
                self.names.add("*")
            self.generic_visit(node)

        def visit_ExceptHandler(self, node):
            if node.name:
                self.names.add(node.name)
            self.generic_visit(node)

        def visit_MatchAs(self, node):
            if node.name:
                self.names.add(node.name)
            self.generic_visit(node)

        visit_MatchStar = visit_MatchAs

        def visit_MatchMapping(self, node):
            if node.rest:
                self.names.add(node.rest)
            self.generic_visit(node)

        def visit_Global(self, node):
            self.names.update(node.names)

        visit_Nonlocal = visit_Global

    visitor = Bindings()
    visitor.names.update(
        parameter.name for parameter in getattr(scope, "type_params", ())
    )
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = scope.args
        visitor.names.update(
            argument.arg
            for argument in [
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            ]
        )
        for argument in (arguments.vararg, arguments.kwarg):
            if argument is not None:
                visitor.names.add(argument.arg)
    body = scope.body if not isinstance(scope, ast.Lambda) else [scope.body]
    for statement in body:
        visitor.visit(statement)
    return visitor.names


def _declared_function_contracts(tree):
    """Resolve typing/ABC declaration decorators, rather than trusting spelling."""
    imports = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(statement, ast.ImportFrom) and statement.level == 0:
            for alias in statement.names:
                imports[alias.asname or alias.name] = f"{statement.module}.{alias.name}"
    rebound = set()
    for statement in ast.walk(tree):
        targets = []
        # A local import binds its name just as a parameter or assignment
        # does. Conservatively invalidate a module alias if another scope
        # can bind it to a different import; never borrow the module's ABC
        # identity for an application-provided decorator.
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".")[0]
                imported = alias.name if alias.asname else alias.name.split(".")[0]
                if local in imports and imports[local] != imported:
                    rebound.add(local)
        elif isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                local = alias.asname or alias.name
                imported = f"{statement.module}.{alias.name}"
                if statement.level or local in imports and imports[local] != imported:
                    rebound.add(local)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound.add(statement.name)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            rebound.update(
                argument.arg
                for argument in [
                    *statement.args.posonlyargs,
                    *statement.args.args,
                    *statement.args.kwonlyargs,
                ]
            )
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, (ast.AnnAssign, ast.NamedExpr)):
            if statement.value is not None:
                targets = [statement.target]
        for target in targets:
            rebound.update(
                _dotted_name(part)
                for part in ast.walk(target)
                if isinstance(part, (ast.Name, ast.Attribute))
            )
    contracts = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            name = _decorator_name(decorator)
            head, dot, tail = name.partition(".")
            if head in rebound or name in rebound:
                continue
            resolved = imports.get(head, "") + (dot + tail if dot else "")
            if resolved in {
                "abc.abstractmethod",
                "typing.overload",
                "typing_extensions.overload",
            }:
                contracts.add(id(node))
    return contracts


def _ellipsis_default_findings(
    node,
    *,
    filename,
    basename,
    ellipsis_type_names,
    ellipsis_type_modules,
):
    findings = []
    for arg, default in _iter_arg_defaults(node):
        if not is_ellipsis_literal(default):
            continue

        parameter = arg.arg
        if annotation_accepts_ellipsis(
            arg.annotation,
            type_names=ellipsis_type_names,
            type_modules=ellipsis_type_modules,
        ):
            continue
        if function_handles_ellipsis_parameter(node, parameter):
            continue

        findings.append(
            {
                "rule_id": "SKY-L026",
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "function",
                "name": node.name,
                "simple_name": node.name,
                "parameter": parameter,
                "value": "...",
                "threshold": 0,
                "message": (
                    f"Function '{node.name}' uses `...` as the default for "
                    f"parameter '{parameter}'. Calls that omit this argument "
                    "receive Ellipsis at runtime; use a real default or handle "
                    "Ellipsis explicitly."
                ),
                "file": filename,
                "basename": basename,
                "line": getattr(default, "lineno", getattr(node, "lineno", 1)),
                "col": getattr(default, "col_offset", getattr(node, "col_offset", 0)),
                "vibe_category": "incomplete_generation",
                "ai_likelihood": "medium",
            }
        )
    return findings


def _unfinished_generation_marker(stmt):
    if isinstance(stmt, ast.Pass):
        return "pass"

    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
        if stmt.value.value is ...:
            return "..."

    if isinstance(stmt, ast.Raise):
        exc = stmt.exc
        if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
            if exc.func.id == "NotImplementedError":
                return "NotImplementedError"
        elif isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
            return "NotImplementedError"

    if isinstance(stmt, ast.Return):
        return _placeholder_return_marker(stmt.value)

    return None


def _decorator_name(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _dotted_name(decorator.func)
    return _dotted_name(decorator)


def _dotted_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _placeholder_return_marker(value):
    if value is None:
        return "return"

    if isinstance(value, ast.Constant):
        if value.value is None:
            return "return None"
        if value.value == "":
            return 'return ""'

    if isinstance(value, (ast.List, ast.Dict, ast.Set, ast.Tuple)):
        if not _container_elements(value):
            return f"return {type(value).__name__.lower()}"

    if _is_empty_container_constructor(value):
        return f"return {_empty_container_constructor_name(value)}"

    return None


def _is_empty_container_constructor(value):
    return _empty_container_constructor_name(value) is not None


def _empty_container_constructor_name(value):
    if not isinstance(value, ast.Call):
        return None
    if value.args or value.keywords:
        return None
    if not isinstance(value.func, ast.Name):
        return None
    if value.func.id not in {"dict", "list", "set", "tuple"}:
        return None
    return value.func.id


def _container_elements(node):
    if isinstance(node, ast.Dict):
        return node.keys or node.values
    return getattr(node, "elts", [])


class UndefinedConfigRule(SkylosRule):
    rule_id = "SKY-L016"
    name = "Undefined Config"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
        self._env_refs = None
        self._env_sets = None
        self._env_declarations = set()
        self._current_file = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            self._env_refs = []
            self._env_sets = set()
            self._env_declarations = set()
            for statement in node.body:
                if isinstance(statement, ast.Assign):
                    targets = statement.targets
                    value = statement.value
                elif isinstance(statement, ast.AnnAssign):
                    targets = [statement.target]
                    value = statement.value
                else:
                    continue
                if not isinstance(value, ast.Call):
                    continue
                env_name = self._extract_env_var(value)
                if any(
                    isinstance(target, ast.Name) and target.id == env_name
                    for target in targets
                ):
                    # This statement declares a named external setting; it
                    # does not imply the setting's value or use is secure.
                    self._env_declarations.add(id(value))
            for child in ast.walk(node):
                if isinstance(child, ast.Subscript):
                    if (
                        isinstance(child.value, ast.Attribute)
                        and isinstance(child.value.value, ast.Name)
                        and child.value.value.id == "os"
                        and child.value.attr == "environ"
                    ):
                        if isinstance(child.slice, ast.Constant) and isinstance(
                            child.slice.value, str
                        ):
                            self._env_sets.add(child.slice.value)
            return None

        if self._env_refs is None:
            return None

        if not isinstance(node, ast.Call):
            return None

        env_var_name = self._extract_env_var(node)
        if not env_var_name:
            return None

        if id(node) in self._env_declarations:
            return None

        # ``os.getenv("ENABLE_X", "False")`` declares the flag's default; the
        # read is where the setting is defined, not a reference to nothing.
        # An explicit ``None`` default declares nothing.
        default = node.args[1] if len(node.args) >= 2 else None
        for kw in node.keywords:
            if kw.arg == "default":
                default = kw.value
        if default is not None and not (
            isinstance(default, ast.Constant) and default.value is None
        ):
            return None

        if env_var_name in self.vibe_dictionary.well_known_env_vars:
            return None

        if env_var_name in self._env_sets:
            return None

        upper = env_var_name.upper()
        is_flag = any(
            upper.startswith(p)
            for p in ("ENABLE_", "DISABLE_", "USE_", "FEATURE_", "FLAG_", "TOGGLE_")
        )

        if not is_flag:
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "call",
                "name": env_var_name,
                "simple_name": env_var_name,
                "value": "undefined",
                "threshold": 0,
                "message": (
                    f"Feature flag '{env_var_name}' is checked but never defined in this file. "
                    f"AI-generated code often references configuration that was never set up."
                ),
                "file": filename,
                "basename": basename,
                "line": node.lineno,
                "col": node.col_offset,
                "vibe_category": "ghost_config",
                "ai_likelihood": "medium",
            }
        ]

    @staticmethod
    def _extract_env_var(node):
        func = node.func
        if isinstance(func, ast.Attribute):
            if (
                func.attr == "getenv"
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
            ):
                if node.args and isinstance(node.args[0], ast.Constant):
                    return node.args[0].value
            if (
                func.attr == "get"
                and isinstance(func.value, ast.Attribute)
                and func.value.attr == "environ"
                and isinstance(func.value.value, ast.Name)
                and func.value.value.id == "os"
            ):
                if node.args and isinstance(node.args[0], ast.Constant):
                    return node.args[0].value
        return None


class StaleMockRule(SkylosRule):
    rule_id = "SKY-L024"
    name = "Stale Mock"
    node_types = (ast.Module, ast.Call)

    _parse_cache: dict = {}

    def __init__(self):
        self._current_file = None
        self._is_test = False
        self._project_root_cache = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            basename = Path(filename).name
            self._is_test = basename.startswith("test_") or basename.startswith(
                "conftest"
            )
            self._project_root_cache = None
            return None

        if not self._is_test:
            return None

        target_str = None
        target_node = None

        if isinstance(node, ast.Call):
            target_str, target_node = self._extract_patch_target(node)

        if not target_str or not target_node:
            return None

        parts = target_str.split(".")
        if len(parts) < 2:
            return None

        attr_name = parts[-1]
        module_parts = parts[:-1]

        if self._project_root_cache is None:
            self._project_root_cache = self._find_project_root(filename) or False
        project_root = self._project_root_cache
        if not project_root:
            return None

        module_file = self._resolve_module(project_root, module_parts)
        if not module_file:
            return None

        try:
            stat = module_file.stat()
            cache_key = (str(module_file), stat.st_mtime_ns, stat.st_size)
        except OSError:
            return None

        bindings = StaleMockRule._parse_cache.get(cache_key)
        if bindings is None:
            try:
                source = module_file.read_text(errors="replace")
                tree = ast.parse(source)
            except (OSError, SyntaxError):
                StaleMockRule._parse_cache[cache_key] = (frozenset(), True)
                return None
            bindings = _module_patch_bindings(tree)
            StaleMockRule._parse_cache[cache_key] = bindings

        defined_names, dynamic = bindings
        if attr_name in defined_names or dynamic:
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "HIGH",
                "type": "mock",
                "name": target_str,
                "simple_name": attr_name,
                "value": "stale",
                "threshold": 0,
                "message": (
                    f"mock.patch('{target_str}') references '{attr_name}' "
                    f"but no module binding was found in '{'.'.join(module_parts)}'. "
                    "Check for a renamed or removed target; patch normally raises "
                    "AttributeError when the target is missing."
                ),
                "file": filename,
                "basename": basename,
                "line": target_node.lineno,
                "col": target_node.col_offset,
                "vibe_category": "stale_reference",
                "ai_likelihood": "medium",
            }
        ]

    @staticmethod
    def _extract_patch_target(call_node):
        func = call_node.func
        # patch(target, new=DEFAULT, spec=None, create=False, ...)
        if (
            len(call_node.args) >= 4
            and isinstance(call_node.args[3], ast.Constant)
            and call_node.args[3].value is True
        ):
            return None, None
        if any(
            kw.arg == "create"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in call_node.keywords
        ):
            return None, None

        is_patch = False
        if isinstance(func, ast.Attribute) and func.attr == "patch":
            is_patch = True
        elif isinstance(func, ast.Name) and func.id == "patch":
            is_patch = True
        elif isinstance(func, ast.Attribute) and func.attr == "object":
            return None, None

        if not is_patch:
            return None, None

        if call_node.args and isinstance(call_node.args[0], ast.Constant):
            if isinstance(call_node.args[0].value, str):
                return call_node.args[0].value, call_node
        return None, None

    @staticmethod
    def _find_project_root(filepath):
        p = Path(filepath).resolve().parent
        for _ in range(20):
            if (p / "pyproject.toml").exists():
                return p
            if (p / "setup.py").exists():
                return p
            if (p / ".git").exists():
                return p
            parent = p.parent
            if parent == p:
                break
            p = parent
        return None

    @staticmethod
    def _resolve_module(project_root, module_parts):
        """The module file a dotted patch target names, matched with exact case:
        on a case-insensitive filesystem ``Pipeline.py`` would otherwise open
        ``pipeline.py`` and read a class name as a module."""
        candidates = [Path(*module_parts) / "__init__.py"]
        if len(module_parts) > 1:
            candidates.append(Path(*module_parts[:-1]) / (module_parts[-1] + ".py"))
        else:
            candidates.append(Path(module_parts[0] + ".py"))
        for relative in candidates:
            if _exists_with_exact_case(project_root, relative):
                return project_root / relative
        return None


def _exists_with_exact_case(root, relative):
    current = Path(root)
    for part in relative.parts:
        try:
            entries = os.listdir(current)
        except OSError:
            return False
        if part not in entries:
            return False
        current = current / part
    return current.is_file()


def _module_patch_bindings(tree):
    """Potential runtime module bindings, without leaking locals into globals.

    An open namespace cannot prove a patch target absent. In particular,
    module __getattr__, star imports and executable namespace updates need
    runtime knowledge, so abstain instead of diagnosing a missing attribute.
    """
    names = set()
    dynamic = False

    def bind(target):
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                bind(element)
        elif isinstance(target, ast.Starred):
            bind(target.value)

    def visit(node):
        nonlocal dynamic
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                dynamic |= node.name == "__getattr__"
                headers = [
                    *node.decorator_list,
                    *node.args.defaults,
                    *(d for d in node.args.kw_defaults if d is not None),
                ]
            else:
                headers = [
                    *node.decorator_list,
                    *node.bases,
                    *(keyword.value for keyword in node.keywords),
                ]
            # Definition headers execute in the containing namespace; the
            # function/class body has its own scope. A walrus in a default
            # or decorator can therefore create a real module attribute.
            for header in headers:
                visit(header)
            return
        if isinstance(node, ast.Lambda):
            return
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target)
            if any(
                not isinstance(t, (ast.Name, ast.Tuple, ast.List)) for t in node.targets
            ):
                # globals()[name] = ... / module.__dict__[name] = ...
                dynamic |= any(
                    isinstance(part, ast.Call)
                    and isinstance(part.func, ast.Name)
                    and part.func.id in {"globals", "locals", "vars"}
                    for target in node.targets
                    for part in ast.walk(target)
                )
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bind(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.NamedExpr)):
            bind(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars:
                    bind(item.optional_vars)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    dynamic = True
                else:
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.Call):
            dynamic |= isinstance(node.func, ast.Name) and node.func.id == "exec"
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "setattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Subscript)
                and _qualified_call_name(node.args[0].value) == "sys.modules"
                and isinstance(node.args[0].slice, ast.Name)
                and node.args[0].slice.id == "__name__"
            ):
                attribute = node.args[1]
                if isinstance(attribute, ast.Constant) and isinstance(
                    attribute.value, str
                ):
                    names.add(attribute.value)
                else:
                    dynamic = True
            dynamic |= isinstance(node.func, ast.Attribute) and any(
                isinstance(part, ast.Call)
                and isinstance(part.func, ast.Name)
                and part.func.id in {"globals", "locals", "vars"}
                for part in ast.walk(node.func.value)
            )
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return frozenset(names), dynamic


def _var_name_is_security(name, vibe_dictionary=None):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    lower = name.lower()
    for kw in vibe_dictionary.security_var_keywords:
        if kw in lower:
            return True
    return False


class InsecureRandomRule(SkylosRule):
    rule_id = "SKY-L013"
    name = "Insecure Randomness"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(node, ast.Assign):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        call = node.value
        if not isinstance(call, ast.Call):
            return None

        func = call.func
        func_name = None
        is_random_module = False

        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "random":
                if func.attr in self.vibe_dictionary.insecure_random_funcs:
                    func_name = f"random.{func.attr}"
                    is_random_module = True
        elif isinstance(func, ast.Name):
            if func.id in self.vibe_dictionary.insecure_random_funcs:
                func_name = func.id

        if not func_name or not is_random_module:
            return None

        for target in node.targets:
            var_name = None
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr
            elif isinstance(target, ast.Subscript) and isinstance(
                target.value, ast.Name
            ):
                var_name = target.value.id

            if var_name and _var_name_is_security(var_name, self.vibe_dictionary):
                basename = Path(filename).name
                return [
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "HIGH",
                        "type": "call",
                        "name": func_name,
                        "simple_name": func_name,
                        "value": "insecure_random",
                        "threshold": 0,
                        "message": (
                            f"'{func_name}()' used for security-sensitive value '{var_name}'. "
                            f"Use 'secrets' module instead (e.g. secrets.token_urlsafe())."
                        ),
                        "file": filename,
                        "basename": basename,
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                ]

        return None


_CREDENTIAL_DSN_RE = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+.-]*://[^:]+:[^@]+@",
)

_MOCK_CONTEXT_WORDS = {
    "mock",
    "fake",
    "dummy",
    "placeholder",
    "sample",
    "example",
    "fixture",
    "stub",
    "demo",
}
_PLACEHOLDER_EMAIL_RE = re.compile(
    r"(?i)^[a-z0-9._%+-]+@"
    r"("
    r"example\.(?:com|org|net)|test\.(?:com|org|net)|localhost|invalid|"
    r"foo\.com|bar\.com"
    r")$"
)
_PLACEHOLDER_PHONE_RE = re.compile(
    r"(?:^|[^0-9])"
    r"(\(?(?:0{3}|1{3}|123)\)?[-.\s]?(?:0{3,4}|1{3,4}|456)[-.\s]?"
    r"(?:0{4}|1{4}|7890))"
    r"(?:[^0-9]|$)"
)
_UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_TEST_CREDENTIAL_RE = re.compile(
    r"(?i)^(?:password|secret|api[_-]?key|token|credential|auth)[0-9]*$"
    r"|^(?:password|secret)123$"
    r"|^test(?:password|secret|key)$"
)
_PLACEHOLDER_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.org",
    "test.net",
    "foo.com",
    "bar.com",
)


def _is_credential_var(name, vibe_dictionary=None):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    lower = name.lower()
    if lower in vibe_dictionary.credential_var_names:
        return True
    for suffix in vibe_dictionary.credential_var_suffixes:
        if lower.endswith(suffix):
            return True
    return False


def _name_has_mock_context(name: str) -> bool:
    parts = {p for p in re.split(r"[^a-zA-Z0-9]+", name.lower()) if p}
    return bool(parts & _MOCK_CONTEXT_WORDS)


def _target_names(node) -> list[str]:
    names = []

    def collect(target):
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, ast.Attribute):
            names.append(target.attr)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                collect(item)

    if isinstance(node, ast.Assign):
        for target in node.targets:
            collect(target)
    elif isinstance(node, ast.AnnAssign):
        collect(node.target)

    return names


def _is_low_entropy_uuid(value: str) -> bool:
    if not _UUID_RE.match(value):
        return False
    cleaned = value.replace("-", "").lower()
    if not cleaned:
        return False
    if len(set(cleaned)) <= 2:
        return True
    return cleaned in {
        "00000000000000000000000000000000",
        "11111111111111111111111111111111",
        "ffffffffffffffffffffffffffffffff",
        "12345678123456781234567812345678",
    }


def _is_repetitive_placeholder(value: str) -> bool:
    if len(value) < 4 or len(value) > 20:
        return False
    if len(set(value)) == 1:
        return True
    if len(value) % 2 == 0:
        pair = value[:2]
        return pair * (len(value) // 2) == value
    return False


def _classify_placeholder_value(
    value: str,
    target_names: list[str],
    vibe_dictionary=None,
):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    stripped = value.strip()
    lower = stripped.lower()
    target_context = any(_name_has_mock_context(name) for name in target_names)
    credential_context = any(
        _is_credential_var(name, vibe_dictionary) for name in target_names
    )

    if _PLACEHOLDER_EMAIL_RE.match(stripped):
        return "placeholder_email", "MEDIUM", "Email uses a test/example domain"

    if _is_low_entropy_uuid(stripped):
        return (
            "low_entropy_uuid",
            "MEDIUM",
            "UUID has a low-entropy placeholder pattern",
        )

    if _PLACEHOLDER_PHONE_RE.search(stripped):
        return "placeholder_phone", "MEDIUM", "Phone number uses a placeholder pattern"

    if credential_context and _TEST_CREDENTIAL_RE.match(stripped):
        return (
            "test_credential",
            "HIGH",
            "Credential value is a common test placeholder",
        )

    if target_context and lower in vibe_dictionary.placeholder_values:
        return "placeholder_value", "MEDIUM", "Value is a configured placeholder token"

    if target_context and any(domain in lower for domain in _PLACEHOLDER_DOMAINS):
        return "placeholder_domain", "LOW", "Value references a test/example domain"

    if target_context and _is_repetitive_placeholder(stripped):
        return "repetitive_placeholder", "LOW", "Value is a repetitive placeholder"

    return None


def _is_env_lookup(node):
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                if func.value.id == "os" and func.attr in ("getenv", "environ"):
                    return True
            if isinstance(func.value, ast.Attribute):
                if hasattr(func.value, "attr") and func.value.attr == "environ":
                    return True
        if isinstance(func, ast.Name) and func.id == "getenv":
            return True
    if isinstance(func if isinstance(node, ast.Call) else node, ast.Subscript):
        val = node.value if isinstance(node, ast.Subscript) else None
        if val and isinstance(val, ast.Attribute):
            if hasattr(val, "attr") and val.attr == "environ":
                return True
    return False


_HEX_SECRET_RE = re.compile(r"[0-9a-fA-F]{24,}")
_TOKEN_SECRET_RE = re.compile(r"[A-Za-z0-9._~+/=-]{20,}")
_LOOKUP_METHODS = frozenset({"get", "getenv", "environ", "getattr", "get_secret"})


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    import math

    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_like_real_secret(value: str, vibe_dictionary=None) -> bool:
    """A literal that has the shape of a real credential, not a placeholder."""
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    stripped = value.strip()
    lower = stripped.lower()
    if len(stripped) < 10 or any(c.isspace() for c in stripped):
        return False
    if "://" in stripped or stripped.startswith(("/", "./", "~")):
        return False
    if lower in vibe_dictionary.placeholder_values or _TEST_CREDENTIAL_RE.match(
        stripped
    ):
        return False
    if len(set(stripped)) <= 4:
        return False
    has_alpha = any(c.isalpha() for c in stripped)
    has_digit = any(c.isdigit() for c in stripped)
    if _HEX_SECRET_RE.fullmatch(stripped):
        return has_alpha and has_digit and _shannon_entropy(stripped) >= 3.0
    classes = sum(
        (
            any(c.islower() for c in stripped),
            any(c.isupper() for c in stripped),
            has_digit,
            any(not c.isalnum() for c in stripped),
        )
    )
    if classes >= 3 and has_alpha and len(stripped) >= 12:
        return _shannon_entropy(stripped) >= 3.0
    return bool(
        _TOKEN_SECRET_RE.fullmatch(stripped)
        and has_alpha
        and has_digit
        and _shannon_entropy(stripped) >= 3.5
    )


# ``APP_URL``, ``GITHUB_PAT``: two or more UPPER_SNAKE words, each letters
# with at most two trailing digits.
_UPPER_SNAKE_NAME_RE = re.compile(r"[A-Z]+[0-9]{0,2}(?:_[A-Z]+[0-9]{0,2})+")
# English words and acronyms stay below this; random runs reach it.
_NAME_WORD_MAX_ENTROPY = 3.5
# Any of these in a target name makes it hold a credential...
_CREDENTIAL_NAME_STEMS = (
    "key",
    "secret",
    "token",
    "pass",
    "pwd",
    "auth",
    "credential",
    "private",
    "signing",
    "salt",
    "session",
    "jwt",
    "api",
)
# ...otherwise one of these words makes it a location: ``DATABASE_URL``.
_LOCATION_NAME_WORDS = frozenset(
    {
        "url",
        "urls",
        "uri",
        "dsn",
        "host",
        "hostname",
        "endpoint",
        "connection",
        "conn",
        "address",
        "addr",
    }
)
# ``<X>_KEY`` names that hold a key, not the name of a setting.
_SECRET_KEY_NAME_SUFFIXES = (
    "secret_key",
    "api_key",
    "private_key",
    "encryption_key",
    "signing_key",
    "master_key",
    "access_key",
    "hmac_key",
)


def _has_random_run(value: str) -> bool:
    """Upper, lower and digits mixed together, or a high-entropy word."""
    if (
        any(c.isupper() for c in value)
        and any(c.islower() for c in value)
        and any(c.isdigit() for c in value)
    ):
        return True
    return any(
        _shannon_entropy(word) >= _NAME_WORD_MAX_ENTROPY
        for word in re.split(r"[^A-Za-z0-9]+", value)
    )


def _is_location_name(target, var_name: str) -> bool:
    """``DATABASE_URL``, ``DSN``, ``CONNECTION_STRING``: a plain name that
    holds where something is, with no credential word in it."""
    if not isinstance(target, ast.Name):
        return False
    lower = var_name.lower()
    if any(stem in lower for stem in _CREDENTIAL_NAME_STEMS):
        return False
    return bool(set(re.split(r"[^a-z0-9]+", lower)) & _LOCATION_NAME_WORDS)


def _key_names_its_setting(target, var_name: str, value: str) -> bool:
    """``APP_URL_KEY = "APP_URL"``: a plain name ending in ``_KEY`` whose
    value is the rest of the name in UPPER_SNAKE with two or more words.
    ``MASTER_KEY = "MASTER"`` and names for a key itself
    (``JWT_SECRET_KEY``, ``STRIPE_API_KEY``) never qualify."""
    if not isinstance(target, ast.Name):
        return False
    lower = var_name.lower()
    if not lower.endswith("_key") or lower.endswith(_SECRET_KEY_NAME_SUFFIXES):
        return False
    return (
        value == var_name[:-4].lstrip("_").upper()
        and bool(_UPPER_SNAKE_NAME_RE.fullmatch(value))
        and not _has_random_run(value)
    )


def _names_a_setting(target, var_name: str, value: str) -> bool:
    """The literal names a setting rather than holding a credential: a
    reference to one, or ``APP_URL_KEY = "APP_URL"``."""
    # Python never expands a raw `${PASSWORD}` / `{{ password }}` string.
    # A location reference contains no credential, but reference-like spelling
    # under a credential name cannot prove a shipped password is safe.
    return (
        _is_location_name(target, var_name) and secret_shapes.is_reference(value)
    ) or _key_names_its_setting(target, var_name, value)


def _resolved_builtin_getattr_calls(tree):
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    if any(
        isinstance(node, ast.Global) and "getattr" in node.names
        for node in ast.walk(tree)
    ):
        return set()
    scopes = {}
    resolved = set()
    for call in ast.walk(tree):
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Name)
            or call.func.id != "getattr"
        ):
            continue
        current, in_function = call, False
        while current in parents:
            current = parents[current]
            if isinstance(current, ast.ClassDef) and in_function:
                continue
            if isinstance(
                current,
                (
                    ast.Module,
                    ast.ClassDef,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.Lambda,
                ),
            ):
                in_function |= isinstance(
                    current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                )
                if current not in scopes:
                    scopes[current] = _lexical_binding_names(current)
                if {"getattr", "*"} & scopes[current]:
                    break
        else:
            resolved.add(id(call))
    return resolved


def _lookup_key_name(node, builtin_getattr_calls=None) -> str | None:
    """``os.getenv("X")`` / ``config.get("X")`` / ``os.environ["X"]`` -> "X"."""
    if isinstance(node, ast.Call):
        func = node.func
        name = (
            func.attr
            if isinstance(func, ast.Attribute)
            else func.id
            if isinstance(func, ast.Name)
            else ""
        )
        if name not in _LOOKUP_METHODS:
            return None
        if name == "getattr" and (
            not isinstance(func, ast.Name)
            or builtin_getattr_calls is not None
            and id(node) not in builtin_getattr_calls
            or node.keywords
            or len(node.args) not in (2, 3)
            or any(isinstance(arg, ast.Starred) for arg in node.args)
        ):
            return None
        key_index = 1 if name == "getattr" else 0
        if len(node.args) > key_index and isinstance(
            node.args[key_index], ast.Constant
        ):
            key = node.args[key_index].value
            return key if isinstance(key, str) else None
        return ""
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
        return ""
    return None


def _secret_fallback_literals(value, builtin_getattr_calls=None):
    """Yield (literal_node, lookup_key) for credential literals used as the
    fallback of a config/env lookup:

    ``os.environ.get("X") or "<lit>"``, ``os.getenv("X", "<lit>")``,
    ``config.get("X", default="<lit>")``.
    """
    if isinstance(value, ast.BoolOp) and isinstance(value.op, ast.Or):
        lookups = [
            _lookup_key_name(item, builtin_getattr_calls) for item in value.values[:-1]
        ]
        last = value.values[-1]
        if (
            any(key is not None for key in lookups)
            and isinstance(last, ast.Constant)
            and isinstance(last.value, str)
        ):
            key = next((k for k in lookups if k), "")
            yield last, key
        return
    if isinstance(value, ast.Call):
        key = _lookup_key_name(value, builtin_getattr_calls)
        if key is None:
            return
        func = value.func
        method = (
            func.id
            if isinstance(func, ast.Name)
            else func.attr
            if isinstance(func, ast.Attribute)
            else ""
        )
        default_index = 2 if method == "getattr" else 1
        default = value.args[default_index] if len(value.args) > default_index else None
        for kw in value.keywords:
            if kw.arg == "default":
                default = kw.value
        if isinstance(default, ast.Constant) and isinstance(default.value, str):
            yield default, key


def _credential_literal_sources(
    tree,
    credential_keyword,
    builtin_getattr_calls=None,
    *,
    imported_sources=None,
    resolver_callback=None,
):
    """Bounded may-reaching provenance for literals passed as credentials.

    Evidence belongs to a literal binding, not every equally spelled name
    in the module. Follow direct assignment aliases and constructor-owned
    fields. Conditional or unknown writes cannot refute an earlier literal;
    a definite overwrite in the same scope can. This adds credential evidence,
    so uncertain control flow retains possible literal sources.

    Project analysis can register the scan/export closures with
    ``resolver_callback`` before resolving imports. Each module's lexical
    tables are then constructed once, including for recursive re-exports.
    """
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    module_end_lineno = max((getattr(n, "lineno", 0) for n in parents), default=0) + 1
    scope_types = (
        ast.Module,
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.Lambda,
    )

    def scope(node):
        while node not in (None, tree):
            node = parents.get(node)
            if isinstance(node, scope_types):
                return node
        return tree

    def direct_nodes(owner):
        pending = list(ast.iter_child_nodes(owner))
        while pending:
            node = pending.pop()
            yield node
            if not isinstance(node, scope_types):
                pending.extend(ast.iter_child_nodes(node))

    locals_by_scope = {}
    global_names = {}
    nonlocal_names = {}
    for owner in (n for n in ast.walk(tree) if isinstance(n, scope_types)):
        nodes = list(direct_nodes(owner))
        names = {
            n.id
            for n in nodes
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))
        }
        names.update(n.arg for n in nodes if isinstance(n, ast.arg))
        for n in nodes:
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                names.update(a.asname or a.name.split(".")[0] for a in n.names)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(n.name)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                names.add(n.name)
        locals_by_scope[owner] = names
        global_names[owner] = {
            name for n in nodes if isinstance(n, ast.Global) for name in n.names
        }
        nonlocal_names[owner] = {
            name for n in nodes if isinstance(n, ast.Nonlocal) for name in n.names
        }

    def name_key(name, owner):
        first = owner
        while owner is not tree:
            if name in global_names.get(owner, ()):
                return (tree, name)
            if (
                (not isinstance(owner, ast.ClassDef) or owner is first)
                and name in locals_by_scope.get(owner, ())
                and name not in nonlocal_names.get(owner, ())
            ):
                return (owner, name)
            owner = scope(owner)
        return (tree, name)

    def key(node):
        owner = scope(node)
        if isinstance(node, ast.Name):
            return name_key(node.id, owner)
        if not isinstance(node, ast.Attribute):
            return None
        parts = []
        receiver = node
        while isinstance(receiver, ast.Attribute):
            parts.append(receiver.attr)
            receiver = receiver.value
        if not isinstance(receiver, ast.Name):
            return None
        cls = scope(owner)
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)) and isinstance(
            cls, ast.ClassDef
        ):
            positional = [*owner.args.posonlyargs, *owner.args.args]
            if (
                positional
                and receiver.id == positional[0].arg
                and not any(
                    _decorator_name(d).rsplit(".", 1)[-1] == "staticmethod"
                    for d in owner.decorator_list
                )
            ):
                return (cls, ("field", tuple(reversed(parts))))
        receiver_key = name_key(receiver.id, owner)
        return (*receiver_key, tuple(reversed(parts)))

    definitions = {}
    imported_definitions = {}

    def remember(target, value, statement):
        if isinstance(target, (ast.Tuple, ast.List)):
            values = (
                value.elts
                if isinstance(value, (ast.Tuple, ast.List))
                and len(target.elts) == len(value.elts)
                else [None] * len(target.elts)
            )
            for child, item in zip(target.elts, values):
                remember(child, item, statement)
            return
        binding = key(target)
        if binding is None:
            return
        owner = scope(statement)
        current = statement
        conditional = False
        while (current := parents.get(current)) is not None and current is not owner:
            conditional |= isinstance(
                current,
                (
                    ast.If,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.Try,
                    ast.With,
                    ast.AsyncWith,
                    ast.Match,
                ),
            )
        definitions.setdefault(binding, []).append(
            (statement, value, owner, conditional)
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                remember(target, node.value, node)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            if node.value is not None:
                remember(node.target, node.value, node)
        elif isinstance(node, ast.AugAssign):
            remember(node.target, None, node)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                remember(target, None, node)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            remember(node.target, None, node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars:
                    remember(item.optional_vars, None, node)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            target = ast.copy_location(ast.Name(id=node.name, ctx=ast.Store()), node)
            parents[target] = node
            remember(target, None, node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                target = ast.copy_location(
                    ast.Name(id=local_name, ctx=ast.Store()),
                    node,
                )
                parents[target] = node
                remember(target, None, node)
                if isinstance(node, ast.Import):
                    origin = alias.name if alias.asname else alias.name.split(".")[0]
                elif not node.level:
                    origin = f"{node.module}.{alias.name}"
                else:
                    origin = None
                imported_definitions[(node, local_name)] = origin
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defaults = {arg.arg: value for arg, value in _iter_arg_defaults(node)}
            for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                definitions.setdefault((node, arg.arg), []).append(
                    (arg, defaults.get(arg.arg), node, False)
                )
            target = ast.copy_location(ast.Name(id=node.name, ctx=ast.Store()), node)
            parents[target] = parents.get(node)
            remember(target, node, node)
        elif isinstance(node, ast.ClassDef):
            target = ast.copy_location(ast.Name(id=node.name, ctx=ast.Store()), node)
            parents[target] = parents.get(node)
            remember(target, node, node)

    @lru_cache(maxsize=8192)
    def control_regions(value):
        owner = scope(value)
        regions = {}
        current = value
        while (parent := parents.get(current)) is not None and parent is not owner:
            if isinstance(
                parent,
                (
                    ast.If,
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.Try,
                    ast.With,
                    ast.AsyncWith,
                    ast.Match,
                ),
            ):
                for field, child in ast.iter_fields(parent):
                    if isinstance(child, list) and current in child:
                        # Except handlers and match cases are separate paths.
                        regions[parent] = (
                            field,
                            id(current) if field in {"handlers", "cases"} else None,
                        )
                        break
            current = parent
        return regions

    @lru_cache(maxsize=8192)
    def reaching_definitions(value):
        """Keep every feasible local branch since the last definite write."""
        binding = key(value)
        candidates = definitions.get(binding, [])
        owner = scope(value)
        local, back_edges = [], []
        use_regions = control_regions(value)
        for definition in candidates:
            statement = definition[0]
            if definition[2] is not owner:
                continue
            # An assignment's RHS observes the preceding binding, not itself.
            ancestor = value
            while ancestor is not None and ancestor is not statement:
                ancestor = parents.get(ancestor)
            if ancestor is statement:
                continue
            if (statement.lineno, statement.col_offset) > (
                value.lineno,
                value.col_offset,
            ):
                shared_loops = {
                    loop
                    for loop, region in control_regions(statement).items()
                    if isinstance(loop, (ast.For, ast.AsyncFor, ast.While))
                    and region[0] == "body"
                    and use_regions.get(loop, (None,))[0] == "body"
                }
                if shared_loops:
                    back_edges.append((definition, shared_loops))
                continue
            local.append(definition)
        if local:
            local.sort(key=lambda d: (d[0].lineno, d[0].col_offset))
            definite = [
                i
                for i, definition in enumerate(local)
                if all(
                    use_regions.get(region) == branch
                    for region, branch in control_regions(definition[0]).items()
                )
            ]
            selected = local[definite[-1] :] if definite else local[:]
            if not definite:
                selected.extend(d for d in candidates if d[2] is not owner)
            for definition, loops in back_edges:
                # A refresh before every use in the loop kills a previous
                # iteration's value. A pre-loop write does not.
                refreshed = all(
                    any(
                        control_regions(local[index][0]).get(loop, (None,))[0] == "body"
                        for index in definite
                    )
                    for loop in loops
                )
                if not refreshed:
                    selected.append(definition)
            return selected
        if back_edges:
            return [d for d in candidates if d[2] is not owner] + [
                definition for definition, _ in back_edges
            ]
        if binding and binding[0] is owner and any(d[2] is owner for d in candidates):
            # A future local assignment is not visible to an earlier read.
            return []
        # Closures and instance fields can be observed before optional writes
        # in other functions. Their source order does not establish runtime
        # order; every literal definition remains potentially reachable.
        return candidates

    def imported_literals(value, suffix=(), depth=0, constructor_sources=None):
        if depth >= 8:
            return set()
        if isinstance(value, ast.Call) and suffix:
            positional = []
            for argument in value.args:
                if isinstance(argument, ast.Starred):
                    break
                positional.append(tuple(sorted(resolve(argument, depth + 1))))
            keywords = tuple(
                (keyword.arg, tuple(sorted(resolve(keyword.value, depth + 1))))
                for keyword in value.keywords
                if keyword.arg is not None
            )
            return imported_literals(
                value.func, suffix, depth + 1, (tuple(positional), keywords)
            )
        if isinstance(value, ast.Attribute):
            return imported_literals(
                value.value, (value.attr, *suffix), depth + 1, constructor_sources
            )
        if not isinstance(value, ast.Name):
            return set()
        found = set()
        for statement, expression, _, _ in reaching_definitions(value):
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                if imported_sources is not None:
                    found.update(
                        imported_sources(
                            statement,
                            value.id,
                            suffix,
                            constructor_sources=constructor_sources,
                        )
                    )
            elif isinstance(expression, ast.ClassDef) and suffix:
                if constructor_sources is not None:
                    found.update(
                        resolve_instance_fields(expression, suffix, constructor_sources)
                    )
                else:
                    found.update(resolve_export(suffix, expression))
            elif expression is not None and expression is not value:
                found.update(
                    imported_literals(
                        expression, suffix, depth + 1, constructor_sources
                    )
                )
        return found

    @lru_cache(maxsize=8192)
    def resolve(value, depth=0, parameter_sources=()):
        if value is None or depth >= 8:
            return set()
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return {id(value)}
        if isinstance(value, (ast.Name, ast.Attribute)):
            result = imported_literals(value, depth=depth)
            supplied = dict(parameter_sources)
            for statement, expression, _, _ in reaching_definitions(value):
                if id(statement) in supplied:
                    result.update(supplied[id(statement)])
                else:
                    result.update(resolve(expression, depth + 1, parameter_sources))
            return result
        return {
            id(literal)
            for literal, _ in _secret_fallback_literals(value, builtin_getattr_calls)
        }

    def callable_origin(value, depth=0):
        if depth >= 8:
            return None
        if isinstance(value, ast.Attribute):
            origin = callable_origin(value.value, depth + 1)
            return f"{origin}.{value.attr}" if origin else None
        if not isinstance(value, ast.Name):
            return None
        candidates = reaching_definitions(value)
        if len(candidates) != 1 or candidates[0][3]:
            return None
        statement, expression, _, _ = candidates[0]
        imported = imported_definitions.get((statement, value.id))
        return imported or callable_origin(expression, depth + 1)

    def ftp_receiver(value, depth=0):
        if depth >= 8:
            return False
        if isinstance(value, ast.Call):
            return callable_origin(value.func) in {"ftplib.FTP", "ftplib.FTP_TLS"}
        if isinstance(value, (ast.Name, ast.Attribute)):
            candidates = reaching_definitions(value)
            return bool(
                len(candidates) == 1
                and not candidates[0][3]
                and ftp_receiver(candidates[0][1], depth + 1)
            )
        return False

    def export_definitions(owner, name):
        binding = (owner, name)
        read = ast.Name(id=name, ctx=ast.Load())
        read.lineno = module_end_lineno
        read.col_offset = 0
        parents[read] = owner
        candidates = reaching_definitions(read)
        return [
            *candidates,
            *(d for d in definitions.get(binding, ()) if d[2] is not owner),
        ]

    def resolve_instance_fields(cls, path, constructor_sources):
        positional, keywords = constructor_sources
        keyword_sources = dict(keywords)
        result = set()
        constructors = [
            expression
            for _, expression, _, _ in export_definitions(cls, "__init__")
            if isinstance(expression, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        fields = definitions.get((cls, ("field", tuple(path))), ())
        for constructor in constructors or [None]:
            arguments = (
                [*constructor.args.posonlyargs, *constructor.args.args]
                if constructor is not None
                else []
            )
            supplied = {}
            for argument, sources in zip(arguments[1:], positional):
                supplied[id(argument)] = sources
            keyword_arguments = (
                constructor.args.kwonlyargs if constructor is not None else []
            )
            for argument in [*arguments[1:], *keyword_arguments]:
                if argument.arg in keyword_sources:
                    supplied[id(argument)] = keyword_sources[argument.arg]
            substitutions = tuple(sorted(supplied.items()))
            local = sorted(
                (definition for definition in fields if definition[2] is constructor),
                key=lambda definition: (
                    definition[0].lineno,
                    definition[0].col_offset,
                ),
            )
            definite = [
                index for index, definition in enumerate(local) if not definition[3]
            ]
            selected = local[definite[-1] :] if definite else local
            selected.extend(
                definition for definition in fields if definition[2] is not constructor
            )
            # Python reads a class attribute when no instance field exists.
            # A definite constructor write masks it for this instance; optional
            # writes and possible deletions cannot prove that mask persists.
            if not definite or any(isinstance(d[0], ast.Delete) for d in selected):
                result.update(resolve_export(path, cls))
            for _, expression, _, _ in selected:
                result.update(resolve(expression, parameter_sources=substitutions))
        return result

    def resolve_export(path, owner=tree, constructor_sources=None):
        if not path:
            return set()
        name, *suffix = path
        result = set()
        # An importing consumer can observe an export after a function writes
        # it, so source ordering across those scopes cannot prove a kill.
        for statement, expression, _, _ in export_definitions(owner, name):
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                if imported_sources is not None:
                    result.update(
                        imported_sources(
                            statement,
                            name,
                            tuple(suffix),
                            constructor_sources=constructor_sources,
                        )
                    )
            elif expression is not None:
                if suffix:
                    if isinstance(expression, ast.ClassDef):
                        if constructor_sources is not None:
                            result.update(
                                resolve_instance_fields(
                                    expression, suffix, constructor_sources
                                )
                            )
                        else:
                            result.update(resolve_export(suffix, expression))
                    else:
                        result.update(imported_literals(expression, tuple(suffix)))
                else:
                    result.update(resolve(expression))
        return result

    def scan_credential_uses():
        evidence = set()
        for call in ast.walk(tree):
            if isinstance(call, ast.Call):
                for keyword in call.keywords:
                    if credential_keyword(keyword.arg):
                        evidence.update(resolve(keyword.value))
                # ftplib.FTP.login(user='', passwd='', acct='') has a documented
                # password in its second positional argument. Require a resolved
                # stdlib constructor, rather than guessing from a method spelling.
                if (
                    isinstance(call.func, ast.Attribute)
                    and call.func.attr == "login"
                    and len(call.args) >= 2
                    and not any(isinstance(arg, ast.Starred) for arg in call.args[:2])
                    and ftp_receiver(call.func.value)
                ):
                    evidence.update(resolve(call.args[1]))
        return evidence

    if resolver_callback is not None:
        resolver_callback(scan_credential_uses, resolve_export)
        return set()
    return scan_credential_uses()


class HardcodedCredentialRule(SkylosRule):
    rule_id = "SKY-L014"
    name = "Hardcoded Credential"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
        self._credential_uses = set()
        self._builtin_getattr_calls = set()

    def _credential_literal(self, name, value, literal):
        """Generic mapping/routing keys need evidence beyond the word key.

        Explicit password/token/secret names still report weak literals:
        entropy is corroboration for ambiguous keys, never a password policy.
        """
        if id(literal) in self._credential_uses:
            return True
        if not _is_credential_var(name, self.vibe_dictionary):
            return False
        lower = name.lower()
        explicit = lower in self.vibe_dictionary.credential_var_names or any(
            lower.endswith(suffix)
            for suffix in self.vibe_dictionary.credential_var_suffixes
            if suffix != "_key"
        )
        explicit |= lower.endswith(_SECRET_KEY_NAME_SUFFIXES)
        explicit |= bool(
            set(re.split(r"[^a-z0-9]+", lower))
            & {
                "auth",
                "credential",
                "secret",
                "token",
                "password",
                "jwt",
                "session",
                "cookie",
            }
        )
        return bool(
            explicit
            or _looks_like_real_secret(value, self.vibe_dictionary)
            or _CREDENTIAL_DSN_RE.search(value)
            # Preserve suspicious password/passphrase shapes even when they
            # fail the high-entropy token heuristic. Reference handling below
            # still treats location references separately from passwords.
            or value.startswith(("$", "%", "{{"))
            or bool(re.fullmatch(r"[a-z]+(?:-[a-z]+){3,}", value))
        )

    def _credential_keyword(self, name):
        return bool(
            name
            and (
                name.lower() == "token"
                or _is_credential_var(name, self.vibe_dictionary)
            )
            and (
                not name.lower().endswith("_key")
                or name.lower().endswith(_SECRET_KEY_NAME_SUFFIXES)
                or name.lower() in self.vibe_dictionary.credential_var_names
            )
        )

    def _collect_credential_uses(self, tree):
        return _credential_literal_sources(
            tree, self._credential_keyword, self._builtin_getattr_calls
        )

    def _fallback_findings(self, node, filename, basename):
        """Use the same credential evidence for annotations and env fallbacks."""
        if isinstance(node, ast.AnnAssign):
            target = node.target
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        else:
            return []
        var_name = (
            target.id
            if isinstance(target, ast.Name)
            else target.attr
            if isinstance(target, ast.Attribute)
            else None
        )
        value = node.value
        if var_name is None or value is None:
            return []
        candidates = []
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and self._credential_literal(var_name, value.value, value)
        ):
            candidates.append((value, "annotated default"))
        for literal, key in _secret_fallback_literals(
            value, self._builtin_getattr_calls
        ):
            if self._credential_literal(var_name, literal.value, literal) or (
                key and self._credential_literal(key, literal.value, literal)
            ):
                candidates.append((literal, "fallback for a config/env lookup"))
        findings = []
        for literal, kind in candidates:
            if not literal.value.strip() or (
                id(literal) not in self._credential_uses
                and _names_a_setting(target, var_name, literal.value)
            ):
                continue
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "MEDIUM"
                    if literal.value.lower() in self.vibe_dictionary.placeholder_values
                    else "HIGH",
                    "type": "assignment",
                    "name": var_name,
                    "simple_name": var_name,
                    "value": "hardcoded_fallback",
                    "threshold": 0,
                    "message": (
                        f"Hardcoded credential in '{var_name}' ({kind}). "
                        "The literal is shipped in source and used whenever the "
                        "setting is missing; remove it and fail when unset."
                    ),
                    "file": filename,
                    "basename": basename,
                    "line": literal.lineno,
                    "col": literal.col_offset,
                }
            )
        return findings

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self._builtin_getattr_calls = _resolved_builtin_getattr_calls(node)
            self._credential_uses = self._collect_credential_uses(node)
            locations = {
                tuple(location)
                for location in context.get("credential_source_locations", ())
            }
            self._credential_uses.update(
                id(literal)
                for literal in ast.walk(node)
                if isinstance(literal, ast.Constant)
                and isinstance(literal.value, str)
                and (literal.lineno, literal.col_offset) in locations
            )
            return None
        if not isinstance(
            node, (ast.Assign, ast.AnnAssign, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        findings = []
        basename = _basename(filename)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            findings.extend(self._fallback_findings(node, filename, basename))
            if isinstance(node, ast.AnnAssign):
                return findings or None

        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            var_name = None
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr

            if (
                var_name
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and self._credential_literal(var_name, node.value.value, node.value)
            ):
                value = node.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    str_val = value.value
                    if not str_val or str_val.strip() == "":
                        return None
                    if id(value) not in self._credential_uses and _names_a_setting(
                        target, var_name, str_val
                    ):
                        return findings or None
                    try:
                        if _is_env_lookup(value):
                            return None
                    except Exception:
                        pass

                    severity = "HIGH"
                    if str_val.lower() in self.vibe_dictionary.placeholder_values:
                        severity = "MEDIUM"

                    findings.append(
                        {
                            "rule_id": self.rule_id,
                            "kind": "logic",
                            "severity": severity,
                            "type": "assignment",
                            "name": var_name,
                            "simple_name": var_name,
                            "value": "hardcoded",
                            "threshold": 0,
                            "message": (
                                f"Hardcoded credential in '{var_name}'. "
                                f"Use environment variables or a secrets manager instead."
                            ),
                            "file": filename,
                            "basename": basename,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    if _CREDENTIAL_DSN_RE.search(value.value):
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "HIGH",
                                "type": "assignment",
                                "name": var_name,
                                "simple_name": var_name,
                                "value": "hardcoded_dsn",
                                "threshold": 0,
                                "message": (
                                    f"Connection string in '{var_name}' contains embedded credentials. "
                                    f"Use environment variables for database URLs."
                                ),
                                "file": filename,
                                "basename": basename,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg, default in _iter_arg_defaults(node):
                if hasattr(arg, "arg"):
                    arg_name = arg.arg
                else:
                    arg_name = str(arg)

                if (
                    isinstance(default, ast.Constant)
                    and isinstance(default.value, str)
                    and self._credential_literal(arg_name, default.value, default)
                ):
                    if isinstance(default, ast.Constant) and isinstance(
                        default.value, str
                    ):
                        str_val = default.value
                        if str_val and str_val.strip():
                            if id(
                                default
                            ) not in self._credential_uses and _names_a_setting(
                                ast.Name(id=arg_name), arg_name, str_val
                            ):
                                continue
                            severity = "HIGH"
                            if (
                                str_val.lower()
                                in self.vibe_dictionary.placeholder_values
                            ):
                                severity = "MEDIUM"
                            findings.append(
                                {
                                    "rule_id": self.rule_id,
                                    "kind": "logic",
                                    "severity": severity,
                                    "type": "default",
                                    "name": arg_name,
                                    "simple_name": arg_name,
                                    "value": "hardcoded_default",
                                    "threshold": 0,
                                    "message": (
                                        f"Hardcoded credential in default argument '{arg_name}'. "
                                        f"Use environment variables or None with runtime lookup."
                                    ),
                                    "file": filename,
                                    "basename": basename,
                                    "line": default.lineno,
                                    "col": default.col_offset,
                                }
                            )

        return findings if findings else None


class MockPlaceholderDataRule(SkylosRule):
    rule_id = "SKY-L032"
    name = "Mock Or Placeholder Data"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(
            node,
            (ast.Assign, ast.AnnAssign, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        findings = []
        basename = _basename(filename)

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = _string_literal_value(node.value)
            if value is not None:
                self._add_finding(
                    findings,
                    value=value,
                    target_names=_target_names(node),
                    filename=filename,
                    basename=basename,
                    line=getattr(node.value, "lineno", getattr(node, "lineno", 1)),
                    col=getattr(
                        node.value,
                        "col_offset",
                        getattr(node, "col_offset", 0),
                    ),
                )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg, default in _iter_arg_defaults(node):
                value = _string_literal_value(default)
                if value is None:
                    continue
                arg_name = arg.arg if hasattr(arg, "arg") else str(arg)
                self._add_finding(
                    findings,
                    value=value,
                    target_names=[arg_name],
                    filename=filename,
                    basename=basename,
                    line=getattr(default, "lineno", getattr(node, "lineno", 1)),
                    col=getattr(
                        default,
                        "col_offset",
                        getattr(node, "col_offset", 0),
                    ),
                )

        return findings if findings else None

    def _add_finding(
        self,
        findings,
        *,
        value,
        target_names,
        filename,
        basename,
        line,
        col,
    ):
        classification = _classify_placeholder_value(
            value,
            target_names,
            self.vibe_dictionary,
        )
        if not classification:
            return

        placeholder_type, severity, rationale = classification
        name = target_names[0] if target_names else placeholder_type
        findings.append(
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": severity,
                "type": "literal",
                "name": name,
                "simple_name": name,
                "value": placeholder_type,
                "threshold": 0,
                "mock_data_type": placeholder_type,
                "message": (
                    f"Mock or placeholder data in '{name}' "
                    f"({placeholder_type}). {rationale}."
                ),
                "file": filename,
                "basename": basename,
                "line": line,
                "col": col,
            }
        )


_HTTP_RESPONSE_CONSTRUCTORS = {
    "JsonResponse",
    "jsonify",
    "Response",
    "HTMLResponse",
    "JSONResponse",
    "PlainTextResponse",
    "make_response",
    "HttpResponse",
    "HttpResponseBadRequest",
    "HttpResponseServerError",
}

_HTTP_RETURN_KEYS = {"error", "message", "detail", "msg", "reason"}


class ErrorDisclosureRule(SkylosRule):
    rule_id = "SKY-L017"
    name = "Error Information Disclosure"

    def visit_node(self, node, context):
        if not isinstance(node, ast.ExceptHandler):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        # An unnamed handler can still return ``traceback.format_exc()``.
        exc_var = node.name

        findings = []
        basename = Path(filename).name

        for child in ast.walk(node):
            # A returned value reaches a client only by assumption; keep that
            # assumption to handlers that bind the exception, as before.
            if isinstance(child, ast.Return) and child.value and exc_var:
                self._check_disclosure(
                    child.value, exc_var, child, filename, basename, findings
                )

            if isinstance(child, ast.Call):
                func = child.func
                func_name = None
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr
                if func_name in _HTTP_RESPONSE_CONSTRUCTORS:
                    for arg in child.args:
                        self._check_disclosure(
                            arg, exc_var, child, filename, basename, findings
                        )
                    for kw in child.keywords:
                        self._check_disclosure(
                            kw.value, exc_var, child, filename, basename, findings
                        )

        return findings if findings else None

    def _check_disclosure(
        self, value_node, exc_var, report_node, filename, basename, findings
    ):
        disclosed = self._disclosure_kind(value_node, exc_var)
        if disclosed:
            findings.append(
                self._make_finding(report_node, filename, basename, exc_var, disclosed)
            )
            return

        if isinstance(value_node, ast.Dict):
            for k, v in zip(value_node.keys, value_node.values):
                if k and isinstance(k, ast.Constant) and isinstance(k.value, str):
                    if k.value.lower() in _HTTP_RETURN_KEYS:
                        disclosed = self._disclosure_kind(v, exc_var)
                        if disclosed:
                            findings.append(
                                self._make_finding(
                                    report_node, filename, basename, exc_var, disclosed
                                )
                            )
                            return

        if isinstance(value_node, ast.JoinedStr):
            for val in value_node.values:
                if isinstance(val, ast.FormattedValue):
                    disclosed = self._disclosure_kind(val.value, exc_var)
                    if disclosed:
                        findings.append(
                            self._make_finding(
                                report_node, filename, basename, exc_var, disclosed
                            )
                        )
                        return

    def _disclosure_kind(self, node, exc_var):
        """``"traceback"`` for a formatted stack trace, ``"message"`` for exception text."""
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "format_exc":
                if isinstance(func.value, ast.Name) and func.value.id == "traceback":
                    return "traceback"
            if exc_var and isinstance(func, ast.Name) and func.id in ("str", "repr"):
                if node.args and isinstance(node.args[0], ast.Name):
                    if node.args[0].id == exc_var:
                        return "message"

        if exc_var and isinstance(node, ast.Name) and node.id == exc_var:
            return "message"
        return None

    def _make_finding(self, node, filename, basename, exc_var, disclosed="message"):
        destination = (
            f"passed to '{_dotted_name(node.func) or 'Response'}()'"
            if isinstance(node, ast.Call)
            else "returned from an exception handler"
        )
        if disclosed == "traceback":
            message = (
                f"A formatted stack trace is {destination}. If sent to a client, "
                "it can expose internal paths and code. Log it and send a generic "
                "error message instead."
            )
        else:
            message = (
                f"Exception text ('{exc_var}') is {destination}. "
                "Exception messages can include internal details such as paths, "
                "queries or configuration if sent to a client. Send a generic "
                "message unless this "
                "exception's text is written for the client."
            )
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": "MEDIUM",
            "type": "block",
            "name": "error_disclosure",
            "simple_name": "error_disclosure",
            "value": "traceback_leaked" if disclosed == "traceback" else "exception_leaked",
            "threshold": 0,
            "message": message,
            "file": filename,
            "basename": basename,
            "line": node.lineno,
            "col": node.col_offset,
        }


def _is_sensitive_filename(name, vibe_dictionary=None):
    vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
    lower = name.lower()
    for kw in vibe_dictionary.sensitive_file_keywords:
        if kw in lower:
            return True
    return False


class BroadFilePermissionsRule(SkylosRule):
    rule_id = "SKY-L020"
    name = "Overly Broad File Permissions"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(node, ast.Call):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        func = node.func
        func_name = None

        if isinstance(func, ast.Attribute) and func.attr == "chmod":
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                func_name = "os.chmod"

        if func_name != "os.chmod":
            return None

        if len(node.args) < 2:
            return None

        mode_node = node.args[1]
        mode_val = None

        if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, int):
            mode_val = mode_node.value

        if mode_val is None:
            return None

        basename = Path(filename).name

        path_arg = node.args[0]
        target_name = ""
        if isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str):
            target_name = path_arg.value
        elif isinstance(path_arg, ast.Name):
            target_name = path_arg.id

        is_sensitive = _is_sensitive_filename(target_name, self.vibe_dictionary)

        if mode_val & 0o777 == 0o777:
            return [
                self._make_finding(
                    node,
                    filename,
                    basename,
                    mode_val,
                    "HIGH",
                    f"os.chmod() with mode {oct(mode_val)} grants full access to all users.",
                )
            ]

        if mode_val & 0o002:
            return [
                self._make_finding(
                    node,
                    filename,
                    basename,
                    mode_val,
                    "HIGH",
                    f"os.chmod() with mode {oct(mode_val)} is world-writable.",
                )
            ]

        if is_sensitive and mode_val & 0o077:
            return [
                self._make_finding(
                    node,
                    filename,
                    basename,
                    mode_val,
                    "HIGH",
                    f"os.chmod() with mode {oct(mode_val)} on sensitive file. Use 0o600 for private keys and credentials.",
                )
            ]

        return None

    def _make_finding(self, node, filename, basename, mode_val, severity, message):
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": severity,
            "type": "call",
            "name": "os.chmod",
            "simple_name": "os.chmod",
            "value": oct(mode_val),
            "threshold": 0,
            "message": message,
            "file": filename,
            "basename": basename,
            "line": node.lineno,
            "col": node.col_offset,
        }


def _qualified_call_name(func_node):
    parts = []
    node = func_node
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _is_none_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


class MissingNetworkTimeoutRule(SkylosRule):
    rule_id = "SKY-L031"
    name = "Missing Network Timeout"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY

    def visit_node(self, node, context):
        if not isinstance(node, ast.Call):
            return None

        filename = context.get("filename", "")
        if _is_test_file(filename):
            return None

        call_name = _qualified_call_name(node.func)
        if call_name not in self.vibe_dictionary.network_timeout_calls:
            return None

        timeout_kw = next((kw for kw in node.keywords if kw.arg == "timeout"), None)
        if timeout_kw is not None and not _is_none_constant(timeout_kw.value):
            return None

        basename = Path(filename).name
        value = "timeout_none" if timeout_kw is not None else "no_timeout"
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "call",
                "name": call_name,
                "simple_name": call_name,
                "value": value,
                "threshold": 0,
                "message": (
                    f"Network call '{call_name}()' has no timeout. "
                    f"LLM-generated integrations often omit timeouts and can hang worker threads."
                ),
                "file": filename,
                "basename": basename,
                "line": node.lineno,
                "col": node.col_offset,
                "vibe_category": "missing_resilience_control",
                "ai_likelihood": "medium",
            }
        ]
