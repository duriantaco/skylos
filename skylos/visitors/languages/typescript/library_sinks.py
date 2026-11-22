"""TS/JS library sinks that are unsafe by configuration, without request proof.

* SKY-D236 (XXE): libxmljs ``parseXml``/``parseXmlString`` with
  ``noent: true``, and the libxml2 ``XML_PARSE_NOENT`` parse option (also
  through libxml2-wasm's ``ParseOption``). Entity substitution lets a document
  read local files and expand entity bombs. HIGH; the request-taint pass
  raises it to CRITICAL when request data is parsed.
* SKY-D238 (NoSQL injection): a MongoDB ``$where`` string built from a
  parameter of the enclosing function (``{ $where: `this.x > '${threshold}'` }``
  in a DAO method), like SQL text built from a parameter. A ``Number``/
  ``parseInt``/``parseFloat`` value is not text. The request-taint pass
  reports the same shape inside handlers.
* SKY-D252 (cookie flags): ``express-session`` and ``cookie-session``
  middleware whose session cookie is not marked ``secure`` (both default to
  ``false``) or sets ``httpOnly: false``. ``secure: true``, ``'auto'`` or a
  non-literal (``process.env.NODE_ENV === 'production'``) counts as set.
  Not reported inside a branch on a development or test environment.
* SKY-D207 (weak hash): the ``md5`` npm package (also ``blueimp-md5`` and
  ``js-md5``) called in a statement about a token, password, secret, session,
  nonce, salt, signature or reset code (``req.query.token ==
  md5(req.query.login)``). Checksums and cache keys are not reported.
* SKY-D233 (unsafe deserialization): ``node-serialize`` ``unserialize``,
  ``serialize-to-js`` ``deserialize`` and ``funcster`` ``deepDeserialize`` of a
  non-literal value. These rebuild functions from their input. HIGH; CRITICAL
  with request data from the taint pass.
"""

from __future__ import annotations

import re

_XML_MODULES = frozenset({"libxmljs", "libxmljs2"})
_XML_PARSERS = frozenset({"parseXml", "parseXmlString", "parseXmlAsync"})
_LIBXML_MODULE_RE = re.compile(
    rb"""['"`](?:libxmljs2?|libxml2-wasm|node-libxml)['"`]"""
)
_MD5_MODULES = frozenset({"md5", "blueimp-md5", "js-md5"})
_MD5_SECURITY_RE = re.compile(
    r"token|passw|secret|session|nonce|salt|signature|hmac|otp|reset|apikey|credential",
    re.IGNORECASE,
)
_DESERIALIZERS = {
    "node-serialize": frozenset({"unserialize"}),
    "serialize-to-js": frozenset({"deserialize"}),
    "funcster": frozenset({"deepDeserialize"}),
}
_WRAPPERS = frozenset(
    {
        "as_expression",
        "await_expression",
        "non_null_expression",
        "parenthesized_expression",
        "satisfies_expression",
    }
)


def _text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _unwrap(node):
    while node is not None and node.type in _WRAPPERS:
        inner = next(iter(node.named_children), None)
        if inner is None:
            return node
        node = inner
    return node


def _string_value(source: bytes, node) -> str | None:
    node = _unwrap(node)
    if node is None or node.type != "string":
        return None
    text = _text(source, node)
    return text[1:-1] if len(text) >= 2 else None


def _module_bindings(root, source: bytes) -> dict[str, tuple[str, str]]:
    """local name -> (module, imported) for imports and ``require``."""
    bindings: dict[str, tuple[str, str]] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type == "import_statement":
            module = _string_value(source, node.child_by_field_name("source"))
            if module is None:
                continue
            for clause in node.named_children:
                if clause.type != "import_clause":
                    continue
                for child in clause.named_children:
                    if child.type == "identifier":
                        bindings[_text(source, child)] = (module, "*")
                    elif child.type == "namespace_import":
                        for sub in child.named_children:
                            if sub.type == "identifier":
                                bindings[_text(source, sub)] = (module, "*")
                    elif child.type == "named_imports":
                        for spec in child.named_children:
                            name = spec.child_by_field_name("name")
                            alias = spec.child_by_field_name("alias") or name
                            if name is not None and alias is not None:
                                bindings[_text(source, alias)] = (
                                    module,
                                    _text(source, name),
                                )
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = _unwrap(node.child_by_field_name("value"))
            member = None
            if value is not None and value.type == "member_expression":
                prop = value.child_by_field_name("property")
                member = _text(source, prop) if prop is not None else None
                value = _unwrap(value.child_by_field_name("object"))
            if (
                name is None
                or value is None
                or value.type != "call_expression"
                or _text(source, value.child_by_field_name("function")) != "require"
            ):
                continue
            args = value.child_by_field_name("arguments")
            module = _string_value(
                source, next(iter(args.named_children), None) if args else None
            )
            if module is None:
                continue
            if name.type == "identifier":
                bindings[_text(source, name)] = (module, member or "*")
            elif name.type == "object_pattern" and member is None:
                for child in name.named_children:
                    if child.type == "shorthand_property_identifier_pattern":
                        bindings[_text(source, child)] = (module, _text(source, child))
    return bindings


def _statement_text(source: bytes, node) -> str:
    current = node
    while current.parent is not None and current.type not in {
        "expression_statement",
        "lexical_declaration",
        "variable_declaration",
        "return_statement",
        "if_statement",
    }:
        current = current.parent
    if current.type == "if_statement":
        condition = current.child_by_field_name("condition")
        current = condition if condition is not None else current
    return _text(source, current)[:400]


def _call_target(source: bytes, callee, bindings) -> tuple[str, str] | None:
    callee = _unwrap(callee)
    if callee is None:
        return None
    if callee.type == "identifier":
        binding = bindings.get(_text(source, callee))
        if binding is not None and (binding[1] != "*" or binding[0] in _MD5_MODULES):
            return binding
        return None
    if callee.type != "member_expression":
        return None
    obj = _unwrap(callee.child_by_field_name("object"))
    prop = callee.child_by_field_name("property")
    if obj is None or prop is None or obj.type != "identifier":
        return None
    binding = bindings.get(_text(source, obj))
    if binding is None or binding[1] != "*":
        return None
    return binding[0], _text(source, prop)


def _noent_option(source: bytes, node) -> bool:
    node = _unwrap(node)
    if node is None or node.type != "object":
        return False
    for pair in node.named_children:
        if pair.type != "pair":
            continue
        key = pair.child_by_field_name("key")
        value = _unwrap(pair.child_by_field_name("value"))
        if (
            key is not None
            and _text(source, key).strip("'\"") == "noent"
            and value is not None
            and value.type == "true"
        ):
            return True
    return False


def _is_negated_flag(node) -> bool:
    """``options & ~XML_PARSE_NOENT`` clears the flag."""
    parent = node.parent
    while parent is not None and parent.type == "parenthesized_expression":
        parent = parent.parent
    return (
        parent is not None
        and parent.type == "unary_expression"
        and parent.children
        and parent.children[0].type == "~"
    )


_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "function",
        "method_definition",
        "generator_function",
        "generator_function_declaration",
    }
)
_TEXT_METHODS = frozenset(
    {
        "concat",
        "padEnd",
        "padStart",
        "replace",
        "replaceAll",
        "slice",
        "substr",
        "substring",
        "toLowerCase",
        "toString",
        "toUpperCase",
        "trim",
        "trimEnd",
        "trimStart",
    }
)


def _function_parameters(function, source: bytes) -> set[str]:
    names: set[str] = set()
    single = function.child_by_field_name("parameter")
    params = [single] if single is not None else []
    container = function.child_by_field_name("parameters")
    if container is not None:
        params.extend(container.named_children)
    for param in params:
        stack = [param]
        while stack:
            node = stack.pop()
            if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
                names.add(_text(source, node))
            elif node.type in {"object_assignment_pattern", "assignment_pattern"}:
                left = node.child_by_field_name("left")
                if left is not None:
                    stack.append(left)
            elif node.type in {"required_parameter", "optional_parameter"}:
                pattern = node.child_by_field_name("pattern")
                if pattern is not None:
                    stack.append(pattern)
            else:
                stack.extend(node.children)
    return names


def _local_values(function, source: bytes) -> dict[str, list]:
    values: dict[str, list] = {}
    body = function.child_by_field_name("body")
    stack = [body] if body is not None else []
    while stack:
        node = stack.pop()
        if node is not body and node.type in _FUNCTION_TYPES:
            continue
        stack.extend(node.children)
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and name.type == "identifier" and value is not None:
                values.setdefault(_text(source, name), []).append(value)
    return values


def _parameter_text(source: bytes, node, scopes, depth: int = 0) -> bool:
    """The expression can carry text from a parameter of an enclosing
    function (through local ``const``/``let`` values), not only numbers."""
    node = _unwrap(node)
    if node is None or depth > 4:
        return False
    if node.type == "call_expression":
        # Text survives string methods and String(); any other call (a
        # lookup, a cast, a project helper) is left to the request-taint pass.
        callee = _unwrap(node.child_by_field_name("function"))
        if callee is None:
            return False
        if callee.type == "identifier":
            if _text(source, callee) != "String":
                return False
            args = node.child_by_field_name("arguments")
            return any(
                _parameter_text(source, arg, scopes, depth + 1)
                for arg in (args.named_children if args else [])
            )
        if callee.type != "member_expression":
            return False
        prop = callee.child_by_field_name("property")
        if prop is None or _text(source, prop) not in _TEXT_METHODS:
            return False
        return _parameter_text(
            source, callee.child_by_field_name("object"), scopes, depth + 1
        )
    if node.type == "identifier":
        name = _text(source, node)
        for params, values in scopes:
            if name in values:
                return any(
                    _parameter_text(source, value, scopes, depth + 1)
                    for value in values[name]
                )
            if name in params:
                return True
        return False
    if node.type in _FUNCTION_TYPES:
        return False
    return any(
        _parameter_text(source, child, scopes, depth + 1)
        for child in node.named_children
    )


def _where_from_parameter(source_bytes: bytes, pair) -> bool:
    value = _unwrap(pair.child_by_field_name("value"))
    if value is None or value.type not in {"template_string", "binary_expression"}:
        return False
    parts = (
        [
            next(iter(child.named_children), None)
            for child in value.named_children
            if child.type == "template_substitution"
        ]
        if value.type == "template_string"
        else [value]
    )
    scopes = []
    current = pair.parent
    while current is not None and len(scopes) < 4:
        if current.type in _FUNCTION_TYPES:
            scopes.append(
                (
                    _function_parameters(current, source_bytes),
                    _local_values(current, source_bytes),
                )
            )
        current = current.parent
    return any(_parameter_text(source_bytes, part, scopes) for part in parts)


def _where_finding_line(pair) -> int:
    """Report on the query call when the object is its argument, so the
    request-taint finding for the same query merges with this one."""
    obj = pair.parent
    args = obj.parent if obj is not None else None
    call = args.parent if args is not None else None
    if (
        obj is not None
        and obj.type == "object"
        and args is not None
        and args.type == "arguments"
        and call is not None
        and call.type == "call_expression"
    ):
        return call.start_point[0] + 1
    return pair.start_point[0] + 1


_SESSION_MODULES = frozenset({"express-session", "cookie-session"})
_DEV_CONDITION_RE = re.compile(r"develop|\bdev\b|\btest|\blocal", re.IGNORECASE)


def _object_pairs(source: bytes, node) -> dict[str, object] | None:
    node = _unwrap(node)
    if node is None or node.type != "object":
        return None
    pairs: dict[str, object] = {}
    for child in node.named_children:
        if child.type == "pair":
            key = child.child_by_field_name("key")
            if key is not None:
                pairs[_text(source, key).strip("'\"")] = _unwrap(
                    child.child_by_field_name("value")
                )
        elif child.type in {"spread_element", "shorthand_property_identifier"}:
            # A spread or a shorthand value can carry any option.
            pairs.setdefault("\x00unknown", child)
    return pairs


def _in_dev_branch(source: bytes, node) -> bool:
    current = node.parent
    while current is not None:
        if current.type in {"if_statement", "ternary_expression"}:
            condition = current.child_by_field_name("condition")
            if condition is not None and _DEV_CONDITION_RE.search(
                _text(source, condition)
            ):
                return True
        current = current.parent
    return False


def _check_session_cookie(
    source: bytes, call, module: str, file_path: str, findings: list[dict]
) -> None:
    args = call.child_by_field_name("arguments")
    first = next(
        (c for c in (args.named_children if args else []) if c.type != "comment"),
        None,
    )
    options = _object_pairs(source, first)
    if options is None or "\x00unknown" in options or _in_dev_branch(source, call):
        return
    cookie = options
    if module == "express-session":
        if "cookie" not in options:
            cookie = {}
        else:
            cookie = _object_pairs(source, options["cookie"])
            if cookie is None or "\x00unknown" in cookie:
                return
    states = {}
    for flag in ("secure", "httpOnly"):
        value = cookie.get(flag)
        if value is None:
            # express-session and cookie-session default httpOnly to true and
            # secure to false.
            states[flag] = "true" if flag == "httpOnly" else "false"
        elif value.type in {"false", "true"}:
            states[flag] = value.type
        else:
            states[flag] = "true"
    missing = [flag for flag, state in states.items() if state != "true"]
    if not missing:
        return
    risks = []
    if "secure" in missing:
        risks.append("travel over plain HTTP (secure defaults to false)")
    if "httpOnly" in missing:
        risks.append("be read by page scripts")
    findings.append(
        {
            "rule_id": "SKY-D252",
            "severity": "MEDIUM",
            "message": (
                f"{module} session cookie is not marked "
                + " and ".join(missing)
                + ", so the session id can "
                + " and ".join(risks)
                + ". Set "
                + ("cookie: { " if module == "express-session" else "")
                + ", ".join(f"{flag}: true" for flag in missing)
                + (" }" if module == "express-session" else "")
                + "."
            ),
            "file": str(file_path),
            "line": call.start_point[0] + 1,
            "col": 0,
        }
    )


def check_library_sinks(
    root_node, source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    if b"$where" in source_bytes:
        stack = [root_node]
        while stack:
            node = stack.pop()
            stack.extend(node.children)
            if node.type != "pair":
                continue
            key = node.child_by_field_name("key")
            if key is None or _text(source_bytes, key).strip("'\"") != "$where":
                continue
            if _where_from_parameter(source_bytes, node):
                findings.append(
                    {
                        "rule_id": "SKY-D238",
                        "severity": "HIGH",
                        "message": (
                            "NoSQL injection: a MongoDB $where JavaScript string "
                            "is built from a function parameter; a caller that "
                            "passes request text can run code in the database. "
                            "Use query operators with typed values instead."
                        ),
                        "file": str(file_path),
                        "line": _where_finding_line(node),
                        "col": 0,
                    }
                )
    has_libxml = bool(_LIBXML_MODULE_RE.search(source_bytes))
    has_deserializer = any(module.encode() in source_bytes for module in _DESERIALIZERS)
    has_session = any(module.encode() in source_bytes for module in _SESSION_MODULES)
    has_md5 = bool(re.search(rb"""['"`](?:blueimp-|js-)?md5['"`]""", source_bytes))
    if not (has_libxml or has_deserializer or has_session or has_md5):
        return
    bindings = _module_bindings(root_node, source_bytes)
    if has_session:
        session_names = {
            name
            for name, (module, imported) in bindings.items()
            if module in _SESSION_MODULES and imported in {"*", "default"}
        }
        stack = [root_node]
        while session_names and stack:
            node = stack.pop()
            stack.extend(node.children)
            if node.type != "call_expression":
                continue
            callee = _unwrap(node.child_by_field_name("function"))
            if callee is not None and callee.type == "identifier":
                name = _text(source_bytes, callee)
                if name in session_names:
                    _check_session_cookie(
                        source_bytes, node, bindings[name][0], file_path, findings
                    )
    stack = [root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if (
            has_libxml
            and node.type == "property_identifier"
            and _text(source_bytes, node) == "XML_PARSE_NOENT"
            and node.parent is not None
            and node.parent.type == "member_expression"
            and not _is_negated_flag(node.parent)
        ):
            findings.append(
                {
                    "rule_id": "SKY-D236",
                    "severity": "HIGH",
                    "message": (
                        "XML external entity (XXE): libxml2 parse option "
                        "XML_PARSE_NOENT substitutes entities, so a document "
                        "can read local files. Parse without it."
                    ),
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )
            continue
        if node.type != "call_expression":
            continue
        target = _call_target(
            source_bytes, node.child_by_field_name("function"), bindings
        )
        if target is None:
            continue
        module, name = target
        args_node = node.child_by_field_name("arguments")
        args = [
            child
            for child in (args_node.named_children if args_node else [])
            if child.type != "comment"
        ]
        if module in _MD5_MODULES and name in {"*", "default"}:
            if _MD5_SECURITY_RE.search(_statement_text(source_bytes, node)):
                findings.append(
                    {
                        "rule_id": "SKY-D207",
                        "severity": "MEDIUM",
                        "message": (
                            f"Weak hash: {module} computes MD5 for a security "
                            "value. Use crypto.randomBytes for tokens and "
                            "bcrypt/argon2 for passwords."
                        ),
                        "file": str(file_path),
                        "line": node.start_point[0] + 1,
                        "col": 0,
                    }
                )
            continue
        if module in _XML_MODULES and name in _XML_PARSERS:
            if len(args) > 1 and _noent_option(source_bytes, args[1]):
                findings.append(
                    {
                        "rule_id": "SKY-D236",
                        "severity": "HIGH",
                        "message": (
                            f"XML external entity (XXE): {module}.{name}() with "
                            "noent: true substitutes external entities. Remove noent."
                        ),
                        "file": str(file_path),
                        "line": node.start_point[0] + 1,
                        "col": 0,
                    }
                )
        elif (
            name in _DESERIALIZERS.get(module, ())
            and args
            and _unwrap(args[0]).type not in {"string", "template_string"}
        ):
            findings.append(
                {
                    "rule_id": "SKY-D233",
                    "severity": "HIGH",
                    "message": (
                        f"Unsafe deserialization: {module} {name}() rebuilds "
                        "functions from its input; never pass it data you "
                        "did not write. Use JSON.parse."
                    ),
                    "file": str(file_path),
                    "line": node.start_point[0] + 1,
                    "col": 0,
                }
            )
