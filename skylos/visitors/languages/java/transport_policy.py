"""Checks for typed Java trust managers and Spring Security configuration."""

_TRUST_MANAGER = "javax.net.ssl.X509TrustManager"
_EXTENDED_MANAGER = "javax.net.ssl.X509ExtendedTrustManager"
_CERTIFICATE = "java.security.cert.X509Certificate"
_HTTP_SECURITY = (
    "org.springframework.security.config.annotation.web.builders.HttpSecurity"
)
_CSRF_CONFIGURERS = (
    "org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer",
    "org.springframework.security.config.annotation.web.configurers.CsrfConfigurer",
)
_COMMENTS = {"line_comment", "block_comment"}
_FLUENT_CONFIGURERS = {
    "authorizeHttpRequests",
    "cors",
    "headers",
    "httpBasic",
    "oauth2Login",
    "oauth2ResourceServer",
    "requestCache",
    "securityContext",
    "sessionManagement",
}


def _named(node):
    if node is None:
        return []
    return [child for child in node.named_children if child.type not in _COMMENTS]


def _type_matches(analyzer, node, qualified):
    return node is not None and analyzer._resolves_to(analyzer._text(node), qualified)


def _manager_kind(analyzer, owner):
    if owner.type == "object_creation_expression":
        bases = [owner.child_by_field_name("type")]
    elif owner.type == "class_declaration":
        if any(
            _type_matches(analyzer, base, _EXTENDED_MANAGER)
            for base in _named(owner.child_by_field_name("superclass"))
        ):
            return _EXTENDED_MANAGER
        bases = [
            base
            for interface_list in _named(owner.child_by_field_name("interfaces"))
            for base in _named(interface_list)
        ]
    else:
        return None
    for base in bases:
        if _type_matches(analyzer, base, _TRUST_MANAGER):
            return _TRUST_MANAGER
        if owner.type == "object_creation_expression" and _type_matches(
            analyzer, base, _EXTENDED_MANAGER
        ):
            return _EXTENDED_MANAGER
    return None


def _is_noop_check(analyzer, method, manager):
    if analyzer._text(method.child_by_field_name("type")) != "void":
        return False
    modifiers = next(
        (node for node in method.children if node.type == "modifiers"), None
    )
    if modifiers is None:
        return False
    flags = {node.type for node in modifiers.children}
    if "public" not in flags or "static" in flags:
        return False
    parameters = analyzer._formal_parameters(method)
    if len(parameters) not in (2, 3) or (
        len(parameters) == 3 and manager != _EXTENDED_MANAGER
    ):
        return False
    chain, auth, *transport = (
        param.child_by_field_name("type") for param in parameters
    )
    if (
        chain is None
        or chain.type != "array_type"
        or not _type_matches(
            analyzer, chain.child_by_field_name("element"), _CERTIFICATE
        )
    ):
        return False
    if analyzer._text(chain.child_by_field_name("dimensions")).count("[") != 1:
        return False
    auth_type = analyzer._text(auth)
    if auth_type != "java.lang.String" and not (
        auth_type == "String"
        and "String" not in analyzer._file_type_names()
        and not any(
            name != "java.lang.String" and name.endswith(".String")
            for name in analyzer._file_imports()[0]
        )
    ):
        return False
    if transport and not any(
        _type_matches(analyzer, transport[0], qualified)
        for qualified in ("java.net.Socket", "javax.net.ssl.SSLEngine")
    ):
        return False
    body = method.child_by_field_name("body")
    return bool(
        body is not None
        and not body.has_error
        and all(
            statement.type == "return_statement" and not _named(statement)
            for statement in _named(body)
        )
    )


def scan_trust_managers(analyzer, methods):
    if b"TrustManager" not in analyzer.source:
        return
    for method in methods:
        name = analyzer._method_name(method)
        if name not in {"checkClientTrusted", "checkServerTrusted"}:
            continue
        body = method.parent
        owner = body.parent if body is not None and body.type == "class_body" else None
        manager = _manager_kind(analyzer, owner) if owner is not None else None
        if manager and _is_noop_check(analyzer, method, manager):
            analyzer._add_finding(
                "SKY-D210",
                "HIGH",
                f"X.509 trust manager {name} returns without validating certificates. Delegate to a validating trust manager.",
                analyzer._line(method),
                category="tls_certificate_verification",
                cwe="CWE-295",
            )


def _http_security(analyzer, node, state):
    node = analyzer._strip_parentheses(node)
    for _ in range(16):
        if node is None or node.type != "method_invocation":
            break
        if not (
            analyzer._call_name(node) in _FLUENT_CONFIGURERS
            and len(analyzer._call_args(node)) == 1
        ):
            return False
        node = analyzer._strip_parentheses(node.child_by_field_name("object"))
    if node is None:
        return False
    if node.type == "identifier":
        name = analyzer._text(node)
        if name in state.source_types:
            return analyzer._resolves_to(state.source_types[name], _HTTP_SECURITY)
    return analyzer._resolves_to(analyzer._expr_type(node, state) or "", _HTTP_SECURITY)


def _disables_csrf(analyzer, callback, state):
    if callback.type == "method_reference":
        children = _named(callback)
        if len(children) != 2:
            return False
        receiver, member = children
        name = analyzer._text(receiver)
        if receiver.type == "identifier" and (
            name in state.source_types
            or analyzer._is_local_name(receiver, name)
            or analyzer._field_type(receiver, name) is not None
        ):
            return False
        return analyzer._text(member) == "disable" and any(
            _type_matches(analyzer, receiver, configurer)
            for configurer in _CSRF_CONFIGURERS
        )
    if callback.type != "lambda_expression":
        return False
    parameter = callback.child_by_field_name("parameters")
    if parameter is None:
        return False
    if parameter.type != "identifier":
        names = _named(parameter)
        if len(names) != 1:
            return False
        parameter = (
            names[0].child_by_field_name("name")
            if names[0].type == "formal_parameter"
            else names[0]
        )
    body = callback.child_by_field_name("body")
    if body is not None and body.type == "block":
        statements = _named(body)
        if len(statements) != 1 or statements[0].type != "expression_statement":
            return False
        expressions = _named(statements[0])
        body = expressions[0] if expressions else None
    if body is None or body.type != "method_invocation" or parameter is None:
        return False
    receiver = body.child_by_field_name("object")
    return (
        receiver is not None
        and receiver.type == "identifier"
        and analyzer._text(receiver) == analyzer._text(parameter)
        and analyzer._call_name(body) == "disable"
        and not analyzer._call_args(body)
    )


def check_spring_csrf(analyzer, call, state):
    method = analyzer._call_name(call)
    args = analyzer._call_args(call)
    csrf = call
    if method == "disable" and not args:
        csrf = analyzer._strip_parentheses(call.child_by_field_name("object"))
        if (
            csrf is None
            or csrf.type != "method_invocation"
            or analyzer._call_name(csrf) != "csrf"
            or analyzer._call_args(csrf)
        ):
            return
    elif (
        method != "csrf"
        or len(args) != 1
        or not _disables_csrf(analyzer, args[0], state)
    ):
        return
    if _http_security(analyzer, csrf.child_by_field_name("object"), state):
        analyzer._add_finding(
            "SKY-D433",
            "MEDIUM",
            "Spring Security explicitly disables CSRF protection. Review whether this security chain can receive browser credentials.",
            analyzer._line(call.child_by_field_name("name") or call),
            category="csrf_configuration",
            cwe="CWE-352",
        )
