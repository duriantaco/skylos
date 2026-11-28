"""Detect explicit selection of obsolete Python TLS protocol versions."""

from __future__ import annotations

import ast

from .tls_provenance import _Bindings, _safe_native_name

_OBSOLETE_PROTOCOLS = frozenset(
    {
        "ssl.PROTOCOL_SSLv2",
        "ssl.PROTOCOL_SSLv3",
        "ssl.PROTOCOL_TLSv1",
        "ssl.PROTOCOL_TLSv1_1",
        "OpenSSL.SSL.SSLv2_METHOD",
        "OpenSSL.SSL.SSLv3_METHOD",
        "OpenSSL.SSL.TLSv1_METHOD",
        "OpenSSL.SSL.TLSv1_1_METHOD",
    }
)
_OBSOLETE_MINIMUMS = frozenset(
    {
        "ssl.TLSVersion.SSLv3",
        "ssl.TLSVersion.TLSv1",
        "ssl.TLSVersion.TLSv1_1",
        "OpenSSL.SSL.SSL3_VERSION",
        "OpenSSL.SSL.TLS1_VERSION",
        "OpenSSL.SSL.TLS1_1_VERSION",
    }
)
_PROTOCOL_ARGUMENTS = {
    "ssl.SSLContext": ("protocol", 0),
    "ssl.wrap_socket": ("ssl_version", 5),
    "OpenSSL.SSL.Context": ("method", 0),
}
_CONTEXT_FACTORIES = {
    "ssl.SSLContext",
    "ssl.create_default_context",
    "ssl._create_unverified_context",
}


def _argument(call, name, position):
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    values = [kw.value for kw in call.keywords if kw.arg == name]
    if len(call.args) > position:
        values.append(call.args[position])
    return values[0] if len(values) == 1 else None


def scan(tree, file_path, findings, *, project_root=None):
    nodes = list(ast.walk(tree))
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    bindings = _Bindings(tree, parents=parents)

    def native(node):
        return _safe_native_name(node, bindings, file_path, project_root)

    def protocol_value(node):
        # An obsolete parameter default is relevant when it is supplied
        # to the actual provider setting in this function.
        if isinstance(node, ast.Name):
            scope = bindings.scope(node)
            if isinstance(
                scope, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and bindings.bound.get((id(scope), node.id)) == [None]:
                parameters = scope.args
                positional = parameters.posonlyargs + parameters.args
                defaults = list(
                    zip(
                        positional[len(positional) - len(parameters.defaults) :],
                        parameters.defaults,
                    )
                )
                defaults.extend(zip(parameters.kwonlyargs, parameters.kw_defaults))
                for parameter, default in defaults:
                    if parameter.arg == node.id and default is not None:
                        return native(default), True
        resolved = bindings.value(node)
        return (None if isinstance(resolved, ast.Call) else native(node)), False

    def uses_context(node, factories):
        value = bindings.value(node)
        return isinstance(value, ast.Call) and native(value.func) in factories

    candidates = []
    for node in nodes:
        if isinstance(node, ast.Call):
            # Only native APIs can establish the protocol configured by a call.
            provision = _PROTOCOL_ARGUMENTS.get(bindings.name(node.func))
            if provision is not None and native(node.func) in _PROTOCOL_ARGUMENTS:
                version, default = protocol_value(_argument(node, *provision))
                if version in _OBSOLETE_PROTOCOLS:
                    candidates.append((node, version, default))
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "set_min_proto_version"
                and uses_context(func.value, {"OpenSSL.SSL.Context"})
            ):
                version, default = protocol_value(_argument(node, "version", 0))
                if version in _OBSOLETE_MINIMUMS:
                    candidates.append((node, version, default))
            continue
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(
            isinstance(target, ast.Attribute)
            and target.attr == "minimum_version"
            and uses_context(target.value, _CONTEXT_FACTORIES)
            for target in targets
        ):
            version, default = protocol_value(node.value)
            if version in _OBSOLETE_MINIMUMS:
                candidates.append((node, version, default))

    for node, version, default in sorted(
        candidates, key=lambda item: (item[0].lineno, item[0].col_offset)
    ):
        selection = "defaults to" if default else "explicitly selects"
        findings.append(
            {
                "rule_id": "SKY-D430",
                "severity": "HIGH",
                "message": f"TLS configuration {selection} obsolete {version}. Require TLS 1.2 or newer.",
                "file": str(file_path),
                "line": node.lineno,
                "col": node.col_offset,
                "symbol": getattr(bindings.scope(node), "name", "<module>"),
                "cwe": "CWE-327",
            }
        )
