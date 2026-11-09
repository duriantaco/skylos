"""Recognize disabled TLS checks on proven Playwright browser instances."""

import ast

from .untrusted_sources import UntrustedSourceIndex


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _nodes(scope):
    pending = list(getattr(scope, "body", []))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))


def disabled_browser_tls(node):
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {
        "new_context",
        "new_page",
        "launch_persistent_context",
    }:
        return False
    if not any(
        k.arg == "ignore_https_errors"
        and isinstance(k.value, ast.Constant)
        and k.value.value is True
        for k in node.keywords
    ):
        return False
    chain = []
    current = node
    while current is not None:
        chain.append(current)
        current = getattr(current, "parent", None)
    module = next((n for n in chain if isinstance(n, ast.Module)), None)
    scope = next(
        (n for n in chain if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
        module,
    )
    if module is None or scope is None:
        return False
    index = UntrustedSourceIndex(module)
    managers = set()
    for parent in chain:
        if not isinstance(parent, (ast.With, ast.AsyncWith)):
            continue
        for item in parent.items:
            if not isinstance(item.optional_vars, ast.Name) or not isinstance(
                item.context_expr, ast.Call
            ):
                continue
            provider = index.resolved_import(
                scope if scope is not module else None, _dotted(item.context_expr.func)
            )
            if provider in {
                "playwright.async_api.async_playwright",
                "playwright.sync_api.sync_playwright",
            }:
                managers.add(item.optional_vars.id)
    if not managers:
        return False
    nodes = list(_nodes(scope))
    # Provider replacement makes SDK identity unknown, including monkeypatches.
    for child in nodes:
        if (
            isinstance(child, ast.Name)
            and isinstance(child.ctx, (ast.Store, ast.Del))
            and child.id in managers
        ):
            parent = getattr(child, "parent", None)
            if not isinstance(parent, ast.withitem):
                return False
        if isinstance(child, ast.Attribute) and isinstance(
            child.ctx, (ast.Store, ast.Del)
        ):
            if _dotted(child).split(".", 1)[0] in managers:
                return False
        if isinstance(child, ast.Call) and _dotted(child.func) in {
            "setattr",
            "delattr",
            "exec",
        }:
            return False

    def launch(value):
        if isinstance(value, ast.Await):
            value = value.value
        if not isinstance(value, ast.Call):
            return False
        parts = _dotted(value.func).split(".")
        return (
            len(parts) == 3
            and parts[0] in managers
            and parts[1] in {"chromium", "firefox", "webkit"}
            and parts[2] == "launch"
        )

    if node.func.attr == "launch_persistent_context":
        parts = _dotted(node.func.value).split(".")
        return (
            len(parts) == 2
            and parts[0] in managers
            and parts[1] in {"chromium", "firefox", "webkit"}
        )
    receiver = node.func.value
    if not isinstance(receiver, ast.Name):
        return False
    arguments = getattr(scope, "args", None)
    if arguments is not None and any(
        arg.arg == receiver.id
        for arg in ast.walk(arguments)
        if isinstance(arg, ast.arg)
    ):
        return False
    values = []
    for child in nodes:
        if (
            isinstance(child, ast.Name)
            and child.id == receiver.id
            and isinstance(child.ctx, (ast.Store, ast.Del))
        ):
            parent = getattr(child, "parent", None)
            if not isinstance(parent, (ast.Assign, ast.AnnAssign)) or child not in (
                parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            ):
                return False
            # An initial None can only raise at new_context; it cannot supply
            # an unrelated implementation on a branch without a launch.
            if not (
                isinstance(parent.value, ast.Constant) and parent.value.value is None
            ):
                values.append(parent.value)
        if (
            isinstance(child, ast.Attribute)
            and isinstance(child.ctx, (ast.Store, ast.Del))
            and _dotted(child).split(".", 1)[0] == receiver.id
        ):
            return False
    return bool(values) and all(launch(value) for value in values)


def browser_tls_finding(node, filename):
    if not disabled_browser_tls(node):
        return None
    return {
        "rule_id": "SKY-D210",
        "severity": "HIGH",
        "file": str(filename),
        "line": node.lineno,
        "col": node.col_offset,
        "message": "TLS certificate verification disabled on Playwright browser context",
    }
