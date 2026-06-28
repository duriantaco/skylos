from __future__ import annotations

import ast
from pathlib import Path

from skylos.rules.base import SkylosRule


LOCK_ORDER_RULE_ID = "SKY-Q403"
SHARED_STATE_RULE_ID = "SKY-Q404"

_LOCK_NAME_HINTS = ("lock", "mutex", "semaphore")
_MUTATING_METHODS = {
    "append",
    "clear",
    "extend",
    "insert",
    "pop",
    "popitem",
    "remove",
    "setdefault",
    "sort",
    "update",
}
_MUTABLE_FACTORY_NAMES = {"dict", "list", "set", "defaultdict"}


class LockOrderRule(SkylosRule):
    rule_id = LOCK_ORDER_RULE_ID
    name = "Inconsistent Lock Acquisition Order"

    def visit_node(self, node: ast.AST, context: dict) -> list[dict] | None:
        if not isinstance(node, ast.Module):
            return None

        seen_pairs: dict[tuple[str, str], list[frozenset[str]]] = {}
        findings: list[dict] = []

        for first, second, lock_node, guard_locks in _iter_lock_pairs(node.body):
            reverse = (second, first)
            reverse_guards = seen_pairs.get(reverse, [])
            if not any(_can_deadlock(guard_locks, prev) for prev in reverse_guards):
                seen_pairs.setdefault((first, second), []).append(guard_locks)
                continue

            findings.append(
                _make_finding(
                    context,
                    lock_node,
                    LOCK_ORDER_RULE_ID,
                    "lock_order",
                    f"Potential deadlock: locks acquired as {first} -> {second} and {second} -> {first}.",
                )
            )
            seen_pairs.setdefault((first, second), []).append(guard_locks)

        return findings or None


class ThreadSharedStateRule(SkylosRule):
    rule_id = SHARED_STATE_RULE_ID
    name = "Thread Shared State Mutation"

    def visit_node(self, node: ast.AST, context: dict) -> list[dict] | None:
        if not isinstance(node, ast.Module):
            return None

        shared_names = _module_state_names(node)
        if not shared_names:
            return None

        functions = {
            item.name: item for item in node.body if isinstance(item, ast.FunctionDef)
        }
        findings: list[dict] = []

        for target, fn in _thread_target_functions(node, functions):
            if _has_lock_use(fn):
                continue
            findings.extend(_shared_state_findings(context, target, fn, shared_names))

        return findings or None


def _iter_lock_pairs(stmts: list[ast.stmt], held: tuple[str, ...] = ()):
    for stmt in stmts:
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            yield from _iter_with_lock_pairs(stmt, held)
            continue

        for block in _child_statement_blocks(stmt):
            yield from _iter_lock_pairs(block, held)


def _iter_with_lock_pairs(stmt: ast.With | ast.AsyncWith, held: tuple[str, ...]):
    locks = tuple(
        lock_name
        for item in stmt.items
        if (lock_name := _lock_expr_name(item.context_expr)) is not None
    )
    held_lock_pairs = (
        (held_index, held_name, lock_name)
        for held_index, held_name in enumerate(held)
        for lock_name in locks
    )
    for held_index, held_name, lock_name in held_lock_pairs:
        guard_locks = frozenset(held[:held_index])
        if held_name != lock_name:
            yield held_name, lock_name, stmt, guard_locks
    for lock_index, (first, second) in enumerate(zip(locks, locks[1:])):
        guard_locks = frozenset((*held, *locks[:lock_index]))
        if first != second:
            yield first, second, stmt, guard_locks
    yield from _iter_lock_pairs(stmt.body, held + locks)


def _can_deadlock(current_guard: frozenset[str], previous_guard: frozenset[str]) -> bool:
    return not current_guard.intersection(previous_guard)


def _child_statement_blocks(node: ast.AST) -> list[list[ast.stmt]]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.body]
    blocks = []
    for attr in ("body", "orelse", "finalbody"):
        value = getattr(node, attr, None)
        if isinstance(value, list) and value and all(isinstance(v, ast.stmt) for v in value):
            blocks.append(value)
    for handler in getattr(node, "handlers", ()) or ():
        if isinstance(handler, ast.ExceptHandler):
            blocks.append(handler.body)
    return blocks


def _lock_expr_name(node: ast.AST) -> str | None:
    text = _expr_text(node)
    if text and _looks_like_lock_name(text):
        return text
    return None


def _looks_like_lock_name(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _LOCK_NAME_HINTS)


def _expr_text(node: ast.AST) -> str | None:
    try:
        return ast.unparse(node)
    except Exception:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
    return None


def _module_state_names(module: ast.Module) -> set[str]:
    names: set[str] = set()
    for stmt in module.body:
        if isinstance(stmt, ast.Assign) and _looks_like_shared_value(stmt.value):
            for target in stmt.targets:
                names.update(_target_names(target))
        elif isinstance(stmt, ast.AnnAssign) and _looks_like_shared_value(stmt.value):
            names.update(_target_names(stmt.target))
    return names


def _looks_like_shared_value(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, (ast.List, ast.Dict, ast.Set, ast.Constant)):
        return True
    if isinstance(node, ast.Call):
        return _call_name(node.func).split(".")[-1] in _MUTABLE_FACTORY_NAMES
    return False


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for elt in node.elts:
            names.update(_target_names(elt))
        return names
    return set()


def _thread_targets(module: ast.Module) -> set[str]:
    targets: set[str] = set()
    for node in ast.walk(module):
        if not isinstance(node, ast.Call) or not _is_thread_constructor(node.func):
            continue
        for kw in node.keywords:
            if kw.arg == "target" and isinstance(kw.value, ast.Name):
                targets.add(kw.value.id)
    return targets


def _thread_target_functions(
    module: ast.Module,
    functions: dict[str, ast.FunctionDef],
):
    for target in _thread_targets(module):
        fn = functions.get(target)
        if fn is not None:
            yield target, fn


def _is_thread_constructor(node: ast.AST) -> bool:
    name = _call_name(node)
    return name == "Thread" or name.endswith(".Thread")


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _has_lock_use(fn: ast.FunctionDef) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            if any(_lock_expr_name(item.context_expr) for item in node.items):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"acquire", "release"} and _lock_expr_name(node.func.value):
                return True
    return False


def _shared_state_findings(
    context: dict,
    target: str,
    fn: ast.FunctionDef,
    shared_names: set[str],
) -> list[dict]:
    findings = []
    for name, mutation in _mutated_shared_names(fn, shared_names).items():
        findings.append(
            _make_finding(
                context,
                mutation,
                SHARED_STATE_RULE_ID,
                name,
                f"Thread target '{target}' mutates shared module state '{name}' without an obvious lock.",
            )
        )
    return findings


def _mutated_shared_names(fn: ast.FunctionDef, shared_names: set[str]) -> dict[str, ast.AST]:
    global_names = {
        name for node in ast.walk(fn) if isinstance(node, ast.Global) for name in node.names
    }
    mutations: dict[str, ast.AST] = {}

    for target, node, require_global in _iter_mutation_targets(fn):
        _record_mutation(
            target,
            node,
            shared_names,
            global_names,
            mutations,
            require_global_for_name=require_global,
        )

    return mutations


def _iter_mutation_targets(fn: ast.FunctionDef):
    for node in ast.walk(fn):
        if isinstance(node, ast.AugAssign):
            yield node.target, node, True
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            yield from ((target, node, True) for target in _assignment_targets(node))
        elif _is_mutating_method_call(node):
            yield node.func.value, node, False


def _is_mutating_method_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _MUTATING_METHODS
    )


def _assignment_targets(node: ast.Assign | ast.AnnAssign) -> list[ast.expr]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    return [node.target]


def _record_mutation(
    target: ast.AST,
    node: ast.AST,
    shared_names: set[str],
    global_names: set[str],
    mutations: dict[str, ast.AST],
    *,
    require_global_for_name: bool = True,
) -> None:
    name = _mutation_root_name(target)
    can_mutate = name in global_names or not require_global_for_name
    if name in shared_names and (can_mutate or not isinstance(target, ast.Name)):
        mutations.setdefault(name, node)


def _mutation_root_name(node: ast.AST) -> str | None:
    current = node
    while isinstance(current, (ast.Subscript, ast.Attribute)):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return None


def _make_finding(
    context: dict,
    node: ast.AST,
    rule_id: str,
    name: str,
    message: str,
) -> dict:
    filename = context.get("filename", "")
    severity = "HIGH" if rule_id == LOCK_ORDER_RULE_ID else "MEDIUM"
    return {
        "rule_id": rule_id,
        "kind": "concurrency",
        "severity": severity,
        "type": "concurrency",
        "name": name,
        "simple_name": name,
        "value": name,
        "threshold": 0,
        "message": message,
        "file": filename,
        "basename": Path(filename).name,
        "line": getattr(node, "lineno", 1),
        "col": getattr(node, "col_offset", 0),
    }
