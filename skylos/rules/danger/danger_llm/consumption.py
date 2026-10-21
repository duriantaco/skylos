from __future__ import annotations

import ast
import sys
from dataclasses import dataclass

from skylos.rules.danger.builtin_bindings import builtin_references

from .utils import (
    DIRECT_LLM_CALLS,
    LLM_CLIENT_CALL_SUFFIXES,
    LLM_CLIENT_CONSTRUCTORS,
    qualified_name_from_call,
    root_name,
)


TOKEN_LIMIT_KEYWORDS = {
    "max_completion_tokens",
    "max_output_tokens",
    "max_tokens",
    "maxOutputTokens",
}

TIMEOUT_KEYWORDS = {
    "request_timeout",
    "timeout",
    "timeout_seconds",
}

AGENT_ITERATION_KEYWORDS = {
    "max_execution_time",
    "max_iter",
    "max_iterations",
}

AGENT_EXECUTOR_SUFFIXES = (
    ".AgentExecutor",
    ".AgentExecutor.from_agent_and_tools",
    ".initialize_agent",
    "AgentExecutor",
    "AgentExecutor.from_agent_and_tools",
    "initialize_agent",
)

INFINITE_ITERATOR_SUFFIXES = (
    ".count",
    ".cycle",
    "count",
    "cycle",
)

EMBEDDING_CALL_SUFFIXES = (
    ".embeddings.create",
    "embeddings.create",
)


_DICT_READS = frozenset(
    {"copy", "get", "items", "keys", "values", "__contains__", "__getitem__"}
)
_UNBOUNDED = ast.Constant(value=None)
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


@dataclass(frozen=True)
class _ClientBounds:
    has_token_limit: bool
    has_timeout: bool


class _LLMConsumptionChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.aliases: dict[str, str] = {}
        self._symbol_stack = ["<module>"]
        self._client_bounds_stack: list[dict[str, _ClientBounds]] = [{}]
        self._dicts_stack: list[dict[str, dict[str, ast.AST]]] = [{}]
        self._shared_stack: list[set[str]] = [set()]
        self._limit_defaults_stack: list[frozenset[str]] = [frozenset()]
        self._key_writes: set[int] = set()
        self._dict_reads: set[int] = set()
        self._dict_builtins: frozenset[int] = frozenset()
        self._silent = 0
        self._unbounded_loop_depth = 0
        self._emitted: set[tuple[int, int, str]] = set()

    def _current_symbol(self) -> str:
        if self._symbol_stack:
            return self._symbol_stack[-1]
        return "<module>"

    def _push_scope(self, node: ast.AST) -> None:
        self._client_bounds_stack.append({})
        self._push_dicts(node)

    def _pop_scope(self) -> None:
        if len(self._client_bounds_stack) > 1:
            self._client_bounds_stack.pop()
        self._pop_dicts()

    def _push_dicts(self, node: ast.AST) -> None:
        self._dicts_stack.append({})
        self._shared_stack.append(_names_in_nested_scopes(node))

    def _pop_dicts(self) -> None:
        if len(self._dicts_stack) > 1:
            self._dicts_stack.pop()
            self._shared_stack.pop()

    @property
    def _dicts(self) -> dict[str, dict[str, ast.AST]]:
        return self._dicts_stack[-1]

    def _snapshot(self) -> dict[str, dict[str, ast.AST]]:
        return _copy_dicts(self._dicts)

    def _restore(self, state: dict[str, dict[str, ast.AST]]) -> None:
        self._dicts_stack[-1] = state

    def _merge_branches(self, branches) -> None:
        open_states = [
            state for state, statements in branches if not _ends_flow(statements)
        ]
        if not open_states:
            open_states = [branches[0][0]]
        self._restore(_merge_dict_states(open_states))

    def _visit_statements(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self.visit(statement)

    def _track(self, name: str, entries: dict[str, ast.AST]) -> None:
        if name not in self._shared_stack[-1]:
            self._dicts[name] = entries

    def _mark_read(self, node: ast.AST) -> None:
        if isinstance(node, ast.Name) and node.id in self._dicts:
            self._dict_reads.add(id(node))

    def _literal_entries(self, node: ast.AST | None) -> dict[str, ast.AST] | None:
        if isinstance(node, ast.Dict):
            entries = {}
            for key, value in zip(node.keys, node.values):
                literal = _string_key(key)
                if literal is None:
                    return None
                entries[literal] = value
            return entries
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and id(node.func) in self._dict_builtins
            and not node.args
            and all(keyword.arg is not None for keyword in node.keywords)
        ):
            return {keyword.arg: keyword.value for keyword in node.keywords}
        return None

    def _claim_key_write(self, target: ast.AST) -> bool:
        if not (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)):
            return False
        if target.value.id not in self._dicts or _string_key(target.slice) is None:
            return False
        self._key_writes.add(id(target))
        return True

    def _write_key(self, target: ast.Subscript, value: ast.AST) -> None:
        entries = self._dicts.get(target.value.id)
        if entries is not None:
            entries[_string_key(target.slice)] = value

    def _update_entries(self, node: ast.Call) -> dict[str, ast.AST] | None:
        if len(node.args) > 1:
            return None
        entries: dict[str, ast.AST] = {}
        if node.args:
            literal = self._literal_entries(node.args[0])
            if literal is None:
                return None
            entries.update(literal)
        for keyword in node.keywords:
            if keyword.arg is None:
                return None
            entries[keyword.arg] = keyword.value
        return entries

    def _is_modelled_method(self, node: ast.Call) -> bool:
        method = node.func.attr
        if method in _DICT_READS:
            return True
        if method == "clear":
            return not node.args and not node.keywords
        if method in ("pop", "setdefault"):
            return (
                1 <= len(node.args) <= 2
                and not node.keywords
                and _string_key(node.args[0]) is not None
            )
        if method == "update":
            return self._update_entries(node) is not None
        return False

    def _dict_method_owner(self, node: ast.Call) -> str | None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
            return None
        if func.value.id not in self._dicts or not self._is_modelled_method(node):
            return None
        self._dict_reads.add(id(func.value))
        return func.value.id

    def _apply_dict_method(self, node: ast.Call, name: str) -> None:
        entries = self._dicts.get(name)
        if entries is None:
            return
        method = node.func.attr
        if method == "clear":
            entries.clear()
        elif method == "pop":
            entries.pop(_string_key(node.args[0]), None)
        elif method == "setdefault":
            key = _string_key(node.args[0])
            if key not in entries:
                entries[key] = _UNBOUNDED
                if len(node.args) > 1:
                    entries[key] = node.args[1]
        elif method == "update":
            entries.update(self._update_entries(node))

    def _unpacked_entries(self, node: ast.Call) -> dict[str, ast.AST] | None:
        entries: dict[str, ast.AST] = {}
        for keyword in node.keywords:
            if keyword.arg is not None:
                continue
            found = self._literal_entries(keyword.value)
            if found is None and isinstance(keyword.value, ast.Name):
                found = self._dicts.get(keyword.value.id)
            if found is None:
                return None
            entries.update(found)
        return entries

    def _mark_client_bounds(self, name: str, bounds: _ClientBounds) -> None:
        self._client_bounds_stack[-1][name] = bounds

    def _client_bounds_for_name(self, name: str | None) -> _ClientBounds | None:
        if not name:
            return None
        for scope in reversed(self._client_bounds_stack):
            bounds = scope.get(name)
            if bounds:
                return bounds
        return None

    def generic_visit(self, node: ast.AST) -> None:
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def visit_Module(self, node: ast.Module) -> None:
        self._dict_builtins = builtin_references(node, {"dict"})
        self._shared_stack[0] = _names_in_nested_scopes(node)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local] = alias.name
            self._dicts.pop(local, None)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self._dicts.pop(alias.asname or alias.name, None)
        if node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                self.aliases[local] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._dicts.pop(node.name, None)
        self._symbol_stack.append(node.name)
        self._push_scope(node)
        self._limit_defaults_stack.append(_limit_defaults(node))
        self.generic_visit(node)
        self._limit_defaults_stack.pop()
        self._pop_scope()
        self._symbol_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._dicts.pop(node.name, None)
        self._symbol_stack.append(node.name)
        self._push_dicts(node)
        self.generic_visit(node)
        self._pop_dicts()
        self._symbol_stack.pop()

    def visit_Global(self, node: ast.Global | ast.Nonlocal) -> None:
        for name in node.names:
            self._shared_stack[-1].add(name)
            self._dicts.pop(name, None)

    visit_Nonlocal = visit_Global

    def visit_Name(self, node: ast.Name) -> None:
        if id(node) in self._dict_reads:
            self._dict_reads.discard(id(node))
            return
        self._dicts.pop(node.id, None)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.value, ast.Name) and node.value.id in self._dicts:
            self._dict_reads.add(id(node.value))
            if not isinstance(node.ctx, ast.Load) and id(node) not in self._key_writes:
                self._dicts.pop(node.value.id, None)
        self._key_writes.discard(id(node))
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        for operator, comparator in zip(node.ops, node.comparators):
            if isinstance(operator, (ast.In, ast.NotIn)):
                self._mark_read(comparator)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if key is None:
                self._mark_read(value)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        bounds = self._constructor_bounds(node.value)
        if bounds:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._mark_client_bounds(target.id, bounds)
        entries = None
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            entries = self._literal_entries(node.value)
        writes = []
        for target in node.targets:
            if self._claim_key_write(target):
                writes.append(target)
        self.generic_visit(node)
        if entries is not None:
            self._track(node.targets[0].id, entries)
        for target in writes:
            self._write_key(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        bounds = self._constructor_bounds(node.value)
        if bounds and isinstance(node.target, ast.Name):
            self._mark_client_bounds(node.target.id, bounds)
        entries = None
        if isinstance(node.target, ast.Name) and node.value is not None:
            entries = self._literal_entries(node.value)
        write = node.value is not None and self._claim_key_write(node.target)
        self.generic_visit(node)
        if entries is not None:
            self._track(node.target.id, entries)
        if write:
            self._write_key(node.target, node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        target = node.target
        merged = None
        if isinstance(target, ast.Name) and isinstance(node.op, ast.BitOr):
            current = self._dicts.get(target.id)
            added = self._literal_entries(node.value)
            if current is not None and added is not None:
                merged = {**current, **added}
        write = self._claim_key_write(target)
        self.generic_visit(node)
        if merged is not None:
            self._track(target.id, merged)
        if write:
            self._write_key(target, node.value)

    def visit_Delete(self, node: ast.Delete) -> None:
        removals = []
        for target in node.targets:
            if self._claim_key_write(target):
                removals.append(target)
        self.generic_visit(node)
        for target in removals:
            entries = self._dicts.get(target.value.id)
            if entries is not None:
                entries.pop(_string_key(target.slice), None)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        entry = self._snapshot()
        self._visit_statements(node.body)
        body_state = self._dicts
        self._restore(_copy_dicts(entry))
        self._visit_statements(node.orelse)
        else_state = self._dicts
        _carry_guarded_keys(
            node.test, body_state, else_state, self._limit_defaults_stack[-1]
        )
        self._merge_branches([(body_state, node.body), (else_state, node.orelse)])

    def visit_Try(self, node: ast.Try) -> None:
        entry = self._snapshot()
        self._visit_statements(node.body)
        body_state = self._dicts
        handler_entry = _merge_dict_states([entry, body_state])
        branches = []
        for handler in node.handlers:
            self._restore(_copy_dicts(handler_entry))
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                self._dicts.pop(handler.name, None)
            self._visit_statements(handler.body)
            branches.append((self._dicts, handler.body))
        self._restore(body_state)
        self._visit_statements(node.orelse)
        branches.append((self._dicts, [*node.body, *node.orelse]))
        self._merge_branches(branches)
        self._visit_statements(node.finalbody)

    visit_TryStar = visit_Try

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        entry = self._snapshot()
        branches = []
        exhaustive = False
        for case in node.cases:
            self._restore(_copy_dicts(entry))
            self.visit(case.pattern)
            for name in _pattern_names(case.pattern):
                self._dicts.pop(name, None)
            if case.guard is not None:
                self.visit(case.guard)
            self._visit_statements(case.body)
            branches.append((self._dicts, case.body))
            if case.guard is None and _irrefutable(case.pattern):
                exhaustive = True
        if not exhaustive:
            branches.append((_copy_dicts(entry), []))
        self._merge_branches(branches)

    def visit_While(self, node: ast.While) -> None:
        self._visit_loop_body(node, self._is_unbounded_while(node))

    def visit_For(self, node: ast.For) -> None:
        self._visit_loop_body(node, self._is_unbounded_for(node))

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop_body(node, self._is_unbounded_for(node))

    def visit_Call(self, node: ast.Call) -> None:
        call_name = qualified_name_from_call(node, self.aliases)
        for keyword in node.keywords:
            if keyword.arg is None:
                self._mark_read(keyword.value)
        method_owner = self._dict_method_owner(node)
        if self._is_llm_call(node, call_name):
            self._check_llm_call(node, call_name)
        if self._is_agent_executor_call(call_name):
            self._check_agent_executor(node)
        self.generic_visit(node)
        if method_owner is not None:
            self._apply_dict_method(node, method_owner)

    def _visit_loop_body(self, node: ast.For | ast.AsyncFor | ast.While, active: bool) -> None:
        self._silent += 1
        if isinstance(node, ast.While):
            self.visit(node.test)
        else:
            self.visit(node.iter)
            self.visit(node.target)
        self._silent -= 1
        if active:
            self._unbounded_loop_depth += 1
        entry = self._snapshot()
        if not self._silent:
            self._silent += 1
            self._visit_statements(node.body)
            self._silent -= 1
            self._restore(_merge_dict_states([entry, self._dicts]))
            entry = self._snapshot()
        self._visit_statements(node.body)
        self._restore(_merge_dict_states([entry, self._dicts]))
        if active:
            self._unbounded_loop_depth -= 1
        self._visit_statements(node.orelse)

    def _constructor_bounds(self, node: ast.AST | None) -> _ClientBounds | None:
        if not isinstance(node, ast.Call):
            return None
        call_name = qualified_name_from_call(node, self.aliases)
        if not call_name:
            return None
        if call_name not in LLM_CLIENT_CONSTRUCTORS:
            return None
        return _ClientBounds(
            has_token_limit=_has_bound_keyword(node, TOKEN_LIMIT_KEYWORDS),
            has_timeout=_has_bound_keyword(node, TIMEOUT_KEYWORDS),
        )

    def _is_llm_call(self, node: ast.Call, call_name: str | None) -> bool:
        if not call_name:
            return False
        if call_name in DIRECT_LLM_CALLS:
            return True

        root = root_name(node.func)
        if self._client_bounds_for_name(root) and call_name.endswith(
            LLM_CLIENT_CALL_SUFFIXES
        ):
            return True

        if call_name.endswith(LLM_CLIENT_CALL_SUFFIXES):
            qual_root = call_name.split(".", 1)[0]
            return qual_root in {
                "anthropic",
                "bedrock",
                "chain",
                "cohere",
                "genai",
                "llm",
                "openai",
            }

        return False

    def _check_llm_call(self, node: ast.Call, call_name: str | None) -> None:
        issues: list[str] = []
        client_bounds = self._bounds_for_call(node)
        unpacked = self._unpacked_entries(node)

        if self._unbounded_loop_depth > 0:
            issues.append("call runs inside an obvious unbounded loop")
        token_bounded = _has_bound_entry(unpacked or {}, TOKEN_LIMIT_KEYWORDS)
        timeout_bounded = _has_bound_entry(unpacked or {}, TIMEOUT_KEYWORDS)
        if unpacked is None:
            token_bounded = not _disables(node, TOKEN_LIMIT_KEYWORDS)
            timeout_bounded = not _disables(node, TIMEOUT_KEYWORDS)
        if self._needs_token_limit(node, call_name, client_bounds) and not token_bounded:
            issues.append("no max token limit")
        if self._needs_timeout(node, client_bounds) and not timeout_bounded:
            issues.append("no request timeout")

        if issues:
            self._append_finding(node, issues)

    def _bounds_for_call(self, node: ast.Call) -> _ClientBounds | None:
        root = root_name(node.func)
        return self._client_bounds_for_name(root)

    def _needs_token_limit(
        self,
        node: ast.Call,
        call_name: str | None,
        client_bounds: _ClientBounds | None,
    ) -> bool:
        if self._is_embedding_call(call_name):
            return False
        if _has_bound_keyword(node, TOKEN_LIMIT_KEYWORDS):
            return False
        if client_bounds and client_bounds.has_token_limit:
            return False
        return True

    def _needs_timeout(
        self,
        node: ast.Call,
        client_bounds: _ClientBounds | None,
    ) -> bool:
        if _has_bound_keyword(node, TIMEOUT_KEYWORDS):
            return False
        if client_bounds and client_bounds.has_timeout:
            return False
        return True

    def _is_embedding_call(self, call_name: str | None) -> bool:
        if not call_name:
            return False
        return any(call_name.endswith(suffix) for suffix in EMBEDDING_CALL_SUFFIXES)

    def _is_agent_executor_call(self, call_name: str | None) -> bool:
        if not call_name:
            return False
        return any(call_name.endswith(suffix) for suffix in AGENT_EXECUTOR_SUFFIXES)

    def _check_agent_executor(self, node: ast.Call) -> None:
        if _has_bound_keyword(node, AGENT_ITERATION_KEYWORDS):
            return
        self._append_finding(node, ["agent executor has no iteration or time cap"])

    def _is_unbounded_while(self, node: ast.While) -> bool:
        return _truthy_constant(node.test)

    def _is_unbounded_for(self, node: ast.For | ast.AsyncFor) -> bool:
        if not isinstance(node.iter, ast.Call):
            return False
        call_name = qualified_name_from_call(node.iter, self.aliases)
        if not call_name:
            return False
        if any(call_name.endswith(suffix) for suffix in INFINITE_ITERATOR_SUFFIXES):
            return True
        return self._is_unbounded_repeat(node.iter, call_name)

    def _is_unbounded_repeat(self, node: ast.Call, call_name: str) -> bool:
        if not call_name.endswith(("itertools.repeat", "repeat")):
            return False
        if len(node.args) >= 2:
            return False
        for keyword in node.keywords:
            if keyword.arg == "times":
                return False
        return True

    def _append_finding(self, node: ast.Call, issues: list[str]) -> None:
        if self._silent:
            return
        line = int(getattr(node, "lineno", 1) or 1)
        col = int(getattr(node, "col_offset", 0) or 0)
        detail = "; ".join(issues)
        key = (line, col, detail)
        if key in self._emitted:
            return
        self._emitted.add(key)
        self.findings.append(
            {
                "rule_id": "SKY-D267",
                "severity": "MEDIUM",
                "message": (
                    f"Unbounded LLM consumption risk: {detail}. "
                    "Set token, timeout, and iteration limits before invoking the model."
                ),
                "file": str(self.file_path),
                "line": line,
                "col": col,
                "symbol": self._current_symbol(),
                "metadata": {"llm_unbounded_consumption": True},
            }
        )


def _has_bound_keyword(node: ast.Call, names: set[str]) -> bool:
    for keyword in node.keywords:
        if keyword.arg not in names:
            continue
        if _is_unbounded_value(keyword.value):
            continue
        return True
    return False


def _has_bound_entry(entries: dict[str, ast.AST], names: set[str]) -> bool:
    return any(
        key in names and not _is_unbounded_value(value) for key, value in entries.items()
    )


def _string_key(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _names_in_nested_scopes(scope: ast.AST) -> set[str]:
    shared: set[str] = set()
    for node in _own_scope_nodes(scope):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            shared.update(node.names)
        elif isinstance(node, _SCOPE_NODES):
            shared |= _free_names(node)
    return shared


def _own_scope_nodes(scope: ast.AST):
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, _SCOPE_NODES):
            pending.extend(ast.iter_child_nodes(node))


def _free_names(scope: ast.AST) -> set[str]:
    bound: set[str] = set()
    used: set[str] = set()
    nested: set[str] = set()
    declared: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        for argument in (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
            scope.args.vararg,
            scope.args.kwarg,
        ):
            if argument is not None:
                bound.add(argument.arg)
    for node in _own_scope_nodes(scope):
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                used.add(node.id)
            else:
                bound.add(node.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            declared.update(node.names)
        elif isinstance(node, _SCOPE_NODES):
            nested |= _free_names(node)
            if not isinstance(node, ast.Lambda):
                bound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
    if isinstance(scope, ast.ClassDef):
        return (used - bound) | nested | declared
    return ((used | nested) - bound) | declared


def _copy_dicts(state: dict[str, dict[str, ast.AST]]) -> dict[str, dict[str, ast.AST]]:
    return {name: dict(entries) for name, entries in state.items()}


def _merge_dict_states(states) -> dict[str, dict[str, ast.AST]]:
    merged = {}
    for name in set(states[0]).intersection(*states[1:]):
        tables = [state[name] for state in states]
        shared = set(tables[0]).intersection(*tables[1:])
        merged[name] = {
            key: _merged_value([table[key] for table in tables]) for key in shared
        }
    return merged


def _merged_value(values: list[ast.AST]) -> ast.AST:
    for value in values:
        if _is_unbounded_value(value):
            return value
    return values[0]


def _ends_flow(statements: list[ast.stmt]) -> bool:
    return bool(statements) and isinstance(statements[-1], (ast.Return, ast.Raise))


def _guards(test: ast.AST, value: ast.AST) -> bool:
    if not isinstance(value, ast.Name):
        return False
    if isinstance(test, ast.Name):
        return test.id == value.id
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == value.id
        and len(test.ops) == 1
        and isinstance(test.ops[0], (ast.IsNot, ast.NotEq))
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is None
    )


def _carry_guarded_keys(test, body_state, else_state, limit_defaults) -> None:
    for name, entries in body_state.items():
        other = else_state.get(name)
        if other is None:
            continue
        for key, value in entries.items():
            if key in other or not _guards(test, value):
                continue
            if value.id in limit_defaults:
                other[key] = value


def _limit_defaults(function: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    pairs = list(zip(positional[len(positional) - len(args.defaults):], args.defaults))
    pairs.extend(
        (argument, default)
        for argument, default in zip(args.kwonlyargs, args.kw_defaults)
        if default is not None
    )
    rebound = {
        node.id
        for statement in function.body
        for node in ast.walk(statement)
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load)
    }
    return frozenset(
        argument.arg
        for argument, default in pairs
        if isinstance(default, ast.Constant)
        and type(default.value) in (int, float)
        and default.value > 0
        and argument.arg not in rebound
    )


def _disables(node: ast.Call, names: set[str]) -> bool:
    return any(
        keyword.arg in names and _is_unbounded_value(keyword.value)
        for keyword in node.keywords
    )


def _pattern_names(pattern: ast.AST) -> list[str]:
    names = []
    for node in ast.walk(pattern):
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.append(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.append(node.rest)
    return names


def _irrefutable(pattern: ast.AST) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None
    if isinstance(pattern, ast.MatchOr):
        return any(_irrefutable(option) for option in pattern.patterns)
    return False


def _is_unbounded_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is None or node.value is False
    return False


def _truthy_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return bool(node.value)
    return False


def scan(tree, file_path, findings):
    try:
        checker = _LLMConsumptionChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(
            f"LLM consumption analysis failed for {file_path}: {e}",
            file=sys.stderr,
        )

