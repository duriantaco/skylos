from __future__ import annotations

import ast
import re
import string
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from skylos.discover.integration import PromptInput
from skylos.discover.semantics.python_tool_flow import (
    assigned_names,
    dotted_name,
    expr_tags,
    function_params,
    module_sanitizers,
    propagate,
    scope_nodes,
)

_MAX_RESOLVE_DEPTH = 6

PROMPT_KEYWORDS = (
    "system",
    "user",
    "assistant",
    "prompt",
    "instruction",
    "context",
    "you are",
    "respond",
    "answer",
    "generate",
    "summarize",
    "translate",
    "analyze",
)

_NON_PROMPT_KWARGS = frozenset(
    {
        "model",
        "tools",
        "functions",
        "tool_choice",
        "function_call",
        "max_tokens",
        "max_output_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "top_k",
        "stream",
        "response_format",
        "n",
        "stop",
        "seed",
        "timeout",
        "extra_headers",
        "extra_body",
        "metadata",
        "user",
        "store",
        "parallel_tool_calls",
    }
)

_OPEN_TAG = re.compile(r"<([A-Za-z_][\w.-]*)(?:\s[^<>]*)?>$")
_OPEN_FENCE = re.compile(r"```[\w-]*$")

_FLASK_MODULES = ("flask", "quart")
_FLASK_REQUEST_ATTRS = {
    "json": "Flask JSON body",
    "form": "Flask form",
    "args": "Flask query params",
    "data": "Flask raw data",
    "files": "Flask file upload",
}
_FLASK_REQUEST_CALLS = {
    "get_json": "Flask JSON body",
    "get_data": "Flask raw data",
}


@dataclass
class PromptParamInput:
    integration: Any
    filepath: str
    function: str
    param: str
    index: int
    prompt_line: int
    delimited: bool
    linkable: bool = True


def _is_prompt_text(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in PROMPT_KEYWORDS)


def _slot_delimited(before: str, after: str) -> bool:
    before = before.rstrip()
    after = after.lstrip()
    tag = _OPEN_TAG.search(before)
    if tag and after.startswith(f"</{tag.group(1)}>"):
        return True
    if _OPEN_FENCE.search(before) and after.startswith("```"):
        return True
    for opening, closing in (('"""', '"""'), ("'''", "'''"), ("[INST]", "[/INST]")):
        if before.endswith(opening) and after.startswith(closing):
            return True
    return False


class _PromptScope:
    def __init__(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        module_body: list[ast.stmt],
        sanitizers: frozenset[str],
    ):
        self.func_node = func_node
        self.sanitizers = sanitizers
        self.body = func_node.body
        self.module_body = module_body
        positional, keyword_only, vararg, kwarg = function_params(func_node)
        if positional and positional[0] in ("self", "cls"):
            positional = positional[1:]
        self.positional = positional
        self.params = list(positional) + list(keyword_only)
        if vararg:
            self.params.append(vararg)
        if kwarg:
            self.params.append(kwarg)
        self.env = propagate(
            self.body,
            {name: frozenset({name}) for name in self.params},
            None,
            sanitizers,
        )
        self.local_names = assigned_names(self.body)

    def index_of(self, name: str) -> int:
        if name in self.positional:
            return self.positional.index(name)
        return -1

    def assigned_values(self, name: str) -> list[ast.AST]:
        values: list[ast.AST] = []
        for node in scope_nodes(self.body):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == name:
                        values.append(node.value)
            elif (
                isinstance(node, (ast.AnnAssign, ast.AugAssign))
                and isinstance(node.target, ast.Name)
                and node.target.id == name
                and node.value is not None
            ):
                values.append(node.value)
        return values

    def template(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if not isinstance(node, ast.Name):
            return None
        values = self.assigned_values(node.id)
        if not values and node.id not in self.local_names:
            values = _module_values(self.module_body, node.id)
        if len(values) != 1:
            return None
        value = values[0]
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
        return None

    def params_of(self, node: ast.AST) -> frozenset[str]:
        return expr_tags(node, self.env, {}, self.sanitizers) & frozenset(self.params)


def _module_values(body: list[ast.stmt], name: str) -> list[ast.AST]:
    values: list[ast.AST] = []
    for node in body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    values.append(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
            and node.value is not None
        ):
            values.append(node.value)
    return values


def _format_slots(template: str, call: ast.Call) -> list[tuple[ast.AST, str, str]]:
    slots: list[tuple[ast.AST, str, str]] = []
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError:
        return slots
    keywords = {kw.arg: kw.value for kw in call.keywords if kw.arg}
    auto_index = 0
    for position, (_literal, field_name, _spec, _conversion) in enumerate(parsed):
        if field_name is None:
            continue
        before = "".join(part[0] for part in parsed[: position + 1])
        after = ""
        if position + 1 < len(parsed):
            after = "".join(part[0] for part in parsed[position + 1 :])
        key = re.split(r"[.\[]", field_name, maxsplit=1)[0]
        value: ast.AST | None = None
        if key == "":
            if auto_index < len(call.args):
                value = call.args[auto_index]
            auto_index += 1
        elif key.isdigit():
            if int(key) < len(call.args):
                value = call.args[int(key)]
        else:
            value = keywords.get(key)
        if value is not None:
            slots.append((value, before, after))
    return slots


def _flatten_add(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _string_part(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _interpolations(
    node: ast.AST, scope: _PromptScope, chained: set[int]
) -> list[tuple[ast.AST, bool, int]] | None:
    if isinstance(node, ast.JoinedStr):
        texts = [
            str(value.value) for value in node.values if isinstance(value, ast.Constant)
        ]
        if not _is_prompt_text(" ".join(texts)):
            return None
        result = []
        for position, value in enumerate(node.values):
            if not isinstance(value, ast.FormattedValue):
                continue
            before = ""
            after = ""
            if position > 0 and isinstance(node.values[position - 1], ast.Constant):
                before = str(node.values[position - 1].value)
            if position + 1 < len(node.values) and isinstance(
                node.values[position + 1], ast.Constant
            ):
                after = str(node.values[position + 1].value)
            result.append((value.value, _slot_delimited(before, after), node.lineno))
        return result
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        template = scope.template(node.func.value)
        if template is None or not _is_prompt_text(template):
            return None
        return [
            (value, _slot_delimited(before, after), node.lineno)
            for value, before, after in _format_slots(template, node)
        ]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if id(node) in chained:
            return None
        operands = _flatten_add(node)
        for child in ast.walk(node):
            if isinstance(child, ast.BinOp):
                chained.add(id(child))
        texts = [_string_part(operand) for operand in operands]
        static = [text for text in texts if text is not None]
        if not static or not _is_prompt_text(" ".join(static)):
            return None
        result = []
        for position, operand in enumerate(operands):
            if texts[position] is not None:
                continue
            before = ""
            after = ""
            if position > 0 and texts[position - 1] is not None:
                before = texts[position - 1]
            if position + 1 < len(operands) and texts[position + 1] is not None:
                after = texts[position + 1]
            result.append((operand, _slot_delimited(before, after), node.lineno))
        return result
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        template = scope.template(node.left)
        if template is None or not _is_prompt_text(template):
            return None
        values: list[ast.AST] = [node.right]
        if isinstance(node.right, ast.Tuple):
            values = list(node.right.elts)
        elif isinstance(node.right, ast.Dict):
            values = list(node.right.values)
        return [(value, False, node.lineno) for value in values]
    return None


def find_prompt_param_inputs(
    call_node: ast.Call,
    func_node: ast.AST | None,
    module: ast.Module,
    sanitizers: frozenset[str] | None = None,
) -> list[tuple[str, int, int, bool]]:
    if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    if sanitizers is None:
        sanitizers = module_sanitizers(module)
    scope = _PromptScope(func_node, module.body, sanitizers)
    if not scope.params:
        return []
    pending: list[tuple[ast.AST, int]] = [(arg, 0) for arg in call_node.args]
    pending.extend(
        (keyword.value, 0)
        for keyword in call_node.keywords
        if keyword.arg not in _NON_PROMPT_KWARGS
    )
    seen_names: set[str] = set()
    chained: set[int] = set()
    found: dict[tuple[str, int], bool] = {}
    while pending:
        expression, depth = pending.pop(0)
        for node in ast.walk(expression):
            if isinstance(node, ast.Lambda):
                continue
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id not in seen_names
                and depth < _MAX_RESOLVE_DEPTH
            ):
                seen_names.add(node.id)
                for value in scope.assigned_values(node.id):
                    pending.append((value, depth + 1))
                continue
            slots = _interpolations(node, scope, chained)
            if not slots:
                continue
            for value, delimited, line in slots:
                for param in sorted(scope.params_of(value)):
                    key = (param, line)
                    found[key] = found.get(key, True) and delimited
    return [
        (param, scope.index_of(param), line, delimited)
        for (param, line), delimited in sorted(
            found.items(), key=lambda item: (item[0][1], item[0][0])
        )
    ]


def _module_names(rel: str) -> list[str]:
    parts = list(PurePosixPath(rel).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    names = []
    if parts:
        names.append(".".join(parts))
    if len(parts) > 1 and parts[0] == "src":
        names.append(".".join(parts[1:]))
    return names


def _package_parts(rel: str) -> list[str]:
    return list(PurePosixPath(rel).with_suffix("").parts)[:-1]


class _CallerFile:
    def __init__(self, rel: str, tree: ast.Module):
        self.rel = rel
        self.tree = tree
        self.sanitizers = module_sanitizers(tree)
        self.functions = {
            statement.name
            for statement in tree.body
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.symbols: dict[str, tuple[str, str]] = {}
        self.modules: dict[str, str] = {}
        self.flask_request: set[str] = set()
        self.sys_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "sys":
                        self.sys_names.add(alias.asname or "sys")
                    if alias.asname:
                        self.modules[alias.asname] = alias.name
                    else:
                        head = alias.name.split(".", 1)[0]
                        self.modules[head] = head
            elif isinstance(node, ast.ImportFrom):
                module = self._absolute(node)
                if not module:
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    self.symbols[local] = (module, alias.name)
                    self.modules[local] = f"{module}.{alias.name}"
                    if alias.name == "request" and module in _FLASK_MODULES:
                        self.flask_request.add(local)

    def _absolute(self, node: ast.ImportFrom) -> str:
        if node.level == 0:
            return node.module or ""
        package = _package_parts(self.rel)
        if node.level - 1 > len(package):
            return ""
        base = package[: len(package) - (node.level - 1)]
        if node.module:
            base = base + node.module.split(".")
        return ".".join(base)

    def own_modules(self) -> list[str]:
        return _module_names(self.rel)

    def callee(self, func: ast.AST, local_names: set[str]) -> list[tuple[str, str]]:
        if isinstance(func, ast.Name):
            if func.id in local_names:
                return []
            if func.id in self.symbols:
                return [self.symbols[func.id]]
            if func.id in self.functions:
                return [(module, func.id) for module in self.own_modules()]
            return []
        if isinstance(func, ast.Attribute):
            base = dotted_name(func.value)
            if not base:
                return []
            head, _, tail = base.partition(".")
            if head in local_names or head not in self.modules:
                return []
            module = self.modules[head]
            if tail:
                module = f"{module}.{tail}"
            return [(module, func.attr)]
        return []

    def source_seeds(self, statements: list[ast.stmt]) -> dict[int, frozenset[str]]:
        seeds: dict[int, frozenset[str]] = {}
        for node in scope_nodes(statements):
            label = self._source_label(node)
            if label:
                seeds[id(node)] = frozenset({f"{label} ({self.rel}:{node.lineno})"})
        return seeds

    def _source_label(self, node: ast.AST) -> str:
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in self.flask_request:
                return _FLASK_REQUEST_ATTRS.get(node.attr, "")
            if node.value.id in self.sys_names and node.attr == "argv":
                return "CLI arguments"
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id in self.flask_request
            ):
                return _FLASK_REQUEST_CALLS.get(func.attr, "")
            if (
                isinstance(func, ast.Name)
                and func.id == "input"
                and "input" not in self.functions
                and "input" not in self.symbols
            ):
                return "stdin"
        return ""


def _caller_scopes(tree: ast.Module):
    yield tree.body
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.body


def link_prompt_input_sources(
    files: list[tuple[str, ast.Module]],
    records: list[PromptParamInput],
) -> None:
    targets: dict[tuple[str, str], list[PromptParamInput]] = {}
    for record in records:
        if not record.linkable:
            continue
        for module in _module_names(record.filepath):
            targets.setdefault((module, record.function), []).append(record)
    proven: dict[int, list[str]] = {}
    if targets:
        for rel, tree in files:
            caller = _CallerFile(rel, tree)
            for statements in _caller_scopes(tree):
                _link_scope(caller, statements, targets, proven)
    for record in records:
        sources = proven.get(id(record)) or [""]
        for source in sources:
            record.integration.prompt_inputs.append(
                PromptInput(
                    source=source,
                    parameter=record.param,
                    prompt_location=f"{record.filepath}:{record.prompt_line}",
                    delimited=record.delimited,
                )
            )


def _link_scope(
    caller: _CallerFile,
    statements: list[ast.stmt],
    targets: dict[tuple[str, str], list[PromptParamInput]],
    proven: dict[int, list[str]],
) -> None:
    calls = [node for node in scope_nodes(statements) if isinstance(node, ast.Call)]
    if not calls:
        return
    local_names = assigned_names(statements)
    seeds = caller.source_seeds(statements)
    if not seeds:
        return
    env = propagate(statements, {}, seeds, caller.sanitizers)
    for call in calls:
        for key in caller.callee(call.func, local_names):
            for record in targets.get(key, []):
                argument = _argument_for(call, record)
                if argument is None:
                    continue
                tags = expr_tags(argument, env, seeds, caller.sanitizers)
                for source in sorted(tags):
                    bucket = proven.setdefault(id(record), [])
                    if source not in bucket:
                        bucket.append(source)


def _argument_for(call: ast.Call, record: PromptParamInput) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == record.param:
            return keyword.value
    if record.index < 0:
        return None
    for position, arg in enumerate(call.args):
        if isinstance(arg, ast.Starred):
            return None
        if position == record.index:
            return arg
    return None
