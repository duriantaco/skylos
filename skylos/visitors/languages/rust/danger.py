from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from ._security_bindings import UNKNOWN, State, Value, joined, unwrap, use_bindings

_TAINT_NAME_RE = re.compile(
    r"(arg|cmd|command|dir|file|filename|input|name|path|payload|request|url|uri)", re.I
)
_FILE_PATH_ARGS = {
    "read": (0,),
    "read_to_string": (0,),
    "write": (0,),
    "copy": (0, 1),
    "remove_file": (0,),
    "remove_dir": (0,),
    "remove_dir_all": (0,),
    "rename": (0, 1),
    "File::open": (0,),
    "File::create": (0,),
    "File::create_new": (0,),
}
_FILESYSTEMS = ("std::fs::", "tokio::fs::", "async_std::fs::")
_PATH_TYPES = {"std::path::Path", "std::path::PathBuf"}
_PATH_CONSTRUCTORS = {
    f"{path}::{method}" for path in _PATH_TYPES for method in ("new", "from")
}
_SOURCES = {f"std::env::{name}" for name in ("args", "args_os", "var", "var_os")}
_SHELLS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}
_ITEMS = {
    "function_item",
    "struct_item",
    "enum_item",
    "trait_item",
    "type_item",
    "mod_item",
    "const_item",
    "static_item",
    "union_item",
    "macro_definition",
}
_PATH_READ_ONLY = {
    "starts_with",
    "ends_with",
    "is_absolute",
    "is_relative",
    "has_root",
    "exists",
    "is_file",
    "is_dir",
    "metadata",
    "symlink_metadata",
    "read_link",
    "display",
    "components",
    "iter",
    "parent",
    "ancestors",
    "extension",
    "file_stem",
    "as_os_str",
    "to_str",
    "to_string_lossy",
}


class _SecurityFlow:
    def __init__(self, root, file_path, source):
        self.root = root
        self.file = str(Path(file_path))
        self.source = source
        self.findings = []
        self.return_values = []

    def text(self, node):
        if node is None:
            return ""
        return self.source[node.start_byte : node.end_byte].decode("utf-8", "ignore")

    def field(self, node, name):
        return node.child_by_field_name(name) if node is not None else None

    def emit(self, rule, message, node, value):
        self.findings.append(
            {
                "rule_id": rule,
                "severity": "HIGH",
                "message": message,
                "file": self.file,
                "line": node.start_point[0] + 1,
                "col": node.start_point[1],
                "category": "danger",
                "metadata": {
                    "security_evidence": {
                        "evidence_kind": "bounded_rust_source_flow",
                        "sources": sorted(value.sources),
                        "analysis_complete": False,
                        "assumption": (
                            "Parameter-name evidence is conditional; external input "
                            "does not by itself establish exploitability."
                        ),
                    }
                },
            }
        )

    def declarations(self, node, state):
        # Rust items (including use declarations) apply throughout their scope.
        for child, _conditional in self.scope_statements(node):
            if child.type in _ITEMS:
                name = self.field(child, "name")
                if name is not None:
                    state.bind(self.text(name), UNKNOWN)
        bindings = {}
        for child, conditional, guards, complete_guards in self.scope_entries(node):
            if child.type == "use_declaration":
                for name, path in use_bindings(child, self.text):
                    api = state.resolve(path)
                    value = (
                        Value(guarded_api=(guards, api))
                        if conditional and guards and complete_guards and api
                        else UNKNOWN
                        if conditional
                        else Value(api=api)
                    )
                    bindings.setdefault(name, set()).add(value)
        for name, values in bindings.items():
            # Conflicting imports and local declarations cannot prove an API.
            if name in state.frames[-1] or len(values) != 1:
                state.bind(name, UNKNOWN)
            else:
                state.bind(name, next(iter(values)))

    def scope_statements(self, node):
        for child, conditional, _guards, _complete in self.scope_entries(node):
            yield child, conditional

    def cfg_key(self, node):
        """Compare exact cfg token trees; this does not evaluate features."""
        if node is None or node.has_error:
            return ()
        if node.type in {"line_comment", "block_comment"}:
            return ()
        if node.type in {"string_literal", "raw_string_literal"} or not node.children:
            return (self.text(node),)
        return tuple(part for child in node.children for part in self.cfg_key(child))

    def scope_entries(self, node):
        conditional = scope_conditional = False
        guards = scope_guards = frozenset()
        unsupported = scope_unsupported = False
        for child in node.named_children:
            if child.type in {"attribute_item", "inner_attribute_item"}:
                attribute = next(
                    (part for part in child.named_children if part.type == "attribute"),
                    None,
                )
                names = (
                    [
                        part
                        for part in attribute.named_children
                        if part.type not in {"line_comment", "block_comment"}
                    ]
                    if attribute is not None
                    else []
                )
                optional = bool(names and self.text(names[0]) in {"cfg", "cfg_attr"})
                cfg = bool(names and self.text(names[0]) == "cfg")
                key = self.cfg_key(names[1]) if cfg and len(names) == 2 else ()
                if child.type == "inner_attribute_item":
                    scope_conditional |= optional
                    if key:
                        scope_guards |= {key}
                    scope_unsupported |= optional and not key
                else:
                    conditional |= optional
                    if key:
                        guards |= {key}
                    unsupported |= optional and not key
                continue
            if child.type in {"line_comment", "block_comment"}:
                continue
            yield (
                child,
                conditional or scope_conditional,
                guards | scope_guards,
                not (unsupported or scope_unsupported),
            )
            conditional = False
            guards, unsupported = frozenset(), False

    def module(self, node, inherited=None):
        state = inherited.copy() if inherited is not None else State()
        state.frames.append({})
        self.declarations(node, state)
        for child, _conditional, guards, _complete in self.scope_entries(node):
            context = state.copy()
            context.conditions |= guards
            if child.type == "function_item":
                self.function(child, context)
            elif child.type in {"impl_item", "mod_item", "trait_item"}:
                body = self.field(child, "body")
                if body is not None:
                    self.module(body, context)

    def function(self, node, inherited):
        state = inherited.copy()
        state.frames.append({})
        type_params = self.field(node, "type_parameters")
        for param in type_params.named_children if type_params is not None else ():
            name = self.field(param, "name")
            if name is not None:
                state.bind(self.text(name), UNKNOWN)
        params = self.field(node, "parameters")
        for param in params.named_children if params is not None else ():
            pattern = self.field(param, "pattern")
            if pattern is None or pattern.type != "identifier":
                continue
            name = self.text(pattern)
            sources = (
                frozenset({f"parameter:{name}"})
                if _TAINT_NAME_RE.search(name)
                else frozenset()
            )
            type_node = self.field(param, "type")
            while type_node is not None and type_node.type in {
                "reference_type",
                "generic_type",
            }:
                type_node = self.field(type_node, "type")
            api = state.resolve(self.text(type_node))
            kind = "path" if api in _PATH_TYPES else None
            state.bind(name, Value(sources=sources, kind=kind))
        self.return_values.append([])
        try:
            self.block(self.field(node, "body"), state)
        finally:
            self.return_values.pop()

    def bind_pattern(self, node, value, state):
        if node is None:
            return
        if node.type in {"identifier", "shorthand_field_identifier"}:
            state.bind(self.text(node), value)
            return
        for index, child in enumerate(node.children):
            if child.is_named and node.field_name_for_child(index) not in {
                "type",
                "condition",
                "name",
            }:
                self.bind_pattern(child, value, state)

    def block(self, node, state):
        if node is None:
            return UNKNOWN, True
        state.frames.append({})
        self.declarations(node, state)
        value, continuing = UNKNOWN, True
        for child, conditional, guards, _complete in self.scope_entries(node):
            if not continuing:
                break
            before = state.copy() if conditional else None
            prior_conditions = state.conditions
            state.conditions |= guards
            value, continuing = self.statement(child, state)
            state.conditions = prior_conditions
            if before is not None:
                if continuing:
                    for index, frame in enumerate(state.frames):
                        for name, after in frame.items():
                            prior = before.frames[index].get(name, before.get(name))
                            frame[name] = joined([prior, after])
                else:
                    state.frames = before.frames
                # The statement can be absent in another feature selection.
                value, continuing = joined([UNKNOWN, value]), True
        state.frames.pop()
        return value, continuing

    def statement(self, node, state):
        if node is None:
            return UNKNOWN, True
        kind = node.type
        if kind == "expression_statement":
            children = node.named_children
            return self.statement(children[0], state) if children else (UNKNOWN, True)
        if kind == "let_declaration":
            value = self.expression(self.field(node, "value"), state)
            pattern = self.field(node, "pattern")
            self.bind_pattern(pattern, value, state)
            return value, True
        if kind == "assignment_expression":
            value = self.expression(self.field(node, "right"), state)
            left = self.field(node, "left")
            if left is not None and left.type == "identifier":
                state.assign(self.text(left), value)
            return value, True
        if kind == "return_expression":
            value = joined(
                self.expression(child, state) for child in node.named_children
            )
            if self.return_values:
                self.return_values[-1].append(value)
            return value, False
        if kind == "block":
            return self.block(node, state)
        if kind == "if_expression":
            return self.branch(node, state)
        if kind == "match_expression":
            return self.match(node, state)
        if kind in {"while_expression", "for_expression", "loop_expression"}:
            before, branch = state.copy(), state.copy()
            self.expression(self.field(node, "condition"), branch)
            value = self.expression(self.field(node, "value"), branch)
            branch.frames.append({})
            self.bind_pattern(
                self.field(node, "pattern"),
                replace(
                    value,
                    kind=None,
                    api=None,
                    canonical=False,
                    contained=False,
                ),
                branch,
            )
            self.block(self.field(node, "body"), branch)
            branch.frames.pop()
            state.merge([before, branch])
            return UNKNOWN, True
        if kind == "function_item":
            self.function(node, state)
            return UNKNOWN, True
        if kind in _ITEMS or kind == "use_declaration":
            return UNKNOWN, True
        return self.expression(node, state), True

    def branch(self, node, state):
        condition = self.field(node, "condition")
        self.expression(condition, state)
        alternatives, values = [], []
        for truth, body in [
            (True, self.field(node, "consequence")),
            (False, self.field(node, "alternative")),
        ]:
            branch = state.copy()
            self.containment(condition, truth, branch)
            if body is not None and body.type == "else_clause":
                body = body.named_children[-1] if body.named_children else None
            value, continuing = (
                self.statement(body, branch) if body is not None else (UNKNOWN, True)
            )
            if continuing:
                alternatives.append(branch)
                values.append(value)
        if alternatives:
            state.merge(alternatives)
        return joined(values), bool(alternatives)

    def match(self, node, state):
        subject = self.expression(self.field(node, "value"), state)
        body = self.field(node, "body")
        alternatives, values = [], []
        for arm in body.named_children if body is not None else ():
            if arm.type != "match_arm":
                continue
            branch = state.copy()
            branch.frames.append({})
            pattern = self.field(arm, "pattern")
            self.bind_pattern(
                pattern,
                replace(
                    subject,
                    kind=None,
                    api=None,
                    canonical=False,
                    contained=False,
                ),
                branch,
            )
            self.expression(self.field(pattern, "condition"), branch)
            value, continuing = self.statement(self.field(arm, "value"), branch)
            branch.frames.pop()
            if continuing:
                alternatives.append(branch)
                values.append(value)
        if alternatives:
            state.merge(alternatives)
        return joined(values), bool(alternatives)

    def invalidate_path(self, node, state):
        # Invalidating at the escape point also covers a subsequently stored
        # mutable view, without pretending to model Rust's complete alias graph.
        if node is None:
            return
        if node.type == "identifier":
            old = state.get(self.text(node))
            if old.kind == "path":
                state.assign(
                    self.text(node),
                    replace(
                        old,
                        sources=old.sources | {"unknown mutable path operation"},
                        canonical=False,
                        contained=False,
                    ),
                )
        elif node.type == "call_expression":
            callee = self.field(node, "function")
            if callee is not None and callee.type == "field_expression":
                self.invalidate_path(self.field(callee, "value"), state)
        elif node.type in {"reference_expression", "parenthesized_expression"}:
            child = self.field(node, "value") or next(iter(node.named_children), None)
            self.invalidate_path(child, state)

    def containment(self, node, truth, state):
        if node is None:
            return
        if node.type == "unary_expression" and self.text(node).lstrip().startswith("!"):
            self.containment(node.named_children[-1], not truth, state)
            return
        callee = self.field(node, "function")
        if (
            not truth
            or node.type != "call_expression"
            or callee is None
            or callee.type != "field_expression"
        ):
            return
        receiver = self.field(callee, "value")
        arguments = self.field(node, "arguments")
        args = list(arguments.named_children) if arguments is not None else []
        if (
            self.text(self.field(callee, "field")) != "starts_with"
            or receiver.type != "identifier"
            or len(args) != 1
        ):
            return
        value = state.get(self.text(receiver))
        root = self.expression(args[0], state)
        if (
            value.kind == root.kind == "path"
            and value.canonical
            and root.canonical
            and not root.sources
            and root.literal is not None
        ):
            state.assign(self.text(receiver), replace(value, contained=True))

    def expression(self, node, state):
        if node is None:
            return UNKNOWN
        kind = node.type
        if kind == "identifier":
            return state.get(self.text(node))
        if kind == "scoped_identifier":
            return Value(api=state.resolve(self.text(node)))
        if kind in {"string_literal", "raw_string_literal"}:
            text = self.text(node)
            first, last = text.find('"'), text.rfind('"')
            return Value(kind="string", literal=text[first + 1 : last])
        if kind in {
            "reference_expression",
            "parenthesized_expression",
            "try_expression",
        }:
            child = self.field(node, "value") or next(iter(node.named_children), None)
            if kind == "reference_expression" and any(
                part.type == "mutable_specifier" for part in node.named_children
            ):
                self.invalidate_path(child, state)
            value = self.expression(child, state)
            return unwrap(value) if kind == "try_expression" else value
        if kind in {
            "block",
            "if_expression",
            "match_expression",
            "assignment_expression",
        }:
            return self.statement(node, state)[0]
        if kind == "array_expression":
            items = tuple(
                self.expression(child, state) for child in node.named_children
            )
            return replace(joined(items), items=items)
        if kind == "closure_expression":
            # A definition is not execution. Captured values remain available
            # for checking its body, but writes cannot alter the outer state.
            closure = state.copy()
            closure.frames.append({})
            params = self.field(node, "parameters")
            for param in params.named_children if params is not None else ():
                pattern = self.field(param, "pattern") or param
                self.bind_pattern(pattern, UNKNOWN, closure)
            body = self.field(node, "body")
            self.return_values.append([])
            try:
                tail, _continuing = self.statement(body, closure)
                if body is not None and body.type == "block":
                    statements = [
                        child for child, _conditional in self.scope_statements(body)
                    ]
                    last = statements[-1] if statements else None
                    if (
                        last is None
                        or last.type == "let_declaration"
                        or last.type in _ITEMS
                        or last.type == "use_declaration"
                        or (last.children and last.children[-1].type == ";")
                    ):
                        tail = UNKNOWN
                returned = joined([tail, *self.return_values[-1]])
            finally:
                self.return_values.pop()
            # A bounded source summary is not a path restriction, provider
            # identity, or authorization to apply the closure's writes outside.
            return Value(kind="closure", return_sources=returned.sources)
        if kind == "call_expression":
            return self.call(node, state)
        if kind == "macro_invocation":
            value = joined(
                self.expression(child, state) for child in node.named_children
            )
            api = state.resolve(self.text(self.field(node, "macro")))
            tokens = next(
                (c for c in node.named_children if c.type == "token_tree"), None
            )
            if api in {"std::format", "std::format_args"} and tokens is not None:
                parts = tokens.named_children
                if parts and parts[0].type in {"string_literal", "raw_string_literal"}:
                    template = self.expression(parts[0], state).literal or ""
                    captures, index = [], 0
                    while index < len(template):
                        if template[index : index + 2] == "{{":
                            index += 2
                        elif template[index] == "{":
                            end = template.find("}", index + 1)
                            if end < 0:
                                break
                            name = template[index + 1 : end].split(":", 1)[0]
                            if name.isidentifier():
                                captures.append(state.get(name))
                            index = end + 1
                        else:
                            index += 1
                    value = joined([value, *captures])
            return replace(value, kind=None, api=None, canonical=False, contained=False)
        # Unknown transformations retain inputs; no helper spelling is a proof.
        return replace(
            joined(self.expression(child, state) for child in node.named_children),
            kind=None,
            api=None,
            literal=None,
            canonical=False,
            contained=False,
        )

    def call(self, node, state):
        callee = self.field(node, "function")
        args_node = self.field(node, "arguments")
        arg_nodes = list(args_node.named_children) if args_node is not None else []
        if callee is not None and callee.type == "field_expression":
            receiver_node = self.field(callee, "value")
            receiver = self.expression(receiver_node, state)
            args = [self.expression(arg, state) for arg in arg_nodes]
            method = self.text(self.field(callee, "field"))
            return self.method(node, receiver_node, receiver, method, args, state)
        callable_value = self.expression(callee, state)
        args = [self.expression(arg, state) for arg in arg_nodes]
        combined = joined(args)
        if callable_value.return_sources:
            combined = joined([combined, Value(sources=callable_value.return_sources)])
        api = state.resolve(self.text(callee))
        if api in _SOURCES:
            return Value(sources=frozenset({api}), kind="result_string")
        if api == "std::process::Command::new":
            executable = args[0] if args else UNKNOWN
            if executable.sources:
                self.emit(
                    "SKY-D212",
                    "Potentially untrusted input selects the process "
                    "executable; validate or allowlist it.",
                    node,
                    executable,
                )
            return replace(
                executable, kind="command", shell=executable.literal in _SHELLS
            )
        filesystem = next(
            (prefix for prefix in _FILESYSTEMS if api and api.startswith(prefix)), None
        )
        if filesystem:
            operation = api[len(filesystem) :]
            if filesystem == "async_std::fs::" and operation == "File::create_new":
                operation = ""  # Not part of async-std's File API.
            for index in _FILE_PATH_ARGS.get(operation, ()):
                if index < len(args) and args[index].tainted:
                    self.emit(
                        "SKY-D215",
                        "Potentially untrusted path reaches a filesystem "
                        "operation without a proven path restriction.",
                        node,
                        args[index],
                    )
            if filesystem == "std::fs::" and operation == "canonicalize":
                return replace(
                    combined, kind="result_path", canonical=True, contained=False
                )
        if api in _PATH_CONSTRUCTORS:
            return replace(combined, kind="path", canonical=False)
        if api == "std::string::String::from":
            return replace(combined, kind="string")
        # Unknown calls may mutate a borrowed path after its guard.
        for argument in arg_nodes:
            if argument.type == "reference_expression" and any(
                child.type == "mutable_specifier" for child in argument.named_children
            ):
                target = self.field(argument, "value")
                if target is not None and target.type == "identifier":
                    old = state.get(self.text(target))
                    state.assign(
                        self.text(target),
                        replace(
                            old,
                            sources=old.sources | {"unknown mutable borrow"},
                            canonical=False,
                            contained=False,
                        ),
                    )
        return replace(
            combined,
            kind=None,
            api=None,
            literal=None,
            canonical=False,
            contained=False,
        )

    def method(self, node, receiver_node, receiver, name, args, state):
        combined = joined([receiver, *args])
        if (
            name in {"unwrap", "expect"}
            and receiver.kind
            and receiver.kind.startswith(("result_", "option_"))
        ):
            return unwrap(receiver)
        if receiver.kind == "path":
            if name == "file_name" and not args:
                return Value(
                    sources=receiver.sources, kind="option_basename", contained=True
                )
            if name == "canonicalize" and not args:
                return replace(
                    receiver, kind="result_path", canonical=True, contained=False
                )
            if name in {"join", "with_file_name", "with_extension"}:
                restricted = not receiver.sources and all(
                    not value.sources or (value.kind == "basename" and value.contained)
                    for value in args
                )
                return replace(
                    combined, kind="path", canonical=False, contained=restricted
                )
            if name in {"push", "set_file_name", "set_extension"}:
                if args and args[0].tainted:
                    self.emit(
                        "SKY-D215",
                        "Potentially untrusted input modifies a filesystem "
                        "path without a proven path restriction.",
                        node,
                        args[0],
                    )
                restricted = not receiver.sources and all(
                    not value.sources or (value.kind == "basename" and value.contained)
                    for value in args
                )
                changed = replace(
                    combined, kind="path", canonical=False, contained=restricted
                )
                if receiver_node.type == "identifier":
                    state.assign(self.text(receiver_node), changed)
                return changed
            if name in {"as_path", "to_path_buf", "clone"} and not args:
                return receiver
            if name not in _PATH_READ_ONLY:
                self.invalidate_path(receiver_node, state)
        if receiver.kind == "command":
            if name in {"arg", "args"}:
                values = [
                    item
                    for value in args
                    for item in (
                        value.items or (replace(value, kind="unknown_args"),)
                        if name == "args"
                        else (value,)
                    )
                ]
                history = (*receiver.items, *values)
                switch = receiver.shell_switch or any(
                    value.literal in {"-c", "/C", "-Command"} for value in values
                )
                changed = replace(
                    combined,
                    kind="command",
                    shell=receiver.shell,
                    shell_switch=switch,
                    literal=receiver.literal,
                    items=history,
                )
                if receiver_node.type == "identifier":
                    state.assign(self.text(receiver_node), changed)
                payload = self.shell_payload(changed)
                previous_payload = self.shell_payload(receiver)
                if payload.sources and payload.sources != previous_payload.sources:
                    self.emit(
                        "SKY-D212",
                        "Potentially untrusted input reaches a shell command argument.",
                        node,
                        payload,
                    )
                return changed
            if name in {"spawn", "output", "status"}:
                return UNKNOWN
        if (
            receiver.kind in {"string", "basename"}
            and name in {"as_str", "to_string", "to_owned", "clone"}
            and not args
        ):
            return receiver
        return replace(
            combined,
            kind=None,
            api=None,
            literal=None,
            canonical=False,
            contained=False,
        )

    @staticmethod
    def shell_payload(command):
        if not command.shell:
            return UNKNOWN
        for index, value in enumerate(command.items):
            if value.literal in {"-c", "/C", "-Command"}:
                rest = command.items[index + 1 :]
                if command.literal in {"cmd", "cmd.exe", "powershell", "pwsh"}:
                    return joined(rest)
                return rest[0] if rest else UNKNOWN
            if value.kind == "unknown_args" and value.sources:
                # An unresolved argument sequence may include both the switch
                # and its payload; it cannot establish a fixed command slot.
                return value
        return UNKNOWN


def scan_danger(root_node, file_path: str, source: bytes) -> list[dict]:
    if root_node is None:
        return []
    flow = _SecurityFlow(root_node, file_path, source)
    flow.module(root_node)
    return _dedupe_findings(flow.findings)


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for finding in findings:
        key = (finding["rule_id"], finding["file"], finding["line"])
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
