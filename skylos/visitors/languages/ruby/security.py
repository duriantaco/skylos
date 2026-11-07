"""Explicit Kernel command sinks with local, syntax-aware data evidence.

Only direct ARGV/STDIN flow is a demonstrated source in this first slice.
Unresolved providers, argument shapes, and dynamic selectors are disclosed as
unknown; the absence of a finding is not a safety assertion for those cases.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import descendants


@dataclass(frozen=True)
class Value:
    state: str = "unknown"
    literal: str | None = None
    truthy: bool | None = None


UNKNOWN = Value()
TAINTED = Value("tainted")
LITERAL = Value("literal")
SHELLS = {
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/bash",
}


class CommandScan:
    def __init__(self, core):
        self.core = core
        self.findings = []
        self.coverage = {
            "status": "bounded",
            "supported_rules": ["SKY-D212"],
            "checked_sinks": 0,
            "unresolved": [],
            "unsupported_families": [
                "sql",
                "rails_request_flow",
                "interprocedural_command_flow",
            ],
        }
        self.seen = set()
        self.provider_aliases = set()
        self.source_shadowed = set()
        if core.root_node:
            for node in descendants(core.root_node):
                if node.type in {"assignment", "operator_assignment"}:
                    name = (
                        self.text(node.child_by_field_name("left"))
                        .removeprefix("::")
                        .split("::")[-1]
                    )
                    if name in {"ARGV", "STDIN", "$stdin"}:
                        self.source_shadowed.add(name)
        self.provider_uncertain = self._provider_uncertain()

    def text(self, node):
        return self.core.text(node)

    def _provider_uncertain(self):
        if any(
            set(n.split("."))
            & {"Kernel", "Object", "String", "Array", "IO", "BasicObject", "Module"}
            for n in self.core.classes
        ):
            return "visible Kernel provider override"
        if any(n.startswith("Kernel.") for n in self.core.methods):
            return "visible Kernel provider override"
        if self.core.raw_imports:
            return "loaded Ruby code may change Kernel provider"
        if self.core.root_node:
            for node in descendants(self.core.root_node):
                if node.type in {"assignment", "operator_assignment"}:
                    left = node.child_by_field_name("left")
                    if self.text(left).removeprefix("::").split("::")[-1] in {
                        "Kernel",
                        "Object",
                    }:
                        return "visible Kernel provider override"
                if node.type == "call":
                    method = self.text(node.child_by_field_name("method"))
                    if method in {
                        "require",
                        "require_relative",
                        "load",
                        "eval",
                        "class_eval",
                        "module_eval",
                        "const_set",
                        "define_singleton_method",
                    }:
                        return "loaded or dynamic Ruby code may change Kernel provider"
        return ""

    def unknown(self, node, reason):
        item = {"line": node.start_point[0] + 1, "reason": reason}
        if item not in self.coverage["unresolved"]:
            self.coverage["unresolved"].append(item)
        self.coverage["status"] = "partial"

    def value(self, node, env):
        if node is None:
            return UNKNOWN
        if node.type == "identifier":
            return env.get(self.text(node), UNKNOWN)
        if node.type in {"integer", "float", "true", "false", "nil", "simple_symbol"}:
            return Value("literal", truthy=node.type not in {"false", "nil"})
        if node.type == "string":
            literal = self.core.literal_string(node)
            if literal is not None:
                return Value("literal", literal, True)
            values = [
                self.value(n, env)
                for n in node.named_children
                if n.type == "interpolation"
            ]
            if any(v.state == "tainted" for v in values):
                return TAINTED
            return (
                LITERAL
                if values and all(v.state == "literal" for v in values)
                else UNKNOWN
            )
        if (
            node.type == "element_reference"
            and node.named_children
            and self.text(node.named_children[0]) in {"ARGV", "::ARGV"}
        ):
            return UNKNOWN if "ARGV" in self.source_shadowed else TAINTED
        if node.type == "call":
            receiver = node.child_by_field_name("receiver")
            method = self.text(node.child_by_field_name("method"))
            if self.text(receiver) in {"STDIN", "::STDIN", "$stdin"} and method in {
                "read",
                "gets",
                "readline",
            }:
                source_name = "$stdin" if self.text(receiver) == "$stdin" else "STDIN"
                return UNKNOWN if source_name in self.source_shadowed else TAINTED
            # These conversions preserve user control rather than sanitize it.
            if method in {"to_s", "strip", "chomp", "dup"}:
                return self.value(receiver, env)
            return UNKNOWN
        if node.type == "binary":
            operator = self.text(node.child_by_field_name("operator"))
            if operator in {"==", "!=", "===", "<", ">", "<=", ">=", "<=>", "=~", "!~"}:
                return LITERAL
            if operator not in {"+", "%"}:
                return UNKNOWN
        if node.type in {"interpolation", "parenthesized_statements", "binary"}:
            values = [self.value(n, env) for n in node.named_children]
            if any(v.state == "tainted" for v in values):
                return TAINTED
            return (
                LITERAL
                if values and all(v.state == "literal" for v in values)
                else UNKNOWN
            )
        return UNKNOWN

    def finding(self, node):
        line = node.start_point[0] + 1
        if line in self.seen:
            return
        self.seen.add(line)
        self.findings.append(
            {
                "rule_id": "SKY-D212",
                "severity": "CRITICAL",
                "message": "User-controlled ARGV or STDIN reaches a Ruby shell command or executable. Use a fixed executable with separate data arguments.",
                "file": self.core.file_path,
                "line": line,
                "col": node.start_point[1] + 1,
                "cwe": "CWE-78",
                "source": "ARGV/STDIN",
                "category": "danger",
                "metadata": {
                    "security_evidence": {
                        "evidence_kind": "bounded_ruby_source_flow",
                        "sources": ["ARGV/STDIN"],
                        "analysis_complete": False,
                        "assumption": "Local ARGV/STDIN flow establishes command control; no deployed exposure or full Ruby runtime behavior is inferred.",
                    }
                },
            }
        )

    def check_command(self, node, args, env):
        self.coverage["checked_sinks"] += 1
        if self.provider_uncertain:
            self.unknown(node, self.provider_uncertain)
            return
        if not args or any(
            n.type in {"splat_argument", "hash_splat_argument", "pair", "hash", "array"}
            for n in args
        ):
            self.unknown(node, "unresolved Ruby command argument shape")
            return
        values = [self.value(arg, env) for arg in args]
        if values[0].state == "tainted":
            self.finding(node)
            return
        if len(args) == 1:
            if values[0].state != "literal":
                self.unknown(node, "unresolved command-string input")
            return
        program = values[0].literal
        if program in SHELLS:
            # Require a literal shell command flag; flags assembled at runtime
            # stay unknown rather than being silently called safe.
            command_positions = [
                i + 1
                for i, value in enumerate(values[:-1])
                if value.literal in {"-c", "-lc", "-ic"}
            ]
            if not command_positions:
                if any(v.state != "literal" for v in values):
                    self.unknown(node, "unresolved shell argument semantics")
                return
            for position in command_positions:
                if values[position].state == "tainted":
                    self.finding(node)
                elif values[position].state != "literal":
                    self.unknown(node, "unresolved shell payload input")
            return
        if all(v.state == "literal" for v in values):
            return
        # A fixed printf format with separate data has no shell interpretation.
        # Other programs may have execution flags; do not call them safe here.
        if (
            program in {"printf", "/usr/bin/printf"}
            and len(values) >= 3
            and values[1].literal == "%s"
        ):
            return
        self.unknown(node, "external executable argument semantics are unsupported")

    def walk(self, node, env):
        if node is None:
            return
        if node.type in {"method", "singleton_method"}:
            body = node.child_by_field_name("body")
            self.walk(body, {})
            return
        if node.type in {"class", "module", "singleton_class"}:
            self.walk(node.child_by_field_name("body"), {})
            return
        if node.type in {"assignment", "operator_assignment"}:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            name = self.text(left)
            old = env.get(name, Value("literal", truthy=False))
            operator = self.text(node.child_by_field_name("operator"))
            if node.type == "operator_assignment" and (
                (operator == "||=" and old.truthy is True)
                or (operator == "&&=" and old.truthy is False)
            ):
                env[name] = old
                return
            self.walk(right, env)
            if left and left.type == "identifier":
                new = self.value(right, env)
                if node.type == "operator_assignment":
                    if operator in {"||=", "&&="}:
                        keep_old = (
                            old.truthy
                            if operator == "||="
                            else None
                            if old.truthy is None
                            else not old.truthy
                        )
                        if keep_old is True:
                            new = old
                        elif keep_old is None:
                            new = (
                                TAINTED
                                if "tainted" in {old.state, new.state}
                                else UNKNOWN
                            )
                    elif operator == "+=":
                        if "tainted" in {old.state, new.state}:
                            new = TAINTED
                        elif old.state == new.state == "literal":
                            new = Value("literal", truthy=True)
                        else:
                            new = UNKNOWN
                    else:
                        new = UNKNOWN
                env[name] = new
                if (
                    self.text(right) in {"Kernel", "::Kernel"}
                    or self.text(right) in self.provider_aliases
                ):
                    self.provider_aliases.add(self.text(left))
            return
        if node.type in {"if", "unless", "elsif"}:
            condition = node.child_by_field_name("condition")
            self.walk(condition, env)
            truthy = self.value(condition, env).truthy
            if truthy is not None:
                take_body = truthy if node.type != "unless" else not truthy
                self.walk(
                    node.child_by_field_name(
                        "consequence" if take_body else "alternative"
                    ),
                    env,
                )
                return
            consequence, alternative = dict(env), dict(env)
            self.walk(node.child_by_field_name("consequence"), consequence)
            self.walk(node.child_by_field_name("alternative"), alternative)
            self.merge(env, [consequence, alternative])
            return
        if node.type in {"if_modifier", "unless_modifier"}:
            condition = node.child_by_field_name("condition")
            self.walk(condition, env)
            truthy = self.value(condition, env).truthy
            if truthy is not None:
                if truthy == (node.type == "if_modifier"):
                    self.walk(node.child_by_field_name("body"), env)
                return
            branch = dict(env)
            self.walk(node.child_by_field_name("body"), branch)
            self.merge(env, [dict(env), branch])
            return
        if node.type == "binary":
            operator = self.text(node.child_by_field_name("operator"))
            if operator in {"&&", "and", "||", "or"}:
                left, right = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                )
                self.walk(left, env)
                truthy = self.value(left, env).truthy
                if truthy is None or truthy == (operator in {"&&", "and"}):
                    self.walk(right, env)
                return
        if node.type in {"block", "do_block"}:
            branch = dict(env)
            parameters = node.child_by_field_name("parameters")
            local_names = (
                {
                    self.text(n)
                    for n in descendants(parameters)
                    if n.type == "identifier"
                }
                if parameters
                else set()
            )
            for name in local_names:
                branch[name] = UNKNOWN
            self.walk(node.child_by_field_name("body"), branch)
            for name in set(env) | set(branch):
                if name not in local_names and env.get(name) != branch.get(name):
                    env[name] = UNKNOWN
            return
        if node.type in {"case", "while", "until", "for", "begin", "rescue"}:
            # These constructs need exception/loop order and cardinality proof.
            # Analyze direct sinks, but never use an uncertain write as proof
            # that a command after the compound statement is tainted or safe.
            branch = dict(env)
            self._walk_children(node, branch)
            written = {
                self.text(n.child_by_field_name("left"))
                for n in descendants(node)
                if n.type in {"assignment", "operator_assignment"}
            }
            for name in written:
                if name:
                    env[name] = UNKNOWN
            return
        if node.type == "subshell":
            self.coverage["checked_sinks"] += 1
            if self.provider_uncertain:
                self.unknown(node, self.provider_uncertain)
            else:
                values = [
                    self.value(child, env)
                    for child in node.named_children
                    if child.type == "interpolation"
                ]
                if any(v.state == "tainted" for v in values):
                    self.finding(node)
                elif any(v.state == "unknown" for v in values):
                    self.unknown(node, "unresolved backtick input")
        if node.type == "call":
            receiver = self.text(node.child_by_field_name("receiver"))
            method = self.text(node.child_by_field_name("method"))
            args = node.child_by_field_name("arguments")
            if receiver in {"Kernel", "::Kernel"}:
                if method in {"system", "exec", "spawn"}:
                    self.check_command(node, args.named_children if args else [], env)
                elif method in {
                    "send",
                    "public_send",
                    "__send__",
                    "method",
                    "public_method",
                }:
                    self.unknown(node, "dynamic Kernel selector is unsupported")
            elif receiver in self.provider_aliases and method in {
                "system",
                "exec",
                "spawn",
                "send",
                "public_send",
                "__send__",
                "method",
                "public_method",
            }:
                self.unknown(node, "Kernel provider alias is unsupported")
        self._walk_children(node, env)

    def _walk_children(self, node, env):
        for child in node.named_children:
            self.walk(child, env)

    def merge(self, env, branches):
        for name in set().union(*(set(branch) for branch in branches)):
            values = [branch.get(name, UNKNOWN) for branch in branches]
            if all(value == values[0] for value in values):
                env[name] = values[0]
            elif any(value.state == "tainted" for value in values):
                env[name] = TAINTED
            else:
                env[name] = UNKNOWN

    def scan(self):
        if self.core.root_node and not self.core.root_node.has_error:
            self.walk(self.core.root_node, {})
        return self.findings, self.coverage


def scan_commands(core):
    return CommandScan(core).scan()
