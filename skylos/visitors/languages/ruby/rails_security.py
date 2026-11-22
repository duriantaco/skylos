"""Bounded request flows in Rails controller instance methods."""

import re
from dataclasses import replace

from .security import TAINTED, UNKNOWN, CommandScan

# Once the slash following a literal authority is present, interpolating a path
# or query into this URL cannot change the host passed to Net::HTTP.
_FIXED_URL_ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]+(?::[0-9]+)?/")

_RULES = {
    "SKY-D211": (
        "CRITICAL",
        "CWE-89",
        "Rails request data forms SQL text. Use parameter binding.",
    ),
    "SKY-D216": (
        "CRITICAL",
        "CWE-918",
        "Rails request data selects an outbound destination. Restrict allowed destinations.",
    ),
}


class RailsScan(CommandScan):
    """Reuse the Ruby local assignment, interpolation and control-flow evaluator."""

    def __init__(self, core, coverage):
        self.core = core
        self.coverage = coverage
        self.findings = []
        self.provider_aliases = set()
        self.scope = None

    def ancestors(self, owner):
        pending = [owner]
        visited = set()
        while pending:
            name = pending.pop()
            if name in visited:
                continue
            visited.add(name)
            definition = self.core.classes.get(name)
            if definition:
                pending.extend(definition.base_classes)
        return visited

    def scan(self):
        for scope in self.core.scopes:
            if not scope.method or scope.singleton or scope.body is None:
                continue
            ancestors = self.ancestors(scope.owner)
            # ApplicationController normally lives in a different source file.
            if scope.owner not in self.core.rails_classes and not (
                "ApplicationController" in ancestors
                and "ApplicationController" not in self.core.classes
                and "ApplicationController" not in self.core.alias_bindings
            ):
                continue
            self.scope = scope
            self.overrides = {
                method
                for method in ("params", "request", "URI")
                if any(f"{owner}#{method}" in self.core.methods for owner in ancestors)
            }
            self.walk(scope.body, {name: UNKNOWN for name in scope.locals})
        return self.findings

    def walk(self, node, env):
        if node and node.type in {
            "class",
            "module",
            "method",
            "singleton_method",
            "singleton_class",
        }:
            return
        super().walk(node, env)

    def constant(self, node):
        if node is None or node.type not in {"constant", "scope_resolution"}:
            return ""
        spelling = self.text(node)
        if not spelling.startswith("::"):
            parts = spelling.split("::")
            owner = self.scope.owner
            while owner:
                for size in range(len(parts), 0, -1):
                    candidate = ".".join([owner, *parts[:size]])
                    if (
                        candidate in self.core.alias_bindings
                        and candidate not in self.core.class_aliases
                    ):
                        # A visible local binding with an unresolved value is
                        # not evidence for an identically named global API.
                        return ""
                    if (
                        candidate in self.core.classes
                        or candidate in self.core.class_aliases
                    ):
                        return self.core._expand_alias(".".join([owner, *parts]))
                owner = owner.rpartition(".")[0]
        return self.core._constant(node, self.scope)

    def external(self, name):
        # A local definition or reopened namespace may implement different APIs.
        parts = name.split(".")
        return bool(name) and all(
            ".".join(parts[:n]) not in self.core.classes
            and ".".join(parts[:n]) not in self.core.alias_bindings
            for n in range(1, len(parts) + 1)
        )

    def framework_accessor(self, node, name, env):
        return (
            node is not None
            and node.type == "identifier"
            and self.text(node) == name
            and name not in self.overrides
            and name not in env
        )

    def source_value(self, node, env):
        if node.type == "element_reference":
            receiver = node.child_by_field_name("object")
            if self.framework_accessor(receiver, "params", env):
                return TAINTED
            if (
                receiver
                and receiver.type == "call"
                and self.framework_accessor(
                    receiver.child_by_field_name("receiver"), "request", env
                )
                and self.text(receiver.child_by_field_name("method"))
                in {
                    "parameters",
                    "query_parameters",
                    "request_parameters",
                }
            ):
                return TAINTED
        if node.type == "call":
            method = self.text(node.child_by_field_name("method"))
            receiver = node.child_by_field_name("receiver")
            args = node.child_by_field_name("arguments")
            if (
                args
                and len(args.named_children) == 1
                and self.external("URI")
                and (
                    (
                        receiver is None
                        and method == "URI"
                        and "URI" not in self.overrides
                    )
                    or (self.constant(receiver) == "URI" and method == "parse")
                )
            ):
                value = self.value(args.named_children[0], env)
                # A URI object can resolve another URL with `+`. Only string
                # appends are guaranteed to leave a proven host in place.
                return replace(value, fixed_origin_string=False)
        return None

    def value(self, node, env):
        value = super().value(node, env)
        if node is not None and node.type == "string":
            prefix = value.literal
            if value.state == "tainted" and node.named_children:
                first = node.named_children[0]
                if first.type == "string_content":
                    prefix = self.text(first)
            if prefix and _FIXED_URL_ORIGIN.match(prefix):
                return replace(value, fixed_url_origin=True, fixed_origin_string=True)
        return value

    def active_record_model(self, receiver):
        name = self.constant(receiver)
        ancestors = self.ancestors(name)
        return self.external("ActiveRecord.Base") and (
            "ActiveRecord.Base" in ancestors
            or ("ApplicationRecord" in ancestors and self.external("ApplicationRecord"))
        )

    def sink(self, node):
        receiver = node.child_by_field_name("receiver")
        method = self.text(node.child_by_field_name("method"))
        name = self.constant(receiver)
        if (
            method in {"where", "find_by_sql"}
            and self.active_record_model(receiver)
            and not self.core._class_method_overridden(name, method)
        ):
            return "SKY-D211"
        if method in {"execute", "select_all"} and receiver and receiver.type == "call":
            owner = receiver.child_by_field_name("receiver")
            if (
                self.text(receiver.child_by_field_name("method")) == "connection"
                and self.active_record_model(owner)
                and not self.core._class_method_overridden(
                    self.constant(owner), "connection"
                )
            ):
                return "SKY-D211"
        if (
            name == "Net.HTTP"
            and self.external(name)
            and method in {"get", "get_response"}
        ):
            return "SKY-D216"
        if name == "URI" and self.external(name) and method == "open":
            return "SKY-D216"
        return None

    def inspect_operation(self, node, env):
        if node.type != "call":
            return
        args = node.child_by_field_name("arguments")
        if not args or not args.named_children:
            return
        rule = self.sink(node)
        if rule is None:
            return
        self.coverage["checked_sinks"] += 1
        argument = args.named_children[0]
        if rule == "SKY-D211" and argument.type in {"pair", "hash"}:
            return  # Active Record binds values in a hash condition.
        if rule == "SKY-D211" and argument.type == "array" and argument.named_children:
            argument = argument.named_children[0]  # Only the query template is SQL.
        value = self.value(argument, env)
        if value.state == "unknown":
            self.unknown(node, "unresolved Rails operation input")
            return
        if value.state != "tainted" or (rule == "SKY-D216" and value.fixed_url_origin):
            return
        severity, cwe, message = _RULES[rule]
        self.findings.append(
            {
                "rule_id": rule,
                "severity": severity,
                "cwe": cwe,
                "message": message,
                "file": self.core.file_path,
                "line": node.start_point[0] + 1,
                "col": node.start_point[1] + 1,
                "source": "Rails request parameters",
                "category": "danger",
                "metadata": {
                    "security_evidence": {
                        "evidence_kind": "bounded_ruby_source_flow",
                        "sources": ["Rails request parameters"],
                        "analysis_complete": False,
                    }
                },
            }
        )
