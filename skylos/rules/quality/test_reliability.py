"""Narrow test reliability review patterns, without running test code.

Repeated assertions need scalar-value proof, not just equal ASTs. A sleep is
reviewed only when it guesses when a locally created Event will be set. Neither
finding proves a failing test or authorizes an automatic rewrite.
"""

from __future__ import annotations

import ast
import math
import re
from pathlib import Path

from skylos.rules.danger.builtin_bindings import builtin_references
from skylos.rules.quality._import_bindings import import_bindings
from skylos.rules.quality._test_quality_support import TestQualityRule
from skylos.rules.quality._test_subjects import scope_nodes
from skylos.rules.quality.slop import module_facts

_SCALARS = (str, bytes, int, float, complex, bool, type(None))
_COMPARISONS = (ast.Eq, ast.NotEq, ast.Is, ast.IsNot, ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_CLOCKS = {"monotonic", "monotonic_ns", "perf_counter", "perf_counter_ns", "time"}
_TIMING_WORDS = {
    "backoff",
    "debounce",
    "delay",
    "duration",
    "elapsed",
    "interval",
    "latency",
    "sleep",
    "throttle",
    "time",
    "timeout",
    "timer",
    "timing",
}


def _blocks(subject):
    for node in scope_nodes(subject.node):
        for _field, values in ast.iter_fields(node):
            if (
                isinstance(values, list)
                and values
                and all(isinstance(value, ast.stmt) for value in values)
            ):
                yield values


def _facts(context):
    module = context["_test_quality_module"]
    cached = context.get("_test_reliability_facts")
    if cached is None or cached[0] is not module:
        facts = module_facts(module, context)
        lengths = builtin_references(module, frozenset({"len"}))
        changed = set()
        for node in facts.nodes(ast.Attribute, ast.Subscript):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                owner = node
                members = []
                while isinstance(owner, ast.Attribute):
                    members.append(owner.attr)
                    owner = owner.value
                if isinstance(owner, ast.Subscript):
                    key = owner.slice
                    owner = owner.value
                    if isinstance(owner, ast.Attribute) and owner.attr == "__dict__":
                        members.append(
                            key.value
                            if isinstance(key, ast.Constant)
                            and isinstance(key.value, str)
                            else "*"
                        )
                        owner = owner.value
                    elif (
                        isinstance(owner, ast.Attribute)
                        and owner.attr == "modules"
                        and isinstance(key, ast.Constant)
                        and key.value in {"time", "threading"}
                    ):
                        changed.add((key.value, "*"))
                binding = (
                    facts.imports.get(owner.id) if isinstance(owner, ast.Name) else None
                )
                if binding:
                    changed.add(
                        (
                            binding.module,
                            binding.member or members[-1] if members else "*",
                        )
                    )
        for call in facts.nodes(ast.Call):
            for arg in call.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    for module_name, member in (
                        ("time", "sleep"),
                        ("threading", "Event"),
                        ("builtins", "len"),
                    ):
                        if (
                            arg.value == f"{module_name}.{member}"
                            or arg.value.startswith(f"{module_name}.{member}.")
                        ):
                            changed.add((module_name, member))
            if len(call.args) > 1 and isinstance(call.args[0], ast.Name):
                binding = facts.imports.get(call.args[0].id)
                member = call.args[1]
                if (
                    binding
                    and isinstance(member, ast.Constant)
                    and isinstance(member.value, str)
                ):
                    changed.add((binding.module, binding.member or member.value))
        # Passing a module namespace elsewhere can hide an attribute mutation.
        for node in facts.nodes(ast.Name):
            binding = facts.imports.get(node.id)
            if binding is None:
                continue
            parent = facts.parent(node)
            if binding.module == "threading" and binding.member == "Event":
                if (
                    isinstance(parent, ast.Assign)
                    and parent.value is node
                    or isinstance(parent, ast.Call)
                    and node in parent.args
                    or isinstance(parent, ast.keyword)
                    and parent.value is node
                ):
                    changed.add(("threading", "Event"))
            if binding.member is not None:
                continue
            if not (isinstance(parent, ast.Attribute) and parent.value is node):
                changed.add((binding.module, "*"))
        if ("builtins", "len") in changed or ("builtins", "*") in changed:
            lengths = frozenset()
        cached = (module, facts, lengths, changed)
        context["_test_reliability_facts"] = cached
    return cached[1:]


def _stdlib_callable(node, module, member, context):
    facts, _lengths, changed = _facts(context)
    if (module, member) in changed or (module, "*") in changed:
        return False
    if isinstance(node, ast.Name):
        name = node.id
        from_import = True
    elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.attr != member:
            return False
        name = node.value.id
        from_import = False
    else:
        return False
    binding = facts.imports.get(name)
    if binding is None or binding.level or binding.module != module:
        return False
    if binding.member != (member if from_import else None):
        return False
    if any(name in facts.bound_in(scope) for scope in facts.enclosing_functions(node)):
        return False
    # threading, unlike the builtin time module, can be shadowed by a project file.
    if module == "threading":
        bases = set()
        if facts.filename:
            bases.add(Path(facts.filename).parent)
        if facts.project_root:
            bases.update((Path(facts.project_root), Path(facts.project_root) / "src"))
        try:
            if any(
                (base / "threading.py").exists()
                or (base / "threading" / "__init__.py").exists()
                for base in bases
            ):
                return False
        except (OSError, ValueError):
            return False
    return True


def _value_proof(node, values, depth=0):
    if depth > 12:
        return None
    if isinstance(node, ast.Constant) and type(node.value) in _SCALARS:
        return "builtin_literal"
    if isinstance(node, ast.Name):
        return values.get(node.id)
    if (
        isinstance(node, ast.Tuple)
        and len(node.elts) <= 16
        and all(_value_proof(value, values, depth + 1) for value in node.elts)
    ):
        return "immutable_tuple"
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        if isinstance(node.operand, ast.Constant) and type(node.operand.value) in (
            int,
            float,
            complex,
        ):
            return "builtin_literal"
    return None


def _safe_assertion(node, values, depth=0):
    if depth > 12:
        return False
    if isinstance(node, ast.Compare):
        return all(isinstance(op, _COMPARISONS) for op in node.ops) and all(
            _value_proof(value, values) for value in (node.left, *node.comparators)
        )
    if isinstance(node, ast.BoolOp):
        return all(_safe_assertion(value, values, depth + 1) for value in node.values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _safe_assertion(node.operand, values, depth + 1)
    return bool(_value_proof(node, values))


def _advance_values(statement, values, lengths):
    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
        value = statement.value
        proof = _value_proof(value, values)
        if isinstance(value, ast.Call):
            if (
                isinstance(value.func, ast.Name)
                and id(value.func) in lengths
                and len(value.args) == 1
                and not value.keywords
            ):
                proof = "builtin_len_result"
        if any(
            isinstance(node, (ast.Call, ast.NamedExpr, ast.Yield, ast.Await))
            for node in ast.walk(statement)
        ):
            values.clear()
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if any(not isinstance(target, ast.Name) for target in targets):
            values.clear()
            return
        for target in targets:
            if proof:
                values[target.id] = proof
            else:
                values.pop(target.id, None)
    elif not isinstance(statement, ast.Assert) or any(
        isinstance(node, (ast.Call, ast.NamedExpr, ast.Yield, ast.Await))
        for node in ast.walk(statement)
    ):
        values.clear()


class DuplicateTestAssertionRule(TestQualityRule):
    rule_id = "SKY-L042"
    name = "Duplicate test assertion"

    def check(self, subject, context):
        _facts_value, lengths, _changed = _facts(context)
        if any(
            isinstance(node, (ast.Global, ast.Nonlocal))
            for node in ast.walk(subject.node)
        ):
            return []
        findings = []
        for block in _blocks(subject):
            values = {}
            previous = None
            for statement in block:
                if id(statement) in subject.dead_nodes:
                    values.clear()
                    previous = None
                    continue
                if isinstance(statement, ast.Assert) and isinstance(
                    previous, ast.Assert
                ):
                    names = {
                        node.id
                        for node in ast.walk(statement.test)
                        if isinstance(node, ast.Name)
                    }
                    if (
                        names
                        and _safe_assertion(statement.test, values)
                        and ast.dump(previous, include_attributes=False)
                        == ast.dump(statement, include_attributes=False)
                    ):
                        findings.append(
                            self._finding(
                                statement,
                                context,
                                subject=subject,
                                pattern="adjacent_duplicate_assertion",
                                message="This assertion repeats the preceding check of unchanged builtin values; it adds no independent observation.",
                                evidence={
                                    "previous_assertion": {"line": previous.lineno},
                                    "value_proofs": {
                                        name: values[name] for name in sorted(names)
                                    },
                                },
                            )
                        )
                _advance_values(statement, values, lengths)
                previous = statement
        return findings


def _event_candidate(statement, subject, context):
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
    ):
        return None
    value = statement.value
    if (
        not isinstance(value, ast.Call)
        or value.args
        or value.keywords
        or not _stdlib_callable(value.func, "threading", "Event", context)
    ):
        return None
    name = statement.targets[0].id
    nodes = list(ast.walk(subject.node))
    if (
        sum(
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in nodes
        )
        != 1
    ):
        return None
    if any(
        isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names
        for node in nodes
    ):
        return None
    for node in nodes:
        if (
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Load)
        ):
            parent = _facts(context)[0].parent(node)
            if not (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and parent.attr != "__dict__"
            ):
                return None
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return None
        if (
            isinstance(node, ast.Call)
            and len(node.args) > 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == name
        ):
            return None
    return name


def _completion_event(test):
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], (ast.Is, ast.Eq))
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is True
    ):
        test = test.left
    if (
        isinstance(test, ast.Call)
        and not test.args
        and not test.keywords
        and isinstance(test.func, ast.Attribute)
        and test.func.attr == "is_set"
        and isinstance(test.func.value, ast.Name)
    ):
        return test.func.value.id
    return None


def _expects_failure(node, subject, context):
    facts = _facts(context)[0]
    parent = facts.parent(node)
    while parent is not None and parent is not subject.node:
        if isinstance(parent, (ast.With, ast.AsyncWith)):
            for item in parent.items:
                call = item.context_expr
                if isinstance(call, ast.Call):
                    func = call.func
                    name = (
                        func.attr
                        if isinstance(func, ast.Attribute)
                        else getattr(func, "id", None)
                    )
                    if name in {"raises", "assertRaises", "assertRaisesRegex"}:
                        return True
        parent = facts.parent(parent)
    return False


class SleepSynchronizationRule(TestQualityRule):
    rule_id = "SKY-L043"
    name = "Fixed sleep for test synchronization"

    def check(self, subject, context):
        name = re.sub(r"([a-z])([A-Z])", r"\1 \2", subject.name)
        words = set(re.findall(r"[a-z]+", name.lower()))
        if words & _TIMING_WORDS:
            return []
        local_clocks = {
            binding.name
            for node in scope_nodes(subject.node)
            for binding in import_bindings(node)
            if binding.module == "time"
            and binding.member in _CLOCKS
            and not binding.level
        }
        for node in scope_nodes(subject.node):
            if isinstance(node, ast.Call) and id(node) not in subject.dead_nodes:
                if isinstance(node.func, ast.Name) and node.func.id in local_clocks:
                    return []
                if any(
                    _stdlib_callable(node.func, "time", clock, context)
                    for clock in _CLOCKS
                ):
                    return []
        findings = []
        for block in _blocks(subject):
            events = {}
            for index, statement in enumerate(block[:-1]):
                if id(statement) in subject.dead_nodes:
                    continue
                candidate = _event_candidate(statement, subject, context)
                if candidate:
                    events[candidate] = statement.lineno
                if not isinstance(statement, ast.Expr) or not isinstance(
                    statement.value, ast.Call
                ):
                    continue
                call = statement.value
                if (
                    not _stdlib_callable(call.func, "time", "sleep", context)
                    or len(call.args) != 1
                    or call.keywords
                ):
                    continue
                delay = call.args[0]
                if (
                    not isinstance(delay, ast.Constant)
                    or type(delay.value) not in (int, float)
                    or delay.value <= 0
                ):
                    continue
                try:
                    if not math.isfinite(delay.value):
                        continue
                except OverflowError:
                    continue
                following = block[index + 1]
                if (
                    not isinstance(following, ast.Assert)
                    or id(following) in subject.dead_nodes
                ):
                    continue
                event = _completion_event(following.test)
                if event not in events or _expects_failure(call, subject, context):
                    continue
                findings.append(
                    self._finding(
                        call,
                        context,
                        subject=subject,
                        pattern="fixed_sleep_completion_check",
                        message="A fixed sleep guesses when this Event will complete. Review using an explicit bounded wait and checking its result.",
                        evidence={
                            "delay_seconds": delay.value,
                            "event": event,
                            "event_created": {"line": events[event]},
                            "completion_check": {"line": following.lineno},
                            "scope": "local threading.Event; runtime scheduling and external patches are not verified",
                        },
                    )
                )
        return findings
