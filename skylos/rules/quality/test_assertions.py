"""Conservative checks for literal assertion and test-body placeholders."""

from __future__ import annotations

import ast

from skylos.done.inventory import _constant_truth
from skylos.rules.quality._test_quality_support import TestQualityRule
from skylos.rules.quality._test_subjects import scope_nodes


_LITERAL_EXPRESSION_NODES = (
    ast.Constant,
    ast.Tuple,
    ast.List,
    ast.Load,
    ast.UnaryOp,
    ast.Not,
    ast.UAdd,
    ast.USub,
    ast.BoolOp,
    ast.And,
    ast.Or,
    ast.BinOp,
    ast.Add,
    ast.Sub,
    ast.Compare,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.Is,
    ast.IsNot,
    ast.In,
    ast.NotIn,
)


def _literal_condition(node: ast.AST) -> bool:
    # Never infer truth from runtime names, overloaded comparisons or calls.
    # Bound the input to the existing small constant-expression evaluator.
    for position, child in enumerate(ast.walk(node)):
        if position >= 128 or not isinstance(child, _LITERAL_EXPRESSION_NODES):
            return False
    return _constant_truth(node) is True


class ConstantTestAssertionRule(TestQualityRule):
    rule_id = "SKY-L040"
    name = "Constant Test Assertion"

    def check(self, subject, context):
        findings = []
        for node in scope_nodes(subject.node):
            if (
                not isinstance(node, ast.Assert)
                or id(node) in subject.dead_nodes
                or not _literal_condition(node.test)
            ):
                continue
            findings.append(
                self._finding(
                    node,
                    context,
                    subject=subject,
                    pattern="constant_true_assertion",
                    message=(
                        "This assertion has a literal-only condition that is "
                        "always true, so it cannot check a failure. Replace it "
                        "with a check of the behavior this test exercises."
                    ),
                    evidence={
                        "constant_truth": True,
                        "expression_kind": type(node.test).__name__,
                        "proof": "literal-only constant expression",
                        "review_action": "Check an observed result or behavior.",
                    },
                )
            )
        return findings


def _has_input_parameters(subject) -> bool:
    arguments = subject.node.args
    positional = [*arguments.posonlyargs, *arguments.args]
    # The selector names only directly declared class methods as Class.method;
    # static/classmethod decorators and unknown wrappers are not selected.
    if subject.framework == "unittest" or "." in subject.name:
        positional = positional[1:]  # A bound instance is not fixture input.
    return bool(
        positional
        or arguments.kwonlyargs
        or arguments.vararg is not None
        or arguments.kwarg is not None
    )


def _only_placeholders(function) -> bool:
    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return all(
        isinstance(statement, ast.Pass)
        or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is Ellipsis
        )
        for statement in body
    )


class EmptyTestRule(TestQualityRule):
    rule_id = "SKY-L041"
    name = "Empty Test"

    def check(self, subject, context):
        # Setup/asserting fixtures can supply the purpose of a pass-only test.
        if (
            getattr(subject, "fixture_backed", False)
            or _has_input_parameters(subject)
            or not _only_placeholders(subject.node)
        ):
            return []
        return [
            self._finding(
                subject.node,
                context,
                subject=subject,
                pattern="placeholder_test_body",
                message=(
                    "This collected test body contains only a docstring, pass "
                    "or ellipsis. Review whether fixtures or setup supply its "
                    "checks; otherwise implement the behavior named by this test."
                ),
                evidence={
                    "body_kind": "literal_placeholders_only",
                    "statement_count": len(subject.node.body),
                    "review_action": (
                        "Review fixture/setup checks; otherwise implement the "
                        "named behavior."
                    ),
                },
            )
        ]


__all__ = ["ConstantTestAssertionRule", "EmptyTestRule"]
