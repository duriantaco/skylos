"""A reused dangerous-call rule must not retain another module's aliases."""

import ast

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule


def test_reusing_rule_does_not_retain_module_aliases():
    rule = DangerousCallsRule()
    safe = LinterVisitor([rule], "safe.py")
    safe.visit(ast.parse("from json import loads as eval\neval('{}')\n"))
    assert not safe.findings

    unsafe = LinterVisitor([rule], "unsafe.py")
    unsafe.visit(ast.parse("def route(text):\n    return eval(text)\n"))
    assert [(f["rule_id"], f["file"], f["line"]) for f in unsafe.findings] == [
        ("SKY-D201", "unsafe.py", 2)
    ]
