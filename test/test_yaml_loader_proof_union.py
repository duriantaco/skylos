"""Assignment and import-fallback loader proofs must coexist in one module."""

import ast

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


@pytest.mark.parametrize(
    ("rebinding", "expected_calls"),
    [
        ("", set()),
        ("FAST = yaml.UnsafeLoader\n", {"first"}),
    ],
    ids=["native", "assignment-rebound"],
)
@pytest.mark.parametrize(
    "reverse", [False, True], ids=["assignment-first", "import-first"]
)
def test_assignment_and_import_fallback_proofs_share_module_safely(
    tmp_path, reverse, rebinding, expected_calls
):
    calls = [
        "    first = yaml.load(data, Loader=FAST)\n",
        "    second = yaml.load(data, Loader=SafeLoader)\n",
    ]
    if reverse:
        calls.reverse()
    source = (
        "import yaml\n"
        "try:\n"
        "    from yaml import CSafeLoader as SafeLoader\n"
        "except ImportError:\n"
        "    from yaml import SafeLoader\n"
        "FAST = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)\n"
        + rebinding
        + "def parse(data):\n"
        + "".join(calls)
        + "    return first, second\n"
    )
    expected_lines = {
        line
        for line, text in enumerate(source.splitlines(), 1)
        if any(text.lstrip().startswith(name + " =") for name in expected_calls)
    }
    path = tmp_path / "loaders.py"
    path.write_text(source)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.visit(ast.parse(source))
    for findings in (scan_ctx(tmp_path, [path]), linter.findings):
        actual = [row for row in findings if row["rule_id"] == "SKY-D206"]
        assert {(row["line"], row["severity"]) for row in actual} == {
            (line, "HIGH") for line in expected_lines
        }
