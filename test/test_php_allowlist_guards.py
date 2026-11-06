"""Only proved comparisons may erase a request source at an include sink."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.visitors.languages.php import scan_php_file


CASES = [
    ("strict_literals", "if (in_array($page, ['home.php', 'about.php'], true))", False),
    ("loose_true", "if (in_array($page, [true]))", True),
    ("explicit_loose", "if (in_array($page, [true], false))", True),
    ("dynamic_strict", "if (in_array($page, [true], $strict))", True),
    ("strict_true", "if (in_array($page, [true], true))", False),
    (
        "named_strict",
        "if (in_array(needle: $page, haystack: ['home.php'], strict: true))",
        False,
    ),
    ("tainted_list", "if (in_array($page, [$_GET['allowed']], true))", True),
    ("unknown_list", "if (in_array($page, $allowed, true))", True),
    (
        "local_literal_list",
        "$allowed = ['home.php']; if (in_array($page, $allowed, true))",
        False,
    ),
    (
        "list_reassigned",
        "$allowed = ['home.php']; $allowed = $_GET; if (in_array($page, $allowed, true))",
        True,
    ),
    (
        "list_append",
        "$allowed = ['home.php']; $allowed[] = $_GET['allowed']; if (in_array($page, $allowed, true))",
        True,
    ),
    (
        "list_push",
        "$allowed = ['home.php']; array_push($allowed, $_GET['allowed']); if (in_array($page, $allowed, true))",
        True,
    ),
    (
        "list_push_literal",
        "$allowed = ['home.php']; array_push($allowed, 'about.php'); if (in_array($page, $allowed, true))",
        False,
    ),
    (
        "list_branch",
        "$allowed = ['home.php']; if ($change) { $allowed = $_GET; } if (in_array($page, $allowed, true))",
        True,
    ),
]


def _source(guard):
    return (
        "<?php\n$page = $_GET['page'];\n"
        + guard
        + " {\n    include $page; // sink\n}\n"
    )


@pytest.mark.parametrize("name,guard,unsafe", CASES, ids=[row[0] for row in CASES])
def test_include_allowlist_guards(name, guard, unsafe, tmp_path):
    path = tmp_path / "app.php"
    path.write_text(_source(guard))
    findings = scan_php_file(str(path), {})[7]
    assert [(row["rule_id"], row["line"], row["severity"]) for row in findings] == (
        [("SKY-D255", 4, "CRITICAL")] if unsafe else []
    )


@pytest.mark.parametrize("unsafe", [False, True])
def test_include_comparison_survives_native_listing_and_gate(tmp_path, unsafe):
    guard = (
        "if (in_array($page, [true]))"
        if unsafe
        else "if (in_array($page, ['home.php'], true))"
    )
    (tmp_path / "app.php").write_text(_source(guard))
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert result["analysis_summary"]["languages"] == {"PHP": 1}
    assert result["analysis_summary"]["total_files"] == 1
    assert not result.get("analysis_errors")
    findings = result.get("danger", [])
    assert [(row["rule_id"], row["line"], row["severity"]) for row in findings] == (
        [("SKY-D255", 4, "CRITICAL")] if unsafe else []
    )
    assert all(row["listing"]["listed"] for row in findings)
    passed, _ = check_gate(result, {"gate": {"max_security": 0, "max_high": 0}})
    assert passed is not unsafe
