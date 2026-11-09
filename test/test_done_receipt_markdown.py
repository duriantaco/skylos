"""The markdown receipt (step summary and pull request comment) names the fix
for every failed check, as the text receipt does."""

from skylos.done.receipt import FIXES, render_markdown, render_text


def _check(check_id, status, summary, *, mode="block", findings=()):
    return {
        "id": check_id,
        "rule": None,
        "mode": mode,
        "status": status,
        "evidence": {"summary": summary},
        "findings": list(findings),
    }


def _receipt(*checks):
    return {
        "schema": "skylos.done-receipt/v1",
        "base": {"sha": "a" * 40, "source": "merge_base"},
        "head": {"sha": "b" * 40, "dirty": False},
        "verdict": "fail",
        "checks": list(checks),
        "unverified": [],
    }


def test_markdown_receipt_has_the_same_fix_lines_as_the_text_receipt():
    receipt = _receipt(
        _check(
            "tests_pass",
            "fail",
            "1 of 3 tests failed",
            findings=[
                {"rule": None, "file": "tests/test_a.py", "line": 7, "message": "test_a failed"}
            ],
        ),
        _check("gate_tampering", "fail", "pyproject.toml [tool.skylos] changed"),
        _check(
            "changed_lines_checked",
            "fail",
            "1 changed line no test checks",
            mode="advise",
            findings=[
                {
                    "rule": "SKY-A120",
                    "file": "app.py",
                    "line": 2,
                    "message": "No test runs app.py:2. Add a test that does.",
                }
            ],
        ),
        _check("secrets", "pass", "no secrets added"),
        _check("unknown_imports", "incomplete", "imports were not checked"),
    )
    expected = [FIXES["tests_pass"], FIXES["gate_tampering"], FIXES["changed_lines_checked"]]

    markdown = render_markdown(receipt)
    text = render_text(receipt)

    markdown_fixes = [
        line[len("- Fix: ") :] for line in markdown.splitlines() if line.startswith("- Fix: ")
    ]
    text_fixes = [
        line.strip()[len("Fix: ") :]
        for line in text.splitlines()
        if line.strip().startswith("Fix: ")
    ]
    assert markdown_fixes == expected
    assert text_fixes == expected
    assert "**Skylos settings and hooks left alone**" in markdown
    assert FIXES["secrets"] not in markdown
    assert FIXES["unknown_imports"] not in markdown
