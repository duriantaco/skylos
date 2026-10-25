"""Focused advice is a reversible presentation choice for every human report."""

from copy import deepcopy
from io import StringIO

import pytest
from rich.console import Console

from skylos.cli import _skylos_console_theme
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.llm_report import _generate_llm_report
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import render_pretty_results


def _finding(rule, **changes):
    result = {
        "rule_id": rule,
        "severity": "HIGH",
        "file": "app.py",
        "line": 8,
        "name": "app.process",
        "type": "function",
        "value": 22,
        "threshold": 10,
        "message": f"Original {rule} advice",
        "evidence": {"source": rule},
    }
    result.update(changes)
    return result


def _signature():
    return _finding(
        "SKY-L029",
        line=18,
        name="app.configure.enabled",
        value="enabled",
        message=(
            "Boolean parameter 'enabled' permits positional calls, which can obscure "
            "their meaning. Prefer named calls; consider keyword-only arguments when "
            "the public or callback contract permits it."
        ),
    )


def _architecture(rule):
    return _finding(
        rule,
        file="module.py",
        line=1,
        name="module",
        type="module",
        scope="file",
        advisory=True,
        message=f"Optional architecture {rule}",
    )


def _assessment():
    return {
        "risk": {"status": "high", "finding_count": 2},
        "maintainability": {
            "status": "measured",
            "advice_count": 8,
            "rule_count": 7,
            "affected_files": 3,
        },
        "coverage": {"status": "complete"},
    }


def _render(kind, result, root, *, expand=False, all_advice=False):
    if kind == "llm":
        return _generate_llm_report(
            result, root, expand_advice=expand, all_advice=all_advice
        )
    output = StringIO()
    console = Console(
        file=output,
        width=400,
        color_system=None,
        theme=_skylos_console_theme(),
    )
    options = {
        "root_path": root,
        "expand_advice": expand,
        "all_advice": all_advice,
    }
    if kind == "pretty":
        render_pretty_results(console, result, **options)
    else:
        render_results(
            console, result, tree=kind == "tree", copy_badge=False, **options
        )
    return output.getvalue()


@pytest.fixture
def result(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    write_text_no_symlink(tests / "test_sample.py", "def test_sample():\n    pass\n")
    architecture = [_architecture("SKY-Q802"), _architecture("SKY-Q803")]
    return {
        "analysis_summary": {"total_files": 3},
        "quality": [
            _finding("SKY-Q301"),
            _finding("SKY-Q306"),
            _finding("SKY-C304"),
            _signature(),
            _finding(
                "SKY-L029",
                line=20,
                name="app.configure.enabled",
                value="enabled",
                message="Observed positional Boolean call with an unclear argument",
            ),
            _finding(
                "SKY-Q302", file="tests/test_sample.py", line=1, name="test_sample"
            ),
            _finding("SKY-L001", file="tests/test_sample.py", message="Defect remains"),
        ],
        "architecture_metrics": {
            "advisories": [
                {"module": "module", "file": "module.py", "signals": architecture}
            ],
            "advisory_count": 1,
            "advisory_signal_count": 2,
        },
        "custom_rules": [
            {
                **_signature(),
                "file": "tests/test_sample.py",
                "message": "Custom review remains",
            }
        ],
        "assessment": _assessment(),
        "gate": {"passed": False, "reasons": ["Raw quality count exceeds limit"]},
    }


@pytest.mark.parametrize("kind", ["rich", "pretty", "tree", "llm"])
@pytest.mark.parametrize("expand", [False, True])
@pytest.mark.parametrize("all_advice", [False, True])
def test_focus_selection_matches_expanded_and_grouped_views(
    kind, expand, all_advice, result, tmp_path
):
    before = deepcopy(result)

    text = _render(kind, result, tmp_path, expand=expand, all_advice=all_advice)
    normalized = " ".join(text.split())

    assert result == before
    assert "1 defect · 1 review" in normalized
    assert "Defect remains" in text and "Custom review remains" in text
    assert "SKY-Q301" in text and "SKY-Q306" in text and "SKY-C304" in text
    assert "FAIL · configured policy blocked this scan" in normalized
    assert "8 advice findings · 7 rules checked · 3 affected files" in normalized
    if all_advice:
        assert "5 advice entries (8 findings)" in normalized
        assert "SKY-Q802" in text and "SKY-Q803" in text and "SKY-Q302" in text
        assert "optional advice findings" not in text
        if expand:
            assert "permits positional calls" in text
    else:
        # The agreeing function metrics are listed; Boolean traps, test-only
        # nesting and architecture scores are measured and counted.
        assert "1 advice entry (3 findings)" in normalized
        assert "5 further advice findings measured, not listed" in normalized
        assert "--all-advice" in text
        assert "SKY-Q802" not in text and "SKY-Q803" not in text
        assert "SKY-Q302" not in text
        assert "permits positional calls" not in text
        assert "Observed positional Boolean call" not in text
        assert "Assessment includes all analyzed findings" in normalized


@pytest.mark.parametrize("kind", ["rich", "pretty", "tree", "llm"])
def test_all_optional_still_reports_recovery_and_raw_gate(kind, tmp_path):
    result = {
        "analysis_summary": {"total_files": 1},
        "quality": [_signature()],
        "assessment": _assessment(),
        "gate": {"passed": False},
    }
    before = deepcopy(result)

    text = _render(kind, result, tmp_path)
    normalized = " ".join(text.split())

    assert "1 optional advice finding" in normalized
    assert "--all-advice" in text
    assert "FAIL · configured policy blocked this scan" in normalized
    assert "Assessment includes all analyzed findings" in normalized
    assert "SKY-L029" not in text
    if kind in {"pretty", "llm"}:
        assert "No findings to display." in normalized
    assert result == before


@pytest.mark.parametrize("kind", ["rich", "pretty", "llm"])
def test_advice_priority_is_capped_while_raw_severity_is_retained(kind, tmp_path):
    result = {"quality": [_finding("SKY-C303")]}

    text = _render(kind, result, tmp_path, all_advice=True)

    assert "Advice priority" in text
    assert "MEDIUM" in text
    assert result["quality"][0]["severity"] == "HIGH"
    assert result["quality"][0]["severity"] == "HIGH"


@pytest.mark.parametrize("kind", ["rich", "pretty", "tree", "llm"])
@pytest.mark.parametrize(
    "rules, family",
    [
        (["SKY-Q301", "SKY-Q306"], "Function complexity"),
        (
            ["SKY-Q301", "SKY-Q306", "SKY-C304", "SKY-Q302", "SKY-L028"],
            "Function maintainability",
        ),
        (["SKY-Q802", "SKY-Q803"], "Module architecture"),
    ],
)
def test_expanded_metric_titles_use_the_actual_family(kind, rules, family, tmp_path):
    rows = [
        _architecture(rule) if rule.startswith("SKY-Q80") else _finding(rule)
        for rule in rules
    ]
    result = {"quality": rows}
    before = deepcopy(result)

    text = _render(kind, result, tmp_path, expand=True, all_advice=True)

    assert family in text
    for rule in rules:
        assert rule in text
    if family != "Function complexity":
        assert "Function complexity" not in text
    assert result == before


def test_llm_defaults_do_not_modify_unannotated_dead_code(tmp_path):
    result = {"unused_functions": [{"name": "unused", "file": "app.py", "line": 1}]}
    before = deepcopy(result)

    text = _render("llm", result, tmp_path)

    assert "Unused function 'unused'" in text
    assert '"finding_type": "review"' in text
    assert result == before
