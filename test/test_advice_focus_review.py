"""Adversarial review cases for focused advice provenance and category bounds."""

from copy import deepcopy

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.advice_display import advice_display, combine_advice
from skylos.reporting.advice_policy import optional_advice_reason, prepare_advice_view
from skylos.reporting.advice_scope import advice_source_context
from skylos.reporting.finding_types import summarize_finding_types


def _write(root, relative, source):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)
    return path


def _advice(path, **changes):
    return {
        "rule_id": "SKY-Q301",
        "file": str(path),
        "line": 1,
        "name": "payments.authorize",
        "simple_name": "authorize",
        "type": "function",
        "value": 25,
        "threshold": 10,
        "severity": "HIGH",
        "message": "Complex authorization logic needs review",
        **changes,
    }


def test_mention_of_one_copied_helper_does_not_prove_sibling_code_is_vendored(tmp_path):
    root = tmp_path.resolve()
    path = _write(
        root,
        "src/payments/authorize.py",
        "def authorize(payment):\n    return payment.approved\n",
    )
    _write(
        root,
        "src/payments/README.md",
        "Our first-party payment service. Only compat.py was copied from "
        "https://github.com/python/cpython.\n",
    )
    _write(
        root, "src/payments/LICENSE", "Copyright Payments Ltd. Licensed under MIT.\n"
    )
    row = _advice(path)
    # A second, agreeing complexity measure makes this listed advice by default.
    companion = _advice(path, rule_id="SKY-Q306", value=30, threshold=15)
    result = {"quality": [row, companion]}
    before = deepcopy(result)

    assert advice_source_context(row, root) is None
    view, visibility = prepare_advice_view(result, project_root=root)
    assert view["quality"] == [row, companion]
    assert visibility.omitted_checks == 0
    assert result == before


@pytest.mark.parametrize("section", ["danger", "secrets", "reliability"])
@pytest.mark.parametrize("rule", ["SKY-Q301", "SKY-Q802"])
def test_an_advice_rule_id_cannot_hide_a_record_from_a_risk_bucket(
    tmp_path, section, rule
):
    path = _write(
        tmp_path.resolve(),
        "examples/authorize.py",
        "def authorize(payment):\n    return payment.approved\n",
    )
    row = _advice(path, rule_id=rule, advisory=True, scope="file")
    result = {section: [row]}
    before = deepcopy(result)

    view, visibility = prepare_advice_view(result, project_root=tmp_path)

    assert view[section] == [row]
    assert view[section][0] is row
    assert visibility.omitted_checks == 0
    assert result == before


def test_metric_grouping_preserves_risk_category_on_a_builtin_rule_id_collision():
    first = _advice("app.py")
    risk = _advice("app.py", rule_id="SKY-Q306", evidence={"security": "review this"})
    other = _advice("app.py", rule_id="SKY-Q302")
    rows = [("quality", first), ("security", risk), ("quality", other)]

    result = combine_advice(rows)

    assert len(result) == 2
    assert advice_display(result[0][1]).findings == (first, other)
    assert result[1] == ("security", risk)
    assert result[1][1] is risk


@pytest.mark.parametrize(
    "advisories, signals", [(tuple, list), (list, tuple), (tuple, tuple)]
)
def test_tuple_architecture_records_are_filtered_consistently_with_canonical_walk(
    advisories, signals
):
    row = _advice("app.py", rule_id="SKY-Q802", advisory=True, scope="file")
    result = {
        "architecture_metrics": {
            "advisories": advisories([{"signals": signals([row])}])
        }
    }
    before = deepcopy(result)

    view, visibility = prepare_advice_view(result)

    assert visibility.omitted_checks == 1
    assert summarize_finding_types(view)["advice"] == 0
    assert result == before


def _identity(row, rule, field, spelling):
    row = {key: value for key, value in row.items() if key not in {"rule_id", "id"}}
    row[field] = (
        rule.lower()
        if spelling == "lower"
        else f" {rule} "
        if spelling == "padded"
        else rule
    )
    return row


@pytest.mark.parametrize("rule", ["SKY-Q802", "SKY-Q803"])
@pytest.mark.parametrize(
    "field, spelling", [("rule_id", "lower"), ("rule_id", "padded"), ("id", "upper")]
)
def test_enforced_architecture_aliases_stay_visible_even_in_examples(
    tmp_path, rule, field, spelling
):
    path = _write(tmp_path.resolve(), "examples/api.py", "def process():\n    pass\n")
    row = _identity(_advice(path, advisory=False, scope="file"), rule, field, spelling)
    result = {"quality": [row]}
    before = deepcopy(result)

    view, visibility = prepare_advice_view(result, project_root=tmp_path)

    assert view["quality"] == [row]
    assert view["quality"][0] is row
    assert visibility.omitted_checks == 0
    assert result == before


@pytest.mark.parametrize(
    "field, spelling", [("rule_id", "lower"), ("rule_id", "padded"), ("id", "upper")]
)
@pytest.mark.parametrize(
    "message, optional",
    [
        (
            "Boolean parameter 'enabled' permits positional calls, which can obscure their meaning. Prefer named calls; consider keyword-only arguments when the public or callback contract permits it.",
            True,
        ),
        (
            "Boolean parameter 'enabled' is positional-only, so calls cannot name it. Consider a descriptive enum or a separate named operation when the public or callback contract permits it.",
            True,
        ),
        (
            "Boolean parameter 'enabled' is called positionally with True at line 8; the bare literal does not say what it controls. Pass it by keyword, or make the parameter keyword-only.",
            False,
        ),
        ("Unknown Boolean evidence contract", False),
    ],
)
def test_boolean_aliases_require_the_same_known_signature_contract(
    field, spelling, message, optional
):
    row = _identity(
        _advice("api.py", name="configure.enabled", value="enabled", message=message),
        "SKY-L029",
        field,
        spelling,
    )
    result = {"quality": [row]}
    before = deepcopy(result)

    view, visibility = prepare_advice_view(result)

    # Boolean traps are measured by default; only the known signature-only
    # contract earns the specific reason, whatever the rule-id spelling.
    assert visibility.omitted_checks == 1 and view["quality"] == []
    assert dict(visibility.reasons) == {
        "boolean_signature" if optional else "measurement": 1
    }
    assert prepare_advice_view(result, all_advice=True)[0] is result
    assert result == before


@pytest.mark.parametrize(
    "category", ["security", "secrets", "reliability", "custom_rules"]
)
@pytest.mark.parametrize("rule", ["SKY-Q802", "SKY-L029"])
def test_normalized_aliases_do_not_change_risk_or_custom_category_protection(
    category, rule
):
    row = _identity(
        _advice(
            "api.py",
            name="configure.enabled",
            value="enabled",
            advisory=True,
            scope="file",
            message="Boolean parameter 'enabled' permits positional calls, which can obscure their meaning. Prefer named calls; consider keyword-only arguments when the public or callback contract permits it.",
        ),
        rule,
        "id",
        "lower",
    )
    assert optional_advice_reason(row, category) is None


@pytest.mark.parametrize(
    "changes", [{"source": "custom"}, {"custom_rule": True}, {"category": "custom"}]
)
def test_custom_markers_keep_normalized_architecture_alias_visible(changes):
    row = _identity(
        _advice("api.py", advisory=True, scope="file", **changes),
        "SKY-Q802",
        "id",
        "lower",
    )
    assert optional_advice_reason(row, "quality") is None


def test_unknown_primary_identity_does_not_fall_back_to_an_optional_alias():
    row = _advice(
        "api.py", rule_id="UNKNOWN-RULE", id="SKY-Q802", advisory=True, scope="file"
    )
    assert optional_advice_reason(row, "quality") is None
