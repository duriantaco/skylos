"""A deleted test is not excused by an import the change dropped.

The changed code importing a library name (``Decimal`` from ``decimal``) is
not the feature a test checks: the test imports the same name itself and the
library is still there. A name the test reaches through the changed module
(``mock.patch("app.payments.json")``) and a function removed with its test
are still feature removal.
"""

from __future__ import annotations

from skylos.done.checks import check_unknown_imports
from skylos.rules.ai_defect import diff_dependencies
from test.test_done_precision import _advice, _blocking, _ctx, _repo, _tampering

PAYMENTS = """\
from decimal import Decimal, ROUND_HALF_UP


def refund_amount(total, percent):
    amount = Decimal(total) * Decimal(percent) / Decimal(100)
    return amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def charge_total(subtotal, tax_rate):
    tax = Decimal(subtotal) * Decimal(tax_rate)
    return (Decimal(subtotal) + tax).quantize(Decimal("0.01"))
"""
FLOAT_PAYMENTS = """\
def refund_amount(total, percent):
    return round(float(total) * percent / 100, 2)


def charge_total(subtotal, tax_rate):
    return round(float(subtotal) * (1 + float(tax_rate)), 2)
"""
PAYMENT_TESTS = """\
from decimal import Decimal

from app.payments import charge_total, refund_amount


def test_refund_rounding():
    assert refund_amount("26.85", 10) == Decimal("2.69")


def test_charge_total():
    assert charge_total("10.00", "0.08") == Decimal("10.80")
"""
WITHOUT_ROUNDING_TEST = PAYMENT_TESTS.replace(
    'def test_refund_rounding():\n    assert refund_amount("26.85", 10) == '
    'Decimal("2.69")\n\n\n',
    "",
)


def test_a_test_deleted_while_only_a_library_import_left_the_code_blocks(tmp_path):
    result = _tampering(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/payments.py": PAYMENTS,
            "tests/test_payments.py": PAYMENT_TESTS,
        },
        {
            "app/payments.py": FLOAT_PAYMENTS,
            "tests/test_payments.py": WITHOUT_ROUNDING_TEST,
        },
    )
    assert result.status == "fail", result.findings
    assert _blocking(result) == [
        "test_refund_rounding was deleted; no test with the same body exists now"
    ]
    assert not any("feature removal" in m for m in _advice(result))


def test_an_aliased_module_import_dropped_from_the_code_does_not_excuse_it(tmp_path):
    base = {
        "app/__init__.py": "",
        "app/ratio.py": (
            "import fractions as frac\n\n\n"
            "def half(value):\n    return frac.Fraction(value, 2)\n"
        ),
        "tests/test_ratio.py": (
            "import fractions as frac\n\nfrom app.ratio import half\n\n\n"
            "def test_half_is_exact():\n    assert half(3) == frac.Fraction(3, 2)\n\n\n"
            "def test_half_of_zero():\n    assert half(0) == 0\n"
        ),
    }
    head = {
        "app/ratio.py": "def half(value):\n    return value / 2\n",
        "tests/test_ratio.py": (
            "from app.ratio import half\n\n\n"
            "def test_half_of_zero():\n    assert half(0) == 0\n"
        ),
    }
    result = _tampering(tmp_path, base, head)
    assert result.status == "fail", result.findings
    assert _blocking(result) == [
        "test_half_is_exact was deleted; no test with the same body exists now"
    ]


def test_a_test_deleted_with_the_function_it_calls_is_still_feature_removal(
    tmp_path,
):
    without_refunds = FLOAT_PAYMENTS.split("\n\n\ndef charge_total")[1]
    result = _tampering(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/payments.py": PAYMENTS,
            "tests/test_payments.py": PAYMENT_TESTS,
        },
        {
            "app/payments.py": "def charge_total" + without_refunds,
            "tests/test_payments.py": WITHOUT_ROUNDING_TEST.replace(
                "charge_total, refund_amount", "charge_total"
            ),
        },
    )
    assert result.status == "pass", result.findings
    assert _advice(result) == [
        (
            "(advice) test_refund_rounding was deleted together with the code it "
            "tests (feature removal: uses refund_amount, which the change removed)"
        )
    ]


def test_an_import_the_test_patches_through_the_changed_module_is_still_removal(
    tmp_path,
):
    tests = (
        "import json\nfrom unittest import mock\n\nfrom app.export import export\n\n\n"
        "def test_export_serialises_with_json():\n"
        '    with mock.patch("app.export.json") as fake:\n'
        "        export({'a': 1})\n"
        "    fake.dumps.assert_called_once()\n"
        '    assert json.loads("{}") == {}\n\n\n'
        "def test_export_returns_text():\n"
        "    assert isinstance(export({}), str)\n"
    )
    result = _tampering(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/export.py": "import json\n\n\ndef export(data):\n    return json.dumps(data)\n",
            "tests/test_export.py": tests,
        },
        {
            "app/export.py": "def export(data):\n    return repr(data)\n",
            "tests/test_export.py": tests.split("\n\n\ndef test_export_serialises")[0]
            + "\n\n\ndef test_export_returns_text():\n"
            "    assert isinstance(export({}), str)\n",
        },
    )
    assert result.status == "pass", result.findings
    assert _advice(result) == [
        (
            "(advice) test_export_serialises_with_json was deleted together with "
            "the code it tests (feature removal: uses json, which the change removed)"
        )
    ]


def test_import_advice_alone_is_not_reported_as_every_import_resolving(
    tmp_path, monkeypatch
):
    repo = _repo(
        tmp_path,
        {"app/__init__.py": "", "app/x.py": "import os\n"},
        {"app/x.py": "import os\nimport thing\n"},
    )
    monkeypatch.setattr(
        diff_dependencies,
        "scan_diff_dependency_hallucinations",
        lambda *a, **k: {
            "findings": [
                {
                    "rule_id": "SKY-D223",
                    "file": "app/x.py",
                    "line": 2,
                    "message": "Possible hallucinated import 'thing'.",
                }
            ],
            "registry_unreachable": False,
        },
    )
    result = check_unknown_imports(_ctx(repo))
    assert result.status == "pass"
    assert result.summary == (
        "No missing packages found; 1 import(s) could not be tied to a declared package"
    )
    monkeypatch.setattr(
        diff_dependencies,
        "scan_diff_dependency_hallucinations",
        lambda *a, **k: {"findings": [], "registry_unreachable": False},
    )
    assert (
        check_unknown_imports(_ctx(repo)).summary
        == "Every added import and package resolves"
    )
