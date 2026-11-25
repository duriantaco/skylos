import json

import pytest

from skylos.analyzer import analyze
from skylos.cleanup import build_cleanup_plan

RULE_ID = "SKY-Q807"


def _write(root, name, contents=""):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


def _packages(root):
    for package in ("shop", "shop/billing", "shop/orders"):
        _write(root, f"{package}/__init__.py")
    _write(root, "shop/billing/records.py", "TOTAL = 0\n")
    _write(root, "shop/orders/records.py", "TOTAL = 0\n")


def _scan(root, *, enable_cycles=False):
    overrides = (
        {"architecture": {"check_package_cycles": True}} if enable_cycles else None
    )
    return json.loads(
        analyze(
            str(root),
            enable_quality=True,
            grep_verify=False,
            project_config_overrides=overrides,
        )
    )


def _cycles(report):
    return [
        finding
        for finding in report.get("quality", ())
        if finding["rule_id"] == RULE_ID
    ]


@pytest.fixture(autouse=True)
def one_worker(monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")


def test_package_cycle_requires_opt_in_and_reports_every_import_site(tmp_path):
    _packages(tmp_path)
    billing = _write(
        tmp_path,
        "shop/billing/invoices.py",
        "\nfrom shop.orders import records\nimport shop.orders.records\n",
    )
    orders = _write(
        tmp_path,
        "shop/orders/checkout.py",
        "from shop.billing.records import TOTAL\n",
    )
    assert not _cycles(_scan(tmp_path))

    _write(
        tmp_path,
        "pyproject.toml",
        "[tool.skylos.architecture]\ncheck_package_cycles = true\n",
    )
    report = _scan(tmp_path)
    assert not report.get("circular_dependencies")
    (finding,) = _cycles(report)
    assert finding["cycle_members"] == ["shop.billing", "shop.orders"]
    assert (finding["file"], finding["line"]) == (str(billing), 2)
    assert [
        (edge["from_module"], edge["to_module"], edge["line"])
        for edge in finding["dependency_edges"]
    ] == [
        ("shop.billing.invoices", "shop.orders.records", 2),
        ("shop.billing.invoices", "shop.orders.records", 3),
        ("shop.orders.checkout", "shop.billing.records", 1),
    ]
    assert [
        (loc["file"], loc["start_line"]) for loc in finding["related_locations"]
    ] == [
        (str(billing), 2),
        (str(billing), 3),
        (str(orders), 1),
    ]
    plan = build_cleanup_plan(report, project_root=tmp_path, top=None)
    [task] = [task for task in plan["tasks"] if task["rule_id"] == RULE_ID]
    assert task["finding_type"] == "review"
    assert task["finding"]["dependency_edges"] == finding["dependency_edges"]


@pytest.mark.parametrize(
    ("source_file", "source"),
    [
        ("shop/billing/invoices.py", "import shop.orders.missing\n"),
        (
            "shop/billing/invoices.py",
            (
                "from typing import TYPE_CHECKING\n"
                "if TYPE_CHECKING:\n"
                "    import shop.orders.records\n"
            ),
        ),
        (
            "shop/billing/invoices.py",
            "def deferred():\n    import shop.orders.records\n",
        ),
        ("shop/billing/test_invoices.py", "import shop.orders.records\n"),
        ("shop/billing/tests/invoices.py", "import shop.orders.records\n"),
    ],
)
def test_package_cycle_excludes_unresolved_conditional_and_test_imports(
    tmp_path, source_file, source
):
    _packages(tmp_path)
    _write(tmp_path, source_file, source)
    _write(tmp_path, "shop/orders/checkout.py", "import shop.billing.records\n")
    assert not _cycles(_scan(tmp_path, enable_cycles=True))


def test_package_cycle_reports_one_group_for_overlapping_cycles(tmp_path):
    _packages(tmp_path)
    _write(tmp_path, "shop/shipping/__init__.py")
    _write(tmp_path, "shop/shipping/records.py", "TOTAL = 0\n")
    _write(
        tmp_path,
        "shop/billing/invoices.py",
        "import shop.orders.records\nimport shop.shipping.records\n",
    )
    _write(tmp_path, "shop/orders/checkout.py", "import shop.billing.records\n")
    _write(tmp_path, "shop/shipping/delivery.py", "import shop.billing.records\n")
    (finding,) = _cycles(_scan(tmp_path, enable_cycles=True))
    assert finding["cycle_members"] == ["shop.billing", "shop.orders", "shop.shipping"]
    assert len(finding["dependency_edges"]) == 4


def test_package_cycle_does_not_promote_directories_without_an_initializer(tmp_path):
    _packages(tmp_path)
    (tmp_path / "shop/orders/__init__.py").unlink()
    _write(tmp_path, "shop/billing/invoices.py", "import shop.orders.records\n")
    _write(tmp_path, "shop/orders/checkout.py", "import shop.billing.records\n")
    assert not _cycles(_scan(tmp_path, enable_cycles=True))
