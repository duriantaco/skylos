"""skylos done: SKY-A120, the tests check the changed lines."""

from __future__ import annotations

import json
import os
import runpy
import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.done import mutation
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done.base import open_comparison
from skylos.done.config import DoneConfig, parse_done_config
from skylos.done.engine import run
from skylos.done.mutation import (
    _line_ranges,
    make_mutant,
    select_targets,
    statement_units,
)
from skylos.done.receipt import build_receipt, validate_receipt


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _write(root: Path, rel: str, text: str) -> None:
    root = root.resolve(strict=True)
    path = root / rel
    path.resolve(strict=False).relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, dedent(text))


BILLING = """\
import logging

log = logging.getLogger(__name__)
RATE = 5


def total(prices):
    return sum(prices)


def fee(amount):
    \"\"\"Shipping fee.\"\"\"
    log.info("fee for %s", amount)
    if amount > 100:
        return 0
    return RATE


def discount(amount, member):
    if member and amount >= 50:
        return amount * 0.9
    return amount


def refund(amount):
    if amount < 0:
        raise ValueError("negative")
    return -amount
"""

BILLING_TESTS = """\
from shop.billing import discount, fee, total


def test_total():
    assert total([1, 2]) == 3


def test_fee():
    assert fee(500) == 0
    assert fee(10) == 5


def test_discount():
    assert discount(80, True) == 72
    assert discount(80, False) == 80
"""


@pytest.fixture
def shop(tmp_path: Path) -> Path:
    root = tmp_path / "shop-repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, "shop/__init__.py", "")
    _write(root, "shop/billing.py", "def total(prices):\n    return sum(prices)\n")
    _write(
        root,
        "tests/test_billing.py",
        "from shop.billing import total\n\n\ndef test_total():\n    assert total([1, 2]) == 3\n",
    )
    _write(
        root,
        "pyproject.toml",
        '[project]\nname = "shop"\nversion = "0"\n\n[tool.pytest.ini_options]\naddopts = "-q"\n',
    )
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "switch", "-qc", "feature")
    _write(root, "shop/billing.py", BILLING)
    _write(root, "tests/test_billing.py", BILLING_TESTS)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "feature")
    return root


def _changed_lines_check(result):
    return next(c for c in result.checks if c.result.id == "changed_lines_checked")


@pytest.fixture
def probe(tmp_path: Path, monkeypatch):
    from skylos.done import runner

    root = tmp_path / "probe"
    root.mkdir()
    _write(root, "skylos_done_pytest_plugin.py", runner._PLUGIN_SOURCE)
    for name in ("SKYLOS_DONE_MUTANT", "SKYLOS_DONE_TRACE", "SKYLOS_DONE_DESELECTED"):
        monkeypatch.delenv(name, raising=False)
    namespace = runpy.run_path(str(root / "skylos_done_pytest_plugin.py"))
    try:
        yield root, namespace
    finally:
        descriptor = namespace["_CHANNEL_FD"]
        if descriptor is not None:
            os.close(descriptor)


def test_probe_channels_round_trip_and_never_overwrite(probe, monkeypatch):
    root, namespace = probe
    path = root / "input.json"
    namespace["_write_json"](str(path), {"value": 1})
    namespace["_write_json"](str(path), {"value": 2})
    monkeypatch.setenv("SKYLOS_DONE_TRACE", str(path))
    assert namespace["_read_json"]("SKYLOS_DONE_TRACE") == {"value": 1}
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("kind", ["outside", "traversal", "nested", "directory"])
def test_probe_channels_reject_paths_outside_direct_children(probe, monkeypatch, kind):
    root, namespace = probe
    outside = root.parent / "outside.json"
    _write(root.parent, "outside.json", '{"value": "unchanged"}')
    paths = {
        "outside": outside,
        "traversal": root / ".." / "outside.json",
        "nested": root / "nested" / "output.json",
        "directory": root,
    }
    path = paths[kind]
    monkeypatch.setenv("SKYLOS_DONE_TRACE", str(path))
    assert namespace["_read_json"]("SKYLOS_DONE_TRACE") is None
    namespace["_write_json"](str(path), {"value": "changed"})
    assert json.loads(outside.read_text()) == {"value": "unchanged"}
    assert not (root / "nested").exists()


def test_probe_channels_reject_invalid_paths(probe):
    _, namespace = probe
    for path in (None, 1, "\x00"):
        assert namespace["_channel_path"](path) is None


def test_probe_channels_reject_symlinks(probe, monkeypatch):
    root, namespace = probe
    _write(root.parent, "outside.json", '{"value": "unchanged"}')
    outside = root.parent / "outside.json"
    path = root / "channel.json"
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    monkeypatch.setenv("SKYLOS_DONE_TRACE", str(path))
    assert namespace["_read_json"]("SKYLOS_DONE_TRACE") is None
    namespace["_write_json"](str(path), {"value": "changed"})
    assert json.loads(outside.read_text()) == {"value": "unchanged"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_probe_channels_reject_fifos_without_opening(probe, monkeypatch):
    root, namespace = probe
    path = root / "channel.json"
    os.mkfifo(path)
    monkeypatch.setenv("SKYLOS_DONE_TRACE", str(path))
    assert namespace["_read_json"]("SKYLOS_DONE_TRACE") is None
    namespace["_write_json"](str(path), {"value": "changed"})


def test_probe_channels_bound_input_bytes(probe, monkeypatch):
    root, namespace = probe
    _write(root, "input.json", '{"value": "too large"}')
    monkeypatch.setenv("SKYLOS_DONE_TRACE", str(root / "input.json"))
    monkeypatch.setitem(namespace["_read_json"].__globals__, "_MAX_CHANNEL_BYTES", 4)
    assert namespace["_read_json"]("SKYLOS_DONE_TRACE") is None


# ---------------------------------------------------------------------------
# Which lines
# ---------------------------------------------------------------------------


def test_units_skip_logging_docstrings_imports_hints_and_module_code():
    source = dedent(
        """\
        import os
        LIMIT = 3


        def run(x: int) -> int:
            \"\"\"Doc.\"\"\"
            import json
            logger.info("x")
            y: int
            print(x)
            if TYPE_CHECKING:
                pass
            total = x + LIMIT
            return total
        """
    )
    starts = sorted(u.start for u in statement_units(source))
    assert starts == [13, 14]


def test_multi_line_statement_is_one_target_with_its_changed_lines(tmp_path: Path):
    root = tmp_path / "r"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, "app.py", "def build(x):\n    return make(\n        a=x,\n    )\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _write(
        root,
        "app.py",
        "def build(x):\n    return make(\n        a=x,\n        b=x * 2,\n    )\n",
    )
    targets = select_targets(open_comparison(root, "main"), set())
    assert [(t.line, t.changed, t.function) for t in targets] == [(2, (4,), "build")]


def test_test_files_and_migrations_are_not_targets():
    assert mutation.is_test_path("tests/helpers.py", set())
    assert mutation.is_test_path("pkg/conftest.py", set())
    assert mutation.is_test_path("pkg/test_x.py", set())
    assert not mutation.is_test_path("pkg/contest.py", set())


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------


def _mutate(body: str, line: int, changed=None):
    source = "def f(a, b, flag):\n" + body
    return make_mutant("m.py", source, line, changed)


@pytest.mark.parametrize(
    "body, line, description, fragment",
    [
        ("    if a > b:\n        return 1\n", 2, "changes `>` to `>=`", "a >= b"),
        (
            "    if a is None:\n        return 1\n",
            2,
            "changes `is` to `is not`",
            "a is not None",
        ),
        (
            "    if a and flag:\n        return 1\n",
            2,
            "changes `and` to `or`",
            "a or flag",
        ),
        (
            "    if flag:\n        return 1\n",
            2,
            "negates the condition",
            "if not (flag):",
        ),
        (
            "    while not flag:\n        flag = 1\n",
            2,
            "negates the condition",
            "while flag:",
        ),
        ("    return True\n", 2, "returns False instead of True", "return False"),
        ("    return 0\n", 2, "returns 1 instead of 0", "return 1"),
        ("    return 'x'\n", 2, "returns an empty string instead", 'return ""'),
        ("    return a.items()\n", 2, "returns None instead", "return None"),
        ("    x = a[3]\n", 2, "changes 3 to 4", "a[4]"),
        ("    x = a + b\n", 2, "changes `+` to `-`", "a - b"),
        ("    a += 1\n", 2, "changes 1 to 2", "a += 2"),
        ("    a += b\n", 2, "changes `+=` to `-=`", "a -= b"),
        (
            "    save(a, key=b)\n",
            2,
            "passes None as argument 1 of `save()`",
            "save(None, key=b)",
        ),
        ("    x = load()\n", 2, "assigns None instead", "x = None"),
        ("    reset()\n", 2, "removes the call to `reset()`", "    pass"),
    ],
)
def test_one_mutation_per_line_chosen_by_what_the_line_does(
    body, line, description, fragment
):
    mutant = _mutate(body, line)
    assert mutant is not None
    assert mutant.description == description
    assert fragment in mutant.source


def test_only_changed_lines_of_a_statement_are_mutated():
    # The ca9 case: a multi-line call with an unchanged literal and a changed
    # keyword argument. Mutating the literal says nothing about this change.
    body = "    run(\n        size=a * 1024,\n        hosts=b,\n    )\n"
    mutant = _mutate(body, 2, changed=(4,))
    assert mutant is not None and mutant.line == 4
    assert mutant.description == "passes None as `hosts`"
    assert "size=a * 1024" in mutant.source and "hosts=None" in mutant.source
    assert _mutate(body, 2, changed=(5,)) is None  # only the closing bracket


def test_lines_without_a_mutation_return_none():
    assert _mutate("    del a\n", 2) is None
    assert _mutate("    return\n", 2) is None


def test_line_ranges():
    assert _line_ranges([27, 25, 26, 31, 33, 34]) == "25-27, 31, 33-34"
    assert _line_ranges([4]) == "4"


# ---------------------------------------------------------------------------
# The check, end to end
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", ["sys.monitoring", "settrace"])
def test_changed_lines_check_reports_untested_boundaries_and_functions(
    shop: Path, backend: str, monkeypatch
):
    if backend == "settrace":
        monkeypatch.setenv("SKYLOS_DONE_TRACE_BACKEND", "settrace")
    result = run(shop, base_ref="main")
    outcome = _changed_lines_check(result)
    check = outcome.result
    assert outcome.mode == "advise"
    assert result.verdict == "pass"  # advice never blocks by default
    messages = [f.message for f in check.findings]
    assert messages == [
        "No test fails if shop/billing.py:14 changes `>` to `>=`. Add an assertion that would.",
        "No test fails if shop/billing.py:20 changes `>=` to `>`. Add an assertion that would.",
        "No test runs shop/billing.py:26-28 (in `refund`). Add a test that does.",
    ]
    assert check.status == "fail"
    assert check.evidence["caught"] == 4 and check.evidence["missed"] == 2
    receipt = build_receipt(result)
    assert validate_receipt(receipt) == []
    assert receipt["unverified"] == [
        {"file": "shop/billing.py", "line": line} for line in (14, 20, 26, 27, 28)
    ]


def test_mutants_never_touch_the_working_tree(shop: Path):
    before = (shop / "shop/billing.py").read_bytes()
    run(shop, base_ref="main")
    assert (shop / "shop/billing.py").read_bytes() == before
    assert _git(shop, "status", "--porcelain") == ""
    assert not list(shop.rglob("__pycache__"))


def test_strong_tests_leave_only_mutation_inapplicable_lines_unverified(shop: Path):
    _write(
        shop,
        "tests/test_billing.py",
        BILLING_TESTS
        + dedent(
            """\


            def test_boundaries():
                assert fee(100) == 5
                assert discount(50, True) == 45


            def test_refund():
                assert refund(3) == -3
                assert refund(0) == 0
                try:
                    refund(-1)
                except ValueError:
                    pass
                else:
                    raise AssertionError
            """
        ).replace("from shop.billing import discount, fee, total", ""),
    )
    _write(
        shop,
        "tests/test_billing.py",
        (shop / "tests/test_billing.py")
        .read_text()
        .replace(
            "from shop.billing import discount, fee, total",
            "from shop.billing import discount, fee, refund, total",
        ),
    )
    _git(shop, "add", "-A")
    _git(shop, "commit", "-qm", "tests")
    check = _changed_lines_check(run(shop, base_ref="main")).result
    assert check.status == "incomplete", [f.message for f in check.findings]
    assert check.evidence["missed"] == 0 and check.evidence["not_run_by_tests"] == 0
    assert check.evidence["covered_only"] == 1
    assert check.unverified == [("shop/billing.py", 27)]


def test_a_module_the_tests_import_from_elsewhere_is_not_checked(
    shop: Path, tmp_path: Path
):
    # The tests import an installed copy of `shop`, not the repository's file:
    # Skylos cannot say anything about the repository's lines.
    installed = tmp_path / "site" / "shop"
    installed.mkdir(parents=True)
    _write(installed, "__init__.py", "")
    _write(installed, "billing.py", BILLING)
    _write(
        shop,
        "tests/conftest.py",
        f"import sys\nsys.path.insert(0, {str(installed.parent)!r})\n",
    )
    _git(shop, "add", "-A")
    _git(shop, "commit", "-qm", "use installed copy")
    _git(shop, "branch", "-f", "main", "HEAD~2")
    check = _changed_lines_check(run(shop, base_ref="main")).result
    assert not any("No test runs" in f.message for f in check.findings)
    assert check.evidence["not_checked"] >= 1
    assert check.unverified


def test_mutant_limit_reports_not_checked_never_pass(shop: Path, monkeypatch):
    monkeypatch.setattr(mutation, "MAX_MUTANTS", 0)
    check = _changed_lines_check(run(shop, base_ref="main")).result
    assert check.evidence["mutants"] == 0
    assert check.evidence["not_checked"] == 6
    assert check.status == "fail"  # the untested function is still a finding
    assert {line for path, line in check.unverified if path == "shop/billing.py"} == {
        14,
        15,
        16,
        20,
        21,
        22,
        26,
        27,
        28,
    }


def test_not_judged_when_tests_do_not_pass_or_do_not_run(shop: Path):
    # Not judged: "skipped" from the check itself, or "incomplete" when the
    # engine does not run it because an earlier required check blocks.
    not_run = _changed_lines_check(run(shop, base_ref="main", run_tests=False)).result
    assert not_run.status in {"skipped", "incomplete"} and not not_run.findings
    _write(shop, "tests/test_billing.py", BILLING_TESTS.replace("== 72", "== 0"))
    _git(shop, "add", "-A")
    _git(shop, "commit", "-qm", "break")
    check = _changed_lines_check(run(shop, base_ref="main")).result
    assert check.status in {"skipped", "incomplete"} and not check.findings
    assert not check.unverified


def test_off_mode_does_not_trace(shop: Path, monkeypatch):
    import skylos.done.runner as runner

    seen = {}
    real = runner.run_tests

    def spy(*args, **kwargs):
        seen["trace"] = kwargs.get("trace_targets")
        return real(*args, **kwargs)

    monkeypatch.setattr(runner, "run_tests", spy)
    _write(
        shop,
        "pyproject.toml",
        (shop / "pyproject.toml").read_text()
        + '\n[tool.skylos.done.checks]\nchanged_lines_checked = "off"\n',
    )
    _git(shop, "add", "-A")
    _git(shop, "commit", "-qm", "off")
    _git(shop, "branch", "-f", "main", "HEAD")
    _write(shop, "shop/billing.py", BILLING + "\n\ndef extra():\n    return 1\n")
    result = run(shop, base_ref="main")
    assert seen["trace"] is None
    assert _changed_lines_check(result).result.status == "skipped"


def test_budget_setting_is_bounded_and_part_of_the_digest():
    config = parse_done_config(
        "[tool.skylos.done]\nchanged_lines_budget_seconds = 99999\n"
    )
    assert config.changed_lines_budget_seconds == 1800
    assert any("changed_lines_budget_seconds" in p for p in config.problems)
    assert config.digest() != DoneConfig().digest()
    assert DoneConfig().mode("changed_lines_checked") == "advise"


def test_probe_is_standalone():
    source = (Path(mutation.__file__).with_name("pytest_probe.py")).read_text()
    assert "skylos" not in "".join(
        line for line in source.splitlines() if line.startswith(("import", "from"))
    )
    json.loads(json.dumps({"ok": True}))  # the probe only exchanges JSON


def test_inherited_mutant_cannot_make_primary_tests_pass(
    shop: Path, tmp_path: Path, monkeypatch
):
    # This payload would replace the broken checkout with passing code during
    # the primary run if the private probe settings leaked from the caller.
    _write(shop, "shop/billing.py", BILLING.replace("return sum(prices)", "return 0"))
    marker = tmp_path / "forged-loaded.json"
    _write(
        tmp_path,
        "forged-mutant.json",
        json.dumps(
            {
                "file": str(shop / "shop/billing.py"),
                "source": BILLING,
                "loaded_flag": str(marker),
            }
        ),
    )
    monkeypatch.setenv("SKYLOS_DONE_MUTANT", str(tmp_path / "forged-mutant.json"))
    result = run(shop, base_ref="main")
    check = next(c.result for c in result.checks if c.result.id == "tests_pass")
    assert check.status == "fail"
    assert result.verdict == "fail"
    assert any("test_total" in finding.message for finding in check.findings)
    assert not marker.exists()


def test_lost_real_line_trace_reports_every_target_unverified(shop: Path, monkeypatch):
    monkeypatch.setenv("SKYLOS_DONE_TRACE_BACKEND", "settrace")
    _write(
        shop,
        "tests/test_billing.py",
        BILLING_TESTS.replace(
            "def test_total():\n",
            "def test_total():\n    import sys\n    sys.settrace(None)\n",
        ),
    )
    result = run(shop, base_ref="main")
    check = _changed_lines_check(result).result
    assert result.verdict == "pass"  # the default remains advisory
    assert check.status == "incomplete"
    assert "another tool replaced the line tracer" in check.summary
    assert check.evidence["not_checked"] == 9
    receipt = build_receipt(result)
    assert validate_receipt(receipt) == []
    assert receipt["unverified"] == [
        {"file": "shop/billing.py", "line": line}
        for line in (14, 15, 16, 20, 21, 22, 26, 27, 28)
    ]


def test_covered_lines_without_applicable_mutants_are_unverified(tmp_path: Path):
    root = tmp_path / "no-operator"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, "app.py", "def clear(values):\n    values.clear()\n")
    _write(
        root,
        "test_app.py",
        "from app import clear\n\ndef test_clear():\n"
        "    values = [1]\n    assert clear(values) is None\n    assert values == []\n",
    )
    _write(root, "pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-q"\n')
    _git(root, "add", "app.py", "test_app.py", "pyproject.toml")
    _git(root, "commit", "-qm", "base")
    _write(root, "app.py", "def clear(values):\n    del values[:]\n    return\n")
    result = run(root, base_ref="main")
    assert result.verdict == "pass"
    check = _changed_lines_check(result).result
    assert check.status == "incomplete"
    assert check.evidence["covered_only"] == 2
    assert check.evidence["not_checked"] == 2
    assert check.evidence["caught"] == 0
    assert "Tests check all" not in check.summary
    assert build_receipt(result)["unverified"] == [
        {"file": "app.py", "line": 2},
        {"file": "app.py", "line": 3},
    ]


@pytest.mark.parametrize("backend", ["settrace", "sys.monitoring", "monitoring-local"])
@pytest.mark.parametrize("position", ["only", "last"])
def test_tracer_replaced_in_only_or_last_test_reports_incomplete(
    shop: Path, monkeypatch, backend: str, position: str
):
    import sys

    if backend != "settrace" and not hasattr(sys, "monitoring"):
        pytest.skip("sys.monitoring is available on Python 3.12 and later")
    monkeypatch.setenv("SKYLOS_DONE_TRACE_BACKEND", backend)
    if backend == "settrace":
        replacement = "    sys.settrace(None)\n"
    elif backend == "monitoring-local":
        replacement = (
            "    assert total([1, 2]) == 3\n"
            "    for tool in (3, 4):\n"
            '        if sys.monitoring.get_tool(tool) == "skylos-done":\n'
            "            sys.monitoring.set_local_events(tool, total.__code__, 0)\n"
        )
    else:
        replacement = (
            "    for tool in (3, 4):\n"
            '        if sys.monitoring.get_tool(tool) == "skylos-done":\n'
            "            sys.monitoring.set_events(tool, 0)\n"
        )
    body = "    import sys\n" + replacement + "    assert total([1, 2]) == 3\n"
    source = (
        "from shop.billing import total\n\ndef test_total():\n" + body
        if position == "only"
        else BILLING_TESTS + "\n\ndef test_last():\n" + body
    )
    _write(shop, "tests/test_billing.py", source)
    result = run(shop, base_ref="main")
    check = _changed_lines_check(result).result
    assert result.verdict == "pass"
    assert check.status == "incomplete"
    assert "another tool replaced the line tracer" in check.summary
    assert not check.findings
    assert check.evidence["not_checked"] == 9
    assert build_receipt(result)["unverified"] == [
        {"file": "shop/billing.py", "line": line}
        for line in (14, 15, 16, 20, 21, 22, 26, 27, 28)
    ]


def test_multiple_changed_arguments_are_checked_independently(tmp_path: Path):
    root = tmp_path / "changed-arguments"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    source = (
        "def choose(first, second):\n    return first\n\n"
        "def value():\n    return choose(\n        1,\n        2,\n    )\n"
    )
    _write(root, "app.py", source)
    _write(root, "test_app.py", "def test_existing():\n    assert True\n")
    _write(root, "pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-q"\n')
    _git(root, "add", "app.py", "test_app.py", "pyproject.toml")
    _git(root, "commit", "-qm", "base")
    _write(
        root,
        "app.py",
        source.replace("        1,\n        2,", "        100,\n        200,"),
    )
    _write(
        root,
        "test_app.py",
        "from app import value\n\ndef test_existing():\n    assert True\n\n"
        "def test_value():\n    assert value() == 100\n",
    )
    result = run(root, base_ref="main")
    check = _changed_lines_check(result).result
    assert result.verdict == "pass"  # SKY-A120 stays advisory by default.
    assert check.status == "fail"
    assert check.evidence["changed_lines"] == 2
    assert check.evidence["mutants"] == 2
    assert check.evidence["caught"] == 1
    assert check.evidence["missed"] == 1
    assert check.unverified == [("app.py", 7)]
    assert build_receipt(result)["unverified"] == [{"file": "app.py", "line": 7}]
