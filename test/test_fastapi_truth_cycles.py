"""Truth aliases must terminate without inventing route execution evidence."""

import ast
import json
from types import SimpleNamespace

import pytest

from skylos.analyzer import Skylos
from skylos.deadcode.fastapi_liveness import FastAPIProject


def _collect(root, assignments, condition):
    source = (
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "def endpoint(): return 1\n" + assignments + f"{condition}\n"
    )
    path = root / "app.py"
    path.write_text(source, encoding="utf-8")
    tree = ast.parse(source)
    project = FastAPIProject({}, [SimpleNamespace(path=path, tree=tree)], root)
    report = project.collect()
    assert report.complete, report.incomplete_reason
    return report, (str(path.resolve()), 3)


@pytest.mark.parametrize(
    "assignments",
    [
        "flag = True\nflag = not flag\n",
        "first = True\nsecond = not first\nfirst = second\nflag = first\n",
    ],
)
@pytest.mark.parametrize(
    "condition",
    [
        "flag and app.add_api_route('/', endpoint)",
        "flag or app.add_api_route('/', endpoint)",
        "app.add_api_route('/', endpoint) if flag else None",
    ],
)
def test_cyclic_truth_alias_is_uncertain_registration(tmp_path, assignments, condition):
    report, endpoint = _collect(tmp_path, assignments, condition)
    assert endpoint in report.candidates
    assert endpoint not in report.roots
    assert endpoint in report.uncertain


@pytest.mark.parametrize("length", [0, 1, 2, 1100, 1101])
@pytest.mark.parametrize("initial", [False, True])
@pytest.mark.parametrize("operator", ["and", "or"])
def test_acyclic_truth_alias_preserves_short_circuit_parity(
    tmp_path, length, initial, operator
):
    assignments = f"flag_0 = {initial}\n" + "".join(
        f"flag_{index} = not flag_{index - 1}\n" for index in range(1, length + 1)
    )
    report, endpoint = _collect(
        tmp_path,
        assignments,
        f"flag_{length} {operator} app.add_api_route('/', endpoint)",
    )
    truth = initial != bool(length % 2)
    expected_root = truth if operator == "and" else not truth
    assert (endpoint in report.roots) is expected_root
    assert endpoint not in report.uncertain


def test_non_fastapi_click_scan_survives_reassigned_truth_alias(tmp_path):
    (tmp_path / "app.py").write_text(
        "import click\n"
        "@click.command()\ndef entry(): return 1\n"
        "def unused_neighbor(): return 2\n"
        "flag = True\nflag = not flag\nflag and entry()\n",
        encoding="utf-8",
    )
    analyzer = Skylos()
    result = json.loads(
        analyzer.analyze(
            str(tmp_path),
            thr=0,
            grep_verify=False,
            enable_danger=True,
            enable_secrets=True,
            enable_quality=True,
        )
    )
    assert not result.get("analysis_errors")
    unused = {item["full_name"] for item in result["unused_functions"]}
    assert "app.unused_neighbor" in unused
    assert "app.entry" not in unused
    entry = next(item for item in analyzer.defs.values() if item.name == "app.entry")
    assert entry.heuristic_refs.get("framework_root") == 1.0
