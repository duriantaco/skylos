import ast
import json
import threading

import pytest

from skylos.analyzer import analyze
from skylos.core.linter import LinterVisitor
from skylos.reporting.listing import is_listed
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx

DEADLINE_SECONDS = 120

GROWING_LOOP = (
    "    stats = []\n"
    "    for batch in batches:\n"
    "        for item in batch:\n"
    "            first = tensorlib.zeros(item, dtype=tensorlib.kind, device=flag)\n"
    "            second = tensorlib.zeros(item, dtype=tensorlib.mode, device=flag)\n"
    "            tensorlib.cat((first, second), tensorlib.axis)\n"
    "            stats.append((first, second, tensorlib.width))\n"
    "            merged = tensorlib.as_tensor(second, dtype=tensorlib.depth)\n"
    "            tensorlib.stack(merged, tensorlib.order)\n"
)

CASES = {
    "eval_after_loop": (
        "import tensorlib\n"
        "def run(batches, flag, code):\n" + GROWING_LOOP + "    return eval(code)\n",
        {("SKY-D201", 12)},
    ),
    "pickle_after_loop": (
        "import pickle\n"
        "import tensorlib\n"
        "def run(batches, flag, data):\n"
        + GROWING_LOOP
        + "    return pickle.loads(data)\n",
        {("SKY-D205", 13)},
    ),
    "rebound_provider_beside_loop": (
        "import json\n"
        "import pickle\n"
        "import tensorlib\n"
        "pickle = json\n"
        "def collect(batches, flag):\n" + GROWING_LOOP + "    return stats\n"
        "def restore(data):\n"
        "    return pickle.loads(data)\n",
        set(),
    ),
}

SELECTED = {"SKY-D201", "SKY-D202", "SKY-D203", "SKY-D205", "SKY-D209"}


def _within_deadline(work):
    outcome = {}

    def target():
        outcome["value"] = work()

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(DEADLINE_SECONDS)
    assert not worker.is_alive(), "scan did not finish"
    return outcome["value"]


@pytest.mark.parametrize("engine", ["rule", "scan_ctx"])
@pytest.mark.parametrize("name", sorted(CASES))
def test_growing_receiver_labels_finish_and_keep_the_call_identity(
    tmp_path, engine, name
):
    source, expected = CASES[name]
    app = tmp_path / "app.py"
    app.write_text(source)

    def run_rule():
        linter = LinterVisitor([DangerousCallsRule()], str(app))
        linter.visit(ast.parse(source))
        return linter.findings

    def run_scan_ctx():
        return scan_ctx(tmp_path, [app])

    if engine == "rule":
        findings = _within_deadline(run_rule)
    else:
        findings = _within_deadline(run_scan_ctx)
    actual = {
        (row["rule_id"], row["line"]) for row in findings if row["rule_id"] in SELECTED
    }
    assert actual == expected


def test_listing_policy_is_unchanged_beside_a_growing_loop(tmp_path):
    (tmp_path / "app.py").write_text(
        "import tensorlib\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "def collect(batches, flag):\n" + GROWING_LOOP + "    return stats\n"
        "def total():\n"
        "    return eval('1 + 1')\n"
        "@app.get('/calc')\n"
        "def calc():\n"
        "    return str(eval(request.args['q']))\n"
    )

    def run():
        return json.loads(
            analyze(
                str(tmp_path),
                enable_danger=True,
                enable_dependency_hallucinations=False,
                grep_verify=False,
                grep_cache=False,
                all_advice=False,
            )
        )

    result = _within_deadline(run)
    rows = {
        row["line"]: row
        for row in result.get("danger", [])
        if row["rule_id"] == "SKY-D201"
    }
    assert set(rows) == {16, 19}
    assert rows[16]["low_risk_context"]["reason"] == "constant-argument"
    assert "low_risk_context" not in rows[19]
    assert not is_listed(rows[16], "danger")
    assert is_listed(rows[19], "danger")
