"""Gate settings that cannot work say so; the ones that can are no longer dropped."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from skylos.core import gatekeeper as gk
from skylos.reporting.listing import (
    explicit_rule_ids,
    is_listed,
    unrecognized_rule_ids,
)

CRITICAL = {"rule_id": "SKY-D212", "severity": "CRITICAL", "file": "app.py", "line": 3}
SECRET = {"rule_id": "SKY-S101", "severity": "HIGH", "file": "app.py", "line": 4}
ADVISORY_ID = "SKY-SCA-GHSA-ABCD-1234-WXYZ"
DEV_ONLY_ADVISORY = {
    "rule_id": ADVISORY_ID,
    "severity": "HIGH",
    "file": "requirements-dev.txt",
    "line": 1,
    "low_risk_context": {"reason": "dev-only-dependency"},
    "listing": {"version": 1, "listed": False, "reason": "low-risk-context"},
}
LICENSE = {
    "rule_id": "SKY-SCA-LIC001",
    "severity": "HIGH",
    "file": "requirements.txt",
    "line": 2,
}


class Provenance:
    agent_files = ["ai.py"]
    scan_root = None


def test_relaxed_critical_and_secret_limits_are_named_and_still_fail():
    config = {"gate": {"fail_on_critical": False, "max_critical": 5, "max_secrets": 3}}

    notes = gk.gate_config_notes(config)
    passed, reasons = gk.check_gate({"danger": [CRITICAL], "secrets": [SECRET]}, config)

    assert notes == [
        "[tool.skylos.gate] fail_on_critical = false, max_critical = 5, "
        "max_secrets = 3 have no effect: any critical security issue and any "
        "secret always fail the gate."
    ]
    assert passed is False
    assert "1 critical security issue" in reasons
    assert "1 secret (max: 0)" in reasons


def test_one_relaxed_limit_reads_as_singular():
    assert gk.gate_config_notes({"gate": {"max_secrets": 2}}) == [
        "[tool.skylos.gate] max_secrets = 2 has no effect: any critical "
        "security issue and any secret always fail the gate."
    ]


def test_settings_that_already_match_the_floor_add_no_note():
    for gate in (
        {},
        {"fail_on_critical": True, "max_critical": 0, "max_secrets": 0},
        {"max_high": 50, "max_quality": 100},
        {"max_critical": "5", "max_secrets": True},
    ):
        assert gk.gate_config_notes({"gate": gate}) == []
    assert gk.gate_config_notes({"gate": "strict"}) == []
    assert gk.gate_config_notes(None) == []


def test_multi_part_rule_ids_are_kept_and_others_are_named():
    config = {
        "gate": {
            "rules": [
                "SKY-SCA-LIC001",
                "sky-sca-ghsa-abcd-1234-wxyz",
                "SKY-L027",
                "D211",
                "CUSTOM-ROUTE",
                7,
            ]
        }
    }

    assert explicit_rule_ids(config) == {
        "SKY-SCA-LIC001",
        "SKY-SCA-GHSA-ABCD-1234-WXYZ",
        "SKY-L027",
    }
    assert unrecognized_rule_ids(config["gate"]["rules"]) == [
        "D211",
        "CUSTOM-ROUTE",
        "7",
    ]
    assert gk.gate_config_notes(config) == [
        f"[tool.skylos.gate] rules entry '{entry}' is not a Skylos rule ID such "
        "as SKY-D211, so it is not enforced."
        for entry in ("D211", "CUSTOM-ROUTE", "7")
    ]
    assert explicit_rule_ids({"select": "SKY-SCA-LIC001, SKY-D211"}) == {
        "SKY-SCA-LIC001",
        "SKY-D211",
    }
    assert explicit_rule_ids({"gate": {"rules": ["SKY-", "SKY--X", "SKY-A-"]}}) == set()


def test_naming_a_dependency_advisory_lists_its_dev_only_row():
    rules = explicit_rule_ids({"gate": {"rules": [ADVISORY_ID.lower()]}})

    assert is_listed(DEV_ONLY_ADVISORY, "dependencies") is False
    assert is_listed(DEV_ONLY_ADVISORY, "dependencies", explicit_rules=rules) is True
    assert is_listed(LICENSE, "dependencies") is True


def test_dependency_findings_stay_counted_by_the_gate_either_way():
    results = {"dependency_vulnerabilities": [DEV_ONLY_ADVISORY, LICENSE]}

    for gate in ({}, {"rules": ["SKY-SCA-LIC001", ADVISORY_ID]}):
        passed, reasons = gk.check_gate(results, {"gate": gate})
        assert passed is False
        assert reasons == ["2 dependency vulnerabilities (max: 0)"]


def test_require_defend_is_rejected_with_the_replacement():
    for agent in ({"require_defend": True}, {"min_defend_score": 70}):
        passed, reasons = gk.check_gate(
            {"danger": [], "quality": [], "secrets": []},
            {"gate": {"agent": agent}},
            provenance=Provenance(),
        )

        assert passed is False
        (reason,) = reasons
        assert str(reason) == (
            "Agent gate: require_defend and min_defend_score are not supported; "
            "this gate never reads skylos defend results"
        )
        assert "skylos defend . --min-score 70 --fail-on critical" in reason.hint
        assert "run skylos defend)" not in str(reason)


def _cli_env():
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "TMPDIR", "LANG")
        if key in os.environ
    }
    env.update(
        PYTHONPATH=str(Path(__file__).resolve().parents[1]),
        SKYLOS_NO_TELEMETRY="1",
        SKYLOS_JOBS="1",
        SKYLOS_CUSTOM_RULES="[]",
    )
    return env


def _skylos(root, *args):
    return subprocess.run(
        [str(Path(sys.executable).with_name("skylos")), *args],
        cwd=root,
        env=_cli_env(),
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
    )


APP = (
    "import subprocess\n"
    "from flask import request\n\n\n"
    "def run():\n"
    '    return subprocess.check_output(request.args.get("cmd"), shell=True)\n'
)
RELAXED = (
    "[tool.skylos.gate]\n"
    "fail_on_critical = false\n"
    "max_critical = 5\n"
    'rules = ["D211"]\n'
    "max_high = 100\n"
    "max_security = 100\n"
    "max_quality = 100\n"
)


def test_scan_and_cicd_gate_print_the_notes(tmp_path):
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "pyproject.toml").write_text(RELAXED)
    report = tmp_path / "report.json"

    plain = _skylos(tmp_path, ".", "--danger", "--json")
    scan = _skylos(
        tmp_path, ".", "--danger", "--gate", "--format", "json", "-o", str(report)
    )
    gate = _skylos(tmp_path, "cicd", "gate", "--input", str(report))

    assert "has no effect" not in plain.stderr and "have no effect" not in plain.stderr
    json.loads(plain.stdout)
    assert scan.returncode == 1, scan.stdout + scan.stderr
    assert (
        "Warning: [tool.skylos.gate] fail_on_critical = false, max_critical = 5 have no effect"
        in scan.stderr
    )
    assert "rules entry 'D211' is not a Skylos rule ID" in scan.stderr
    assert gate.returncode == 1, gate.stdout + gate.stderr
    assert "max_critical = 5 have no effect" in gate.stdout
    assert "Quality Gate: FAILED" in gate.stdout
