"""`skylos --gate` applies the gate `skylos sync pull` brings from Skylos Cloud.

Cloud evaluates `mode` (zero-new, category, severity, both) with
`by_category` and `by_severity` limits (src/lib/scan-gate-core.ts). The CLI
gate reads the same synced gate, keeps its own floors (any critical security
issue or secret fails) and says when a full scan is not limited to new issues.
A repository's own [tool.skylos.gate] behaves exactly as before.
"""

import copy
import subprocess

import pytest

import skylos.cli as cli
import skylos.core.gatekeeper as gk
from skylos.config import load_config, synced_gate_policy
from skylos.core.cloud_gate import (
    CLOUD_AI_DEFECT_HINT,
    CLOUD_GATE_OFF_NOTE,
    CLOUD_GATE_SCOPE_NOTE,
    UNUSED_CLOUD_GATE_NOTE,
    cloud_category,
    cloud_gate_policy,
    cloud_severity,
)
from skylos.core.gate_outcome import evaluate_gate, gate_record, outcome_text_lines

ZERO_NEW = (
    "gate:\n"
    "  block_ai_defect_severities: [CRITICAL]\n"
    "  by_category: {DEAD_CODE: 0, DEPENDENCY: 0, QUALITY: 0, SECRET: 0, SECURITY: 0}\n"
    "  by_severity: {CRITICAL: 0, HIGH: 0, LOW: 0, MEDIUM: 0}\n"
    "  enabled: true\n"
    "  mode: zero-new\n"
)
ALL_SCANNED = ["security", "quality", "ai_defects", "dead_code", "dependencies", "secrets"]


def _finding(rule_id, severity, file, line=1, message="issue"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": file,
        "line": line,
        "message": message,
    }


def _measurement(rule_id, severity, file):
    finding = _finding(rule_id, severity, file)
    finding["finding_type"] = "advice"
    finding["listing"] = {"version": 1, "listed": False, "reason": "measurement"}
    return finding


def _dependency(advisory, severity, line):
    return _finding(f"SKY-SCA-{advisory}", severity, "requirements.txt", line)


def _demo_results():
    """The `skylos . -a --format json` findings of the acme-policy demo on main."""
    return {
        "danger": [_finding("SKY-D226", "HIGH", "web/checkout.ts", 6)],
        "secrets": [
            _finding("SKY-S101", "CRITICAL", "app/payments.py", 3, "Potential stripe secret detected"),
            _finding("SKY-S101", "CRITICAL", "app/payments.py", 3, "High-entropy value detected"),
        ],
        "quality": [
            _finding("SKY-L014", "HIGH", "app/payments.py", 3),
            _finding("SKY-F102", "MEDIUM", "app/routes.py", 18),
            _measurement("SKY-R101", "MEDIUM", "pyproject.toml"),
            _measurement("SKY-R102", "LOW", "pyproject.toml"),
            _measurement("SKY-R103", "LOW", "pyproject.toml"),
            _measurement("SKY-R104", "LOW", "."),
        ],
        "dependency_vulnerabilities": [
            _dependency("GHSA-68rp-wp8r-4726", "LOW", 1),
            _dependency("GHSA-m2qf-hxjv-5gpq", "HIGH", 1),
            _dependency("PYSEC-2023-62", "UNKNOWN", 1),
            _dependency("PYSEC-2026-2151", "UNKNOWN", 1),
            _dependency("GHSA-9hjg-9r4m-mvj7", "MEDIUM", 2),
            _dependency("GHSA-9wx4-h78v-vm56", "MEDIUM", 2),
            _dependency("GHSA-gc5v-m9x4-r6x2", "MEDIUM", 2),
            _dependency("GHSA-j8r2-6x86-q33q", "MEDIUM", 2),
            _dependency("PYSEC-2023-74", "UNKNOWN", 2),
            _dependency("PYSEC-2026-1872", "UNKNOWN", 2),
            _dependency("PYSEC-2026-1873", "UNKNOWN", 2),
            _dependency("PYSEC-2026-2275", "UNKNOWN", 2),
        ],
        "unused_functions": [
            {"name": "legacy_total", "file": "app/legacy.py", "line": 5},
            {"name": "legacy_tax", "file": "app/legacy.py", "line": 12},
            {"name": "formatPrice", "file": "web/checkout.ts", "line": 9},
        ],
        "unused_imports": [{"name": "os", "file": "app/legacy.py", "line": 2}],
        "analysis_summary": {"grade_categories": list(ALL_SCANNED)},
    }


def _clean_results(**summary):
    return {
        "danger": [],
        "secrets": [],
        "quality": [],
        "dependency_vulnerabilities": [],
        "unused_functions": [],
        "analysis_summary": {"grade_categories": list(ALL_SCANNED), **summary},
    }


@pytest.fixture(autouse=True)
def _no_ci_policy(monkeypatch):
    for name in (
        "SKYLOS_CONFIG_FILE",
        "SKYLOS_POLICY_BASE",
        "SKYLOS_SYNCED_POLICY_FILE",
        "SKYLOS_DIFF_BASE",
        "GITHUB_BASE_REF",
        "GITHUB_STEP_SUMMARY",
    ):
        monkeypatch.delenv(name, raising=False)


def _synced(root, gate_yaml, pyproject=None):
    (root / ".skylos").mkdir(exist_ok=True)
    (root / ".skylos" / "config.yaml").write_text(gate_yaml, encoding="utf-8")  # skylos: ignore[SKY-D324] fixture-owned .skylos directory under tmp_path
    if pyproject is not None:
        (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    return load_config(root)


def _gate_yaml(mode, *, by_category=None, by_severity=None, extra=""):
    lines = ["gate:", "  enabled: true", f"  mode: {mode}"]
    if by_category is not None:
        lines.append(f"  by_category: {by_category}")
    if by_severity is not None:
        lines.append(f"  by_severity: {by_severity}")
    return "\n".join(lines) + "\n" + extra




@pytest.mark.parametrize(
    ("section", "finding", "category"),
    [
        ("danger", {"rule_id": "SKY-L021"}, "SECURITY"),
        ("secrets", {"rule_id": "SKY-S101"}, "SECRET"),
        ("quality", {"rule_id": "SKY-D999"}, "QUALITY"),
        ("dependencies", {"rule_id": "SKY-SCA-GHSA-1"}, "DEPENDENCY"),
        ("dead_code", {"name": "helper"}, "DEAD_CODE"),
        ("ai_defects", {"rule_id": "SKY-D222", "message": "made-up package"}, "SECURITY"),
        ("ai_defects", {"rule_id": "SKY-L012", "message": "phantom symbol reference"}, "QUALITY"),
        ("ai_defects", {"rule_id": "SKY-A118", "message": "Hardcoded token in prompt"}, "SECRET"),
        ("ai_defects", {"rule_id": "SKY-A101", "message": "unused import of a package"}, "DEAD_CODE"),
        ("reliability", {"rule_id": "SKY-D250", "message": "no timeout"}, "SECURITY"),
        ("reliability", {"rule_id": "SKY-Q301", "message": "complex"}, "QUALITY"),
        ("custom_rules", {"rule_id": "CUSTOM-VIBE-002", "message": "open route"}, "QUALITY"),
        ("custom_rules", {"rule_id": "SKY-SC001", "message": "contract"}, "SECURITY"),
        ("ai_defects", {"rule_id": "SKY-U001", "message": "x"}, "DEAD_CODE"),
    ],
)
def test_cloud_category_follows_cloud_sarif_ingest(section, finding, category):
    assert cloud_category(section, finding) == category


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("critical", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("medium", "MEDIUM"),
        ("LOW", "LOW"),
        ("UNKNOWN", "MEDIUM"),
        (None, "MEDIUM"),
        ("WARN", "MEDIUM"),
        ("warning", "MEDIUM"),
        ("INFO", "LOW"),
        ("error", "HIGH"),
        ("bogus", "MEDIUM"),
    ],
)
def test_cloud_severity_follows_the_upload_contract(severity, expected):
    assert cloud_severity({"severity": severity}) == expected




def test_zero_new_counts_every_category_at_zero(tmp_path):
    config = _synced(tmp_path, ZERO_NEW)

    passed, reasons = gk.check_gate(_demo_results(), config)

    assert passed is False
    assert reasons == [
        "1 security issue (max: 0)",
        "2 secrets (max: 0)",
        "2 quality issues (max: 0)",
        "4 dead code issues (max: 0)",
        "12 dependency vulnerabilities (max: 0)",
    ]


def test_zero_new_pass_line_shows_the_cloud_limits(tmp_path):
    config = _synced(tmp_path, ZERO_NEW)
    results = _clean_results(diff_scoped=True)

    assert gk.check_gate(results, config) == (True, [])
    assert gk._passed_gate_summary(results, config, strict=False) == (
        "Skylos Cloud policy: 0 critical security (limit 0), 0 security (limit 0), "
        "0 secrets (limit 0), 0 quality (limit 0), 0 dead code (limit 0), "
        "0 dependency vulnerabilities (limit 0)",
        None,
    )


def test_pass_line_names_cloud_categories_the_scan_did_not_run(tmp_path):
    config = _synced(tmp_path, ZERO_NEW)
    results = {
        "unused_functions": [],
        "analysis_summary": {"grade_categories": ["dead_code"], "diff_scoped": True},
    }

    details, _hint = gk._passed_gate_summary(results, config, strict=False)

    assert details == (
        "Skylos Cloud policy: 0 dead code (limit 0), security, secrets, quality, "
        "dependency vulnerabilities not scanned (add -a)"
    )


def test_critical_security_issue_is_listed_once(tmp_path):
    config = _synced(tmp_path, ZERO_NEW)
    sql = _finding("SKY-D211", "CRITICAL", "app/db.py", 24, "Possible SQL injection")

    passed, reasons = gk.check_gate({"danger": [sql]}, config)

    assert passed is False
    assert reasons == ["1 critical security issue"]
    assert reasons[0].issues == [sql]


def test_category_mode_uses_cloud_limits_and_keeps_the_secret_floor(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml(
            "category",
            by_category="{SECURITY: 1, SECRET: 9, QUALITY: 6, DEAD_CODE: 3, DEPENDENCY: 20}",
            by_severity="{CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0}",
        ),
    )

    passed, reasons = gk.check_gate(_demo_results(), config)

    assert passed is False
    assert reasons == ["2 secrets (max: 0)", "4 dead code issues (max: 3)"]
    assert (
        "Your Skylos Cloud policy allows 9 new secrets, but any secret still "
        "fails the local gate."
    ) in gk.gate_config_notes(config)


def test_category_mode_pass_line_shows_each_limit(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml(
            "category",
            by_category="{SECURITY: 2, SECRET: 4, QUALITY: 1, DEAD_CODE: 0, DEPENDENCY: 3}",
        ),
    )
    results = _clean_results(diff_scoped=True)
    results["danger"] = [
        _finding("SKY-D226", "HIGH", "a.ts", 1),
        _finding("SKY-D226", "HIGH", "b.ts", 1),
    ]
    results["quality"] = [_finding("SKY-Q301", "MEDIUM", "c.py", 1)]

    assert gk.check_gate(results, config) == (True, [])
    assert gk._passed_gate_summary(results, config, strict=False)[0] == (
        "Skylos Cloud policy: 0 critical security (limit 0), 2 security (limit 2), "
        "0 secrets (limit 0), 1 quality (limit 1), 0 dead code (limit 0), "
        "0 dependency vulnerabilities (limit 3)"
    )


def test_severity_mode_counts_every_finding_by_cloud_severity(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml(
            "severity",
            by_category="{SECURITY: 0, SECRET: 0, QUALITY: 0, DEAD_CODE: 0, DEPENDENCY: 0}",
            by_severity="{CRITICAL: 0, HIGH: 5, MEDIUM: 5, LOW: 5}",
        ),
    )

    passed, reasons = gk.check_gate(_demo_results(), config)

    assert passed is False
    assert reasons == [
        "2 critical severity issues (max: 0)",
        "15 medium severity issues (max: 5)",
        "2 secrets (max: 0)",
    ]


def test_severity_mode_pass_line(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml("severity", by_severity="{CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 5}"),
    )
    results = _clean_results(diff_scoped=True)

    assert gk._passed_gate_summary(results, config, strict=False)[0] == (
        "Skylos Cloud policy: 0 critical security (limit 0), 0 critical (limit 0), "
        "0 high (limit 1), 0 medium (limit 2), 0 low (limit 5), 0 secrets (limit 0)"
    )


def test_both_mode_applies_category_and_severity_limits(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml(
            "both",
            by_category="{SECURITY: 99, SECRET: 99, QUALITY: 99, DEAD_CODE: 99, DEPENDENCY: 99}",
            by_severity="{CRITICAL: 9, HIGH: 9, MEDIUM: 9, LOW: 0}",
        ),
    )

    passed, reasons = gk.check_gate(_demo_results(), config)

    assert passed is False
    assert reasons == [
        "2 secrets (max: 0)",
        "15 medium severity issues (max: 9)",
        "1 low severity issue (max: 0)",
    ]


def test_block_secrets_counts_cloud_secret_findings_in_severity_mode(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml(
            "severity",
            by_severity="{CRITICAL: 9, HIGH: 9, MEDIUM: 9, LOW: 9}",
            extra="  block_secrets: true\n",
        ),
    )
    token = _finding("SKY-A118", "LOW", "agent.py", 4, "Hardcoded token in prompt")

    passed, reasons = gk.check_gate({"ai_defects": [token]}, config)

    assert passed is False
    assert reasons == ["1 secret (max: 0)"]




def test_loose_cloud_limits_cannot_relax_critical_security_or_secrets(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml(
            "both",
            by_category="{SECURITY: 50, SECRET: 50, QUALITY: 50, DEAD_CODE: 50, DEPENDENCY: 50}",
            by_severity="{CRITICAL: 50, HIGH: 50, MEDIUM: 50, LOW: 50}",
        ),
    )
    critical = _finding("SKY-D212", "CRITICAL", "run.py", 3)
    secret = _finding("SKY-S101", "CRITICAL", "keys.py", 1)

    passed, reasons = gk.check_gate({"danger": [critical], "secrets": [secret]}, config)

    assert passed is False
    assert reasons == ["1 critical security issue", "1 secret (max: 0)"]


def test_severity_mode_cannot_relax_secrets(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml("severity", by_severity="{CRITICAL: 9, HIGH: 9, MEDIUM: 9, LOW: 9}"),
    )

    passed, reasons = gk.check_gate(
        {"secrets": [_finding("SKY-S101", "CRITICAL", "keys.py", 1)]}, config
    )

    assert passed is False
    assert reasons == ["1 secret (max: 0)"]


def test_critical_reliability_and_ai_defects_are_critical_security_in_cloud(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml(
            "category",
            by_category="{SECURITY: 9, SECRET: 0, QUALITY: 9, DEAD_CODE: 9, DEPENDENCY: 9}",
            extra="  block_ai_defect_severities: []\n",
        ),
    )
    made_up = _finding("SKY-D222", "CRITICAL", "app.py", 1, "made-up package")
    no_timeout = _finding("SKY-D250", "CRITICAL", "client.py", 2, "no timeout")

    passed, reasons = gk.check_gate(
        {"ai_defects": [made_up], "reliability": [no_timeout]}, config
    )

    assert passed is False
    assert reasons == ["2 critical security issues"]


def test_ai_code_severity_rule_applies_outside_zero_new(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml(
            "category",
            by_category="{SECURITY: 9, SECRET: 0, QUALITY: 9, DEAD_CODE: 9, DEPENDENCY: 9}",
            extra="  block_ai_defect_severities: [CRITICAL]\n",
        ),
    )
    phantom = _finding("SKY-L012", "CRITICAL", "app.py", 7, "phantom symbol reference")

    passed, reasons = gk.check_gate({"ai_defects": [phantom]}, config)

    assert passed is False
    assert reasons == ["1 critical AI-code issue (SKY-L012 phantom symbol reference)"]
    assert reasons[0].hint == CLOUD_AI_DEFECT_HINT


def test_zero_new_counts_ai_code_issues_in_their_category_once(tmp_path):
    config = _synced(tmp_path, ZERO_NEW)
    phantom = _finding("SKY-L012", "CRITICAL", "app.py", 7, "phantom symbol reference")

    passed, reasons = gk.check_gate({"ai_defects": [phantom]}, config)

    assert passed is False
    assert reasons == ["1 quality issue (max: 0)"]


def test_security_control_regression_still_fails_a_loose_cloud_gate(tmp_path):
    config = _synced(
        tmp_path,
        _gate_yaml(
            "both",
            by_category="{SECURITY: 9, SECRET: 0, QUALITY: 9, DEAD_CODE: 9, DEPENDENCY: 9}",
            by_severity="{CRITICAL: 9, HIGH: 9, MEDIUM: 9, LOW: 9}",
        ),
    )
    regression = {
        "rule_id": "SKY-L021",
        "kind": "security_regression",
        "severity": "HIGH",
        "file": "views.py",
        "line": 4,
    }

    passed, reasons = gk.check_gate({"quality": [regression]}, config)

    assert passed is False
    assert reasons == [
        "1 security control regression (security controls must be preserved)"
    ]




def test_malformed_gate_reads_as_zero_new(tmp_path):
    config = _synced(
        tmp_path,
        "gate:\n"
        "  enabled: 'yes'\n"
        "  mode: strictest\n"
        "  by_category: lots\n"
        "  by_severity: {HIGH: many}\n",
    )

    assert cloud_gate_policy(synced_gate_policy(config)) == {
        "enabled": True,
        "mode": "zero-new",
        "by_category": dict.fromkeys(
            ("SECURITY", "SECRET", "QUALITY", "DEAD_CODE", "DEPENDENCY"), 0
        ),
        "by_severity": dict.fromkeys(("CRITICAL", "HIGH", "MEDIUM", "LOW"), 0),
        "block_secrets": False,
    }
    passed, reasons = gk.check_gate(
        {"quality": [_finding("SKY-Q301", "LOW", "a.py")]}, config
    )
    assert passed is False
    assert reasons == ["1 quality issue (max: 0)"]


def test_malformed_limits_read_as_zero_and_numbers_round_down(tmp_path):
    config = _synced(
        tmp_path,
        "gate:\n"
        "  mode: category\n"
        "  enabled: 0\n"
        "  by_category: {SECURITY: -3, QUALITY: true, DEAD_CODE: 2.9, DEPENDENCY: '7'}\n",
    )

    policy = cloud_gate_policy(synced_gate_policy(config))

    assert policy["enabled"] is True
    assert policy["by_category"] == {
        "SECURITY": 0,
        "SECRET": 0,
        "QUALITY": 0,
        "DEAD_CODE": 2,
        "DEPENDENCY": 0,
    }


def test_list_mode_reads_as_zero_new(tmp_path):
    config = _synced(tmp_path, "gate:\n  mode: [category]\n  by_category: {QUALITY: 9}\n")

    passed, reasons = gk.check_gate(
        {"quality": [_finding("SKY-Q301", "LOW", "a.py")]}, config
    )

    assert passed is False
    assert reasons == ["1 quality issue (max: 0)"]




@pytest.mark.parametrize("enabled", ["false", "'false'", "' FALSE '"])
def test_disabled_cloud_gate_keeps_the_built_in_limits(tmp_path, enabled):
    config = _synced(tmp_path, ZERO_NEW.replace("enabled: true", f"enabled: {enabled}"))
    highs = [_finding("SKY-D226", "HIGH", f"h{index}.ts") for index in range(3)]
    results = {
        "danger": highs,
        "quality": [_finding("SKY-Q301", "LOW", "a.py")],
        "analysis_summary": {"grade_categories": list(ALL_SCANNED)},
    }

    assert gk.check_gate(results, config) == (True, [])
    assert gk._passed_gate_summary(results, config, strict=False) == (
        "0 critical (limit 0), 3 high (limit 5), 3 security (limit 10), "
        "1 quality (limit 10)",
        "3 high issues are allowed by the default limits. To block them, set "
        "max_high = 0 under [tool.skylos.gate] in pyproject.toml.",
    )
    assert CLOUD_GATE_OFF_NOTE in gk.gate_config_notes(config)
    assert gk.cloud_gate_scope_note(results, config) is None
    passed, reasons = gk.check_gate(
        {"secrets": [_finding("SKY-S101", "CRITICAL", "k.py")]}, config
    )
    assert (passed, reasons) == (False, ["1 secret (max: 0)"])




def test_repository_gate_with_cloud_keys_is_not_a_cloud_gate(tmp_path):
    (tmp_path / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        "[tool.skylos.gate]\n"
        'mode = "zero-new"\n'
        "max_high = 7\n"
        "[tool.skylos.gate.by_category]\n"
        "QUALITY = 0\n",
        encoding="utf-8",
    )
    config = load_config(tmp_path)
    highs = [_finding("SKY-D226", "HIGH", f"h{index}.ts") for index in range(3)]
    results = {
        "danger": highs,
        "quality": [_finding("SKY-Q301", "LOW", "a.py"), _finding("SKY-Q301", "LOW", "b.py")],
        "analysis_summary": {"grade_categories": list(ALL_SCANNED)},
    }

    assert synced_gate_policy(config) is None
    assert gk.check_gate(results, config) == (True, [])
    assert gk._passed_gate_summary(results, config, strict=False) == (
        "0 critical (limit 0), 3 high (limit 7), 3 security (limit 10), "
        "2 quality (limit 10)",
        None,
    )
    assert gk.cloud_gate_scope_note(results, config) is None


def test_plain_dict_config_is_never_a_cloud_gate():
    results = _demo_results()
    config = {"gate": copy.deepcopy(cloud_gate_policy({"mode": "zero-new"}))}

    assert gk.check_gate(results, config) == gk.check_gate(results, {})


def test_synced_gate_without_cloud_keys_keeps_cli_limits(tmp_path):
    config = _synced(tmp_path, "gate:\n  enabled: true\n  max_high: 0\n")

    passed, reasons = gk.check_gate(
        {"danger": [_finding("SKY-D226", "HIGH", "a.ts")]}, config
    )

    assert passed is False
    assert reasons == ["1 high severity issue (max: 0)"]




@pytest.mark.parametrize(
    ("summary", "expected"),
    [
        ({}, CLOUD_GATE_SCOPE_NOTE),
        ({"diff_scoped": True}, None),
        ({"baseline_scoped": True}, None),
        ({"comparison_scope": {"changed_files_only": True}}, None),
    ],
)
def test_scope_note_only_for_scans_not_limited_to_new_issues(tmp_path, summary, expected):
    config = _synced(tmp_path, ZERO_NEW)

    assert gk.cloud_gate_scope_note({"analysis_summary": summary}, config) == expected


def test_scope_note_wording():
    assert CLOUD_GATE_SCOPE_NOTE == (
        "Skylos Cloud counts only new issues. Run skylos . -a --gate --diff "
        "origin/main to check what this branch changes."
    )


def test_strict_gate_has_no_scope_note(tmp_path):
    config = _synced(tmp_path, ZERO_NEW)

    assert gk.cloud_gate_scope_note({}, config, strict=True) is None


def test_failed_outcome_carries_the_scope_note_everywhere(tmp_path):
    config = _synced(tmp_path, ZERO_NEW)

    outcome = evaluate_gate(_demo_results(), config)

    assert outcome.verdict == "failed"
    assert outcome.hint == CLOUD_GATE_SCOPE_NOTE
    lines = outcome_text_lines(outcome)
    assert lines[0] == "Quality Gate: FAILED"
    assert lines[-1] == f"   {CLOUD_GATE_SCOPE_NOTE}"
    assert gate_record(outcome, scope="local_configured_policy")["hint"] == (
        CLOUD_GATE_SCOPE_NOTE
    )


def test_passing_full_scan_carries_the_scope_note(tmp_path):
    config = _synced(tmp_path, ZERO_NEW)

    outcome = evaluate_gate(_clean_results(), config)

    assert outcome.verdict == "passed"
    assert outcome.hint == CLOUD_GATE_SCOPE_NOTE
    assert outcome_text_lines(outcome)[1] == f"   {CLOUD_GATE_SCOPE_NOTE}"


def test_rich_failed_gate_prints_the_scope_note_after_the_reasons(tmp_path, capsys):
    config = _synced(tmp_path, ZERO_NEW)

    exit_code = gk.run_gate_interaction(
        result={"quality": [_finding("SKY-Q301", "LOW", "a.py")]},
        config=config,
    )

    out = capsys.readouterr().out
    assert exit_code == 1
    assert out.index("1 quality issue (max: 0)") < out.index(CLOUD_GATE_SCOPE_NOTE)




def test_operator_policy_file_sets_the_cloud_gate_in_ci(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    _synced(
        project,
        _gate_yaml(
            "category",
            by_category="{SECURITY: 99, SECRET: 0, QUALITY: 99, DEAD_CODE: 99, DEPENDENCY: 99}",
        ),
    )
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "config.yaml").write_text(ZERO_NEW, encoding="utf-8")  # skylos: ignore[SKY-D324] fixture-owned operator policy under tmp_path
    monkeypatch.setenv("SKYLOS_SYNCED_POLICY_FILE", str(operator / "config.yaml"))

    config = load_config(project)
    passed, reasons = gk.check_gate(
        {"quality": [_finding("SKY-Q301", "LOW", "a.py")]}, config
    )

    assert synced_gate_policy(config)["mode"] == "zero-new"
    assert (passed, reasons) == (False, ["1 quality issue (max: 0)"])




@pytest.fixture(autouse=True)
def _outside_ci(monkeypatch):
    from skylos.core.report_context import _CI_MARKERS

    for name in _CI_MARKERS:
        monkeypatch.delenv(name, raising=False)


def _git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def base_repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text("[tool.skylos.gate]\nmax_quality = 0\n", encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    (root / "app.py").write_text("def main():\n    return 1\n", encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "pyproject.toml", "app.py")
    _git(root, "commit", "-qm", "base")
    return root


def _base_config(root, monkeypatch):
    monkeypatch.setenv("SKYLOS_POLICY_BASE", _git(root, "rev-parse", "HEAD"))
    return load_config(root)


def test_policy_base_uses_the_untracked_policy_sync_pull_wrote(base_repo, monkeypatch):
    _synced(base_repo, ZERO_NEW)

    config = _base_config(base_repo, monkeypatch)

    assert synced_gate_policy(config)["mode"] == "zero-new"
    assert UNUSED_CLOUD_GATE_NOTE not in gk.gate_config_notes(config)
    passed, reasons = gk.check_gate(
        {"unused_functions": [{"name": "helper", "file": "app.py", "line": 1}]}, config
    )
    assert (passed, reasons) == (False, ["1 dead code issue (max: 0)"])


def test_policy_base_ignores_an_untracked_policy_in_ci(base_repo, monkeypatch):
    _synced(base_repo, _gate_yaml("category", by_category="{SECURITY: 99, SECRET: 0, QUALITY: 99, DEAD_CODE: 99, DEPENDENCY: 99}"))
    monkeypatch.setenv("CI", "true")

    config = _base_config(base_repo, monkeypatch)

    assert synced_gate_policy(config) is None
    assert config["gate"]["max_quality"] == 0
    assert UNUSED_CLOUD_GATE_NOTE in gk.gate_config_notes(config)
    passed, reasons = gk.check_gate(
        {"quality": [_finding("SKY-Q301", "LOW", "a.py")]}, config
    )
    assert (passed, reasons) == (False, ["1 quality issue (max: 0)"])


def test_policy_base_ignores_a_branch_committed_policy(base_repo, monkeypatch):
    _git(base_repo, "checkout", "-q", "-b", "agent")
    _synced(base_repo, "gate:\n  enabled: false\n  mode: zero-new\n")
    _git(base_repo, "add", ".skylos/config.yaml")
    _git(base_repo, "commit", "-qm", "loosen the gate")
    monkeypatch.setenv("SKYLOS_POLICY_BASE", _git(base_repo, "rev-parse", "main"))

    config = load_config(base_repo)

    assert synced_gate_policy(config) is None
    assert config["gate"]["max_quality"] == 0
    assert UNUSED_CLOUD_GATE_NOTE in gk.gate_config_notes(config)
    passed, reasons = gk.check_gate(
        {"quality": [_finding("SKY-Q301", "LOW", "a.py")]}, config
    )
    assert (passed, reasons) == (False, ["1 quality issue (max: 0)"])


def test_policy_base_ignores_a_staged_policy(base_repo, monkeypatch):
    _synced(base_repo, ZERO_NEW)
    _git(base_repo, "add", ".skylos/config.yaml")

    config = _base_config(base_repo, monkeypatch)

    assert synced_gate_policy(config) is None
    assert UNUSED_CLOUD_GATE_NOTE in gk.gate_config_notes(config)


def test_policy_base_ignores_a_policy_behind_a_symlinked_folder(
    base_repo, tmp_path, monkeypatch
):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "config.yaml").write_text("gate:\n  enabled: false\n  mode: zero-new\n", encoding="utf-8")  # skylos: ignore[SKY-D324] fixture-owned folder under tmp_path
    (base_repo / ".skylos").symlink_to(outside, target_is_directory=True)

    config = _base_config(base_repo, monkeypatch)

    assert synced_gate_policy(config) is None
    assert config["gate"]["max_quality"] == 0


def test_policy_base_keeps_a_committed_base_policy(base_repo, monkeypatch):
    _synced(
        base_repo,
        _gate_yaml("severity", by_severity="{CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 3}"),
    )
    _git(base_repo, "add", ".skylos/config.yaml")
    _git(base_repo, "commit", "-qm", "commit the Cloud policy")
    _git(base_repo, "checkout", "-q", "-b", "agent")
    _synced(base_repo, "gate:\n  enabled: false\n  mode: zero-new\n")

    monkeypatch.setenv("SKYLOS_POLICY_BASE", _git(base_repo, "rev-parse", "main"))
    config = load_config(base_repo)

    assert synced_gate_policy(config)["mode"] == "severity"
    assert UNUSED_CLOUD_GATE_NOTE not in gk.gate_config_notes(config)



DB_BASE = (
    "import sqlite3\n"
    "\n"
    'DB_PATH = "shop.db"\n'
    "\n"
    "\n"
    "def connect():\n"
    "    return sqlite3.connect(DB_PATH)\n"
    "\n"
    "\n"
    "def fetch_order(order_id):\n"
    "    with connect() as conn:\n"
    "        row = conn.execute(\n"
    '            "SELECT id, customer, total FROM orders WHERE id = ?", (order_id,)\n'
    "        ).fetchone()\n"
    "    return row\n"
)
DB_SEARCH = (
    "\n"
    "\n"
    "def search_orders(customer):\n"
    "    with connect() as conn:\n"
    "        rows = conn.execute(\n"
    "            f\"SELECT id, customer, total FROM orders WHERE customer LIKE '%{customer}%'\"\n"
    "        ).fetchall()\n"
    "    return rows\n"
)
MAIN = (
    "from db import fetch_order, search_orders\n"
    "\n"
    "\n"
    'if __name__ == "__main__":\n'
    "    print(fetch_order(1))\n"
)
LEGACY = "def legacy_total(items):\n    return sum(items)\n"


@pytest.fixture
def scan_repo(tmp_path, monkeypatch):
    root = tmp_path / "shop"
    root.mkdir()
    (root / "db.py").write_text(DB_BASE, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    (root / "main.py").write_text(MAIN.replace(", search_orders", ""), encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    (root / "legacy.py").write_text(LEGACY, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "db.py", "main.py", "legacy.py")
    _git(root, "commit", "-qm", "orders")
    _synced(root, ZERO_NEW)
    monkeypatch.chdir(root)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr("skylos.cloud.sync.get_token", lambda: None)

    def no_upload(*args, **kwargs):
        pytest.fail("gate tests must not upload anything")

    monkeypatch.setattr(cli, "upload_report", no_upload)
    return root


def _scan(monkeypatch, capsys, *args):
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            ".",
            "--danger",
            "--secrets",
            "--quality",
            "--no-provenance",
            "--no-grep-verify",
            "--no-clipboard",
            *args,
        ],
    )
    capsys.readouterr()
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def _verdict_block(text):
    lines = [line.rstrip() for line in text.rstrip().splitlines()]
    starts = [index for index, line in enumerate(lines) if "Quality Gate:" in line]
    assert starts, text
    return lines[starts[-1] :]


def test_full_scan_fails_on_every_category_and_says_cloud_counts_new(
    scan_repo, monkeypatch, capsys
):
    exit_code, out, _err = _scan(monkeypatch, capsys, "--gate")

    block = _verdict_block(out)
    assert exit_code == 1
    assert block[0].endswith("Quality Gate: FAILED")
    assert "   • 1 dead code issue (max: 0)" in block
    assert any("legacy.py:1" in line for line in block)
    assert block[-1] == f"   {CLOUD_GATE_SCOPE_NOTE}"


def test_diff_scan_of_an_unchanged_branch_passes_with_cloud_limits(
    scan_repo, monkeypatch, capsys
):
    exit_code, out, _err = _scan(monkeypatch, capsys, "--gate", "--diff", "main")

    block = _verdict_block(out)
    assert exit_code == 0
    assert block[0] == (
        "✅ Quality Gate: PASSED: Skylos Cloud policy: 0 critical security "
        "(limit 0), 0 security (limit 0), 0 secrets (limit 0), 0 quality "
        "(limit 0), 0 dead code (limit 0), dependency vulnerabilities not "
        "scanned (add -a)"
    )
    assert CLOUD_GATE_SCOPE_NOTE not in out


def test_diff_scan_fails_on_the_new_sql_injection(scan_repo, monkeypatch, capsys):
    _git(scan_repo, "checkout", "-q", "-b", "agent/order-search")
    (scan_repo / "db.py").write_text(DB_BASE + DB_SEARCH, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    (scan_repo / "main.py").write_text(MAIN, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    _git(scan_repo, "commit", "-qam", "search orders")

    exit_code, out, _err = _scan(monkeypatch, capsys, "--gate", "--diff", "main")

    block = _verdict_block(out)
    assert exit_code == 1
    assert block[1] == "   • 1 critical security issue"
    assert block[2].strip().startswith("SKY-D211  db.py:20")
    assert not any("security issue (max: 0)" in line for line in block)
    assert CLOUD_GATE_SCOPE_NOTE not in out


def test_json_gate_carries_the_scope_note(scan_repo, monkeypatch, capsys):
    import json

    exit_code, out, _err = _scan(monkeypatch, capsys, "--gate", "--format", "json")

    gate = json.loads(out)["gate"]
    assert exit_code == 1
    assert gate["passed"] is False
    assert "1 dead code issue (max: 0)" in gate["reasons"]
    assert gate["hint"] == CLOUD_GATE_SCOPE_NOTE


def test_without_the_synced_file_the_gate_is_unchanged(scan_repo, monkeypatch, capsys):
    (scan_repo / ".skylos" / "config.yaml").unlink()

    exit_code, out, _err = _scan(monkeypatch, capsys, "--gate")

    block = _verdict_block(out)
    assert exit_code == 0
    assert block[0].startswith(
        "✅ Quality Gate: PASSED: 0 critical (limit 0), 0 high (limit 5), "
        "0 security (limit 10)"
    )
    assert "Skylos Cloud" not in out
