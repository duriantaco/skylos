"""Frozen cloud context/format pairs; fixture source is never executed."""

import hashlib
from pathlib import Path

import pytest

from skylos.benchmarks import cloud
from skylos.core.gatekeeper import check_gate
from skylos.reporting.listing import is_listed


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmarks/cloud/fixtures"
CASES = (
    ("rds_sibling_local_unsafe", "SKY-D401", "aws_db_instance.db", "unsafe", 2, 1),
    ("rds_sibling_local_safe", "SKY-D401", "aws_db_instance.db", "safe", 2, 1),
    (
        "rds_sibling_local_variable_default",
        "SKY-D401",
        "aws_db_instance.db",
        "unknown",
        2,
        1,
    ),
    (
        "modern_ingress_json_unsafe",
        "SKY-D400",
        "aws_vpc_security_group_ingress_rule.admin",
        "unsafe",
        1,
        4,
    ),
    (
        "modern_ingress_json_safe",
        "SKY-D400",
        "aws_vpc_security_group_ingress_rule.admin",
        "safe",
        1,
        4,
    ),
    (
        "modern_ingress_json_numeric_string",
        "SKY-D400",
        "aws_vpc_security_group_ingress_rule.admin",
        "unknown",
        1,
        4,
    ),
)


@pytest.mark.parametrize("name,rule,resource,status,files,line", CASES)
def test_cloud_context_pairs_preserve_exact_policy_and_coverage(
    name, rule, resource, status, files, line
):
    source = FIXTURES / f"aws_{name}"
    before = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()
    }
    report = cloud.scan_case(source)
    assert not report["analysis_errors"]
    summary = report["analysis_summary"]
    assert summary["total_files"] == 0
    assert summary["languages"] == {}
    coverage = summary["configuration_coverage"]["terraform"]
    assert coverage["files_discovered"] == coverage["files_parsed"] == files
    assert coverage["resources"] == 1
    assert coverage["status"] == "complete"
    [check] = coverage["checks"]
    filename = "main.tf.json" if name.startswith("modern_ingress_json") else "main.tf"
    assert (
        check["rule_id"],
        check["resource"],
        Path(check["file"]).name,
        check["line"],
        check["status"],
    ) == (rule, resource, filename, line, status)
    assert coverage["evaluation_status"] == (
        "partial" if status == "unknown" else "complete"
    )
    findings = report.get("danger", [])
    assert [
        (
            f["rule_id"],
            f["resource"],
            Path(f["file"]).name,
            f["line"],
            f["severity"],
        )
        for f in findings
    ] == ([(rule, resource, filename, line, "HIGH")] if status == "unsafe" else [])
    assert all(is_listed(f, "danger") for f in findings)
    passed, _ = check_gate(report, {"gate": {"max_security": 0, "max_high": 0}})
    assert passed is (status != "unsafe")
    assessment = report["assessment"]["risk"]["categories"]["security"]
    assert (
        assessment["status"]
        == {
            "unsafe": "high",
            "safe": "none",
            "unknown": "unknown",
        }[status]
    )
    scored = cloud.evaluate_case(
        {
            "id": f"aws-{name.replace('_', '-')}",
            "expect": {
                "checks": [{"rule_id": rule, "resource": resource, "status": status}]
            },
        },
        report,
    )
    assert scored["failures"] == []
    assert scored["counts"] == {status: 1}
    assert before == {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()
    }


@pytest.mark.parametrize(
    "name,rule",
    [
        ("rds_sibling_local_variable_default", "SKY-D401"),
        ("modern_ingress_json_numeric_string", "SKY-D400"),
    ],
)
def test_required_unknown_cloud_context_pair_fails_closed(name, rule, monkeypatch):
    original = cloud.analyze

    def require_policy(*args, **kwargs):
        return original(*args, **kwargs, required_config_rules=rule)

    monkeypatch.setattr(cloud, "analyze", require_policy)
    report = cloud.scan_case(FIXTURES / f"aws_{name}")
    [error] = report["analysis_errors"]
    assert error["kind"] == "terraform_evaluation_incomplete"
    assert error["error_type"] == "TerraformPolicyUnresolved"
    assert error["required_rule"] == rule
    coverage = report["analysis_summary"]["configuration_coverage"]["terraform"]
    assert coverage["evaluation_status"] == "partial"
    assert coverage["evaluation_counts"]["safe"] == 0


def test_cloud_context_pairs_are_in_the_default_manifest():
    cases = cloud.load_manifest(ROOT / "benchmarks/cloud/manifest.json")["cases"]
    by_id = {case["id"]: case for case in cases}
    for name, rule, resource, status, _, _ in CASES:
        case = by_id[f"aws-{name.replace('_', '-')}"]
        assert case["path"] == f"fixtures/aws_{name}"
        assert case["expect"]["checks"] == [
            {"rule_id": rule, "resource": resource, "status": status}
        ]
