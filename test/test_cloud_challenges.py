"""Independent cloud corpus challenges: invalid reports cannot earn credit."""

import json

import pytest

from skylos.benchmarks.cloud import evaluate_case


def _case():
    return {
        "id": "independent-challenge",
        "expect": {
            "checks": [
                {
                    "rule_id": "SKY-D401",
                    "resource": "aws_db_instance.db",
                    "status": "safe",
                }
            ]
        },
    }


def _report():
    return {
        "analysis_summary": {
            "configuration_coverage": {
                "terraform": {
                    "status": "complete",
                    "files_discovered": 1,
                    "files_parsed": 1,
                    "resources": 1,
                    "checks": [
                        {
                            "rule_id": "SKY-D401",
                            "resource": "aws_db_instance.db",
                            "status": "safe",
                        }
                    ],
                }
            }
        },
        "analysis_errors": [],
        "danger": [],
    }


@pytest.mark.parametrize("mutation", ["zero_parsed", "zero_resources", "parse_error"])
def test_invalid_parser_receipt_cannot_award_safe_credit(mutation):
    raw = _report()
    coverage = raw["analysis_summary"]["configuration_coverage"]["terraform"]
    if mutation == "zero_parsed":
        coverage["files_parsed"] = 0
    elif mutation == "zero_resources":
        coverage["resources"] = 0
    else:
        raw["analysis_errors"] = [{"kind": "terraform_parse_error"}]
    result = evaluate_case(_case(), raw)
    assert result["failures"]
    assert result["counts"].get("safe", 0) == 0


def test_extra_unsafe_check_without_finding_cannot_pass_contract():
    raw = _report()
    coverage = raw["analysis_summary"]["configuration_coverage"]["terraform"]
    coverage["resources"] = 2
    coverage["checks"].append(
        {
            "rule_id": "SKY-D400",
            "resource": "aws_security_group.extra",
            "status": "unsafe",
        }
    )
    result = evaluate_case(_case(), raw)
    assert result["failures"]
    assert result["counts"].get("safe", 0) == 0


def test_policy_unknown_diagnostic_is_not_malformed_parse_evidence():
    expected = {
        "id": "malformed",
        "expect": {"parse_status": "incomplete", "checks": []},
    }
    raw = _report()
    coverage = raw["analysis_summary"]["configuration_coverage"]["terraform"]
    coverage.update(status="incomplete", checks=[])
    raw["analysis_errors"] = [{"kind": "terraform_evaluation_incomplete"}]
    result = evaluate_case(expected, raw)
    assert result["failures"]
    assert result["counts"] == {}


def test_native_file_list_preserves_module_with_aliased_parent_path(tmp_path):
    from skylos.analyzer import analyze

    module = tmp_path / "module"
    module.mkdir()
    (module / "main.tf").write_text(
        'resource "aws_db_instance" "db" { storage_encrypted = false }\n'
    )
    alias = tmp_path / "alias"
    alias.symlink_to(module, target_is_directory=True)
    raw = json.loads(
        analyze(
            [str(alias / "main.tf")],
            enable_danger=True,
            enable_quality=False,
            enable_secrets=False,
            enable_ai_defects=False,
            enable_sca=False,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
        )
    )
    coverage = raw["analysis_summary"]["configuration_coverage"]["terraform"]
    assert coverage["files_discovered"] == coverage["files_parsed"] == 1
    assert coverage["resources"] == 1
    assert any(f["rule_id"] == "SKY-D401" for f in raw.get("danger", []))
    assert raw["analysis_errors"] == []


@pytest.mark.parametrize("required", [False, True])
def test_unavailable_module_policy_is_unknown_and_required_checks_fail(
    tmp_path, required
):
    from skylos.analyzer import analyze

    (tmp_path / "main.tf").write_text(
        'module "database" {\n'
        '  source = "example/database/aws"\n'
        '  version = "1.0.0"\n'
        "}\n"
    )
    raw = json.loads(
        analyze(
            str(tmp_path),
            required_config_rules="SKY-D401" if required else None,
            enable_danger=True,
            enable_quality=False,
            enable_secrets=False,
            enable_ai_defects=False,
            enable_sca=False,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
        )
    )
    coverage = raw["analysis_summary"]["configuration_coverage"]["terraform"]
    assert coverage["files_discovered"] == coverage["files_parsed"] == 1
    assert coverage["resources"] == 0
    assert coverage["evaluation_status"] == "partial"
    assert raw["assessment"]["risk"]["categories"]["security"]["status"] == "unknown"
    assert bool(raw["analysis_errors"]) is required
    assert not any(
        f["rule_id"] in {"SKY-D400", "SKY-D401"} for f in raw.get("danger", [])
    )
