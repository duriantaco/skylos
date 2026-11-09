"""Coverage must prove a configuration was checked, including unknown controls."""

from copy import deepcopy
from pathlib import Path
import json

import pytest

from skylos.benchmarks.cloud import evaluate_case, load_manifest, run_manifest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks/cloud/manifest.json"


def report(status="safe"):
    return {
        "analysis_summary": {
            "total_files": 0,
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
                            "status": status,
                        }
                    ],
                }
            },
        },
        "analysis_errors": [],
        "danger": [],
    }


def case(status="safe"):
    return {
        "id": "contract",
        "expect": {
            "checks": [
                {
                    "rule_id": "SKY-D401",
                    "resource": "aws_db_instance.db",
                    "status": status,
                }
            ]
        },
    }


@pytest.mark.parametrize("status", ["safe", "unknown", "not_applicable"])
def test_distinct_outcomes_do_not_require_dummy_app_sources(status):
    outcome = evaluate_case(case(status), report(status))
    assert outcome["failures"] == []
    assert outcome["counts"] == {status: 1}


@pytest.mark.parametrize(
    "mutation",
    [
        "no_coverage",
        "zero_parsed",
        "bool_count",
        "unknown_instead",
        "missing_checks",
        "error",
    ],
)
def test_absence_cannot_earn_safe_credit(mutation):
    raw = report()
    tf = raw["analysis_summary"]["configuration_coverage"]["terraform"]
    if mutation == "no_coverage":
        raw["analysis_summary"].pop("configuration_coverage")
    elif mutation == "zero_parsed":
        tf["files_parsed"] = 0
    elif mutation == "bool_count":
        tf["files_parsed"] = True
    elif mutation == "unknown_instead":
        tf["checks"][0]["status"] = "unknown"
    elif mutation == "missing_checks":
        tf.pop("checks")
    else:
        raw["analysis_errors"] = [{"kind": "read_error"}]
    assert evaluate_case(case(), raw)["failures"]


def test_unsafe_check_requires_a_matching_finding():
    raw = report("unsafe")
    assert evaluate_case(case("unsafe"), raw)["failures"]
    raw["danger"] = [{"rule_id": "SKY-D401", "resource": "aws_db_instance.db"}]
    assert not evaluate_case(case("unsafe"), raw)["failures"]


def test_malformed_contract_requires_diagnostic_and_file_receipt():
    expected = {"id": "bad", "expect": {"parse_status": "incomplete", "checks": []}}
    raw = report()
    assert evaluate_case(expected, raw)["failures"]
    tf = raw["analysis_summary"]["configuration_coverage"]["terraform"]
    tf.update(status="incomplete", files_parsed=0, checks=[])
    raw["analysis_errors"] = [{"kind": "terraform_parse_error"}]
    assert not evaluate_case(expected, raw)["failures"]


def test_default_cloud_contracts_native_analyzer():
    summary = run_manifest(MANIFEST)
    assert summary["case_count"] == 22
    assert summary["failure_count"] == 0, [
        (c["id"], c["failures"]) for c in summary["cases"] if c["failures"]
    ]
    assert summary["outcome_counts"] == {
        "unsafe": 7,
        "safe": 5,
        "unknown": 7,
        "not_applicable": 2,
    }
    for result in summary["cases"]:
        assert result["configuration_coverage"]["files_discovered"] > 0


def test_manifest_rejects_path_escape_and_empty_complete_cases(tmp_path):
    manifest = deepcopy(json.loads(MANIFEST.read_text()))
    manifest["cases"] = [manifest["cases"][0]]
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    manifest["cases"][0]["path"] = "fixture"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    assert load_manifest(path)
    manifest["cases"][0]["expect"]["checks"] = []
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="complete cases need"):
        load_manifest(path)
    manifest["cases"][0]["path"] = "../outside"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="inside manifest"):
        load_manifest(path)


def test_unknown_policy_is_visible_in_native_assessment():
    from skylos.benchmarks.cloud import scan_case

    raw = scan_case(ROOT / "benchmarks/cloud/fixtures/aws_rds_missing_encryption")
    assert raw["analysis_summary"]["total_files"] == 0
    assert raw["analysis_errors"] == []
    assert raw["assessment"]["risk"]["categories"]["security"]["status"] == "unknown"
    assert (
        "terraform_policy_coverage_incomplete"
        in raw["assessment"]["coverage"]["reasons"]
    )


def test_mixed_source_scope_keeps_configuration_coverage(tmp_path):
    from skylos.analyzer import analyze

    (tmp_path / "app.py").write_text('print("hello")\n')
    (tmp_path / "main.tf").write_text(
        'resource "aws_db_instance" "db" { storage_encrypted = false }\n'
    )
    raw = json.loads(
        analyze(
            str(tmp_path),
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
    assert raw["analysis_summary"]["languages"] == {"Python": 1}
    coverage = raw["analysis_summary"]["configuration_coverage"]["terraform"]
    assert coverage["files_parsed"] == 1
    assert coverage["resources"] == 1
    assert any(f.get("rule_id") == "SKY-D401" for f in raw.get("danger", []))


@pytest.mark.parametrize("rule", ["SKY-D400", "SKY-D401"])
def test_new_policy_catalog_and_documented_severity_agree(rule):
    from skylos.rules.catalog import get_rule_catalog

    entry = next(item for item in get_rule_catalog() if item["id"] == rule)
    assert entry["severity"] == "HIGH"
    assert entry["finding_type"] == "review"
    assert (
        f"| {rule.removeprefix('SKY-')} | HIGH |"
        in (ROOT / "dictionary.md").read_text()
    )
