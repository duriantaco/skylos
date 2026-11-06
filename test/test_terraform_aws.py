"""Frozen AWS declaration outcomes, including unknown and inapplicable inputs."""

import json
from pathlib import Path
import sys

import pytest

from skylos.rules.config.terraform.scanner import scan_terraform


FIXTURES = Path(__file__).resolve().parents[1] / "benchmarks/cloud/fixtures"
FROZEN_CASES = [
    ("aws_sg_world_ssh", "SKY-D400", "unsafe"),
    ("aws_sg_private_admin", "SKY-D400", "safe"),
    ("aws_sg_world_https", "SKY-D400", "safe"),
    ("aws_sg_egress_all", "SKY-D400", "not_applicable"),
    ("aws_sg_ipv6_all", "SKY-D400", "unsafe"),
    ("aws_sg_unknown_cidr", "SKY-D400", "unknown"),
    ("aws_sg_world_mixed_unknown", "SKY-D400", "unsafe"),
    ("aws_sg_split_world", "SKY-D400", "unsafe"),
    ("aws_rds_unencrypted", "SKY-D401", "unsafe"),
    ("aws_rds_encrypted_json", "SKY-D401", "safe"),
    ("aws_rds_missing_encryption", "SKY-D401", "unknown"),
    ("aws_rds_snapshot", "SKY-D401", "unknown"),
    ("aws_rds_replica", "SKY-D401", "unknown"),
    ("aws_provider_unresolved", "SKY-D401", "unknown"),
    ("aws_count_zero", "SKY-D401", "not_applicable"),
]


def _scan(root, **kwargs):
    coverage, errors = {}, []
    findings = scan_terraform(
        root, configuration_coverage=coverage, analysis_errors=errors, **kwargs
    )
    return findings, coverage["terraform"], errors


def _write(tmp_path, source):
    (tmp_path / "main.tf").write_text(source, encoding="utf-8")
    return tmp_path


def _rule_source(lines):
    return (
        'resource "aws_security_group_rule" "admin" {\n'
        '  type = "ingress"\n' + "\n".join(f"  {line}" for line in lines) + "\n}\n"
    )


@pytest.mark.parametrize("directory,rule,status", FROZEN_CASES)
def test_frozen_cloud_fixture_has_actual_parse_and_policy_outcome(
    directory, rule, status
):
    findings, coverage, errors = _scan(FIXTURES / directory)
    assert errors == []
    assert coverage["files_discovered"] == coverage["files_parsed"] == 1
    assert coverage["resources"] == 1
    [check] = coverage["checks"]
    assert check["rule_id"] == rule
    assert check["status"] == status
    assert check["file"].endswith(("main.tf", "main.tf.json"))
    assert check["line"] > 0
    assert coverage["evaluation_counts"][status] == 1
    assert coverage["evaluation_status"] == (
        "partial" if status == "unknown" else "complete"
    )
    assert len(findings) == int(status == "unsafe")
    if findings:
        [finding] = findings
        assert finding["rule_id"] == rule
        assert finding["resource"] == check["resource"]
        assert finding["severity"] == "HIGH"
        assert finding["domain"] == "cloud"
        assert finding["metadata"]["terraform"]["scope"] == "declaration_policy"


def test_malformed_cloud_fixture_is_incomplete_and_cannot_be_safe():
    findings, coverage, errors = _scan(FIXTURES / "aws_malformed")
    assert findings == []
    assert errors
    assert all(error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE" for error in errors)
    assert coverage["files_discovered"] == 1
    assert coverage["files_parsed"] == 0
    assert coverage["checks"] == []
    assert coverage["evaluation_status"] == "partial"
    assert coverage["evaluation_counts"]["safe"] == 0


@pytest.mark.parametrize(
    "lines,status",
    [
        (
            [
                "protocol = -1",
                "from_port = 0",
                "to_port = 0",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unsafe",
        ),
        (
            [
                'protocol = "all"',
                "from_port = 443",
                "to_port = 443",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unsafe",
        ),
        (
            [
                "protocol = 6",
                "from_port = 1",
                "to_port = 65535",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unsafe",
        ),
        (
            [
                'protocol = "udp"',
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "safe",
        ),
        (
            [
                'protocol = "icmp"',
                "from_port = -1",
                "to_port = -1",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "safe",
        ),
        (
            [
                "protocol = 999",
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unknown",
        ),
        (
            [
                'protocol = "madeup"',
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unknown",
        ),
        (
            [
                "protocol = var.protocol",
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unknown",
        ),
        (
            ['protocol = "tcp"', "to_port = 22", 'cidr_blocks = ["0.0.0.0/0"]'],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = false",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 23",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = -1",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 65536",
                'cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["invalid"]',
            ],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["::/0"]',
            ],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'ipv6_cidr_blocks = ["0.0.0.0/0"]',
            ],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = "0.0.0.0/0"',
            ],
            "unknown",
        ),
        (
            ['protocol = "tcp"', "from_port = 22", "to_port = 22", "cidr_blocks = []"],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0", "invalid"]',
            ],
            "unknown",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/1"]',
            ],
            "safe",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'ipv6_cidr_blocks = ["::/1", "8000::/1"]',
            ],
            "unsafe",
        ),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'source_security_group_id = "sg-source"',
            ],
            "safe",
        ),
        (['protocol = "tcp"', "from_port = 22", "to_port = 22", "self = true"], "safe"),
        (
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'prefix_list_ids = ["pl-unknown"]',
            ],
            "unknown",
        ),
    ],
)
def test_protocol_port_and_cidr_edges_have_frozen_outcomes(tmp_path, lines, status):
    root = _write(tmp_path, _rule_source(lines))
    findings, coverage, errors = _scan(root)
    assert errors == []
    assert coverage["checks"][0]["status"] == status
    assert len(findings) == int(status == "unsafe")


@pytest.mark.parametrize(
    "source",
    [
        """resource "aws_vpc_security_group_ingress_rule" "admin" {
  ip_protocol = "tcp"
  from_port = 22
  to_port = 22
  cidr_ipv4 = "0.0.0.0/0"
  cidr_ipv6 = "::/0"
}
""",
        """resource "aws_vpc_security_group_ingress_rule" "admin" {
  ip_protocol = "tcp"
  from_port = 22
  to_port = 22
  cidr_ipv4 = "0.0.0.0/0"
  referenced_security_group_id = "sg-source"
}
""",
        _rule_source(
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0"]',
                "self = true",
            ]
        ),
        _rule_source(
            [
                'protocol = "tcp"',
                "from_port = 22",
                "to_port = 22",
                'cidr_blocks = ["0.0.0.0/0"]',
                'source_security_group_id = "sg-source"',
            ]
        ),
    ],
)
def test_mutually_exclusive_source_declarations_are_unknown(tmp_path, source):
    _write(tmp_path, source)
    findings, coverage, errors = _scan(tmp_path)
    assert findings == errors == []
    assert coverage["checks"][0]["status"] == "unknown"


@pytest.mark.parametrize(
    "attribute,status",
    [
        ("storage_encrypted = true", "safe"),
        ("storage_encrypted = false", "unsafe"),
        ('storage_encrypted = "false"', "unknown"),
        ("storage_encrypted = 0", "unknown"),
        ("storage_encrypted = null", "unknown"),
        ("storage_encrypted = var.encryption", "unknown"),
        ("", "unknown"),
        ('storage_encrypted = true\nsnapshot_identifier = "snapshot"', "unknown"),
        ('storage_encrypted = false\nreplicate_source_db = "source"', "unknown"),
        (
            'storage_encrypted = false\nrestore_to_point_in_time { source_db_instance_identifier = "source" }',
            "unknown",
        ),
        ('storage_encrypted = false\ns3_import { bucket_name = "backup" }', "unknown"),
    ],
)
def test_encryption_requires_literal_direct_creation_evidence(
    tmp_path, attribute, status
):
    _write(tmp_path, 'resource "aws_db_instance" "db" {\n' + attribute + "\n}\n")
    findings, coverage, errors = _scan(tmp_path)
    assert errors == []
    assert coverage["checks"][0]["status"] == status
    assert len(findings) == int(status == "unsafe")


@pytest.mark.parametrize(
    "attribute,status",
    [
        ("count = 0", "not_applicable"),
        ("count = 2", "unsafe"),
        ("count = var.instances", "unknown"),
        ("count = -1", "unknown"),
        ("count = false", "unknown"),
        ("for_each = {}", "not_applicable"),
        ('for_each = { first = "value" }', "unsafe"),
        ("for_each = var.instances", "unknown"),
        ("count = 1\nfor_each = {}", "unknown"),
    ],
)
def test_instance_presence_is_required_before_policy_findings(
    tmp_path, attribute, status
):
    _write(
        tmp_path,
        'resource "aws_db_instance" "db" {\n'
        + attribute
        + "\n  storage_encrypted = false\n}\n",
    )
    findings, coverage, errors = _scan(tmp_path)
    assert errors == []
    assert coverage["checks"][0]["status"] == status
    assert len(findings) == int(status == "unsafe")


def test_custom_provider_cannot_inherit_aws_policy_semantics(tmp_path):
    _write(
        tmp_path,
        """terraform {
  required_providers { aws = { source = "example/custom" } }
}
resource "aws_db_instance" "db" { storage_encrypted = false }
""",
    )
    findings, coverage, errors = _scan(tmp_path)
    assert findings == errors == []
    assert coverage["checks"][0]["status"] == "unknown"


def test_dynamic_inline_ingress_does_not_turn_unknown_into_safe(tmp_path):
    _write(
        tmp_path,
        """resource "aws_security_group" "admin" {
  dynamic "ingress" {
    for_each = var.rules
    content { protocol = "tcp" }
  }
}
""",
    )
    findings, coverage, errors = _scan(tmp_path)
    assert findings == errors == []
    assert coverage["checks"][0]["status"] == "unknown"


def test_known_unsafe_inline_rule_survives_another_unresolved_rule(tmp_path):
    _write(
        tmp_path,
        """resource "aws_security_group" "admin" {
  ingress {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = var.sources
  }
}
""",
    )
    findings, coverage, errors = _scan(tmp_path)
    assert errors == []
    assert len(findings) == 1
    assert coverage["checks"][0]["status"] == "unsafe"


@pytest.mark.parametrize("required", ["SKY-D400", {"SKY-D400", "SKY-DEP001"}])
def test_explicit_required_rule_rejects_unresolved_policy(required):
    findings, coverage, errors = _scan(
        FIXTURES / "aws_sg_unknown_cidr", required_rules=required
    )
    assert findings == []
    assert [error["required_rule"] for error in errors] == ["SKY-D400"]
    assert coverage["evaluation_status"] == "partial"


def test_unrelated_required_rule_does_not_create_terraform_failure():
    findings, coverage, errors = _scan(
        FIXTURES / "aws_sg_unknown_cidr", required_rules={"SKY-GPU001", "SKY-DEP001"}
    )
    assert findings == errors == []
    assert coverage["checks"][0]["status"] == "unknown"


def test_ignored_rule_cannot_emit_a_finding_or_a_safe_check():
    findings, coverage, errors = _scan(
        FIXTURES / "aws_sg_world_ssh", ignore={"SKY-D400"}
    )
    assert findings == errors == []
    assert coverage["checks"] == []
    assert coverage["evaluation_counts"]["safe"] == 0


def test_unsupported_resource_identity_prevents_complete_coverage(tmp_path):
    _write(tmp_path, 'resource "aws_s3_bucket" "bucket" {}\n')
    findings, coverage, errors = _scan(tmp_path)
    assert findings == errors == []
    assert coverage["unsupported_resource_count"] == 1
    assert coverage["unsupported_resources"][0]["resource"] == "aws_s3_bucket.bucket"
    assert coverage["evaluation_status"] == "partial"


@pytest.mark.parametrize(
    "source", ['"example/database/aws"', '"./database"', "var.source"]
)
@pytest.mark.parametrize("required", [None, "SKY-D401"])
def test_module_calls_remain_unknown_without_applied_inputs(tmp_path, source, required):
    _write(tmp_path, f'module "database" {{ source = {source} }}\n')
    findings, coverage, errors = _scan(tmp_path, required_rules=required)
    assert findings == []
    assert coverage["resources"] == 0
    assert coverage["unresolved_module_count"] == 1
    assert coverage["evaluation_status"] == "partial"
    assert coverage["module_calls"][0]["name"] == "database"
    assert coverage["module_calls"][0]["status"] == "unknown"
    assert bool(errors) == (required is not None)
    if errors:
        assert errors[0]["required_rule"] == "SKY-D401"


def test_empty_terraform_scope_is_inapplicable_without_safe_credit(tmp_path):
    (tmp_path / "notes.txt").write_text("storage_encrypted = false\n")
    findings, coverage, errors = _scan(tmp_path)
    assert findings == errors == []
    assert coverage["evaluation_status"] == "not_applicable"
    assert coverage["checks"] == []


def test_missing_parser_cannot_turn_unsafe_fixture_into_a_safe_result(monkeypatch):
    monkeypatch.setitem(sys.modules, "hcl2", None)
    findings, coverage, errors = _scan(FIXTURES / "aws_sg_world_ssh")
    assert findings == []
    assert errors
    assert coverage["evaluation_status"] == "partial"
    assert coverage["evaluation_counts"]["safe"] == 0


def test_tf_json_ignores_policy_words_in_plain_strings(tmp_path):
    (tmp_path / "main.tf.json").write_text(
        json.dumps(
            {
                "output": {"example": {"value": "storage_encrypted = false"}},
                "resource": {"aws_db_instance": {"db": {"storage_encrypted": True}}},
            }
        )
    )
    findings, coverage, errors = _scan(tmp_path)
    assert findings == errors == []
    assert coverage["checks"][0]["status"] == "safe"


@pytest.mark.parametrize("required", [None, "SKY-D400", "SKY-D401", "SKY-DEP001"])
@pytest.mark.parametrize("has_terraform", [False, True])
def test_uncertain_optional_discovery_is_partial_and_required_policy_fails_closed(
    tmp_path, monkeypatch, required, has_terraform
):
    import skylos.rules.config.terraform.model as model

    names = ["app.py"]
    (tmp_path / "app.py").write_text("VALUE=1\n")
    if has_terraform:
        _write(tmp_path, 'resource "aws_db_instance" "db" {storage_encrypted=false}\n')
        names.append("main.tf")
    hidden = tmp_path / "hidden"

    def incomplete_walk(root, *, onerror, **kwargs):
        yield str(tmp_path), ["hidden"], names
        onerror(PermissionError(13, "fixture denied", str(hidden)))

    monkeypatch.setattr(model.os, "walk", incomplete_walk)
    findings, coverage, errors = _scan(tmp_path, required_rules=required)
    assert coverage["status"] == "incomplete"
    assert coverage["evaluation_status"] == "partial"
    assert coverage["discovery_errors"][0]["file"] == str(hidden)
    assert [finding["rule_id"] for finding in findings] == (
        ["SKY-D401"] if has_terraform else []
    )
    if required in {"SKY-D400", "SKY-D401"}:
        assert [error["required_rule"] for error in errors] == [required]
        assert errors[0]["error_type"] == "TerraformPolicyUnresolved"
        assert errors[0]["file"] == str(hidden)
    else:
        assert errors == []
    if not has_terraform:
        assert coverage["evaluation_counts"]["safe"] == 0
