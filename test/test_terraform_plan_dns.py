import json

import pytest

from skylos.commands.rules_cmd import run_rules_command
from skylos.rules.config.terraform.plan_dns import evaluate

NAME = "archive.example.test"
ENDPOINT = NAME + ".s3.us-west-2.amazonaws.com"
BUCKET = {"bucket": NAME, "bucket_regional_domain_name": ENDPOINT}
RECORD = {"type": "CNAME", "fqdn": NAME, "records": [ENDPOINT]}


def resource(kind, actions, before, after, address=None):
    return {
        "address": address or kind + ".example",
        "type": kind,
        "mode": "managed",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": actions, "before": before, "after": after},
    }


def plan(*rows):
    return {
        "format_version": "1.2",
        "complete": True,
        "errored": False,
        "resource_changes": list(rows),
    }


def deletion():
    return resource("aws_s3_bucket", ["delete"], BUCKET, None)


def retained(**fields):
    record = {**RECORD, **fields}
    return resource("aws_route53_record", ["no-op"], record, record.copy())


@pytest.mark.parametrize(
    "field,endpoint",
    [
        ("bucket_domain_name", NAME + ".s3.amazonaws.com"),
        ("bucket_regional_domain_name", ENDPOINT),
        ("website_endpoint", NAME + ".s3-website-us-west-2.amazonaws.com"),
        ("website_endpoint", NAME + ".s3-website.us-east-2.amazonaws.com"),
    ],
)
def test_plan_cli_links_only_the_evidence_locations(tmp_path, capsys, field, endpoint):
    bucket = deletion()
    bucket["change"]["before"] = {"bucket": NAME, field: endpoint}
    data = plan(bucket, retained(fqdn=NAME.upper() + ".", records=[endpoint + "."]))
    data["variables"] = {"secret": {"value": "private-value"}}
    path = tmp_path / "arbitrary-export.json"
    path.write_text(json.dumps(data))
    assert run_rules_command(["terraform-plan", str(path), "--format", "json"]) == 1
    output = capsys.readouterr().out
    assert NAME not in output and "private-value" not in output
    report = json.loads(output)
    assert report["status"] == "complete" and not report["errors"]
    (finding,) = report["findings"]
    assert (finding["rule_id"], finding["bucket_change"], finding["dns_change"]) == (
        "SKY-D414",
        "/resource_changes/0",
        "/resource_changes/1",
    )


def test_separate_website_configuration_corroborates_endpoint():
    endpoint = NAME + ".s3-website-us-west-2.amazonaws.com"
    before = {"bucket": NAME, "website_endpoint": endpoint}
    config = resource("aws_s3_bucket_website_configuration", ["delete"], before, None)
    hits, errors = evaluate(plan(config, deletion(), retained(records=[endpoint])))
    assert not errors and len(hits) == 1


@pytest.mark.parametrize(
    "rows",
    [
        [retained()],
        [deletion()],
        [deletion(), retained(fqdn="different.example.test")],
        [deletion(), retained(type="TXT")],
        [deletion(), retained(records=[ENDPOINT + ".invalid"])],
        [deletion(), retained(records=["other.s3.us-west-2.amazonaws.com"])],
        [deletion(), resource("aws_route53_record", ["delete"], RECORD, None)],
        [
            deletion(),
            resource(
                "aws_route53_record",
                ["update"],
                RECORD,
                {**RECORD, "records": ["new.example.test"]},
            ),
        ],
        [resource("aws_s3_bucket", ["create", "delete"], BUCKET, BUCKET), retained()],
        [resource("aws_s3_bucket", ["forget"], BUCKET, None), retained()],
        [
            deletion(),
            retained(),
            resource(
                "aws_s3_bucket",
                ["create"],
                None,
                BUCKET,
                "module.new.aws_s3_bucket.site",
            ),
        ],
        [
            {**deletion(), "provider_name": "registry.example.test/other/aws"},
            retained(),
        ],
        [deletion(), {**retained(), "mode": "data"}],
        [
            deletion(),
            retained(),
            {
                **resource("awscc_s3_bucket", ["create"], None, {"bucket_name": NAME}),
                "provider_name": "registry.terraform.io/hashicorp/awscc",
            },
        ],
    ],
)
def test_lifecycle_controls(rows):
    assert evaluate(plan(*rows)) == ([], [])


def test_unknowns_cannot_be_scored_clean_or_as_a_confirmed_match():
    new = resource(
        "aws_s3_bucket", ["create"], None, {}, "module.other.aws_s3_bucket.new"
    )
    new["change"]["after_unknown"] = {"bucket": True}
    dns = retained()
    dns["change"]["after_unknown"] = {"records": [True]}
    for data in (
        plan(deletion(), retained(), new),
        plan(deletion(), dns),
        plan(
            deletion(), retained(records=[NAME + ".s3-website-us-west-2.amazonaws.com"])
        ),
    ):
        findings, errors = evaluate(data)
        assert findings == [] and errors
    # An unrelated unknown bucket cannot prevent evaluation when no bucket is deleted.
    assert evaluate(plan(retained(), new)) == ([], [])


def test_new_cname_with_unknown_fqdn_and_unrelated_destination_stays_quiet():
    record = resource(
        "aws_route53_record",
        ["create"],
        None,
        {"type": "CNAME", "records": ["other.example.test"]},
    )
    record["change"]["after_unknown"] = {"fqdn": True}
    assert evaluate(plan(deletion(), record)) == ([], [])


def test_bucket_replacement_that_releases_old_name_is_still_a_deletion():
    replaced = resource(
        "aws_s3_bucket", ["create", "delete"], BUCKET, {"bucket": "new.example.test"}
    )
    findings, errors = evaluate(plan(replaced, retained()))
    assert len(findings) == 1 and not errors


def test_delete_first_replacement_reviews_interval_only_with_unchanged_cname():
    replacement = resource("aws_s3_bucket", ["delete", "create"], BUCKET, BUCKET)
    findings, errors = evaluate(plan(replacement, retained()))
    assert not errors and len(findings) == 1
    assert "before recreating the same shared name" in findings[0]["message"]
    for dns in (
        retained(fqdn="elsewhere.example.test"),
        resource("aws_route53_record", ["delete"], RECORD, None),
        resource("aws_route53_record", ["create"], None, RECORD),
        resource("aws_route53_record", ["update"], RECORD, {**RECORD, "ttl": 30}),
    ):
        assert evaluate(plan(replacement, dns)) == ([], [])


def test_distinct_deposed_bucket_is_checked_against_the_current_bucket_name():
    deposed = {**deletion(), "deposed": "deadbeef"}
    other = {**BUCKET, "bucket": "other.example.test"}
    current = resource("aws_s3_bucket", ["no-op"], other, other)
    findings, errors = evaluate(plan(current, deposed, retained()))
    assert not errors and len(findings) == 1
    assert findings[0]["bucket_change"] == "/resource_changes/1"
    assert "recreating" not in findings[0]["message"]
    current = resource("aws_s3_bucket", ["no-op"], BUCKET, BUCKET)
    assert evaluate(plan(current, deposed, retained())) == ([], [])


@pytest.mark.parametrize("explicit_namespace", [True, False])
def test_account_regional_bucket_name_stays_reserved(explicit_namespace):
    name = "media.example.test-111122223333-us-west-2-an"
    endpoint = name + ".s3.us-west-2.amazonaws.com"
    bucket = {"bucket": name, "bucket_regional_domain_name": endpoint}
    if explicit_namespace:
        bucket["bucket_namespace"] = "account-regional"
    dns = retained(fqdn=name, records=[endpoint])
    for actions, after in ((["delete"], None), (["delete", "create"], bucket)):
        assert evaluate(
            plan(resource("aws_s3_bucket", actions, bucket, after), dns)
        ) == ([], [])


@pytest.mark.parametrize(
    "invalid",
    [
        {},
        [],
        {"format_version": "1.2", "values": {}},
        {**plan(), "format_version": "2.0"},
        {**plan(), "complete": False},
        {**plan(), "complete": None},
        {**plan(), "errored": True},
        {**plan(), "deferred_changes": [{}]},
        {**plan(), "resource_changes": None},
        plan({}),
        plan(deletion(), deletion()),
        plan({**deletion(), "mode": 42}),
        plan(
            {
                **deletion(),
                "change": {"actions": ["delete"], "before": {"bucket": None}},
            }
        ),
        plan(
            {
                **retained(),
                "change": {"actions": ["no-op"], "before": {}, "after": RECORD},
            }
        ),
    ],
)
def test_partial_or_malformed_plan_returns_error(tmp_path, capsys, invalid):
    path = tmp_path / "input.json"
    path.write_text(json.dumps(invalid))
    assert run_rules_command(["terraform-plan", str(path), "--format", "json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "incomplete" and report["errors"]


def test_cli_rejects_duplicate_keys_and_missing_files(tmp_path, capsys):
    path = tmp_path / "plan.json"
    for raw in (None, '{"secret":"private-value","secret":2}', "{"):
        if raw:
            path.write_text(raw)
        assert run_rules_command(["terraform-plan", str(path), "--format", "json"]) == 2
        assert "private-value" not in capsys.readouterr().out


def test_complete_unrelated_plan_returns_zero(tmp_path, capsys):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan(retained())))
    assert run_rules_command(["terraform-plan", str(path)]) == 0
    assert "No matching S3 deletion" in capsys.readouterr().out


def test_empty_export_can_omit_resource_changes_when_other_views_agree():
    data = plan()
    del data["resource_changes"]
    data.update(configuration={"root_module": {}}, planned_values={"root_module": {}})
    assert evaluate(data) == ([], [])
    data["prior_state"] = {"values": {"root_module": {}}}
    assert evaluate(data) == ([], [])
    data["prior_state"]["values"]["root_module"] = {"resources": [BUCKET]}
    with pytest.raises(ValueError, match="resource_changes"):
        evaluate(data)


def test_select_in_normal_scan_requests_explicit_plan(monkeypatch, capsys):
    from skylos import cli

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", ".", "--select", "sky-d414", "--gate", "--format", "json"],
    )
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert "skylos rules terraform-plan PLAN.json" in capsys.readouterr().err
