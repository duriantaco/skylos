"""Review an explicitly supplied Terraform plan for a retained S3 DNS record."""

from __future__ import annotations

import json
import re

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.config.terraform.model import (
    _invalid_json_constant,
    _strict_json_object,
)

RULE_ID = "SKY-D414"
_AWS = "registry.terraform.io/hashicorp/aws"
_AWSCC = "registry.terraform.io/hashicorp/awscc"
_MAX_PLAN_BYTES = 32 * 1024 * 1024
_INCOMPLETE = "The plan leaves a bucket or DNS value needed for this check unresolved."
_DIRECT_ENDPOINT = re.compile(
    r"(?P<bucket>.+)\.s3(?:-website)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?\Z"
)


class InvalidPlan(ValueError):
    """A public validation message safe to print without exposing plan contents."""


def _hostname(value):
    if not isinstance(value, str):
        return ""
    return value.removesuffix(".").lower()


def _bucket_endpoints(before):
    name = _hostname(before.get("bucket"))
    if not name:
        raise InvalidPlan("Missing bucket identity on a planned deletion.")
    # Terraform records the actual provider-assigned endpoints in prior state.
    # Some AWS regions use a hyphen in their website endpoint and others a dot.
    endpoints = {name + ".s3.amazonaws.com"}
    for field in (
        "bucket_domain_name",
        "bucket_regional_domain_name",
        "website_endpoint",
    ):
        host = _hostname(before.get(field))
        endpoint = _DIRECT_ENDPOINT.fullmatch(host)
        if endpoint and endpoint["bucket"] == name:
            endpoints.add(host)
    return name, endpoints


def _unknown(change, key):
    mask = change.get("after_unknown", {})
    if mask is True:
        return True
    if not isinstance(mask, dict):
        if mask is False:
            return False
        raise InvalidPlan("Invalid Terraform unknown-value mask.")
    flag = mask.get(key, False)
    if isinstance(flag, list):
        return any(flag)
    return bool(flag)


def _resources(plan):
    version = plan.get("format_version") if isinstance(plan, dict) else None
    if not isinstance(version, str) or not re.fullmatch(r"1\.[0-9]+", version):
        raise InvalidPlan("Expected Terraform plan JSON with format_version 1.x.")
    if (
        plan.get("complete") is not True
        or plan.get("errored") is not False
        or plan.get("deferred_changes")
        or plan.get("deferred_action_invocations")
    ):
        raise InvalidPlan(
            "Expected a complete Terraform plan with no planning errors or deferred changes."
        )
    changes = plan.get("resource_changes")
    if "resource_changes" not in plan and _empty_plan(plan):
        return
    if not isinstance(changes, list):
        raise InvalidPlan("Missing Terraform resource_changes array.")
    seen = set()
    for index, row in enumerate(changes):
        if not isinstance(row, dict) or not all(
            isinstance(row.get(key), str) and row[key]
            for key in ("mode", "address", "type", "provider_name")
        ):
            raise InvalidPlan("Invalid resource entry in Terraform plan.")
        key = row["address"], row.get("deposed")
        if not isinstance(key[1], (str, type(None))) or key in seen:
            raise InvalidPlan("Invalid or duplicate Terraform resource identity.")
        seen.add(key)
        change = row.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        if (
            not isinstance(actions, list)
            or not actions
            or not all(isinstance(action, str) for action in actions)
        ):
            raise InvalidPlan("Missing Terraform resource actions.")
        if row["mode"] not in ("managed", "data"):
            raise InvalidPlan("Unsupported Terraform resource mode.")
        if row["mode"] == "managed":
            yield index, row, change


def _empty_plan(plan):
    # Terraform omits empty change arrays and omits prior_state on first use.
    # Require the other exported views to corroborate the empty inventory.
    config = plan.get("configuration")
    planned = plan.get("planned_values")
    if not isinstance(config, dict) or not isinstance(planned, dict):
        return False
    root_config = config.get("root_module")
    if (
        not isinstance(root_config, dict)
        or root_config.get("resources")
        or root_config.get("module_calls")
    ):
        return False
    roots = [planned.get("root_module")]
    if "prior_state" in plan:
        prior = plan["prior_state"]
        if not isinstance(prior, dict) or not isinstance(prior.get("values"), dict):
            return False
        roots.append(prior["values"].get("root_module"))
    return all(
        isinstance(root, dict)
        and not root.get("resources")
        and not root.get("child_modules")
        for root in roots
    )


def evaluate(plan):
    """Return findings and completeness errors. Evidence points inside the local plan."""
    deleted = {}
    replacements = {}
    survivors = {}
    records = []
    unknown_bucket = False
    website_endpoints = {}
    for index, row, change in _resources(plan):
        provider, kind = row["provider_name"], row["type"]
        if (provider, kind) not in {
            (_AWS, "aws_s3_bucket"),
            (_AWSCC, "awscc_s3_bucket"),
            (_AWS, "aws_route53_record"),
            (_AWS, "aws_s3_bucket_website_configuration"),
        }:
            continue
        actions = change["actions"]
        if actions not in (
            ["no-op"],
            ["create"],
            ["update"],
            ["delete"],
            ["delete", "create"],
            ["create", "delete"],
            ["forget"],
            ["create", "forget"],
        ):
            raise InvalidPlan("Unsupported action for an S3 bucket or Route 53 record.")
        before, after = change.get("before"), change.get("after")
        if actions != ["create"] and not isinstance(before, dict):
            raise InvalidPlan("Missing prior values for a planned AWS resource.")
        if actions == ["create"] and before is not None:
            raise InvalidPlan("Unexpected prior values for a newly created resource.")
        if kind == "aws_s3_bucket_website_configuration":
            if (
                before
                and _hostname(before.get("bucket"))
                and _hostname(before.get("website_endpoint"))
            ):
                name, endpoints = _bucket_endpoints(before)
                website_endpoints.setdefault(name, set()).update(endpoints)
            continue
        if "delete" in actions and kind == "aws_s3_bucket":
            name, endpoints = _bucket_endpoints(before)
            # AWS reserves the -an suffix for account-regional names. Those
            # names remain reserved to the account after a bucket is deleted.
            if before.get("bucket_namespace") in (None, "global") and not name.endswith(
                "-an"
            ):
                deleted[name] = (index, endpoints)
                if (
                    actions == ["delete", "create"]
                    and not row.get("deposed")
                    and isinstance(after, dict)
                    and _hostname(after.get("bucket")) == name
                    and not _unknown(change, "bucket")
                    and after.get("bucket_namespace") in (None, "global")
                ):
                    replacements[name] = (index, endpoints)
        if actions in (["delete"], ["forget"]):
            if after is not None:
                raise InvalidPlan("Unexpected after values for a removed resource.")
            if actions == ["delete"]:
                continue
            # A forgotten resource continues to exist outside Terraform.
            after = before
        if not isinstance(after, dict):
            raise InvalidPlan("Missing after values for a planned AWS resource.")
        if actions == ["no-op"] and any(
            before.get(k) != after.get(k)
            for k in ("bucket", "bucket_name", "fqdn", "type", "records")
        ):
            raise InvalidPlan(
                "Inconsistent before and after values for an unchanged resource."
            )
        if actions == ["create", "forget"] and kind != "aws_route53_record":
            retained_name = _hostname(before.get("bucket") or before.get("bucket_name"))
            if retained_name:
                survivors.setdefault(retained_name, set()).add(index)
            else:
                unknown_bucket = True
        if kind == "aws_route53_record":
            records.append((index, change, after))
        else:
            key = "bucket" if kind == "aws_s3_bucket" else "bucket_name"
            name = _hostname(after.get(key))
            if not name or _unknown(change, key):
                unknown_bucket = True
            else:
                survivors.setdefault(name, set()).add(index)
    for name, surviving_rows in survivors.items():
        deleted.pop(name, None)
        replacement = replacements.get(name)
        if replacement and surviving_rows != {replacement[0]}:
            replacements.pop(name)
    findings = []
    unresolved = False
    including_replacements = deleted | replacements
    for index, change, record in records:
        # Ordered replacement is evidence of a gap only for a CNAME the
        # plan leaves in place. Other DNS changes may occur in either order.
        candidates = (
            including_replacements if change["actions"] == ["no-op"] else deleted
        )
        if not candidates:
            continue
        kind = record.get("type") if not _unknown(change, "type") else None
        if isinstance(kind, str) and kind.upper() != "CNAME":
            continue
        name = "" if _unknown(change, "fqdn") else _hostname(record.get("fqdn"))
        if name and name not in candidates:
            continue
        targets = None if _unknown(change, "records") else record.get("records")
        if not isinstance(targets, list) or not targets:
            unresolved = True
            continue
        if len(targets) != 1 or not isinstance(targets[0], str):
            if kind is not None:
                raise InvalidPlan("Invalid target for a planned CNAME record.")
            unresolved = True
            continue
        host = _hostname(targets[0])
        target = _DIRECT_ENDPOINT.fullmatch(host)
        if (
            not target
            or target["bucket"] not in candidates
            or (name and target["bucket"] != name)
        ):
            continue
        bucket_index, endpoints = candidates[target["bucket"]]
        if (
            not name
            or not isinstance(kind, str)
            or unknown_bucket
            or (host not in endpoints and host not in website_endpoints.get(name, ()))
        ):
            unresolved = True
            continue
        message = (
            "The plan deletes an S3 bucket and retains a matching Route 53 CNAME. "
            "Retire or retarget the record before releasing the bucket."
        )
        if name in replacements:
            message = (
                "The plan deletes the S3 bucket before recreating the same shared "
                "name. Its Route 53 CNAME is unchanged during this interval. "
                "Review DNS retirement or preserve ownership of the bucket."
            )
        findings.append(
            {
                "rule_id": RULE_ID,
                "severity": "MEDIUM",
                "finding_type": "review",
                "message": message,
                "bucket_change": f"/resource_changes/{bucket_index}",
                "dns_change": f"/resource_changes/{index}",
            }
        )
    return findings, [_INCOMPLETE] if unresolved else []


def run_plan(path, output_format):
    findings = []
    errors = []
    try:
        raw = read_text_no_symlink(path, max_bytes=_MAX_PLAN_BYTES)
        if raw is None:
            raise InvalidPlan(
                "Expected a readable regular plan JSON file of at most 32 MiB."
            )
        try:
            plan = json.loads(
                raw,
                object_pairs_hook=_strict_json_object,
                parse_constant=_invalid_json_constant,
            )
        except (ValueError, RecursionError):
            raise InvalidPlan("Invalid Terraform plan JSON.") from None
        findings, errors = evaluate(plan)
    except RecursionError:
        errors.append("Terraform plan JSON exceeds the supported nesting depth.")
    except InvalidPlan as exc:
        errors.append(str(exc))
    if output_format == "json":
        print(
            json.dumps(
                {
                    "status": "incomplete" if errors else "complete",
                    "findings": findings,
                    "errors": errors,
                }
            )
        )
    else:
        for finding in findings:
            print(
                f"{RULE_ID} {finding['message']} ({finding['bucket_change']}, {finding['dns_change']})"
            )
        for error in errors:
            print(error)
        if not errors and not findings:
            print("No matching S3 deletion and retained Route 53 CNAME in this plan.")
    return 2 if errors else int(bool(findings))
