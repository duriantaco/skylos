"""Bounded high-risk AWS declaration policies, never deployed-state proofs."""

from __future__ import annotations

import json
import math
from pathlib import Path
import re

from skylos.rules.config.findings import config_finding
from skylos.rules.config.terraform import aws
from skylos.rules.config.terraform.model import (
    Expression,
    MAX_DEPTH,
    MAX_NODES,
    _native_blocks,
    _normalize,
    _strict_json_object,
    _invalid_json_constant,
    is_unknown,
)


ACL_RULE = "SKY-D402"
POLICY_RULE = "SKY-D403"
BLOCK_RULE = "SKY-D404"
RDS_RULE = "SKY-D405"
EBS_RULE = "SKY-D406"
METADATA_RULE = "SKY-D407"
DATABASE_RULE = "SKY-D408"
RULE_RESOURCES = {
    ACL_RULE: frozenset({"aws_s3_bucket", "aws_s3_bucket_acl"}),
    POLICY_RULE: frozenset({"aws_s3_bucket_policy"}),
    BLOCK_RULE: frozenset({"aws_s3_bucket_public_access_block"}),
    RDS_RULE: frozenset({"aws_db_instance"}),
    EBS_RULE: frozenset({"aws_ebs_volume"}),
    METADATA_RULE: frozenset({"aws_instance", "aws_launch_template"}),
    DATABASE_RULE: aws.NETWORK_RESOURCES,
}
SUPPORTED_RULES = frozenset(RULE_RESOURCES)
SUPPORTED_RESOURCES = frozenset().union(*RULE_RESOURCES.values())
DATABASE_PORTS = (1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017, 27018)
BLOCK_FLAGS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)
MAX_POLICY_BYTES = 65536
MAX_STATEMENTS = 128
MAX_POLICY_VALUES = 128
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_S3_RESOURCE = re.compile(r"arn:(aws|aws-cn|aws-us-gov):s3:::([^/]+)(/\*)?\Z")
_AWS_PRINCIPAL = re.compile(
    r"(?:[0-9]{12}|arn:(?:aws|aws-cn|aws-us-gov):iam::[0-9]{12}:(?:root|(?:user|role)/[A-Za-z0-9+=,.@_/-]+))\Z"
)
_SERVICE_PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9.-]*\.amazonaws\.com(?:\.cn)?\Z")
_ACTIONS = frozenset(
    {
        "*",
        "s3:*",
        "s3:get*",
        "s3:put*",
        "s3:delete*",
        "s3:getobject",
        "s3:getobjectversion",
        "s3:putobject",
        "s3:deleteobject",
        "s3:deleteobjectversion",
        "s3:getobjectacl",
        "s3:putobjectacl",
        "s3:listbucket",
        "s3:getbucketacl",
        "s3:putbucketacl",
        "s3:getbucketpolicy",
        "s3:putbucketpolicy",
        "s3:deletebucketpolicy",
    }
)
_MESSAGES = {
    ACL_RULE: "Terraform requests a broad S3 canned ACL granting anonymous users or all AWS accounts access. Review the declaration and prefer private access; effective access also depends on ownership and public-access blocks.",
    POLICY_RULE: "Terraform declares an unconditional broad public S3 policy grant. Review the source policy; this does not prove deployed public exposure.",
    BLOCK_RULE: "Terraform explicitly disables an S3 bucket public-access-block protection. Enable the protections or review the intentional exception; disabling a protection alone does not grant public access.",
    RDS_RULE: "Terraform requests a publicly accessible RDS instance. Review the declaration and prefer private accessibility; routing and security groups determine effective reachability.",
    EBS_RULE: "Terraform explicitly requests an unencrypted EBS volume. Enable encryption in the declaration; account encryption defaults may override this request.",
    METADATA_RULE: "Terraform makes EC2 metadata tokens optional. Require IMDSv2 tokens in this declaration; this does not prove that the metadata endpoint is deployed or reachable.",
    DATABASE_RULE: "Terraform declares worldwide ingress on database or cache service ports. Restrict source CIDRs or ports and review this declaration; application access is not evaluated.",
}


def _result(status, reason, **evidence):
    return {"status": status, "reason": reason, "evidence": evidence}


def _explicit_boolean(project, resource, key, *, unsafe):
    value = project.resolve(resource.attributes.get(key), resource)
    if type(value) is not bool:
        return _result("unknown", f"{key} is omitted, invalid or unresolved")
    return _result(
        "unsafe" if value is unsafe else "safe",
        f"{key} explicitly {'enabled' if value else 'disabled'}",
        **{key: value},
    )


def _same_bucket(project, resource, other):
    if resource.module != other.module:
        return False
    left_raw = resource.attributes.get("bucket")
    right_raw = other.attributes.get("bucket")
    if isinstance(left_raw, Expression) and isinstance(right_raw, Expression):
        if left_raw.text == right_raw.text:
            return True
    left = project.resolve(left_raw, resource)
    right = project.resolve(right_raw, other)
    return isinstance(left, str) and isinstance(right, str) and left == right


def _declared_block(project, resource, flags):
    """A matching block declaration defeats an assertion of an effective grant."""
    for other in project.resources:
        if other.resource_type not in {
            "aws_s3_bucket_public_access_block",
            "aws_s3_account_public_access_block",
        }:
            continue
        if other.resource_type == "aws_s3_account_public_access_block":
            # Provider/account identity is not resolved; retain uncertainty.
            if resource.module != other.module:
                continue
        elif not _same_bucket(project, resource, other):
            continue
        if project.instance_status(other) == "absent":
            continue
        for flag in flags:
            if project.resolve(other.attributes.get(flag), other) is True:
                return True
    return False


def _acl(project, resource):
    attrs = resource.attributes
    if "grant" in attrs or "access_control_policy" in attrs:
        return _result("unknown", "Explicit grants are outside the canned-ACL model")
    value = project.resolve(attrs.get("acl"), resource)
    if value in ("public-read", "public-read-write", "authenticated-read"):
        if _declared_block(
            project, resource, ("block_public_acls", "ignore_public_acls")
        ):
            return _result(
                "unknown", "Public ACL request overlaps a declared public-access block"
            )
        return _result(
            "unsafe",
            "Broad canned ACL explicitly requested",
            acl=value,
            granted_group="all_aws_accounts"
            if value == "authenticated-read"
            else "anonymous",
        )
    if value in (
        "private",
        "log-delivery-write",
        "aws-exec-read",
        "bucket-owner-read",
        "bucket-owner-full-control",
    ):
        return _result(
            "safe", "Known canned ACL does not grant anonymous public access", acl=value
        )
    return _result("unknown", "Canned ACL is omitted, unsupported or unresolved")


def _blocks(project, resource):
    values = {
        key: project.resolve(resource.attributes.get(key), resource)
        for key in BLOCK_FLAGS
    }
    if any(
        not is_unknown(value) and type(value) is not bool for value in values.values()
    ):
        return _result("unknown", "Invalid public-access-block declaration")
    disabled = [key for key, value in values.items() if value is False]
    if disabled:
        return _result(
            "unsafe",
            "One or more public-access-block protections explicitly disabled",
            disabled_protections=disabled,
        )
    if all(value is True for value in values.values()):
        return _result(
            "safe", "All four public-access-block protections explicitly enabled"
        )
    return _result(
        "unknown", "Public-access-block protections are omitted or unresolved"
    )


def _jsonencode(text):
    """Parse an exact jsonencode literal argument; never execute an expression."""
    import hcl2
    from hcl2.utils import SerializationOptions

    text = text.strip()
    if not text.startswith("jsonencode(") or not text.endswith(")"):
        raise ValueError("Unsupported policy expression")
    source = "locals { value = " + text[len("jsonencode(") : -1] + "\n}"
    options = SerializationOptions(
        with_comments=False, explicit_blocks=False, preserve_heredocs=False
    )
    try:
        tree = hcl2.parses(source)
    except Exception as error:
        raise ValueError("Malformed policy expression") from error
    stack = [(tree, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("Policy expression budget exhausted")
        if getattr(node, "lark_name", lambda: "")() == "object":
            keys = set()
            for child in node.children:
                if getattr(child, "lark_name", lambda: "")() != "object_elem":
                    continue
                raw = child.children[0].serialize(options)
                key = next(iter(_normalize({raw: 1}, native=True)))
                if not isinstance(key, str) or key in keys:
                    raise ValueError("Duplicate or dynamic policy key")
                keys.add(key)
        stack.extend((child, depth + 1) for child in getattr(node, "children", ()))
    blocks = _native_blocks(source)
    if (
        len(blocks) != 1
        or blocks[0][0:2] != ("locals", [])
        or set(blocks[0][2]) != {"value"}
    ):
        raise ValueError("Policy expression is not a single literal value")
    value = blocks[0][2]["value"]
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("Nonfinite policy value")
        elif type(item) not in (str, int, float, bool) and item is not None:
            raise ValueError("Nonliteral policy expression")
    return value


def _policy_document(project, resource):
    raw = resource.attributes.get("policy")
    value = project.resolve(raw, resource)
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_POLICY_BYTES:
            raise ValueError("Policy byte budget exhausted")
        return json.loads(
            value,
            object_pairs_hook=_strict_json_object,
            parse_constant=_invalid_json_constant,
        )
    if (
        isinstance(raw, Expression)
        and len(raw.text.encode("utf-8")) <= MAX_POLICY_BYTES
    ):
        return _jsonencode(raw.text)
    raise ValueError(
        "Policy is not a bounded literal JSON document or jsonencode literal"
    )


def _strings(value):
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_POLICY_VALUES:
        return None
    if any(
        not isinstance(item, str) or not item or len(item) > 2048 for item in values
    ):
        return None
    return values


def _public_principal(value):
    if value == "*":
        return True
    if isinstance(value, str):
        return False if _AWS_PRINCIPAL.fullmatch(value) else None
    if (
        not isinstance(value, dict)
        or not value
        or set(value) - {"AWS", "Service", "CanonicalUser"}
    ):
        return None
    public = False
    for key, raw in value.items():
        values = _strings(raw)
        if values is None:
            return None
        for principal in values:
            if key == "AWS" and principal == "*":
                public = True
            elif key == "AWS" and _AWS_PRINCIPAL.fullmatch(principal):
                continue
            elif key == "Service" and _SERVICE_PRINCIPAL.fullmatch(principal):
                continue
            elif key == "CanonicalUser" and re.fullmatch(r"[0-9a-fA-F]{64}", principal):
                continue
            else:
                return None
    return public


def _policy(project, resource):
    try:
        document = _policy_document(project, resource)
    except (ValueError, TypeError, RecursionError, ImportError):
        return _result(
            "unknown",
            "Policy is malformed, dynamic, unsupported or exceeds the literal evaluation budget",
        )
    if not isinstance(document, dict) or set(document) - {"Version", "Id", "Statement"}:
        return _result("unknown", "Unsupported policy document shape")
    if "Id" in document and not isinstance(document["Id"], str):
        return _result("unknown", "Invalid policy identifier")
    if "Version" in document and document["Version"] not in (
        "2008-10-17",
        "2012-10-17",
    ):
        return _result("unknown", "Unsupported policy version")
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not 1 <= len(statements) <= MAX_STATEMENTS:
        return _result(
            "unknown", "Policy statements are missing, invalid or over budget"
        )
    raw_bucket = resource.attributes.get("bucket")
    if not isinstance(raw_bucket, (str, Expression)) or raw_bucket == "":
        return _result("unknown", "Policy bucket is missing, invalid or unresolved")
    bucket = project.resolve(raw_bucket, resource)
    grants = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict) or set(statement) - {
            "Sid",
            "Effect",
            "Principal",
            "Action",
            "Resource",
        }:
            return _result(
                "unknown",
                "Conditional, negated or unsupported policy statement requires review",
            )
        if "Sid" in statement and not isinstance(statement["Sid"], str):
            return _result("unknown", "Invalid statement identifier")
        if statement.get("Effect") != "Allow":
            return _result(
                "unknown",
                "Deny or invalid policy effect requires full authorization evaluation",
            )
        principal = _public_principal(statement.get("Principal"))
        actions, resources = (
            _strings(statement.get("Action")),
            _strings(statement.get("Resource")),
        )
        if (
            principal is None
            or actions is None
            or resources is None
            or any(action.lower() not in _ACTIONS for action in actions)
        ):
            return _result(
                "unknown", "Unsupported policy principal, action or resource"
            )
        for value in resources:
            if value == "*":
                continue
            match = _S3_RESOURCE.fullmatch(value)
            if match is None or not _BUCKET.fullmatch(match.group(2)):
                return _result(
                    "unknown",
                    "Resource scope is outside the bounded broad-S3-resource model",
                )
            if not isinstance(bucket, str) or bucket != match.group(2):
                return _result(
                    "unknown", "Policy resource and bucket identity cannot be matched"
                )
            object_scope = bool(match.group(3))
            if not any(
                action.lower() in {"*", "s3:*", "s3:get*", "s3:put*", "s3:delete*"}
                or ("object" in action.lower()) == object_scope
                for action in actions
            ):
                return _result(
                    "unknown",
                    "S3 action does not match the declared bucket/object resource scope",
                )
        if principal:
            grants.append(index)
    if grants:
        if _declared_block(
            project, resource, ("block_public_policy", "restrict_public_buckets")
        ):
            return _result(
                "unknown", "Public policy grant overlaps a declared public-access block"
            )
        return _result(
            "unsafe",
            "Unconditional wildcard-principal S3 grant in a literal source policy",
            statement_indexes=grants,
        )
    return _result(
        "safe", "Supported literal policy grants only to fixed nonpublic principals"
    )


def _ebs(project, resource):
    if "snapshot_id" in resource.attributes:
        return _result("unknown", "Snapshot encryption requires inherited evidence")
    if "kms_key_id" in resource.attributes:
        value = project.resolve(resource.attributes.get("encrypted"), resource)
        if value is not True:
            return _result(
                "unknown",
                "KMS key and encryption declaration require joint provider validation",
            )
    return _explicit_boolean(project, resource, "encrypted", unsafe=False)


def _metadata(project, resource):
    attrs = resource.attributes
    if "dynamic" in attrs:
        return _result("unknown", "Dynamic metadata configuration requires expansion")
    blocks = project.resolve(attrs.get("metadata_options"), resource)
    # JSON nested-block syntax permits one object in place of a one-item array.
    # A native HCL object attribute is not a metadata_options block.
    if resource.file.endswith(".tf.json") and isinstance(blocks, dict):
        blocks = [blocks]
    if (
        not isinstance(blocks, list)
        or len(blocks) != 1
        or not isinstance(blocks[0], dict)
    ):
        return _result(
            "unknown", "Metadata options are omitted, unresolved or not a single block"
        )
    options = blocks[0]
    endpoint = options.get("http_endpoint")
    if endpoint == "disabled":
        return _result("safe", "Metadata endpoint explicitly disabled")
    if "http_endpoint" in options and endpoint != "enabled":
        return _result("unknown", "Metadata endpoint is invalid or unresolved")
    tokens = options.get("http_tokens")
    if tokens == "required":
        return _result("safe", "Metadata tokens explicitly required")
    if tokens == "optional":
        return _result(
            "unsafe",
            "Metadata tokens explicitly optional",
            http_tokens="optional",
            http_endpoint=endpoint if endpoint == "enabled" else "unspecified",
        )
    return _result(
        "unknown", "Metadata token requirement is omitted, invalid or unresolved"
    )


def _database_ingress(attributes, *, modern=False, standalone=False):
    if not isinstance(attributes, dict):
        return _result("unknown", "Unresolved ingress declaration")
    if aws._source_conflict(attributes, modern=modern, standalone=standalone):
        return _result("unknown", "Mutually exclusive source declarations")
    protocol = aws._protocol(attributes.get("ip_protocol" if modern else "protocol"))
    if protocol == "other":
        return _result("safe", "Protocol excludes TCP database and cache ports")
    if protocol == "unknown":
        return _result("unknown", "Unresolved database ingress protocol")
    if protocol == "all":
        ports = list(DATABASE_PORTS)
    else:
        first, last = attributes.get("from_port"), attributes.get("to_port")
        if (
            type(first) is not int
            or type(last) is not int
            or not 0 <= first <= last <= 65535
        ):
            return _result("unknown", "Unresolved or invalid database ingress ports")
        ports = [port for port in DATABASE_PORTS if first <= port <= last]
    if not ports:
        return _result(
            "safe", "Port range excludes the supported database and cache ports"
        )
    world, cidrs, reason = aws._world_sources(attributes, modern=modern)
    if world is True:
        return _result(
            "unsafe",
            "Worldwide ingress includes TCP database or cache ports",
            world_cidrs=cidrs,
            database_ports=ports,
            protocol=protocol,
        )
    return _result("safe" if world is False else "unknown", reason)


def _database(project, resource):
    attrs = resource.attributes
    if resource.resource_type == "aws_security_group":
        results = []
        if "ingress" in attrs:
            ingress = project.resolve(attrs["ingress"], resource)
            if not isinstance(ingress, list):
                results.append(
                    _result("unknown", "Unresolved inline ingress collection")
                )
            else:
                results.extend(_database_ingress(item) for item in ingress)
        if "dynamic" in attrs:
            dynamic = project.resolve(attrs["dynamic"], resource)
            if not isinstance(dynamic, list) or any(
                not isinstance(item, dict) or "ingress" in item for item in dynamic
            ):
                results.append(_result("unknown", "Dynamic ingress requires expansion"))
        return aws._combine(results)
    if resource.resource_type == "aws_security_group_rule":
        direction = project.resolve(attrs.get("type"), resource)
        if direction == "egress":
            return _result("not_applicable", "Outbound rule is outside ingress policy")
        if direction != "ingress":
            return _result("unknown", "Unresolved or invalid rule direction")
    return _database_ingress(
        project.resolve(attrs, resource),
        modern=resource.resource_type == "aws_vpc_security_group_ingress_rule",
        standalone=resource.resource_type == "aws_security_group_rule",
    )


def evaluate_project(project, *, ignore=None):
    checks, findings = [], []
    ignored = set(ignore or ())
    evaluators = {
        ACL_RULE: _acl,
        POLICY_RULE: _policy,
        BLOCK_RULE: _blocks,
        RDS_RULE: lambda p, r: _explicit_boolean(
            p, r, "publicly_accessible", unsafe=True
        ),
        EBS_RULE: _ebs,
        METADATA_RULE: _metadata,
        DATABASE_RULE: _database,
    }
    for resource in project.resources:
        for rule, kinds in RULE_RESOURCES.items():
            if rule in ignored or resource.resource_type not in kinds:
                continue
            instance = project.instance_status(resource)
            if instance == "absent":
                result = _result(
                    "not_applicable",
                    "No declared instances (zero count/empty for_each)",
                )
            elif instance == "unknown":
                result = _result("unknown", "Resource instance expansion is unresolved")
            elif project.aws_provider_status(resource) is not True:
                result = _result(
                    "unknown", "Official AWS provider identity is unresolved or absent"
                )
            else:
                result = evaluators[rule](project, resource)
            check = {
                "rule_id": rule,
                "resource": f"{resource.resource_type}.{resource.name}",
                "resource_type": resource.resource_type,
                "file": resource.file,
                "line": resource.line,
                **result,
            }
            checks.append(check)
            if result["status"] == "unsafe":
                finding = config_finding(
                    rule_id=rule,
                    domain="cloud",
                    provider="aws",
                    name=check["resource"],
                    message=_MESSAGES[rule],
                    file=Path(resource.file),
                    line=resource.line,
                    severity="HIGH",
                    value=check["resource"],
                    finding_type="terraform",
                )
                finding["resource"] = check["resource"]
                finding["metadata"] = {
                    "terraform": {**check, "scope": "declaration_policy"}
                }
                findings.append(finding)
    return checks, findings
