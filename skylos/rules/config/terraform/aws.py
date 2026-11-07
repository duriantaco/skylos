"""Two bounded AWS declaration policies, independent of deployed cloud state."""

from __future__ import annotations

from ipaddress import collapse_addresses, ip_network
from pathlib import Path

from skylos.rules.config.findings import config_finding
from skylos.rules.config.terraform.model import is_unknown


NETWORK_RULE = "SKY-D400"
STORAGE_RULE = "SKY-D401"
SUPPORTED_RULES = frozenset({NETWORK_RULE, STORAGE_RULE})
NETWORK_RESOURCES = frozenset(
    {
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
    }
)
SUPPORTED_RESOURCES = NETWORK_RESOURCES | {"aws_db_instance"}
MAX_CIDRS = 1024


def _result(status, reason, **evidence):
    return {"status": status, "reason": reason, "evidence": evidence}


def _combine(results):
    """An independently proven unsafe rule wins over other unresolved rules."""
    for status in ("unsafe", "unknown", "safe"):
        selected = [result for result in results if result["status"] == status]
        if selected:
            return _result(
                status,
                selected[0]["reason"],
                ingress_checks=results,
            )
    return _result("not_applicable", "No inline ingress declaration")


def _protocol(value):
    if type(value) is int:
        protocol = value
    elif isinstance(value, str):
        text = value.lower()
        if text in {"all", "-1"}:
            return "all"
        if text == "tcp":
            return "tcp"
        if text in {"udp", "icmp", "icmpv6"}:
            return "other"
        try:
            protocol = int(text)
        except ValueError:
            return "unknown"
    else:
        return "unknown"
    if protocol == -1:
        return "all"
    if protocol == 6:
        return "tcp"
    return "other" if 0 <= protocol <= 255 else "unknown"


def _admin_ports(protocol, attributes):
    if protocol == "all":
        return True, [22, 3389]
    if protocol == "other":
        return False, []
    if protocol == "unknown":
        return None, []
    first, last = attributes.get("from_port"), attributes.get("to_port")
    if (
        type(first) is not int
        or type(last) is not int
        or not 0 <= first <= last <= 65535
    ):
        return None, []
    ports = [port for port in (22, 3389) if first <= port <= last]
    return bool(ports), ports


def _world_sources(attributes, *, modern):
    """Return True/False/None for a bounded CIDR union, retaining unknown leaves."""
    keys = ("cidr_ipv4", "cidr_ipv6") if modern else ("cidr_blocks", "ipv6_cidr_blocks")
    networks = {4: [], 6: []}
    unknown = False
    invalid = False
    provided = False
    source_count = 0
    for key, version in zip(keys, (4, 6)):
        if key not in attributes:
            continue
        raw = attributes[key]
        if is_unknown(raw):
            unknown = True
            continue
        values = [raw] if modern else raw
        if not isinstance(values, list):
            invalid = True
            continue
        if values:
            provided = True
        source_count += len(values)
        if source_count > MAX_CIDRS:
            return None, [], "CIDR evaluation budget exceeded"
        for value in values:
            if is_unknown(value):
                unknown = True
                continue
            if not isinstance(value, str):
                invalid = True
                continue
            try:
                network = ip_network(value, strict=False)
            except ValueError:
                invalid = True
                continue
            if network.version != version:
                invalid = True
                continue
            networks[version].append(network)

    # A malformed literal is not a valid declaration to judge as a policy pass
    # or a proven world rule. Unresolved values remain independent of known CIDRs.
    if invalid:
        return None, [], "Invalid CIDR source declaration"
    world = []
    for version, values in networks.items():
        merged = list(collapse_addresses(values))
        if any(network.prefixlen == 0 for network in merged):
            world.append("0.0.0.0/0" if version == 4 else "::/0")
    if world:
        return True, world, "CIDR union covers an entire address family"
    if unknown:
        return None, [], "Unresolved CIDR source"

    group_keys = (
        ("referenced_security_group_id",)
        if modern
        else ("source_security_group_id", "security_groups")
    )
    if any(key in attributes for key in group_keys) or attributes.get("self") is True:
        for key in group_keys:
            if key not in attributes:
                continue
            value = attributes[key]
            if is_unknown(value):
                return None, [], "Unresolved security group source"
            if not (
                isinstance(value, str)
                and value
                or isinstance(value, list)
                and value
                and all(isinstance(item, str) and item for item in value)
            ):
                return None, [], "Invalid security group source"
        provided = True
    prefix_key = "prefix_list_id" if modern else "prefix_list_ids"
    if prefix_key in attributes:
        return None, [], "Prefix-list contents are outside the source-only model"
    if provided:
        return False, [], "Known sources do not cover an entire address family"
    return None, [], "No supported ingress source declaration"


def _source_conflict(attributes, *, modern, standalone):
    def nonempty(key):
        value = attributes.get(key)
        return isinstance(value, (str, list)) and len(value) > 0

    if modern:
        return (
            sum(
                nonempty(key)
                for key in (
                    "cidr_ipv4",
                    "cidr_ipv6",
                    "prefix_list_id",
                    "referenced_security_group_id",
                )
            )
            > 1
        )
    if standalone:
        cidrs = nonempty("cidr_blocks") or nonempty("ipv6_cidr_blocks")
        group = nonempty("source_security_group_id")
        itself = attributes.get("self") is True
        return cidrs and (group or itself) or group and itself
    return False


def _ingress(attributes, *, modern=False, standalone=False):
    if not isinstance(attributes, dict):
        return _result("unknown", "Unresolved ingress declaration")
    if _source_conflict(attributes, modern=modern, standalone=standalone):
        return _result("unknown", "Mutually exclusive source declarations")
    protocol = _protocol(attributes.get("ip_protocol" if modern else "protocol"))
    admin, ports = _admin_ports(protocol, attributes)
    if admin is None:
        return _result("unknown", "Unresolved or invalid administrative protocol/ports")
    if admin is False:
        return _result("safe", "Protocol or port range excludes TCP SSH and RDP")
    world, cidrs, reason = _world_sources(attributes, modern=modern)
    if world is False:
        return _result("safe", reason)
    if admin is True and world is True:
        return _result(
            "unsafe",
            "Worldwide ingress includes TCP administrative ports",
            world_cidrs=cidrs,
            administrative_ports=ports,
            protocol=protocol,
        )
    return _result(
        "unknown",
        reason,
    )


def _network(project, resource):
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
                results.extend(_ingress(item) for item in ingress)
        if "dynamic" in attrs:
            dynamic = project.resolve(attrs["dynamic"], resource)
            if not isinstance(dynamic, list) or any(
                not isinstance(item, dict) or "ingress" in item for item in dynamic
            ):
                results.append(_result("unknown", "Dynamic ingress requires expansion"))
        return _combine(results)
    if resource.resource_type == "aws_security_group_rule":
        direction = project.resolve(attrs.get("type"), resource)
        if direction == "egress":
            return _result("not_applicable", "Outbound rule is outside ingress policy")
        if direction != "ingress":
            return _result("unknown", "Unresolved or invalid rule direction")
    return _ingress(
        project.resolve(attrs, resource),
        modern=resource.resource_type == "aws_vpc_security_group_ingress_rule",
        standalone=resource.resource_type == "aws_security_group_rule",
    )


def _storage(project, resource):
    attrs = resource.attributes
    inherited = {
        "snapshot_identifier",
        "replicate_source_db",
        "restore_to_point_in_time",
        "s3_import",
    }
    if inherited.intersection(attrs):
        return _result(
            "unknown",
            "Restored or replicated storage needs inherited encryption evidence",
        )
    value = project.resolve(attrs.get("storage_encrypted"), resource)
    if value is True:
        return _result("safe", "New DB storage encryption explicitly enabled")
    if value is False:
        return _result(
            "unsafe",
            "New DB storage encryption explicitly disabled",
            storage_encrypted=False,
            creation_context="direct",
        )
    return _result("unknown", "Storage encryption is omitted, invalid or unresolved")


def evaluate_project(project, *, ignore=None):
    """Return per-resource policy outcomes and only proven-unsafe findings."""
    ignored = set(ignore or ())
    checks = []
    findings = []
    for resource in project.resources:
        if resource.resource_type not in SUPPORTED_RESOURCES:
            continue
        network = resource.resource_type in NETWORK_RESOURCES
        rule = NETWORK_RULE if network else STORAGE_RULE
        if rule in ignored:
            continue
        instance = project.instance_status(resource)
        if instance == "absent":
            result = _result(
                "not_applicable", "No declared instances (zero count/empty for_each)"
            )
        elif instance == "unknown":
            result = _result("unknown", "Resource instance expansion is unresolved")
        elif project.aws_provider_status(resource) is not True:
            result = _result(
                "unknown", "Official AWS provider identity is unresolved or absent"
            )
        else:
            result = (
                _network(project, resource) if network else _storage(project, resource)
            )
        check = {
            "rule_id": rule,
            "resource": f"{resource.resource_type}.{resource.name}",
            "resource_type": resource.resource_type,
            "file": resource.file,
            "line": resource.line,
            **result,
        }
        checks.append(check)
        if result["status"] != "unsafe":
            continue
        message = (
            "Terraform declares worldwide administrative ingress (SSH/RDP). "
            "Restrict the source CIDRs or administrative ports; review this declaration."
            if network
            else "Terraform explicitly disables encryption for new RDS DB storage. "
            "Enable storage encryption for this declaration."
        )
        finding = config_finding(
            rule_id=rule,
            domain="cloud",
            provider="aws",
            name=check["resource"],
            message=message,
            file=Path(resource.file),
            line=resource.line,
            severity="HIGH",
            value=check["resource"],
            finding_type="terraform",
        )
        finding["resource"] = check["resource"]
        finding["metadata"] = {"terraform": {**check, "scope": "declaration_policy"}}
        findings.append(finding)
    return checks, findings
