"""SARIF for imported image findings, without inventing repository locations."""

from __future__ import annotations

from skylos.cicd.evidence import sanitize_bounded_payload, sanitize_untrusted_text
from skylos.reporting.sarif import severity_to_sarif_level


def _text(value: str, limit: int = 1000) -> str:
    return sanitize_untrusted_text(value, max_length=limit, preserve_newlines=False)


def container_sarif(document: dict) -> dict:
    """Render the validated import envelope; report locations stay logical."""
    rules: dict[str, dict] = {}
    results = []
    image = document["image"]
    receipt = document["receipt"]
    identity = (
        receipt.get("verified_image")
        or next(iter(image["repo_digests"]), "")
        or image["id"]
        or image["name"]
        or "unknown image"
    )
    for finding in document["container_vulnerabilities"]:
        # IDs are validated, bounded JSON strings. Display sanitization belongs
        # in labels/messages, not identifiers where truncation causes collisions.
        rule_id = finding["rule_id"]
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": _text(finding["vulnerability_id"], 256)},
                "properties": {
                    "tags": ["security", "dependency", "container", "external"]
                },
            },
        )
        message = (
            f"{finding['vulnerability_id']}: {finding['package']} {finding['version']} "
            f"in {finding['target']}. "
        )
        if finding.get("fixed_version"):
            message += f"Reported fixed version: {finding['fixed_version']}. "
        message += finding.get("title") or ""
        results.append(
            {
                "ruleId": rule_id,
                "level": severity_to_sarif_level(finding["severity"]),
                "message": {"text": _text(message, 4000)},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": _text(finding["package"]),
                                "fullyQualifiedName": _text(
                                    f"{identity}::{finding['target']}::{finding['package']}@{finding['version']}",
                                    4000,
                                ),
                                "kind": "module",
                            }
                        ]
                    }
                ],
                "partialFingerprints": {"skylosContainer/v1": finding["fingerprint"]},
                "properties": sanitize_bounded_payload(
                    finding,
                    max_depth=6,
                    max_items=64,
                    max_text_length=4000,
                    neutralize_mentions=False,
                ),
            }
        )
    driver = {
        "name": "Trivy (imported by Skylos)",
        "informationUri": "https://trivy.dev/",
        "rules": list(rules.values()),
    }
    if document["engine"].get("version"):
        driver["version"] = _text(document["engine"]["version"], 128)
    invocation = {"executionSuccessful": receipt["import_complete"]}
    if receipt["errors"]:
        invocation["toolExecutionNotifications"] = [
            {
                "descriptor": {"id": _text(error["code"], 128)},
                "level": "error",
                "message": {"text": _text(error["message"])},
            }
            for error in receipt["errors"]
        ]
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": driver},
                "results": results,
                "invocations": [invocation],
                "properties": {
                    "source": "trivy",
                    "image": sanitize_bounded_payload(image, neutralize_mentions=False),
                    "receipt": sanitize_bounded_payload(
                        receipt, max_depth=6, max_items=128, neutralize_mentions=False
                    ),
                    "gate": document.get("gate", {"status": "not_requested"}),
                },
            }
        ],
    }
