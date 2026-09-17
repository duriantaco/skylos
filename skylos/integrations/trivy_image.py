"""Bounded, offline import of Trivy container-image vulnerability reports.

Import success describes the supplied report, never the original scan's coverage.
Trivy JSON does not attest which scanners, filters, or databases were used.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink

MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_RESULTS = 4096
MAX_FINDINGS = 100_000
MAX_PACKAGES = 100_000
MAX_DIAGNOSTICS = 40
MAX_TEXT_LENGTH = 4096
MAX_DESCRIPTION_LENGTH = 16_384
SUPPORTED_CLASSES = frozenset({"os-pkgs", "lang-pkgs"})
SEVERITIES = frozenset({"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_IMAGE_REFERENCE = re.compile(
    rf"{_NAME_COMPONENT}(?::[0-9]+)?(?:/{_NAME_COMPONENT})*@sha256:[0-9a-f]{{64}}\Z"
)
_PLATFORM = re.compile(
    r"[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)?\Z"
)
_PLATFORM_COMPONENT = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")


def _diagnostic(receipt: dict, kind: str, code: str, message: str) -> None:
    if kind == "errors":
        receipt["import_complete"] = False
    entries = receipt[kind]
    if len(entries) < MAX_DIAGNOSTICS and not any(
        item["code"] == code for item in entries
    ):
        entries.append({"code": code, "message": message})


def _error(receipt: dict, code: str, message: str) -> None:
    _diagnostic(receipt, "errors", code, message)


def _warning(receipt: dict, code: str, message: str) -> None:
    _diagnostic(receipt, "warnings", code, message)


def _text(
    value: Any, *, max_length: int = MAX_TEXT_LENGTH, multiline=False
) -> str | None:
    if not isinstance(value, str) or len(value) > max_length:
        return None
    allowed = "\t\r\n" if multiline else ""
    if any(
        (ord(char) < 32 and char not in allowed)
        or ord(char) == 127
        or 0xD800 <= ord(char) <= 0xDFFF
        for char in value
    ):
        return None
    return value


def _field(
    data: dict, key: str, receipt: dict, *, required=False, multiline=False
) -> str:
    value = data.get(key, "")
    parsed = _text(
        value,
        max_length=MAX_DESCRIPTION_LENGTH if multiline else MAX_TEXT_LENGTH,
        multiline=multiline,
    )
    if parsed is None or (required and not parsed.strip()):
        _error(
            receipt,
            "invalid_text_field",
            "A report field has missing, invalid, or oversized text.",
        )
        return ""
    return parsed


def _envelope(report_sha256: str | None) -> dict:
    return {
        "schema_version": 1,
        "source": "trivy",
        "engine": {"name": "Trivy", "version": None},
        "image": {"name": "", "id": "", "repo_digests": [], "platform": None, "os": {}},
        "container_vulnerabilities": [],
        "receipt": {
            "import_complete": True,
            "scan_complete": None,
            "identity_verified": False,
            "platform_verified": False,
            "verified_image": None,
            "verified_platform": None,
            "errors": [],
            "warnings": [],
            "report_sha256": report_sha256,
            "scope": "reported_container_vulnerabilities",
            "supported_result_count": 0,
            "unsupported_result_count": 0,
            "reported_vulnerability_count": 0,
            "imported_vulnerability_count": 0,
            "duplicate_vulnerability_count": 0,
            "reported_package_count": 0,
            "results_with_package_inventory": 0,
            "targets": [],
            "created_at": None,
            "database_freshness": "unknown",
        },
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON number")


def load_trivy_image_report(
    path: str | Path,
    *,
    expected_image: str | None = None,
    expected_platform: str | None = None,
) -> dict[str, Any]:
    """Read a regular, non-symlink UTF-8 file without executing report content."""
    document = _envelope(None)
    try:
        report_path = Path(os.path.abspath(Path(path).expanduser()))
        text = read_project_text_no_symlink(
            Path(report_path.anchor),
            report_path,
            max_bytes=MAX_REPORT_BYTES,
            newline="",
        )
    except (OSError, ValueError, RuntimeError):
        text = None
    if text is None:
        _error(
            document["receipt"],
            "unreadable_report",
            "Report must be a regular, non-symlink UTF-8 file no larger than 20 MiB.",
        )
        return document
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    try:
        data = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except (ValueError, RecursionError):
        document["receipt"]["report_sha256"] = digest
        _error(
            document["receipt"],
            "invalid_json",
            "Report must contain valid JSON without duplicate keys or non-finite numbers.",
        )
        return document
    return normalize_trivy_image_report(
        data,
        expected_image=expected_image,
        expected_platform=expected_platform,
        report_sha256=digest,
    )


def _metadata(data: dict, document: dict) -> None:
    receipt = document["receipt"]
    image = document["image"]
    image["name"] = _field(data, "ArtifactName", receipt, required=True)
    trivy = data.get("Trivy", {})
    if isinstance(trivy, dict):
        document["engine"]["version"] = _field(trivy, "Version", receipt) or None
    else:
        _error(receipt, "invalid_engine_metadata", "Trivy metadata must be an object.")
    receipt["created_at"] = _field(data, "CreatedAt", receipt) or None
    metadata = data.get("Metadata", {})
    if not isinstance(metadata, dict):
        _error(receipt, "invalid_image_metadata", "Image metadata must be an object.")
        return
    image["id"] = _field(metadata, "ImageID", receipt)
    digests = metadata.get("RepoDigests", [])
    if not isinstance(digests, list) or len(digests) > MAX_RESULTS:
        _error(
            receipt,
            "invalid_repo_digests",
            "Repository digests must be a bounded list of pinned image references.",
        )
    else:
        for digest in digests:
            if _text(digest) is None or not _IMAGE_REFERENCE.fullmatch(digest):
                _error(
                    receipt,
                    "invalid_repo_digests",
                    "Repository digests must be a bounded list of pinned image references.",
                )
                continue
            image["repo_digests"].append(digest)
        image["repo_digests"] = sorted(set(image["repo_digests"]))
    _os_metadata(metadata, image, receipt)
    config = metadata.get("ImageConfig", {})
    if not isinstance(config, dict):
        _error(
            receipt,
            "invalid_platform",
            "Image configuration must be an object with valid platform fields.",
        )
        return
    parts = [_field(config, key, receipt) for key in ("os", "architecture", "variant")]
    if any(part and not _PLATFORM_COMPONENT.fullmatch(part) for part in parts):
        _error(
            receipt,
            "invalid_platform",
            "Image configuration contains an invalid platform.",
        )
        return
    if parts[0] and parts[1]:
        platform = "/".join(parts[:2] + ([parts[2]] if parts[2] else []))
        if _PLATFORM.fullmatch(platform):
            image["platform"] = platform
        else:
            _error(
                receipt,
                "invalid_platform",
                "Image configuration contains an invalid platform.",
            )


def _os_metadata(metadata: dict, image: dict, receipt: dict) -> None:
    os_data = metadata.get("OS", {})
    if not isinstance(os_data, dict):
        _error(receipt, "invalid_os_metadata", "OS metadata must be an object.")
        return
    for key in ("Family", "Name"):
        if key in os_data:
            image["os"][key] = _field(os_data, key, receipt)
    if "EOSL" in os_data:
        if not isinstance(os_data["EOSL"], bool):
            _error(
                receipt,
                "invalid_os_metadata",
                "OS end-of-support status must be boolean.",
            )
        else:
            image["os"]["EOSL"] = os_data["EOSL"]
            if os_data["EOSL"]:
                _warning(
                    receipt,
                    "os_end_of_support",
                    "Trivy reports an end-of-support OS; vulnerability coverage may be limited.",
                )


def _verify_identity(
    document: dict, expected_image: Any, expected_platform: Any
) -> None:
    receipt, image = document["receipt"], document["image"]
    if expected_image is not None:
        if _text(expected_image) is None or not _IMAGE_REFERENCE.fullmatch(
            expected_image
        ):
            _error(
                receipt,
                "invalid_expected_image",
                "Expected image must be a repository reference pinned to a lowercase sha256 digest.",
            )
        elif expected_image not in image["repo_digests"]:
            _error(
                receipt,
                "image_identity_mismatch",
                "The expected pinned image is not present in the report's repository digests.",
            )
        else:
            receipt["identity_verified"] = True
            receipt["verified_image"] = expected_image
    if expected_platform is not None:
        if _text(expected_platform) is None or not _PLATFORM.fullmatch(
            expected_platform
        ):
            _error(
                receipt,
                "invalid_expected_platform",
                "Expected platform must have the form os/architecture or os/architecture/variant.",
            )
        elif expected_platform != image["platform"]:
            _error(
                receipt,
                "image_platform_mismatch",
                "The report platform does not match the expected platform.",
            )
        else:
            receipt["platform_verified"] = True
            receipt["verified_platform"] = expected_platform


def _inventory(result: dict, receipt: dict) -> None:
    if "Packages" not in result:
        return
    packages = result["Packages"]
    if not isinstance(packages, list):
        _error(receipt, "invalid_packages", "Reported packages must be an array.")
        return
    receipt["results_with_package_inventory"] += 1
    remaining = max(0, MAX_PACKAGES - receipt["reported_package_count"])
    if len(packages) > remaining:
        _error(
            receipt,
            "package_limit",
            "Report exceeds the supported package-count limit.",
        )
    for package in packages[:remaining]:
        receipt["reported_package_count"] += 1
        if not isinstance(package, dict):
            _error(
                receipt,
                "invalid_package",
                "A package inventory entry is not an object.",
            )
            continue
        _field(package, "Name", receipt, required=True)
        _field(package, "Version", receipt, required=True)


def _finding(raw: Any, result: dict, receipt: dict) -> dict | None:
    if not isinstance(raw, dict):
        _error(
            receipt, "invalid_vulnerability", "A vulnerability entry is not an object."
        )
        return None
    identifier = _field(raw, "VulnerabilityID", receipt, required=True)
    package = _field(raw, "PkgName", receipt, required=True)
    version = _field(raw, "InstalledVersion", receipt, required=True)
    if not identifier or not package or not version:
        return None
    severity = _field(raw, "Severity", receipt, required=True).upper()
    if severity not in SEVERITIES or severity == "UNKNOWN":
        severity = "UNKNOWN"
        _error(
            receipt,
            "unknown_severity",
            "A reported vulnerability has unknown or invalid severity; severity gating is incomplete.",
        )
    finding = {
        "rule_id": "TRIVY:" + identifier,
        "vulnerability_id": identifier,
        "package": package,
        "version": version,
        "severity": severity,
        **result,
    }
    for source, target in (
        ("FixedVersion", "fixed_version"),
        ("PkgID", "package_id"),
        ("PkgPath", "package_path"),
        ("Title", "title"),
        ("Description", "description"),
        ("PrimaryURL", "primary_url"),
        ("Status", "status"),
        ("SeveritySource", "severity_source"),
    ):
        finding[target] = _field(
            raw, source, receipt, multiline=source in {"Description", "Title"}
        )
    finding["data_source"] = {}
    source_data = raw.get("DataSource", {})
    if isinstance(source_data, dict):
        for key in ("ID", "Name", "URL"):
            if key in source_data:
                finding["data_source"][key] = _field(source_data, key, receipt)
    else:
        _error(
            receipt, "invalid_data_source", "An advisory data source is not an object."
        )
    identifier_data = raw.get("PkgIdentifier", {})
    finding["purl"] = ""
    if isinstance(identifier_data, dict):
        finding["purl"] = _field(identifier_data, "PURL", receipt)
    else:
        _error(
            receipt,
            "invalid_package_identifier",
            "A vulnerability package identifier is not an object.",
        )
    layer = raw.get("Layer", {})
    finding["layer"] = {}
    if isinstance(layer, dict):
        for key in ("Digest", "DiffID"):
            if key in layer:
                finding["layer"][key] = _field(layer, key, receipt)
    else:
        _error(receipt, "invalid_layer", "A vulnerability layer is not an object.")
    return finding


def _image_fingerprint(image: dict) -> str:
    identity = {
        "image": image["repo_digests"] or image["id"] or image["name"],
        "platform": image["platform"],
    }
    serialized = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _fingerprint(finding: dict, image_fingerprint: str) -> str:
    identity = {
        key: finding[key]
        for key in (
            "vulnerability_id",
            "package",
            "version",
            "package_id",
            "package_path",
            "purl",
            "layer",
            "target",
            "class",
            "type",
        )
    }
    identity["image_fingerprint"] = image_fingerprint
    serialized = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _result(raw: Any, document: dict, seen: set[str], image_fingerprint: str) -> None:
    receipt = document["receipt"]
    if not isinstance(raw, dict):
        _error(receipt, "invalid_result", "A report result is not an object.")
        return
    if not isinstance(raw.get("Class"), str) or raw["Class"] not in SUPPORTED_CLASSES:
        receipt["unsupported_result_count"] += 1
        _error(
            receipt,
            "unsupported_result_class",
            "Only os-pkgs and lang-pkgs vulnerability results are supported.",
        )
        return
    target = _field(raw, "Target", receipt, required=True)
    package_type = _field(raw, "Type", receipt, required=True)
    header = {"target": target, "class": raw["Class"], "type": package_type}
    if target and package_type:
        receipt["supported_result_count"] += 1
    receipt["targets"].append(header)
    _inventory(raw, receipt)
    for section in (
        "Secrets",
        "Misconfigurations",
        "Licenses",
        "CustomResources",
        "ExperimentalModifiedFindings",
    ):
        if raw.get(section):
            _error(
                receipt,
                "unsupported_findings",
                "The report contains findings outside the supported active-vulnerability import scope.",
            )
    vulnerabilities = raw.get("Vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        _error(
            receipt,
            "invalid_vulnerabilities",
            "Reported vulnerabilities must be an array.",
        )
        return
    remaining = max(0, MAX_FINDINGS - receipt["reported_vulnerability_count"])
    if len(vulnerabilities) > remaining:
        _error(
            receipt,
            "vulnerability_limit",
            "Report exceeds the supported vulnerability-count limit.",
        )
    for raw_finding in vulnerabilities[:remaining]:
        receipt["reported_vulnerability_count"] += 1
        finding = _finding(raw_finding, header, receipt)
        if finding is None:
            continue
        serialized = json.dumps(
            finding, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        evidence_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        if evidence_hash in seen:
            receipt["duplicate_vulnerability_count"] += 1
            continue
        seen.add(evidence_hash)
        finding["fingerprint"] = _fingerprint(finding, image_fingerprint)
        document["container_vulnerabilities"].append(finding)


def normalize_trivy_image_report(
    data: Any,
    *,
    expected_image: str | None = None,
    expected_platform: str | None = None,
    report_sha256: str | None = None,
) -> dict[str, Any]:
    """Normalize the supported schema-v2 subset, retaining findings on partial imports."""
    document = _envelope(report_sha256)
    receipt = document["receipt"]
    _warning(
        receipt,
        "scan_coverage_unknown",
        "Report import does not verify original scan completion, filters, database freshness, or image authenticity.",
    )
    if not isinstance(data, dict):
        _error(receipt, "invalid_report", "Trivy report must be a JSON object.")
        return document
    if type(data.get("SchemaVersion")) is not int or data["SchemaVersion"] != 2:
        _error(
            receipt,
            "unsupported_schema",
            "Only Trivy JSON SchemaVersion 2 is supported.",
        )
        return document
    if data.get("ArtifactType") != "container_image":
        _error(
            receipt,
            "unsupported_artifact",
            "Only container_image reports are supported.",
        )
        return document
    _metadata(data, document)
    _verify_identity(document, expected_image, expected_platform)
    results = data.get("Results", [])
    if not isinstance(results, list):
        _error(receipt, "invalid_results", "Report Results must be an array.")
        return document
    if len(results) > MAX_RESULTS:
        _error(
            receipt, "result_limit", "Report exceeds the supported result-count limit."
        )
    seen: set[str] = set()
    image_fingerprint = _image_fingerprint(document["image"])
    for result in results[:MAX_RESULTS]:
        _result(result, document, seen, image_fingerprint)
    findings = document["container_vulnerabilities"]
    receipt["imported_vulnerability_count"] = len(findings)
    receipt["by_severity"] = dict(
        sorted(Counter(item["severity"] for item in findings).items())
    )
    if receipt["supported_result_count"] == 0:
        _warning(
            receipt,
            "no_supported_results",
            "No supported package result was supplied; an empty import does not demonstrate image coverage.",
        )
    return document
