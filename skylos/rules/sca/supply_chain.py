"""Supply-chain findings from Skylos's dependency inventory, decided by ca9.

ca9 (``ca9.api``, API version 1 or newer) is the engine; Skylos supplies the
packages it read from manifests and lockfiles and turns ca9's findings into
``SKY-SCA-*`` rows:

- ``SKY-SCA-SRC001`` dependency confusion, only when the policy names
  internal package patterns and the entry's registry is known.
- ``SKY-SCA-SRC003`` a Git dependency not pinned to a full commit, or a URL
  dependency without a hash.
- ``SKY-SCA-INT001`` a lockfile registry entry without an integrity hash
  (lockfiles only; requirements files are never reported).
- ``SKY-SCA-AGE001`` a version younger than the configured minimum release
  age (scans check this only when the policy sets one).

Each ca9 finding must agree with the inventory record it names, so a looser
or newer engine cannot report a pinned commit, a hashed URL, a requirements
file entry, or confusion without configured patterns. When ca9 is missing,
too old or fails, the scan carries a note and no new findings.

When the OSV query is incomplete, the installed ca9 malware feed is checked
as a fallback and the receipt says so.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from skylos.rules.sca.advisory_metadata import malicious_package_message
from skylos.rules.sca.package_sources import (
    SOURCE_GIT,
    SOURCE_REGISTRY,
    SOURCE_URL,
    registry_url,
    source_is_mutable,
)

logger = logging.getLogger(__name__)

CA9_API_MIN_VERSION = 1
RULE_CONFUSION = "SKY-SCA-SRC001"
RULE_MUTABLE_SOURCE = "SKY-SCA-SRC003"
RULE_MISSING_INTEGRITY = "SKY-SCA-INT001"
RULE_RELEASE_AGE = "SKY-SCA-AGE001"
RULE_FEED_MALWARE_FALLBACK = "SKY-SCA-MAL000"
SUPPLY_CHAIN_RULES = frozenset(
    {RULE_CONFUSION, RULE_MUTABLE_SOURCE, RULE_MISSING_INTEGRITY, RULE_RELEASE_AGE}
)
NOTE_API_UNAVAILABLE = "ca9_supply_chain_api_unavailable"
NOTE_API_FAILED = "ca9_supply_chain_api_failed"
NOTE_FEED_UNAVAILABLE = "ca9_malware_feed_unavailable"
NOTE_FEED_FAILED = "ca9_malware_feed_failed"
NOTE_FEED_USED = "osv_incomplete_ca9_feed_checked"
MAX_CA9_PACKAGES = 20_000
MAX_CA9_LOOKUPS = 200
MAX_EVIDENCE_TEXT = 300
INTEGRITY_LOCKFILES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "uv.lock",
        "poetry.lock",
    }
)
_CA9_ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi"}
_SKYLOS_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}
SIGNAL_RULES = {
    "dependency_confusion": RULE_CONFUSION,
    "mutable_source": RULE_MUTABLE_SOURCE,
    "git_dependency": RULE_MUTABLE_SOURCE,
    "direct_url_dependency": RULE_MUTABLE_SOURCE,
    "unpinned_git_dependency": RULE_MUTABLE_SOURCE,
    "unhashed_url_dependency": RULE_MUTABLE_SOURCE,
    "missing_integrity": RULE_MISSING_INTEGRITY,
    "missing_lockfile_integrity": RULE_MISSING_INTEGRITY,
    "missing_artifact_hash": RULE_MISSING_INTEGRITY,
    "new_package_version": RULE_RELEASE_AGE,
    "release_too_new": RULE_RELEASE_AGE,
    "release_age": RULE_RELEASE_AGE,
    "too_new": RULE_RELEASE_AGE,
}
_MALWARE_ID_KEYS = ("malware_id", "advisory_id", "osv_id", "vuln_id", "id")
_ADVISORY_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+")


def load_ca9_api():
    """``ca9.api`` when it is importable and speaks API version 1 or newer."""
    try:
        from ca9 import api
    except Exception:  # noqa: BLE001 - a broken optional engine must not stop a scan
        return None
    version = getattr(api, "API_VERSION", None)
    if isinstance(version, bool) or not isinstance(version, int):
        return None
    if version < CA9_API_MIN_VERSION:
        return None
    return api


def _normalized_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def _registry_records(inventory) -> list[dict]:
    records: dict[tuple, dict] = {}
    for dependency in getattr(inventory, "occurrences", None) or list(inventory):
        ecosystem = dependency.get("ecosystem")
        if ecosystem not in _CA9_ECOSYSTEMS:
            continue
        name = _normalized_name(ecosystem, str(dependency.get("name") or ""))
        version = str(dependency.get("version") or "")
        if not name or not version:
            continue
        key = (ecosystem, name, version, str(dependency.get("file") or ""))
        previous = records.get(key)
        if previous is not None and "lockfile_version" in previous:
            continue
        lockfile = "lockfile_version" in dependency
        direct = not lockfile or dependency.get("dependency_kind") == "direct"
        records[key] = {
            "kind": SOURCE_REGISTRY,
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "direct": direct,
            "dev": dependency.get("dependency_dev") is True,
            "registry": registry_url(dependency.get("registry")),
            "registry_mode": dependency.get("registry_mode"),
            "registries": list(dependency.get("registries") or []),
            "integrity": dependency.get("integrity"),
            "integrity_recorded": lockfile
            and "integrity" in dependency
            and Path(str(dependency.get("file") or "")).name in INTEGRITY_LOCKFILES,
            "lockfile": lockfile,
            "file": str(dependency.get("file") or ""),
            "line": dependency.get("line") or 1,
            "snippet": dependency.get("snippet") or "",
        }
    return list(records.values())


def _lockfile_covers(inventory, record: dict) -> bool:
    if Path(record["file"]).name not in {"package.json", "pyproject.toml"}:
        return False
    directory = str(Path(record["file"]).parent)
    return (directory, record["ecosystem"]) in getattr(
        inventory, "lockfile_projects", set()
    )


def _source_records(inventory) -> list[dict]:
    records = []
    for source in getattr(inventory, "source_records", ()):
        if source.get("ecosystem") not in _CA9_ECOSYSTEMS:
            continue
        if source.get("source_kind") not in {SOURCE_GIT, SOURCE_URL}:
            continue
        record = {
            "kind": source["source_kind"],
            "ecosystem": source["ecosystem"],
            "name": _normalized_name(source["ecosystem"], source.get("name") or ""),
            "version": source.get("version") or "",
            "direct": source.get("direct") is not False,
            "dev": source.get("dev") is True,
            "registry": None,
            "registry_mode": None,
            "registries": [],
            "integrity": source.get("integrity"),
            "integrity_recorded": False,
            "lockfile": False,
            "source_url": source.get("source_url"),
            "source_ref": source.get("source_ref"),
            "file": str(source.get("file") or ""),
            "line": source.get("line") or 1,
            "snippet": source.get("source_url") or "",
        }
        if _lockfile_covers(inventory, record):
            continue
        records.append(record)
    return records


def _ca9_package(record: dict) -> dict:
    package = {
        "ecosystem": _CA9_ECOSYSTEMS[record["ecosystem"]],
        "name": record["name"],
        "version": record["version"] or None,
        "direct": record["direct"],
        "dev": record["dev"],
        "registry": record["registry"],
        "registry_mode": record["registry_mode"],
        "source_kind": record["kind"],
        "source_url": record.get("source_url"),
        "integrity": record["integrity"],
        "file": record["file"],
        "line": record["line"],
        "lockfile": record["integrity_recorded"] is True,
    }
    if record.get("registries"):
        package["registries"] = list(record["registries"])
    return package


def _record_key(ecosystem: object, name: object, version: object) -> tuple:
    skylos_ecosystem = _SKYLOS_ECOSYSTEMS.get(
        str(ecosystem or "").lower(), str(ecosystem)
    )
    return (
        skylos_ecosystem,
        _normalized_name(skylos_ecosystem, str(name or "")),
        str(version or ""),
    )


def _match_record(finding: dict, index: dict, located: dict) -> dict | None:
    key = _record_key(
        finding.get("ecosystem"), finding.get("name"), finding.get("version")
    )
    exact = located.get((*key, str(finding.get("file") or ""), finding.get("line")))
    if exact is not None:
        return exact
    candidates = index.get(key) or []
    if candidates:
        return candidates[0]
    return None


def _confirmed(rule_id: str, record: dict, policy) -> bool:
    if rule_id == RULE_CONFUSION:
        return (
            bool(policy.internal_packages)
            and record["kind"] == SOURCE_REGISTRY
            and (
                bool(record.get("registry")) or record.get("registry_mode") == "merged"
            )
        )
    if rule_id == RULE_MUTABLE_SOURCE:
        return record["kind"] in {SOURCE_GIT, SOURCE_URL} and source_is_mutable(
            {
                "source_kind": record["kind"],
                "source_ref": record.get("source_ref"),
                "integrity": record.get("integrity"),
            }
        )
    if rule_id == RULE_MISSING_INTEGRITY:
        integrity = record.get("integrity")
        return (
            record["kind"] == SOURCE_REGISTRY
            and record.get("integrity_recorded") is True
            and not (isinstance(integrity, str) and integrity.strip())
        )
    if rule_id == RULE_RELEASE_AGE:
        return policy.scan_release_age_hours() is not None
    return False


def _text(value: object, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).replace("\n", " ").strip()
    return text[:MAX_EVIDENCE_TEXT] or default


def _evidence(finding: dict) -> dict:
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return {}
    kept = {}
    for key, value in list(evidence.items())[:20]:
        if isinstance(value, (str, int, float, bool)) or value is None:
            kept[str(key)[:60]] = value
        elif isinstance(value, list):
            kept[str(key)[:60]] = [
                item for item in value[:10] if isinstance(item, (str, int, float, bool))
            ]
    return kept


def _package_label(record: dict) -> str:
    if record.get("version"):
        return f"{record['name']}@{record['version']}"
    return record["name"] or "dependency"


def _message(rule_id: str, record: dict, evidence: dict, policy) -> str:
    label = _package_label(record)
    if rule_id == RULE_CONFUSION:
        pattern = _text(
            evidence.get("internal_pattern"), "a configured internal pattern"
        )
        mode = ""
        if record.get("registry_mode") == "merged":
            mode = " through an extra index that pip merges with the public one"
        return (
            f"{label} matches internal package pattern {pattern} but resolves from "
            f"{record.get('registry')}{mode}. Anyone can publish that name on the "
            "public registry (dependency confusion). Install internal packages only "
            "from your private registry: an exclusive --index-url or a scoped registry."
        )
    if rule_id == RULE_MUTABLE_SOURCE:
        url = _text(record.get("source_url"), "an unpinned source")
        if record["kind"] == SOURCE_GIT:
            ref = record.get("source_ref")
            if ref:
                state = f"Git ref {_text(ref)}, not a full commit"
            else:
                state = "a Git branch with no ref (the default branch)"
            return (
                f"{label} installs from {url} at {state}: the code can change "
                "without any change in this repository. Pin it to a 40-character "
                "commit SHA."
            )
        return (
            f"{label} installs from {url} without a hash: the file at that URL can "
            "change. Add --hash=sha256:<digest> (or #sha256=<digest>), or install "
            "it from a registry."
        )
    if rule_id == RULE_MISSING_INTEGRITY:
        return (
            f"{label} has no integrity hash in {Path(record['file']).name}, so an "
            "install cannot verify the downloaded package. Regenerate the lockfile "
            "with your package manager and commit it."
        )
    hours = policy.scan_release_age_hours()
    age = evidence.get("age_hours")
    published = ""
    if isinstance(age, (int, float)) and not isinstance(age, bool):
        published = f" was published {round(float(age), 1)} hours ago,"
    suggested = _text(evidence.get("suggested_version"))
    advice = "Wait until it is older, or pin the newest version older than the window."
    if suggested:
        advice = f"Pin {record['name']}@{suggested} (older than the window) or wait."
    return (
        f"{label}{published} younger than the {hours}-hour minimum release age. "
        f"Most malicious versions are found and removed in their first hours. {advice}"
    )


def _severity(rule_id: str, record: dict) -> str:
    if rule_id == RULE_CONFUSION:
        if record["direct"]:
            return "CRITICAL"
        return "HIGH"
    if rule_id == RULE_RELEASE_AGE:
        return "HIGH"
    return "MEDIUM"


def _skylos_finding(rule_id: str, record: dict, finding: dict, policy) -> dict:
    evidence = _evidence(finding)
    signal = _text(finding.get("signal_type"))
    metadata = {
        "ecosystem": record["ecosystem"],
        "package_name": record["name"],
        "package_version": record["version"],
        "supply_chain_signal": signal,
        "engine": "ca9",
        "action": _text(finding.get("action")),
        "dependency_kind": "direct",
        "dependency_dev": record["dev"],
        "evidence": evidence,
    }
    if not record["direct"]:
        metadata["dependency_kind"] = "transitive"
    if rule_id == RULE_CONFUSION:
        metadata["registry"] = record.get("registry")
        metadata["registry_mode"] = record.get("registry_mode")
    if rule_id == RULE_MUTABLE_SOURCE:
        metadata["source_kind"] = record["kind"]
        metadata["source_url"] = record.get("source_url")
        metadata["source_ref"] = record.get("source_ref")
    return {
        "rule_id": rule_id,
        "category": "DEPENDENCY",
        "severity": _severity(rule_id, record),
        "message": _message(rule_id, record, evidence, policy),
        "file": record["file"],
        "file_path": record["file"],
        "line": record["line"],
        "line_number": record["line"],
        "snippet": record.get("snippet") or "",
        "symbol": _package_label(record),
        "metadata": metadata,
    }


def _options(policy) -> dict:
    age = policy.scan_release_age_hours()
    return {
        "internal_packages": list(policy.internal_packages),
        "private_registries": list(policy.private_registries),
        "trusted_registries": list(policy.trusted_registries),
        "min_release_age_hours": age,
        "check_provenance": False,
        "network": age is not None,
        "max_lookups": MAX_CA9_LOOKUPS,
        "cache_dir": None,
    }


def _checks(policy) -> list[str]:
    checks = [RULE_MUTABLE_SOURCE, RULE_MISSING_INTEGRITY]
    if policy.internal_packages:
        checks.insert(0, RULE_CONFUSION)
    if policy.scan_release_age_hours() is not None:
        checks.append(RULE_RELEASE_AGE)
    return checks


def _engine_receipt(result: Any) -> dict:
    receipt = None
    if isinstance(result, dict):
        receipt = result.get("receipt")
    if not isinstance(receipt, dict):
        return {"complete": False}
    kept: dict[str, Any] = {"complete": receipt.get("complete") is True}
    for key in ("checked", "lookups", "cache_hits"):
        value = receipt.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            kept[key] = value
    skipped = receipt.get("skipped")
    if isinstance(skipped, list):
        kept["skipped"] = [
            {"reason": _text(item.get("reason")), "count": item.get("count")}
            for item in skipped[:20]
            if isinstance(item, dict)
        ]
    return kept


def _only_feed_skips(engine: dict) -> bool:
    """Skylos checks malware through OSV; ca9 skipping its own feed lookup
    does not make the supply-chain checks incomplete."""
    skipped = engine.get("skipped") or []
    return bool(skipped) and all(
        str(item.get("reason") or "").startswith("malware_feed") for item in skipped
    )


def evaluate_supply_chain(inventory, policy, *, api=None) -> tuple[list[dict], dict]:
    """ca9-backed findings for ``inventory`` plus a receipt for sca_coverage."""
    receipt: dict[str, Any] = {
        "engine": "ca9",
        "checks": _checks(policy),
        "notes": [],
    }
    if api is None:
        api = load_ca9_api()
    if api is None or not callable(getattr(api, "evaluate_packages", None)):
        receipt["status"] = "unavailable"
        receipt["notes"].append(NOTE_API_UNAVAILABLE)
        return [], receipt
    receipt["api_version"] = getattr(api, "API_VERSION", None)
    records = (_registry_records(inventory) + _source_records(inventory))[
        :MAX_CA9_PACKAGES
    ]
    receipt["packages"] = len(records)
    if not records:
        receipt["status"] = "complete"
        return [], receipt
    try:
        result = api.evaluate_packages(
            [_ca9_package(record) for record in records], options=_options(policy)
        )
    except Exception as exc:  # noqa: BLE001 - engine failures become a receipt note
        logger.debug("ca9 evaluate_packages failed: %s", type(exc).__name__)
        receipt["status"] = "incomplete"
        receipt["notes"].append(NOTE_API_FAILED)
        receipt["error_type"] = type(exc).__name__
        return [], receipt
    engine = _engine_receipt(result)
    receipt.update(engine)
    receipt["status"] = "complete"
    if not engine.get("complete") and not _only_feed_skips(engine):
        receipt["status"] = "incomplete"
    index: dict[tuple, list[dict]] = {}
    located: dict[tuple, dict] = {}
    for record in records:
        key = (record["ecosystem"], record["name"], record["version"])
        index.setdefault(key, []).append(record)
        located.setdefault((*key, record["file"], record["line"]), record)
    findings: list[dict] = []
    seen: set[tuple] = set()
    unconfirmed = 0
    raw = None
    if isinstance(result, dict):
        raw = result.get("findings")
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        rule_id = SIGNAL_RULES.get(str(item.get("signal_type") or ""))
        if rule_id is None:
            continue
        record = _match_record(item, index, located)
        if record is None or not _confirmed(rule_id, record, policy):
            unconfirmed += 1
            continue
        identity = (
            rule_id,
            record["ecosystem"],
            record["name"],
            record["version"],
            record["file"],
            record["line"],
        )
        if identity in seen:
            continue
        seen.add(identity)
        findings.append(_skylos_finding(rule_id, record, item, policy))
    if unconfirmed:
        receipt["unconfirmed_findings"] = unconfirmed
    return findings, receipt


def _malware_id(finding: dict) -> str | None:
    for source in (finding, finding.get("evidence"), finding.get("metadata")):
        if not isinstance(source, dict):
            continue
        for key in _MALWARE_ID_KEYS:
            value = source.get(key)
            if isinstance(value, str) and _ADVISORY_ID_RE.fullmatch(value.strip()):
                return value.strip()
    return None


def _advisory_identities(findings: list[dict]) -> set[tuple]:
    identities = set()
    for finding in findings:
        metadata = finding.get("metadata") or {}
        key = _record_key(
            metadata.get("ecosystem"),
            metadata.get("package_name"),
            metadata.get("package_version"),
        )
        ids = {str(metadata.get("vuln_id") or "")}
        ids.update(str(alias) for alias in metadata.get("aliases") or [])
        for advisory_id in ids - {""}:
            identities.add((*key, advisory_id.upper()))
        if metadata.get("malicious") is True:
            identities.add((*key, "*malicious*"))
    return identities


def offline_malware(
    inventory, existing: list[dict], *, api=None
) -> tuple[list[dict], dict]:
    """Malware matches from the installed ca9 feed when OSV did not answer."""
    receipt: dict[str, Any] = {"source": "ca9_feed", "notes": []}
    if api is None:
        api = load_ca9_api()
    if api is None or not callable(getattr(api, "malware_matches", None)):
        receipt["status"] = "unavailable"
        receipt["notes"].append(NOTE_API_UNAVAILABLE)
        return [], receipt
    records = _registry_records(inventory)[:MAX_CA9_PACKAGES]
    try:
        matches = api.malware_matches(
            [_ca9_package(record) for record in records], feed_dir=None
        )
    except Exception as exc:  # noqa: BLE001 - feed failures become a receipt note
        logger.debug("ca9 malware_matches failed: %s", type(exc).__name__)
        receipt["error_type"] = type(exc).__name__
        if type(exc).__name__ == "FeedUnavailable":
            receipt["status"] = "unavailable"
            receipt["notes"].append(NOTE_FEED_UNAVAILABLE)
        else:
            receipt["status"] = "failed"
            receipt["notes"].append(NOTE_FEED_FAILED)
        return [], receipt
    index: dict[tuple, list[dict]] = {}
    located: dict[tuple, dict] = {}
    for record in records:
        key = (record["ecosystem"], record["name"], record["version"])
        index.setdefault(key, []).append(record)
        located.setdefault((*key, record["file"], record["line"]), record)
    known = _advisory_identities(existing)
    findings = []
    receipt["status"] = "checked"
    for item in matches or []:
        if not isinstance(item, dict):
            continue
        signal = str(item.get("signal_type") or "")
        if signal == "feed_unavailable":
            receipt["status"] = "unavailable"
            if NOTE_FEED_UNAVAILABLE not in receipt["notes"]:
                receipt["notes"].append(NOTE_FEED_UNAVAILABLE)
            continue
        if signal != "malware":
            continue
        record = _match_record(item, index, located)
        if record is None:
            continue
        advisory_id = _malware_id(item)
        key = (record["ecosystem"], record["name"], record["version"])
        if (*key, "*malicious*") in known:
            continue
        if advisory_id and (*key, advisory_id.upper()) in known:
            continue
        findings.append(_feed_finding(record, advisory_id, item))
        known.add((*key, "*malicious*"))
    receipt["matches"] = len(findings)
    return findings, receipt


def _feed_finding(record: dict, advisory_id: str | None, item: dict) -> dict:
    rule_id = RULE_FEED_MALWARE_FALLBACK
    shown_id = "ca9 malware feed"
    if advisory_id:
        rule_id = f"SKY-SCA-{advisory_id}"
        shown_id = advisory_id
    metadata = {
        "ecosystem": record["ecosystem"],
        "package_name": record["name"],
        "package_version": record["version"],
        "malicious": True,
        "malicious_evidence": ["ca9_feed_match"],
        "malware_source": "ca9_feed",
        "aliases": [],
        "fixed_version": None,
        "affected_range": "unknown",
        "references": [],
        "cvss_score": None,
        "advisory_status": "ca9_feed",
        "evidence": _evidence(item),
    }
    if advisory_id:
        metadata["vuln_id"] = advisory_id
        metadata["display_id"] = advisory_id
    return {
        "rule_id": rule_id,
        "category": "DEPENDENCY",
        "severity": "CRITICAL",
        "message": malicious_package_message(
            record["name"], record["version"], shown_id
        ),
        "file": record["file"],
        "file_path": record["file"],
        "line": record["line"],
        "line_number": record["line"],
        "snippet": record.get("snippet") or "",
        "symbol": _package_label(record),
        "metadata": metadata,
    }


__all__ = [
    "NOTE_API_FAILED",
    "NOTE_API_UNAVAILABLE",
    "NOTE_FEED_FAILED",
    "NOTE_FEED_UNAVAILABLE",
    "NOTE_FEED_USED",
    "RULE_CONFUSION",
    "RULE_MISSING_INTEGRITY",
    "RULE_MUTABLE_SOURCE",
    "RULE_RELEASE_AGE",
    "SIGNAL_RULES",
    "SUPPLY_CHAIN_RULES",
    "evaluate_supply_chain",
    "load_ca9_api",
    "offline_malware",
]
