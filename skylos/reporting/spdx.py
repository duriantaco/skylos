"""Offline SPDX 2.3 JSON export of Skylos's supported dependency inventory.

Spec: https://spdx.github.io/spdx-spec/v2.3/
Schema: https://github.com/spdx/spdx-spec/blob/support/2.3/schemas/spdx-schema.json

Same inventory and license evidence as the CycloneDX export. Anything Skylos
cannot prove is written as NOASSERTION: download locations, concluded
licenses, copyright text, and any declared license that was not found or not
recognized.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import skylos
from skylos.reporting.sbom import _graph, _identity, _occurrence
from skylos.rules.sca.licenses import (
    NOASSERTION,
    LicenseInventory,
    collect_licenses,
    license_ids,
)
from skylos.rules.sca.vulnerability_scanner import DependencyInventory

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
DOCUMENT_ID = "SPDXRef-DOCUMENT"
ROOT_ID = "SPDXRef-RootPackage"
NAMESPACE_BASE = "https://spdx.skylos.dev/spdxdocs"
_ID_UNSAFE = re.compile(r"[^A-Za-z0-9.-]+")


class SPDXExport(dict):
    """JSON document plus the offline inventory receipt."""

    def __init__(self, document: dict, receipt: dict):
        super().__init__(document)
        self.receipt = receipt


def _created() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    try:
        moment = (
            datetime.fromtimestamp(int(epoch), tz=timezone.utc)
            if epoch
            else datetime.now(timezone.utc)
        )
    except (ValueError, OverflowError, OSError):
        moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _package_id(purl: str) -> str:
    readable = _ID_UNSAFE.sub("-", purl.removeprefix("pkg:")).strip("-")[:80]
    digest = hashlib.sha256(purl.encode("utf-8")).hexdigest()[:10]
    return f"SPDXRef-Package-{readable}-{digest}"


def _is_direct(occurrence: dict) -> bool:
    return (
        occurrence.get("dependency_kind") == "direct"
        or "lockfile_version" not in occurrence
        or bool(occurrence.get("dependency_roots"))
    )


class _Inventory:
    """Package identities, license records, and occurrences keyed by purl."""

    def __init__(self, inventory, root: Path, licenses: LicenseInventory):
        self.identities: dict[str, tuple[str, str, str]] = {}
        self.licenses: dict[str, dict] = {}
        self.occurrences: dict[str, list[dict]] = defaultdict(list)
        self.direct: set[str] = set()
        self.invalid_identity_count = 0
        for dependency in inventory:
            identity = _identity(dependency)
            if identity is None:
                self.invalid_identity_count += 1
                continue
            ref, pkg_name, version = identity
            self.identities[ref] = (pkg_name, version, dependency["ecosystem"])
            self._add_license(ref, licenses.get_record(dependency))
            for item in dependency.get("dependency_occurrences", [dependency]):
                occurrence = _occurrence(item, root)
                self.occurrences[ref].append(occurrence)
                if _is_direct(occurrence):
                    self.direct.add(ref)
        self.ids = {ref: _package_id(ref) for ref in self.identities}

    def _add_license(self, ref: str, record: dict) -> None:
        current = self.licenses.get(ref)
        if current is None or (
            current["license"] == NOASSERTION and record["license"] != NOASSERTION
        ):
            self.licenses[ref] = record


def _receipt(inventory, collected: _Inventory, licenses: LicenseInventory) -> dict:
    receipt = dict(inventory.receipt)
    for field in ("queried_dependency_count", "cache_hit_count", "cache_policy"):
        receipt.pop(field, None)
    receipt["invalid_identity_count"] = collected.invalid_identity_count
    unlocked = [
        gap
        for gap in inventory.manifest_gaps
        if (str(Path(gap["file"]).parent), gap["ecosystem"])
        not in inventory.lockfile_projects
    ]
    receipt["unlocked_manifest_count"] = len(unlocked)
    receipt["complete"] = bool(
        receipt.get("complete")
        and not receipt.get("unsupported_lockfile_count")
        and not receipt.get("lockfile_limitation_count")
        and not collected.invalid_identity_count
        and not unlocked
    )
    if not receipt["complete"]:
        receipt["status"] = "incomplete"
    receipt["licenses"] = licenses.receipt
    return receipt


def _package(ref: str, collected: _Inventory) -> dict:
    pkg_name, version, ecosystem = collected.identities[ref]
    record = collected.licenses.get(ref) or {"license": NOASSERTION}
    locations = sorted(
        {f"{item['file']}:{item['line']}" for item in collected.occurrences[ref]}
    )
    return {
        "SPDXID": collected.ids[ref],
        "name": pkg_name,
        "versionInfo": version,
        "downloadLocation": NOASSERTION,
        "filesAnalyzed": False,
        "licenseConcluded": NOASSERTION,
        "licenseDeclared": record["license"],
        "copyrightText": NOASSERTION,
        "primaryPackagePurpose": "LIBRARY",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": ref,
            }
        ],
        "comment": (
            f"ecosystem={ecosystem}; license_source={record.get('source', 'none')}; "
            f"locations={','.join(locations)}"
        ),
    }


def _extracted_licenses(collected: _Inventory) -> list[dict]:
    """SPDX requires hasExtractedLicensingInfos for each LicenseRef used."""
    extracted: dict[str, str] = {}
    for record in collected.licenses.values():
        if record["license"] == NOASSERTION:
            continue
        for term in license_ids(record["license"]):
            base = term.split(" WITH ", 1)[0]
            if base.startswith("LicenseRef-"):
                extracted.setdefault(base, record.get("declared") or NOASSERTION)
    return [
        {"licenseId": key, "extractedText": value}
        for key, value in sorted(extracted.items())
    ]


def _relationship(source: str, kind: str, target: str, comment: str = "") -> dict:
    relationship = {
        "spdxElementId": source,
        "relationshipType": kind,
        "relatedSpdxElement": target,
    }
    if comment:
        relationship["comment"] = comment
    return relationship


def _relationships(collected: _Inventory, graph_complete: bool) -> list[dict]:
    ids = collected.ids
    relationships = [_relationship(DOCUMENT_ID, "DESCRIBES", ROOT_ID)]
    linked: set[str] = set()
    for ref in sorted(collected.direct):
        relationships.append(_relationship(ROOT_ID, "DEPENDS_ON", ids[ref]))
        linked.add(ref)
    # Package edges only from a complete recorded graph (same rule as CycloneDX).
    nodes = _graph(collected.occurrences) if graph_complete else []
    for node in nodes:
        for target in node["dependsOn"]:
            relationships.append(
                _relationship(ids[node["ref"]], "DEPENDS_ON", ids[target])
            )
            linked.add(target)
    for ref in sorted(set(collected.identities) - linked):
        relationships.append(
            _relationship(
                ROOT_ID,
                "OTHER",
                ids[ref],
                "Recorded in the inventory; dependency path from the root "
                "was not recorded.",
            )
        )
    return relationships


def _root_package(root_name: str) -> dict:
    return {
        "SPDXID": ROOT_ID,
        "name": root_name,
        "downloadLocation": NOASSERTION,
        "filesAnalyzed": False,
        "licenseConcluded": NOASSERTION,
        "licenseDeclared": NOASSERTION,
        "copyrightText": NOASSERTION,
        "primaryPackagePurpose": "SOURCE",
        "comment": "Scanned project root. Dependency inventory is pre-build "
        "evidence from supported manifests and lockfiles.",
    }


def _creation_comment(receipt: dict) -> str:
    status = (
        "Complete for supported inputs."
        if receipt["complete"]
        else "INCOMPLETE: some inputs could not be inventoried; the CycloneDX "
        "export's skylos:inventory:receipt lists each gap."
    )
    summary = {
        "complete": receipt["complete"],
        "invalid_identity_count": receipt["invalid_identity_count"],
        "unlocked_manifest_count": receipt["unlocked_manifest_count"],
        "licenses": receipt["licenses"],
    }
    return f"Offline pre-build dependency inventory. {status} Receipt: " + json.dumps(
        summary, sort_keys=True, separators=(",", ":")
    )


def spdx_document(
    inventory: DependencyInventory,
    root: Path,
    licenses: LicenseInventory | None = None,
    *,
    name: str | None = None,
) -> SPDXExport:
    """Build an SPDX 2.3 JSON document (dict) for the recorded inventory."""
    root = Path(root).resolve()
    if licenses is None:
        licenses = collect_licenses(inventory, root)
    collected = _Inventory(inventory, root, licenses)
    receipt = _receipt(inventory, collected, licenses)

    root_name = name or root.name or "project"
    fingerprint = hashlib.sha256(
        json.dumps(
            [root_name, sorted(collected.identities), skylos.__version__],
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    namespace_name = _ID_UNSAFE.sub("-", root_name).strip("-") or "project"
    document = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_ID,
        "name": f"{root_name}-sbom",
        "documentNamespace": f"{NAMESPACE_BASE}/{namespace_name}-{fingerprint}",
        "creationInfo": {
            "created": _created(),
            "creators": [f"Tool: skylos-{skylos.__version__}"],
            "comment": _creation_comment(receipt),
        },
        "packages": [
            _root_package(root_name),
            *(_package(ref, collected) for ref in sorted(collected.identities)),
        ],
        "relationships": _relationships(collected, receipt["complete"]),
    }
    extracted = _extracted_licenses(collected)
    if extracted:
        document["hasExtractedLicensingInfos"] = extracted
    return SPDXExport(document, receipt)
