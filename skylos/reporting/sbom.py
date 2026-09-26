"""Offline CycloneDX 1.6 export of Skylos's supported dependency inventory.

Schema: https://cyclonedx.org/schema/bom-1.6.schema.json
This is pre-build evidence, not an installed-environment attestation. Declared
licenses come from offline package metadata (see skylos.rules.sca.licenses);
anything not provable stays unknown rather than guessed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote

import skylos

from skylos.rules.sca.licenses import (
    _CANONICAL_IDS,
    NOASSERTION,
    LicenseInventory,
    collect_licenses,
)
from skylos.rules.sca.npm_lockfile import _exact_version, _name as _npm_name
from skylos.rules.sca.poetry_lockfile import _version as _pypi_version
from skylos.rules.sca.uv_lockfile import _name as _pypi_name
from skylos.rules.sca.vulnerability_scanner import (
    DependencyInventory,
    _DEPENDENCY_CONTEXT_KEYS,
    _NUGET_NAME_RE,
    _NUGET_VERSION_RE,
    _nuget_is_queryable,
)

_PURL_TYPES = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "NuGet": "nuget"}
_SOURCE_REFERENCE = re.compile(r"://|\b(?:git@|git\+|file:|link:|portal:)")
_GO_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~+/-]{0,511}\Z")


class CycloneDXExport(dict):
    """JSON document plus its offline export receipt (not an SCA result)."""

    def __init__(self, document: dict, receipt: dict):
        super().__init__(document)
        self.receipt = receipt


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _context(value: object, depth: int = 0) -> object:
    """Keep recorded context, excluding transport URLs and raw source snippets."""
    if depth > 20:
        return "[omitted:context_depth_limit]"
    if isinstance(value, str):
        if _SOURCE_REFERENCE.search(value):
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
            return f"[redacted:source:{digest}]"
        return value
    if isinstance(value, dict):
        return {
            str(_context(str(key))): _context(item, depth + 1)
            for key, item in value.items()
            if key not in {"snippet", "source", "url", "resolved", "integrity"}
        }
    if isinstance(value, (list, tuple)):
        return [_context(item, depth + 1) for item in value]
    return value


def _relative_file(value: str, root: Path) -> str:
    # Inputs are locations supplied by the inventory, not requests to read files.
    try:
        return Path(value).relative_to(root).as_posix()
    except ValueError:
        return "[outside-scan-root]"


def _occurrence(value: dict, root: Path) -> dict:
    result = {
        "file": _relative_file(value["file"], root),
        "line": value.get("line", 1),
    }
    for key in _DEPENDENCY_CONTEXT_KEYS:
        if key in value:
            result[key] = _context(value[key])
    return result


def _identity(dependency: dict) -> tuple[str, str, str] | None:
    kind = _PURL_TYPES.get(dependency["ecosystem"])
    name, version = dependency["name"], dependency["version"]
    if kind == "pypi":
        name = _pypi_name(name)
        if name is None or not _pypi_version(version):
            return None
        version = version.lower()
    elif kind == "npm":
        if _npm_name(name) is None or _exact_version(version) is None:
            return None
    elif kind == "golang":
        if (
            not isinstance(name, str)
            or not _GO_NAME.fullmatch(name)
            or any(part in {"", ".", ".."} for part in name.split("/"))
            or not isinstance(version, str)
            or _exact_version(version.removeprefix("v")) is None
        ):
            return None
        version = "v" + version.removeprefix("v")
    elif kind == "nuget":
        if (
            not _nuget_is_queryable(dependency)
            or not _NUGET_NAME_RE.fullmatch(name)
            or not _NUGET_VERSION_RE.fullmatch(version)
        ):
            return None
        name = name.lower()
    else:
        return None
    # Scope separators remain separators; an npm scope's @ is percent encoded.
    purl = f"pkg:{kind}/{quote(name, safe='/')}@{quote(version, safe='')}"
    return purl, name, version


def _graph(components: dict[str, list[dict]]) -> list[dict]:
    locations: dict[tuple[str, str], set[str]] = defaultdict(set)
    for ref, occurrences in components.items():
        for occurrence in occurrences:
            if "package_path" in occurrence:
                locations[(occurrence["file"], occurrence["package_path"])].add(ref)

    graph = []
    for ref, occurrences in sorted(components.items()):
        # A direct manifest pin doesn't specify the package's own dependencies.
        locked = [item for item in occurrences if "lockfile_version" in item]
        targets = set()
        known = bool(locked)
        for occurrence in locked:
            if (
                "dependencies" not in occurrence
                or occurrence.get("dependency_graph_complete") is False
            ):
                known = False
                break
            for edge in occurrence["dependencies"]:
                candidates = locations.get(
                    (occurrence["file"], edge.get("package_path", "")), set()
                )
                if len(candidates) != 1:
                    known = False
                    break
                targets.update(candidates)
        # Missing nodes mean unknown dependencies in CycloneDX. In particular,
        # never turn an unresolved edge into an apparently dependency-free node.
        if known:
            graph.append({"ref": ref, "dependsOn": sorted(targets)})
    return graph


_SPDX_ID_VALUES = frozenset(_CANONICAL_IDS.values())


def cyclonedx_licenses(expression: str) -> list[dict] | None:
    """CycloneDX ``licenses`` for a normalized SPDX expression; None if unknown."""
    if not expression or expression == NOASSERTION:
        return None
    if expression in _SPDX_ID_VALUES:
        return [{"license": {"id": expression}}]
    return [{"expression": expression}]


def cyclonedx_bom(
    inventory: DependencyInventory,
    root: Path,
    licenses: LicenseInventory | None = None,
) -> CycloneDXExport:
    """Build deterministic JSON-compatible CycloneDX, including healthy packages."""
    root = Path(root).resolve()
    if licenses is None:
        licenses = collect_licenses(inventory, root)
    license_by_ref: dict[str, dict] = {}
    identities = {}
    invalid_identity_count = 0
    occurrences: dict[str, list[dict]] = defaultdict(list)
    for dependency in inventory:
        identity = _identity(dependency)
        if identity is None:
            invalid_identity_count += 1
            continue
        ref, name, version = identity
        identities[ref] = (name, version, dependency["ecosystem"])
        record = licenses.get_record(dependency)
        if ref not in license_by_ref or (
            license_by_ref[ref]["license"] == NOASSERTION
            and record["license"] != NOASSERTION
        ):
            license_by_ref[ref] = record
        for item in dependency.get("dependency_occurrences", [dependency]):
            occurrences[ref].append(_occurrence(item, root))

    components = []
    for ref, (name, version, ecosystem) in sorted(identities.items()):
        # Stable output across traversal and duplicate occurrence order.
        contexts = sorted({_json(item) for item in occurrences[ref]})
        occurrences[ref] = [json.loads(item) for item in contexts]
        component = {
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "version": version,
            "purl": ref,
            "properties": [
                {"name": "skylos:ecosystem", "value": ecosystem},
                *(
                    {"name": "skylos:dependency:occurrence", "value": item}
                    for item in contexts
                ),
            ],
            "evidence": {
                "occurrences": [
                    json.loads(item)
                    for item in sorted(
                        {
                            _json({"location": item["file"], "line": item["line"]})
                            for item in occurrences[ref]
                        }
                    )
                ]
            },
        }
        record = license_by_ref.get(ref)
        declared = cyclonedx_licenses(record["license"]) if record else None
        if declared:
            component["licenses"] = declared
            component["properties"].append(
                {"name": "skylos:license:source", "value": record["source"]}
            )
        if ecosystem == "npm" and name.startswith("@") and "/" in name:
            component["group"], component["name"] = name.split("/", 1)
        components.append(component)

    receipt = dict(inventory.receipt)
    receipt["lockfile_issues"] = [
        {**issue, "file": _relative_file(issue["file"], root)}
        for issue in receipt.get("lockfile_issues", [])
    ]
    receipt["lockfile_limitations"] = [
        {**limitation, "file": _relative_file(limitation["file"], root)}
        for limitation in receipt.get("lockfile_limitations", [])
    ]
    receipt["ignored_lockfiles"] = [
        {
            **item,
            "file": _relative_file(item["file"], root),
            "selected_file": _relative_file(item["selected_file"], root),
        }
        for item in receipt.get("ignored_lockfiles", [])
    ]
    # Query/cache fields belong to SCA, not an offline SBOM operation.
    for field in ("queried_dependency_count", "cache_hit_count", "cache_policy"):
        receipt.pop(field, None)
    receipt["invalid_identity_count"] = invalid_identity_count
    # Manifest-only ranges cannot produce an exact-version SBOM. With a parsed
    # lock, retain the existing inventory's explicit freshness/range limitations.
    unlocked = [
        gap
        for gap in inventory.manifest_gaps
        if (str(Path(gap["file"]).parent), gap["ecosystem"])
        not in inventory.lockfile_projects
    ]
    receipt["unlocked_manifest_count"] = len(unlocked)
    receipt["unlocked_manifest_files"] = sorted(
        {_relative_file(gap["file"], root) for gap in unlocked}
    )
    # SCA may finish despite known coverage limits, but an exact SBOM may not.
    receipt["complete"] = bool(
        receipt.get("complete")
        and not receipt.get("unsupported_lockfile_count")
        and not receipt.get("lockfile_limitation_count")
        and not invalid_identity_count
        and not unlocked
    )
    if not receipt["complete"]:
        receipt["status"] = "incomplete"
    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "lifecycles": [{"phase": "pre-build"}],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "skylos",
                        "version": skylos.__version__,
                    }
                ]
            },
            "properties": [
                {"name": "skylos:inventory:receipt", "value": _json(_context(receipt))},
                {
                    "name": "skylos:inventory:scope",
                    "value": "supported_public_dependencies_all_recorded_environments",
                },
                {
                    "name": "skylos:dependency_graph",
                    "value": "recorded_resolved_edges_only",
                },
                {"name": "skylos:licenses", "value": _json(licenses.receipt)},
            ],
        },
        "components": components,
        # Some parsers retain known packages after rejecting malformed edges.
        # An incomplete inventory is not evidence that such a package is a leaf.
        "dependencies": _graph(occurrences) if receipt["complete"] else [],
        # Local packages, private sources, unresolved manifest ranges, and
        # runtime/platform selection are not a complete installed inventory.
        "compositions": [{"aggregate": "incomplete"}],
    }
    return CycloneDXExport(document, receipt)
