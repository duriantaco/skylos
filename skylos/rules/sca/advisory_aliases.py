"""Combine OSV aliases without losing source evidence or inventing a fix.

Only package-matched advisory details may establish an alias relationship.
Related IDs, shared titles and shared reference URLs are not equivalence proof.
"""

from __future__ import annotations

from copy import deepcopy

from skylos.rules.sca.osv_client import is_valid_advisory_id

_SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _advisory_order(record: dict) -> tuple[int, str]:
    advisory_id = record["vuln_id"]
    for rank, prefix in enumerate(("GHSA-", "CVE-", "PYSEC-")):
        if advisory_id.startswith(prefix):
            return rank, advisory_id
    return 3, advisory_id


def _append_unique(destination: list, values: list) -> None:
    for value in values:
        if value not in destination:
            destination.append(value)


def _merge_records(records: list[dict]) -> dict:
    records = sorted(records, key=_advisory_order)
    merged = deepcopy(records[0])
    merged["advisory_records"] = deepcopy(records)
    merged["advisory_ids"] = []
    aliases = set()
    merged["references"] = []
    merged["fixed_versions"] = []
    merged["severity_vectors"] = []
    merged["severity"] = "UNKNOWN"
    merged["cvss_score"] = None
    all_complete = True
    errors = {}
    for record in records:
        advisory_id = record["vuln_id"]
        merged["advisory_ids"].append(advisory_id)
        aliases.add(advisory_id)
        for alias in record.get("aliases", []):
            if is_valid_advisory_id(alias):
                aliases.add(alias)
        for field in ("references", "fixed_versions", "severity_vectors"):
            _append_unique(merged[field], record.get(field, []))
        severity = record.get("severity", "UNKNOWN")
        if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER[merged["severity"]]:
            merged["severity"] = severity
        score = record.get("cvss_score")
        if score is not None:
            if merged["cvss_score"] is None or score > merged["cvss_score"]:
                merged["cvss_score"] = score
        if record.get("advisory_status") != "complete":
            all_complete = False
        if record.get("advisory_error"):
            errors[advisory_id] = record["advisory_error"]

    aliases.remove(merged["vuln_id"])
    merged["aliases"] = sorted(aliases)
    merged["advisory_status"] = "complete"
    if not all_complete:
        merged["advisory_status"] = "incomplete"
        merged["advisory_error"] = "alias_details_incomplete"
    if errors:
        merged["advisory_errors"] = errors

    # A union of publishers' fixes is evidence, not a universally safe upgrade.
    fixed = records[0].get("fixed_version")
    affected_range = records[0].get("affected_range", "unknown")
    withdrawn = records[0].get("withdrawn")
    conflicts = []
    for field in (
        "fixed_version",
        "affected_range",
        "severity",
        "cvss_score",
        "withdrawn",
    ):
        for record in records[1:]:
            if record.get(field) != records[0].get(field):
                conflicts.append(field)
                break
    for record in records:
        if record.get("fixed_version") != fixed or record.get("withdrawn"):
            fixed = None
        if record.get("affected_range", "unknown") != affected_range:
            affected_range = "unknown"
        if record.get("withdrawn") != withdrawn:
            withdrawn = None
    if not all_complete:
        fixed = None
    merged["fixed_version"] = fixed
    merged["affected_range"] = affected_range
    merged["withdrawn"] = withdrawn
    if conflicts:
        merged["advisory_conflicts"] = conflicts
    return merged


def merge_advisory_aliases(matches: list[tuple[dict, dict]]) -> list[tuple[dict, dict]]:
    """Merge alias-connected matches within one exact dependency identity.

    The inventory already retains dependency occurrences on each identity. No
    dependency metadata is changed here. Unavailable details cannot establish
    edges, but an available advisory can identify an unavailable match as an
    alias; that source and the incomplete lookup remain explicit in the result.
    """
    parents = list(range(len(matches)))

    def root(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    owners = {}
    dependency_contexts = {}
    for index, (dependency, record) in enumerate(matches):
        identity = (dependency["ecosystem"], dependency["name"], dependency["version"])
        contexts = dependency_contexts.setdefault(identity, [])
        if dependency not in contexts:
            contexts.append(dependency)
        # Conditional project references can share a package/version while
        # carrying different source and scope evidence. Do not drop either.
        identity += (contexts.index(dependency),)
        advisory_ids = [record["vuln_id"]]
        if record.get("advisory_status") == "complete":
            for alias in record.get("aliases", []):
                if is_valid_advisory_id(alias):
                    advisory_ids.append(alias)
        for advisory_id in advisory_ids:
            key = (*identity, advisory_id)
            previous = owners.get(key)
            if previous is None:
                owners[key] = index
            else:
                parents[root(index)] = root(previous)

    groups = {}
    for index, match in enumerate(matches):
        groups.setdefault(root(index), []).append(match)
    result = []
    for group in groups.values():
        if len(group) == 1:
            result.append(group[0])
            continue
        records = []
        for dependency, record in group:
            records.append(record)
        result.append((group[0][0], _merge_records(records)))
    return result
