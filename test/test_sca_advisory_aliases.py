"""Alias equivalence must generalize across packages and OSV ecosystems."""

from copy import deepcopy
from itertools import permutations
import json

import pytest

from skylos.rules.sca import vulnerability_scanner as sca
from skylos.rules.sca.advisory_aliases import merge_advisory_aliases
from skylos.rules.sca.advisory_metadata import extract_advisory_metadata
from test.test_sca_advisories import Transport, advisory, dependency

FIRST = "GHSA-unit-first"
SECOND = "PYSEC-2099-100"
CVE = "CVE-2099-12345"


def _document(advisory_id, dep, aliases=(), fixed="3.0.0", severity="HIGH"):
    document = advisory(advisory_id, dep["name"])
    document["aliases"] = list(aliases)
    document["database_specific"]["severity"] = severity
    affected = document["affected"][0]
    affected["package"]["ecosystem"] = dep["ecosystem"]
    if dep["ecosystem"] in {"PyPI", "NuGet"}:
        affected["ranges"][0]["type"] = "ECOSYSTEM"
    affected["ranges"][0]["events"][1]["fixed"] = fixed
    return document


def _scan(monkeypatch, documents, dependencies=None, advisory_ids=None):
    if dependencies is None:
        dependencies = [dependency()]
    if advisory_ids is None:
        advisory_ids = list(documents)
    results = []
    for _dep in dependencies:
        vulns = []
        for advisory_id in advisory_ids:
            vulns.append({"id": advisory_id})
        results.append({"vulns": vulns})
    monkeypatch.setattr(sca, "_requests", Transport(results, documents))
    cache = {}
    result = sca._query_osv_batch(dependencies, cache)
    return result, cache


@pytest.mark.parametrize("ecosystem", ["PyPI", "npm", "Go", "NuGet"])
@pytest.mark.parametrize("relationship", ["one_way", "shared_alias"])
def test_equivalent_advisories_merge_across_ecosystems(
    monkeypatch, ecosystem, relationship
):
    dep = dependency()
    dep["ecosystem"] = ecosystem
    fixed = "3.0.0"
    if ecosystem == "Go":
        dep["version"] = "v1.0.0"
        fixed = "v3.0.0"
    aliases = [SECOND]
    if relationship == "shared_alias":
        aliases = [CVE]
    documents = {
        FIRST: _document(FIRST, dep, aliases, fixed, "LOW"),
        SECOND: _document(SECOND, dep, [CVE], fixed, "HIGH"),
    }

    result, cache = _scan(monkeypatch, documents, [dep])

    assert len(result) == 1
    finding = result[0]
    assert finding["rule_id"] == "SKY-SCA-" + FIRST
    assert finding["severity"] == "HIGH"
    assert finding["metadata"]["fixed_version"] == fixed
    assert finding["metadata"]["advisory_ids"] == [FIRST, SECOND]
    assert finding["metadata"]["aliases"] == [CVE, SECOND]
    assert len(finding["metadata"]["references"]) == 2
    assert len(finding["metadata"]["advisory_records"]) == 2
    assert result.receipt["complete"] is True
    assert result.receipt["advisory_details"]["requested_count"] == 2
    assert len(cache[f"{ecosystem}:example:{dep['version']}"]) == 1


@pytest.mark.parametrize("order", list(permutations([FIRST, SECOND, "OSV-unit-third"])))
def test_transitive_aliases_are_stable_under_batch_order(monkeypatch, order):
    dep = dependency()
    documents = {
        FIRST: _document(FIRST, dep, [CVE]),
        SECOND: _document(SECOND, dep, [CVE, "ALIAS-unit-link"]),
        "OSV-unit-third": _document("OSV-unit-third", dep, ["ALIAS-unit-link"]),
    }

    result, _cache = _scan(monkeypatch, documents, advisory_ids=order)
    reference, _cache = _scan(monkeypatch, documents)

    assert len(result) == 1
    assert result == reference
    assert result[0]["metadata"]["advisory_ids"] == [FIRST, SECOND, "OSV-unit-third"]


def test_similar_advisories_and_related_ids_remain_separate(monkeypatch):
    dep = dependency()
    first = _document(FIRST, dep)
    second = deepcopy(first)
    second["id"] = SECOND
    first["related"] = [SECOND]
    second["related"] = [FIRST]

    result, _cache = _scan(monkeypatch, {FIRST: first, SECOND: second})

    assert len(result) == 2
    assert result[0]["message"] == result[1]["message"]
    assert "advisory_records" not in result[0]["metadata"]


@pytest.mark.parametrize("difference", ["ecosystem", "name", "version"])
def test_aliases_do_not_cross_dependency_identities(monkeypatch, difference):
    first_dep = dependency()
    second_dep = deepcopy(first_dep)
    second_dep[difference] = {"ecosystem": "PyPI", "name": "other", "version": "2.0.0"}[
        difference
    ]
    second_dep["file"] = "/fixture/second-lock.json"
    documents = {}
    for advisory_id in (FIRST, SECOND):
        document = _document(advisory_id, first_dep, [CVE])
        other_affected = deepcopy(document["affected"][0])
        other_affected["package"] = {
            "name": second_dep["name"],
            "ecosystem": second_dep["ecosystem"],
        }
        document["affected"].append(other_affected)
        documents[advisory_id] = document

    result, _cache = _scan(monkeypatch, documents, [first_dep, second_dep])

    assert len(result) == 2
    assert result[0]["file"] != result[1]["file"]
    assert result[0]["metadata"]["package_version"] == first_dep["version"]
    assert result[1]["metadata"]["package_version"] == second_dep["version"]


def test_dependency_occurrences_and_scope_survive_alias_merging(monkeypatch):
    dep = dependency()
    dep["dependency_dev"] = True
    dep["dependency_occurrences"] = [
        {"file": "/fixture/a.lock", "line": 9, "dependency_groups": ["dev"]},
        {"file": "/fixture/b.lock", "line": 17, "dependency_groups": ["tools"]},
    ]
    before = deepcopy(dep)
    documents = {
        FIRST: _document(FIRST, dep, [CVE]),
        SECOND: _document(SECOND, dep, [CVE]),
    }

    result, _cache = _scan(monkeypatch, documents, [dep])

    assert (
        result[0]["metadata"]["dependency_occurrences"] == dep["dependency_occurrences"]
    )
    assert result[0]["metadata"]["dependency_dev"] is True
    assert dep == before


def test_distinct_dependency_contexts_are_not_lost_by_alias_grouping():
    first_dep = dependency()
    second_dep = deepcopy(first_dep)
    second_dep["file"] = "/fixture/other-project/package-lock.json"
    second_dep["conditional"] = True
    matches = []
    for dep, advisory_id in ((first_dep, FIRST), (second_dep, SECOND)):
        record = extract_advisory_metadata(_document(advisory_id, dep, [CVE]), dep)
        record["advisory_status"] = "complete"
        matches.append((dep, record))

    merged = merge_advisory_aliases(matches)

    assert len(merged) == 2
    assert merged[0][0] == first_dep
    assert merged[1][0] == second_dep


@pytest.mark.parametrize("missing", [None, ConnectionError("offline")])
def test_one_way_alias_can_merge_missing_detail_without_claiming_complete(
    monkeypatch, missing
):
    dep = dependency()
    documents = {FIRST: _document(FIRST, dep, [SECOND]), SECOND: missing}

    result, cache = _scan(monkeypatch, documents)

    assert len(result) == 1
    assert result[0]["severity"] == "HIGH"
    metadata = result[0]["metadata"]
    assert metadata["advisory_status"] == "incomplete"
    assert SECOND in metadata["advisory_errors"]
    assert len(metadata["advisory_records"]) == 2
    assert metadata["fixed_version"] is None
    assert metadata["fixed_versions"] == ["3.0.0"]
    assert "Upgrade to" not in result[0]["message"]
    assert result.receipt["complete"] is False
    assert result.receipt["advisory_details"]["failed_count"] == 1
    assert cache["npm:example:1.0.0"][0]["advisory_status"] == "incomplete"


def test_wrong_package_cannot_establish_an_alias_edge(monkeypatch):
    dep = dependency()
    unrelated = dependency(name="unrelated")
    documents = {
        FIRST: _document(FIRST, dep),
        SECOND: _document(SECOND, unrelated, [FIRST]),
    }

    result, _cache = _scan(monkeypatch, documents)

    assert len(result) == 2
    assert result[1]["metadata"]["advisory_error"] == "package_mismatch"
    assert result.receipt["advisory_context_error_count"] == 1
    assert result.receipt["complete"] is False


def test_alias_link_to_wrong_package_retains_error_without_using_its_fix(monkeypatch):
    dep = dependency()
    unrelated = dependency(name="unrelated")
    documents = {
        FIRST: _document(FIRST, dep, [SECOND], severity="LOW"),
        SECOND: _document(
            SECOND, unrelated, [FIRST], fixed="9.0.0", severity="CRITICAL"
        ),
    }

    result, _cache = _scan(monkeypatch, documents)

    assert len(result) == 1
    assert result[0]["severity"] == "LOW"
    assert result[0]["metadata"]["advisory_errors"] == {SECOND: "package_mismatch"}
    assert result[0]["metadata"]["fixed_versions"] == ["3.0.0"]
    assert result[0]["metadata"]["fixed_version"] is None
    assert result.receipt["complete"] is False


@pytest.mark.parametrize("alias", ["", "../../same", "same alias", "x" * 201])
def test_invalid_alias_tokens_cannot_join_independent_advisories(monkeypatch, alias):
    dep = dependency()
    documents = {
        FIRST: _document(FIRST, dep, [alias]),
        SECOND: _document(SECOND, dep, [alias]),
    }

    result, _cache = _scan(monkeypatch, documents)

    assert len(result) == 2


def test_conflicting_fixes_preserve_sources_without_inventing_upgrade(monkeypatch):
    dep = dependency()
    documents = {
        FIRST: _document(FIRST, dep, [CVE], fixed="3.0.0", severity="LOW"),
        SECOND: _document(SECOND, dep, [CVE], fixed="4.0.0", severity="HIGH"),
    }

    result, _cache = _scan(monkeypatch, documents)

    assert len(result) == 1
    finding = result[0]
    metadata = finding["metadata"]
    assert finding["severity"] == "HIGH"
    assert metadata["fixed_version"] is None
    assert metadata["fixed_versions"] == ["3.0.0", "4.0.0"]
    assert metadata["affected_range"] == "unknown"
    assert "fixed_version" in metadata["advisory_conflicts"]
    assert "affected_range" in metadata["advisory_conflicts"]
    assert metadata["advisory_records"][0]["fixed_version"] == "3.0.0"
    assert metadata["advisory_records"][1]["fixed_version"] == "4.0.0"
    assert "Upgrade to" not in finding["message"]
    assert result.receipt["complete"] is True


def test_missing_fix_in_complete_alias_does_not_become_a_universal_upgrade(monkeypatch):
    dep = dependency()
    minimal = _document(SECOND, dep, [CVE])
    minimal["affected"][0].pop("ranges")
    documents = {FIRST: _document(FIRST, dep, [CVE]), SECOND: minimal}

    result, _cache = _scan(monkeypatch, documents)

    assert result[0]["metadata"]["fixed_version"] is None
    assert result[0]["metadata"]["fixed_versions"] == ["3.0.0"]
    assert result.receipt["complete"] is True


def test_withdrawn_alias_does_not_mark_active_advisory_withdrawn(monkeypatch):
    dep = dependency()
    first = _document(FIRST, dep, [CVE])
    first["withdrawn"] = "2099-01-01T00:00:00Z"
    documents = {FIRST: first, SECOND: _document(SECOND, dep, [CVE])}

    result, _cache = _scan(monkeypatch, documents)

    metadata = result[0]["metadata"]
    assert metadata["withdrawn"] is None
    assert metadata["fixed_version"] is None
    assert metadata["advisory_records"][0]["withdrawn"] == first["withdrawn"]
    assert "withdrawn" in metadata["advisory_conflicts"]


def test_numeric_severity_and_vectors_preserve_strongest_source(monkeypatch):
    dep = dependency()
    first = _document(FIRST, dep, [CVE], severity="HIGH")
    first["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}]
    second = _document(SECOND, dep, [CVE], severity="LOW")
    second["severity"] = [{"type": "CVSS_V3", "score": "9.8"}]

    result, _cache = _scan(monkeypatch, {FIRST: first, SECOND: second})

    assert result[0]["severity"] == "CRITICAL"
    assert result[0]["metadata"]["cvss_score"] == 9.8
    assert result[0]["metadata"]["severity_vectors"] == first["severity"]


def test_normalized_cache_round_trip_preserves_finding_and_source_records(monkeypatch):
    dep = dependency()
    documents = {
        FIRST: _document(FIRST, dep, [CVE]),
        SECOND: _document(SECOND, dep, [CVE]),
    }
    result, cache = _scan(monkeypatch, documents)
    restored = json.loads(json.dumps(cache))

    recreated = sca._make_finding(dep, restored["npm:example:1.0.0"][0])

    assert recreated == result[0]
    source = restored["npm:example:1.0.0"][0]
    before = deepcopy(source)
    assert merge_advisory_aliases([(dep, source)]) == [(dep, source)]
    assert source == before


@pytest.mark.parametrize("selected", [FIRST, SECOND, CVE, SECOND.lower()])
def test_explicit_selection_retains_canonical_or_alias_finding(monkeypatch, selected):
    from skylos.cli import _apply_rule_selection

    dep = dependency()
    documents = {
        FIRST: _document(FIRST, dep, [CVE]),
        SECOND: _document(SECOND, dep, [CVE]),
    }
    findings, _cache = _scan(monkeypatch, documents)
    report = {"dependency_vulnerabilities": findings}

    selected_report = _apply_rule_selection(report, ["SKY-SCA-" + selected])

    assert selected_report["dependency_vulnerabilities"] == findings
    assert selected_report["analysis_summary"]["sca_count"] == 1


def test_selection_does_not_borrow_aliases_from_other_categories_or_related_ids():
    from skylos.cli import _apply_rule_selection

    finding = {
        "rule_id": "SKY-SCA-" + FIRST,
        "metadata": {"aliases": [CVE], "related": [SECOND]},
    }
    report = {"dependency_vulnerabilities": [finding], "quality": [finding]}

    selected = _apply_rule_selection(report, ["SKY-SCA-" + CVE])
    unrelated = _apply_rule_selection(report, ["SKY-SCA-" + SECOND])

    assert selected["dependency_vulnerabilities"] == [finding]
    assert selected["quality"] == []
    assert unrelated["dependency_vulnerabilities"] == []


def test_compact_upload_preserves_alias_sources_and_incomplete_status(monkeypatch):
    from skylos.api._payloads import _compact_finding_metadata
    from skylos.core.sca_baseline import dependency_fingerprints

    dep = dependency()
    documents = {FIRST: _document(FIRST, dep, [SECOND]), SECOND: None}
    result, _cache = _scan(monkeypatch, documents)
    metadata = result[0]["metadata"]
    before = deepcopy(metadata)

    compact = _compact_finding_metadata(metadata)

    assert compact["aliases"] == metadata["aliases"]
    assert compact["advisory_ids"] == metadata["advisory_ids"]
    assert compact["advisory_records"] == metadata["advisory_records"]
    assert compact["advisory_record_count"] == 2
    assert compact["advisory_status"] == "incomplete"
    assert "advisory_evidence_truncated" not in compact
    assert metadata == before
    assert dependency_fingerprints(result[0], "/fixture") is None


def test_compact_upload_bounds_large_evidence_with_explicit_truncation():
    from skylos.api._payloads import _compact_finding_metadata, _json_size_bytes

    identifiers = []
    records = []
    for index in range(600):
        advisory_id = f"OSV-2099-{index}"
        identifiers.append(advisory_id)
        records.append({"vuln_id": advisory_id, "summary": "x" * 300})
    metadata = {
        "advisory_ids": identifiers,
        "aliases": identifiers,
        "advisory_records": records,
        "advisory_status": "incomplete",
        "advisory_error": "alias_details_incomplete",
    }
    before = deepcopy(metadata)

    compact = _compact_finding_metadata(metadata)

    assert len(compact["advisory_ids"]) == 512
    assert len(compact["aliases"]) == 512
    assert len(compact["advisory_records"]) < 512
    assert compact["advisory_record_count"] == 600
    assert compact["advisory_evidence_truncated"] is True
    assert compact["advisory_status"] == "incomplete"
    assert _json_size_bytes(compact["advisory_records"]) < 66_000
    assert metadata == before


def test_oversized_source_record_does_not_erase_other_compact_evidence():
    from skylos.api._payloads import _compact_finding_metadata

    metadata = {
        "advisory_records": [
            {"vuln_id": FIRST, "summary": "x" * 70_000},
            {"vuln_id": SECOND, "advisory_error": "http_404"},
        ],
        "advisory_status": "incomplete",
    }

    compact = _compact_finding_metadata(metadata)

    assert compact["advisory_record_count"] == 2
    assert compact["advisory_records"] == [metadata["advisory_records"][1]]
    assert compact["advisory_evidence_truncated"] is True
    assert compact["advisory_status"] == "incomplete"
