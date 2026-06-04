from __future__ import annotations

from typing import Any

KIND_BY_VIBE_CATEGORY = {
    "hallucinated_reference": "phantom_reference",
    "incomplete_generation": "incomplete_generation",
    "api_signature_hallucination": "api_signature",
    "dependency_hallucination": "dependency_version",
}

KIND_BY_RULE_ID = {
    "SKY-L012": "phantom_reference",
    "SKY-L026": "incomplete_generation",
    "SKY-D222": "dependency_package",
    "SKY-D223": "dependency_import",
    "SKY-D224": "api_signature",
    "SKY-D225": "dependency_version",
}


def evaluate_case(
    case: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    matched_indexes: set[int] = set()
    matched: list[dict[str, Any]] = []
    missed: list[dict[str, Any]] = []

    for expectation in expectations(case):
        match_index = _first_match(expectation, findings, matched_indexes)
        if match_index is None:
            missed.append(expectation)
            continue
        matched_indexes.add(match_index)
        matched.append(expectation)

    forbidden_hits = _forbidden_hits(case, findings)
    unexpected = _unexpected_findings(findings, matched_indexes, forbidden_hits)
    passed = not missed
    if forbidden_hits:
        passed = False
    if unexpected:
        passed = False

    return {
        "matched": matched,
        "missed": missed,
        "forbidden": forbidden_hits,
        "unexpected": unexpected,
        "passed": passed,
    }


def expectations(case: dict[str, Any]) -> list[dict[str, Any]]:
    expected = case.get("expected_findings")
    if not isinstance(expected, list):
        return []

    items: list[dict[str, Any]] = []
    for item in expected:
        if isinstance(item, dict):
            items.append(item)
    return items


def summarize_results(
    manifest: dict[str, Any],
    cases: list[dict[str, Any]],
    elapsed: float,
) -> dict[str, Any]:
    expected_total = 0
    matched_total = 0
    false_positive_total = 0
    passed_cases = []
    failed_cases = []

    for case in cases:
        expected_total += int(case["expected_count"])
        matched_total += int(case["matched_count"])
        false_positive_total += len(case["unexpected"])
        false_positive_total += len(case["forbidden"])
        if case["passed"]:
            passed_cases.append(case["id"])
            continue
        failed_cases.append(case["id"])

    false_negative_total = expected_total - matched_total
    precision = _ratio(matched_total, matched_total + false_positive_total)
    recall = _ratio(matched_total, expected_total)

    return {
        "name": manifest.get("name"),
        "description": manifest.get("description"),
        "methodology_sources": manifest.get("methodology_sources", []),
        "case_count": len(cases),
        "passed_count": len(passed_cases),
        "failed_count": len(failed_cases),
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "expected_findings": expected_total,
        "matched_findings": matched_total,
        "false_negatives": false_negative_total,
        "false_positives": false_positive_total,
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
        "elapsed_seconds": elapsed,
        "cases": cases,
    }


def _forbidden_expectations(case: dict[str, Any]) -> list[dict[str, Any]]:
    forbidden = case.get("forbidden_findings")
    if not isinstance(forbidden, list):
        return []

    items: list[dict[str, Any]] = []
    for item in forbidden:
        if isinstance(item, dict):
            items.append(item)
    return items


def _first_match(
    expectation: dict[str, Any],
    findings: list[dict[str, Any]],
    matched_indexes: set[int],
) -> int | None:
    for index, finding in enumerate(findings):
        if index in matched_indexes:
            continue
        if _finding_matches(expectation, finding):
            return index
    return None


def _forbidden_hits(
    case: dict[str, Any],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for expectation in _forbidden_expectations(case):
        for finding in findings:
            if _finding_matches(expectation, finding):
                hits.append(
                    {
                        "expectation": expectation,
                        "finding": compact_finding(finding),
                    }
                )
    return hits


def _unexpected_findings(
    findings: list[dict[str, Any]],
    matched_indexes: set[int],
    forbidden_hits: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    forbidden_ids = _forbidden_source_indexes(forbidden_hits)
    unexpected: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if index in matched_indexes:
            continue
        if index in forbidden_ids:
            continue
        compact = compact_finding(finding)
        compact["_source_index"] = index
        unexpected.append(compact)
    return unexpected


def _forbidden_source_indexes(forbidden_hits: list[dict[str, Any]]) -> set[int]:
    source_indexes: set[int] = set()
    for hit in forbidden_hits:
        finding = hit.get("finding")
        if not isinstance(finding, dict):
            continue
        source_index = finding.get("_source_index")
        if isinstance(source_index, int):
            source_indexes.add(source_index)
    return source_indexes


def _finding_matches(expectation: dict[str, Any], finding: dict[str, Any]) -> bool:
    expected_kind = expectation.get("kind")
    if not isinstance(expected_kind, str):
        return False
    if neutral_kind(finding) != expected_kind:
        return False
    if not _file_matches(expectation, finding):
        return False
    if not _line_matches(expectation, finding):
        return False
    return _evidence_matches(expectation, finding)


def _file_matches(expectation: dict[str, Any], finding: dict[str, Any]) -> bool:
    file_contains = expectation.get("file_contains")
    if not isinstance(file_contains, str):
        return True
    return file_contains in finding_file(finding)


def _line_matches(expectation: dict[str, Any], finding: dict[str, Any]) -> bool:
    line = expectation.get("line")
    if not isinstance(line, int):
        return True
    return finding_line(finding) == line


def _evidence_matches(expectation: dict[str, Any], finding: dict[str, Any]) -> bool:
    evidence = expectation.get("evidence")
    if not isinstance(evidence, list):
        return True

    text = finding_text(finding)
    for token in evidence:
        if str(token) not in text:
            return False
    return True


def neutral_kind(finding: dict[str, Any]) -> str:
    vibe_category = finding.get("vibe_category")
    if isinstance(vibe_category, str):
        kind = KIND_BY_VIBE_CATEGORY.get(vibe_category)
        if kind is not None:
            if vibe_category == "dependency_hallucination":
                return _dependency_kind(finding)
            return kind

    rule_id = finding.get("rule_id")
    if isinstance(rule_id, str):
        kind = KIND_BY_RULE_ID.get(rule_id)
        if kind is not None:
            return kind
    return "unknown"


def _dependency_kind(finding: dict[str, Any]) -> str:
    rule_id = finding.get("rule_id")
    if rule_id == "SKY-D222":
        return "dependency_package"
    if rule_id == "SKY-D223":
        return "dependency_import"
    if rule_id == "SKY-D225":
        return "dependency_version"
    return "dependency_import"


def finding_file(finding: dict[str, Any]) -> str:
    finding_range = finding.get("range")
    if isinstance(finding_range, dict):
        value = finding_range.get("file")
        if isinstance(value, str):
            return value

    value = finding.get("file")
    if isinstance(value, str):
        return value
    return ""


def finding_line(finding: dict[str, Any]) -> int | None:
    finding_range = finding.get("range")
    if isinstance(finding_range, dict):
        value = finding_range.get("start_line")
        if isinstance(value, int):
            return value

    value = finding.get("line")
    if isinstance(value, int):
        return value
    return None


def finding_text(finding: dict[str, Any]) -> str:
    parts = []
    for key in ("rule_id", "vibe_category", "message", "symbol"):
        value = finding.get(key)
        if value is None:
            continue
        parts.append(str(value))
    parts.append(finding_file(finding))
    return " ".join(parts)


def compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": neutral_kind(finding),
        "rule_id": finding.get("rule_id"),
        "vibe_category": finding.get("vibe_category"),
        "message": finding.get("message"),
        "file": finding_file(finding),
        "line": finding_line(finding),
    }


def _ratio(numerator: int | float, denominator: int | float) -> float:
    if denominator <= 0:
        return 1.0
    return float(numerator) / float(denominator)


def _f1(precision: float, recall: float) -> float:
    denominator = precision + recall
    if denominator <= 0:
        return 0.0
    return (2.0 * precision * recall) / denominator
