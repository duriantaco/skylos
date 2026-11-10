from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.analyzer import analyze
from skylos.benchmarks._analysis_validation import analysis_issues


@dataclass(frozen=True)
class CorpusFailure:
    case_id: str
    category: str
    mode: str
    expected: str
    found: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "mode": self.mode,
            "expected": self.expected,
            "found": list(self.found),
        }


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def validate_manifest(
    manifest: dict[str, Any], manifest_path: str | Path
) -> list[dict[str, Any]]:
    manifest_file = Path(manifest_path)
    if manifest.get("version") != 1:
        raise ValueError("corpus manifest version must be 1")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("corpus manifest must define a non-empty cases list")

    seen_ids: set[str] = set()
    manifest_root = manifest_file.parent
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each corpus case must be an object")

        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("each corpus case must have a non-empty id")
        if case_id in seen_ids:
            raise ValueError(f"duplicate corpus case id: {case_id}")
        seen_ids.add(case_id)

        rel_path = case.get("path")
        if not isinstance(rel_path, str) or not rel_path.strip():
            raise ValueError(f"corpus case {case_id} must declare a path")
        case_path = (manifest_root / rel_path).resolve()
        if not case_path.exists():
            raise ValueError(f"corpus case {case_id} path does not exist: {case_path}")

        source = case.get("source")
        if not isinstance(source, dict):
            raise ValueError(f"corpus case {case_id} must declare source metadata")
        repo = source.get("repo")
        license_name = source.get("license")
        if not isinstance(repo, str) or not repo.startswith("https://"):
            raise ValueError(f"corpus case {case_id} must declare an https repo URL")
        if not isinstance(license_name, str) or not license_name.strip():
            raise ValueError(f"corpus case {case_id} must declare a license")

        expect = case.get("expect")
        if not isinstance(expect, dict):
            raise ValueError(f"corpus case {case_id} must declare expectations")
        absent = expect.get("absent", {})
        present = expect.get("present", {})
        if not isinstance(absent, dict) or not isinstance(present, dict):
            raise ValueError(
                f"corpus case {case_id} expectations must use absent/present maps"
            )
        if not absent and not present:
            raise ValueError(
                f"corpus case {case_id} must declare at least one expectation"
            )

        for mode_name, expectation_map in (("absent", absent), ("present", present)):
            for category, symbols in expectation_map.items():
                if not isinstance(category, str) or not category.strip():
                    raise ValueError(
                        f"corpus case {case_id} {mode_name} expectations need string categories"
                    )
                if not isinstance(symbols, list) or not symbols:
                    raise ValueError(
                        f"corpus case {case_id} {mode_name}.{category} must be a non-empty list"
                    )
                for symbol in symbols:
                    if isinstance(symbol, dict):
                        _validate_location_expectation(symbol, case_path)
                        continue
                    if not isinstance(symbol, str) or not symbol.strip():
                        raise ValueError(
                            f"corpus case {case_id} {mode_name}.{category} has an invalid symbol"
                        )

    return cases


def _validate_location_expectation(expected: dict, case_path: Path) -> None:
    from skylos.rules.catalog import get_rule_catalog

    fields = {"rule_id", "file", "start_line", "end_line"}
    if set(expected) != fields:
        raise ValueError(
            "location expectations require exactly rule_id/file/start_line/end_line"
        )
    if not isinstance(expected["rule_id"], str) or not expected["rule_id"].startswith(
        "SKY-"
    ):
        raise ValueError("location expectation needs a SKY rule ID")
    if expected["rule_id"] not in {entry["id"] for entry in get_rule_catalog()}:
        raise ValueError("location expectation has an unknown rule ID")
    filename = expected["file"]
    if not isinstance(filename, str) or not filename or "\\" in filename:
        raise ValueError("location expectation needs a relative POSIX file path")
    relative = Path(filename)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != filename
    ):
        raise ValueError("location expectation file must stay within its case")
    if case_path.is_file() and relative != Path(case_path.name):
        raise ValueError("single-file cases cannot expect findings in sibling files")
    root = case_path if case_path.is_dir() else case_path.parent
    source = (root / relative).resolve()
    if not source.is_relative_to(root.resolve()) or not source.is_file():
        raise ValueError("location expectation file must exist within its case")
    start, end = expected["start_line"], expected["end_line"]
    if type(start) is not int or type(end) is not int or not 1 <= start <= end:
        raise ValueError("location expectation needs a positive ordered line range")
    if end > len(source.read_text(encoding="utf-8").splitlines()):
        raise ValueError("location expectation range exceeds its source file")


def _finding_path(finding, analysis_root):
    filename = finding.get("file") or finding.get("file_path")
    if not isinstance(filename, str) or not filename:
        return None
    actual = Path(filename)
    if actual.is_absolute():
        try:
            actual = actual.resolve().relative_to(analysis_root)
        except ValueError:
            return None
    return actual.as_posix()


def _expectation_matches(expected, finding, *, category, analysis_root):
    if isinstance(expected, str):
        return expected in _finding_tokens(finding, category=category)
    line = finding.get("line")
    return (
        finding.get("rule_id") == expected["rule_id"]
        and _finding_path(finding, analysis_root) == expected["file"]
        and type(line) is int
        and expected["start_line"] <= line <= expected["end_line"]
    )


def _finding_tokens(
    finding: dict[str, Any], *, category: str | None = None
) -> set[str]:
    symbol_category = category is not None and category.startswith("unused_")
    # A native unused-file finding identifies a path, not a Python symbol.
    # Keep symbol categories strict so generic rule/type/value tokens cannot
    # satisfy an unused-function or unused-import expectation.
    keys = (
        ("file", "file_path")
        if category == "unused_files"
        else ("full_name", "simple_name", "name")
    )
    if not symbol_category:
        keys += ("rule_id", "type", "value")
    tokens: set[str] = set()
    for key in keys:
        value = finding.get(key)
        if isinstance(value, str) and value and (not symbol_category or value.strip()):
            tokens.add(value)
    return tokens


def _has_finding_identity(category: str, finding: object) -> bool:
    if not isinstance(finding, Mapping):
        return False
    return bool(_finding_tokens(finding, category=category))


def _scan_case(case_path: Path, scan: dict[str, Any] | None = None) -> dict[str, Any]:
    scan_cfg = scan or {}
    raw = analyze(
        str(case_path),
        conf=0,
        enable_quality=bool(scan_cfg.get("enable_quality", False)),
        enable_danger=bool(scan_cfg.get("enable_danger", False)),
        enable_secrets=bool(scan_cfg.get("enable_secrets", False)),
        grep_verify=bool(scan_cfg.get("grep_verify", True)),
        grep_cache=False,
        trace_file=False,
        enable_ai_defects=False,
        enable_dependency_hallucinations=False,
        enable_sca=False,
    )
    return json.loads(raw)


@contextmanager
def _analysis_path(case_path: Path):
    """Keep project imports and grep inside the declared fixture scope."""
    with tempfile.TemporaryDirectory(prefix="skylos_corpus_") as temp_dir:
        target = Path(temp_dir) / case_path.name
        if case_path.is_dir():
            shutil.copytree(case_path, target)
        else:
            shutil.copy2(case_path, target)
        yield target


def run_case(case: dict[str, Any], manifest_path: str | Path) -> dict[str, Any]:
    manifest_root = Path(manifest_path).parent
    case_path = (manifest_root / case["path"]).resolve()
    located_rules = {
        expected["rule_id"]
        for mode in ("absent", "present")
        for expected_list in case.get("expect", {}).get(mode, {}).values()
        for expected in expected_list
        if isinstance(expected, dict)
    }
    with _analysis_path(case_path) as analysis_path:
        analysis_root = (
            analysis_path if case_path.is_dir() else analysis_path.parent
        ).resolve()
        source_lines = {}
        if located_rules:
            for source in analysis_root.rglob("*"):
                if source.is_file():
                    try:
                        source_lines[source.relative_to(analysis_root).as_posix()] = (
                            len(source.read_text(encoding="utf-8").splitlines())
                        )
                    except (OSError, UnicodeError):
                        continue
        result = _scan_case(analysis_path, scan=case.get("scan"))
    issues = analysis_issues(result, scanner="skylos")
    expect = case.get("expect", {})
    categories = {
        category for mode in ("absent", "present") for category in expect.get(mode, {})
    }
    if isinstance(result, Mapping):
        for category in sorted(categories):
            if category not in result:
                continue
            findings = result[category]
            if not isinstance(findings, list) or any(
                not _has_finding_identity(category, finding) for finding in findings
            ):
                issues.append(
                    f"{category} must be a list of finding objects with identities"
                )
                continue
            located = [
                expected
                for mode in ("absent", "present")
                for expected in expect.get(mode, {}).get(category, [])
                if isinstance(expected, dict)
            ]
            if located and any(
                not isinstance(finding.get("rule_id"), str)
                or not finding["rule_id"].strip()
                or (
                    finding["rule_id"] in {item["rule_id"] for item in located}
                    and (
                        type(finding.get("line")) is not int
                        or finding["line"] < 1
                        or finding["line"]
                        > source_lines.get(_finding_path(finding, analysis_root), 0)
                    )
                )
                for finding in findings
            ):
                issues.append(
                    f"{category} needs rule IDs and valid locations for mapped rules"
                )
    located_quality = any(
        isinstance(expected, dict)
        for mode in ("absent", "present")
        for expected in expect.get(mode, {}).get("quality", [])
    )
    if located_quality:
        from skylos.benchmarks.quality import _quality_analysis_issues

        issues.extend(
            issue
            for issue in _quality_analysis_issues(case, case_path, result)
            if issue not in issues
        )
        summary = (
            result.get("analysis_summary", {}) if isinstance(result, Mapping) else {}
        )
        if not isinstance(summary, Mapping):
            summary = {}
        categories = summary.get("grade_categories")
        if (
            (case.get("scan") or {}).get("enable_quality") is not True
            or not isinstance(categories, list)
            or "quality" not in categories
        ):
            issues.append(
                "quality analysis must be enabled and recorded for location expectations"
            )

    source_summary = (
        result.get("analysis_summary", {}) if isinstance(result, Mapping) else {}
    )
    source_count = (
        source_summary.get("total_files")
        if isinstance(source_summary, Mapping)
        else None
    )
    evidence = {
        "id": case["id"],
        "path": str(case_path),
        "description": case.get("description", ""),
        "analyzed_source_count": source_count
        if type(source_count) is int and source_count > 0
        else None,
        "analysis_status": "incomplete" if issues else "complete",
        "analysis_issues": issues,
        "scored": not issues,
    }
    if issues:
        failure = CorpusFailure(
            case_id=case["id"],
            category="analysis",
            mode="completeness",
            expected="complete analysis before checking expectations",
            found=issues,
        )
        return {
            **evidence,
            "checked_expectation_count": 0,
            "findings_by_category": {},
            "failures": [failure.to_dict()],
        }

    failures: list[CorpusFailure] = []

    checked_count = 0
    for mode in ("absent", "present"):
        expectations = expect.get(mode, {}) or {}
        for category, symbols in expectations.items():
            findings = result.get(category, []) or []
            for symbol in symbols:
                checked_count += 1
                matched = sorted(
                    {
                        token
                        for finding in findings
                        if _expectation_matches(
                            symbol,
                            finding,
                            category=category,
                            analysis_root=analysis_root,
                        )
                        for token in _finding_tokens(finding, category=category)
                    }
                )

                if mode == "absent" and matched:
                    failures.append(
                        CorpusFailure(
                            case_id=case["id"],
                            category=category,
                            mode=mode,
                            expected=json.dumps(symbol, sort_keys=True)
                            if isinstance(symbol, dict)
                            else symbol,
                            found=matched,
                        )
                    )
                if mode == "present" and not matched:
                    failures.append(
                        CorpusFailure(
                            case_id=case["id"],
                            category=category,
                            mode=mode,
                            expected=json.dumps(symbol, sort_keys=True)
                            if isinstance(symbol, dict)
                            else symbol,
                            found=[],
                        )
                    )

    findings_by_category = {
        key: len(value)
        for key, value in result.items()
        if isinstance(value, list) and value
    }

    return {
        **evidence,
        "checked_expectation_count": checked_count,
        "findings_by_category": findings_by_category,
        "failures": [failure.to_dict() for failure in failures],
    }


def run_manifest(
    manifest_path: str | Path, selected_cases: set[str] | None = None
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    cases = validate_manifest(manifest, manifest_path)
    selected = set(selected_cases or set())
    unknown = selected - {case["id"] for case in cases}
    if unknown:
        raise ValueError("unknown corpus case id(s): " + ", ".join(sorted(unknown)))

    case_results = []
    for case in cases:
        if selected and case["id"] not in selected:
            continue
        case_results.append(run_case(case, manifest_path))

    failure_count = sum(len(case["failures"]) for case in case_results)
    scored_count = sum(case["scored"] for case in case_results)
    unscored_count = len(case_results) - scored_count
    return {
        "manifest": str(Path(manifest_path).resolve()),
        "case_count": len(case_results),
        "scored_case_count": scored_count,
        "unscored_case_count": unscored_count,
        "analysis_status": "incomplete" if unscored_count else "complete",
        "pass_count": sum(
            case["scored"] and not case["failures"] for case in case_results
        ),
        "failure_count": failure_count,
        "cases": case_results,
    }


def format_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"Corpus cases: {summary['case_count']}",
        f"Corpus analysis: {summary.get('analysis_status', 'complete')}",
        (
            f"Corpus scored cases: {summary.get('scored_case_count', summary['case_count'])}; "
            f"unscored cases: {summary.get('unscored_case_count', 0)}"
        ),
        f"Corpus failures: {summary['failure_count']}",
    ]
    for case in summary["cases"]:
        if case["findings_by_category"]:
            counts = ", ".join(
                f"{category}={count}"
                for category, count in sorted(case["findings_by_category"].items())
            )
        else:
            counts = "no findings"
        status = (
            "UNSCORED"
            if case.get("scored") is False
            else "PASS"
            if not case["failures"]
            else "FAIL"
        )
        lines.append(f"{status} {case['id']}: {counts}")
        for failure in case["failures"]:
            found = ", ".join(failure["found"]) if failure["found"] else "none"
            lines.append(
                f"  {failure['mode']} {failure['category']} -> {failure['expected']} (found: {found})"
            )
    return "\n".join(lines)
