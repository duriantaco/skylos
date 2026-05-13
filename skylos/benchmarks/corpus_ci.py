from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.analyzer import analyze


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
                    if not isinstance(symbol, str) or not symbol.strip():
                        raise ValueError(
                            f"corpus case {case_id} {mode_name}.{category} has an invalid symbol"
                        )

    return cases


def _finding_tokens(finding: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in ("full_name", "simple_name", "name", "rule_id", "type", "value"):
        value = finding.get(key)
        if isinstance(value, str) and value:
            tokens.add(value)
    return tokens


def _scan_case(case_path: Path, scan: dict[str, Any] | None = None) -> dict[str, Any]:
    scan_cfg = scan or {}
    raw = analyze(
        str(case_path),
        conf=0,
        enable_quality=bool(scan_cfg.get("enable_quality", False)),
        enable_danger=bool(scan_cfg.get("enable_danger", False)),
        enable_secrets=bool(scan_cfg.get("enable_secrets", False)),
        grep_verify=bool(scan_cfg.get("grep_verify", True)),
    )
    return json.loads(raw)


def run_case(case: dict[str, Any], manifest_path: str | Path) -> dict[str, Any]:
    manifest_root = Path(manifest_path).parent
    case_path = (manifest_root / case["path"]).resolve()
    result = _scan_case(case_path, scan=case.get("scan"))
    failures: list[CorpusFailure] = []

    expect = case.get("expect", {})
    for mode in ("absent", "present"):
        expectations = expect.get(mode, {}) or {}
        for category, symbols in expectations.items():
            findings = result.get(category, []) or []
            finding_tokens = [_finding_tokens(finding) for finding in findings]

            for symbol in symbols:
                matched = sorted(
                    {
                        token
                        for tokens in finding_tokens
                        if symbol in tokens
                        for token in tokens
                    }
                )

                if mode == "absent" and matched:
                    failures.append(
                        CorpusFailure(
                            case_id=case["id"],
                            category=category,
                            mode=mode,
                            expected=symbol,
                            found=matched,
                        )
                    )
                if mode == "present" and not matched:
                    failures.append(
                        CorpusFailure(
                            case_id=case["id"],
                            category=category,
                            mode=mode,
                            expected=symbol,
                            found=[],
                        )
                    )

    findings_by_category = {
        key: len(value)
        for key, value in result.items()
        if isinstance(value, list) and value
    }

    return {
        "id": case["id"],
        "path": str(case_path),
        "description": case.get("description", ""),
        "findings_by_category": findings_by_category,
        "failures": [failure.to_dict() for failure in failures],
    }


def run_manifest(
    manifest_path: str | Path, selected_cases: set[str] | None = None
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    cases = validate_manifest(manifest, manifest_path)
    selected = set(selected_cases or set())

    case_results = []
    for case in cases:
        if selected and case["id"] not in selected:
            continue
        case_results.append(run_case(case, manifest_path))

    failure_count = sum(len(case["failures"]) for case in case_results)
    return {
        "manifest": str(Path(manifest_path).resolve()),
        "case_count": len(case_results),
        "failure_count": failure_count,
        "cases": case_results,
    }


def format_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"Corpus cases: {summary['case_count']}",
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
        status = "PASS" if not case["failures"] else "FAIL"
        lines.append(f"{status} {case['id']}: {counts}")
        for failure in case["failures"]:
            found = ", ".join(failure["found"]) if failure["found"] else "none"
            lines.append(
                f"  {failure['mode']} {failure['category']} -> {failure['expected']} (found: {found})"
            )
    return "\n".join(lines)
