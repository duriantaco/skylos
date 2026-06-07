from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from skylos.analyzer import analyze
from skylos.benchmarks.framework_corpus_schema import (
    DEAD_CODE_CATEGORIES,
    FrameworkCorpusFailure,
    load_manifest,
    validate_manifest,
)

DEFAULT_CHECKOUT_ROOT = Path("/private/tmp/skylos-framework-corpus")
DEFAULT_SCAN = {
    "confidence": 60,
    "grep_verify": True,
}


def _default_checkout_root(manifest: dict[str, Any]) -> Path:
    env_root = os.environ.get("SKYLOS_FRAMEWORK_CORPUS_ROOT")
    if env_root:
        return Path(env_root).expanduser().resolve()

    root = manifest.get("checkout_root")
    if isinstance(root, str) and root.strip():
        return Path(root).expanduser().resolve()

    return DEFAULT_CHECKOUT_ROOT


def _resolve_target_path(target: dict[str, Any], checkout_root: Path) -> Path:
    checkout = target.get("checkout")
    if not isinstance(checkout, str) or not checkout.strip():
        checkout = target["id"]

    path = Path(checkout).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (checkout_root / path).resolve()


def _scan_paths(target: dict[str, Any], target_path: Path) -> list[Path]:
    paths = []
    raw_paths = target.get("scan_paths") or ["."]
    for raw_path in raw_paths:
        paths.append((target_path / raw_path).resolve())
    return paths


def _missing_paths(target: dict[str, Any], target_path: Path) -> list[Path]:
    paths = []
    if not target_path.exists():
        paths.append(target_path)
        return paths

    for scan_path in _scan_paths(target, target_path):
        if not scan_path.exists():
            paths.append(scan_path)
    return paths


def _scan_target(target: dict[str, Any], target_path: Path) -> dict[str, Any]:
    scan_cfg = dict(DEFAULT_SCAN)
    scan_cfg.update(target.get("scan") or {})

    scan_paths = _scan_paths(target, target_path)
    if len(scan_paths) == 1:
        scan_target: str | list[str] = str(scan_paths[0])
    else:
        scan_target = [str(scan_path) for scan_path in scan_paths]

    analyzer_logger = logging.getLogger("Skylos")
    previous_level = analyzer_logger.level
    analyzer_logger.setLevel(logging.WARNING)
    try:
        raw = analyze(
            scan_target,
            conf=int(scan_cfg.get("confidence", DEFAULT_SCAN["confidence"])),
            enable_quality=False,
            enable_danger=False,
            enable_secrets=False,
            grep_verify=bool(scan_cfg.get("grep_verify", DEFAULT_SCAN["grep_verify"])),
        )
    finally:
        analyzer_logger.setLevel(previous_level)
    return json.loads(raw)


def _category_counts(result: dict[str, Any]) -> dict[str, int]:
    counts = {}
    for category in DEAD_CODE_CATEGORIES:
        findings = result.get(category, [])
        if isinstance(findings, list):
            counts[category] = len(findings)
        else:
            counts[category] = 0
    return counts


def _norm_rel_path(value: str, project_root: Path) -> str:
    text = str(value or "").replace("\\", "/")
    if not text:
        return ""

    path = Path(text)
    if path.is_absolute():
        try:
            text = path.resolve().relative_to(project_root.resolve()).as_posix()
        except ValueError:
            text = path.as_posix()

    if text.startswith("./"):
        text = text[2:]
    return text


def _finding_symbols(finding: dict[str, Any]) -> set[str]:
    symbols = set()
    for key in ("simple_name", "name", "symbol", "full_name", "value"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            symbols.add(value.strip())
    return symbols


def _finding_matches(
    expectation: dict[str, Any],
    finding: dict[str, Any],
    target_path: Path,
) -> bool:
    expected_file = expectation.get("file")
    if isinstance(expected_file, str) and expected_file.strip():
        actual_file = _norm_rel_path(str(finding.get("file", "")), target_path)
        if actual_file != expected_file.replace("\\", "/"):
            return False

    expected_symbol = expectation.get("symbol")
    if isinstance(expected_symbol, str) and expected_symbol.strip():
        symbols = _finding_symbols(finding)
        if expected_symbol not in symbols:
            return False

    return True


def _expectation_label(expectation: dict[str, Any]) -> str:
    parts = [str(expectation["category"])]
    file_name = expectation.get("file")
    symbol = expectation.get("symbol")
    if isinstance(file_name, str) and file_name.strip():
        parts.append(file_name)
    if isinstance(symbol, str) and symbol.strip():
        parts.append(symbol)
    return ":".join(parts)


def _finding_label(finding: dict[str, Any], target_path: Path) -> str:
    file_name = _norm_rel_path(str(finding.get("file", "")), target_path)
    symbols = sorted(_finding_symbols(finding))
    if symbols:
        return f"{file_name}:{symbols[0]}"
    return file_name


def _compare_baseline(
    target: dict[str, Any],
    counts: dict[str, int],
) -> list[FrameworkCorpusFailure]:
    baseline = target.get("baseline", {}) or {}
    expected_counts = baseline.get("counts", {}) or {}
    max_delta = int(baseline.get("max_delta", 0))
    failures = []

    for category, expected in sorted(expected_counts.items()):
        actual = counts.get(category, 0)
        delta = abs(actual - int(expected))
        if delta <= max_delta:
            continue
        failures.append(
            FrameworkCorpusFailure(
                target_id=target["id"],
                failure_type="baseline_count",
                mode=category,
                expected=f"{expected} +/- {max_delta}",
                found=[str(actual)],
            )
        )

    return failures


def _compare_expectations(
    target: dict[str, Any],
    result: dict[str, Any],
    target_path: Path,
) -> list[FrameworkCorpusFailure]:
    failures = []
    expect = target.get("expect", {}) or {}
    for mode in ("absent", "present"):
        expectations = expect.get(mode, []) or []
        for expectation in expectations:
            category = str(expectation["category"])
            findings = result.get(category, []) or []
            matches = []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                if _finding_matches(expectation, finding, target_path):
                    matches.append(_finding_label(finding, target_path))

            if mode == "absent" and matches:
                failures.append(
                    FrameworkCorpusFailure(
                        target_id=target["id"],
                        failure_type="expectation",
                        mode=mode,
                        expected=_expectation_label(expectation),
                        found=sorted(matches),
                    )
                )
            if mode == "present" and not matches:
                failures.append(
                    FrameworkCorpusFailure(
                        target_id=target["id"],
                        failure_type="expectation",
                        mode=mode,
                        expected=_expectation_label(expectation),
                        found=[],
                    )
                )

    return failures


def _missing_checkout_result(
    target: dict[str, Any],
    target_path: Path,
    missing_paths: list[Path],
) -> dict[str, Any]:
    found = [str(path) for path in missing_paths]
    failure = FrameworkCorpusFailure(
        target_id=target["id"],
        failure_type="missing_checkout",
        mode="path_exists",
        expected=str(target_path),
        found=found,
    )
    return {
        "id": target["id"],
        "repo": target["repo"],
        "ref": target["ref"],
        "path": str(target_path),
        "status": "fail",
        "counts": {},
        "failures": [failure.to_dict()],
    }


def run_target(
    target: dict[str, Any],
    *,
    checkout_root: Path,
    require_checkouts: bool = False,
) -> dict[str, Any]:
    target_path = _resolve_target_path(target, checkout_root)
    missing = _missing_paths(target, target_path)
    if missing:
        if require_checkouts:
            return _missing_checkout_result(target, target_path, missing)
        return {
            "id": target["id"],
            "repo": target["repo"],
            "ref": target["ref"],
            "path": str(target_path),
            "status": "skip",
            "reason": "checkout or scan path is missing",
            "missing_paths": [str(path) for path in missing],
        }

    result = _scan_target(target, target_path)
    counts = _category_counts(result)
    failures = []
    failures.extend(_compare_baseline(target, counts))
    failures.extend(_compare_expectations(target, result, target_path))

    status = "pass"
    if failures:
        status = "fail"

    return {
        "id": target["id"],
        "repo": target["repo"],
        "ref": target["ref"],
        "path": str(target_path),
        "status": status,
        "counts": counts,
        "failures": [failure.to_dict() for failure in failures],
    }


def _select_targets(
    targets: list[dict[str, Any]],
    selected_targets: set[str],
) -> list[dict[str, Any]]:
    if not selected_targets:
        return targets

    selected = []
    for target in targets:
        if target["id"] in selected_targets:
            selected.append(target)

    if not selected:
        wanted = ", ".join(sorted(selected_targets))
        raise ValueError(f"no framework corpus target matched: {wanted}")
    return selected


def run_manifest(
    manifest_path: str | Path,
    *,
    checkout_root: str | Path | None = None,
    selected_targets: set[str] | None = None,
    require_checkouts: bool = False,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    targets = validate_manifest(manifest, manifest_path)
    selected = _select_targets(targets, set(selected_targets or set()))

    if checkout_root is None:
        resolved_checkout_root = _default_checkout_root(manifest)
    else:
        resolved_checkout_root = Path(checkout_root).expanduser().resolve()

    target_results = []
    skipped_targets = []
    for target in selected:
        result = run_target(
            target,
            checkout_root=resolved_checkout_root,
            require_checkouts=require_checkouts,
        )
        if result["status"] == "skip":
            skipped_targets.append(result)
        else:
            target_results.append(result)

    failure_count = 0
    for result in target_results:
        failure_count += len(result.get("failures", []))

    pass_count = 0
    for result in target_results:
        if result["status"] == "pass":
            pass_count += 1

    return {
        "manifest": str(Path(manifest_path).resolve()),
        "checkout_root": str(resolved_checkout_root),
        "target_count": len(target_results),
        "skipped_target_count": len(skipped_targets),
        "pass_count": pass_count,
        "failure_count": failure_count,
        "targets": target_results,
        "skipped_targets": skipped_targets,
    }


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "no counts"
    parts = []
    for category in DEAD_CODE_CATEGORIES:
        if category in counts:
            parts.append(f"{category}={counts[category]}")
    return ", ".join(parts)


def format_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"Framework corpus checkout root: {summary['checkout_root']}",
        f"Framework corpus targets: {summary['target_count']}",
        f"Framework corpus skipped targets: {summary['skipped_target_count']}",
        f"Framework corpus failures: {summary['failure_count']}",
    ]

    for target in summary.get("targets", []):
        status = str(target["status"]).upper()
        counts = _format_counts(target.get("counts", {}))
        lines.append(f"{status} {target['id']}: {counts}")
        for failure in target.get("failures", []):
            found = "none"
            if failure["found"]:
                found = ", ".join(failure["found"])
            lines.append(
                f"  {failure['failure_type']} {failure['mode']} -> "
                f"{failure['expected']} (found: {found})"
            )

    for target in summary.get("skipped_targets", []):
        reason = target.get("reason", "skipped")
        lines.append(f"SKIP {target['id']}: {reason}")

    return "\n".join(lines)
