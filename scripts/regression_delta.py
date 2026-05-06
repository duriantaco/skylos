#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: str | Path) -> dict[str, Any]:
    workspace = Path.cwd().resolve()
    safe_path = _safe_workspace_json(path, workspace)
    if not safe_path.is_relative_to(workspace):
        raise ValueError(f"JSON path escapes workspace: {path}")
    return json.loads(safe_path.read_text(encoding="utf-8"))


def _safe_workspace_json(path: str | Path, workspace: Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or str(candidate) != candidate.name:
        raise ValueError(f"expected a workspace-local JSON filename, got: {path}")
    if candidate.suffix.lower() != ".json":
        raise ValueError(f"expected a .json file, got: {path}")

    safe_path = (workspace / candidate.name).resolve()
    if not safe_path.is_relative_to(workspace):
        raise ValueError(f"JSON path escapes workspace: {path}")
    return safe_path


def _case_failures(summary: dict[str, Any]) -> dict[str, set[tuple[str, ...]]]:
    failures_by_case: dict[str, set[tuple[str, ...]]] = {}
    for case in summary.get("cases", []) or []:
        case_id = str(case.get("id") or "")
        failures = case.get("failures", []) or []
        if not case_id or not failures:
            continue

        keys = failures_by_case.setdefault(case_id, set())
        for failure in failures:
            keys.add(
                (
                    str(failure.get("failure_type") or "expectation"),
                    str(failure.get("category") or ""),
                    str(failure.get("mode") or ""),
                    str(failure.get("expected") or ""),
                )
            )
    return failures_by_case


def _new_failures(
    base: dict[str, Any], head: dict[str, Any]
) -> dict[str, set[tuple[str, ...]]]:
    base_failures = _case_failures(base)
    head_failures = _case_failures(head)

    new: dict[str, set[tuple[str, ...]]] = {}
    for case_id, failures in head_failures.items():
        added = failures - base_failures.get(case_id, set())
        if added:
            new[case_id] = added
    return new


def _failure_count(summary: dict[str, Any]) -> int:
    return int(summary.get("failure_count") or 0)


def _score(summary: dict[str, Any], key: str) -> float:
    scores = summary.get("scores", {}) or {}
    return float(scores.get(key) or 0.0)


def _taxonomy_scores(summary: dict[str, Any]) -> dict[str, float]:
    taxonomy = summary.get("taxonomy", {}) or {}
    return {
        str(name): float((bucket or {}).get("weighted_score") or 0.0)
        for name, bucket in taxonomy.items()
    }


def compare_corpus(base: dict[str, Any], head: dict[str, Any]) -> tuple[bool, list[str]]:
    lines = [
        "# Corpus Guard Regression Delta",
        "",
        f"Base failures: {_failure_count(base)}",
        f"Head failures: {_failure_count(head)}",
    ]
    failed = False

    if _failure_count(head) > _failure_count(base):
        failed = True
        lines.append(
            f"Regression: failure count increased "
            f"{_failure_count(base)} -> {_failure_count(head)}."
        )

    added = _new_failures(base, head)
    if added:
        failed = True
        lines.append("Regression: new failing corpus expectations:")
        for case_id, failures in sorted(added.items()):
            for failure in sorted(failures):
                _, category, mode, expected = failure
                lines.append(f"- {case_id}: {mode} {category} -> {expected}")

    if not failed:
        lines.append("No corpus regression detected.")

    return not failed, lines


def compare_quality(base: dict[str, Any], head: dict[str, Any]) -> tuple[bool, list[str]]:
    base_score = _score(base, "overall_score")
    head_score = _score(head, "overall_score")
    lines = [
        "# Quality Benchmark Regression Delta",
        "",
        f"Base failures: {_failure_count(base)}",
        f"Head failures: {_failure_count(head)}",
        f"Base overall score: {base_score}",
        f"Head overall score: {head_score}",
    ]
    failed = False

    if _failure_count(head) > _failure_count(base):
        failed = True
        lines.append(
            f"Regression: failure count increased "
            f"{_failure_count(base)} -> {_failure_count(head)}."
        )

    if head_score < base_score:
        failed = True
        lines.append(f"Regression: overall score dropped {base_score} -> {head_score}.")

    base_taxonomy = _taxonomy_scores(base)
    head_taxonomy = _taxonomy_scores(head)
    for label, base_value in sorted(base_taxonomy.items()):
        if label not in head_taxonomy:
            continue
        head_value = head_taxonomy[label]
        if head_value < base_value:
            failed = True
            lines.append(
                f"Regression: taxonomy '{label}' score dropped "
                f"{base_value} -> {head_value}."
            )

    added = _new_failures(base, head)
    if added:
        failed = True
        lines.append("Regression: new failing quality benchmark expectations:")
        for case_id, failures in sorted(added.items()):
            for failure in sorted(failures):
                failure_type, category, mode, expected = failure
                lines.append(
                    f"- {case_id}: {failure_type} {mode} {category} -> {expected}"
                )

    if not failed:
        lines.append("No quality benchmark regression detected.")

    return not failed, lines


def compare(
    kind: str, base: dict[str, Any], head: dict[str, Any]
) -> tuple[bool, list[str]]:
    if kind == "corpus":
        return compare_corpus(base, head)
    if kind == "quality":
        return compare_quality(base, head)
    raise ValueError(f"unsupported regression delta kind: {kind}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare base and head benchmark JSON outputs for regressions."
    )
    parser.add_argument("--kind", choices=("corpus", "quality"), required=True)
    parser.add_argument("--base", required=True, help="Base branch JSON summary.")
    parser.add_argument("--head", required=True, help="Head branch JSON summary.")
    args = parser.parse_args()

    passed, lines = compare(args.kind, _load_json(args.base), _load_json(args.head))
    print("\n".join(lines))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
