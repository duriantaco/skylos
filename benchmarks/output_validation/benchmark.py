"""Compare legacy and flow-aware output-validation decisions on static fixtures.

The fixtures are read by ``detect_integrations``. They are never imported or run.
"""

from __future__ import annotations

import argparse
import ast
import copy
import json
import re
import time
from pathlib import Path
from typing import Any

from skylos.defend.plugins.output_validation import OutputValidationPlugin
from skylos.discover import detect_integrations


MANIFEST_PATH = Path(__file__).with_name("manifest.json")
LABELS = frozenset({"safe", "unsafe", "unknown"})
STATUS_TO_PREDICTION = {
    "validated": "safe",
    "unvalidated": "unsafe",
    "unknown": "unknown",
}
_MARKER = re.compile(r"# ov-(call|use): ([a-z][a-z0-9-]*)\s*$")


def load_manifest(path: str | Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _fixture_markers(root: Path) -> dict[str, dict[str, str]]:
    markers: dict[str, dict[str, str]] = {"call": {}, "use": {}}
    for source_path in sorted(root.rglob("*.py")):
        source = source_path.read_text(encoding="utf-8")
        ast.parse(source, filename=str(source_path))
        relative = source_path.relative_to(root).as_posix()
        for lineno, line in enumerate(source.splitlines(), 1):
            marker = _MARKER.search(line)
            if marker is None:
                continue
            kind, name = marker.groups()
            if name in markers[kind]:
                raise ValueError(f"Duplicate {kind} marker {name!r} in {root}")
            markers[kind][name] = f"{relative}:{lineno}"
    return markers


def validate_manifest(
    manifest: dict[str, Any], path: str | Path = MANIFEST_PATH
) -> list[dict[str, Any]]:
    """Validate labels and source anchors, then return normalized cases."""
    if manifest.get("version") != 1 or not isinstance(manifest.get("cases"), list):
        raise ValueError("Expected version 1 with a cases list")

    manifest_root = Path(path).resolve().parent
    normalized: list[dict[str, Any]] = []
    seen_cases: set[str] = set()
    for case in manifest["cases"]:
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in seen_cases:
            raise ValueError(f"Invalid or duplicate case id: {case_id!r}")
        seen_cases.add(case_id)
        cohort = case.get("cohort", "pilot")
        if not isinstance(cohort, str) or not cohort:
            raise ValueError(f"Invalid cohort for {case_id}")

        fixture_name = case.get("fixture")
        if not isinstance(fixture_name, str):
            raise ValueError(f"Missing fixture in {case_id}")
        fixture = (manifest_root / fixture_name).resolve()
        if not fixture.is_relative_to(manifest_root) or not fixture.is_dir():
            raise ValueError(f"Fixture must be a directory inside the suite: {case_id}")
        markers = _fixture_markers(fixture)
        expectations = case.get("paths")
        if not isinstance(expectations, list) or not expectations:
            raise ValueError(f"Case {case_id} needs at least one labeled path")

        paths: list[dict[str, str]] = []
        seen_paths: set[str] = set()
        seen_calls: set[str] = set()
        for expectation in expectations:
            path_id = expectation.get("id")
            call = expectation.get("call")
            use = expectation.get("use")
            label = expectation.get("label")
            if not isinstance(path_id, str) or not path_id or path_id in seen_paths:
                raise ValueError(
                    f"Invalid or duplicate path id in {case_id}: {path_id!r}"
                )
            if call not in markers["call"] or use not in markers["use"]:
                raise ValueError(f"Missing call/use marker for {case_id}/{path_id}")
            if call in seen_calls:
                raise ValueError(
                    f"The per-integration verdict cannot score two uses of {call} "
                    f"separately in {case_id}"
                )
            if label not in LABELS:
                raise ValueError(f"Invalid label for {case_id}/{path_id}: {label!r}")
            reason = expectation.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"Missing label rationale for {case_id}/{path_id}")
            seen_paths.add(path_id)
            seen_calls.add(call)
            paths.append(
                {
                    "id": path_id,
                    "label": label,
                    "reason": reason,
                    "source_location": markers["call"][call],
                    "use_location": markers["use"][use],
                }
            )
        normalized.append(
            {"id": case_id, "cohort": cohort, "fixture": fixture, "paths": paths}
        )
    return normalized


def _evidence_location(evidence: object, name: str) -> str | None:
    if isinstance(evidence, dict):
        return evidence.get(name)
    return getattr(evidence, name, None)


def _score(rows: list[dict[str, Any]], arm: str) -> dict[str, Any]:
    counts = {
        "correct_known": 0,
        "false_passes": 0,
        "false_alarms": 0,
        "unknown_on_known": 0,
        "discovery_misses": 0,
        "unknown_label_reported": 0,
        "unknown_overclaims": 0,
        "safe_total": 0,
        "unsafe_total": 0,
        "unknown_label_total": 0,
    }
    for row in rows:
        label = row["label"]
        predicted = row[arm]["prediction"]
        counts[f"{label}_total" if label != "unknown" else "unknown_label_total"] += 1
        if predicted == "missed":
            counts["discovery_misses"] += 1
        elif label == "unknown":
            if predicted == "unknown":
                counts["unknown_label_reported"] += 1
            else:
                counts["unknown_overclaims"] += 1
        elif predicted == label:
            counts["correct_known"] += 1
        elif predicted == "unknown":
            counts["unknown_on_known"] += 1
        elif label == "unsafe":
            counts["false_passes"] += 1
        else:
            counts["false_alarms"] += 1

    known_total = counts["safe_total"] + counts["unsafe_total"]
    counts["known_total"] = known_total
    counts["known_accuracy"] = (
        counts["correct_known"] / known_total if known_total else None
    )
    counts["safe_retention"] = (
        sum(row["label"] == "safe" and row[arm]["prediction"] == "safe" for row in rows)
        / counts["safe_total"]
        if counts["safe_total"]
        else None
    )
    counts["unsafe_detection"] = (
        sum(
            row["label"] == "unsafe" and row[arm]["prediction"] == "unsafe"
            for row in rows
        )
        / counts["unsafe_total"]
        if counts["unsafe_total"]
        else None
    )
    return counts


def run_manifest(
    path: str | Path = MANIFEST_PATH,
    *,
    case_id: str | None = None,
    cohort: str | None = None,
) -> dict[str, Any]:
    """Scan each fixture once and score both decisions for each labeled path."""
    cases = validate_manifest(load_manifest(path), path)
    if case_id is not None:
        cases = [case for case in cases if case["id"] == case_id]
        if not cases:
            raise ValueError(f"Unknown case: {case_id}")
    if cohort is not None:
        cases = [case for case in cases if case["cohort"] == cohort]
        if not cases:
            raise ValueError(f"No cases in cohort: {cohort}")

    plugin = OutputValidationPlugin()
    rows: list[dict[str, Any]] = []
    case_times: list[dict[str, Any]] = []
    started = time.perf_counter()
    for case in cases:
        scan_started = time.perf_counter()
        integrations, graph = detect_integrations(case["fixture"])
        scan_elapsed = time.perf_counter() - scan_started
        by_location = {
            integration.location: integration for integration in integrations
        }
        case_times.append(
            {
                "id": case["id"],
                "cohort": case["cohort"],
                "scan_elapsed_seconds": scan_elapsed,
            }
        )

        for expectation in case["paths"]:
            source_location = expectation["source_location"]
            integration = by_location.get(source_location)
            row = {"case": case["id"], "cohort": case["cohort"], **expectation}
            if integration is None:
                row["baseline"] = {"prediction": "missed", "defense_passed": None}
                row["candidate"] = {"prediction": "missed", "defense_passed": None}
                row["evidence_source_matches"] = False
                row["evidence_use_matches"] = False
                row["evidence_path_matches"] = False
                rows.append(row)
                continue

            legacy = copy.copy(integration)
            legacy.output_flow_status = None
            legacy.output_flow_evidence = []
            baseline_result = plugin.check(legacy, graph)
            candidate_result = plugin.check(integration, graph)
            status = getattr(integration, "output_flow_status", None)
            evidence = getattr(integration, "output_flow_evidence", []) or []
            row["baseline"] = {
                "prediction": "safe" if baseline_result.passed else "unsafe",
                "defense_passed": baseline_result.passed,
            }
            row["candidate"] = {
                "prediction": STATUS_TO_PREDICTION.get(status, "unknown"),
                "status": status,
                "defense_passed": candidate_result.passed,
            }
            row["evidence_source_matches"] = any(
                _evidence_location(item, "source_location") == source_location
                for item in evidence
            )
            row["evidence_use_matches"] = any(
                _evidence_location(item, "use_location") == expectation["use_location"]
                for item in evidence
            )
            row["evidence_path_matches"] = any(
                _evidence_location(item, "source_location") == source_location
                and _evidence_location(item, "use_location")
                == expectation["use_location"]
                and _evidence_location(item, "status") == status
                for item in evidence
            )
            rows.append(row)

    discovered = [row for row in rows if row["candidate"]["prediction"] != "missed"]
    flow_decisions = [
        row
        for row in discovered
        if row["candidate"].get("status") in STATUS_TO_PREDICTION
    ]
    cohorts = {}
    for cohort_name in sorted({case["cohort"] for case in cases}):
        cohort_rows = [row for row in rows if row["cohort"] == cohort_name]
        cohorts[cohort_name] = {
            "case_count": sum(case["cohort"] == cohort_name for case in cases),
            "path_count": len(cohort_rows),
            "baseline": _score(cohort_rows, "baseline"),
            "candidate": _score(cohort_rows, "candidate"),
            "scan_elapsed_seconds": sum(
                item["scan_elapsed_seconds"]
                for item in case_times
                if item["cohort"] == cohort_name
            ),
        }
    return {
        "case_count": len(cases),
        "path_count": len(rows),
        "baseline": _score(rows, "baseline"),
        "candidate": _score(rows, "candidate"),
        "cohorts": cohorts,
        "evidence_alignment": {
            "source_matches": sum(row["evidence_source_matches"] for row in discovered),
            "use_matches": sum(row["evidence_use_matches"] for row in discovered),
            "both_match": sum(row["evidence_path_matches"] for row in discovered),
            "discovered_paths": len(discovered),
        },
        "defense_mismatches": sum(
            row["candidate"]["defense_passed"]
            != (row["candidate"]["status"] == "validated")
            for row in flow_decisions
        ),
        "scan_elapsed_seconds": sum(
            item["scan_elapsed_seconds"] for item in case_times
        ),
        "total_elapsed_seconds": time.perf_counter() - started,
        "case_times": case_times,
        "paths": rows,
    }


def format_summary(summary: dict[str, Any]) -> str:
    baseline = summary["baseline"]
    candidate = summary["candidate"]
    lines = [
        f"Output-validation benchmark: {summary['case_count']} cases, "
        f"{summary['path_count']} call-to-use paths",
        f"Scan time: {summary['scan_elapsed_seconds']:.3f}s",
    ]
    for name, counts in (("baseline", baseline), ("candidate", candidate)):
        lines.append(
            f"{name}: correct={counts['correct_known']}/{counts['known_total']} "
            f"false_passes={counts['false_passes']} "
            f"false_alarms={counts['false_alarms']} "
            f"unknown_on_known={counts['unknown_on_known']} "
            f"discovery_misses={counts['discovery_misses']} "
            f"unknown_label_reported={counts['unknown_label_reported']}/"
            f"{counts['unknown_label_total']}"
        )
    for cohort_name, cohort_summary in summary["cohorts"].items():
        before = cohort_summary["baseline"]
        after = cohort_summary["candidate"]
        lines.append(
            f"  {cohort_name}: {cohort_summary['path_count']} paths; "
            f"false_passes {before['false_passes']}→{after['false_passes']}, "
            f"false_alarms {before['false_alarms']}→{after['false_alarms']}, "
            f"unknown_on_known {before['unknown_on_known']}→{after['unknown_on_known']}"
        )
    alignment = summary["evidence_alignment"]
    lines.append(
        f"Evidence cites call and use: {alignment['both_match']}/"
        f"{alignment['discovered_paths']}; "
        f"defense mismatches: {summary['defense_mismatches']}"
    )
    for row in summary["paths"]:
        lines.append(
            f"  {row['cohort']}/{row['case']}/{row['id']}: {row['label']} | "
            f"baseline={row['baseline']['prediction']} "
            f"candidate={row['candidate']['prediction']}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--case", dest="case_id")
    parser.add_argument("--cohort")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = run_manifest(args.manifest, case_id=args.case_id, cohort=args.cohort)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(format_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
