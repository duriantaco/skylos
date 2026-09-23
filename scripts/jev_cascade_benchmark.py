#!/usr/bin/env python3
"""Four-arm, source-only evaluation of Skylos dead-code verification.

The same frozen cases are statically scanned in isolated temporary directories.
The pure Skylos arm uses no model; the baseline uses the existing LLM verifier;
the cascade enables Jev precheck; the judge arm lets confident Jev answers
decide both ways before LLM fallback. Labels and manifest metadata never enter
a source directory or model prompt.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

# This host's Python 3.13 stdlib ast.NodeVisitor has a parent-link patch that
# references a missing module global. Repair that process-local binding only;
# never edit the interpreter installation or change Skylos's scanner code.
if "ast" in ast.NodeVisitor.generic_visit.__code__.co_names:
    ast.NodeVisitor.generic_visit.__globals__.setdefault("ast", ast)

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.analysis.errors import analysis_result_incomplete  # noqa: E402
from skylos.benchmarks._jev_dead_code_dataset import (  # noqa: E402
    JevBenchmarkError,
    _load_manifest_snapshot,
    _manifest_cases,
    _read_case_files,
    _safe_case_path,
)
from skylos.commands.agent_verify_cmd import (  # noqa: E402
    _collect_dead_code_findings,
)
from skylos.core.safe_cache_io import write_text_no_symlink  # noqa: E402
from skylos.llm.harness import run_verification_harness  # noqa: E402


DEFAULT_MANIFEST = (
    REPO_ROOT / "benchmarks" / "dead_code" / "jev_hard_suite_v2_manifest.json"
)
MAX_CASES = 20
BENCHMARK_ARMS = frozenset({"static", "baseline", "cascade", "judge"})


def _source_root(parent: Path, files: list[dict[str, str]], arm: str) -> Path:
    try:
        if parent.is_symlink() or not parent.is_dir():
            raise OSError("source parent is not a real directory")
        parent = parent.resolve(strict=True)
    except OSError as exc:
        raise JevBenchmarkError("cannot use benchmark source parent") from exc
    if arm not in BENCHMARK_ARMS:
        raise JevBenchmarkError(f"unsupported benchmark arm: {arm}")

    arm_root = parent / arm
    root = arm_root / "project"
    try:
        # These directories must be new. Refuse a pre-positioned symlink or file
        # instead of following it while staging the isolated source snapshot.
        arm_root.mkdir(mode=0o700)
        root.mkdir(mode=0o700)
    except OSError as exc:
        raise JevBenchmarkError(f"cannot create isolated {arm} source root") from exc

    for item in files:
        relative = Path(item["path"])
        if (
            relative.is_absolute()
            or bool(relative.anchor)
            or bool(relative.drive)
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise JevBenchmarkError(f"unsafe staged source path: {item['path']}")
        destination = root.joinpath(*relative.parts)
        try:
            destination.relative_to(root)
            destination.parent.mkdir(parents=True, exist_ok=True)
        except (OSError, ValueError) as exc:
            raise JevBenchmarkError(
                f"cannot create staged source parent: {item['path']}"
            ) from exc
        if not write_text_no_symlink(destination, item["content"], encoding="utf-8"):
            raise JevBenchmarkError(f"cannot safely stage source: {item['path']}")
    return root.resolve(strict=True)


def _scan(root: Path, *, scan: dict | None = None) -> tuple[list[dict], dict]:
    from skylos.analyzer import analyze

    policy = scan or {"confidence": 60, "grep_verify": True}
    raw = analyze(
        str(root),
        conf=policy["confidence"],
        grep_verify=policy["grep_verify"],
        enable_danger=False,
        enable_quality=False,
        enable_secrets=False,
        exclude_folders=[],
    )
    result = json.loads(raw) if isinstance(raw, str) else raw
    if analysis_result_incomplete(result):
        raise JevBenchmarkError("static analysis was incomplete")
    return _collect_dead_code_findings(result), result.get("definitions") or {}


def _scan_policy(case: dict) -> dict[str, int | bool]:
    configured = case.get("scan", {})
    if not isinstance(configured, dict) or set(configured) - {
        "confidence",
        "grep_verify",
    }:
        raise JevBenchmarkError(
            f"{case['id']}: unsupported scan settings for paired benchmark"
        )
    confidence = configured.get("confidence", 60)
    grep_verify = configured.get("grep_verify", True)
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, int)
        or not 0 <= confidence <= 100
    ):
        raise JevBenchmarkError(f"{case['id']}: invalid scan confidence")
    if not isinstance(grep_verify, bool):
        raise JevBenchmarkError(f"{case['id']}: invalid scan grep_verify")
    return {"confidence": confidence, "grep_verify": grep_verify}


def _relative_file(finding: dict, root: Path) -> str | None:
    raw = finding.get("file") or finding.get("file_path")
    if not isinstance(raw, str):
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = root / path
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return None


def _matches(finding: dict, label: dict, root: Path) -> bool:
    if _relative_file(finding, root) != label["file"]:
        return False
    finding_kind = finding.get("type")
    if finding_kind == "method":
        finding_kind = "function"
    if finding_kind != label["kind"]:
        return False
    names = {
        str(finding.get("name") or ""),
        str(finding.get("name") or "").rsplit(".", 1)[-1],
        str(finding.get("simple_name") or ""),
        str(finding.get("full_name") or ""),
        str(finding.get("full_name") or "").rsplit(".", 1)[-1],
    }
    if not names.intersection(_label_symbols(label)):
        return False
    line = label.get("line")
    return line is None or finding.get("line") == line


def _label_symbols(label: dict) -> set[str]:
    return {label["symbol"], *(label.get("aliases") or [])}


def _symbols_overlap(left: dict, right: dict) -> bool:
    left_symbols = _label_symbols(left)
    right_symbols = _label_symbols(right)
    return any(
        a == b
        or ("." not in a and a == b.rsplit(".", 1)[-1])
        or ("." not in b and b == a.rsplit(".", 1)[-1])
        for a in left_symbols
        for b in right_symbols
    )


def _label_id(label: dict) -> str:
    return str(
        label.get("label_id")
        or f"{label['file']}:{label['symbol']}:{label.get('line', '')}"
    )


def _labels(expect: dict) -> list[tuple[str, dict]]:
    return [
        (expected, label)
        for expected in ("unused", "used")
        for label in expect[expected]
    ]


def _validate_labels(case_id: str, expect: dict) -> list[tuple[str, dict]]:
    labels = _labels(expect)
    seen_ids: set[str] = set()
    for index, (_expected, label) in enumerate(labels):
        label_id = _label_id(label)
        if label_id in seen_ids:
            raise JevBenchmarkError(f"{case_id}: duplicate label {label_id}")
        seen_ids.add(label_id)
        line = label.get("line")
        if line is not None and (
            isinstance(line, bool) or not isinstance(line, int) or line < 1
        ):
            raise JevBenchmarkError(f"{case_id}: invalid line for label {label_id}")
        for _other_expected, other in labels[:index]:
            if label["file"] != other["file"] or label["kind"] != other["kind"]:
                continue
            other_line = other.get("line")
            if line is not None and other_line is not None and line != other_line:
                continue
            if _symbols_overlap(label, other):
                raise JevBenchmarkError(
                    f"{case_id}: ambiguous labels {_label_id(other)} and {label_id}"
                )
    return labels


def _source_digest(files: list[dict[str, str]]) -> str:
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _candidate_inventory(findings: list[dict], root: Path) -> list[str]:
    identities = [
        {
            "file": _relative_file(finding, root),
            "name": finding.get("full_name") or finding.get("name"),
            "simple_name": finding.get("simple_name"),
            "type": finding.get("type"),
            "line": finding.get("line"),
            "confidence": finding.get("confidence"),
            "references": finding.get("references"),
        }
        for finding in findings
    ]
    return sorted(json.dumps(item, sort_keys=True, default=str) for item in identities)


def _candidate_coverage(
    case_id: str, expect: dict, findings: list[dict], root: Path
) -> dict[str, int]:
    labels = _validate_labels(case_id, expect)
    matched_labels: set[int] = set()
    for finding in findings:
        matched = [
            index
            for index, (_expected, label) in enumerate(labels)
            if _matches(finding, label, root)
        ]
        if len(matched) != 1:
            problem = "unlabeled" if not matched else "ambiguous"
            raise JevBenchmarkError(
                f"{case_id}: {problem} static candidate "
                f"{finding.get('name')}@{_relative_file(finding, root)}:"
                f"{finding.get('line')} ({finding.get('type')})"
            )
        if matched[0] in matched_labels:
            raise JevBenchmarkError(
                f"{case_id}: multiple static candidates match label "
                f"{_label_id(labels[matched[0]][1])}"
            )
        matched_labels.add(matched[0])
    return {
        "static_candidate_count": len(findings),
        "matched_static_candidate_count": len(findings),
        "label_count": len(labels),
        "matched_label_count": len(matched_labels),
        "unmatched_label_count": len(labels) - len(matched_labels),
    }


def _validate_new_dead(
    case_id: str, expect: dict, findings: list[dict], root: Path
) -> None:
    labels = _labels(expect)
    seen: set[int] = set()
    for finding in findings:
        matched = [
            index
            for index, (_expected, label) in enumerate(labels)
            if _matches(finding, label, root)
        ]
        if len(matched) != 1 or matched[0] in seen:
            raise JevBenchmarkError(
                f"{case_id}: unlabeled or ambiguous new_dead_code "
                f"{finding.get('name')}@{_relative_file(finding, root)}:"
                f"{finding.get('line')} ({finding.get('type')})"
            )
        seen.add(matched[0])


def _prepare_case(
    parent: Path, case: dict, files: list[dict[str, str]], arms: list[str]
) -> dict:
    source_digest = _source_digest(files)
    policy = _scan_policy(case)
    scans = {}
    inventories = {}
    coverage = None
    for arm in arms:
        root = _source_root(parent, files, arm)
        if _source_digest(_read_case_files(root)) != source_digest:
            raise JevBenchmarkError(f"{case['id']}: {arm} source snapshot differs")
        started = time.monotonic()
        findings, defs_map = _scan(root, scan=policy)
        scan_elapsed = round(time.monotonic() - started, 3)
        if _source_digest(_read_case_files(root)) != source_digest:
            raise JevBenchmarkError(f"{case['id']}: {arm} source changed during scan")
        current_coverage = _candidate_coverage(
            case["id"], case["expect"], findings, root
        )
        inventory = _candidate_inventory(findings, root)
        if inventories and inventory != next(iter(inventories.values())):
            raise JevBenchmarkError(
                f"{case['id']}: arm static candidate inventories differ"
            )
        inventories[arm] = inventory
        scans[arm] = (root, findings, defs_map, scan_elapsed)
        coverage = current_coverage
    return {
        "arms": scans,
        "source_digest": source_digest,
        "scan_policy": policy,
        "static_candidate_inventory_digest": hashlib.sha256(
            json.dumps(next(iter(inventories.values())), separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest(),
        "coverage": coverage,
    }


def _reported(output: dict) -> list[dict]:
    # Mirror agent scan's reported dead-code branch. A Jev-only agreement
    # remains a static finding; a false-positive/uncertain LLM verdict does not.
    reported = [
        item
        for item in output.get("verified_findings", [])
        if not item.get("_jev_judged_retained")
        and (
            item.get("_llm_verdict") == "TRUE_POSITIVE"
            or (item.get("_jev_agreed") is True and not item.get("_llm_verdict"))
        )
    ]
    reported.extend(output.get("new_dead_code", []))
    return reported


def _score(rows: list[dict]) -> dict[str, float | int | None]:
    tp = sum(row["expected"] == "unused" and row["reported"] for row in rows)
    fp = sum(row["expected"] == "used" and row["reported"] for row in rows)
    fn = sum(row["expected"] == "unused" and not row["reported"] for row in rows)
    tn = sum(row["expected"] == "used" and not row["reported"] for row in rows)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "accuracy": (tp + tn) / len(rows) if rows else None,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _label_rows(
    root: Path,
    labels: dict[str, list[dict]],
    reported: list[dict],
    verified: list[dict] | None = None,
) -> list[dict]:
    rows = []
    for expected, items in (("unused", labels["unused"]), ("used", labels["used"])):
        for label in items:
            match = next(
                (item for item in reported if _matches(item, label, root)), None
            )
            source = next(
                (item for item in verified or [] if _matches(item, label, root)),
                None,
            )
            rows.append(
                {
                    "label_id": label.get("label_id")
                    or f"{label['file']}:{label['symbol']}:{label.get('line', '')}",
                    "expected": expected,
                    "reported": match is not None,
                    "jev_status": source.get("_jev_status") if source else None,
                    "jev_agreed": bool(source and source.get("_jev_agreed")),
                    "jev_judged_retained": bool(
                        source and source.get("_jev_judged_retained")
                    ),
                    "jev_choice": source.get("_jev_choice") if source else None,
                    "jev_confidence": source.get("_jev_confidence") if source else None,
                    "jev_choice_probability": (
                        source.get("_jev_choice_probability") if source else None
                    ),
                    "llm_verdict": source.get("_llm_verdict") if source else None,
                }
            )
    return sorted(rows, key=lambda row: row["label_id"])


def _run_static_arm(
    parent: Path,
    files: list[dict[str, str]],
    labels: dict[str, list[dict]],
    *,
    case_id: str = "case",
    scan: dict | None = None,
    prepared: tuple[Path, list[dict], dict, float] | None = None,
) -> dict:
    if prepared is None:
        root = _source_root(parent, files, "static")
        started = time.monotonic()
        findings, _ = _scan(root, scan=scan)
        elapsed = round(time.monotonic() - started, 3)
        _candidate_coverage(case_id, labels, findings, root)
    else:
        root, findings, _, elapsed = prepared
    rows = _label_rows(root, labels, findings)
    return {
        "static_candidate_count": len(findings),
        "stats": {"llm_calls": 0, "total_tokens": 0},
        "elapsed_seconds": elapsed,
        "static_scan_seconds": elapsed,
        "score": _score(rows),
        "labels": rows,
    }


def _run_arm(
    parent: Path,
    files: list[dict[str, str]],
    labels: dict[str, list[dict]],
    *,
    arm: str,
    model: str,
    api_key: str,
    case_id: str = "case",
    scan: dict | None = None,
    prepared: tuple[Path, list[dict], dict, float] | None = None,
) -> dict:
    if prepared is None:
        root = _source_root(parent, files, arm)
        scan_started = time.monotonic()
        findings, defs_map = _scan(root, scan=scan)
        scan_elapsed = round(time.monotonic() - scan_started, 3)
        _candidate_coverage(case_id, labels, findings, root)
    else:
        root, findings, defs_map, scan_elapsed = prepared
    started = time.monotonic()
    # Verification feedback is a user-global adaptive store, not part of this
    # benchmark. Keep the paid experiment from mutating it.
    with patch("skylos.llm.verify_orchestrator._attach_feedback_summary"):
        result = run_verification_harness(
            findings=copy.deepcopy(findings),
            defs_map=defs_map,
            project_root=root,
            harness_trace_root=parent / arm / "traces",
            model=model,
            provider="openai",
            api_key=api_key,
            max_verify=50,
            max_challenge=20,
            verification_mode="judge_all",
            jev_precheck=arm == "cascade",
            jev_judge=arm == "judge",
            quiet=True,
        )
    elapsed = round(time.monotonic() - started, 3)
    output = result.output
    _validate_new_dead(case_id, labels, output.get("new_dead_code", []), root)
    reported = _reported(output)
    rows = _label_rows(root, labels, reported, output["verified_findings"])
    return {
        "static_candidate_count": len(findings),
        "stats": output["stats"],
        "elapsed_seconds": elapsed,
        "static_scan_seconds": scan_elapsed,
        "score": _score(rows),
        "labels": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--model", default="gpt-4.1")
    parser.add_argument(
        "--expect-manifest-digest",
        help="Fail before any paid call unless frozen manifest bytes match this SHA-256",
    )
    parser.add_argument(
        "--judge-only",
        action="store_true",
        help="Run only the Jev judge arm (requires --live; not a same-run comparison)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--live", action="store_true", help="Make paid OpenAI and TypeSafe calls"
    )
    mode.add_argument(
        "--static-only",
        action="store_true",
        help="Write a pure Skylos report without either model or API key",
    )
    args = parser.parse_args()
    if args.judge_only and not args.live:
        parser.error("--judge-only requires --live")

    manifest, digest = _load_manifest_snapshot(args.manifest)
    if args.expect_manifest_digest and args.expect_manifest_digest != digest:
        raise JevBenchmarkError(
            "manifest digest does not match --expect-manifest-digest"
        )
    cases = _manifest_cases(manifest, args.manifest)
    raw_cases = manifest.get("cases") or []
    raw_scan_by_id = {
        raw["id"]: raw["scan"]
        for raw in raw_cases
        if isinstance(raw, dict) and "id" in raw and "scan" in raw
    }
    for case in cases:
        if "scan" not in case and case["id"] in raw_scan_by_id:
            case["scan"] = raw_scan_by_id[case["id"]]
    if len(cases) > MAX_CASES:
        raise JevBenchmarkError(f"more than {MAX_CASES} cases need explicit scoping")
    prepared = [(case, _read_case_files(_safe_case_path(case))) for case in cases]
    print(
        f"Frozen {manifest.get('split') or 'labeled'} benchmark: {len(prepared)} cases, "
        f"{sum(len(case['expect']['unused']) + len(case['expect']['used']) for case, _ in prepared)} labels"
    )
    dry_plan = not args.live and not args.static_only
    if not dry_plan:
        if args.output is None or args.output.exists() or args.output.is_symlink():
            raise JevBenchmarkError(
                "--live or --static-only requires a new --output path"
            )
        if args.live and (
            not os.environ.get("TYPESAFE_API_KEY")
            or not os.environ.get("OPENAI_API_KEY")
        ):
            raise JevBenchmarkError("TYPESAFE_API_KEY and OPENAI_API_KEY are required")

    arms = (
        ["judge"]
        if args.judge_only
        else ["static", "baseline", "cascade", "judge"]
        if args.live or dry_plan
        else ["static"]
    )
    preflight_arms = ["static", "judge"] if args.judge_only else arms
    seen_label_ids: set[str] = set()
    for case, _files in prepared:
        for _expected, label in _validate_labels(case["id"], case["expect"]):
            explicit_id = label.get("label_id")
            if explicit_id is None:
                continue
            if explicit_id in seen_label_ids:
                raise JevBenchmarkError(f"duplicate benchmark label id: {explicit_id}")
            seen_label_ids.add(explicit_id)

    # Complete all static checks before the first paid request. A partial run
    # must never be interpreted as a valid paired benchmark when a later case
    # has an unlabeled candidate or the isolated arm scans disagree.
    with ExitStack() as stack:
        ready = []
        for case, files in prepared:
            parent = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="skylos-jev-cascade-")
                )
            )
            preflight = _prepare_case(parent, case, files, preflight_arms)
            ready.append((case, files, parent, preflight))
            if dry_plan:
                coverage = preflight["coverage"]
                print(
                    f"  {case['id']}: {coverage['static_candidate_count']} labeled "
                    f"static candidates, {coverage['matched_label_count']}/"
                    f"{coverage['label_count']} labels matched"
                )
        if dry_plan:
            print(
                "Dry plan only. --static-only writes a no-key Skylos score; "
                "--live runs all four arms, including paid APIs; "
                "--live --judge-only reruns only the judge arm."
            )
            return 0

        report = {
            "schema_version": "skylos-jev-cascade-benchmark/v3",
            "manifest": str(args.manifest),
            "manifest_digest": digest,
            "split": manifest.get("split"),
            "model": args.model if args.live else None,
            "verification_mode": "judge_all" if args.live else None,
            "max_verify": 50 if args.live else None,
            "max_challenge": 20 if args.live else None,
            "arms": arms,
            "status": "incomplete",
            "cases": [],
        }
        for case, files, parent, preflight in ready:
            result = {
                "case_id": case["id"],
                "source_digest": preflight["source_digest"],
                "scan_policy": preflight["scan_policy"],
                "static_candidate_inventory_digest": preflight[
                    "static_candidate_inventory_digest"
                ],
                "coverage": preflight["coverage"],
            }
            for arm in arms:
                try:
                    if arm == "static":
                        result[arm] = _run_static_arm(
                            parent,
                            files,
                            case["expect"],
                            case_id=case["id"],
                            prepared=preflight["arms"][arm],
                        )
                    else:
                        result[arm] = _run_arm(
                            parent,
                            files,
                            case["expect"],
                            arm=arm,
                            model=args.model,
                            api_key=os.environ["OPENAI_API_KEY"],
                            case_id=case["id"],
                            prepared=preflight["arms"][arm],
                        )
                except Exception as exc:
                    error = {"error_type": type(exc).__name__}
                    if isinstance(exc, ImportError):
                        error["error_message"] = str(exc)
                    result[arm] = error
                    report["cases"].append(result)
                    args.output.write_text(
                        json.dumps(report, indent=2) + "\n", encoding="utf-8"
                    )
                    print(f"{case['id']} {arm} failed: {error}", file=sys.stderr)
                    return 1
            report["cases"].append(result)
            args.output.write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            print(
                f"{case['id']}: "
                + " ".join(f"{arm}={result[arm]['score']}" for arm in arms)
            )

    for arm in report["arms"]:
        report[arm] = {
            "score": _score(
                [row for case in report["cases"] for row in case[arm]["labels"]]
            ),
            "llm_calls": sum(
                case[arm]["stats"]["llm_calls"] for case in report["cases"]
            ),
            "llm_tokens": sum(
                case[arm]["stats"]["total_tokens"] for case in report["cases"]
            ),
            "elapsed_seconds": round(
                sum(case[arm]["elapsed_seconds"] for case in report["cases"]), 3
            ),
            "static_scan_seconds": round(
                sum(case[arm]["static_scan_seconds"] for case in report["cases"]),
                3,
            ),
        }
    if args.live:
        for arm in ("cascade", "judge"):
            if arm not in report["arms"]:
                continue
            for key in (
                "jev_agreed",
                "jev_disagreed",
                "jev_uncertain",
                "jev_unavailable",
                "jev_judged_retained",
            ):
                report[arm][key] = sum(
                    case[arm]["stats"].get(key, 0) for case in report["cases"]
                )
        checked = sum(
            report["judge"][key]
            for key in ("jev_agreed", "jev_disagreed", "jev_uncertain")
        )
        report["status"] = "complete" if checked else "jev_unavailable"
    else:
        report["status"] = "complete"
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for arm in report["arms"]:
        print(f"Overall {arm}: {report[arm]}")
    print(f"Full result: {args.output}")
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except JevBenchmarkError as exc:
        print(f"Cascade benchmark error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
