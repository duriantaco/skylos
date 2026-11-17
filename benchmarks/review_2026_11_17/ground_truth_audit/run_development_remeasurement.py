"""Static development remeasurement of all five frozen source-labelled repos.

Labels and original scan artifacts stay immutable. Output must be a new directory.
Fixes used these sources, so this is development evidence, not a new blind study.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative_file(record, root):
    value = record.get("file")
    if not isinstance(value, str) or ".." in Path(value).parts:
        return None
    path = Path(value)
    try:
        return (
            (path if path.is_absolute() else root / path)
            .resolve()
            .relative_to(root.resolve())
            .as_posix()
        )
    except ValueError:
        return None


def symbol_matches(record, symbol):
    name = (
        record.get("full_name") or record.get("name") or record.get("simple_name") or ""
    )
    name = name.replace("::", ".")
    return name == symbol or name.endswith("." + symbol)


def evaluate(facts, report, root, issues=()):
    definitions = report.get("definitions", {})
    definitions = (
        list(definitions.values()) if isinstance(definitions, dict) else definitions
    )
    definitions = definitions if isinstance(definitions, list) else []
    dead = [
        f
        for key, rows in report.items()
        if key.startswith("unused_") and isinstance(rows, list)
        for f in rows
    ]
    results = []
    for fact in facts:
        kind = fact.get("kind") or fact.get("truth")
        row = {
            "label": fact,
            "outcome": "unscored",
            "issues": [],
            "matching_findings": [],
        }
        if (
            kind not in {"used", "unused", "security_absent"}
            or fact.get("scoring_eligibility") is False
        ):
            row["issues"] = ["Unknown or explicitly inapplicable source fact"]
        elif issues:
            row.update(outcome="incomplete_analysis", issues=list(issues))
        elif kind in {"used", "unused"}:
            matches = [
                d
                for d in definitions
                if relative_file(d, root) == fact["file"]
                and d.get("line") == fact["line"]
                and symbol_matches(d, fact["symbol"])
            ]
            if len(matches) != 1:
                row.update(
                    outcome="incomplete_extraction",
                    issues=[
                        "Exact file/line/owner/symbol declaration not uniquely extracted"
                    ],
                )
            else:
                findings = [
                    f
                    for f in dead
                    if relative_file(f, root) == fact["file"]
                    and f.get("line") == fact["line"]
                    and symbol_matches(f, fact["symbol"])
                ]
                if kind == "used":
                    target_name = matches[0].get("full_name") or matches[0].get(
                        "name", ""
                    )
                    for parent in report.get("unused_classes", []):
                        parent_name = parent.get("full_name") or parent.get("name", "")
                        if (
                            relative_file(parent, root) == fact["file"]
                            and parent_name
                            and target_name.startswith(parent_name + ".")
                            and parent not in findings
                        ):
                            findings.append(parent)
                row["matching_findings"] = findings
                row["outcome"] = (
                    ("true_positive" if findings else "false_negative")
                    if kind == "unused"
                    else ("false_positive" if findings else "retained_used_control")
                )
        else:
            rule_id = fact.get("rule_id")
            if fact.get("property") == "untrusted_deserialization":
                tree = ast.parse((root / fact["file"]).read_text())
                calls = [
                    n
                    for n in ast.walk(tree)
                    if isinstance(n, ast.Call)
                    and n.lineno == fact["line"]
                    and (
                        (isinstance(n.func, ast.Name) and n.func.id == "loads")
                        or (
                            isinstance(n.func, ast.Attribute) and n.func.attr == "loads"
                        )
                    )
                ]
                if not calls:
                    row.update(
                        outcome="incomplete_label_location",
                        issues=[
                            "Frozen location does not contain described deserialization call"
                        ],
                    )
                    results.append(row)
                    continue
                rule_id = "SKY-D205"
            if not rule_id:
                row["issues"] = [
                    "No applicable native rule identity; absence earns no safe credit"
                ]
            elif not any(relative_file(d, root) == fact["file"] for d in definitions):
                row.update(
                    outcome="incomplete_extraction",
                    issues=["No declarations extracted in labelled security file"],
                )
            else:
                findings = [
                    f
                    for f in report.get("danger", [])
                    if relative_file(f, root) == fact["file"]
                    and f.get("rule_id") == rule_id
                    and fact["start_line"] <= f.get("line", 0) <= fact["end_line"]
                ]
                row["matching_findings"] = findings
                row["outcome"] = (
                    (
                        "safe_property_policy_warning"
                        if findings
                        else "retained_safe_property"
                    )
                    if fact.get("property")
                    else ("false_positive" if findings else "retained_safe_control")
                )
        results.append(row)
    return results


def load_targets():
    targets = []
    for name in [
        "SOURCE_LABELS_PYTHON.json",
        "SOURCE_LABELS_TYPESCRIPT.json",
        "SOURCE_LABELS_GOJI.json",
    ]:
        path = BASE / name
        data = json.loads(path.read_text())
        for item in data.get("repositories", [data.get("repository")]):
            targets.append(
                {
                    "id": item["id"],
                    "root": item.get("checkout") or item["root"],
                    "revision": item["revision"],
                    "coverage": item.get("review_coverage")
                    or item.get("coverage")
                    or data["files"],
                    "facts": item.get("labels") or data["rows"],
                    "labels_source": str(path),
                    "labels_sha256": digest(path),
                }
            )
    return targets


def verify_source(target):
    from skylos.benchmarks.security_holdouts import _git, _tracked_snapshot
    from skylos.core.git_context import GitContext

    root = Path(target["root"]).resolve()
    context = GitContext.from_path(root)
    if _git(context, "rev-parse", "HEAD") != target["revision"]:
        raise ValueError("Pinned revision changed: " + target["id"])
    snapshot = _tracked_snapshot(context, root, target["revision"])
    for record in target["coverage"]:
        if digest(root / record["file"]) != record["sha256"]:
            raise ValueError("Frozen source hash changed: " + record["file"])
    extensions = {".py", ".pyi", ".go", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
    for path in root.rglob("*"):
        if any(
            part in {".git", ".ruff_cache", "__pycache__"}
            for part in path.relative_to(root).parts
        ):
            continue
        if path.is_symlink():
            raise ValueError("Source symlink outside frozen regular-tree contract")
        if (
            path.is_file()
            and path.suffix in extensions
            and path.relative_to(root).as_posix() not in snapshot
        ):
            raise ValueError("Untracked source outside frozen tree: " + str(path))
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go-engine", type=Path, required=True)
    parser.add_argument("--target", action="append", default=[])
    args = parser.parse_args()
    sys.path.insert(0, str(REPO))
    from skylos.analyzer import analyze
    from skylos.benchmarks._analysis_validation import analysis_issues
    from skylos.benchmarks.security_holdouts import _isolated_environment

    targets = [t for t in load_targets() if not args.target or t["id"] in args.target]
    if set(args.target) - {t["id"] for t in targets}:
        raise ValueError("Unknown target selection")
    if not args.go_engine.is_file():
        raise ValueError("Missing trusted Go engine")
    snapshots = {t["id"]: verify_source(t) for t in targets}
    args.output.mkdir(parents=True, exist_ok=False)
    receipt = {
        "phase": "development_remeasurement_after_source_was_used_for_fixes",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "target_execution": False,
        "go_engine": str(args.go_engine.resolve()),
        "go_engine_sha256": digest(args.go_engine),
        "analyzer_source_sha256": {
            p.relative_to(REPO).as_posix(): digest(p)
            for p in sorted((REPO / "skylos").rglob("*.py"))
        },
        "scan_configuration": {
            "conf": 60,
            "enable_danger": True,
            "grep_verify": True,
            "grep_cache": False,
            "trace_file": False,
            "enable_quality": False,
            "enable_secrets": False,
            "enable_sca": False,
            "enable_ai_defects": False,
            "enable_dependency_hallucinations": False,
        },
        "repositories": [],
    }
    go_env = {
        k: os.environ[k]
        for k in (
            "GOROOT",
            "GOTOOLCHAIN",
            "GOWORK",
            "GOPROXY",
            "GOSUMDB",
            "CGO_ENABLED",
            "PATH",
        )
        if k in os.environ
    }
    receipt["go_environment"] = go_env
    for target in targets:
        started = time.monotonic()
        with _isolated_environment():
            os.environ.update(go_env)
            os.environ["SKYLOS_GO_BIN"] = str(args.go_engine.resolve())
            raw = analyze(
                target["root"],
                **receipt["scan_configuration"],
                custom_rules_data=[],
                all_advice=True,
                project_config_overrides={"ignore": [], "exclude": []},
            )
        report = json.loads(raw) if isinstance(raw, str) else raw
        raw_path = args.output / (target["id"] + ".json")
        raw_path.write_text(json.dumps(report, indent=2) + "\n")
        if (
            verify_source(target) != snapshots[target["id"]]
            or digest(Path(target["labels_source"])) != target["labels_sha256"]
        ):
            raise ValueError("Source or frozen labels changed during scan")
        issues = analysis_issues(report, scanner="skylos")
        outcomes = evaluate(target["facts"], report, Path(target["root"]), issues)
        row = {
            "id": target["id"],
            "revision": target["revision"],
            "root": target["root"],
            "labels_source": target["labels_source"],
            "labels_sha256": target["labels_sha256"],
            "source_integrity": "all_tracked_Git_blobs_and_frozen_hashes_unchanged",
            "seconds": round(time.monotonic() - started, 4),
            "analysis_issues": issues,
            "raw_report_sha256": digest(raw_path),
            "outcomes": outcomes,
            "counts": dict(Counter(o["outcome"] for o in outcomes)),
            "warning_counts": {
                k: len(v)
                for k, v in report.items()
                if isinstance(v, list) and (k.startswith("unused_") or k == "danger")
            },
        }
        receipt["repositories"].append(row)
        (args.output / "summary.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(target["id"], row["counts"], flush=True)
    receipt["completed_at"] = datetime.now(timezone.utc).isoformat()
    after_source = {
        p.relative_to(REPO).as_posix(): digest(p)
        for p in sorted((REPO / "skylos").rglob("*.py"))
    }
    receipt["analyzer_source_unchanged_after_scans"] = (
        after_source == receipt["analyzer_source_sha256"]
    )
    if not receipt["analyzer_source_unchanged_after_scans"]:
        raise ValueError("Analyzer source changed during remeasurement")
    receipt["total_counts"] = dict(
        Counter(o["outcome"] for r in receipt["repositories"] for o in r["outcomes"])
    )
    (args.output / "summary.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
