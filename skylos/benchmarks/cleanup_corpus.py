"""Evaluate curated cleanup patterns without executing corpus source code.

An observation matches only its mapped rule, file and line span. Unmapped
patterns and incomplete scans are reported separately from detection misses.
This evaluates detection and queue visibility, never repair correctness.
"""

from __future__ import annotations

import argparse
from collections import Counter
from functools import wraps
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


def _contained(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError("corpus paths must be relative without parent traversal")
    candidate = root / path
    if any(part.is_symlink() for part in (candidate, *candidate.parents)):
        raise ValueError("corpus paths cannot contain symlinks")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve(strict=True)):
        raise ValueError("corpus path escapes its root")
    return resolved


def _regular_tree(root: Path) -> bool:
    return all(
        stat.S_ISREG(path.lstat().st_mode) or stat.S_ISDIR(path.lstat().st_mode)
        for path in root.rglob("*")
    )


def load_cases(manifest_path: Path) -> tuple[dict, list[dict]]:
    from skylos.rules.catalog import get_rule_catalog

    manifest_path = manifest_path.resolve(strict=True)
    root = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported cleanup corpus schema")
    cases = list(manifest.get("cases", []))
    for part in manifest.get("parts", []):
        document = json.loads(_contained(root, part).read_text(encoding="utf-8"))
        if document.get("schema_version") != 1:
            raise ValueError("unsupported cleanup corpus part schema")
        cases.extend(document["cases"])
    if not cases:
        raise ValueError("cleanup corpus must contain cases")
    rules = {entry["id"] for entry in get_rule_catalog()}
    seen, pairs = set(), {}
    for case in cases:
        for key in ("id", "path", "pair_id", "pattern", "rationale", "language"):
            if not isinstance(case.get(key), str) or not case[key].strip():
                raise ValueError(f"case needs a non-empty {key}")
        if case["id"] in seen:
            raise ValueError("duplicate corpus case id")
        seen.add(case["id"])
        if case["variant"] not in {"problematic", "control"}:
            raise ValueError("unknown case variant")
        if case["language"] not in {"python", "typescript", "javascript"}:
            raise ValueError("unsupported case language")
        source = case.get("source", {})
        if not source.get("url", "").startswith("https://") or any(
            not isinstance(source.get(key), str) or not source[key].strip()
            for key in ("revision", "license", "kind")
        ):
            raise ValueError("case needs pinned provenance and license metadata")
        directory = _contained(root, case["path"])
        if not directory.is_dir() or not _regular_tree(directory):
            raise ValueError(
                "case must be a directory of regular files without symlinks"
            )
        targets = case.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ValueError("case needs target spans")
        for target in targets:
            source_file = _contained(directory, target["file"])
            if not stat.S_ISREG(source_file.stat().st_mode):
                raise ValueError("target must be a regular source file")
            lines = source_file.read_text(encoding="utf-8").splitlines()
            start, end = target["start_line"], target["end_line"]
            if (
                type(start) is not int
                or type(end) is not int
                or not 1 <= start <= end <= len(lines)
            ):
                raise ValueError("invalid target line range")
            mapped = target.get("rule_ids")
            if not isinstance(mapped, list) or any(
                rule not in rules for rule in mapped
            ):
                raise ValueError("target contains an unknown rule id")
        pairs.setdefault(case["pair_id"], []).append(case)
    for pair in pairs.values():
        if len(pair) != 2 or {c["variant"] for c in pair} != {"problematic", "control"}:
            raise ValueError("each pattern needs one problematic case and one control")
        if len({(c["pattern"], c["language"]) for c in pair}) != 1:
            raise ValueError("paired cases must share pattern and language")
        mapped = [{r for t in c["targets"] for r in t["rule_ids"]} for c in pair]
        if mapped[0] != mapped[1]:
            raise ValueError("paired cases must check the same rules")
    return manifest, cases


def _hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _blocked_operation(event, args, target: Path):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto"}:
        return "network"
    if event == "exec":
        filename = getattr(args[0], "co_filename", "")
        if (
            filename
            and not filename.startswith("<")
            and Path(filename).resolve().is_relative_to(target)
        ):
            return "corpus source execution"
    if event in {
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.posix_spawnp",
    }:
        argv = args[1] if len(args) > 1 else None
        if (
            not isinstance(argv, (list, tuple))
            or not argv
            or Path(str(argv[0])).name != "git"
        ):
            return "non-Git subprocess"
        tail = list(argv[1:])
        from skylos.core.git_safety import read_only_git_command

        for literal in (True, False):
            safe = read_only_git_command((), literal_pathspecs=literal)[1:]
            if tail[: len(safe)] == safe:
                tail = tail[len(safe) :]
                break
        while len(tail) >= 2 and tail[0] == "-C":
            tail = tail[2:]
        if len(tail) == 6 and tail[:5] == [
            "config",
            "--includes",
            "--null",
            "--name-only",
            "--get-regexp",
        ]:
            return None
        if not tail or tail[0] not in {
            "rev-parse",
            "ls-files",
            "status",
            "log",
            "show",
            "diff",
            "check-ignore",
        }:
            return "unexpected Git operation"
    return None


def _worker(target: Path) -> dict:
    """Run in a fresh process so audit hooks and analyzer state stay isolated."""
    target = target.resolve(strict=True)
    before = _hashes(target)
    blocked, captured = [], {}

    def audit(event, args):
        reason = _blocked_operation(event, args, target)
        if reason:
            detail = {"event": event, "reason": reason}
            if event == "subprocess.Popen" and Path(str(args[0])).name == "git":
                detail["git_argv"] = list(args[1])
            blocked.append(detail)
            raise RuntimeError(f"corpus evaluation blocked {reason}")

    sys.addaudithook(audit)
    from skylos.analyzer import analyze
    from skylos.commands.cleanup_cmd import run_cleanup_command
    from skylos.cleanup import build_cleanup_plan
    from skylos.reporting.finding_types import iter_result_findings

    @wraps(analyze)
    def capture(*args, **kwargs):
        raw = analyze(*args, **kwargs)
        captured.update(json.loads(raw) if isinstance(raw, str) else raw)
        return raw

    output = io.StringIO()
    code = run_cleanup_command(
        [str(target), "--format", "json", "--no-state", "--top", "100000"],
        stdout=output,
        analyze_func=capture,
    )
    queue = json.loads(output.getvalue())
    optional = (
        build_cleanup_plan(captured, project_root=target, top=None, all_advice=True)
        if captured.get("analysis_summary")
        else {"tasks": [], "advisories": []}
    )
    findings = []
    for category, finding in iter_result_findings(captured):
        if category in {"quality", "ai_defects", "dead_code"}:
            findings.append({**finding, "category": category})

    def relative(value):
        if isinstance(value, dict):
            return {key: relative(item) for key, item in value.items()}
        if isinstance(value, list):
            return [relative(item) for item in value]
        if isinstance(value, str):
            if value == str(target):
                return "."
            return value.replace(str(target) + os.sep, "")
        return value

    return relative(
        {
            "exit_code": code,
            "queue_status": queue["status"],
            "limitations": queue.get("limitations", []),
            "analysis_summary": captured.get("analysis_summary", {}),
            "analysis_errors": captured.get("analysis_errors", []),
            "findings": findings,
            "default_queue": queue["tasks"] + queue["advisories"],
            "all_advice_queue": optional["tasks"] + optional["advisories"],
            "blocked_events": blocked,
            "source_unchanged": before == _hashes(target),
            "source_sha256": before,
        }
    )


def _matches(finding: dict, target: dict) -> bool:
    return (
        finding.get("rule_id") in target["rule_ids"]
        and finding.get("file") == target["file"]
        and type(finding.get("line")) is int
        and target["start_line"] <= finding["line"] <= target["end_line"]
    )


def evaluate_case(case: dict, observation: dict) -> dict:
    from skylos.benchmarks._analysis_validation import analysis_issues

    issues = analysis_issues(observation, scanner="skylos")
    issues.extend(observation.get("limitations", []))
    if observation.get("exit_code") != 0 or observation.get("queue_status") not in {
        "clear",
        "ready",
    }:
        issues.append("cleanup did not complete")
    if observation.get("source_unchanged") is not True or observation.get(
        "blocked_events"
    ):
        issues.append("source integrity or execution boundary check failed")
    expected = {
        "python": "Python",
        "typescript": "TypeScript",
        "javascript": "JavaScript",
    }[case["language"]]
    count = observation.get("analysis_summary", {}).get("languages", {}).get(expected)
    if type(count) is not int or count <= 0:
        issues.append("case language was not analyzed")
    targets = []
    for target in case["targets"]:
        matches = [
            row for row in observation.get("findings", []) if _matches(row, target)
        ]
        if issues:
            outcome = "incomplete"
        elif not target["rule_ids"]:
            outcome = "unmapped"
        elif case["variant"] == "problematic":
            outcome = "detected" if matches else "missed"
        else:
            outcome = "false_positive" if matches else "clean_control"
        targets.append(
            {
                **target,
                "outcome": outcome,
                "matches": matches,
                "default_visible": any(
                    _matches(row, target)
                    for row in observation.get("default_queue", [])
                ),
                "all_advice_visible": any(
                    _matches(row, target)
                    for row in observation.get("all_advice_queue", [])
                ),
            }
        )
    return {
        **case,
        "targets": targets,
        "analysis_status": "incomplete" if issues else "complete",
        "analysis_issues": list(dict.fromkeys(issues)),
        "observation": observation,
    }


def run_manifest(manifest_path: Path, *, timeout: float = 60) -> dict:
    manifest, cases = load_cases(manifest_path)
    results = []
    for case in cases:
        original = _contained(manifest_path.resolve().parent, case["path"])
        with tempfile.TemporaryDirectory(prefix="skylos-cleanup-corpus-") as temporary:
            workspace = Path(temporary)
            target = workspace / "source"
            shutil.copytree(original, target)
            staged_hashes = _hashes(target)
            config = workspace / "operator.toml"
            config.write_text("[tool.skylos]\n", encoding="utf-8")
            policy = workspace / "operator-policy" / "config.yaml"
            policy.parent.mkdir()
            policy.write_text("{}\n", encoding="utf-8")
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("SKYLOS_")
            }
            env.update(
                SKYLOS_CONFIG_FILE=str(config),
                SKYLOS_SYNCED_POLICY_FILE=str(policy),
                SKYLOS_CUSTOM_RULES="[]",
                SKYLOS_JOBS="1",
            )
            try:
                process = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "skylos.benchmarks.cleanup_corpus",
                        "--worker",
                        str(target),
                    ],
                    cwd=Path(__file__).resolve().parents[2],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                if process.returncode:
                    raise ValueError("worker failed: " + process.stderr[-1000:])
                observation = json.loads(process.stdout)
            except (subprocess.TimeoutExpired, ValueError) as exc:
                observation = {"limitations": [str(exc)]}
        result = evaluate_case(case, observation)
        result["source_sha256"] = staged_hashes
        results.append(result)
    counts = Counter(
        target["outcome"] for result in results for target in result["targets"]
    )
    from skylos import __version__

    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "schema_version": 1,
        "scanner_version": __version__,
        "scanner_revision": revision.stdout.strip()
        if revision.returncode == 0
        else None,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "corpus_kind": manifest.get("kind", "curated-reproductions"),
        "case_count": len(results),
        "pair_count": len({case["pair_id"] for case in results}),
        "outcomes": dict(counts),
        "unmapped_patterns": sorted(
            {
                result["pattern"]
                for result in results
                if result["variant"] == "problematic"
                and any(target["outcome"] == "unmapped" for target in result["targets"])
            }
        ),
        "repair_evaluated": False,
        "target_code_executed": False,
        "profile": "cleanup CLI defaults; empty operator and synced policy; no history, registry checks, model calls, tests or edits; jobs=1",
        "cases": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker is not None:
        print(json.dumps(_worker(args.worker)))
        return 0
    if args.manifest is None:
        parser.error("--manifest is required")
    report = run_manifest(args.manifest)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {key: value for key, value in report.items() if key != "cases"}, indent=2
        )
    )
    if report["outcomes"].get("incomplete"):
        return 2
    return (
        1
        if any(report["outcomes"].get(key) for key in ("missed", "false_positive"))
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
