"""Benign mock scorer demonstrations; no detectors or target code execute."""

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from skylos.benchmarks import dead_code, framework_corpus, security  # noqa: E402


def source(function):
    return {"file": Path(inspect.getsourcefile(function)).relative_to(ROOT).as_posix(),
            "line": inspect.getsourcelines(function)[1]}


def finding(rule, file, line):
    return {"rule_id": rule, "file": file, "line": line, "message": "Mock record"}


def security_proof(directory):
    case = {"id": "mock-security-selected-rule", "path": ".",
            "taxonomy": ["precision_guard"], "expect": {
                "present": {"danger": ["SKY-D211"]},
                "absent": {"danger": ["SKY-D209"]}}}
    correct = finding("SKY-D211", "target.py", 10)
    wrong_file = finding("SKY-D211", "unrelated.py", 10)
    wrong_line = finding("SKY-D211", "target.py", 40)
    extra = finding("SKY-D216", "other.py", 3)
    scenarios = {
        "intended_location": [correct],
        "wrong_file_same_rule": [wrong_file],
        "wrong_line_same_rule": [wrong_line],
        "additional_unlabelled_rule": [correct, extra],
        "wrong_location_and_extra_rule": [wrong_file, extra]}
    outcomes = {}
    for name, findings in scenarios.items():
        report = {"analysis_summary": {"total_files": 3, "analysis_error_count": 0},
                  "analysis_errors": [], "danger": findings}
        with patch.object(security, "_scan_case_with_scanner", return_value=report):
            scored = security.run_case(case, directory / "manifest.json")
        scored.pop("path")
        scored.pop("elapsed_seconds")
        assert scored["scored"] and scored["analysis_status"] == "complete"
        assert scored["true_positives"] == scored["true_negatives"] == 1
        assert scored["false_positives"] == scored["false_negatives"] == 0
        assert scored["scores"]["overall_score"] == 100 and not scored["failures"]
        outcomes[name] = {"mock_findings": findings, "actual_runner_result": scored}
    return {"scope": "Hypothetical finding records at scanner boundary, not detector output",
            "manifest_expectations": case["expect"],
            "intended_positive_location_not_represented_in_schema": correct,
            "assumed_false_warning_locations": [wrong_file, wrong_line, extra],
            "scenarios": outcomes,
            "source": [source(security.run_case), source(security._evaluate_expectations)]}


def framework_proof(directory):
    counts = {"unused_imports": 0, "unused_functions": 1, "unused_classes": 0,
              "unused_variables": 0, "unused_parameters": 0}
    target = {"id": "mock-framework-counts", "repo": "https://github.com/duriantaco/skylos",
              "ref": "mock-only", "checkout": ".",
              "baseline": {"counts": counts, "max_delta": 0}}
    original = {"name": "dead_local", "file": "module.py", "line": 1}
    replacement = {"name": "live_handler", "file": "module.py", "line": 5}
    scenarios = {
        "original_finding": {"unused_functions": [original]},
        "same_count_replacement": {"unused_functions": [replacement]},
        "lower_count": {"unused_functions": []},
        "extra_untracked_file": {"unused_functions": [original],
                                 "unused_files": [{"file": "module.py", "line": 1}]}}
    outcomes = {}
    for name, report in scenarios.items():
        with patch.object(framework_corpus, "_scan_target", return_value=report):
            scored = framework_corpus.run_target(target, checkout_root=directory)
        scored.pop("path")
        outcomes[name] = {"mock_findings": report, "actual_runner_result": scored}
        assert scored["status"] == ("fail" if name == "lower_count" else "pass")
    precise = deepcopy(target)
    precise["expect"] = {
        "present": [{"category": "unused_functions", "file": "module.py", "symbol": "dead_local"}],
        "absent": [{"category": "unused_functions", "file": "module.py", "symbol": "live_handler"}]}
    with patch.object(framework_corpus, "_scan_target", return_value=scenarios["same_count_replacement"]):
        checked = framework_corpus.run_target(precise, checkout_root=directory)
    checked.pop("path")
    assert checked["status"] == "fail" and len(checked["failures"]) == 2
    manifest = json.loads((ROOT / "benchmarks/framework_corpus/manifest.json").read_text())
    return {"scope": "Mock finding substitution, not framework repository analysis",
            "baseline_counts": counts, "scenarios": outcomes,
            "replacement_with_symbol_expectations": checked,
            "current_manifest_targets": [{"id": item["id"],
                "max_delta": item["baseline"].get("max_delta", 0),
                "has_symbol_expectations": bool(item.get("expect")),
                "counted_categories": sorted(item["baseline"]["counts"])}
                for item in manifest["targets"]],
            "source": [source(framework_corpus.run_target), source(framework_corpus._compare_baseline),
                       source(framework_corpus._compare_expectations)]}


def metric_proof():
    counts = {"true_positives": 0, "false_positives": 1, "false_negatives": 8,
              "true_negatives": 7, "elapsed_seconds": 0, "max_seconds": None}
    security_scores = security._score_counts(**counts)
    deadcode_scores = dead_code._score_counts(**counts)
    assert security_scores["precision"] == security_scores["recall"] == 0
    assert security_scores["f1"] == 0.0
    assert deadcode_scores["f1"] == 0.0
    return {"input": counts, "security_actual": security_scores,
            "deadcode_actual": deadcode_scores,
            "correct_f1_from_2tp_over_2tp_plus_fp_plus_fn": 0.0,
            "source": [source(security._score_counts), source(dead_code._score_counts)]}


def corpus_inventory():
    manifest = ROOT / "corpus/manifest.json"
    cases = json.loads(manifest.read_text())["cases"]
    recognized = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts",
                  ".go", ".java", ".rs", ".php", ".dart", ".rb", ".swift", ".cs",
                  ".kt", ".cpp", ".sh", ".svelte", ".vue", ".astro"}
    file_counts, case_counts, entries = Counter(), Counter(), []
    assertion_categories = Counter()
    for case in cases:
        for categories in case["expect"].values():
            for category, labels in categories.items():
                assertion_categories[category] += len(labels)
        path = manifest.parent / case["path"]
        files = sorted(path.rglob("*")) if path.is_dir() else [path]
        files = [file for file in files if file.is_file() and file.suffix.lower() in recognized]
        suffixes = Counter(file.suffix.lower() for file in files)
        file_counts.update(suffixes)
        case_counts.update(suffixes.keys())
        python_files = [file.relative_to(ROOT).as_posix() for file in files if file.suffix == ".py"]
        entries.append({"id": case["id"], "path": case["path"],
                        "source_suffix_counts": dict(sorted(suffixes.items())),
                        "python_files": python_files,
                        "python_files_excluding_run_py": [file for file in python_files if Path(file).name != "run.py"]})
    return {"manifest": manifest.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(), "case_count": len(cases),
            "cases_with_python": sum(bool(item["python_files"]) for item in entries),
            "cases_with_python_excluding_run_py": sum(bool(item["python_files_excluding_run_py"]) for item in entries),
            "python_only_cases": sum(set(item["source_suffix_counts"]) == {".py"} for item in entries),
            "cases_without_python": sum(not item["python_files"] for item in entries),
            "suffix_file_counts": dict(sorted(file_counts.items())),
            "suffix_case_counts": dict(sorted(case_counts.items())),
            "assertion_category_counts": dict(sorted(assertion_categories.items())),
            "files_named_run_py": [file for item in entries for file in item["python_files"] if Path(file).name == "run.py"],
            "limits": "Suffix presence measures fixture composition, not assertion-bound language coverage or completeness",
            "cases": entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="skylos-score-proof-") as temporary:
        directory = Path(temporary)
        (directory / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
        result = {"purpose": "Executed benign scorer counterexamples, not scanner vulnerability claims",
                  "security": security_proof(directory), "framework": framework_proof(directory),
                  "metric": metric_proof(), "corpus_language_audit": corpus_inventory()}
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"All scoring demonstrations passed; output: {args.output}")


if __name__ == "__main__":
    main()
