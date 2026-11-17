"""Replay frozen open-set labels without executing any target code.

Example: python run_holdouts.py --checkout-root /path/to/checkouts
  --analyzer-root /path/to/skylos --output /path/to/new-results-directory
Raw reports are kept alongside the summary; existing outputs are never replaced.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def relative_file(entry, checkout):
    try:
        return Path(entry.get("file", "")).resolve().relative_to(checkout).as_posix()
    except ValueError:
        return None


def evaluate(target, report, checkout, issues, overrides=()):
    definitions = report.get("definitions", {})
    definitions = list(definitions.values()) if isinstance(definitions, dict) else []
    unused = [item for key, items in report.items() if key.startswith("unused_")
              and isinstance(items, list) for item in items]
    outcomes = []
    for label in target["labels"]:
        scope = next((o for o in overrides if o["target_id"] == target["id"]
                      and all(o.get(k) == label.get(k) for k in
                              ("kind", "file", "rule_id", "start_line", "end_line"))), None)
        if scope and not scope["score_eligible"]:
            outcomes.append({"label": label, "outcome": scope["status"],
                             "issues": [scope["reason"]], "matching_findings": []})
            continue
        file_defs = [d for d in definitions if relative_file(d, checkout) == label["file"]]
        problems = list(issues)
        if not file_defs:
            problems.append("No parsed definitions in labelled source file")
        if label["kind"] == "used":
            matches = [d for d in file_defs if d.get("line") == label["line"]
                       and d.get("name", "").replace("::", ".").split(".")[-1] == label["symbol"]]
            if not matches:
                problems.append("Exact labelled definition was not parsed")
            findings = [f for f in unused if relative_file(f, checkout) == label["file"]
                        and (f.get("line") == label["line"] or f.get("rule_id") == "SKY-E003")]
            # A method is also at risk when its enclosing class is reported.
            for finding in report.get("unused_classes", []):
                if relative_file(finding, checkout) != label["file"]:
                    continue
                owner = finding.get("name", "").replace("::", ".")
                if owner and any(d.get("name", "").replace("::", ".").startswith(owner + ".")
                                 or owner in d.get("name", "").replace("::", ".").split(".")[:-1]
                                 for d in matches):
                    if finding not in findings:
                        findings.append(finding)
        else:
            findings = [f for f in report.get("danger", [])
                        if relative_file(f, checkout) == label["file"]
                        and f.get("rule_id") == label["rule_id"]
                        and label["start_line"] <= f.get("line", 0) <= label["end_line"]]
        outcomes.append({"label": label, "outcome": "incomplete" if problems else
                         "false_positive" if findings else "retained_control",
                         "issues": problems, "matching_findings": findings})
    return outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout-root", required=True, type=Path)
    parser.add_argument("--analyzer-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("blind_manifest.json"))
    parser.add_argument("--scope-review", type=Path, default=Path(__file__).with_name("blind_scope_review.json"))
    args = parser.parse_args()
    sys.path.insert(0, str(args.analyzer_root.resolve()))
    from skylos.analyzer import analyze
    from skylos.benchmarks._analysis_validation import analysis_issues
    from skylos.benchmarks.security_holdouts import verify_checkout, _isolated_environment

    manifest_path = args.manifest
    manifest = json.loads(manifest_path.read_text())
    review_path = args.scope_review
    review = json.loads(review_path.read_text())
    if review["manifest_sha256"] != hashlib.sha256(manifest_path.read_bytes()).hexdigest():
        raise ValueError("Scope review does not match frozen manifest")
    args.output.mkdir(parents=True, exist_ok=False)
    source_hashes = {str(p.relative_to(args.analyzer_root)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted((args.analyzer_root / "skylos").rglob("*.py"))}
    go_bin = os.environ.get("SKYLOS_GO_BIN")
    result = {"manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
              "scope_review_sha256": hashlib.sha256(review_path.read_bytes()).hexdigest(),
              "analyzer_source_sha256": hashlib.sha256(json.dumps(source_hashes, sort_keys=True).encode()).hexdigest(),
              "go_engine_sha256": hashlib.sha256(Path(go_bin).read_bytes()).hexdigest() if go_bin else None,
              "python": sys.version, "label_scope": "open", "targets": []}
    (args.output / "analyzer_sources.json").write_text(json.dumps(source_hashes, indent=2) + "\n")
    for target in manifest["targets"]:
        start = time.monotonic()
        row = {"id": target["id"], "revision": target["revision"]}
        check = dict(target, checkout=target["id"], ref=target["revision"],
                     source_files=[{"path": p, "sha256": h} for p, h in target["source_files"].items()])
        try:
            checkout, scan_root, _, snapshot = verify_checkout(check, args.checkout_root.resolve())
            with _isolated_environment():
                if go_bin:
                    os.environ["SKYLOS_GO_BIN"] = go_bin
                raw = analyze(str(scan_root), **manifest["scan"], enable_sca=False,
                              enable_ai_defects=False, enable_quality=False, enable_secrets=False,
                              enable_dependency_hallucinations=False, custom_rules_data=[],
                              trace_file=False, all_advice=True,
                              project_config_overrides={"ignore": [], "exclude": []})
            report = json.loads(raw) if isinstance(raw, str) else raw
            _, _, _, after_snapshot = verify_checkout(check, args.checkout_root.resolve())
            if snapshot != after_snapshot:
                raise ValueError("Checkout changed during analysis")
            issues = analysis_issues(report, scanner="skylos")
            raw_path = args.output / (target["id"] + ".json")
            raw_path.write_text(json.dumps(report, indent=2) + "\n")
            row.update(analysis_summary=report.get("analysis_summary"), analysis_issues=issues,
                       raw_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                       raw_report=raw_path.name,
                       finding_counts={k: len(v) for k, v in report.items() if isinstance(v, list)
                                       and (k.startswith("unused_") or k == "danger")},
                       labels=evaluate(target, report, checkout, issues, review["overrides"]))
        except Exception as exc:
            row.update(error=str(exc), labels=[{"label": label, "outcome": "incomplete", "issues": [str(exc)]}
                                              for label in target["labels"]])
        row["elapsed_seconds"] = round(time.monotonic() - start, 3)
        result["targets"].append(row)
        print(target["id"], dict(Counter(l["outcome"] for l in row["labels"])), flush=True)
        (args.output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    result["label_outcomes"] = dict(Counter(l["outcome"] for r in result["targets"] for l in r["labels"]))
    (args.output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return int(any(k in {"false_positive", "incomplete"} and v
                   for k, v in result["label_outcomes"].items()))


if __name__ == "__main__":
    raise SystemExit(main())
