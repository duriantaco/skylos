#!/usr/bin/env python3
"""Reproduce the current workflow/SCA product audit. No target code is executed.

Run from any directory:
  /Users/oha/skylos/.venv/bin/python /Users/oha/skylos/scripts/product_workflow_sca_evidence.py
Use --output to select an artifact directory. OSV/network calls are blocked.
Assertions cover fixed enforcement paths and the remaining explicit coverage
limits. Fixtures are synthetic; this is not live service or accuracy evidence.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=Path("/private/tmp/skylos-product-audit/fixed/workflow_sca"))
args = parser.parse_args()
OUT = args.output.resolve()
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT))

def deny_network(*args, **kwargs):
    raise AssertionError("Audit fixtures must not contact the network")

socket.socket.connect = deny_network

import yaml
from skylos.cicd.workflow import generate_workflow
from skylos.cloud.sync_setup import cloud_workflow_content
from skylos.cli_core.main_parser import build_main_parser
from skylos.rules.config.cicd.github_actions import scan_github_actions
from skylos.rules.ai_defect.ci_permission_expansion import detect_ci_permission_expansion
from skylos.rules.sca.vulnerability_scanner import collect_dependencies


def write(relative, content):
    target = OUT / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


cloud = cloud_workflow_content()
cicd = generate_workflow()
write("generated-cloud.yml", cloud)
write("generated-cicd.yml", cicd)
cloud_parsed = yaml.safe_load(cloud)
cicd_parsed = yaml.safe_load(cicd)
cicd_policy_pull = next(
    step["run"] for step in cicd_parsed["jobs"]["cloud-upload"]["steps"]
    if "sync pull" in step.get("run", "")
)
pr_commands = [s["run"] for s in cloud_parsed["jobs"]["pull-request"]["steps"] if "run" in s]
pr_scan = next(s for s in pr_commands if s.startswith("skylos ."))
pr_args = build_main_parser(version="audit").parse_args(shlex.split(pr_scan)[1:])

unsafe = '''name: Unsafe workflow
"on": pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
      - run: ./scripts/release.sh
'''
unsafe_root = OUT / "fixtures/unsafe"
write("fixtures/unsafe/.github/workflows/unsafe.yml", unsafe)
unsafe_findings = scan_github_actions(unsafe_root)
write("unsafe-findings.json", json.dumps(unsafe_findings, indent=2))

malformed = '''name: Malformed
"on": pull_request_target
permissions: write-all
jobs: [
'''
write("fixtures/malformed/.github/workflows/malformed.yml", malformed)
malformed_errors = []
malformed_findings = scan_github_actions(
    OUT / "fixtures/malformed", analysis_errors=malformed_errors
)

caller = '''name: Caller
"on": pull_request
permissions: {}
jobs:
  call:
    permissions:
      contents: read
      id-token: write
    uses: ./.github/workflows/build.yml
'''
callee = '''name: Callee
"on": workflow_call
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: ./scripts/release.sh
'''
write("fixtures/reusable/.github/workflows/caller.yml", caller)
write("fixtures/reusable/.github/workflows/build.yml", callee)
reusable_findings = scan_github_actions(OUT / "fixtures/reusable")
write("reusable-findings.json", json.dumps(reusable_findings, indent=2))

write("fixtures/sca_exact/requirements.txt", "requests==2.31.0\n")
write("fixtures/sca_ranges/requirements.txt", "requests>=2.31.0\n")
write("fixtures/sca_extra/requirements-dev.txt", "requests==2.31.0\n")
write("fixtures/sca_cargo/Cargo.toml", '[package]\nname="example"\nversion="0.1.0"\n[dependencies]\nregex="1.0"\n')
write("fixtures/sca_java/pom.xml", '<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>\n')
write("fixtures/sca_npm/package-lock.json", json.dumps({"name":"example", "lockfileVersion":3, "packages":{"":{"name":"example", "dependencies":{"lodash":"4.17.20"}}, "node_modules/lodash":{"version":"4.17.20", "resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}))
coverage_policy = "gate:\n  coverage:\n    required: [sca]\n    require_resolved_versions: true\n"
for name, manifest in {
    "ranges": "requirements.txt", "cargo": "Cargo.toml", "java": "pom.xml"
}.items():
    write(f"fixtures/sca_{name}_required/{manifest}", (OUT / f"fixtures/sca_{name}/{manifest}").read_text())
    write(f"fixtures/sca_{name}_required/.skylos/config.yaml", coverage_policy)
inventories = {}
for name in ("exact", "ranges", "extra", "cargo", "java", "npm"):
    inventory = collect_dependencies(OUT / "fixtures" / f"sca_{name}")
    inventories[name] = {"dependencies":list(inventory), "receipt":inventory.receipt, "manifest_gaps":inventory.manifest_gaps}
write("sca-inventories.json", json.dumps(inventories, indent=2))

old = 'name: CI\n"on": pull_request\npermissions: read-all\n'
new = 'name: CI\n"on": pull_request_target\npermissions: write-all\n'
diff = "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile="a/.github/workflows/ci.yml", tofile="b/.github/workflows/ci.yml"))
write("permission-expansion.diff", diff)
expansion = detect_ci_permission_expansion(diff, ".github/workflows/ci.yml")
write("permission-expansion-findings.json", json.dumps(expansion, indent=2))

# Execute Skylos static scans and gates, never the scanned target.
# Unsafe workflow command text is parsed as data, never executed.
env = os.environ.copy()
for key in list(env):
    if key.startswith(("SKYLOS_", "ANTHROPIC_", "OPENAI_", "TYPESAFE_")):
        env.pop(key, None)
env["CI"] = "true"
env["SKYLOS_JOBS"] = "1"
network_guard = write("network_guard/sitecustomize.py", 'import socket\ndef _deny_network(*args, **kwargs):\n    raise AssertionError("Audit CLI subprocess must not contact the network")\nsocket.socket.connect = _deny_network\n')
env["PYTHONPATH"] = os.pathsep.join((str(network_guard.parent), str(ROOT)))

# Exercise the exact generated PR arguments against an immutable fixture base.
# Only Git records are written; no workflow commands or source are executed.
safe_workflow = 'name: Safe\n"on": pull_request\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - run: echo safe\n'
unsafe_path = unsafe_root / ".github/workflows/unsafe.yml"
unsafe_path.write_text(safe_workflow, encoding="utf-8")
def fixture_git(*arguments):
    return subprocess.run(
        ["git", "-c", "user.name=Skylos Audit", "-c", "user.email=audit@example.invalid",
         "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
         "-c", "core.fsmonitor=false", *arguments],
        cwd=unsafe_root, env=env, text=True, capture_output=True, check=True, timeout=30,
    )
fixture_git("init", "-q")
fixture_git("add", "--", ".github/workflows/unsafe.yml")
fixture_git("commit", "--allow-empty", "-qm", "fixture baseline")
base_sha = fixture_git("rev-parse", "HEAD").stdout.strip()
unsafe_path.write_text(unsafe, encoding="utf-8")
generated_pr_arguments = [
    base_sha if argument == "$SKYLOS_BASE_REF" else argument
    for argument in shlex.split(pr_scan)[1:]
]
commands = {
    "cloud_pr_equivalent": [str(ROOT / ".venv/bin/skylos"), *generated_pr_arguments],
    "json_report_only": [str(ROOT / ".venv/bin/skylos"), ".", "--danger", "--no-upload", "--format", "json"],
    "json_with_gate": [str(ROOT / ".venv/bin/skylos"), ".", "--danger", "--no-upload", "--format", "json", "--gate"],
    "json_with_strict_gate": [str(ROOT / ".venv/bin/skylos"), ".", "--danger", "--no-upload", "--format", "json", "--gate", "--strict"],
    "malformed_json_with_gate": [str(ROOT / ".venv/bin/skylos"), ".", "--danger", "--no-upload", "--format", "json", "--gate"],
    "sca_ranges_with_gate": [str(ROOT / ".venv/bin/skylos"), ".", "--sca", "--no-upload", "--format", "json", "--gate"],
    "sca_cargo_with_gate": [str(ROOT / ".venv/bin/skylos"), ".", "--sca", "--no-upload", "--format", "json", "--gate"],
    "sca_java_with_gate": [str(ROOT / ".venv/bin/skylos"), ".", "--sca", "--no-upload", "--format", "json", "--gate"],
    "sca_ranges_required_with_gate": [str(ROOT / ".venv/bin/skylos"), ".", "--sca", "--no-upload", "--format", "json", "--gate"],
    "sca_cargo_required_with_gate": [str(ROOT / ".venv/bin/skylos"), ".", "--sca", "--no-upload", "--format", "json", "--gate"],
    "sca_java_required_with_gate": [str(ROOT / ".venv/bin/skylos"), ".", "--sca", "--no-upload", "--format", "json", "--gate"],
}
command_results = {}
for name, command in commands.items():
    cwd = OUT / "fixtures/malformed" if name == "malformed_json_with_gate" else unsafe_root
    if name.startswith("sca_"):
        cwd = OUT / "fixtures" / name.removesuffix("_with_gate")
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=120)
    write(f"{name}.stdout.txt", result.stdout)
    write(f"{name}.stderr.txt", result.stderr)
    command_results[name] = {"command":command, "cwd":str(cwd), "exit_code":result.returncode, "stdout_file":str(OUT / f"{name}.stdout.txt"), "stderr_file":str(OUT / f"{name}.stderr.txt")}
    if name != "cloud_pr_equivalent" and result.stdout.strip():
        parsed = json.loads(result.stdout)
        command_results[name]["security_findings"] = len(parsed.get("danger", []))
        command_results[name]["analysis_errors"] = parsed.get("analysis_errors", [])
        if name.startswith("sca_"):
            command_results[name]["sca_coverage"] = parsed.get("analysis_summary", {}).get("sca_coverage")

results = {
    "source_root": str(ROOT),
    "artifact_root": str(OUT),
    "probe_scope": {
        "fixture_kind": "small synthetic examples, not deployment or accuracy evidence",
        "network": "connections blocked; no live OSV or Cloud calls",
        "target_execution": "none; workflow command text is analyzed as data",
        "generated_pr_baseline": "immutable commit created in the fixture repository",
        "dependency_coverage": "unsupported ecosystems and unresolved versions remain explicit limits",
    },
    "generated_cloud_pr": {"command":pr_scan, "gate":pr_args.gate, "strict":pr_args.strict, "sca":pr_args.sca, "diff_mode":pr_args.diff_mode, "baseline_sha":base_sha, "sync_pull_present":any("sync pull" in x for x in pr_commands)},
    "generated_cicd": {"separate_gate_present":"skylos cicd gate" in cicd, "sca_present":"--sca" in cicd, "sync_failures_continue":"skylos sync pull || echo" in cicd, "sync_failure_blocks_upload":"if ! skylos sync pull" in cicd_policy_pull and "exit 1" in cicd_policy_pull},
    "positive_workflow": {"count":len(unsafe_findings), "rule_ids":sorted({x["rule_id"] for x in unsafe_findings})},
    "malformed_workflow": {"findings":malformed_findings, "analysis_errors":malformed_errors},
    "reusable_workflow": {"rule_ids":sorted({x["rule_id"] for x in reusable_findings}), "oidc_build_risk_detected":any(x["rule_id"] == "SKY-D310" for x in reusable_findings)},
    "permission_expansion": {"count":len(expansion), "rule_ids":sorted({x["rule_id"] for x in expansion})},
    "sca_inventory_summary": {name:{"dependency_count":len(value["dependencies"]), "status":value["receipt"]["status"], "complete":value["receipt"]["complete"], "category_complete":value["receipt"]["category_complete"], "unresolved_dependency_count":value["receipt"]["unresolved_dependency_count"]} for name,value in inventories.items()},
    "cli_runs": command_results,
}
checks = []

def check(name, actual, expected):
    checks.append({"name": name, "actual": actual, "expected": expected, "passed": actual == expected})

check("cloud_pr_enforces_gate", results["generated_cloud_pr"]["gate"], True)
check("cloud_pr_enforces_strict_gate", results["generated_cloud_pr"]["strict"], True)
check("cloud_pr_includes_sca", results["generated_cloud_pr"]["sca"], True)
check("cloud_pr_gates_introduced_findings", results["generated_cloud_pr"]["diff_mode"], "impact")
check("cloud_pr_has_no_policy_pull", results["generated_cloud_pr"]["sync_pull_present"], False)
check("cicd_has_separate_gate", results["generated_cicd"]["separate_gate_present"], True)
check("cicd_includes_sca", results["generated_cicd"]["sca_present"], True)
check("cicd_policy_pull_failure_does_not_continue", results["generated_cicd"]["sync_failures_continue"], False)
check("cicd_policy_pull_failure_blocks_upload", results["generated_cicd"]["sync_failure_blocks_upload"], True)
check("unsafe_yaml_detects_seven_risk_classes", results["positive_workflow"]["rule_ids"], ["SKY-D290", "SKY-D291", "SKY-D292", "SKY-D293", "SKY-D294", "SKY-D310", "SKY-D313"])
check("ci_diff_detects_two_permission_expansions", len(expansion), 2)
check("malformed_yaml_has_structured_scanner_error", [error["kind"] for error in malformed_errors], ["config_parse_error"])
check("reusable_permission_context_is_not_propagated", results["reusable_workflow"]["oidc_build_risk_detected"], False)
for name, expected_exit in {
    "cloud_pr_equivalent": 1,
    "json_report_only": 0,
    "json_with_gate": 0,
    "json_with_strict_gate": 1,
    "malformed_json_with_gate": 2,
    "sca_ranges_with_gate": 0,
    "sca_cargo_with_gate": 0,
    "sca_java_with_gate": 0,
    "sca_ranges_required_with_gate": 1,
    "sca_cargo_required_with_gate": 1,
    "sca_java_required_with_gate": 1,
}.items():
    check(f"{name}_exit", command_results[name]["exit_code"], expected_exit)
check("malformed_yaml_has_cli_analysis_error", [error["kind"] for error in command_results["malformed_json_with_gate"]["analysis_errors"]], ["config_parse_error"])
check("range_dependency_is_unresolved", inventories["ranges"]["receipt"]["unresolved_dependency_count"], 1)
check("range_dependency_is_not_queried", command_results["sca_ranges_with_gate"]["sca_coverage"]["queried_dependency_count"], 0)
for name in ("extra", "cargo", "java"):
    check(f"{name}_manifest_is_unsupported", inventories[name]["receipt"]["status"], "no_supported_manifests")
check("exact_requirements_pin_is_inventoried", len(inventories["exact"]["dependencies"]), 1)
check("npm_lockfile_package_is_inventoried", len(inventories["npm"]["dependencies"]), 1)
results["assertions"] = checks
results["assertion_count"] = len(checks)
results["passed_assertion_count"] = sum(item["passed"] for item in checks)
write("results.json", json.dumps(results, indent=2))
print(json.dumps({
    "assertion_count": results["assertion_count"],
    "passed_assertion_count": results["passed_assertion_count"],
    "cli_run_count": len(command_results),
    "dependency_inventory_count": len(inventories),
    "cli_exit_codes": {name: value["exit_code"] for name, value in command_results.items()},
    "results": str(OUT / "results.json"),
}, indent=2))
if results["passed_assertion_count"] != results["assertion_count"]:
    raise SystemExit(1)
