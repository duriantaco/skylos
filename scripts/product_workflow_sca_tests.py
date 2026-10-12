#!/usr/bin/env python3
"""Run the existing focused regression suites and save their real output."""
import argparse
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=Path("/private/tmp/skylos-product-audit/fixed/workflow_sca"))
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
tests = [
    "test/test_cloud_workflow.py", "test/test_cicd_workflow.py",
    "test/test_github_actions_security.py", "test/test_github_actions_finding_locations.py",
    "test/test_github_actions_yaml_source.py", "test/test_github_actions_runner_labels.py",
    "test/test_ai_pr_diff_rules.py", "test/test_sca_lockfiles.py",
    "test/test_sca_poetry_yarn.py", "test/test_sca_pipfile.py", "test/test_sca_pnpm.py",
    "test/test_sca_nuget.py", "test/test_sca_advisories.py", "test/test_sca_cache.py",
    "test/test_action_sca.py",
    "test/test_product_coverage_gates.py", "test/test_cli_sca_sarif.py",
]
cmd = [str(root / ".venv/bin/python"), "-m", "pytest", "-q", "-o", "addopts=", *tests]
result = subprocess.run(cmd, cwd=root, text=True, capture_output=True, timeout=300)
(out / "test-output.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
(out / "test-run.json").write_text(json.dumps({"command":cmd, "exit_code":result.returncode}, indent=2), encoding="utf-8")
print(result.stdout + result.stderr)
raise SystemExit(result.returncode)
