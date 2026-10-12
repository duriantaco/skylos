"""Exercise actual Skylos CLI/analyzer and sync writers without external services.

Run with the Skylos venv Python. All fixtures stay in --output.
Cloud interactions are mocked; findings come from the real static analyzer.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", "--out", dest="out", type=Path, default=Path("/private/tmp/skylos-product-audit/fixed/cloud"))
    options = parser.parse_args()
    options.out.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parent.parent
    if not (root / "skylos" / "cli.py").is_file():
        parser.error("This script must be located under the Skylos checkout's scripts directory")
    sys.path.insert(0, str(root))
    from skylos import cli
    from skylos.cloud import sync
    from skylos.core import review_decisions

    results = {}
    fixture_root = Path(tempfile.mkdtemp(prefix="fixtures-", dir=options.out))
    home = fixture_root / "isolated-user-state"
    home.mkdir()
    blocked_network_attempts = []

    def make_repo(name: str) -> Path:
        repo = fixture_root / name
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/audit/synthetic.git"], check=True)
        (repo / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        return repo

    def deny_network(*_args, **_kwargs):
        blocked_network_attempts.append("unexpected network attempt")
        raise AssertionError("This script must never reach a real network endpoint")

    clean_env = {"PATH": os.environ.get("PATH", ""), "SKYLOS_TOKEN": "AUDIT_TEST_TOKEN", "SKYLOS_UPLOAD_CONTRACT_CHECK": "0"}
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, clean_env, clear=True))
        stack.enter_context(patch.object(sync, "GLOBAL_CREDS_DIR", home))
        stack.enter_context(patch.object(sync, "GLOBAL_CREDS_FILE", home / "credentials.json"))
        stack.enter_context(patch("requests.get", side_effect=deny_network))
        stack.enter_context(patch("requests.post", side_effect=deny_network))
        stack.enter_context(patch("requests.put", side_effect=deny_network))
        stack.enter_context(patch("socket.socket.connect", side_effect=deny_network))
        stack.enter_context(patch("skylos.analysis.file_processing.load_community_rules", return_value=[]))

        # 1: Identical source, options, Cloud rule, and analyzer; only renderer differs.
        repo = make_repo("format-parity")
        (repo / "app.py").write_text("@route\ndef handler():\n    return 'ok'\n", encoding="utf-8")
        cloud_rule = {"rule_id": "CUSTOM-AUTH-001", "name": "Route requires auth", "rule_type": "yaml", "severity": "HIGH", "enabled": True, "yaml_config": {"pattern": {"type": "function", "decorators": {"has_any": ["route"], "must_also_have_any": ["auth"]}}, "message": "Route is missing required auth decorator"}}
        formats = {}
        for output_format in ("pretty", "json", "json-ci", "concise", "github"):
            calls = []
            analyzed = []
            original_analyze = cli.run_analyze

            def capture_analyze(*args, **kwargs):
                calls.append({"custom_rule_count_supplied_to_analyzer": len(kwargs.get("custom_rules_data") or [])})
                result = original_analyze(*args, **kwargs)
                analyzed.append(json.loads(result) if isinstance(result, str) else result)
                return result

            def fake_api(endpoint, token):
                calls.append({"api_endpoint": endpoint})
                if endpoint == "/api/sync/rules":
                    return {"rules": [cloud_rule]}
                raise AssertionError(f"Unexpected mocked endpoint: {endpoint}")

            argv = ["skylos", str(repo), "--quality", "--gate", "--strict", "--no-upload", "--no-clipboard", "--no-grep-verify", "--format", output_format]
            stdout, stderr = io.StringIO(), io.StringIO()
            code = 0
            with patch.object(sys, "argv", argv), patch.object(sync, "api_get", side_effect=fake_api), patch.object(sync, "_find_repo_root", return_value=repo), patch.object(cli, "run_analyze", side_effect=capture_analyze), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    cli.main()
                except SystemExit as exc:
                    code = exc.code
            final = analyzed[-1] if analyzed else {}
            hits = [finding for key, items in final.items() if isinstance(items, list) for finding in items if isinstance(finding, dict) and finding.get("rule_id") == cloud_rule["rule_id"]]
            formats[output_format] = {"exit_code": code, "calls": calls, "custom_rule_finding_count": len(hits), "findings": hits}
            (options.out / f"format-{output_format}.stdout.txt").write_text(stdout.getvalue(), encoding="utf-8")
            (options.out / f"format-{output_format}.stderr.txt").write_text(stderr.getvalue(), encoding="utf-8")
            (options.out / f"format-{output_format}.analysis.json").write_text(json.dumps(final, indent=2, default=str), encoding="utf-8")
        results["format_parity"] = {"expected": "Output format changes only presentation, not custom-rule execution", "actual": formats}
        for output_format in formats:
            assert formats[output_format]["custom_rule_finding_count"] == 1, f"{output_format} must retain the Cloud-rule finding"
            assert formats[output_format]["exit_code"] == 1, f"{output_format} must enforce the same strict gate"

        # 1b: Scan uploads do not consume credits; both renderers must deliver.
        repo = make_repo("zero-credit-upload")
        (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
        sync._write_link(repo, "project-a", project_name="Fixture", base_url=sync.DEFAULT_API_URL)
        zero_credit_formats = {}
        for output_format in ("rich", "json"):
            uploads = []
            balances = []

            def capture_upload(*args, **kwargs):
                uploads.append({"quiet": kwargs.get("quiet", False)})
                return {"success": True, "scan_id": "audit-scan", "quality_gate_passed": True}

            def zero_credit_balance(*args, **kwargs):
                balances.append("balance requested")
                return {"plan": "free", "balance": 0}

            stdout, stderr = io.StringIO(), io.StringIO()
            argv = ["skylos", str(repo), "--upload", "--no-clipboard", "--no-grep-verify", "--format", output_format]
            code = 0
            with patch.object(sys, "argv", argv), patch.object(sync, "_find_repo_root", return_value=repo), patch.object(sync, "api_get", return_value={"rules": []}), patch("skylos.api.get_project_token", return_value="AUDIT_TEST_TOKEN"), patch("skylos.api.get_credit_balance", side_effect=zero_credit_balance), patch.object(cli, "upload_report", side_effect=capture_upload), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    cli.main()
                except SystemExit as exc:
                    code = exc.code
            zero_credit_formats[output_format] = {"exit_code": code, "upload_call_count": len(uploads), "balance_call_count": len(balances), "upload_skipped_message": "0 credits remaining" in stdout.getvalue()}
            if output_format == "json":
                zero_credit_formats[output_format]["receipt"] = json.loads(stdout.getvalue()).get("upload")
            (options.out / f"zero-credit-{output_format}.stdout.txt").write_text(stdout.getvalue(), encoding="utf-8")
            (options.out / f"zero-credit-{output_format}.stderr.txt").write_text(stderr.getvalue(), encoding="utf-8")
        results["zero_credit_upload"] = {"expected": "Scan uploads never require credits per current Cloud contract", "actual": zero_credit_formats}
        for output_format in zero_credit_formats:
            assert zero_credit_formats[output_format]["exit_code"] == 0, f"{output_format} upload must succeed"
            assert zero_credit_formats[output_format]["upload_call_count"] == 1, f"{output_format} upload must reach mocked transport"
            assert zero_credit_formats[output_format]["balance_call_count"] == 0, f"{output_format} must not preflight upload credits"
            assert not zero_credit_formats[output_format]["upload_skipped_message"], f"{output_format} must not skip upload based on credits"
        receipt = zero_credit_formats["json"]["receipt"]
        assert receipt["status"] == "uploaded" and receipt["scan_id"] == "audit-scan"
        assert receipt["quality_gate"]["passed"] is True

        # 2: Suppression fetch failure leaves both repository files unchanged.
        repo = make_repo("partial-sync")
        state = repo / ".skylos"
        state.mkdir()
        (state / "config.yaml").write_text("complexity: 10\n", encoding="utf-8")
        old_bundle = {"schema": "skylos.reviewed-findings", "version": 2, "project_id": "project-a", "count": 0, "decisions": [], "audit_marker": "old"}
        (state / "suppressions.json").write_text(json.dumps(old_bundle), encoding="utf-8")
        trusted = review_decisions.write_trusted_bundle(repo, old_bundle, cache_root=home / "reviewed-findings")
        if trusted is None:
            raise AssertionError("Fixture must create prior trusted state")

        def failed_api(endpoint, token):
            if endpoint == sync.WHOAMI_ENDPOINT:
                return {"project": {"id": "project-a", "name": "Fixture"}}
            if endpoint == "/api/sync/config":
                return {"config": {"complexity": 20, "security_enabled": True}}
            if endpoint == "/api/sync/suppressions":
                raise sync.AuthError("Injected suppression endpoint outage")
            raise AssertionError(endpoint)

        stdout = io.StringIO()
        code = 0
        with patch.object(sync, "api_get", side_effect=failed_api), patch.object(sync, "_find_repo_root", return_value=repo), patch.object(sync, "_current_repo_subpath", return_value=""), contextlib.redirect_stdout(stdout):
            try:
                sync.main(["pull"])
            except SystemExit as exc:
                code = exc.code
        results["partial_sync"] = {"expected": "A failed pull does not partially activate its new configuration", "actual": {"exit_code": code, "config": (state / "config.yaml").read_text(), "suppression_audit_marker": json.loads((state / "suppressions.json").read_text())["audit_marker"], "prior_trusted_bundle_still_exists": trusted.exists(), "stdout": stdout.getvalue()}}
        assert code == 1, "Injected suppression outage must fail the pull"
        assert results["partial_sync"]["actual"]["config"] == "complexity: 10\n", "Failed pull must preserve the previous config"
        assert results["partial_sync"]["actual"]["suppression_audit_marker"] == "old", "Failed pull must retain old repo suppression JSON"
        assert not trusted.exists(), "Failed pull must reproduce conservative prior-cache invalidation"

        # 3: Supported dry-run and JSON flags validate without mutating files.
        repo = make_repo("ignored-flags")

        def healthy_api(endpoint, token):
            if endpoint == sync.WHOAMI_ENDPOINT:
                return {"project": {"id": "project-a", "name": "Fixture"}}
            if endpoint == "/api/sync/config":
                return {"config": {"complexity": 20}}
            if endpoint == "/api/sync/suppressions":
                return {"project_id": "project-a", "decisions": [], "count": 0}
            raise AssertionError(endpoint)

        stdout = io.StringIO()
        with patch.object(sync, "api_get", side_effect=healthy_api), patch.object(sync, "_find_repo_root", return_value=repo), patch.object(sync, "_current_repo_subpath", return_value=""), contextlib.redirect_stdout(stdout):
            sync.main(["pull", "--dry-run", "--format", "json"])
        results["dry_run"] = {"expected": "Honor dry-run with no mutations and one JSON response", "actual": {"config_written": (repo / ".skylos/config.yaml").exists(), "suppressions_written": (repo / ".skylos/suppressions.json").exists(), "stdout_is_json": _is_json(stdout.getvalue()), "stdout": stdout.getvalue()}}
        assert not results["dry_run"]["actual"]["config_written"], "Dry-run must not mutate configuration"
        assert not results["dry_run"]["actual"]["suppressions_written"], "Dry-run must not mutate suppression files"
        assert results["dry_run"]["actual"]["stdout_is_json"], "JSON output must be one parseable response"
        assert json.loads(stdout.getvalue())["status"] == "validated"

        # Unknown flags are rejected before any request or filesystem mutation.
        stderr = io.StringIO()
        with patch.object(sync, "api_get", side_effect=AssertionError("API called for invalid arguments")), contextlib.redirect_stderr(stderr):
            try:
                sync.main(["pull", "--unknown-audit-flag"])
            except SystemExit as exc:
                unknown_exit = exc.code
            else:
                raise AssertionError("Unknown sync flag was accepted")
        results["unknown_flags"] = {"exit_code": unknown_exit, "stderr": stderr.getvalue(), "skylos_directory_created": (repo / ".skylos").exists()}
        assert unknown_exit == 2
        assert not (repo / ".skylos").exists()

        # 4: Temp-only symlink attack through production cmd_pull path.
        repo = make_repo("config-symlink")
        state = repo / ".skylos"
        state.mkdir()
        outside = fixture_root / "outside-config-sentinel.txt"
        outside.write_text("DO NOT OVERWRITE\n", encoding="utf-8")
        (state / "config.yaml").symlink_to(outside)
        stdout = io.StringIO()
        code = 0
        with patch.object(sync, "api_get", side_effect=healthy_api), patch.object(sync, "_find_repo_root", return_value=repo), patch.object(sync, "_current_repo_subpath", return_value=""), contextlib.redirect_stdout(stdout):
            try:
                sync.main(["pull"])
            except SystemExit as exc:
                code = exc.code
        results["config_symlink"] = {"expected": "Reject symlinked config like symlinked link files; leave sentinel intact", "actual": {"exit_code": code, "target_outside_fixture_repo": str(outside), "sentinel_after": outside.read_text(), "symlink_still_exists": (state / "config.yaml").is_symlink(), "stdout": stdout.getvalue()}}
        assert code == 1, "Symlinked configuration must fail the pull"
        assert outside.read_text() == "DO NOT OVERWRITE\n", "Config symlink target must remain unchanged"
        assert (state / "config.yaml").is_symlink(), "Refusal must leave the existing symlink intact"

    assert not blocked_network_attempts, "A production path attempted network access outside the mocked Cloud interactions"
    results["evidence_summary"] = {
        "asserted_scenario_groups": 6,
        "full_cli_scan_runs": 7,
        "output_formats_compared": 5,
        "unmocked_network_attempts": len(blocked_network_attempts),
        "production_source_mutated_by_harness": False,
        "assertions_describe": "Desired enforcement behavior; Cloud responses and upload transport are explicitly mocked",
        "sync_consistency_scope": "Caught failures preserve files; this does not prove crash-atomic multi-file activation",
    }

    (options.out / "results.json").write_text(json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2, default=str))


def _is_json(value: str) -> bool:
    try:
        json.loads(value)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    main()
