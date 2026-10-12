#!/usr/bin/env python3
"""Reproduce local scan capabilities and changed-line reporting boundaries.

Runs the real CLI on generated fixtures without executing their source. Network
connections are denied. JSON reports and fixture repositories remain in the
requested output directory for inspection. This is an audit, not a speed or
competitor accuracy benchmark.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from skylos import cli  # noqa: E402


def run_cli(root: Path, *options: str) -> dict:
    stdout, stderr = io.StringIO(), io.StringIO()
    connections: list[str] = []
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SKYLOS_")
        and not key.endswith("API_KEY")
        and key != "TYPESAFE_API_KEY"
    }
    environment.update(CI="true", SKYLOS_NO_CLIPBOARD="1", SKYLOS_JOBS="1")
    arguments = [
        "skylos", str(root), "--format", "json", "--no-upload",
        "--no-provenance", "--no-grep-verify", *options,
    ]

    def deny_connection(_socket, address):
        connections.append(str(address))
        raise RuntimeError("Audit denies network connections")

    started = time.perf_counter()
    exit_code = 0
    old_cwd = Path.cwd()
    try:
        os.chdir(root)
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(sys, "argv", arguments),
            patch.object(socket.socket, "connect", deny_connection),
            redirect_stdout(stdout), redirect_stderr(stderr),
        ):
            try:
                cli.main()
            except SystemExit as exc:
                exit_code = int(exc.code or 0)
    finally:
        os.chdir(old_cwd)
    payload = json.loads(stdout.getvalue())
    return {
        "argv": arguments, "exit_code": exit_code,
        "elapsed_seconds": round(time.perf_counter() - started, 4),
        "network_attempts": connections, "stderr": stderr.getvalue(),
        "report": payload,
    }


def git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=Skylos Audit", "-c",
         "user.email=audit@example.invalid", *arguments],
        cwd=root, check=True, capture_output=True, text=True,
    )


def names(run: dict) -> list[str]:
    return sorted(item["name"] for item in run["report"].get("unused_functions", []))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path("/private/tmp/skylos-product-audit/fixed/scan"))
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    logging.getLogger("Skylos").setLevel(logging.ERROR)

    static_root = output / "static_fixture"
    static_root.mkdir(exist_ok=True)
    (static_root / "app.py").write_text(
        "def active():\n    return 1\n\n"
        "def unused():\n    return 2\n\n"
        "result = active()\n"
        "raise RuntimeError('AUDIT_TARGET_MUST_NOT_EXECUTE')\n",
        encoding="utf-8",
    )
    static = run_cli(static_root)
    static_names = names(static)
    assert "unused" in static_names and "active" not in static_names
    assert static["network_attempts"] == []
    unused = next(item for item in static["report"]["unused_functions"]
                  if item["name"] == "unused")
    assert unused["dead_code_classification"] == "likely_dead"
    assert unused.get("dead_code_evidence")
    assert not static["report"].get("analysis_errors")
    (output / "static_scan.json").write_text(json.dumps(static, indent=2) + "\n")

    # Synthetic credential from the scanner's own test corpus, never a live key.
    categories_root = output / "category_fixture"
    categories_root.mkdir(exist_ok=True)
    (categories_root / "app.py").write_text(
        "import os\nimport time\n"
        "AWS_ACCESS_KEY_ID = 'AKIAABCDEFGHIJKLMNOP'\n\n"
        "def shell(command):\n    return os.system(command)\n\n"
        "async def block():\n    time.sleep(1)\n\n"
        "print(shell, block)\n"
        "raise RuntimeError('AUDIT_TARGET_MUST_NOT_EXECUTE')\n",
        encoding="utf-8",
    )
    categories = run_cli(categories_root, "--danger", "--secrets", "--quality")
    category_rule_ids = {
        category: sorted({item["rule_id"] for item in
                          categories["report"].get(category, [])})
        for category in ("danger", "secrets", "quality")
    }
    assert "SKY-S101" in category_rule_ids["secrets"]
    assert "SKY-Q401" in category_rule_ids["quality"]
    assert "SKY-D203" in category_rule_ids["danger"]
    assert not categories["network_attempts"]
    assert not categories["report"].get("analysis_errors")
    (output / "category_scan.json").write_text(
        json.dumps(categories, indent=2) + "\n"
    )

    # A new fixture avoids depending on any previous audit invocation's HEAD.
    import tempfile
    diff_root = Path(tempfile.mkdtemp(prefix="diff_fixture_", dir=output))
    source = diff_root / "app.py"
    source.write_text("def legacy():\n    return 7\n\nlegacy()\n")
    git(diff_root, "init", "-q")
    git(diff_root, "add", "app.py")
    git(diff_root, "commit", "-q", "-m", "Audit baseline")
    before = run_cli(diff_root, "--strict")
    assert "legacy" not in names(before)
    source.write_text("def legacy():\n    return 7\n\nprint('done')\n")
    full = run_cli(diff_root, "--strict")
    diff = run_cli(diff_root, "--strict", "--diff", "HEAD")
    impact = run_cli(diff_root, "--strict", "--diff", "HEAD", "--diff-mode", "impact")
    assert "legacy" in names(full)
    assert "legacy" not in names(diff)
    assert full["exit_code"] == 1 and diff["exit_code"] == 0
    assert impact["exit_code"] == 1 and "legacy" in names(impact)
    assert impact["report"]["analysis_summary"]["pr_impact"]["status"] == "complete"
    assert next(item for item in impact["report"]["unused_functions"]
                if item["name"] == "legacy")["change_status"] == "introduced"
    assert not full["network_attempts"] and not diff["network_attempts"]
    (output / "diff_scan.json").write_text(
        json.dumps({"fixture": str(diff_root), "before": before,
                    "after_full": full, "after_changed_lines": diff,
                    "after_impact": impact}, indent=2) + "\n"
    )
    evidence = {
        "source_checkout": str(REPO_ROOT),
        "static_capability": {
            "unused_reported": "unused" in static_names,
            "active_reported": "active" in static_names,
            "classification": unused["dead_code_classification"],
            "reason_tags": unused.get("dead_code_reason_tags"),
            "network_attempts": static["network_attempts"],
            "target_top_level_raise_was_not_executed": True,
        },
        "changed_line_boundary": {
            "baseline_unused_functions": names(before),
            "after_full_unused_functions": names(full),
            "after_diff_unused_functions": names(diff),
            "full_strict_exit": full["exit_code"],
            "diff_strict_exit": diff["exit_code"],
            "after_impact_unused_functions": names(impact),
            "impact_strict_exit": impact["exit_code"],
            "interpretation": "Default changed-line reporting preserves its scope; "
                              "impact mode compares with raw base Git objects and "
                              "retains newly unused definitions outside changed lines.",
        },
        "category_capability": {
            "rule_ids": category_rule_ids,
            "network_attempts": categories["network_attempts"],
            "target_top_level_raise_was_not_executed": True,
            "credential_scope": "Synthetic fixture, not a live credential",
        },
        "artifacts": [str(output / "static_scan.json"),
                      str(output / "category_scan.json"),
                      str(output / "diff_scan.json")],
    }
    (output / "summary.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
