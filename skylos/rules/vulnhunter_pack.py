"""Run the bundled static rules using a locally installed Semgrep CLI."""

import json
import shutil
import subprocess
import sys
from importlib import resources
from pathlib import Path
from tempfile import TemporaryDirectory


def run_pack(target: Path, output_format: str) -> int:
    if not target.exists():
        print(f"Source path does not exist: {target}", file=sys.stderr)
        return 2
    binary = shutil.which("semgrep")
    if not binary:
        print(
            "Install the Semgrep CLI to use the VulnHunter rule pack.", file=sys.stderr
        )
        return 2
    pack = resources.files("skylos.rules").joinpath("packs", "vulnhunter.yml")
    with (
        resources.as_file(pack) as config,
        TemporaryDirectory(prefix="skylos-vulnhunter-") as directory,
    ):
        status_report = Path(directory) / "status.json"
        command = [
            binary,
            "scan",
            "--config",
            str(config),
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--strict",
            "--error",
            "--json-output",
            str(status_report),
        ]
        if output_format != "text":
            command.append(f"--{output_format}")
        command.append(str(target.resolve()))
        try:
            status = subprocess.run(command, check=False).returncode
        except OSError as error:
            print(f"Could not launch Semgrep: {error}", file=sys.stderr)
            return 2
        if status not in {0, 1}:
            return status
        # A run with findings can also time out or fail to parse a file.
        # Semgrep may return 1 for that combination even with --strict.
        try:
            report = json.loads(status_report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = None
        if (
            not isinstance(report, dict)
            or not isinstance(report.get("errors"), list)
            or not isinstance(report.get("results"), list)
        ):
            print("Semgrep did not produce a readable scan status report.", file=sys.stderr)
            return 2
        if report["errors"]:
            print(
                f"VulnHunter rule pack scan incomplete ({len(report['errors'])} Semgrep errors).",
                file=sys.stderr,
            )
            return 2
        if status == 1 and not report["results"]:
            print("Semgrep exited without producing findings.", file=sys.stderr)
            return 2
        return status
