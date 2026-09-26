"""Export a local dependency inventory without running an advisory scan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.sbom import cyclonedx_bom
from skylos.reporting.spdx import spdx_document
from skylos.rules.sca.licenses import collect_licenses
from skylos.rules.sca.vulnerability_scanner import collect_dependencies


def run_sbom_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="skylos sbom",
        description=(
            "Export supported dependencies as CycloneDX or SPDX 2.3 JSON, "
            "offline by default. Declared licenses come from lockfiles and "
            "installed package metadata; unknown licenses are NOASSERTION."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="Project directory")
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Output file; '-' writes JSON to stdout (default)",
    )
    parser.add_argument(
        "--format",
        choices=["cyclonedx-json", "spdx-json"],
        default="cyclonedx-json",
        help="Output format (default: cyclonedx-json)",
    )
    parser.add_argument(
        "--license-lookup",
        action="store_true",
        help=(
            "Also query deps.dev over the network for licenses missing from "
            "local metadata (off by default; 5s timeout per package)"
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit 2 when the inventory is incomplete (for example unpinned "
            "requirements.txt without a lockfile). By default the SBOM is still "
            "written, a warning is printed and the exit code is 0."
        ),
    )
    args = parser.parse_args(argv)
    try:
        root = Path(args.path).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("not a directory")
    except (OSError, RuntimeError, ValueError):
        print(
            "SBOM error: path must be an existing project directory.", file=sys.stderr
        )
        return 2

    if args.output != "-" and (
        Path(args.output).name.casefold()
        in {
            "requirements.txt",
            "pyproject.toml",
            "package.json",
            "go.mod",
            "uv.lock",
            "package-lock.json",
            "pnpm-lock.yaml",
            "poetry.lock",
            "yarn.lock",
            "pipfile.lock",
            "npm-shrinkwrap.json",
        }
        or Path(args.output).suffix.casefold() == ".csproj"
    ):
        print(
            "SBOM error: output must not overwrite a dependency input.", file=sys.stderr
        )
        return 2

    inventory = collect_dependencies(root)
    licenses = collect_licenses(inventory, root, lookup=args.license_lookup)
    if args.format == "spdx-json":
        document = spdx_document(inventory, root, licenses)
    else:
        document = cyclonedx_bom(inventory, root, licenses)
    text = json.dumps(document, indent=2, ensure_ascii=True) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    elif not write_text_no_symlink(args.output, text):
        print("SBOM error: could not safely write output file.", file=sys.stderr)
        return 2

    if not document.receipt["complete"]:
        where = (
            "creationInfo.comment"
            if args.format == "spdx-json"
            else "metadata.properties skylos:inventory:receipt"
        )
        print(
            "SBOM incomplete: available packages were exported; see "
            f"{where} for input gaps.",
            file=sys.stderr,
        )
        if args.strict:
            return 2
    return 0
