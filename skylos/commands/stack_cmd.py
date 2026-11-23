from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from skylos.cicd.stack import StackError, plan_stack, read_manifest, verify_stack


def run_stack_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="skylos stack", description="Check an existing stack in CI"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    plan = subcommands.add_parser(
        "plan", help="Freeze ordered Git layer tips and Done policy"
    )
    plan.add_argument(
        "--base", required=True, help="Approved common ancestor and Done policy source"
    )
    plan.add_argument(
        "--layer",
        action="append",
        required=True,
        help="Layer tip; repeat from lowest to highest",
    )
    plan.add_argument(
        "--original", help="Original unsplit revision for exact final-tree comparison"
    )
    verify = subcommands.add_parser(
        "verify", help="Check all layer receipts against the pinned stack"
    )
    verify.add_argument(
        "--manifest", type=Path, required=True, help="Trusted output of stack plan"
    )
    verify.add_argument(
        "--receipts-dir",
        type=Path,
        required=True,
        help="Directory of CI receipts named <commit>.json",
    )
    for sub in (plan, verify):
        sub.add_argument(
            "--path", type=Path, default=Path("."), help="Git repository (default: .)"
        )
        sub.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            output = plan_stack(
                args.path, args.base, args.layer, args.original
            ).manifest()
        else:
            stack = read_manifest(args.path, args.manifest)
            output = verify_stack(stack, args.receipts_dir)
    except (StackError, OSError, subprocess.SubprocessError) as exc:
        output = {"outcome": "ERROR", "message": str(exc)}
    status = output.get("outcome", "PLANNED")
    if args.format == "json":
        print(json.dumps(output, indent=2))
    elif status == "ERROR":
        print(f"ERROR: {output['message']}")
    else:
        print(f"{status}: {len(output['layers'])} layers, base {output['base']['sha']}")
        for layer in output["layers"]:
            print(
                f"  {layer['sha']}  {layer.get('reason', layer.get('status', 'pinned'))}"
            )
        if args.command == "verify":
            print(
                "Final tree matches original."
                if output["final_tree_matches_original"]
                else "No original supplied; final-tree equality was not checked."
            )
            print("Uses supplied CI receipts; runner identity is not authenticated.")
    return 2 if status == "ERROR" else 1 if status == "NOT_VERIFIED" else 0
