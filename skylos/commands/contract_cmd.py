from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from rich.console import Console

from skylos.contracts import (
    DEFAULT_CONTRACT_PATH,
    ContractError,
    contract_enables_dependency_hallucinations,
    contract_project_config_overrides,
    starter_contract_text,
    validate_contract_file,
)
from skylos.core.safe_cache_io import write_existing_text_no_symlink


def run_contract_command(argv, *, console_factory=Console) -> int:
    console = console_factory()
    parser = argparse.ArgumentParser(
        prog="skylos contract",
        description="Manage AI hallucination contracts for Skylos verify.",
    )
    sub = parser.add_subparsers(dest="contract_cmd")

    p_init = sub.add_parser("init", help="Create a starter AI contract")
    p_init.add_argument(
        "--path",
        default=DEFAULT_CONTRACT_PATH,
        help=f"Contract path. Default: {DEFAULT_CONTRACT_PATH}",
    )
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the contract if it already exists.",
    )

    p_validate = sub.add_parser("validate", help="Validate an AI contract")
    p_validate.add_argument(
        "path",
        nargs="?",
        default=DEFAULT_CONTRACT_PATH,
        help=f"Contract path. Default: {DEFAULT_CONTRACT_PATH}",
    )

    p_inspect = sub.add_parser(
        "inspect",
        aliases=["explain"],
        help="Explain an AI contract",
    )
    p_inspect.add_argument(
        "path",
        nargs="?",
        default=DEFAULT_CONTRACT_PATH,
        help=f"Contract path. Default: {DEFAULT_CONTRACT_PATH}",
    )
    p_inspect.add_argument(
        "--json",
        action="store_true",
        help="Print a machine-readable contract summary.",
    )

    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(list(argv))
    if args.contract_cmd == "init":
        return init_contract(console, args.path, force=bool(args.force))
    if args.contract_cmd == "validate":
        return validate_contract(console, args.path)
    if args.contract_cmd in {"inspect", "explain"}:
        return inspect_contract(console, args.path, output_json=bool(args.json))

    parser.print_help()
    return 0


def init_contract(console, path_str: str, *, force: bool = False) -> int:
    try:
        dest = _resolve_project_path(path_str)
        _write_contract_file(dest, starter_contract_text(), force=force)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1

    console.print(f"[green]Created AI contract: {dest}[/green]")
    console.print(f"[dim]Validate it with: skylos contract validate {dest}[/dim]")
    return 0


def validate_contract(console, path_str: str) -> int:
    try:
        contract = validate_contract_file(path_str, project_root=Path.cwd())
    except ContractError as exc:
        console.print(f"[red]Invalid contract:[/red] {exc}")
        return 1

    console.print(
        "[green]Valid AI contract[/green] "
        f"[dim](version {contract.version}, path {contract.path})[/dim]"
    )
    return 0


def inspect_contract(console, path_str: str, *, output_json: bool = False) -> int:
    try:
        contract = validate_contract_file(path_str, project_root=Path.cwd())
    except ContractError as exc:
        console.print(f"[red]Invalid contract:[/red] {exc}")
        return 1

    summary = _contract_summary(contract)
    if output_json:
        console.print(json.dumps(summary, indent=2), markup=False)
        return 0

    console.print(
        "[green]AI contract[/green] "
        f"[dim](version {contract.version}, path {contract.path})[/dim]"
    )
    if contract.contract_id:
        console.print(f"[dim]id:[/dim] {contract.contract_id}")
    console.print("[bold]Clauses[/bold]")
    for clause, detail in summary["clauses"].items():
        console.print(f"- {clause}: {_format_clause_detail(detail)}")
    console.print("[bold]Analyzer effects[/bold]")
    effects = summary["analyzer_effects"]
    dependency_status = (
        "enabled" if effects["dependency_hallucination_scan"] else "disabled"
    )
    console.print(f"- dependency hallucination scan: {dependency_status}")
    overrides = effects["project_config_overrides"]
    if overrides:
        console.print(
            f"- project config overrides: {json.dumps(overrides, sort_keys=True)}"
        )
    else:
        console.print("- project config overrides: none")
    return 0


def _resolve_project_path(path_str: str) -> Path:
    root = Path.cwd().resolve()
    candidate = Path(path_str).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate

    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("Contract path must stay inside the current project") from exc

    return resolved


def _write_contract_file(dest: Path, text: str, *, force: bool) -> None:
    if dest.is_symlink():
        raise ValueError("Contract path must not be a symlink")
    if dest.exists():
        if not force:
            raise ValueError(
                f"Contract already exists: {dest}. Use --force to overwrite."
            )
        if not write_existing_text_no_symlink(dest, text, encoding="utf-8"):
            raise ValueError(f"Could not safely overwrite contract: {dest}")
        return

    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_new_text_no_symlink(dest, text)


def _write_new_text_no_symlink(dest: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(dest, flags, 0o600)  # skylos: ignore[SKY-D215] path was resolved inside cwd and opened no-follow
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise ValueError(f"Could not safely create contract: {dest}") from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _contract_summary(contract) -> dict:
    return {
        "schema_version": contract.version,
        "id": contract.contract_id,
        "path": str(contract.path),
        "clauses": {
            "ai.phantom_symbols.names": {
                "enabled": bool(contract.ai.phantom_symbols.names),
                "values": list(contract.ai.phantom_symbols.names),
            },
            "ai.phantom_symbols.decorators": {
                "enabled": bool(contract.ai.phantom_symbols.decorators),
                "values": list(contract.ai.phantom_symbols.decorators),
            },
            "ai.dependencies.reject_nonexistent_packages": {
                "enabled": contract.ai.dependencies.reject_nonexistent_packages,
            },
            "ai.dependencies.reject_impossible_versions": {
                "enabled": contract.ai.dependencies.reject_impossible_versions,
            },
            "ai.api_surface.reject_unknown_members": {
                "enabled": contract.ai.api_surface.reject_unknown_members,
            },
            "ai.api_surface.reject_unknown_kwargs": {
                "enabled": contract.ai.api_surface.reject_unknown_kwargs,
            },
            "security.routes.paths": {
                "enabled": bool(contract.security.routes.paths),
                "values": list(contract.security.routes.paths),
            },
            "security.routes.require_any_decorator": {
                "enabled": bool(contract.security.routes.require_any_decorator),
                "values": list(contract.security.routes.require_any_decorator),
            },
            "tests.high_risk_changes_require_tests": {
                "enabled": contract.tests.high_risk_changes_require_tests,
            },
        },
        "analyzer_effects": {
            "dependency_hallucination_scan": contract_enables_dependency_hallucinations(
                contract
            ),
            "project_config_overrides": contract_project_config_overrides(contract),
        },
    }


def _format_clause_detail(detail: dict) -> str:
    if not detail["enabled"]:
        result = "disabled"
    else:
        values = detail.get("values")
        if not values:
            result = "enabled"
        else:
            result = ", ".join(str(value) for value in values)
    return result
