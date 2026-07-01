from __future__ import annotations

import argparse
import os
from pathlib import Path

from rich.console import Console

from skylos.contracts import (
    DEFAULT_CONTRACT_PATH,
    ContractError,
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

    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(list(argv))
    if args.contract_cmd == "init":
        return init_contract(console, args.path, force=bool(args.force))
    if args.contract_cmd == "validate":
        return validate_contract(console, args.path)

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
