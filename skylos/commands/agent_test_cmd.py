from __future__ import annotations

import json
import os
import stat
from io import StringIO
from pathlib import Path
from typing import Any
from uuid import uuid4

from rich.console import Console
from rich.table import Table

from skylos.agents.evaluation import (
    BEHAVIOR_RESULT_VERSION,
    DEFAULT_BEHAVIOR_CONTRACT_PATH,
    AgentBehaviorError,
    discover_behavior_contract,
    load_behavior_contract,
    load_behavior_observations,
    starter_behavior_contract_text,
)
from skylos.agents.evaluation.runner import (
    DEFAULT_MAX_SCENARIOS,
    DEFAULT_MAX_SECONDS,
    DEFAULT_MAX_TOKENS,
    run_behavior_test,
)
from skylos.core.safe_cache_io import write_existing_text_no_symlink


def add_agent_test_parsers(agent_sub) -> None:
    init_parser = agent_sub.add_parser(
        "init",
        help="Create a starter runtime agent behavior contract",
    )
    init_parser.add_argument(
        "--path",
        default=DEFAULT_BEHAVIOR_CONTRACT_PATH,
        help=f"Contract path. Default: {DEFAULT_BEHAVIOR_CONTRACT_PATH}",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Safely overwrite an existing regular contract file",
    )

    test_parser = agent_sub.add_parser(
        "test",
        help="Test runtime agent behavior against a deterministic contract",
    )
    test_parser.add_argument(
        "contract",
        nargs="?",
        default=None,
        help=(
            "Behavior contract path. Defaults to auto-discovering "
            f"{DEFAULT_BEHAVIOR_CONTRACT_PATH}."
        ),
    )
    test_parser.add_argument(
        "--observations",
        default=None,
        help=("Evaluate an unverified normalized JSON fixture without network calls"),
    )
    test_parser.add_argument(
        "--endpoint",
        default=None,
        help="Trusted agent.endpoint override for this run",
    )
    test_parser.add_argument(
        "--auth-env",
        default=None,
        help=("Environment variable containing a bearer token; requires --endpoint"),
    )
    test_parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow a non-loopback HTTPS --endpoint override",
    )
    test_parser.add_argument(
        "--allow-contract-endpoint",
        action="store_true",
        help="Explicitly allow the contract's unauthenticated loopback endpoint",
    )
    test_parser.add_argument(
        "--scenario",
        action="append",
        dest="scenarios",
        help="Run one scenario id; repeat to select multiple scenarios",
    )
    test_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Result output format",
    )
    test_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write the selected output format to a project-local file",
    )
    test_parser.add_argument(
        "--no-artifacts",
        action="store_true",
        help="Do not save local harness and behavior evidence artifacts",
    )
    test_parser.add_argument(
        "--max-scenarios",
        type=int,
        default=DEFAULT_MAX_SCENARIOS,
        help=f"Maximum scenarios per run. Default: {DEFAULT_MAX_SCENARIOS}",
    )
    test_parser.add_argument(
        "--max-seconds",
        type=float,
        default=DEFAULT_MAX_SECONDS,
        help=f"Maximum run time in seconds. Default: {int(DEFAULT_MAX_SECONDS)}",
    )
    test_parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help=f"Requested endpoint response-token cap. Default: {DEFAULT_MAX_TOKENS}",
    )


def run_agent_behavior_init(args, console: Console) -> int:
    try:
        root = Path.cwd().resolve(strict=True)
        destination = _resolve_project_output(args.path, root)
        _write_starter_contract(
            destination,
            starter_behavior_contract_text(),
            force=bool(args.force),
            project_root=root,
        )
    except (AgentBehaviorError, OSError) as exc:
        console.print(f"[red]Could not create agent behavior contract:[/red] {exc}")
        return 2

    console.print(f"[green]Created agent behavior contract:[/green] {destination}")
    console.print("[dim]Run it with: skylos agent test --allow-contract-endpoint[/dim]")
    return 0


def run_agent_behavior_test(args, console: Console) -> int:
    project_root = Path.cwd().resolve(strict=False)
    try:
        contract_path, project_root = _resolve_contract_argument(args.contract)
        contract = load_behavior_contract(
            contract_path,
            project_root=project_root,
        )
        observations = None
        if args.observations:
            observations = load_behavior_observations(
                args.observations,
                project_root=project_root,
            )
        result = run_behavior_test(
            contract,
            observations=observations,
            scenario_ids=_scenario_selection(args.scenarios),
            endpoint_override=args.endpoint,
            auth_env=args.auth_env,
            allow_remote=bool(args.allow_remote),
            allow_contract_endpoint=bool(
                getattr(args, "allow_contract_endpoint", False)
            ),
            save_artifacts=not bool(args.no_artifacts),
            max_scenarios=getattr(args, "max_scenarios", DEFAULT_MAX_SCENARIOS),
            max_seconds=getattr(args, "max_seconds", DEFAULT_MAX_SECONDS),
            max_tokens=getattr(args, "max_tokens", DEFAULT_MAX_TOKENS),
        )
        output = _render_behavior_output(result.payload, args.format)
        if args.output:
            destination = _resolve_project_output(args.output, project_root)
            _write_user_output(destination, output, project_root=project_root)
            if args.format == "table":
                console.print(
                    f"[green]Wrote agent behavior report:[/green] {destination}"
                )
        else:
            if args.format == "json":
                console.file.write(output + "\n")
                console.file.flush()
            else:
                console.print(output, markup=False)
    except (AgentBehaviorError, OSError, ValueError) as exc:
        if getattr(args, "format", None) == "json":
            payload = {
                "schema_version": BEHAVIOR_RESULT_VERSION,
                "kind": "agent_behavior",
                "status": "incomplete",
                "error": str(exc),
            }
            rendered = json.dumps(payload, indent=2, sort_keys=True)
            if getattr(args, "output", None):
                try:
                    destination = _resolve_project_output(args.output, project_root)
                    _write_user_output(
                        destination,
                        rendered,
                        project_root=project_root,
                    )
                except (AgentBehaviorError, OSError, ValueError) as output_exc:
                    payload["output_error"] = str(output_exc)
                    console.file.write(
                        json.dumps(payload, indent=2, sort_keys=True) + "\n"
                    )
                    console.file.flush()
            else:
                console.file.write(rendered + "\n")
                console.file.flush()
            return 2
        message = f"Agent behavior test incomplete: {exc}"
        if getattr(args, "output", None):
            try:
                destination = _resolve_project_output(args.output, project_root)
                _write_user_output(
                    destination,
                    message,
                    project_root=project_root,
                )
            except (AgentBehaviorError, OSError, ValueError):
                console.print(f"[red]Agent behavior test incomplete:[/red] {exc}")
        else:
            console.print(f"[red]Agent behavior test incomplete:[/red] {exc}")
        return 2

    return _behavior_exit_code(result.payload)


def _resolve_contract_argument(contract_arg: str | None) -> tuple[Path, Path]:
    current = Path.cwd().resolve(strict=True)
    if contract_arg is not None:
        return Path(contract_arg), current
    discovered = discover_behavior_contract(current)
    if discovered is None:
        raise AgentBehaviorError(
            f"No {DEFAULT_BEHAVIOR_CONTRACT_PATH} found; run skylos agent init"
        )
    project_root = (
        discovered.parent.parent if discovered.parent.name == ".skylos" else current
    )
    return discovered, project_root


def _scenario_selection(values: list[str] | None) -> tuple[str, ...] | None:
    if not values:
        return None
    selected = tuple(dict.fromkeys(value.strip() for value in values if value.strip()))
    if not selected:
        raise AgentBehaviorError("--scenario requires a non-empty scenario id")
    return selected


def _resolve_project_output(path_value: str, project_root: Path) -> Path:
    root = project_root.resolve(strict=True)
    candidate = Path(path_value).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise AgentBehaviorError("output path must stay inside the project") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise AgentBehaviorError("output path must stay inside the project")
    return root.joinpath(*relative.parts)


def _write_starter_contract(
    destination: Path,
    text: str,
    *,
    force: bool,
    project_root: Path,
) -> None:
    try:
        _write_project_text(
            project_root,
            destination,
            text,
            overwrite=force,
        )
    except FileExistsError as exc:
        raise AgentBehaviorError(
            f"contract already exists: {destination}; use --force to overwrite"
        ) from exc


def _write_user_output(
    destination: Path,
    text: str,
    *,
    project_root: Path,
) -> None:
    _write_project_text(
        project_root,
        destination,
        text.rstrip() + "\n",
        overwrite=True,
    )


def _write_project_text(
    project_root: Path,
    destination: Path,
    text: str,
    *,
    overwrite: bool,
) -> None:
    if os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
        _write_project_text_fallback(
            project_root,
            destination,
            text,
            overwrite=overwrite,
        )
        return

    parent_fd: int | None = None
    try:
        parent_fd, final_name = _open_project_parent(
            project_root,
            destination,
        )
        if overwrite:
            _replace_text_at(parent_fd, final_name, text)
        else:
            _create_text_at(parent_fd, final_name, text)
    except FileExistsError:
        raise
    except (OSError, UnicodeError, TypeError, NotImplementedError) as exc:
        raise AgentBehaviorError(f"could not safely write {destination}") from exc
    finally:
        _close_fd(parent_fd)


def _open_project_parent(project_root: Path, destination: Path) -> tuple[int, str]:
    root = project_root.resolve(strict=True)
    relative = destination.relative_to(root)
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise OSError("unsafe output path")
    directory_fd = os.open(  # skylos: ignore[SKY-D215] trusted resolved project root
        root,
        _directory_flags(follow_symlinks=True),
    )
    try:
        for part in relative.parts[:-1]:
            try:
                os.mkdir(  # skylos: ignore[SKY-D215] dir_fd component rejects separators and dotdot
                    part,
                    mode=0o700,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                pass
            next_fd = os.open(  # skylos: ignore[SKY-D215] dir_fd component opened with O_NOFOLLOW
                part,
                _directory_flags(),
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd, relative.parts[-1]
    except Exception:
        _close_fd(directory_fd)
        raise


def _create_text_at(parent_fd: int, final_name: str, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    file_descriptor: int | None = None
    try:
        file_descriptor = os.open(  # skylos: ignore[SKY-D215] project-contained path is created exclusively with no-follow
            final_name,
            flags,
            0o600,
            dir_fd=parent_fd,
        )
        owned_descriptor = file_descriptor
        file_descriptor = None
        _write_text_fd(owned_descriptor, text)
    finally:
        _close_fd(file_descriptor)


def _replace_text_at(parent_fd: int, final_name: str, text: str) -> None:
    _reject_unsafe_existing_output(parent_fd, final_name)
    temp_name = f".{final_name}.{uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    file_descriptor: int | None = None
    try:
        file_descriptor = os.open(  # skylos: ignore[SKY-D215] random dir_fd temp name with O_EXCL and O_NOFOLLOW
            temp_name,
            flags,
            0o600,
            dir_fd=parent_fd,
        )
        owned_descriptor = file_descriptor
        file_descriptor = None
        _write_text_fd(owned_descriptor, text)
        _reject_unsafe_existing_output(parent_fd, final_name)
        os.replace(
            temp_name,
            final_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
    finally:
        _close_fd(file_descriptor)
        try:
            os.unlink(  # skylos: ignore[SKY-D215] random dir_fd temp cleanup
                temp_name,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            pass


def _reject_unsafe_existing_output(parent_fd: int, final_name: str) -> None:
    try:
        metadata = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("output destination is not a regular file")


def _write_text_fd(file_descriptor: int, text: str) -> None:
    with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def _directory_flags(*, follow_symlinks: bool = False) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if not follow_symlinks and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _close_fd(file_descriptor: int | None) -> None:
    if file_descriptor is None:
        return
    try:
        os.close(file_descriptor)
    except OSError:
        pass


def _write_project_text_fallback(
    project_root: Path,
    destination: Path,
    text: str,
    *,
    overwrite: bool,
) -> None:
    current = project_root.resolve(strict=True)
    relative = destination.relative_to(current)
    try:
        for part in relative.parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise AgentBehaviorError("output parent must not be a symlink")
            current.mkdir(mode=0o700, exist_ok=True)
        if destination.exists():
            if not overwrite:
                raise FileExistsError(destination)
            if not write_existing_text_no_symlink(destination, text, encoding="utf-8"):
                raise AgentBehaviorError(f"could not safely write {destination}")
            return
        _write_new_text_fallback(destination, text)
    except FileExistsError:
        raise
    except (OSError, UnicodeError) as exc:
        raise AgentBehaviorError(f"could not safely write {destination}") from exc


def _write_new_text_fallback(destination: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    file_descriptor: int | None = None
    try:
        file_descriptor = os.open(  # skylos: ignore[SKY-D215] fallback path checks project containment and symlink parents
            destination,
            flags,
            0o600,
        )
        owned_descriptor = file_descriptor
        file_descriptor = None
        _write_text_fd(owned_descriptor, text)
    finally:
        _close_fd(file_descriptor)


def _render_behavior_output(payload: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(payload, indent=2, sort_keys=True, default=str)
    buffer = StringIO()
    console = Console(file=buffer, force_terminal=False, color_system=None, width=120)
    _print_behavior_table(console, payload)
    return buffer.getvalue().rstrip()


def _print_behavior_table(console: Console, payload: dict[str, Any]) -> None:
    status = str(payload.get("status", "incomplete"))
    style = {"pass": "green", "fail": "red", "incomplete": "yellow"}.get(
        status,
        "yellow",
    )
    console.print(f"[bold]Agent behavior test:[/bold] [{style}]{status}[/{style}]")
    table = Table(expand=True)
    table.add_column("Scenario")
    table.add_column("Status", width=12)
    table.add_column("Passed", justify="right", width=8)
    table.add_column("Failed", justify="right", width=8)
    table.add_column("Incomplete", justify="right", width=10)
    table.add_column("Details", overflow="fold")
    for scenario in payload.get("scenarios", []):
        assertions = scenario.get("assertions", [])
        failed = [item for item in assertions if item.get("status") == "fail"]
        incomplete = [item for item in assertions if item.get("status") == "incomplete"]
        details = failed or incomplete
        table.add_row(
            str(scenario.get("id", "")),
            str(scenario.get("status", "")),
            str(sum(item.get("status") == "pass" for item in assertions)),
            str(len(failed)),
            str(len(incomplete)),
            "; ".join(str(item.get("message", "")) for item in details[:3]),
        )
    console.print(table)
    summary = payload.get("summary", {})
    console.print(
        "[dim]"
        f"Scenarios: {summary.get('scenario_count', 0)} | "
        f"Assertions: {summary.get('assertion_count', 0)} | "
        f"Pass: {summary.get('passed_assertions', 0)} | "
        f"Fail: {summary.get('failed_assertions', 0)} | "
        f"Incomplete: {summary.get('incomplete_assertions', 0)}"
        "[/dim]"
    )
    run_dir = payload.get("artifacts", {}).get("run_dir")
    if run_dir:
        console.print(f"[dim]Run dir: {run_dir}[/dim]")


def _behavior_exit_code(payload: dict[str, Any]) -> int:
    status = payload.get("status")
    if status == "fail":
        return 1
    if status != "pass":
        return 2
    return 0
