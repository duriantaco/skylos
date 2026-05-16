from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from rich.console import Console

from skylos.config import load_config
from skylos.constants import parse_exclude_folders


def _load_start_server() -> Callable[..., Any]:
    from skylos.web.server import start_server

    return start_server


def run_run_command(
    argv: Sequence[str],
    *,
    console_factory: type[Console] = Console,
    load_config_func: Callable[[Path], dict[str, Any]] = load_config,
    parse_exclude_folders_func: Callable[..., set[str] | tuple[str, ...]] = parse_exclude_folders,
    start_server_loader: Callable[[], Callable[..., Any]] = _load_start_server,
) -> None:
    run_exclude_folders: list[str] = []
    run_include_folders: list[str] = []
    run_port = None
    no_defaults = False

    i = 0
    while i < len(argv):
        if argv[i] == "--exclude-folder" and i + 1 < len(argv):
            run_exclude_folders.append(argv[i + 1])
            i += 2
        elif argv[i] == "--include-folder" and i + 1 < len(argv):
            run_include_folders.append(argv[i + 1])
            i += 2
        elif argv[i] == "--no-default-excludes":
            no_defaults = True
            i += 1
        elif argv[i] == "--port" and i + 1 < len(argv):
            try:
                run_port = int(argv[i + 1])
            except ValueError:
                console_factory().print("[bold red]Error: --port must be an integer[/bold red]")
                raise SystemExit(1)
            i += 2
        elif argv[i] == "--port":
            console_factory().print("[bold red]Error: --port requires a value[/bold red]")
            raise SystemExit(1)
        else:
            i += 1

    original_server_port = os.environ.get("SKYLOS_PORT")
    try:
        if run_port is not None:
            os.environ["SKYLOS_PORT"] = str(run_port)

        try:
            start_server = start_server_loader()
        except ImportError:
            console_factory().print("[bold red]Error: Flask is required[/bold red]")
            console_factory().print(
                "[bold yellow]Install with: pip install flask flask-cors[/bold yellow]"
            )
            raise SystemExit(1)

        exclude_folders = parse_exclude_folders_func(
            user_exclude_folders=run_exclude_folders or None,
            config_exclude_folders=load_config_func(Path.cwd()).get("exclude"),
            use_defaults=not no_defaults,
            include_folders=run_include_folders or None,
        )

        start_server(exclude_folders=list(exclude_folders))
    except ImportError:
        console_factory().print("[bold red]Error: Flask is required[/bold red]")
        console_factory().print(
            "[bold yellow]Install with: pip install flask flask-cors[/bold yellow]"
        )
        raise SystemExit(1)
    except ValueError as exc:
        console_factory().print(f"[bold red]Error: {exc}[/bold red]")
        raise SystemExit(1)
    finally:
        if run_port is not None:
            if original_server_port is None:
                os.environ.pop("SKYLOS_PORT", None)
            else:
                os.environ["SKYLOS_PORT"] = original_server_port
