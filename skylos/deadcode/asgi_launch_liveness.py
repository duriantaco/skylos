"""Read explicit ASGI launcher references without starting an application."""

from __future__ import annotations

import ast
import shlex
from pathlib import Path

import tomllib

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.ai_defect.environment_dependencies import (
    _dockerfile_instructions,
    _exec_form,
)

_MAX_CONFIG_BYTES = 1_000_000
_UVICORN_VALUE_OPTIONS = {
    "--app-dir",
    "--host",
    "--port",
    "--uds",
    "--fd",
    "--workers",
    "--loop",
    "--http",
    "--ws",
    "--lifespan",
    "--interface",
    "--env-file",
    "--log-config",
    "--log-level",
    "--reload-dir",
    "--reload-include",
    "--reload-exclude",
    "--root-path",
    "--timeout-keep-alive",
    "--timeout-graceful-shutdown",
    "--forwarded-allow-ips",
    "--ssl-keyfile",
    "--ssl-certfile",
    "--ssl-ca-certs",
    "--header",
}
_UVICORN_SWITCHES = {
    "--factory",
    "--reload",
    "--proxy-headers",
    "--no-proxy-headers",
    "--access-log",
    "--no-access-log",
    "--use-colors",
    "--no-use-colors",
    "--server-header",
    "--no-server-header",
    "--date-header",
    "--no-date-header",
}
_FASTAPI_VALUE_OPTIONS = {
    "--entrypoint",
    "--host",
    "--port",
    "--workers",
    "--root-path",
}
_FASTAPI_SWITCHES = {"--reload", "--no-reload", "--proxy-headers", "--no-proxy-headers"}


def _object_ref(reference):
    if not isinstance(reference, str):
        return None
    module, separator, member = reference.partition(":")
    if (
        separator
        and member.isidentifier()
        and all(part.isidentifier() for part in module.split("."))
    ):
        return module, member
    return None


def _tool_fastapi(directory):
    raw = read_text_no_symlink(
        directory / "pyproject.toml", max_bytes=_MAX_CONFIG_BYTES
    )
    if not raw:
        return None
    try:
        tool = tomllib.loads(raw).get("tool")
    except (ValueError, RecursionError):
        return None
    fastapi = tool.get("fastapi") if isinstance(tool, dict) else None
    return fastapi.get("entrypoint") if isinstance(fastapi, dict) else None


def _docker_command(body, *, default_shell):
    parts = _exec_form(body)
    if parts is not None:
        return parts
    if not default_shell or any(char in body for char in "$`;&|<>"):
        return []
    try:
        return shlex.split(body, comments=True)
    except ValueError:
        return []


def _docker_argv(directory):
    raw = read_text_no_symlink(directory / "Dockerfile", max_bytes=_MAX_CONFIG_BYTES)
    if not raw:
        return []
    cmd = entrypoint = ""
    cmd_shell = entrypoint_shell = True
    default_shell = True
    for instruction, body in _dockerfile_instructions(raw):
        if instruction == "FROM":
            cmd = entrypoint = ""
            default_shell = True
        elif instruction == "CMD":
            cmd = body
            cmd_shell = default_shell
        elif instruction == "ENTRYPOINT":
            entrypoint = body
            entrypoint_shell = default_shell
        elif instruction == "SHELL":
            default_shell = _exec_form(body) == ["/bin/sh", "-c"]
    if not entrypoint or entrypoint == "[]":
        return _docker_command(cmd, default_shell=cmd_shell) if cmd else []
    argv = _docker_command(entrypoint, default_shell=entrypoint_shell)
    # A shell-form ENTRYPOINT ignores CMD. With an exec-form entrypoint,
    # only exec-form CMD supplies its literal argument vector.
    if entrypoint.startswith("["):
        cmd_args = _exec_form(cmd) if cmd else []
        return [*argv, *(cmd_args or ())] if argv else []
    return argv


def _cli_arguments(args, value_options, switch_options):
    positionals = []
    options = {}
    switches = set()
    tokens = iter(args)
    for token in tokens:
        if not token.startswith("-"):
            positionals.append(token)
            continue
        flag, separator, value = token.partition("=")
        if flag in value_options:
            value = value if separator else next(tokens, None)
            if value is None or value.startswith("--"):
                return None
            options[flag] = value
        elif token in switch_options:
            switches.add(token)
        else:
            return None
    return positionals, options, switches


def _docker_launch(directory):
    argv = _docker_argv(directory)
    if not argv:
        return None
    program, *args = argv
    if program in {"python", "python3"} and args[:2] == ["-m", "uvicorn"]:
        program, args = "uvicorn", args[2:]
    if program == "uvicorn":
        parsed = _cli_arguments(args, _UVICORN_VALUE_OPTIONS, _UVICORN_SWITCHES)
        if parsed is not None:
            positionals, options, switches = parsed
            if len(positionals) == 1:
                return positionals[0], "--factory" in switches, options.get("--app-dir")
    if program == "fastapi" and args[:1] in (["run"], ["dev"]):
        parsed = _cli_arguments(args[1:], _FASTAPI_VALUE_OPTIONS, _FASTAPI_SWITCHES)
        if parsed is not None:
            positionals, options, _ = parsed
            if not positionals and "--entrypoint" in options:
                return options["--entrypoint"], False, None
    return None


def _literal_argument(call, name, position=None, default=None):
    node = next((kw.value for kw in call.keywords if kw.arg == name), None)
    if position is not None and len(call.args) > position:
        if node is not None:
            return None
        node = call.args[position]
    if node is None:
        return default
    return node.value if isinstance(node, ast.Constant) else None


def _python_launches(project):
    if "uvicorn" in project.shadowed:
        return
    for event in tuple(project.calls):
        if (
            event.target not in {"uvicorn.run", "uvicorn.main.run"}
            or not event.executed
            or event.uncertain
            or any(kw.arg is None for kw in event.node.keywords)
        ):
            continue
        reference = _literal_argument(event.node, "app", 0)
        factory = _literal_argument(event.node, "factory", default=False)
        if isinstance(factory, bool):
            app_dir = _literal_argument(event.node, "app_dir", default="")
            if isinstance(app_dir, str):
                yield reference, factory, app_dir, project.root, event.module


def _module_from_directory(project, name, directory):
    try:
        prefix = directory.relative_to(project.root).parts
    except ValueError:
        return None
    for parts in (prefix, (*prefix, "src")):
        module = project.modules.get(".".join((*parts, name)))
        if module is not None:
            return module
    return None


def _launch_requests(project):
    yield from _python_launches(project)
    directories = {project.root}
    for module in project.modules.values():
        directory = module.path.parent
        while directory not in directories:
            directories.add(directory)
            directory = directory.parent
    for directory in sorted(directories):
        reference = _tool_fastapi(directory)
        if reference is not None:
            yield reference, False, None, directory, None
        docker = _docker_launch(directory)
        if docker is not None:
            yield *docker, directory, None


def collect_asgi_launches(project):
    """Resolve the launcher's named object or invoke a proven zero-arg factory."""
    handled = set()
    for reference, factory, app_dir, directory, importer in _launch_requests(project):
        parsed = _object_ref(reference)
        if parsed is None:
            continue
        name, member = parsed
        if app_dir and (Path(app_dir).is_absolute() or ".." in Path(app_dir).parts):
            continue
        module = (
            project.module_named(name, importer)
            if importer is not None and not app_dir
            else _module_from_directory(project, name, directory / (app_dir or ""))
        )
        if module is None or (module.name, member, factory) in handled:
            continue
        handled.add((module.name, member, factory))
        value = module.bindings.get(member)
        if factory:
            key = project.invoke_launch_factory(value, module)
            if key is not None:
                project.report.launch_roots.add(key)
        else:
            obj = project.objects.get(value)
            if obj is None or obj.kind not in {
                "app",
                "starlette_app",
                "starlette_router",
            }:
                continue
            project.active_objects.add(obj.key)
        assigned, line = module.assignment_sites.get(member, (None, None))
        if line is not None and assigned == value:
            project.report.launch_bindings.add((str(module.path), line, member))
