"""Opt-in project checker adapters. No installs, shell commands or package scripts."""

from __future__ import annotations

import configparser
import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path
from functools import lru_cache

from skylos.core.safe_cache_io import read_project_text_no_symlink

SUPPORTED_CHECKERS = frozenset({"mypy", "pyright", "tsc", "pyrefly"})
MAX_CONFIG_BYTES = 2_000_000
MAX_OUTPUT_BYTES = 4_000_000
MAX_DIAGNOSTICS = 20_000


class _Incomplete(ValueError):
    pass


class _ComparisonUnsupported(_Incomplete):
    pass


def _read(root: Path, path: Path) -> str:
    source = read_project_text_no_symlink(root, path, max_bytes=MAX_CONFIG_BYTES)
    if source is None:
        raise _Incomplete(
            f"Configuration is unreadable or outside the project: {path.name}"
        )
    return source


def _toml(source: str) -> dict:
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python 3.10
        import tomli as tomllib
    return tomllib.loads(source)


def _json_config(source: str) -> dict:
    from skylos.visitors.languages.typescript.workspace import (
        _strip_json_comments,
        _strip_trailing_commas,
    )

    data = json.loads(
        _strip_trailing_commas(_strip_json_comments(source.lstrip("\ufeff")))
    )
    if not isinstance(data, dict):
        raise _Incomplete("Checker configuration must be an object")
    return data


def _config_inventory(root: Path) -> tuple[dict, dict[str, list[str]], dict]:
    pyproject = root / "pyproject.toml"
    data = _toml(_read(root, pyproject)) if os.path.lexists(pyproject) else {}
    tool = data.get("tool", {})
    if not isinstance(tool, dict):
        raise _Incomplete("Invalid [tool] configuration")
    declarations = {name: [] for name in SUPPORTED_CHECKERS}
    for name in ("mypy", "pyright", "pyrefly"):
        if name in tool:
            if not isinstance(tool[name], dict):
                raise _Incomplete(f"Invalid [tool.{name}] configuration")
            declarations[name].append("pyproject.toml")
    for name, filenames in {
        "mypy": ("mypy.ini", ".mypy.ini", "setup.cfg"),
        "pyright": ("pyrightconfig.json",),
        "tsc": ("tsconfig.json",),
        "pyrefly": ("pyrefly.toml",),
    }.items():
        for filename in filenames:
            path = root / filename
            if not os.path.lexists(path):
                continue
            if name == "mypy":
                ini = configparser.ConfigParser(interpolation=None, strict=False)
                ini.read_string(_read(root, path))
                if "mypy" not in ini:
                    continue
            declarations[name].append(filename)
    skylos = tool.get("skylos", {})
    settings = skylos.get("type_check", {}) if isinstance(skylos, dict) else {}
    if not isinstance(settings, dict):
        raise _Incomplete("Invalid [tool.skylos.type_check] configuration")
    return tool, declarations, settings


def _executable(root: Path, name: str) -> str | None:
    directories = [root / ".venv/bin", root / "venv/bin", root / "node_modules/.bin"]
    directories += [root / ".venv/Scripts", root / "venv/Scripts"]
    for directory in directories:
        for suffix in ("", ".exe", ".cmd") if os.name == "nt" else ("",):
            path = directory / (name + suffix)
            if path.is_file() and os.access(path, os.X_OK):
                return str(path.resolve())
    found = shutil.which(name)
    return str(Path(found).resolve()) if found else None


@lru_cache(maxsize=64)
def _executable_digest(path: str, token: tuple) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 256_000_000:
            raise _Incomplete("Checker executable is not a bounded regular file")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, 1024 * 1024):
            total += len(chunk)
            if total > 256_000_000:
                raise _Incomplete("Checker executable exceeds its size limit")
            digest.update(chunk)
        after = os.fstat(fd)
        actual = (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_ino,
            after.st_dev,
        )
        if actual != token:
            raise _Incomplete("Checker executable changed while it was fingerprinted")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _executable_fingerprint(path: str) -> dict:
    metadata = os.stat(path)
    token = (
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_ino,
        metadata.st_dev,
    )
    return {
        "sha256": _executable_digest(path, token),
        "size": token[0],
        "mtime_ns": token[1],
        "ctime_ns": token[2],
        "inode": token[3],
        "device": token[4],
    }


def _fingerprints(root: Path, files: list[str], checker: str) -> dict[str, str]:
    fingerprints: dict[str, str] = {}
    visiting: set[Path] = set()

    def visit(path: Path, depth: int = 0):
        if depth > 32 or len(fingerprints) >= 128:
            raise _Incomplete("Checker configuration inheritance exceeds its limit")
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise _ComparisonUnsupported(
                "Checker configuration inherits outside the project"
            ) from exc
        if resolved in visiting:
            raise _Incomplete("Checker configuration inheritance contains a cycle")
        if relative in fingerprints:
            return
        visiting.add(resolved)
        source = _read(root, path)
        fingerprints[relative] = hashlib.sha256(source.encode()).hexdigest()
        config = None
        if path.suffix.lower() == ".json" and checker in {"tsc", "pyright"}:
            config = _json_config(source)
        elif path.name == "pyproject.toml" and checker == "pyright":
            config = _toml(source).get("tool", {}).get("pyright", {})
        if config is not None:
            if checker == "tsc" and config.get("references"):
                # Check this before allowing unsupported inheritance: tsc -p
                # is not a solution build even when it inherits a package.
                raise _Incomplete(
                    "TypeScript project-reference builds are not supported"
                )
            extends = config.get("extends", [])
            if isinstance(extends, str):
                extends = [extends]
            if not isinstance(extends, list) or any(
                not isinstance(v, str) for v in extends
            ):
                raise _Incomplete("Invalid checker configuration inheritance")
            for value in extends:
                if (
                    not value.startswith(".")
                    and not Path(value).is_absolute()
                    and not (path.parent / value).is_file()
                ):
                    raise _ComparisonUnsupported(
                        "Package-based checker configuration inheritance is not supported"
                    )
                inherited = path.parent / value
                if not inherited.suffix:
                    inherited = inherited.with_suffix(".json")
                visit(inherited, depth + 1)
        elif checker == "pyrefly" and path.suffix == ".toml":
            config = _toml(source)
            if path.name == "pyproject.toml":
                config = config.get("tool", {}).get("pyrefly", {})
            if config.get("extends"):
                visit(path.parent / config["extends"], depth + 1)
            if config.get("baseline"):
                # Native Pyrefly baselines suppress diagnostics too: changing
                # their contents is a change to effective checker policy.
                baseline = path.parent / config["baseline"]
                try:
                    visit(baseline, depth + 1)
                except (OSError, _Incomplete) as exc:
                    raise _ComparisonUnsupported(
                        "Pyrefly baseline context is unavailable"
                    ) from exc
        visiting.remove(resolved)

    for relative in files:
        visit(root / relative)
    return fingerprints


def _command(
    root: Path, checker: str, executable: str, configs: list[str], tool: dict
) -> list[str]:
    if checker == "tsc":
        return [
            executable,
            "--project",
            "tsconfig.json",
            "--noEmit",
            "--pretty",
            "false",
        ]
    if checker == "pyright":
        return [executable, "--project", ".", "--outputjson"]
    if checker == "pyrefly":
        return [executable, "check", "--output-format", "json"]
    args = [
        executable,
        "--no-pretty",
        "--no-color-output",
        "--show-column-numbers",
        "--show-error-codes",
        "--error-summary",
    ]
    selected = next(
        (
            p
            for p in ("mypy.ini", ".mypy.ini", "pyproject.toml", "setup.cfg")
            if p in configs and (p != "pyproject.toml" or "mypy" in tool)
        ),
        None,
    )
    configured_targets = False
    if selected:
        args.extend(["--config-file", selected])
        if selected == "pyproject.toml":
            settings = tool.get("mypy", {})
        else:
            ini = configparser.ConfigParser(interpolation=None, strict=False)
            ini.read_string(_read(root, root / selected))
            settings = ini["mypy"]
        configured_targets = any(
            settings.get(key) for key in ("files", "packages", "modules")
        )
    else:
        # Explicit checker selection without its own project configuration must
        # not inherit an unrecorded user-wide mypy configuration.
        args.extend(["--config-file", ""])
    if not configured_targets:
        args.append(".")
    return args


def discover_checker(root: Path, checker: str | None = None) -> dict:
    """Read declarations and resolve an installed tool; never execute it."""
    root = Path(root).resolve()
    plan = {
        "status": "incomplete",
        "checker": None,
        "project_root": str(root),
        "config_files": [],
        "config_fingerprints": {},
        "executable": None,
        "executable_fingerprint": None,
        "comparison_supported": True,
        "comparison_reason": "",
        "command": [],
        "reason": "",
        "summary": "",
    }
    try:
        if not root.is_dir():
            raise _Incomplete("Project root is not a directory")
        tool, declarations, settings = _config_inventory(root)
        selection = (
            checker if checker not in {None, "auto"} else settings.get("checker")
        )
        if selection in {None, "auto"}:
            declared = sorted(name for name, files in declarations.items() if files)
            if not declared:
                plan.update(
                    status="not_configured",
                    reason="not_configured",
                    summary="No project type checker is configured",
                )
                return plan
            if len(declared) != 1:
                raise _Incomplete(
                    "Multiple project checkers are configured; select one explicitly"
                )
            selection = declared[0]
        if selection not in SUPPORTED_CHECKERS:
            raise _Incomplete(f"Unsupported checker: {selection!r}")
        plan["checker"] = selection
        configs = list(declarations[selection])
        if settings.get("checker") and "pyproject.toml" not in configs:
            configs.append("pyproject.toml")
        try:
            fingerprints = _fingerprints(root, configs, selection)
        except _ComparisonUnsupported as exc:
            # The actual checker can resolve package and external configs for
            # a current check. Baseline attribution needs a closed config
            # inventory and must explicitly reject this unsupported context.
            fingerprints = _fingerprints(root, configs, "direct")
            plan.update(comparison_supported=False, comparison_reason=str(exc))
        plan.update(config_files=sorted(fingerprints), config_fingerprints=fingerprints)
        executable = _executable(root, selection)
        # A missing tool can be rebound to the same installed executable when
        # comparing an isolated source snapshot through executable_override.
        plan["executable"] = executable
        plan["command"] = _command(
            root, selection, executable or selection, configs, tool
        )
        if executable is None:
            plan.update(
                reason="checker_unavailable",
                summary=f"Configured checker {selection} is not installed",
            )
        else:
            plan["executable_fingerprint"] = _executable_fingerprint(executable)
            plan.update(status="ready", summary=f"Ready to run {selection}")
    except (OSError, ValueError, RuntimeError, configparser.Error, TypeError) as exc:
        plan.update(reason="configuration_incomplete", summary=str(exc))
    return plan


def _kill(process):
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:  # pragma: no cover - Windows
            process.kill()
    except OSError:
        pass


def _run_bounded(command: list[str], root: Path, timeout_seconds: float) -> dict:
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    read_error = threading.Event()
    process = subprocess.Popen(
        command,
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=(os.name == "posix"),
        env={**os.environ, "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1"},
    )

    def consume(pipe, buffer):
        try:
            while chunk := pipe.read(65536):
                available = MAX_OUTPUT_BYTES - len(buffer)
                buffer.extend(chunk[:available])
                if len(chunk) > available:
                    overflow.set()
                    break
        except (OSError, ValueError):
            read_error.set()
        finally:
            pipe.close()

    threads = [
        threading.Thread(target=consume, args=(pipe, buffer), daemon=True)
        for pipe, buffer in zip((process.stdout, process.stderr), buffers)
    ]
    reason = ""
    started = time.monotonic()
    try:
        for thread in threads:
            thread.start()
        while process.poll() is None:
            if overflow.is_set():
                reason = "output_limit"
                break
            if time.monotonic() - started >= timeout_seconds:
                reason = "timeout"
                break
            time.sleep(0.01)
    finally:
        # Also stop descendants retaining a pipe after the checker exits.
        _kill(process)
        process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=1)
    if overflow.is_set():
        reason = "output_limit"
    if read_error.is_set() or any(thread.is_alive() for thread in threads):
        reason = reason or "output_incomplete"
    return {
        "returncode": process.returncode,
        "stdout": bytes(buffers[0]),
        "stderr": bytes(buffers[1]),
        "reason": reason,
    }


def _diagnostic(root: Path, file, line, column, code, message, severity) -> dict:
    if (
        not isinstance(file, str)
        or not file
        or not isinstance(message, str)
        or not message
    ):
        raise _Incomplete("Malformed checker diagnostic")
    if type(line) is not int or type(column) is not int or line < 1 or column < 0:
        raise _Incomplete("Malformed checker diagnostic location")
    if severity not in {
        "error",
        "warning",
        "information",
        "note",
        "warn",
        "info",
        "hint",
    }:
        raise _Incomplete("Unknown checker diagnostic severity")
    if "://" in file or (os.name != "nt" and re.match(r"^[A-Za-z]:[\\/]", file)):
        raise _Incomplete("Checker diagnostic uses an unsupported path")
    path = Path(file)
    if not path.is_absolute():
        path = root / path
    try:
        relative = path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        raise _Incomplete("Checker diagnostic is outside the project") from exc
    return {
        "file": relative,
        "line": line,
        "column": max(1, column),
        "code": str(code or ""),
        "message": message,
        "severity": severity,
    }


def _parse_json(checker: str, output: str, root: Path) -> list[dict]:
    try:
        data = json.loads(output)
    except ValueError as exc:
        raise _Incomplete("Checker did not return valid JSON") from exc
    key = "generalDiagnostics" if checker == "pyright" else "errors"
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        raise _Incomplete("Checker returned an unknown diagnostic format")
    diagnostics = []
    if len(data[key]) > MAX_DIAGNOSTICS:
        raise _Incomplete("Checker diagnostic count exceeds its limit")
    for item in data[key]:
        if not isinstance(item, dict):
            raise _Incomplete("Malformed checker diagnostic")
        if checker == "pyright":
            position = item.get("range", {}).get("start", {})
            line, column = position.get("line"), position.get("character")
            if (
                type(line) is not int
                or type(column) is not int
                or line < 0
                or column < 0
            ):
                raise _Incomplete("Malformed checker diagnostic location")
            diagnostics.append(
                _diagnostic(
                    root,
                    item.get("file"),
                    line + 1,
                    column + 1,
                    item.get("rule"),
                    item.get("message"),
                    item.get("severity"),
                )
            )
        else:
            diagnostics.append(
                _diagnostic(
                    root,
                    item.get("path"),
                    item.get("line"),
                    item.get("column"),
                    item.get("name", item.get("code")),
                    item.get("description"),
                    item.get("severity", "error"),
                )
            )
    if checker == "pyright":
        summary = data.get("summary")
        if (
            not isinstance(summary, dict)
            or type(summary.get("filesAnalyzed")) is not int
            or summary["filesAnalyzed"] < 1
        ):
            raise _Incomplete("Pyright did not confirm any analyzed files")
        for severity, field in (("error", "errorCount"), ("warning", "warningCount")):
            if type(summary.get(field)) is not int or summary[field] != sum(
                d["severity"] == severity for d in diagnostics
            ):
                raise _Incomplete("Pyright diagnostic totals are inconsistent")
    return diagnostics


_MYPY = re.compile(
    r"^(.+?):(\d+)(?::(\d+))?: (error|warning|note): (.*?)(?:  \[([^\]]+)\])?$"
)
_TSC = re.compile(r"^(.+?)\((\d+),(\d+)\): (error|warning) (TS\d+): (.+)$")


def _parse_text(checker: str, output: str, root: Path) -> list[dict]:
    diagnostics = []
    recognized = checker == "tsc" and not output.strip()
    summary_errors = None
    for line in output.splitlines():
        if not line.strip():
            continue
        match = (_MYPY if checker == "mypy" else _TSC).match(line)
        if match:
            if checker == "mypy":
                file, row, col, severity, message, code = match.groups()
            else:
                file, row, col, severity, code, message = match.groups()
            diagnostics.append(
                _diagnostic(
                    root, file, int(row), int(col or 1), code, message, severity
                )
            )
            recognized = True
        elif checker == "mypy" and line.startswith("Success:"):
            summary = re.fullmatch(
                r"Success: no issues found in (\d+) source files?", line
            )
            if summary is None or int(summary.group(1)) < 1:
                raise _Incomplete("Mypy did not confirm any checked source files")
            summary_errors = 0
            recognized = True
        elif checker == "mypy" and line.startswith("Found "):
            summary = re.fullmatch(
                r"Found (\d+) errors? in \d+ files? \(checked \d+ source files?\)", line
            )
            if summary is None:
                raise _Incomplete("Unrecognized mypy diagnostic summary")
            summary_errors = int(summary.group(1))
            recognized = True
        elif checker == "mypy" and re.match(r"^.+?: note: ", line):
            continue
        elif diagnostics and line[0].isspace():
            diagnostics[-1]["message"] += "\n" + line.strip()
        else:
            raise _Incomplete(
                "Checker output includes an unrecognized diagnostic or setup error"
            )
    if not recognized:
        raise _Incomplete("Checker output did not confirm a completed check")
    if summary_errors is not None and summary_errors != sum(
        d["severity"] == "error" for d in diagnostics
    ):
        raise _Incomplete("Mypy diagnostic totals are inconsistent")
    return diagnostics


def run_project_checker(
    root: Path,
    *,
    checker: str = "auto",
    timeout_seconds: float = 120,
    executable_override: str | None = None,
) -> dict:
    """Execute an installed project checker after the caller obtained opt-in."""
    started = time.monotonic()
    root = Path(root).resolve()
    plan = discover_checker(root, checker)
    result = {
        **plan,
        "complete": False,
        "diagnostics": [],
        "seconds": 0.0,
        "returncode": None,
        "error_count": 0,
        "warning_count": 0,
        "setup": "",
    }
    try:
        if (
            executable_override
            and plan.get("command")
            and plan.get("reason") in {"", "checker_unavailable"}
        ):
            executable = Path(executable_override).resolve()
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise _Incomplete("Executable override is unavailable")
            result.update(
                status="ready",
                reason="",
                executable=str(executable),
                executable_fingerprint=_executable_fingerprint(str(executable)),
            )
            result["command"] = [str(executable), *plan["command"][1:]]
        if result["status"] != "ready":
            return result
        if (
            type(timeout_seconds) not in {int, float}
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise _Incomplete("Checker timeout must be a positive finite number")
        outcome = _run_bounded(result["command"], root, timeout_seconds)
        result["returncode"] = outcome["returncode"]
        if outcome["reason"]:
            result["reason"] = outcome["reason"]
            raise _Incomplete(f"Checker execution incomplete: {outcome['reason']}")
        if (
            _executable_fingerprint(result["executable"])
            != result["executable_fingerprint"]
        ):
            raise _Incomplete("Checker executable changed during execution")
        if (
            _fingerprints(root, result["config_files"], "direct")
            != result["config_fingerprints"]
        ):
            raise _Incomplete("Checker configuration changed during execution")
        stdout = outcome["stdout"].decode("utf-8", errors="strict")
        stderr = outcome["stderr"].decode("utf-8", errors="strict")
        result["setup"] = stderr[-4000:]
        selected = result["checker"]
        accepted = {0, 1, 2} if selected == "tsc" else {0, 1}
        if outcome["returncode"] not in accepted:
            raise _Incomplete("Checker exited with a setup error or crashed")
        diagnostics = (
            _parse_json(selected, stdout, root)
            if selected in {"pyright", "pyrefly"}
            else _parse_text(selected, stdout, root)
        )
        if any(
            diagnostic["severity"] == "error"
            and diagnostic["file"] in result["config_files"]
            for diagnostic in diagnostics
        ):
            raise _Incomplete(
                "Checker configuration contains errors; project checking did not complete"
            )
        if len(diagnostics) > MAX_DIAGNOSTICS:
            raise _Incomplete("Checker diagnostic count exceeds its limit")
        errors = sum(d["severity"] == "error" for d in diagnostics)
        if (
            outcome["returncode"] == 0
            and errors
            or outcome["returncode"] != 0
            and not errors
        ):
            raise _Incomplete("Checker exit status and diagnostics are inconsistent")
        # Stderr is retained for setup evidence. It must not conceal a crash
        # or an unsupported option behind an otherwise valid stdout report.
        if stderr.strip() and (
            selected in {"mypy", "tsc", "pyright"}
            or re.search(
                r"Traceback|internal error|fatal|unknown option|unrecognized argument|error:",
                stderr,
                re.I,
            )
        ):
            raise _Incomplete("Checker wrote unexpected setup output")
        result.update(
            status="fail" if errors else "pass",
            complete=True,
            diagnostics=diagnostics,
            error_count=errors,
            warning_count=sum(
                d["severity"] in {"warning", "warn"} for d in diagnostics
            ),
            reason="",
            summary=f"{selected}: {errors} type error(s)",
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
        UnicodeError,
        AttributeError,
        TypeError,
    ) as exc:
        result.update(
            status="incomplete",
            complete=False,
            reason=result["reason"] or "checker_incomplete",
            summary=str(exc),
        )
    result["seconds"] = time.monotonic() - started
    return result
