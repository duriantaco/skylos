from __future__ import annotations

import json
import os
import re
import shlex
from collections import Counter
from collections.abc import Iterator
from dataclasses import replace
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink, read_text_no_symlink
from skylos.rules.config.cicd.runner_labels import runner_may_be_self_hosted
from skylos.rules.config.cicd.template_injection import interpolates_untrusted
from skylos.rules.config.cicd.yaml_source import YamlSource, load_yaml_with_locations
from skylos.rules.config.findings import config_finding
from skylos.security.command_guard import scan_shell_command
from skylos.security.command_guard_parse import dequote_shell, redefines_home

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a runtime dependency.
    yaml = None


SKIP_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}

ACTION_FILENAMES = {"action.yml", "action.yaml"}
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
COOKIECUTTER_VARIABLE_RE = re.compile(
    r"(?<!\$)\{\{[ \t]*cookiecutter\.([A-Za-z_][A-Za-z0-9_]*)[ \t]*\}\}"
)
COOKIECUTTER_LITERAL_RE = re.compile(
    r"(?<!\$)\{\{[ \t]*(?:'(?P<single>[^'\\\r\n]*)'|"
    r'"(?P<double>[^"\\\r\n]*)")[ \t]*\}\}'
)
COOKIECUTTER_SENTINEL = "__SKYLOS_COOKIECUTTER_"
MAX_YAML_BYTES = 1_000_000
MAX_YAML_GRAPH_DEPTH = 100
MAX_YAML_GRAPH_NODES = 50_000
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
WORKSPACE_EXPR_RE = re.compile(
    r"^\$\{\{\s*github\.workspace\s*\}\}(?:/|$)", re.IGNORECASE
)
# Runner labels that are clearly Linux or macOS, where a run block's default
# shell is bash. Windows runners default to pwsh.
POSIX_RUNNER_PREFIXES = ("ubuntu-", "macos-")
POSIX_RUNNER_LABELS = {"linux", "macos"}
POSIX_SHELLS = {"bash", "sh"}
SECRETS_OUTSIDE_ENV_RE = re.compile(
    r"\$\{\{[^}]*\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)\b[^}]*\}\}",
    re.IGNORECASE,
)
OVERPROVISIONED_SECRETS_RE = re.compile(
    r"\$\{\{[^}]*\b(?:toJSON\s*\(\s*secrets\s*\)|secrets\s*\[\s*"
    r"(?!['\"]).+?\s*\])[^}]*\}\}",
    re.IGNORECASE | re.DOTALL,
)
GITHUB_ENV_DEST_RE = re.compile(
    r"(?i)(?:\$GITHUB_(?:ENV|PATH)|\$\{GITHUB_(?:ENV|PATH)\}|"
    r"%GITHUB_(?:ENV|PATH)%|\$env:GITHUB_(?:ENV|PATH))"
)
UNSAFE_CONTAINS_RE = re.compile(
    r"contains\s*\(\s*['\"][^'\"]+['\"]\s*,\s*([A-Za-z_][A-Za-z0-9_.]*)",
    re.IGNORECASE,
)
BOT_CONDITION_RE = re.compile(
    r"(?i)\b(github\.(?:actor|triggering_actor|actor_id)|"
    r"github\.event\.pull_request\.sender\.(?:login|id))\b[^\n]*"
    r"(?:\[bot\]|29110|49699333|27856297|29139614)"
)
BLOCK_SCALAR_IF_RE = re.compile(r"^(?P<indent>\s*)(?:-\s*)?if\s*:\s*[|>]")
LOCAL_SCRIPT_RE = re.compile(
    r"(?im)^\s*(?:"
    r"\./(?:scripts|ci|build|tools|release|deploy)/"
    r"|(?:bash|sh|python3?|node|ruby|pwsh|powershell)\s+"
    r"(?:\./)?(?:scripts|ci|build|tools|release|deploy)/"
    r"|(?:npm|pnpm|yarn|bun)\s+run\s+"
    r"|make(?:\s|$)"
    r")"
)
JS_INSTALL_RE = re.compile(
    r"(?im)^\s*(?:npm|pnpm|yarn|bun)\s+(?:ci|install)\b(?![^\n]*--ignore-scripts)"
)
DOCKER_CMD_RE = re.compile(r"(?im)^\s*docker\s+(pull|run)\b(?P<args>[^\n]*)")

DOCKER_OPTIONS_WITH_ARGS = {
    "-e",
    "--env",
    "--env-file",
    "-h",
    "--hostname",
    "--label",
    "--log-driver",
    "--log-opt",
    "--name",
    "--network",
    "--platform",
    "--pull",
    "--user",
    "-u",
    "-v",
    "--volume",
    "--volumes-from",
    "-w",
    "--workdir",
    "--entrypoint",
    "--add-host",
}

WRITE_PERMISSION_SEVERITY = {
    "actions": "HIGH",
    "artifact-metadata": "MEDIUM",
    "attestations": "HIGH",
    "checks": "MEDIUM",
    "contents": "HIGH",
    "deployments": "HIGH",
    "discussions": "MEDIUM",
    "id-token": "HIGH",
    "issues": "HIGH",
    "packages": "HIGH",
    "pages": "HIGH",
    "pull-requests": "HIGH",
    "repository-projects": "MEDIUM",
    "security-events": "MEDIUM",
}


CACHE_AWARE_ACTIONS = {
    "actions/cache",
    "actions/setup-java",
    "actions/setup-go",
    "actions/setup-node",
    "actions/setup-python",
    "actions/setup-dotnet",
    "astral-sh/setup-uv",
    "swatinem/rust-cache",
    "ruby/setup-ruby",
    "pyo3/maturin-action",
    "mlugg/setup-zig",
    "oven-sh/setup-bun",
    "determinateSystems/magic-nix-cache-action".lower(),
    "graalvm/setup-graalvm",
    "gradle/actions/setup-gradle",
    "docker/setup-buildx-action",
    "actions-rust-lang/setup-rust-toolchain",
    "mozilla-actions/sccache-action",
    "nix-community/cache-nix-action",
    "jdx/mise-action",
    "ramsey/composer-install",
}

USER_CONTROLLED_CONTAINS_CONTEXTS = {
    "env",
    "github.actor",
    "github.base_ref",
    "github.head_ref",
    "github.ref",
    "github.ref_name",
    "github.sha",
    "github.triggering_actor",
    "inputs",
}


def _finding(
    *,
    rule_id: str,
    name: str,
    message: str,
    file: Path,
    line: int,
    severity: str,
    value: str,
) -> dict[str, Any]:
    return config_finding(
        rule_id=rule_id,
        domain="cicd",
        provider="github_actions",
        name=name,
        message=message,
        file=file,
        line=line,
        severity=severity,
        value=value,
        finding_type="workflow",
    )


def _is_workflow_file(path: Path) -> bool:
    parts = path.parts
    if path.suffix.lower() not in WORKFLOW_SUFFIXES:
        return False
    for idx, part in enumerate(parts[:-1]):
        if part == ".github" and idx + 1 < len(parts) and parts[idx + 1] == "workflows":
            return True
    return False


def _is_action_file(path: Path) -> bool:
    return path.name.lower() in ACTION_FILENAMES


def _is_github_actions_file(path: Path) -> bool:
    return _is_workflow_file(path) or _is_action_file(path)


def _is_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_github_actions_scan_path(
    path: str | Path,
    *,
    root: Path | None = None,
) -> Path | None:
    # Keep the requested path, so the guarded reader can refuse a symlink
    # rather than silently following it or losing it during discovery.
    candidate = Path(os.path.abspath(path))
    if root is not None and not _is_under_root(candidate, root):
        return None
    if not (candidate.is_file() or candidate.is_symlink()):
        return None
    if not _is_github_actions_file(candidate):
        return None
    return candidate


def _discover_action_files(
    root: Path,
    changed_files: set[str] | None,
) -> list[Path]:
    if root.is_file():
        candidate = _resolve_github_actions_scan_path(root)
        return [candidate] if candidate is not None else []

    if changed_files is not None:
        candidates = []
        for raw_path in changed_files:
            path = Path(raw_path)
            if not path.is_absolute():
                path = root / path
            candidate = _resolve_github_actions_scan_path(path, root=root)
            if candidate is not None:
                candidates.append(candidate)
        return sorted(set(candidates))

    candidates: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        base = Path(current_root)
        for filename in filenames:
            path = base / filename
            if _is_github_actions_file(path):
                candidates.append(path)
    return sorted(candidates)


class _WorkflowLines(list[str]):
    """Raw lines paired with the source map from the same safe YAML parse."""

    def __init__(self, text: str, source: YamlSource, parsed_text: str | None = None):
        super().__init__(text.splitlines())
        self.source = source
        self.parsed_lines = (text if parsed_text is None else parsed_text).splitlines()


def _config_analysis_error(path: Path, kind: str, message: str) -> dict[str, Any]:
    return {
        "rule_id": "SKY-ANALYSIS-INCOMPLETE",
        "kind": kind,
        "component": "github_actions",
        "file": str(path),
        "line": 1,
        "severity": "HIGH",
        "message": message,
    }


def _is_cookiecutter_template(path: Path, root: Path | None) -> bool:
    """Recognize generator inputs, never a repository's active workflows."""
    if root is None or root.is_file():
        return False
    parts = path.relative_to(root).parts
    for index, part in enumerate(parts):
        if part == ".github":
            break
        match = COOKIECUTTER_VARIABLE_RE.fullmatch(part)
        if match is None:
            continue
        manifest_path = root.joinpath(*parts[:index], "cookiecutter.json")
        manifest = read_project_text_no_symlink(
            root, manifest_path, max_bytes=65_536, encoding="utf-8"
        )
        if manifest is None:
            continue
        try:
            data = json.loads(manifest)
        except (ValueError, RecursionError):
            continue
        if isinstance(data, dict) and match.group(1) in data:
            return True
    return False


def _cookiecutter_yaml(text: str) -> str | None:
    """Decode static GitHub-expression escapes without evaluating Jinja."""
    if COOKIECUTTER_SENTINEL in text:
        return None
    literals: list[str] = []

    def literal(match: re.Match[str]) -> str:
        value = match.group("single") or match.group("double") or ""
        # No escapes, multiline output, expressions, filters or function calls.
        if not value.startswith("${{"):
            return match.group(0)
        token = f"{COOKIECUTTER_SENTINEL}LITERAL_{len(literals)}__"
        literals.append(value)
        return token

    normalized = COOKIECUTTER_LITERAL_RE.sub(literal, text)
    normalized = COOKIECUTTER_VARIABLE_RE.sub(
        lambda match: f"{COOKIECUTTER_SENTINEL}VARIABLE_{match.group(1)}__", normalized
    )
    # Jinja also evaluates {{ ... }} after a literal '$'. Only expressions
    # from the quoted constants above may pass through as GitHub syntax.
    if re.search(r"\{\{|\{%|\{#", normalized):
        return None
    for index, value in enumerate(literals):
        normalized = normalized.replace(f"{COOKIECUTTER_SENTINEL}LITERAL_{index}__", value)
    return normalized


def _cookiecutter_variables_are_display_only(data: dict[str, Any]) -> bool:
    """Unknown generated names may not determine a security control."""
    stack: list[tuple[Any, tuple[Any, ...]]] = [(data, ())]
    visits = 0
    while stack:
        value, location = stack.pop()
        visits += 1
        if visits > MAX_YAML_GRAPH_NODES:
            return False
        if isinstance(value, (dict, list)):
            if isinstance(value, dict):
                for key, child in value.items():
                    if isinstance(key, str) and COOKIECUTTER_SENTINEL in key:
                        return False
                    stack.append((child, (*location, key)))
            else:
                stack.extend(
                    (child, (*location, index)) for index, child in enumerate(value)
                )
        elif isinstance(value, str) and COOKIECUTTER_SENTINEL in value:
            workflow_name = location == ("name",)
            job_name = (
                len(location) == 3 and location[0] == "jobs" and location[2] == "name"
            )
            step_name = (
                len(location) == 5
                and location[0] == "jobs"
                and location[2] == "steps"
                and isinstance(location[3], int)
                and location[4] == "name"
            )
            event_path = (
                len(location) == 4
                and location[0] in ("on", True)
                and location[1] in ("push", "pull_request", "pull_request_target")
                and location[2] in ("paths", "paths-ignore")
                and isinstance(location[3], int)
            )
            if not (workflow_name or job_name or step_name or event_path):
                return False
    return True


def _load_yaml(
    path: Path,
    *,
    root: Path | None = None,
    analysis_errors: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], _WorkflowLines] | None:
    def incomplete(kind: str, message: str) -> None:
        if analysis_errors is not None:
            analysis_errors.append(_config_analysis_error(path, kind, message))

    if yaml is None:
        incomplete(
            "config_parser_unavailable",
            "GitHub Actions analysis incomplete: YAML parser unavailable",
        )
        return None
    try:
        if root is not None:
            text = read_project_text_no_symlink(
                root.parent if root.is_file() else root,
                path,
                max_bytes=MAX_YAML_BYTES,
                encoding="utf-8",
            )
        else:
            text = read_text_no_symlink(path, max_bytes=MAX_YAML_BYTES, encoding="utf-8")
        if text is None:
            incomplete(
                "config_read_error",
                "GitHub Actions analysis incomplete: YAML file could not be safely read "
                f"(symlink, unreadable file, invalid UTF-8, or size limit {MAX_YAML_BYTES} bytes)",
            )
            return None
        template = _is_cookiecutter_template(path, root)
        parse_text = _cookiecutter_yaml(text) if template else text
        loaded = (
            None
            if parse_text is None
            else load_yaml_with_locations(
                parse_text, max_depth=MAX_YAML_GRAPH_DEPTH, max_nodes=MAX_YAML_GRAPH_NODES
            )
        )
        if loaded is None:
            incomplete(
                "config_parse_error",
                "GitHub Actions analysis incomplete: invalid YAML or YAML resource limit exceeded",
            )
            return None
        raw, source = loaded
    except Exception:
        incomplete(
            "config_parse_error",
            "GitHub Actions analysis incomplete: YAML parser failed",
        )
        return None
    if not isinstance(raw, dict):
        incomplete("config_parse_error", "GitHub Actions analysis incomplete: expected a YAML mapping")
        return None
    if not _yaml_graph_is_safe(raw):
        incomplete("config_parse_error", "GitHub Actions analysis incomplete: unsafe YAML graph")
        return None
    if template and not _cookiecutter_variables_are_display_only(raw):
        incomplete(
            "config_parse_error",
            "GitHub Actions analysis incomplete: unsupported dynamic workflow template",
        )
        return None
    return raw, _WorkflowLines(text, source, parse_text)


def _yaml_graph_is_safe(value: Any) -> bool:
    active: set[int] = set()
    visited: set[int] = set()
    nodes_seen = 0
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]

    while stack:
        current, depth, leaving = stack.pop()
        if depth > MAX_YAML_GRAPH_DEPTH:
            return False

        if isinstance(current, dict):
            current_id = id(current)
            if leaving:
                active.discard(current_id)
                visited.add(current_id)
                continue
            if current_id in active:
                return False
            if current_id in visited:
                continue

            nodes_seen += 1
            if nodes_seen > MAX_YAML_GRAPH_NODES:
                return False

            active.add(current_id)
            stack.append((current, depth, True))
            for child in reversed(tuple(current.values())):
                stack.append((child, depth + 1, False))
            continue

        if isinstance(current, list):
            current_id = id(current)
            if leaving:
                active.discard(current_id)
                visited.add(current_id)
                continue
            if current_id in active:
                return False
            if current_id in visited:
                continue

            nodes_seen += 1
            if nodes_seen > MAX_YAML_GRAPH_NODES:
                return False

            active.add(current_id)
            stack.append((current, depth, True))
            for child in reversed(tuple(current)):
                stack.append((child, depth + 1, False))
            continue

        nodes_seen += 1
        if nodes_seen > MAX_YAML_GRAPH_NODES:
            return False

    return True


def _line_for_contains(lines: list[str], needle: str, *, start: int = 1) -> int:
    search_lines = lines.parsed_lines if isinstance(lines, _WorkflowLines) else lines
    for lineno, line in enumerate(search_lines, 1):
        if lineno < start:
            continue
        if needle in line:
            return lineno
    return 1


def _line_for_key(lines: list[str], key: str) -> int:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:")
    for lineno, line in enumerate(lines, 1):
        if pattern.search(line):
            return lineno
    return 1


def _source_for_lines(lines: list[str]) -> YamlSource | None:
    if isinstance(lines, _WorkflowLines):
        return lines.source
    loaded = load_yaml_with_locations(
        "\n".join(lines),
        max_depth=MAX_YAML_GRAPH_DEPTH,
        max_nodes=MAX_YAML_GRAPH_NODES,
    )
    return loaded[1] if loaded is not None else None


def _line_for_trigger(data: dict[str, Any], lines: list[str], name: str) -> int:
    source = _source_for_lines(lines)
    if source is None:
        return 1
    on_key = "on" if "on" in data else True
    trigger = _on_value(data)
    if isinstance(trigger, dict):
        path = (on_key, name)
    elif isinstance(trigger, list):
        path = (on_key, trigger.index(name))
    else:
        return source.line_for_path((on_key,), key=False) or 1
    return source.line_for_path(path) or source.line_for_path((on_key,)) or 1


def _line_for_job_field(lines: list[str], job_id: Any, field: str) -> int:
    source = _source_for_lines(lines)
    if source is None:
        return 1
    return (
        source.line_for_path(("jobs", job_id, field))
        or source.line_for_path(("jobs", job_id))
        or 1
    )


def _is_inline_ignored(
    lines: list[str], line: int, rule_id: str, *, yaml_only: bool = True
) -> bool:
    if not 1 <= line <= len(lines):
        return False
    needle = f"skylos: ignore[{rule_id}]"
    if not any(needle in lines[idx] for idx in (line - 2, line - 1) if idx >= 0):
        return False
    if not yaml_only:
        # Existing script findings can be anchored inside run block scalars.
        # Preserve their script-comment behavior; they need a separate parser.
        return True
    source = _source_for_lines(lines)
    if source is None:
        return False
    for idx in (line - 2, line - 1):
        if idx < 0:
            continue
        # A trailing ignore belongs only to its own line. Only a standalone
        # comment may apply to the next line, never quoted or block-scalar text.
        if idx == line - 2 and not lines[idx].lstrip().startswith("#"):
            continue
        comment = source.comment_on_line(idx + 1)
        if comment is not None and needle in comment:
            return True
    return False


def _finding_identity(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding.get("rule_id"),
        finding.get("file"),
        finding.get("line"),
        finding.get("name"),
        finding.get("message"),
        finding.get("value"),
    )


def _add_finding(
    findings: list[dict[str, Any]],
    lines: list[str],
    finding: dict[str, Any],
    *,
    yaml_only: bool = False,
):
    if _is_inline_ignored(
        lines,
        int(finding.get("line", 1)),
        str(finding["rule_id"]),
        yaml_only=yaml_only,
    ):
        return
    identity = _finding_identity(finding)
    if any(_finding_identity(existing) == identity for existing in findings):
        return
    findings.append(finding)


def _trigger_contains(trigger: Any, name: str) -> bool:
    if isinstance(trigger, str):
        return trigger == name
    if isinstance(trigger, list):
        return name in trigger
    if isinstance(trigger, dict):
        return name in trigger
    return False


def _on_value(data: dict[str, Any]) -> Any:
    if "on" in data:
        return data.get("on")
    # PyYAML parses the GitHub Actions key "on" as boolean True under YAML 1.1.
    return data.get(True)


def _jobs(data: dict[str, Any]) -> Iterator[tuple[Any, dict[str, Any]]]:
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_id, job in jobs.items():
        if isinstance(job, dict):
            # Keep the parsed key for source lookup (YAML 1.1 resolves names
            # such as on/yes to booleans). Message formatting still uses str.
            yield job_id, job


def _is_reusable_job(job: dict[str, Any]) -> bool:
    return isinstance(job.get("uses"), str)


def _iter_strings(value: Any) -> Iterator[str]:
    visited: set[int] = set()
    nodes_seen = 0
    stack: list[tuple[Any, int]] = [(value, 0)]

    while stack:
        current, depth = stack.pop()
        if depth > MAX_YAML_GRAPH_DEPTH:
            return

        nodes_seen += 1
        if nodes_seen > MAX_YAML_GRAPH_NODES:
            return

        if isinstance(current, str):
            yield current
        elif isinstance(current, dict):
            current_id = id(current)
            if current_id in visited:
                continue
            visited.add(current_id)
            for child in reversed(tuple(current.values())):
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            current_id = id(current)
            if current_id in visited:
                continue
            visited.add(current_id)
            for child in reversed(tuple(current)):
                stack.append((child, depth + 1))


def _iter_env_blocks(
    data: dict[str, Any], *, is_workflow: bool
) -> Iterator[dict[str, Any]]:
    env = data.get("env")
    if isinstance(env, dict):
        yield env
    if is_workflow:
        for _job_id, job in _jobs(data):
            env = job.get("env")
            if isinstance(env, dict):
                yield env
            steps = job.get("steps")
            if isinstance(steps, list):
                for step in steps:
                    if isinstance(step, dict) and isinstance(step.get("env"), dict):
                        yield step["env"]
    else:
        runs = data.get("runs")
        steps = runs.get("steps") if isinstance(runs, dict) else None
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict) and isinstance(step.get("env"), dict):
                    yield step["env"]


def _uses_repo(value: str) -> str:
    value = value.strip()
    if value.startswith("docker://"):
        return "docker://"
    if "@" in value:
        value = value.rsplit("@", 1)[0]
    return value.lower()


def _uses_matches(value: str, target: str) -> bool:
    return _uses_repo(value) == target.lower()


def _actions_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    return None


def _permissions_write(
    permissions: Any,
    *,
    permission: str | None = None,
) -> bool:
    if isinstance(permissions, str):
        return permissions == "write-all"
    if not isinstance(permissions, dict):
        return False
    for key, value in permissions.items():
        if permission is not None and str(key) != permission:
            continue
        if str(value).lower() == "write":
            return True
    return False


def _effective_permissions_write(
    job: dict[str, Any],
    workflow_permissions: Any,
    *,
    permission: str | None = None,
) -> bool:
    if "permissions" in job:
        return _permissions_write(job.get("permissions"), permission=permission)
    return _permissions_write(workflow_permissions, permission=permission)


def _line_for_value(lines: list[str], value: Any) -> int:
    if isinstance(value, str):
        first_line = value.strip().splitlines()[0] if value.strip() else value
        return _line_for_contains(lines, first_line)
    return 1


def _is_release_like_workflow(trigger: Any) -> bool:
    if _trigger_contains(trigger, "release"):
        return True
    if isinstance(trigger, dict):
        push = trigger.get("push")
        if isinstance(push, dict) and "tags" in push:
            return True
    return False


def _workflow_has_dangerous_trigger(trigger: Any) -> bool:
    return _trigger_contains(trigger, "pull_request_target") or _trigger_contains(
        trigger, "workflow_run"
    )


def _steps_from_workflow(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    yield step


def _steps_from_action(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
    runs = data.get("runs")
    if not isinstance(runs, dict):
        return
    steps = runs.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, dict):
                yield step


def _job_uses_from_workflow(data: dict[str, Any]) -> Iterator[str]:
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job in jobs.values():
        if isinstance(job, dict) and isinstance(job.get("uses"), str):
            yield job["uses"]


def _iter_steps(data: dict[str, Any], *, is_workflow: bool) -> Iterator[dict[str, Any]]:
    if is_workflow:
        yield from _steps_from_workflow(data)
    else:
        yield from _steps_from_action(data)


def _steps_with_jobs(
    data: dict[str, Any], *, is_workflow: bool
) -> Iterator[tuple[dict[str, Any], dict[str, Any] | None]]:
    """Each step with its job; None for a composite action's steps."""
    if not is_workflow:
        for step in _steps_from_action(data):
            yield step, None
        return
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job in jobs.values():
        if isinstance(job, dict) and isinstance(job.get("steps"), list):
            for step in job["steps"]:
                if isinstance(step, dict):
                    yield step, job


def _run_starts_in_workspace(
    data: dict[str, Any], job: dict[str, Any] | None, step: dict[str, Any]
) -> bool:
    """Default-deny: a bash/sh run block on a Linux or macOS runner whose
    working directories are all inside the workspace. A composite action's
    runner and starting directory belong to its caller, so they are unknown."""
    if job is None or not _runs_on_posix(job.get("runs-on")):
        return False
    # BASH_ENV (ENV for sh) names a file every later bash step sources first.
    if any(
        _env_may_set(env, {"bash_env", "env"}) for env in _env_layers(data, job, step)
    ):
        return False
    if any(_mentions(run, "BASH_ENV") for run in _job_runs(job)):
        return False
    layers = (data, job)
    shells = [_default_run_setting(layer, "shell") for layer in layers]
    directories = [_default_run_setting(layer, "working-directory") for layer in layers]
    shells.append(step.get("shell"))
    directories.append(step.get("working-directory"))
    return all(
        shell is None or (isinstance(shell, str) and shell.strip() in POSIX_SHELLS)
        for shell in shells
    ) and _runs_in_workspace(directories)


def _home_is_default(
    data: dict[str, Any], job: dict[str, Any] | None, step: dict[str, Any]
) -> bool:
    """Whether HOME is the runner's own for this step: no env sets it and no
    run block in the job assigns it or writes it to $GITHUB_ENV. Unknown for
    a composite action, whose calling job is not visible."""
    if job is None:
        return False
    if any(_env_may_set(env, {"home"}) for env in _env_layers(data, job, step)):
        return False
    return not any(
        redefines_home(run) or (_mentions(run, "HOME") and _mentions(run, "GITHUB_ENV"))
        for run in _job_runs(job)
    )


def _env_layers(
    data: dict[str, Any], job: dict[str, Any], step: dict[str, Any]
) -> list[Any]:
    container = job.get("container")
    container_env = container.get("env") if isinstance(container, dict) else None
    return [data.get("env"), job.get("env"), container_env, step.get("env")]


def _env_may_set(env: Any, names: set[str]) -> bool:
    if isinstance(env, dict):
        return any(str(name).strip().lower() in names for name in env)
    return env is not None  # an expression can set any variable


def _job_runs(job: dict[str, Any]) -> list[str]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return []
    return [
        step["run"]
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("run"), str)
    ]


def _mentions(run: str, name: str) -> bool:
    return name in run or name in dequote_shell(run)


def _runs_on_posix(runs_on: Any) -> bool:
    labels = [runs_on] if isinstance(runs_on, str) else runs_on
    if not isinstance(labels, list) or not labels:
        return False
    if not all(isinstance(label, str) for label in labels):
        return False
    lowered = [label.strip().lower() for label in labels]
    if any("${{" in label or label.startswith("windows") for label in lowered):
        return False
    return any(
        label.startswith(POSIX_RUNNER_PREFIXES) or label in POSIX_RUNNER_LABELS
        for label in lowered
    )


def _default_run_setting(mapping: dict[str, Any], key: str) -> Any:
    defaults = mapping.get("defaults")
    run = defaults.get("run") if isinstance(defaults, dict) else None
    return run.get(key) if isinstance(run, dict) else None


def _runs_in_workspace(directories: list[Any]) -> bool:
    """Whether a run block starts in the checked-out workspace: every working
    directory set for it is relative to it, without ".." or expressions."""
    for directory in directories:
        if directory is None:
            continue
        if not isinstance(directory, str):
            return False
        text = WORKSPACE_EXPR_RE.sub("", directory.strip()).replace("\\", "/")
        if (
            text.startswith(("/", "~", "$"))
            or "${{" in text
            or ":" in text
            or ".." in text.split("/")
        ):
            return False
    return True


def _is_false(value: Any) -> bool:
    if value is False:
        return True
    return isinstance(value, str) and value.lower() == "false"


_GITHUB_OWNED_ACTION_OWNERS = frozenset({"actions", "github"})


def _unpinned_uses_severity(value: str) -> str:
    value = value.strip()
    owner, slash, rest = value.partition("/")
    path, at, ref = rest.rpartition("@")
    if (
        slash
        and at
        and owner.lower() in _GITHUB_OWNED_ACTION_OWNERS
        and ref.strip()
        and "${{" not in value
        and all(part not in ("", ".", "..") for part in path.split("/"))
    ):
        return "LOW"
    return "HIGH"


def _is_third_party_action(value: str) -> bool:
    """A remote action whose code neither the repository nor GitHub owns."""
    value = value.strip()
    if not value or value.startswith(("./", "../")):
        return False
    if value.lower().startswith("docker://"):
        return True
    owner = value.partition("/")[0].lower()
    return owner not in _GITHUB_OWNED_ACTION_OWNERS


def _is_pinned_uses(value: str) -> bool:
    value = value.strip()
    if not value or value.startswith("./") or value.startswith("../"):
        return True
    if value.startswith("docker://"):
        return "@" in value
    if "${{" in value:
        return False
    if "@" not in value:
        return False
    ref = value.rsplit("@", 1)[1].strip()
    return bool(FULL_SHA_RE.fullmatch(ref))


# How a job reaches the pull request's own code under pull_request_target:
# a checkout of the head or merge ref, or a git/gh command that fetches it.
_PR_CODE_REF_RE = re.compile(
    r"github\.event\.pull_request\.(?:head|merge_commit_sha)|github\.head_ref"
    r"|refs/pull/|\bpull/\$\{\{",
    re.IGNORECASE,
)
_PR_CODE_FETCH_RE = re.compile(
    r"\bgh\s+pr\s+checkout\b|\bgit\s+(?:fetch|checkout|pull)\b[^\n]*\bpull/",
    re.IGNORECASE,
)
_EVENT_NAME_RE = re.compile(
    r"github\.event_name\s*==\s*['\"]([A-Za-z_]+)['\"]", re.IGNORECASE
)


def _job_events(job: dict[str, Any]) -> set[str] | None:
    """Events a job's ``if`` limits it to, when it is only
    ``github.event_name == '...'`` checks joined by ``||``; otherwise None."""
    condition = job.get("if")
    if not isinstance(condition, str):
        return None
    events = set(_EVENT_NAME_RE.findall(condition))
    rest = _EVENT_NAME_RE.sub("", condition)
    rest = re.sub(r"\$\{\{|\}\}|\|\||[()\s]", "", rest)
    return events if events and not rest else None


def _job_reads_pr_code(job: dict[str, Any]) -> bool:
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        uses = step.get("uses")
        if isinstance(uses, str) and _uses_matches(uses, "actions/checkout"):
            with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
            target = " ".join(
                str(with_block.get(key, "")) for key in ("ref", "repository")
            )
            if _PR_CODE_REF_RE.search(target):
                return True
        run = step.get("run")
        if isinstance(run, str) and (
            _PR_CODE_FETCH_RE.search(run) or _PR_CODE_REF_RE.search(run)
        ):
            return True
    return False


def _pull_request_target_is_isolated(data: dict[str, Any]) -> bool:
    """True when no job that runs on pull_request_target can hand the pull
    request's author anything worth taking.

    The trigger is dangerous because it runs with the base repository's
    token and secrets. A job is isolated when its permissions are declared
    (an undeclared token may be read-write), it doesn't interpolate PR-
    controlled context into commands, and, if it reads the PR's code, it does
    so read-only: no write scope or OIDC token, no secrets, no persisted
    checkout credentials and no shared cache to poison. Jobs that never read
    the PR's code may hold privileges: they run the base branch's workflow.
    """
    workflow_permissions = data.get("permissions")
    for _job_id, job in _jobs(data):
        events = _job_events(job)
        if events is not None and "pull_request_target" not in events:
            continue
        if _is_reusable_job(job):
            return False
        if "permissions" not in job and "permissions" not in data:
            return False
        steps = [step for step in job.get("steps") or [] if isinstance(step, dict)]
        for step in steps:
            if any(
                interpolates_untrusted(data, job, step, text)
                for text in _iter_strings(step.get("run"))
            ):
                return False
        if not _job_reads_pr_code(job):
            continue
        permissions = job.get("permissions", workflow_permissions)
        if _effective_permissions_write(job, workflow_permissions):
            return False
        if isinstance(permissions, str) and permissions != "read-all":
            return False
        job_text = "\n".join(_iter_strings(job))
        if re.search(r"\bsecrets\.|\bgithub\.token\b|\bGITHUB_TOKEN\b", job_text):
            return False
        for step in steps:
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            with_block = step.get("with") if isinstance(step.get("with"), dict) else {}
            if _cache_action_enabled(uses, with_block):
                return False
            if _uses_matches(uses, "actions/checkout") and (
                _actions_bool(with_block.get("persist-credentials")) is not False
            ):
                return False
    return True


def _scan_triggers(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D290"
    if rule_id in ignore:
        return

    trigger = _on_value(data)
    labeler_only = False
    jobs = list(_jobs(data))
    if len(jobs) == 1:
        _job_id, job = jobs[0]
        steps = job.get("steps")
        if isinstance(steps, list) and len(steps) == 1 and isinstance(steps[0], dict):
            uses_value = steps[0].get("uses")
            labeler_only = isinstance(uses_value, str) and _uses_matches(
                uses_value, "actions/labeler"
            )

    if (
        _trigger_contains(trigger, "pull_request_target")
        and not labeler_only
        and not _pull_request_target_is_isolated(data)
    ):
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-dangerous-trigger",
                message=(
                    "Workflow uses pull_request_target; avoid running untrusted PR "
                    "content with a privileged token."
                ),
                file=path,
                line=_line_for_trigger(data, lines, "pull_request_target"),
                severity="HIGH",
                value="pull_request_target",
            ),
            yaml_only=True,
        )
    if _trigger_contains(trigger, "workflow_run"):
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-dangerous-trigger",
                message=(
                    "Workflow uses workflow_run; avoid chaining privileged workflow "
                    "execution from potentially attacker-influenced workflows."
                ),
                file=path,
                line=_line_for_trigger(data, lines, "workflow_run"),
                severity="HIGH",
                value="workflow_run",
            ),
            yaml_only=True,
        )


def _line_for_yaml_path(lines: list[str], path: tuple[Any, ...]) -> int | None:
    source = _source_for_lines(lines)
    return source.line_for_path(path) if source is not None else None


def _scan_permissions(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    """Token scope the workflow hands out. A job's own ``permissions`` replaces
    the workflow's entirely, so a workflow-level value matters only for the
    jobs that inherit it. Missing permissions are reported once per workflow,
    naming the jobs that run with the repository default, not again per job."""
    rule_id = "SKY-D291"
    if rule_id in ignore:
        return

    inheriting = [str(job_id) for job_id, job in _jobs(data) if "permissions" not in job]
    permissions = data.get("permissions")
    if "permissions" not in data:
        if inheriting:
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-default-permissions",
                    message=(
                        "Workflow declares no permissions, so "
                        f"{_job_list(inheriting)} run with the repository's default "
                        "GITHUB_TOKEN permissions, which may be read-write. Set "
                        "permissions: {} at the top and grant each job only what "
                        "it needs."
                    ),
                    file=path,
                    line=1,
                    severity="MEDIUM",
                    value="default_permissions",
                ),
            )
    elif isinstance(permissions, str) and permissions in {"read-all", "write-all"}:
        if inheriting:
            severity = "MEDIUM"
            if permissions == "write-all":
                severity = "HIGH"
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-broad-permissions",
                    message=(
                        f"Workflow grants {permissions} permissions to GITHUB_TOKEN "
                        f"for {_job_list(inheriting)}."
                    ),
                    file=path,
                    line=_line_for_key(lines, "permissions"),
                    severity=severity,
                    value=permissions,
                ),
            )
    elif isinstance(permissions, dict) and len(inheriting) > 1:
        for permission, level in permissions.items():
            if str(level).lower() != "write":
                continue
            severity = WRITE_PERMISSION_SEVERITY.get(str(permission), "MEDIUM")
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-broad-permissions",
                    message=(
                        f"Workflow-level permission {permission}: write reaches "
                        f"{_job_list(inheriting)}. Grant write access only on the "
                        "job that needs it."
                    ),
                    file=path,
                    line=_line_for_yaml_path(lines, ("permissions", permission))
                    or _line_for_contains(lines, str(permission)),
                    severity=severity,
                    value=f"{permission}:write",
                ),
            )

    for job_id, job in _jobs(data):
        job_permissions = job.get("permissions")
        if isinstance(job_permissions, str) and job_permissions in {
            "read-all",
            "write-all",
        }:
            severity = "HIGH" if job_permissions == "write-all" else "MEDIUM"
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-broad-permissions",
                    message=f"Job {job_id} grants {job_permissions} permissions.",
                    file=path,
                    line=_line_for_job_field(lines, job_id, "permissions"),
                    severity=severity,
                    value=f"{job_id}:{job_permissions}",
                ),
            )


def _job_list(job_ids: list[str], *, limit: int = 5) -> str:
    if len(job_ids) == 1:
        return f"job {job_ids[0]}"
    shown = ", ".join(job_ids[:limit])
    more = len(job_ids) - limit
    if more > 0:
        return f"jobs {shown} and {more} more"
    return f"jobs {shown}"


def _scan_uses(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
) -> None:
    workflow_uses = _job_uses_from_workflow(data) if is_workflow else ()
    for job_uses in workflow_uses:
        if "SKY-D292" not in ignore and not _is_pinned_uses(job_uses):
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id="SKY-D292",
                    name="github-actions-unpinned-uses",
                    message="Reusable workflow reference is not pinned to a full commit SHA.",
                    file=path,
                    line=_line_for_contains(lines, job_uses),
                    severity=_unpinned_uses_severity(job_uses),
                    value=job_uses,
                ),
            )

    for step in _iter_steps(data, is_workflow=is_workflow):
        uses_value = step.get("uses")
        if not isinstance(uses_value, str):
            continue

        if "SKY-D292" not in ignore and not _is_pinned_uses(uses_value):
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id="SKY-D292",
                    name="github-actions-unpinned-uses",
                    message="Action reference is not pinned to a full commit SHA.",
                    file=path,
                    line=_line_for_contains(lines, uses_value),
                    severity=_unpinned_uses_severity(uses_value),
                    value=uses_value,
                ),
            )


_UPLOAD_ARTIFACT_VERSION_RE = re.compile(r"^v(\d+)(?:\.(\d+)(?:\.\d+)?)?$")
_WORKSPACE_PREFIX_RE = re.compile(
    r"^(?:\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?)(?:/|$)"
)


def _literal_action_input(value: Any) -> Any:
    """Normalize only a complete, bounded scalar Actions literal expression."""
    if not isinstance(value, str) or len(value) > 4096:
        return value
    match = re.fullmatch(
        r"\$\{\{\s*(true|false|null|'(?:[^']|'')*')\s*\}\}",
        value.strip(), re.IGNORECASE,
    )
    if match is None:
        return value
    literal = match.group(1)
    if literal.lower() == "true":
        return True
    if literal.lower() == "false":
        return False
    if literal.lower() == "null":
        return None
    return literal[1:-1].replace("''", "'")


def _action_input_reference(value: Any) -> str | None:
    """Return an input's reference spelling, never an embedded credential value."""
    if not isinstance(value, str) or len(value) > 512:
        return None
    match = re.fullmatch(
        r"\$\{\{\s*((?:secrets|env|inputs|vars|steps|needs)"
        r"(?:\.[A-Za-z_][A-Za-z0-9_-]*){1,5})\s*\}\}",
        value.strip(), re.IGNORECASE,
    )
    if match is not None:
        return match.group(1)
    match = re.fullmatch(
        r"\$\{\{\s*(secrets|env|inputs|vars)\[\s*'([A-Za-z_][A-Za-z0-9_-]*)'\s*\]"
        r"\s*\}\}", value.strip(), re.IGNORECASE,
    )
    if match is not None:
        return match.group(1) + "." + match.group(2)
    return None


def _workspace_relative(path: str) -> str:
    """``path`` relative to the workspace, without ``./`` or a trailing slash."""
    path = _WORKSPACE_PREFIX_RE.sub("", path.strip())
    parts = [part for part in path.split("/") if part not in {"", "."}]
    return "/".join(parts)


def _upload_skips_hidden_files(uses_value: str, with_config: dict[str, Any]) -> bool:
    """actions/upload-artifact leaves out hidden files such as ``.git`` from
    v4.4.0 unless ``include-hidden-files`` is set. A floating ``@v4`` resolves
    to the newest v4 release; a SHA pin's version is unknown."""
    hidden = _literal_action_input(with_config.get("include-hidden-files"))
    hidden_state = _actions_bool(hidden)
    if hidden_state is True:
        return False
    if "include-hidden-files" in with_config and hidden_state is None:
        # An input or expression may enable hidden files at runtime.
        return False
    ref = uses_value.rsplit("@", 1)[1].strip() if "@" in uses_value else ""
    match = _UPLOAD_ARTIFACT_VERSION_RE.match(ref)
    if match is None:
        return False
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else None
    return major > 4 or (major == 4 and (minor is None or minor >= 4))


def _artifact_pattern_covers_file(
    pattern: str, target: str, *, directory_only: bool = False
) -> bool | None:
    """Match the supported Actions glob syntax, including implicit descendants.

    Unknown syntax cannot prove that a negative pattern excludes credentials.
    Match path segments separately so ``*`` cannot consume a slash.
    """
    unsupported = ("$", "{", "}", "(", ")", "\\")
    if len(pattern) > 4096 or any(char in pattern for char in unsupported):
        return None
    pattern_parts = pattern.split("/") if pattern else []
    target_parts = target.split("/")
    if len(pattern_parts) > 128 or len(target_parts) > 128:
        return None
    positions = {0}
    for part in pattern_parts:
        next_positions = set()
        for position in positions:
            if part == "**":
                next_positions.update(range(position, len(target_parts) + 1))
            elif position < len(target_parts) and fnmatchcase(
                target_parts[position], part
            ):
                next_positions.add(position + 1)
        positions = next_positions
        if not positions:
            return False
    # A trailing separator matches directories, never the credential file itself.
    if directory_only:
        return any(position < len(target_parts) for position in positions)
    # Actions glob includes descendants of matching directories by default.
    return bool(positions)


def _upload_includes_checkout(step: dict[str, Any], checkout_dir: str) -> str | None:
    """The uploaded path that holds the checkout's ``.git`` directory, if any."""
    uses_value = step.get("uses")
    if not isinstance(uses_value, str) or not _uses_matches(
        uses_value, "actions/upload-artifact"
    ):
        return None
    with_config = step.get("with") if isinstance(step.get("with"), dict) else {}
    upload = with_config.get("path")
    if not isinstance(upload, str) or _upload_skips_hidden_files(uses_value, with_config):
        return None
    target = ".git/config"
    if checkout_dir:
        target = checkout_dir + "/" + target
    included = None
    for entry in upload.splitlines():
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        excluded = False
        pattern = entry
        while pattern.startswith("!"):
            excluded = not excluded
            pattern = pattern[1:].strip()
        if not pattern:
            continue
        if excluded and pattern.startswith(("/", "~")):
            # An absolute exclusion cannot be equated with a workspace-relative
            # path. Only a recognized workspace prefix establishes that relation.
            matched = None
        else:
            matched = _artifact_pattern_covers_file(
                _workspace_relative(pattern), target,
                directory_only=pattern.endswith("/"),
            )
        if excluded:
            if matched is True:
                included = None
        elif matched is not False:
            included = entry
    return included


def _checkout_credential(with_config: dict[str, Any]) -> tuple[str, bool]:
    """The persisted credential and whether GITHUB_TOKEN scopes constrain it."""
    if _literal_action_input(with_config.get("ssh-key")):
        # Checkout v4 configures HTTP token auth as well as its SSH command.
        token_config = dict(with_config)
        del token_config["ssh-key"]
        token_name, _ = _checkout_credential(token_config)
        ssh_name = "the configured checkout SSH key"
        reference = _action_input_reference(with_config.get("ssh-key"))
        if reference is not None:
            ssh_name += " from " + reference
        return f"{token_name} and {ssh_name}", False
    token = with_config.get("token")
    if token is None:
        return "GITHUB_TOKEN", True
    if isinstance(token, str) and re.fullmatch(
        r"\s*\$\{\{\s*(?:github\s*(?:\.\s*token|\[\s*'token'\s*\])"
        r"|secrets\s*(?:\.\s*GITHUB_TOKEN|\[\s*'GITHUB_TOKEN'\s*\]))\s*\}\}\s*",
        token, re.I,
    ):
        return "GITHUB_TOKEN", True
    token_name = "the configured checkout token"
    reference = _action_input_reference(token)
    if reference is not None:
        token_name += " from " + reference
    return token_name, False


def _token_write_scopes(job: dict[str, Any], workflow_permissions: Any) -> list[str]:
    """GITHUB_TOKEN scopes the job is explicitly granted write on. ``id-token``
    mints OIDC tokens and adds nothing to the persisted repository token."""
    permissions = job.get("permissions", workflow_permissions)
    if isinstance(permissions, str):
        return ["write-all"] if permissions == "write-all" else []
    if not isinstance(permissions, dict):
        return []
    return [
        str(scope)
        for scope, level in permissions.items()
        if str(level).lower() == "write" and str(scope) != "id-token"
    ]


def _persisted_credential_exposure(
    steps: list[Any],
    index: int,
    *,
    write_scopes: list[str],
    outsider_events: list[str],
) -> str | None:
    """Why the credential a checkout persists can reach someone
    the job did not already hand it to, or None without such evidence.

    zizmor's ``artipacked`` names the clearest path, an artifact that uploads
    the checkout. The others: the checkout fetches a pull request's code in a
    job that accounts without write access can start, so their code runs
    beside the token, or a write-scoped token sits next to a later third-party
    action. A step the repository or GitHub owns already holds the token, so
    it is not a new reader; a token whose scope is undeclared is reported by
    SKY-D291 instead.
    """
    checkout = steps[index]
    with_config = checkout.get("with") if isinstance(checkout.get("with"), dict) else {}
    credential, github_token = _checkout_credential(with_config)
    checkout_path = with_config.get("path")
    checkout_dir = _workspace_relative(checkout_path) if isinstance(checkout_path, str) else ""
    later = [step for step in steps[index + 1 :] if isinstance(step, dict)]
    for step in later:
        uploaded = _upload_includes_checkout(step, checkout_dir)
        if uploaded is not None:
            return f"a later step uploads {uploaded} as an artifact, .git/config included"
    target = " ".join(str(with_config.get(key, "")) for key in ("ref", "repository"))
    if outsider_events and _PR_CODE_REF_RE.search(target):
        return (
            "it checks out pull request code in a job that accounts without "
            f"write access can start ({', '.join(outsider_events)})"
        )
    if write_scopes or not github_token:
        for step in later:
            uses_value = step.get("uses")
            if isinstance(uses_value, str) and _is_third_party_action(uses_value):
                if github_token:
                    return (
                        f"the token has {', '.join(write_scopes)} write access and the "
                        f"later third-party action {uses_value.strip()} can read it"
                    )
                return (
                    f"the later third-party action {uses_value.strip()} can read "
                    f"{credential}, whose access is not limited by GITHUB_TOKEN permissions"
                )
    return None


def _scan_persisted_checkout_credentials(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
    root: Path | None,
) -> None:
    rule_id = "SKY-D293"
    if rule_id in ignore:
        return
    if is_workflow:
        from skylos.rules.config.cicd.ai_agents import outsider_job_events

        outsiders = outsider_job_events(data, path, root)
        workflow_permissions = data.get("permissions")
        jobs = [
            (job_id, job.get("steps"), _token_write_scopes(job, workflow_permissions))
            for job_id, job in _jobs(data)
        ]
    else:
        # A composite action runs in its caller's job: only an upload inside
        # the action itself is evidence here.
        runs = data.get("runs") if isinstance(data.get("runs"), dict) else {}
        outsiders = {}
        jobs = [(None, runs.get("steps"), [])]
    for job_id, steps, write_scopes in jobs:
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            uses_value = step.get("uses")
            if not isinstance(uses_value, str) or not _uses_matches(
                uses_value, "actions/checkout"
            ):
                continue
            with_config = step.get("with") if isinstance(step.get("with"), dict) else {}
            if _is_false(_literal_action_input(with_config.get("persist-credentials"))):
                continue
            exposure = _persisted_credential_exposure(
                steps,
                index,
                write_scopes=write_scopes,
                outsider_events=outsiders.get(str(job_id), []),
            )
            if exposure is None:
                continue
            credential, _ = _checkout_credential(with_config)
            step_path = (
                ("jobs", job_id, "steps", index, "uses")
                if is_workflow
                else ("runs", "steps", index, "uses")
            )
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-checkout-credentials",
                    message=(
                        f"actions/checkout persists {credential} for later git commands, and "
                        f"{exposure}. Set persist-credentials: false unless a later "
                        "git push needs it."
                    ),
                    file=path,
                    line=_line_for_yaml_path(lines, step_path)
                    or _line_for_contains(lines, uses_value),
                    severity="MEDIUM",
                    value=uses_value,
                ),
            )


def _scan_run_blocks(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
    root: Path | None = None,
) -> None:
    rule_id = "SKY-D294"

    for step, job in _steps_with_jobs(data, is_workflow=is_workflow):
        run_body = step.get("run")
        if not isinstance(run_body, str):
            continue
        for risk in scan_shell_command(
            run_body,
            cwd_in_project=_run_starts_in_workspace(data, job, step),
            home_is_default=_home_is_default(data, job, step),
        ):
            if risk.rule_id in ignore:
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=risk.rule_id,
                    name="github-actions-shell-command-risk",
                    message=risk.message,
                    file=path,
                    line=_line_for_value(lines, run_body),
                    severity=risk.severity,
                    value=risk.rule_id,
                ),
            )
    if rule_id not in ignore:
        _scan_template_injection(
            data, path, lines, findings, is_workflow=is_workflow, root=root
        )


def _scan_template_injection(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    *,
    is_workflow: bool,
    root: Path | None,
) -> None:
    from skylos.rules.config.cicd.template_injection import Scope, job_audiences

    source = _source_for_lines(lines)
    if not is_workflow:
        scope = Scope(data, path, root, False, audience="unknown")
        runs = data.get("runs")
        steps = []
        if isinstance(runs, dict) and isinstance(runs.get("steps"), list):
            steps = runs["steps"]
        for index, step in enumerate(steps):
            if isinstance(step, dict):
                _report_step_injections(
                    findings, lines, source, path, replace(scope, step=step), step,
                    ("runs", "steps", index),
                )
        return
    audiences = job_audiences(data, path, root)
    for job_id, job in _jobs(data):
        audience, events = audiences.get(job_id, ("writers", frozenset()))
        scope = Scope(
            data, path, root, True, job_id, job, None, audience,
            audiences=audiences, events=events,
        )
        container = job.get("container")
        if isinstance(container, dict):
            _report_injections(
                findings, lines, source, path, scope, container.get("options"),
                ("jobs", job_id, "container", "options"),
                f"Job {job_id} container options",
            )
        services = job.get("services")
        if isinstance(services, dict):
            for service, config in services.items():
                if isinstance(config, dict):
                    _report_injections(
                        findings, lines, source, path, scope, config.get("options"),
                        ("jobs", job_id, "services", service, "options"),
                        f"Service {service} options",
                    )
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if isinstance(step, dict):
                _report_step_injections(
                    findings, lines, source, path, replace(scope, step=step), step,
                    ("jobs", job_id, "steps", index),
                )


def _report_step_injections(
    findings: list[dict[str, Any]],
    lines: list[str],
    source: YamlSource | None,
    path: Path,
    scope: Any,
    step: dict[str, Any],
    step_path: tuple[Any, ...],
) -> None:
    from skylos.rules.config.cicd.template_injection import action_sink_inputs

    _report_injections(
        findings, lines, source, path, scope, step.get("run"), (*step_path, "run"),
        "run block",
    )
    uses_value = step.get("uses")
    with_config = step.get("with")
    if not isinstance(uses_value, str) or not isinstance(with_config, dict):
        return
    for input_name in action_sink_inputs(uses_value):
        _report_injections(
            findings, lines, source, path, scope, with_config.get(input_name),
            (*step_path, "with", input_name),
            f"{uses_value} input {input_name}",
        )


def _report_injections(
    findings: list[dict[str, Any]],
    lines: list[str],
    source: YamlSource | None,
    path: Path,
    scope: Any,
    text: Any,
    yaml_path: tuple[Any, ...],
    where: str,
) -> None:
    if not isinstance(text, str) or "${{" not in text:
        return
    injections = scope.injections(text)
    if not injections:
        return
    start_line = None
    if source is not None:
        start_line = source.line_for_path(yaml_path, key=False)
    if start_line is None:
        start_line = _line_for_value(lines, text)
    seen: Counter[str] = Counter()
    for injection in injections:
        needle = injection.raw.splitlines()[0]
        line = _fragment_line(lines, start_line, needle, seen[needle])
        seen[needle] += 1
        reasons = "; ".join(
            f"{item.context} ({item.reason})" for item in injection.sources[:3]
        )
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id="SKY-D294",
                name="github-actions-template-injection",
                message=(
                    f"{where} expands {injection.raw} into code: {reasons}. Pass the "
                    "value through env and quote the variable instead."
                ),
                file=path,
                line=line,
                severity=injection.severity,
                value=f"{where}:{injection.raw}:{seen[needle]}",
            ),
        )


def _fragment_line(lines: list[str], start_line: int, needle: str, skip: int) -> int:
    first = max(start_line, 1)
    for number in range(first, len(lines) + 1):
        count = lines[number - 1].count(needle)
        if skip < count:
            return number
        skip -= count
    return first


def _scan_self_hosted_runners(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D295"
    if rule_id in ignore:
        return

    for job_id, job in _jobs(data):
        if _is_reusable_job(job):
            continue
        runs_on = job.get("runs-on")
        if not runner_may_be_self_hosted(job):
            continue
        if isinstance(runs_on, str):
            value = runs_on
        elif isinstance(runs_on, list):
            value = ",".join(str(label) for label in runs_on)
        elif isinstance(runs_on, dict):
            value = "runner-group" if "group" in runs_on else str(runs_on)
        else:
            value = str(runs_on)

        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-self-hosted-runner",
                message=(
                    f"Job {job_id} uses or may expand to a self-hosted runner. "
                    "Use ephemeral isolated runners for untrusted workflows."
                ),
                file=path,
                line=_line_for_job_field(lines, job_id, "runs-on"),
                severity="HIGH",
                value=value,
            ),
            yaml_only=True,
        )


def _image_is_pinned(image: str) -> bool:
    return "@sha256:" in image.lower()


def _image_tag(image: str) -> str | None:
    if "${{" in image:
        return None
    image = image.split("@", 1)[0]
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return None
    return last.rsplit(":", 1)[1]


def _docker_image_from_command(command: str, args_text: str) -> str | None:
    try:
        args = shlex.split(args_text)
    except ValueError:
        args = args_text.split()
    if not args:
        return None

    if command == "pull":
        idx = 0
        while idx < len(args):
            token = args[idx]
            if token.startswith("--") and "=" in token:
                idx += 1
                continue
            if token in DOCKER_OPTIONS_WITH_ARGS:
                idx += 2
                continue
            if token.startswith("-"):
                idx += 1
                continue
            return token
        return None

    idx = 0
    while idx < len(args):
        token = args[idx]
        if token == "--":
            idx += 1
            continue
        if token.startswith("--") and "=" in token:
            idx += 1
            continue
        if token in DOCKER_OPTIONS_WITH_ARGS:
            idx += 2
            continue
        if token.startswith("-"):
            idx += 1
            continue
        return token
    return None


def _scan_image_value(
    *,
    image: Any,
    rule_id: str,
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    location: str,
) -> None:
    if not isinstance(image, str) or not image:
        return
    if _image_is_pinned(image):
        return
    tag = _image_tag(image)
    severity = "HIGH" if tag in {None, "latest"} else "MEDIUM"
    reason = "unpinned" if tag is None else f"tagged as {tag}, not pinned by digest"
    if "${{" in image:
        reason = "dynamic and cannot be verified as digest-pinned"
        severity = "MEDIUM"
    _add_finding(
        findings,
        lines,
        _finding(
            rule_id=rule_id,
            name="github-actions-unpinned-container-image",
            message=f"{location} container image is {reason}.",
            file=path,
            line=_line_for_value(lines, image),
            severity=severity,
            value=image,
        ),
    )


def _scan_container_images(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
) -> None:
    rule_id = "SKY-D296"
    if rule_id in ignore:
        return

    if is_workflow:
        for job_id, job in _jobs(data):
            container = job.get("container")
            if isinstance(container, str):
                _scan_image_value(
                    image=container,
                    rule_id=rule_id,
                    path=path,
                    lines=lines,
                    findings=findings,
                    location=f"job {job_id}",
                )
            elif isinstance(container, dict):
                _scan_image_value(
                    image=container.get("image"),
                    rule_id=rule_id,
                    path=path,
                    lines=lines,
                    findings=findings,
                    location=f"job {job_id}",
                )

            services = job.get("services")
            if isinstance(services, dict):
                for service, config in services.items():
                    if isinstance(config, str):
                        image = config
                    elif isinstance(config, dict):
                        image = config.get("image")
                    else:
                        image = None
                    _scan_image_value(
                        image=image,
                        rule_id=rule_id,
                        path=path,
                        lines=lines,
                        findings=findings,
                        location=f"service {service}",
                    )

        for step in _iter_steps(data, is_workflow=True):
            uses_value = step.get("uses")
            if isinstance(uses_value, str) and uses_value.startswith("docker://"):
                _scan_image_value(
                    image=uses_value[len("docker://") :],
                    rule_id=rule_id,
                    path=path,
                    lines=lines,
                    findings=findings,
                    location="docker action",
                )
    else:
        runs = data.get("runs")
        if isinstance(runs, dict) and runs.get("using") == "docker":
            _scan_image_value(
                image=runs.get("image"),
                rule_id=rule_id,
                path=path,
                lines=lines,
                findings=findings,
                location="docker action",
            )

    for step in _iter_steps(data, is_workflow=is_workflow):
        run_body = step.get("run")
        if not isinstance(run_body, str):
            continue
        for match in DOCKER_CMD_RE.finditer(run_body):
            image = _docker_image_from_command(
                match.group(1).lower(), match.group("args")
            )
            _scan_image_value(
                image=image,
                rule_id=rule_id,
                path=path,
                lines=lines,
                findings=findings,
                location="docker command",
            )


def _scan_secrets_inherit(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D297"
    if rule_id in ignore:
        return
    for job_id, job in _jobs(data):
        if isinstance(job.get("uses"), str) and job.get("secrets") == "inherit":
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-secrets-inherit",
                    message=(
                        f"Reusable workflow job {job_id} inherits all caller secrets. "
                        "Pass only the specific secrets it needs."
                    ),
                    file=path,
                    line=_line_for_contains(lines, "secrets"),
                    severity="MEDIUM",
                    value=f"{job_id}:inherit",
                ),
            )


def _scan_overprovisioned_secrets(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D298"
    if rule_id in ignore:
        return
    for text in _iter_strings(data):
        if not OVERPROVISIONED_SECRETS_RE.search(text):
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-overprovisioned-secrets",
                message=(
                    "Expression expands the entire secrets context or indexes secrets "
                    "dynamically, which can expose more secrets than intended."
                ),
                file=path,
                line=_line_for_value(lines, text),
                severity="MEDIUM",
                value="secrets_context",
            ),
        )


def _scan_secrets_outside_env(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    root: Path | None = None,
) -> None:
    """A repository secret in a job that accounts without write access can
    start. An environment with required reviewers is what stands between them
    and the secret. Jobs only writers can start (push, schedule, dispatch,
    release) and pull_request runs, which get no secrets from forks, are not
    reported: anyone who can start them can already read repository secrets."""
    rule_id = "SKY-D299"
    if rule_id in ignore:
        return
    from skylos.rules.config.cicd.ai_agents import outsider_job_events

    outsiders = outsider_job_events(data, path, root)
    if not outsiders:
        return
    for job_id, job in _jobs(data):
        if _is_reusable_job(job) or job.get("environment") is not None:
            continue
        events = outsiders.get(str(job_id))
        if not events:
            continue
        for text in _iter_strings(job):
            for match in SECRETS_OUTSIDE_ENV_RE.finditer(text):
                secret_name = match.group(1)
                if secret_name.upper() == "GITHUB_TOKEN":
                    continue
                _add_finding(
                    findings,
                    lines,
                    _finding(
                        rule_id=rule_id,
                        name="github-actions-secrets-outside-environment",
                        message=(
                            f"Job {job_id} references secret {secret_name} without a "
                            "dedicated GitHub environment, and accounts without "
                            f"write access can start it ({', '.join(events)})."
                        ),
                        file=path,
                        line=_line_for_value(lines, text),
                        severity="MEDIUM",
                        value=f"{job_id}:{secret_name}",
                    ),
                )


def _run_line_writes_env_unsafely(line: str) -> bool:
    if not GITHUB_ENV_DEST_RE.search(line):
        return False
    if (
        ">>" not in line
        and ">" not in line
        and "tee" not in line.lower()
        and "|" not in line
    ):
        return False
    before = re.split(
        r">>|>|\|\s*tee|\|\s*out-file|\|\s*add-content",
        line,
        maxsplit=1,
        flags=re.I,
    )[0]
    stripped = before.strip()
    if re.fullmatch(r"echo\s+['\"][A-Za-z_][A-Za-z0-9_]*=[^$`]*['\"]\s*", stripped):
        return False
    return True


def _scan_github_env_writes(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
) -> None:
    rule_id = "SKY-D300"
    if rule_id in ignore:
        return
    for step in _iter_steps(data, is_workflow=is_workflow):
        run_body = step.get("run")
        if not isinstance(run_body, str):
            continue
        if any(_run_line_writes_env_unsafely(line) for line in run_body.splitlines()):
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-dangerous-env-file",
                    message=(
                        "run block writes non-literal or command-derived data to "
                        "GITHUB_ENV/GITHUB_PATH."
                    ),
                    file=path,
                    line=_line_for_key(lines, "run"),
                    severity="MEDIUM",
                    value="github_env_write",
                ),
            )


def _scan_hardcoded_container_credentials(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D301"
    if rule_id in ignore:
        return

    def check_credentials(credentials: Any, location: str) -> None:
        if not isinstance(credentials, dict):
            return
        password = credentials.get("password")
        if not isinstance(password, str) or "${{" in password:
            return
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-hardcoded-container-credentials",
                message=f"{location} container registry password is hardcoded.",
                file=path,
                line=_line_for_value(lines, password),
                severity="HIGH",
                value=location,
            ),
        )

    for job_id, job in _jobs(data):
        container = job.get("container")
        if isinstance(container, dict):
            check_credentials(container.get("credentials"), f"job {job_id}")
        services = job.get("services")
        if isinstance(services, dict):
            for service, config in services.items():
                if isinstance(config, dict):
                    check_credentials(config.get("credentials"), f"service {service}")


def _scan_github_app_tokens(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
) -> None:
    rule_id = "SKY-D302"
    if rule_id in ignore:
        return
    for step in _iter_steps(data, is_workflow=is_workflow):
        uses_value = step.get("uses")
        if not isinstance(uses_value, str) or not _uses_matches(
            uses_value, "actions/create-github-app-token"
        ):
            continue
        with_config = step.get("with") if isinstance(step.get("with"), dict) else {}
        if _actions_bool(with_config.get("skip-token-revoke")) is True:
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-github-app-token",
                    message="GitHub App token revocation is disabled.",
                    file=path,
                    line=_line_for_contains(lines, "skip-token-revoke"),
                    severity="HIGH",
                    value="skip-token-revoke",
                ),
            )
        if "owner" in with_config and not (
            "repository" in with_config or "repositories" in with_config
        ):
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-github-app-token",
                    message=(
                        "GitHub App token scopes an owner without limiting repositories."
                    ),
                    file=path,
                    line=_line_for_contains(lines, "owner"),
                    severity="HIGH",
                    value="owner_without_repository",
                ),
            )
        if not any(str(key).startswith("permission-") for key in with_config):
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-github-app-token",
                    message=(
                        "GitHub App token does not specify permission-* inputs and may "
                        "inherit broad installation permissions."
                    ),
                    file=path,
                    line=_line_for_contains(lines, uses_value),
                    severity="HIGH",
                    value="missing_permission_inputs",
                ),
            )


def _scan_conditions(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
) -> None:
    if not is_workflow:
        return

    conditions: list[str] = []
    for _job_id, job in _jobs(data):
        if isinstance(job.get("if"), str):
            conditions.append(job["if"])
        steps = job.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict) and isinstance(step.get("if"), str):
                    conditions.append(step["if"])

    if "SKY-D303" not in ignore:
        for condition in conditions:
            for match in UNSAFE_CONTAINS_RE.finditer(condition):
                context = match.group(1)
                context_lower = context.lower()
                if not any(
                    context_lower == item or context_lower.startswith(item + ".")
                    for item in USER_CONTROLLED_CONTAINS_CONTEXTS
                ):
                    continue
                _add_finding(
                    findings,
                    lines,
                    _finding(
                        rule_id="SKY-D303",
                        name="github-actions-unsound-contains",
                        message=(
                            f"contains(.., {context}) can be bypassed when the "
                            "context is attacker-controlled."
                        ),
                        file=path,
                        line=_line_for_value(lines, condition),
                        severity="HIGH",
                        value=context,
                    ),
                )

    if "SKY-D304" not in ignore:
        for condition in conditions:
            if not BOT_CONDITION_RE.search(condition):
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id="SKY-D304",
                    name="github-actions-spoofable-bot-condition",
                    message=(
                        "Condition checks a spoofable actor context for a bot identity. "
                        "Use event-specific sender IDs where possible."
                    ),
                    file=path,
                    line=_line_for_value(lines, condition),
                    severity="HIGH",
                    value="bot_condition",
                ),
            )

    if "SKY-D305" not in ignore:
        for lineno, line in enumerate(lines, 1):
            match = BLOCK_SCALAR_IF_RE.search(line)
            if not match:
                continue
            indent = len(match.group("indent"))
            block = []
            for next_line in lines[lineno:]:
                if (
                    next_line.strip()
                    and len(next_line) - len(next_line.lstrip()) <= indent
                ):
                    break
                block.append(next_line)
            if any("${{" in block_line for block_line in block):
                _add_finding(
                    findings,
                    lines,
                    _finding(
                        rule_id="SKY-D305",
                        name="github-actions-unsound-condition",
                        message=(
                            "Multiline fenced if expression can evaluate as a truthy "
                            "string. Use an unfenced expression or a stripped block scalar."
                        ),
                        file=path,
                        line=lineno,
                        severity="HIGH",
                        value="multiline_if",
                    ),
                )


def _scan_insecure_commands(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
) -> None:
    rule_id = "SKY-D306"
    if rule_id in ignore:
        return
    for env in _iter_env_blocks(data, is_workflow=is_workflow):
        if _actions_bool(env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS")) is True:
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-insecure-commands",
                    message="ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables legacy commands.",
                    file=path,
                    line=_line_for_contains(lines, "ACTIONS_ALLOW_UNSECURE_COMMANDS"),
                    severity="HIGH",
                    value="ACTIONS_ALLOW_UNSECURE_COMMANDS",
                ),
            )


def _scan_anonymous_definition(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D307"
    if rule_id in ignore or "name" in data:
        return
    _add_finding(
        findings,
        lines,
        _finding(
            rule_id=rule_id,
            name="github-actions-anonymous-definition",
            message="Workflow or action definition has no name field.",
            file=path,
            line=1,
            severity="LOW",
            value="missing_name",
        ),
    )


def _cache_action_enabled(uses_value: str, with_config: dict[str, Any]) -> bool:
    repo = _uses_repo(uses_value)
    if repo not in CACHE_AWARE_ACTIONS:
        return False
    if repo in {
        "actions/cache",
        "mozilla-actions/sccache-action",
        "nix-community/cache-nix-action",
    }:
        return True
    for key in (
        "cache",
        "enable-cache",
        "use-cache",
        "bundler-cache",
        "sccache",
        "cache-binary",
        "package-manager-cache",
        "use-gha-cache",
    ):
        if key in with_config and _actions_bool(with_config.get(key)) is not False:
            return True
    return False


def _scan_cache_poisoning(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D308"
    if rule_id in ignore or not _is_release_like_workflow(_on_value(data)):
        return
    for step in _iter_steps(data, is_workflow=True):
        uses_value = step.get("uses")
        if not isinstance(uses_value, str):
            continue
        with_config = step.get("with") if isinstance(step.get("with"), dict) else {}
        if not _cache_action_enabled(uses_value, with_config):
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-cache-poisoning",
                message=(
                    "Release-like workflow uses a cache-aware action. Avoid restoring "
                    "mutable CI cache state in artifact publishing workflows."
                ),
                file=path,
                line=_line_for_contains(lines, uses_value),
                severity="MEDIUM",
                value=uses_value,
            ),
        )


def _scan_broad_secret_env(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D309"
    if rule_id in ignore:
        return

    def check_env(env: Any, location: str, severity: str) -> None:
        if not isinstance(env, dict):
            return
        for name, value in env.items():
            if not isinstance(value, str):
                continue
            matches = [
                match.group(1)
                for match in SECRETS_OUTSIDE_ENV_RE.finditer(value)
                if match.group(1).upper() != "GITHUB_TOKEN"
            ]
            if not matches:
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-broad-secret-env",
                    message=(
                        f"{location} environment variable {name} exposes secret "
                        f"{matches[0]} to every nested step. Move it to the one step "
                        "that needs it."
                    ),
                    file=path,
                    line=_line_for_value(lines, value),
                    severity=severity,
                    value=f"{location}:{name}",
                ),
            )

    check_env(data.get("env"), "workflow", "HIGH")
    for job_id, job in _jobs(data):
        if _is_reusable_job(job):
            continue
        check_env(job.get("env"), f"job {job_id}", "MEDIUM")


def _scan_oidc_build_script_exposure(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D310"
    if rule_id in ignore:
        return

    workflow_permissions = data.get("permissions")
    for job_id, job in _jobs(data):
        if _is_reusable_job(job) or not _effective_permissions_write(
            job, workflow_permissions, permission="id-token"
        ):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            run_body = step.get("run")
            if not isinstance(run_body, str) or not LOCAL_SCRIPT_RE.search(run_body):
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-oidc-build-script",
                    message=(
                        f"Job {job_id} grants id-token: write while invoking local "
                        "build or release scripts. Keep OIDC publish steps separate "
                        "from repository-controlled build scripts."
                    ),
                    file=path,
                    line=_line_for_value(lines, run_body),
                    severity="HIGH",
                    value=f"{job_id}:id-token-build-script",
                ),
            )
            break


def _scan_artifact_upload_policy(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
) -> None:
    rule_id = "SKY-D311"
    if rule_id in ignore:
        return
    for step in _iter_steps(data, is_workflow=is_workflow):
        uses_value = step.get("uses")
        if not isinstance(uses_value, str) or not _uses_matches(
            uses_value, "actions/upload-artifact"
        ):
            continue
        with_config = step.get("with") if isinstance(step.get("with"), dict) else {}
        if str(with_config.get("if-no-files-found", "")).lower() == "error":
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-lax-artifact-upload",
                message=(
                    "actions/upload-artifact does not set if-no-files-found: error, "
                    "so missing build outputs can pass silently."
                ),
                file=path,
                line=_line_for_contains(lines, uses_value),
                severity="LOW",
                value=uses_value,
            ),
        )


def _scan_js_install_scripts(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
) -> None:
    rule_id = "SKY-D312"
    if rule_id in ignore:
        return
    for step in _iter_steps(data, is_workflow=is_workflow):
        run_body = step.get("run")
        if not isinstance(run_body, str):
            continue
        match = JS_INSTALL_RE.search(run_body)
        if not match:
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-js-install-scripts",
                message=(
                    "JavaScript package installation runs lifecycle scripts. Use "
                    "--ignore-scripts in workflows unless install scripts are required."
                ),
                file=path,
                line=_line_for_contains(lines, match.group(0).strip()),
                severity="MEDIUM",
                value=match.group(0).strip(),
            ),
        )


def _scan_privileged_job_timeouts(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    root: Path | None = None,
) -> None:
    """A privileged job lets outsider-controlled PR code consume its timeout.

    The default job timeout is 360 minutes on hosted and self-hosted runners.
    Only a reachable outsider PR-code path justifies this security advisory.
    """
    rule_id = "SKY-D313"
    if rule_id in ignore:
        return

    from skylos.rules.config.cicd.ai_agents import outsider_job_events

    trigger = _on_value(data)
    workflow_permissions = data.get("permissions")
    workflow_privileged = _is_release_like_workflow(
        trigger
    ) or _workflow_has_dangerous_trigger(trigger)
    outsiders = outsider_job_events(data, path, root)
    for job_id, job in _jobs(data):
        if _is_reusable_job(job) or "timeout-minutes" in job:
            continue
        privileged = (
            workflow_privileged
            or _effective_permissions_write(job, workflow_permissions)
            or _effective_permissions_write(
                job, workflow_permissions, permission="id-token"
            )
        )
        if not privileged:
            continue
        if outsiders.get(str(job_id)) and _job_reads_pr_code(job):
            reason = (
                "it runs pull request code that accounts without write access "
                f"can start ({', '.join(outsiders[str(job_id)])})"
            )
        else:
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-missing-timeout",
                message=(
                    f"Privileged job {job_id} has no timeout-minutes and {reason}. "
                    "Set a bounded timeout to limit hung or compromised workflow runs."
                ),
                file=path,
                line=_line_for_contains(lines, f"{job_id}:"),
                severity="LOW",
                value=f"{job_id}:timeout-minutes",
            ),
        )


def scan_github_actions_file(
    path: str | Path,
    *,
    root: str | Path | None = None,
    ignore: set[str] | None = None,
    analysis_errors: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve() if root is not None else None
    file_path = _resolve_github_actions_scan_path(path, root=root_path)
    if file_path is None:
        return []
    loaded = _load_yaml(file_path, root=root_path, analysis_errors=analysis_errors)
    if loaded is None:
        return []
    data, lines = loaded

    ignore = ignore or set()
    findings: list[dict[str, Any]] = []
    is_workflow = _is_workflow_file(file_path)

    if is_workflow:
        _scan_triggers(data, file_path, lines, findings, ignore)
        _scan_permissions(data, file_path, lines, findings, ignore)
        _scan_self_hosted_runners(data, file_path, lines, findings, ignore)
        _scan_secrets_inherit(data, file_path, lines, findings, ignore)
        _scan_secrets_outside_env(
            data, file_path, lines, findings, ignore, root=root_path
        )
        _scan_hardcoded_container_credentials(data, file_path, lines, findings, ignore)
        _scan_conditions(data, file_path, lines, findings, ignore, is_workflow=True)
        _scan_cache_poisoning(data, file_path, lines, findings, ignore)
        _scan_broad_secret_env(data, file_path, lines, findings, ignore)
        _scan_oidc_build_script_exposure(data, file_path, lines, findings, ignore)
        _scan_privileged_job_timeouts(
            data, file_path, lines, findings, ignore, root=root_path
        )
        # Imported here: ai_agents builds on this module's helpers.
        from skylos.rules.config.cicd.ai_agents import scan_ai_agent_workflows

        scan_ai_agent_workflows(
            data, file_path, lines, findings, ignore, root=root_path
        )

    _scan_uses(data, file_path, lines, findings, ignore, is_workflow=is_workflow)
    _scan_persisted_checkout_credentials(
        data, file_path, lines, findings, ignore, is_workflow=is_workflow, root=root_path
    )
    _scan_run_blocks(
        data, file_path, lines, findings, ignore, is_workflow=is_workflow, root=root_path
    )
    _scan_container_images(
        data, file_path, lines, findings, ignore, is_workflow=is_workflow
    )
    _scan_overprovisioned_secrets(data, file_path, lines, findings, ignore)
    _scan_github_env_writes(
        data, file_path, lines, findings, ignore, is_workflow=is_workflow
    )
    _scan_github_app_tokens(
        data, file_path, lines, findings, ignore, is_workflow=is_workflow
    )
    _scan_insecure_commands(
        data, file_path, lines, findings, ignore, is_workflow=is_workflow
    )
    _scan_artifact_upload_policy(
        data, file_path, lines, findings, ignore, is_workflow=is_workflow
    )
    _scan_js_install_scripts(
        data, file_path, lines, findings, ignore, is_workflow=is_workflow
    )
    _scan_anonymous_definition(data, file_path, lines, findings, ignore)
    from skylos.rules.config.cicd.workflow_audits import scan_workflow_audits

    scan_workflow_audits(
        data, file_path, lines, findings, ignore, is_workflow=is_workflow, root=root_path
    )
    return findings


def scan_github_actions(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
    analysis_errors: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    findings: list[dict[str, Any]] = []
    for file_path in _discover_action_files(root_path, changed_files):
        findings.extend(
            scan_github_actions_file(
                file_path, root=root_path, ignore=ignore, analysis_errors=analysis_errors
            )
        )
    from skylos.rules.config.cicd.workflow_audits import scan_dependabot

    findings.extend(
        scan_dependabot(
            root_path, changed_files=changed_files, ignore=ignore,
            analysis_errors=analysis_errors,
        )
    )
    return findings
