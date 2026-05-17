from __future__ import annotations

import os
import re
import shlex
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from skylos.rules.config.findings import config_finding

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
MAX_YAML_BYTES = 1_000_000
MAX_YAML_GRAPH_DEPTH = 100
MAX_YAML_GRAPH_NODES = 50_000
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
TEMPLATE_EXPR_RE = re.compile(
    r"\$\{\{\s*(github\.event(?:[.\[]|\s|\})|github\."
    r"(?:base_ref|head_ref|ref_name)(?:\s|\})|inputs\.)",
    re.IGNORECASE,
)
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

ACTION_INJECTION_SINKS = {
    "actions/github-script": {"script"},
    "amadevus/pwsh-script": {"script"},
    "jannekem/run-python-script-action": {"script"},
    "cardinalby/js-eval-action": {"expression"},
    "addnab/docker-run-action": {"options", "run"},
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
    candidate = Path(path).resolve()
    if root is not None and not _is_under_root(candidate, root):
        return None
    if not candidate.is_file() or not _is_github_actions_file(candidate):
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


def _load_yaml(path: Path) -> dict[str, Any] | None:
    if yaml is None:
        return None
    try:
        if path.stat().st_size > MAX_YAML_BYTES:
            return None
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    if not _yaml_graph_is_safe(raw):
        return None
    return raw


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
    for lineno, line in enumerate(lines, 1):
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


def _line_for_template(lines: list[str], run_body: str) -> int:
    match = TEMPLATE_EXPR_RE.search(run_body)
    if match:
        return _line_for_contains(lines, match.group(0))
    return _line_for_key(lines, "run")


def _is_inline_ignored(lines: list[str], line: int, rule_id: str) -> bool:
    needle = f"skylos: ignore[{rule_id}]"
    for idx in (line - 2, line - 1):
        if 0 <= idx < len(lines) and needle in lines[idx]:
            return True
    return False


def _add_finding(
    findings: list[dict[str, Any]],
    lines: list[str],
    finding: dict[str, Any],
):
    if _is_inline_ignored(lines, int(finding.get("line", 1)), str(finding["rule_id"])):
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


def _jobs(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_id, job in jobs.items():
        if isinstance(job, dict):
            yield str(job_id), job


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
        return _line_for_contains(lines, value)
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


def _is_false(value: Any) -> bool:
    if value is False:
        return True
    return isinstance(value, str) and value.lower() == "false"


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

    if _trigger_contains(trigger, "pull_request_target") and not labeler_only:
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
                line=_line_for_contains(lines, "pull_request_target"),
                severity="HIGH",
                value="pull_request_target",
            ),
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
                line=_line_for_contains(lines, "workflow_run"),
                severity="HIGH",
                value="workflow_run",
            ),
        )


def _scan_permissions(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D291"
    if rule_id in ignore:
        return

    if "permissions" not in data:
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-default-permissions",
                message=(
                    "Workflow does not declare top-level permissions. Set "
                    "permissions: {} and grant minimal permissions per job."
                ),
                file=path,
                line=1,
                severity="MEDIUM",
                value="default_permissions",
            ),
        )
        parent_permissions_explicit = False
    else:
        parent_permissions_explicit = True

    permissions = data.get("permissions")
    if isinstance(permissions, str) and permissions in {"read-all", "write-all"}:
        severity = "HIGH" if permissions == "write-all" else "MEDIUM"
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-broad-permissions",
                message=f"Workflow grants {permissions} permissions to GITHUB_TOKEN.",
                file=path,
                line=_line_for_key(lines, "permissions"),
                severity=severity,
                value=permissions,
            ),
        )
    elif isinstance(permissions, dict):
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
                        f"Workflow-level permission {permission}: write is broad. "
                        "Prefer granting write access only on the job that needs it."
                    ),
                    file=path,
                    line=_line_for_contains(lines, str(permission)),
                    severity=severity,
                    value=f"{permission}:write",
                ),
            )

    for job_id, job in _jobs(data):
        job_permissions = job.get("permissions")
        if job_permissions is None and not parent_permissions_explicit:
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-default-permissions",
                    message=(
                        f"Job {job_id} inherits the default GITHUB_TOKEN "
                        "permissions because neither workflow nor job permissions are set."
                    ),
                    file=path,
                    line=_line_for_contains(lines, f"{job_id}:"),
                    severity="MEDIUM",
                    value=f"{job_id}:default_permissions",
                ),
            )
        elif isinstance(job_permissions, str) and job_permissions in {
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
                    line=_line_for_contains(lines, "permissions", start=1),
                    severity=severity,
                    value=f"{job_id}:{job_permissions}",
                ),
            )


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
                    severity="HIGH",
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
                    severity="HIGH",
                    value=uses_value,
                ),
            )

        if "SKY-D293" not in ignore and uses_value.lower().startswith(
            "actions/checkout@"
        ):
            with_config = step.get("with") if isinstance(step.get("with"), dict) else {}
            if not _is_false(with_config.get("persist-credentials")):
                _add_finding(
                    findings,
                    lines,
                    _finding(
                        rule_id="SKY-D293",
                        name="github-actions-checkout-credentials",
                        message=(
                            "actions/checkout leaves credentials persisted by default. "
                            "Set persist-credentials: false unless later git pushes need it."
                        ),
                        file=path,
                        line=_line_for_contains(lines, uses_value),
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
) -> None:
    rule_id = "SKY-D294"
    if rule_id in ignore:
        return

    for step in _iter_steps(data, is_workflow=is_workflow):
        run_body = step.get("run")
        if not isinstance(run_body, str):
            continue
        if not TEMPLATE_EXPR_RE.search(run_body):
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-template-injection",
                message=(
                    "run block expands attacker-influenced GitHub context directly. "
                    "Move the value into env and quote/use the environment variable."
                ),
                file=path,
                line=_line_for_template(lines, run_body),
                severity="HIGH",
                value="template_in_run",
            ),
        )

    if is_workflow:
        for job_id, job in _jobs(data):
            container = job.get("container")
            if isinstance(container, dict):
                options = container.get("options")
                if isinstance(options, str) and TEMPLATE_EXPR_RE.search(options):
                    _add_finding(
                        findings,
                        lines,
                        _finding(
                            rule_id=rule_id,
                            name="github-actions-template-injection",
                            message=(
                                f"Job {job_id} container options expand "
                                "attacker-influenced GitHub context directly."
                            ),
                            file=path,
                            line=_line_for_value(lines, options),
                            severity="HIGH",
                            value=f"{job_id}:container_options",
                        ),
                    )

            services = job.get("services")
            if not isinstance(services, dict):
                continue
            for service, config in services.items():
                if not isinstance(config, dict):
                    continue
                options = config.get("options")
                if not isinstance(options, str) or not TEMPLATE_EXPR_RE.search(options):
                    continue
                _add_finding(
                    findings,
                    lines,
                    _finding(
                        rule_id=rule_id,
                        name="github-actions-template-injection",
                        message=(
                            f"Service {service} options expand attacker-influenced "
                            "GitHub context directly."
                        ),
                        file=path,
                        line=_line_for_value(lines, options),
                        severity="HIGH",
                        value=f"{job_id}:{service}:options",
                    ),
                )

    for step in _iter_steps(data, is_workflow=is_workflow):
        uses_value = step.get("uses")
        with_config = step.get("with")
        if not isinstance(uses_value, str) or not isinstance(with_config, dict):
            continue

        sink_inputs = ACTION_INJECTION_SINKS.get(_uses_repo(uses_value))
        if not sink_inputs:
            continue

        for input_name in sink_inputs:
            script = with_config.get(input_name)
            if not isinstance(script, str) or not TEMPLATE_EXPR_RE.search(script):
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="github-actions-template-injection",
                    message=(
                        f"{uses_value} input {input_name} accepts code and expands "
                        "attacker-influenced GitHub context directly."
                    ),
                    file=path,
                    line=_line_for_value(lines, script),
                    severity="HIGH",
                    value=f"{uses_value}:{input_name}",
                ),
            )


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
        risky = False
        value = "self-hosted"
        if isinstance(runs_on, str):
            risky = runs_on == "self-hosted" or "${{" in runs_on
            value = runs_on
        elif isinstance(runs_on, list):
            labels = [str(item) for item in runs_on]
            risky = bool(labels) and (
                labels[0] == "self-hosted" or any("${{" in label for label in labels)
            )
            value = ",".join(labels)
        elif isinstance(runs_on, dict):
            risky = "group" in runs_on
            value = "runner-group"

        if risky:
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
                    line=_line_for_contains(lines, "runs-on"),
                    severity="MEDIUM",
                    value=value,
                ),
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
) -> None:
    rule_id = "SKY-D299"
    if rule_id in ignore:
        return
    for job_id, job in _jobs(data):
        if _is_reusable_job(job) or job.get("environment") is not None:
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
                            "dedicated GitHub environment."
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
) -> None:
    rule_id = "SKY-D313"
    if rule_id in ignore:
        return

    trigger = _on_value(data)
    workflow_permissions = data.get("permissions")
    workflow_privileged = _is_release_like_workflow(
        trigger
    ) or _workflow_has_dangerous_trigger(trigger)
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
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="github-actions-missing-timeout",
                message=(
                    f"Privileged or release-like job {job_id} has no timeout-minutes. "
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
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve() if root is not None else None
    file_path = _resolve_github_actions_scan_path(path, root=root_path)
    if file_path is None:
        return []
    data = _load_yaml(file_path)
    if data is None:
        return []

    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []

    ignore = ignore or set()
    findings: list[dict[str, Any]] = []
    is_workflow = _is_workflow_file(file_path)

    if is_workflow:
        _scan_triggers(data, file_path, lines, findings, ignore)
        _scan_permissions(data, file_path, lines, findings, ignore)
        _scan_self_hosted_runners(data, file_path, lines, findings, ignore)
        _scan_secrets_inherit(data, file_path, lines, findings, ignore)
        _scan_secrets_outside_env(data, file_path, lines, findings, ignore)
        _scan_hardcoded_container_credentials(data, file_path, lines, findings, ignore)
        _scan_conditions(data, file_path, lines, findings, ignore, is_workflow=True)
        _scan_cache_poisoning(data, file_path, lines, findings, ignore)
        _scan_broad_secret_env(data, file_path, lines, findings, ignore)
        _scan_oidc_build_script_exposure(data, file_path, lines, findings, ignore)
        _scan_privileged_job_timeouts(data, file_path, lines, findings, ignore)

    _scan_uses(data, file_path, lines, findings, ignore, is_workflow=is_workflow)
    _scan_run_blocks(data, file_path, lines, findings, ignore, is_workflow=is_workflow)
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
    return findings


def scan_github_actions(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    findings: list[dict[str, Any]] = []
    for file_path in _discover_action_files(root_path, changed_files):
        findings.extend(
            scan_github_actions_file(file_path, root=root_path, ignore=ignore)
        )
    return findings
