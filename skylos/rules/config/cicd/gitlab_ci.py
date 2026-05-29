from __future__ import annotations

import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.config.findings import config_finding
from skylos.security.command_guard import scan_shell_command

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

GITLAB_CI_FILENAMES = {".gitlab-ci.yml"}
MAX_YAML_BYTES = 1_000_000
MAX_YAML_GRAPH_DEPTH = 100
MAX_YAML_GRAPH_NODES = 50_000
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
SECRET_VARIABLE_RE = re.compile(
    r"(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASS|API_KEY|PRIVATE_KEY|ACCESS_KEY|"
    r"CREDENTIAL|CREDENTIALS)(?:_|$)",
    re.IGNORECASE,
)
EVAL_SINK_RE = re.compile(
    r"(?im)(?:^|[;&|]\s*|\s)(?:eval\b|(?:bash|sh|zsh)\s+-l?c\b|"
    r"(?:python3?|node|ruby|perl|php)\s+-[ce]\b)"
)
UNTRUSTED_CI_VARIABLE_RE = re.compile(
    r"\$(?:\{)?(?:CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME)|"
    r"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME|CI_COMMIT_MESSAGE|"
    r"CI_COMMIT_REF_NAME|CI_COMMIT_BRANCH)(?:\})?",
    re.IGNORECASE,
)
LOCAL_SCRIPT_RE = re.compile(
    r"(?im)^\s*(?:"
    r"\./(?:scripts|ci|build|tools|release|deploy)/"
    r"|(?:bash|sh|python3?|node|ruby|pwsh|powershell)\s+"
    r"(?:\./)?(?:scripts|ci|build|tools|release|deploy)/"
    r"|(?:npm|pnpm|yarn|bun)\s+run\s+"
    r"|make(?:\s|$)"
    r")"
)
RELEASE_COMMAND_RE = re.compile(
    r"(?im)^\s*(?:"
    r"docker\s+(?:push|buildx\s+build)"
    r"|npm\s+publish\b"
    r"|pnpm\s+publish\b"
    r"|yarn\s+npm\s+publish\b"
    r"|twine\s+upload\b"
    r"|maturin\s+publish\b"
    r"|cargo\s+publish\b"
    r"|semantic-release\b"
    r"|helm\s+(?:upgrade|install)\b"
    r"|kubectl\s+(?:apply|set|rollout)\b"
    r"|terraform\s+apply\b"
    r"|gcloud\s+(?:run\s+deploy|app\s+deploy)\b"
    r"|aws\s+(?:s3\s+sync|cloudformation\s+deploy|ecs\s+update-service)\b"
    r")"
)
RELEASE_STAGE_NAMES = {"deploy", "deployment", "release", "publish", "production"}
RESERVED_TOP_LEVEL_KEYS = {
    "after_script",
    "before_script",
    "cache",
    "default",
    "extends",
    "hooks",
    "image",
    "include",
    "inherit",
    "pages",
    "schedules",
    "services",
    "spec",
    "stages",
    "timeout",
    "types",
    "variables",
    "workflow",
}
PLACEHOLDER_SECRET_VALUES = {
    "changeme",
    "change-me",
    "dummy",
    "example",
    "fake",
    "none",
    "password",
    "placeholder",
    "postgres",
    "root",
    "test",
    "todo",
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
        provider="gitlab_ci",
        name=name,
        message=message,
        file=file,
        line=line,
        severity=severity,
        value=value,
        finding_type="workflow",
    )


def _is_gitlab_ci_file(path: Path) -> bool:
    return path.name.lower() in GITLAB_CI_FILENAMES


def _is_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_gitlab_ci_scan_path(
    path: str | Path,
    *,
    root: Path | None = None,
) -> Path | None:
    candidate = Path(path).resolve()
    if root is not None and not _is_under_root(candidate, root):
        return None
    if not candidate.is_file() or not _is_gitlab_ci_file(candidate):
        return None
    return candidate


def _discover_gitlab_ci_files(
    root: Path,
    changed_files: set[str] | None,
) -> list[Path]:
    if root.is_file():
        candidate = _resolve_gitlab_ci_scan_path(root)
        return [candidate] if candidate is not None else []

    if changed_files is not None:
        candidates = []
        for raw_path in changed_files:
            path = Path(raw_path)
            if not path.is_absolute():
                path = root / path
            candidate = _resolve_gitlab_ci_scan_path(path, root=root)
            if candidate is not None:
                candidates.append(candidate)
        return sorted(set(candidates))

    candidates: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        base = Path(current_root)
        for filename in filenames:
            path = base / filename
            if _is_gitlab_ci_file(path):
                candidates.append(path)
    return sorted(candidates)


def _load_yaml(path: Path) -> dict[str, Any] | None:
    if yaml is None:
        return None
    try:
        text = read_text_no_symlink(path, max_bytes=MAX_YAML_BYTES, encoding="utf-8")
        if text is None:
            return None
        raw = yaml.safe_load(text)
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

        children = _yaml_graph_children(current)
        if children is None:
            nodes_seen += 1
            if nodes_seen > MAX_YAML_GRAPH_NODES:
                return False
            continue

        state = _yaml_graph_visit_state(current, leaving, active, visited)
        if state == "cycle":
            return False
        if state != "enter":
            continue

        nodes_seen += 1
        if nodes_seen > MAX_YAML_GRAPH_NODES:
            return False
        stack.append((current, depth, True))
        for child in reversed(children):
            stack.append((child, depth + 1, False))

    return True


def _yaml_graph_children(value: Any) -> tuple[Any, ...] | None:
    if isinstance(value, dict):
        return tuple(value.values())
    if isinstance(value, list):
        return tuple(value)
    return None


def _yaml_graph_visit_state(
    value: Any,
    leaving: bool,
    active: set[int],
    visited: set[int],
) -> str:
    value_id = id(value)
    if leaving:
        active.discard(value_id)
        visited.add(value_id)
        return "leave"
    if value_id in active:
        return "cycle"
    if value_id in visited:
        return "visited"
    active.add(value_id)
    return "enter"


def _line_for_contains(lines: list[str], needle: str, *, start: int = 1) -> int:
    if not needle:
        return 1
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


def _line_for_value(lines: list[str], value: Any, *, fallback_key: str = "") -> int:
    if isinstance(value, str):
        first_line = value.strip().splitlines()[0] if value.strip() else value
        line = _line_for_contains(lines, first_line)
        if line != 1 or not fallback_key:
            return line
    if fallback_key:
        return _line_for_key(lines, fallback_key)
    return 1


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
) -> None:
    if _is_inline_ignored(lines, int(finding.get("line", 1)), str(finding["rule_id"])):
        return
    findings.append(finding)


def _iter_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _iter_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_strings(child)


def _iter_jobs(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for job_id, job in data.items():
        if str(job_id) in RESERVED_TOP_LEVEL_KEYS or not isinstance(job, dict):
            continue
        yield str(job_id), job


def _default_block(data: dict[str, Any]) -> dict[str, Any]:
    default = data.get("default")
    return default if isinstance(default, dict) else {}


def _effective_job_value(data: dict[str, Any], job: dict[str, Any], key: str) -> Any:
    if key in job:
        return job.get(key)
    default = _default_block(data)
    if key in default:
        return default.get(key)
    if key in {"after_script", "before_script", "cache", "image", "services"}:
        return data.get(key)
    return None


def _effective_variables(data: dict[str, Any], job: dict[str, Any]) -> dict[str, Any]:
    variables: dict[str, Any] = {}
    top_level = data.get("variables")
    if isinstance(top_level, dict):
        variables.update(top_level)
    job_variables = job.get("variables")
    if isinstance(job_variables, dict):
        variables.update(job_variables)
    return variables


def _iter_commands(data: dict[str, Any], job: dict[str, Any]) -> Iterator[str]:
    for key in ("before_script", "script", "after_script"):
        value = _effective_job_value(data, job, key)
        yield from _iter_strings(value)
    hooks = job.get("hooks")
    if not isinstance(hooks, dict):
        hooks = _default_block(data).get("hooks")
    if isinstance(hooks, dict):
        yield from _iter_strings(hooks.get("pre_get_sources_script"))


def _image_name(value: Any) -> str | None:
    if isinstance(value, str):
        name = value.strip()
        return name or None
    if isinstance(value, dict) and isinstance(value.get("name"), str):
        name = value["name"].strip()
        return name or None
    return None


def _service_images(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        name = value.strip()
        if name:
            yield name
    elif isinstance(value, list):
        for service in value:
            name = _image_name(service)
            if name:
                yield name
    elif isinstance(value, dict):
        name = _image_name(value)
        if name:
            yield name


def _image_is_digest_pinned(image: str) -> bool:
    return "@sha256:" in image.lower()


def _image_tag(image: str) -> str | None:
    if "@" in image:
        image = image.split("@", 1)[0]
    last_segment = image.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return None
    return last_segment.rsplit(":", 1)[1]


def _is_dind_image(image: str) -> bool:
    normalized = image.lower()
    last_segment = normalized.rsplit("/", 1)[-1]
    return "docker" in last_segment and "dind" in last_segment


def _is_mutable_image(image: str) -> bool:
    if _image_is_digest_pinned(image):
        return False
    tag = _image_tag(image)
    if tag is None or tag.lower() == "latest":
        return True
    return _is_dind_image(image)


def _iter_includes(value: Any) -> Iterator[Any]:
    if isinstance(value, list):
        for item in value:
            yield from _iter_includes(item)
    else:
        yield value


def _is_literal_secret_value(value: Any) -> bool:
    if isinstance(value, (dict, list)) or value is None:
        return False
    if isinstance(value, bool):
        return False
    text = str(value).strip()
    if not text or text.startswith("$") or "${" in text:
        return False
    if text.lower() in PLACEHOLDER_SECRET_VALUES:
        return False
    return len(text) >= 8 or any(char in text for char in "-_=:/")


def _is_release_like_job(
    data: dict[str, Any],
    job_id: str,
    job: dict[str, Any],
) -> bool:
    lowered_id = job_id.lower()
    if any(word in lowered_id for word in ("deploy", "release", "publish")):
        return True

    stage = job.get("stage")
    if isinstance(stage, str) and stage.strip().lower() in RELEASE_STAGE_NAMES:
        return True

    environment = job.get("environment")
    if isinstance(environment, str):
        env_name = environment
    elif isinstance(environment, dict) and isinstance(environment.get("name"), str):
        env_name = environment["name"]
    else:
        env_name = ""
    if env_name.strip().lower() in {"prod", "production"}:
        return True

    if "release" in job or "id_tokens" in job or "identity" in job:
        return True

    return any(
        RELEASE_COMMAND_RE.search(command) for command in _iter_commands(data, job)
    )


def _cache_enabled(value: Any) -> bool:
    if value is None or value is False:
        return False
    if value == [] or value == {}:
        return False
    return True


def _has_oidc(job: dict[str, Any], data: dict[str, Any]) -> bool:
    return (
        _effective_job_value(data, job, "id_tokens") is not None
        or _effective_job_value(data, job, "identity") is not None
    )


def _id_token_names(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    return [str(name) for name in value if isinstance(name, str)]


def _secret_has_explicit_token(value: Any) -> bool:
    if isinstance(value, dict):
        if "token" in value:
            return True
        return any(_secret_has_explicit_token(child) for child in value.values())
    if isinstance(value, list):
        return any(_secret_has_explicit_token(child) for child in value)
    return False


def _scan_images(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D314"
    if rule_id in ignore:
        return

    candidates: list[tuple[str, str, Any, str]] = [
        ("global image", "image", data.get("image"), "image"),
        ("global services", "services", data.get("services"), "service"),
        (
            "default image",
            "image",
            _default_block(data).get("image"),
            "image",
        ),
        (
            "default services",
            "services",
            _default_block(data).get("services"),
            "service",
        ),
    ]
    for job_id, job in _iter_jobs(data):
        if "image" in job:
            candidates.append(
                (f"job {job_id} image", "image", job.get("image"), "image")
            )
        if "services" in job:
            candidates.append(
                (f"job {job_id} services", "services", job.get("services"), "service")
            )

    seen: set[tuple[str, str]] = set()
    for location, key, value, kind in candidates:
        images = (
            [_image_name(value)] if kind == "image" else list(_service_images(value))
        )
        for image in images:
            if image is None or not _is_mutable_image(image):
                continue
            seen_key = (location, image)
            if seen_key in seen:
                continue
            seen.add(seen_key)
            severity = "HIGH" if _is_dind_image(image) else "MEDIUM"
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="gitlab-ci-mutable-image",
                    message=(
                        f"GitLab CI {location} uses mutable container reference "
                        f"{image}. Pin release-sensitive images by digest."
                    ),
                    file=path,
                    line=_line_for_value(lines, image, fallback_key=key),
                    severity=severity,
                    value=image,
                ),
            )


def _scan_external_includes(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D315"
    if rule_id in ignore:
        return

    for include in _iter_includes(data.get("include")):
        if isinstance(include, str):
            if not include.lower().startswith(("http://", "https://")):
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="gitlab-ci-unpinned-remote-include",
                    message=(
                        "Remote GitLab CI include has no integrity checksum. Add "
                        "include:remote integrity to detect upstream changes."
                    ),
                    file=path,
                    line=_line_for_contains(lines, include),
                    severity="HIGH",
                    value=include,
                ),
            )
            continue

        if not isinstance(include, dict):
            continue

        project = include.get("project")
        if isinstance(project, str):
            ref = include.get("ref")
            if not isinstance(ref, str) or not FULL_SHA_RE.fullmatch(ref.strip()):
                _add_finding(
                    findings,
                    lines,
                    _finding(
                        rule_id=rule_id,
                        name="gitlab-ci-unpinned-project-include",
                        message=(
                            f"GitLab CI project include {project} is not pinned to "
                            "a full commit SHA ref."
                        ),
                        file=path,
                        line=_line_for_contains(lines, project),
                        severity="HIGH",
                        value=f"project:{project}",
                    ),
                )

        remote = include.get("remote")
        if isinstance(remote, str) and not include.get("integrity"):
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="gitlab-ci-unpinned-remote-include",
                    message=(
                        f"Remote GitLab CI include {remote} has no integrity checksum."
                    ),
                    file=path,
                    line=_line_for_contains(lines, remote),
                    severity="HIGH",
                    value=f"remote:{remote}",
                ),
            )


def _scan_literal_secret_variables(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D316"
    if rule_id in ignore:
        return

    variable_blocks: list[tuple[str, dict[str, Any], str]] = []
    top_level = data.get("variables")
    if isinstance(top_level, dict):
        variable_blocks.append(("top-level", top_level, "HIGH"))
    for job_id, job in _iter_jobs(data):
        variables = job.get("variables")
        if isinstance(variables, dict):
            variable_blocks.append((f"job {job_id}", variables, "MEDIUM"))

    for location, variables, severity in variable_blocks:
        for key, value in variables.items():
            key_text = str(key)
            if not SECRET_VARIABLE_RE.search(key_text) or not _is_literal_secret_value(
                value
            ):
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="gitlab-ci-literal-secret-variable",
                    message=(
                        f"GitLab CI {location} variable {key_text} looks like a "
                        "literal secret. Store it as a protected and masked CI/CD "
                        "variable instead."
                    ),
                    file=path,
                    line=_line_for_key(lines, key_text),
                    severity=severity,
                    value=f"{location}:{key_text}",
                ),
            )


def _scan_untrusted_eval(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D317"
    if rule_id in ignore:
        return

    for job_id, job in _iter_jobs(data):
        for command in _iter_commands(data, job):
            variable = UNTRUSTED_CI_VARIABLE_RE.search(command)
            if not variable or not EVAL_SINK_RE.search(command):
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="gitlab-ci-untrusted-eval",
                    message=(
                        f"Job {job_id} passes attacker-controlled CI metadata into "
                        "an eval-like shell or interpreter sink."
                    ),
                    file=path,
                    line=_line_for_value(lines, command, fallback_key="script"),
                    severity="HIGH",
                    value=variable.group(0),
                ),
            )


def _scan_shell_command_risks(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    for job_id, job in _iter_jobs(data):
        for command in _iter_commands(data, job):
            for risk in scan_shell_command(command):
                if risk.rule_id in ignore:
                    continue
                _add_finding(
                    findings,
                    lines,
                    _finding(
                        rule_id=risk.rule_id,
                        name="gitlab-ci-shell-command-risk",
                        message=f"Job {job_id}: {risk.message}",
                        file=path,
                        line=_line_for_value(lines, command, fallback_key="script"),
                        severity=risk.severity,
                        value=f"{job_id}:{risk.rule_id}",
                    ),
                )


def _scan_dind_without_tls(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D318"
    if rule_id in ignore:
        return

    for job_id, job in _iter_jobs(data):
        service_images = list(
            _service_images(_effective_job_value(data, job, "services"))
        )
        if not any(_is_dind_image(image) for image in service_images):
            continue

        variables = _effective_variables(data, job)
        tls_certdir = variables.get("DOCKER_TLS_CERTDIR")
        docker_host = variables.get("DOCKER_HOST")
        tls_disabled = isinstance(tls_certdir, str) and tls_certdir.strip() == ""
        plain_host = isinstance(
            docker_host, str
        ) and docker_host.strip().lower().startswith("tcp://docker:2375")
        if not tls_disabled and not plain_host:
            continue

        variable_name = "DOCKER_TLS_CERTDIR" if tls_disabled else "DOCKER_HOST"
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="gitlab-ci-dind-tls-disabled",
                message=(
                    f"Job {job_id} uses Docker-in-Docker with TLS disabled. Use "
                    "TLS-enabled DinD or avoid privileged Docker socket access."
                ),
                file=path,
                line=_line_for_key(lines, variable_name),
                severity="HIGH",
                value=f"{job_id}:{variable_name}",
            ),
        )


def _scan_oidc_local_scripts(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D319"
    if rule_id in ignore:
        return

    for job_id, job in _iter_jobs(data):
        if job_id.startswith(".") or not _has_oidc(job, data):
            continue
        for command in _iter_commands(data, job):
            if not LOCAL_SCRIPT_RE.search(command):
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="gitlab-ci-oidc-local-script",
                    message=(
                        f"Job {job_id} requests GitLab OIDC credentials while "
                        "running repository-controlled build or release scripts. "
                        "Issue tokens in a small publish job over prebuilt artifacts."
                    ),
                    file=path,
                    line=_line_for_value(lines, command, fallback_key="script"),
                    severity="HIGH",
                    value=f"{job_id}:oidc-local-script",
                ),
            )
            break


def _scan_release_cache(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D320"
    if rule_id in ignore:
        return

    for job_id, job in _iter_jobs(data):
        if job_id.startswith(".") or not _is_release_like_job(data, job_id, job):
            continue
        cache = _effective_job_value(data, job, "cache")
        if not _cache_enabled(cache):
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="gitlab-ci-release-cache",
                message=(
                    f"Release-like GitLab CI job {job_id} restores cache. Avoid "
                    "cache restore in publish/deploy jobs, or isolate release caches."
                ),
                file=path,
                line=_line_for_contains(lines, f"{job_id}:"),
                severity="MEDIUM",
                value=f"{job_id}:cache",
            ),
        )


def _scan_missing_timeouts(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D321"
    if rule_id in ignore:
        return

    for job_id, job in _iter_jobs(data):
        if job_id.startswith("."):
            continue
        if not _is_release_like_job(data, job_id, job) and not _has_oidc(job, data):
            continue
        if _effective_job_value(data, job, "timeout") is not None:
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="gitlab-ci-missing-timeout",
                message=(
                    f"Release-like or OIDC job {job_id} has no timeout. Set a "
                    "bounded job timeout to limit hung or compromised CI runs."
                ),
                file=path,
                line=_line_for_contains(lines, f"{job_id}:"),
                severity="LOW",
                value=f"{job_id}:timeout",
            ),
        )


def _scan_dynamic_tags(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D322"
    if rule_id in ignore:
        return

    tag_blocks: list[tuple[str, Any]] = [("default", _default_block(data).get("tags"))]
    for job_id, job in _iter_jobs(data):
        if "tags" in job:
            tag_blocks.append((f"job {job_id}", job.get("tags")))

    for location, tags in tag_blocks:
        for tag in _iter_strings(tags):
            if "$" not in tag:
                continue
            _add_finding(
                findings,
                lines,
                _finding(
                    rule_id=rule_id,
                    name="gitlab-ci-dynamic-runner-tag",
                    message=(
                        f"GitLab CI {location} uses dynamic runner tag {tag}. Keep "
                        "runner selection static so untrusted refs cannot steer jobs "
                        "onto privileged runners."
                    ),
                    file=path,
                    line=_line_for_contains(lines, tag),
                    severity="MEDIUM",
                    value=f"{location}:{tag}",
                ),
            )


def _scan_secret_token_ambiguity(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D323"
    if rule_id in ignore:
        return

    for job_id, job in _iter_jobs(data):
        secrets = job.get("secrets")
        if not isinstance(secrets, dict):
            continue
        token_names = _id_token_names(_effective_job_value(data, job, "id_tokens"))
        if len(token_names) < 2:
            continue
        ambiguous = [
            str(secret_name)
            for secret_name, secret_value in secrets.items()
            if not _secret_has_explicit_token(secret_value)
        ]
        if not ambiguous:
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="gitlab-ci-ambiguous-secret-token",
                message=(
                    f"Job {job_id} defines multiple id_tokens but GitLab secret "
                    f"{ambiguous[0]} does not select an explicit token."
                ),
                file=path,
                line=_line_for_key(lines, ambiguous[0]),
                severity="MEDIUM",
                value=f"{job_id}:{ambiguous[0]}",
            ),
        )


def scan_gitlab_ci_file(
    path: str | Path,
    *,
    root: str | Path | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve() if root is not None else None
    file_path = _resolve_gitlab_ci_scan_path(path, root=root_path)
    if file_path is None:
        return []
    data = _load_yaml(file_path)
    if data is None:
        return []

    text = read_text_no_symlink(file_path, max_bytes=MAX_YAML_BYTES, encoding="utf-8")
    lines = text.splitlines() if text is not None else []

    ignore = ignore or set()
    findings: list[dict[str, Any]] = []
    _scan_images(data, file_path, lines, findings, ignore)
    _scan_external_includes(data, file_path, lines, findings, ignore)
    _scan_literal_secret_variables(data, file_path, lines, findings, ignore)
    _scan_untrusted_eval(data, file_path, lines, findings, ignore)
    _scan_shell_command_risks(data, file_path, lines, findings, ignore)
    _scan_dind_without_tls(data, file_path, lines, findings, ignore)
    _scan_oidc_local_scripts(data, file_path, lines, findings, ignore)
    _scan_release_cache(data, file_path, lines, findings, ignore)
    _scan_missing_timeouts(data, file_path, lines, findings, ignore)
    _scan_dynamic_tags(data, file_path, lines, findings, ignore)
    _scan_secret_token_ambiguity(data, file_path, lines, findings, ignore)
    return findings


def scan_gitlab_ci(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    findings: list[dict[str, Any]] = []
    for file_path in _discover_gitlab_ci_files(root_path, changed_files):
        findings.extend(scan_gitlab_ci_file(file_path, root=root_path, ignore=ignore))
    return findings
