"""GitHub Actions and Dependabot audits for privileged triggers, cache
poisoning, Dependabot code execution and cooldowns, unmasked secrets,
obfuscation and long-lived publishing tokens.

Who can start a job comes from the outsider reachability in ai_agents.py,
``${{ }}`` values from the reader in actions_expressions.py, and a finding
needs the evidence that makes it exploitable, not only the presence of a
keyword.

- SKY-D290 (``issue_comment``): anyone who can comment starts a job that
  checks out pull request code and runs it while the job holds a write
  token, secrets, cache writes or a self-hosted runner.
- SKY-D308 (cache writes and default caches): a job an account without write
  access can start declares a write-capable ``cache-mode`` and handles pull
  request code, pull request artifacts or event text; or a release workflow
  restores a cache that an action turns on without being asked.
- SKY-D360: Dependabot runs manifest code
  (``insecure-external-code-execution: allow``) for bundler, mix or pip.
- SKY-D361: Dependabot version updates whose effective cooldown, after the
  SemVer-specific days and ``exclude: ["*"]``, is under seven days.
- SKY-D362: a decoded secret (``fromJSON(secrets.X)`` or a field of it)
  reaches a value GitHub prints, where masking of the stored text misses it.
- SKY-D363: a ``uses:`` path with ``.``, ``..`` or empty segments, or a
  ``${{ }}`` that folds to a constant or only wraps a value.
- SKY-D364: publishing to PyPI or npm with a stored token where the registry
  offers trusted publishing to the workflow.

Action defaults, cache-mode semantics, registry limits and Dependabot options
were read from the actions' action.yml files and the GitHub, PyPI and npm
documentation on 2026-10-21; dictionary.md names them.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.config.cicd import actions_expressions as expressions
from skylos.rules.config.cicd.ai_agent_expressions import (
    EvalContext,
    evaluate,
    has_status_override,
    parse_condition,
)
from skylos.rules.config.cicd.ai_agents import (
    _ASSOCIATION_CHECK_RE,
    _MEMBER_VALUE_RE,
    _PERMISSION_SCRIPT_RE,
    _job_routes_by_event,
    _permissions_scopes,
    _Reach,
    _secret_names,
    _trigger_map,
    _untrusted_events,
    local_workflow_callers,
)
from skylos.rules.config.cicd.github_actions import (
    FULL_SHA_RE,
    MAX_YAML_GRAPH_DEPTH,
    MAX_YAML_GRAPH_NODES,
    _PR_CODE_FETCH_RE,
    _actions_bool,
    _add_finding,
    _cache_action_enabled,
    _finding,
    _fragment_line,
    _is_inline_ignored,
    _is_release_like_workflow,
    _jobs,
    _line_for_trigger,
    _load_yaml,
    _on_value,
    _source_for_lines,
    _uses_matches,
    _uses_repo,
)
from skylos.rules.config.cicd.runner_labels import (
    _is_hosted_label_value,
    _matrix_property_is_hosted,
    runner_may_be_self_hosted,
)
from skylos.rules.config.cicd.template_injection import (
    _PAYLOAD_CARRIERS,
    interpolates_untrusted,
)
from skylos.rules.config.findings import config_finding
from skylos.security.command_guard_parse import (
    shell_tokens,
    split_pipeline,
    split_shell_statements,
)

RULE_TRIGGER = "SKY-D290"
RULE_CACHE = "SKY-D308"
RULE_DEPENDABOT_EXECUTION = "SKY-D360"
RULE_DEPENDABOT_COOLDOWN = "SKY-D361"
RULE_UNREDACTED = "SKY-D362"
RULE_OBFUSCATION = "SKY-D363"
RULE_PUBLISHING = "SKY-D364"

COOLDOWN_MINIMUM_DAYS = 7
DEPENDABOT_DEFAULT_COOLDOWN_DAYS = 3
DEPENDABOT_FILENAMES = ("dependabot.yml", "dependabot.yaml")
_TRACE_DEPTH = 4
_NEWEST = (math.inf,)
_UNKNOWN = object()

_CODE_RUNNING_ECOSYSTEMS = frozenset({"bundler", "mix", "pip"})
_SEMVER_COOLDOWN_ECOSYSTEMS = frozenset(
    {
        "bun",
        "bundler",
        "cargo",
        "composer",
        "conda",
        "deno",
        "dotnet-sdk",
        "elm",
        "gomod",
        "gradle",
        "julia",
        "maven",
        "mix",
        "npm",
        "nuget",
        "pip",
        "pub",
        "rust-toolchain",
        "sbt",
        "swift",
        "uv",
    }
)
_DAYS_ONLY_COOLDOWN_ECOSYSTEMS = frozenset(
    {
        "bazel",
        "devcontainers",
        "docker",
        "docker-compose",
        "github-actions",
        "gitsubmodule",
        "helm",
        "nix",
        "opentofu",
        "pre-commit",
        "terraform",
        "vcpkg",
    }
)
_SEMVER_DAY_KEYS = ("semver-major-days", "semver-minor-days", "semver-patch-days")
_PRINTED_STEP_KEYS = frozenset({"run", "with", "env", "name", "working-directory"})
_PRINTED_JOB_KEYS = frozenset({"env", "outputs", "name", "runs-on", "environment", "with"})
_PRINTED_CONTAINER_KEYS = frozenset({"image", "env", "options", "entrypoint", "args"})

_WRITING_CACHE_MODES = frozenset({"write", "write-only"})
_RESTORING_CACHE_MODES = frozenset({"read", "write"})
_UV_RELEASE_AWARE = (10,)
_UV_AUTO_CACHE = (5,)
_NODE_PACKAGE_MANAGER_CACHE = (5,)
_NPM_PACKAGE_MANAGER_RE = re.compile(r"^(\^)?npm(@.*)?$")


@dataclass(frozen=True)
class _DefaultCache:
    """A cache-aware action whose cache runs unless an input stops it.

    ``opt_in`` inputs enable caching when true and default to true;
    ``opt_out`` inputs disable caching when they hold one of ``stops``."""

    toggle: str
    opt_in: bool
    stops: frozenset[str] = frozenset({"true"})
    since: tuple[int, ...] | None = None


_DEFAULT_CACHES = {
    "actions/setup-go": _DefaultCache("cache", True, since=(4,)),
    "jdx/mise-action": _DefaultCache("cache", True),
    "actions-rust-lang/setup-rust-toolchain": _DefaultCache("cache", True),
    "mlugg/setup-zig": _DefaultCache("use-cache", True),
    "swatinem/rust-cache": _DefaultCache("lookup-only", False),
    "oven-sh/setup-bun": _DefaultCache("no-cache", False),
    "gradle/actions/setup-gradle": _DefaultCache("cache-disabled", False),
    "ramsey/composer-install": _DefaultCache(
        "ignore-cache", False, frozenset({"yes", "true", "1"})
    ),
}

_PR_HEAD_CONTEXTS = (
    "github.event.pull_request.head",
    "github.event.pull_request.merge_commit_sha",
    "github.head_ref",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_commit",
    "github.event.workflow_run.head_repository",
    "github.event.workflow_run.pull_requests",
)
_EVENT_TEXT_CONTEXTS = (
    "github.event.comment.body",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.review.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
)
_PR_LOOKUP_RE = re.compile(
    r"pulls?/|pulls\.|/pulls\b|pull[-_]request|\bgh\s+pr\b|"
    r"\bhead(?:_ref|_sha|_repo|\.ref|\.sha|\.repo|RefName|RefOid)",
    re.IGNORECASE,
)
_PULL_REF_TEXT_RE = re.compile(r"refs/pull/|\bpull/\$\{\{", re.IGNORECASE)
_PR_CHECKOUT_COMMAND_RE = re.compile(r"\b(?:gh|hub)\s+pr\s+checkout\b", re.IGNORECASE)
_HEAD_VALUE_RE = re.compile(
    r"head(?:_ref|_sha|_repo|_branch|\.ref|\.sha|\.repo|RefName|RefOid)|refs/pull/|\bpull/",
    re.IGNORECASE,
)
_OUTPUT_ASSIGNMENTS = (
    r"setOutput\(\s*['\"]{name}['\"]\s*,\s*(?P<value>[^\n]+)",
    r"(?<![\w-]){name}=(?P<value>[^\n]*)",
    r"::set-output name={name}::(?P<value>[^\n]*)",
)
_PRINTED_LINE_RE = re.compile(
    r"^\s*(?:echo|printf|print|Write-Host|console\.(?:log|info|warn)"
    r"|core\.(?:info|notice|warning|debug))\b.*$",
    re.MULTILINE,
)
_SCRIPT_FAILS_RE = re.compile(r"core\.setFailed|\bthrow\b|process\.exit\(\s*[1-9]")
_PULL_REQUEST_SCOPED_EVENTS = frozenset({"pull_request_review", "pull_request_review_comment"})
_GIT_REF_COMMAND_RE = re.compile(
    r"\bgit\s+(?:fetch|checkout|switch|pull|reset|worktree\s+add)\b", re.IGNORECASE
)
_SHELL_VARIABLE_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_REF_VERSION_RE = re.compile(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_COMMENT_VERSION_RE = re.compile(r"(?<![\w.])v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?![\w])")
_DEFAULT_BRANCHES = frozenset({"main", "master"})
FOLD_STEP_LIMIT = 2_000
FOLD_TEXT_LIMIT = 4_096
_SLOT_RE = re.compile(r"[0-9]+")
_HEX_NUMBER_RE = re.compile(r"0[xX][0-9A-Fa-f]+")
_DECIMAL_NUMBER_RE = re.compile(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")

_PYTHON_RE = re.compile(r"python(?:\d+(?:\.\d+)*)?(?:\.exe)?")
_TWINE_RE = re.compile(r"twine(?:[=@<>~!].*)?")
_PYPI_RUNNERS = frozenset({"pipx", "uvx", "uv", "poetry", "pdm", "hatch", "pipenv", "rye"})
_PYPI_PUBLISHERS = frozenset({"hatch", "pdm", "poetry", "flit"})
_NODE_RUNNERS = frozenset({"npx", "pnpx", "bunx"})
_NODE_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun"})
_SCRIPT_SUBCOMMANDS = frozenset({"run", "run-script", "exec", "x", "dlx"})
_VALUE_OPTIONS = frozenset(
    {
        "--filter",
        "-F",
        "--dir",
        "-C",
        "--prefix",
        "--workspace",
        "-w",
        "--cwd",
        "--directory",
        "--project",
        "--config-file",
        "--cache-dir",
        "--package",
        "-p",
    }
)
_COMMAND_PREFIXES = frozenset({"sudo", "env", "command", "time", "nohup", "exec"})
_PYPI_HOSTS = frozenset({"upload.pypi.org", "test.pypi.org"})
_PYPI_INDEX_NAMES = frozenset({"pypi", "testpypi", "main", "test"})
_NPM_HOSTS = frozenset({"registry.npmjs.org"})
_PYPI_TOKEN_ENV = frozenset(
    {
        "TWINE_PASSWORD",
        "UV_PUBLISH_TOKEN",
        "UV_PUBLISH_PASSWORD",
        "HATCH_INDEX_AUTH",
        "PDM_PUBLISH_PASSWORD",
        "FLIT_PASSWORD",
        "MATURIN_PYPI_TOKEN",
        "MATURIN_PASSWORD",
    }
)
_PYPI_TOKEN_ENV_RE = re.compile(r"POETRY_PYPI_TOKEN_\w+|POETRY_HTTP_BASIC_\w+_PASSWORD")
_PYPI_CREDENTIAL_FLAGS = frozenset({"-p", "--password", "-t", "--token", "-a", "--auth", "-P"})
_PYPI_TARGET_ENV = frozenset(
    {
        "TWINE_REPOSITORY_URL",
        "TWINE_REPOSITORY",
        "UV_PUBLISH_URL",
        "FLIT_INDEX_URL",
        "HATCH_INDEX_REPO",
        "PDM_PUBLISH_REPO",
        "MATURIN_REPOSITORY_URL",
        "MATURIN_REPOSITORY",
    }
)
_PYPI_TARGET_FLAGS = frozenset(
    {"--repository-url", "--repository", "-r", "--repo", "--publish-url", "--index"}
)
_NPM_TOKEN_ENV = frozenset(
    {
        "NODE_AUTH_TOKEN",
        "NPM_TOKEN",
        "NPM_AUTH_TOKEN",
        "NPM_CONFIG_TOKEN",
        "NPM_CONFIG__AUTHTOKEN",
        "YARN_NPM_AUTH_TOKEN",
    }
)
_NPM_TOKEN_TEXT_RE = re.compile(r"_authToken|npmAuthToken", re.IGNORECASE)
_PYPI_TOKEN_TEXT_RE = re.compile(r"\.pypirc\b|\bpypi-token\.", re.IGNORECASE)


@dataclass(frozen=True)
class _Step:
    job_id: Any
    job: dict[str, Any] | None
    index: int
    step: dict[str, Any]
    path: tuple[Any, ...]


@dataclass
class _Audit:
    data: dict[str, Any]
    path: Path
    lines: list[str]
    findings: list[dict[str, Any]]
    ignore: set[str]
    root: Path | None
    is_workflow: bool
    _memo: dict[str, Any] = field(default_factory=dict)

    def wants(self, rule_id: str) -> bool:
        return rule_id not in self.ignore

    def cached(self, key: str, compute: Any) -> Any:
        if key not in self._memo:
            self._memo[key] = compute()
        return self._memo[key]

    def source(self) -> Any:
        return self.cached("source", lambda: _source_for_lines(self.lines))

    def outsiders(self) -> dict[str, list[str]]:
        return self.cached("outsiders", lambda: _outsider_events(self.data, self.path, self.root))

    def callers(self) -> list[tuple[Path, dict[str, Any], Any, dict[str, Any]]]:
        return self.cached(
            "callers", lambda: local_workflow_callers(self.data, self.path, self.root)
        )

    def reach(self) -> _Reach:
        return self.cached("reach", lambda: _StrictReach(self.data))

    def line(self, path: tuple[Any, ...], *, key: bool = True) -> int:
        source = self.source()
        if source is None:
            return 1
        for length in range(len(path), 0, -1):
            found = source.line_for_path(path[:length], key=key)
            if found is not None:
                return found
        return 1

    def comment(self, line: int) -> str:
        source = self.source()
        if source is None:
            return ""
        return source.comment_on_line(line) or ""

    def report(
        self,
        rule_id: str,
        name: str,
        message: str,
        line: int,
        severity: str,
        value: str,
        *,
        yaml_only: bool = True,
    ) -> None:
        _add_finding(
            self.findings,
            self.lines,
            _finding(
                rule_id=rule_id,
                name=name,
                message=message,
                file=self.path,
                line=line,
                severity=severity,
                value=value,
            ),
            yaml_only=yaml_only,
        )


def scan_workflow_audits(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    is_workflow: bool,
    root: Path | None = None,
) -> None:
    """Run the ported audits on one parsed workflow or composite action."""
    audit = _Audit(data, path, lines, findings, ignore, root, is_workflow)
    _audit_uses_paths(audit)
    _audit_expressions(audit)
    if not is_workflow:
        return
    _audit_comment_trigger(audit)
    _audit_cache_writes(audit)
    _audit_default_caches(audit)
    _audit_publishing(audit)


def _steps(audit: _Audit) -> Iterator[_Step]:
    if not audit.is_workflow:
        runs = audit.data.get("runs")
        if not isinstance(runs, dict) or not isinstance(runs.get("steps"), list):
            return
        for index, step in enumerate(runs["steps"]):
            if isinstance(step, dict):
                yield _Step(None, None, index, step, ("runs", "steps", index))
        return
    for job_id, job in _jobs(audit.data):
        yield from _job_steps(job_id, job)


def _job_steps(job_id: Any, job: dict[str, Any]) -> Iterator[_Step]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return
    for index, step in enumerate(steps):
        if isinstance(step, dict):
            yield _Step(job_id, job, index, step, ("jobs", job_id, "steps", index))


def _with(step: dict[str, Any]) -> dict[str, Any]:
    config = step.get("with")
    if not isinstance(config, dict):
        return {}
    return {str(key): value for key, value in config.items()}


def _env_layers(
    data: dict[str, Any], job: dict[str, Any] | None, step: dict[str, Any] | None
) -> list[dict[str, Any]]:
    """env mappings visible to a step, nearest first."""
    layers = []
    for holder in (step, job, data):
        if isinstance(holder, dict) and isinstance(holder.get("env"), dict):
            layers.append(holder["env"])
    return layers


def _env_value(layers: list[dict[str, Any]], name: str) -> Any:
    wanted = name.lower()
    for layer in layers:
        for key, value in layer.items():
            if str(key).lower() == wanted:
                return value
    return None


def _parse(body: str) -> Any:
    try:
        return expressions.parse_expression(body)
    except (expressions.ExpressionError, RecursionError):
        return None


def _references(text: Any) -> list[expressions.Reference]:
    """Every reference whose value flows out of the ``${{ }}`` spans in text,
    including the inputs of a call that a member is read from."""
    if not isinstance(text, str) or "${{" not in text:
        return []
    found = []
    for body, _start, _end in expressions.template_spans(text):
        node = _parse(body)
        if node is None:
            continue
        for reference in expressions.flowing_references(node):
            found.append(reference)
            found.extend(expressions.invoke_inputs(reference))
    return found


def _secret_reference(reference: expressions.Reference) -> str | None:
    if not reference.under("secrets"):
        return None
    member = reference.only_member()
    if member is None or member.upper() == "GITHUB_TOKEN":
        return None
    return member


def _secret_backing(text: Any, layers: list[dict[str, Any]], depth: int = 0) -> str | None:
    """The stored secret a value is made from: a ``secrets.X`` reference in
    its expressions, or a shell variable whose env value holds one."""
    if not isinstance(text, str) or depth > _TRACE_DEPTH:
        return None
    for reference in _references(text):
        name = _secret_reference(reference)
        if name is not None:
            return name
        if reference.under("env") and reference.only_member() is not None:
            backing = _secret_backing(
                _env_value(layers, reference.only_member()), layers, depth + 1
            )
            if backing is not None:
                return backing
    for match in _SHELL_VARIABLE_RE.finditer(text):
        value = _env_value(layers, match.group(1))
        if value is not None and value != text:
            backing = _secret_backing(value, layers, depth + 1)
            if backing is not None:
                return backing
    return None


def _ref_version(uses_value: str, comment: str) -> tuple[float, ...] | None:
    """The release an action reference resolves to: a version tag, a commit
    with a version comment, or the default branch (the newest release)."""
    ref = uses_value.rpartition("@")[2].strip()
    if FULL_SHA_RE.fullmatch(ref):
        return _comment_version(comment)
    if ref.lower() in _DEFAULT_BRANCHES:
        return _NEWEST
    match = _REF_VERSION_RE.fullmatch(ref)
    if match is None:
        return None
    return tuple(float(part) for part in match.groups() if part is not None)


def _comment_version(comment: str) -> tuple[float, ...] | None:
    """The version in a pin comment such as ``# v5.0.0`` or ``# tag=v5``. A
    bare number counts only with a dot, so a date or count is not read as
    a release."""
    for match in _COMMENT_VERSION_RE.finditer(comment.lstrip("#")):
        if match.group(0).startswith("v") or match.group(2) is not None:
            return tuple(float(part) for part in match.groups() if part is not None)
    return None


def _uses_version(audit: _Audit, step: _Step) -> tuple[float, ...] | None:
    uses_value = step.step.get("uses")
    if not isinstance(uses_value, str):
        return None
    line = audit.line((*step.path, "uses"), key=False)
    return _ref_version(uses_value, audit.comment(line))


def _github_hosted(job: dict[str, Any] | None) -> bool:
    if not isinstance(job, dict):
        return False
    runs_on = job.get("runs-on")
    if isinstance(runs_on, str) and "${{" in runs_on:
        return _matrix_property_is_hosted(runs_on, job)
    return _is_hosted_label_value(runs_on)


def _cache_mode(
    data: dict[str, Any], job_id: Any, job: dict[str, Any]
) -> tuple[str | None, tuple[Any, ...] | None]:
    """The explicit cache-mode for a job and where it is set."""
    for holder, path in ((job, ("jobs", job_id, "cache-mode")), (data, ("cache-mode",))):
        if "cache-mode" not in holder:
            continue
        value = holder.get("cache-mode")
        if isinstance(value, str) and "${{" not in value:
            return value.strip().lower(), path
        return None, path
    return None, None


def _audit_uses_paths(audit: _Audit) -> None:
    if not audit.wants(RULE_OBFUSCATION):
        return
    sites: list[tuple[tuple[Any, ...], Any]] = []
    if audit.is_workflow:
        for job_id, job in _jobs(audit.data):
            sites.append((("jobs", job_id, "uses"), job.get("uses")))
    for step in _steps(audit):
        sites.append(((*step.path, "uses"), step.step.get("uses")))
    for path, uses_value in sites:
        if not isinstance(uses_value, str):
            continue
        oddities = _path_oddities(uses_value)
        if not oddities:
            continue
        normalized = _normalized_uses(uses_value)
        resolution = "GitHub cannot resolve it to a plain path"
        if normalized is not None:
            resolution = f"GitHub resolves it as {normalized}"
        audit.report(
            RULE_OBFUSCATION,
            "github-actions-obfuscated-uses",
            (
                f"uses: {uses_value.strip()} has {', '.join(oddities)} in its path; "
                f"{resolution}, while pin policies, allow lists and rules that "
                "match action names see a different string. Write the plain path."
            ),
            audit.line(path, key=False),
            "MEDIUM",
            uses_value.strip(),
        )


def _split_uses(uses_value: str) -> tuple[list[str], str] | None:
    text = uses_value.strip()
    if not text or text.startswith(("./", "../")) or text.lower().startswith("docker://"):
        return None
    if "${{" in text:
        return None
    target, at, ref = text.rpartition("@")
    if not at or "/" not in target:
        return None
    return target.split("/"), ref


def _path_oddities(uses_value: str) -> list[str]:
    split = _split_uses(uses_value)
    if split is None:
        return []
    parts, _ref = split
    oddities = []
    for part, label in ((".", "'.'"), ("..", "'..'"), ("", "an empty segment")):
        if part in parts and label not in oddities:
            oddities.append(label)
    return oddities


def _normalized_uses(uses_value: str) -> str | None:
    parts, ref = _split_uses(uses_value)
    owner, repo, rest = parts[0], parts[1], parts[2:]
    if owner in ("", ".", "..") or repo in ("", ".", ".."):
        return None
    kept: list[str] = []
    for part in rest:
        if part in ("", "."):
            continue
        if part == "..":
            if not kept:
                return None
            kept.pop()
            continue
        kept.append(part)
    return "/".join([owner, repo, *kept]) + "@" + ref


def _audit_expressions(audit: _Audit) -> None:
    wants_secrets = audit.is_workflow and audit.wants(RULE_UNREDACTED)
    wants_folding = audit.wants(RULE_OBFUSCATION)
    if not wants_secrets and not wants_folding:
        return
    for path, text in _scalars(audit.data):
        condition = _is_condition(path)
        spans = expressions.template_spans(text)
        if condition and not spans and text.strip():
            spans = [(text, 0, len(text))]
        if not spans:
            continue
        seen: Counter[str] = Counter()
        start_line = audit.line(path, key=False)
        for body, start, end in spans:
            node = _parse(body)
            if node is None:
                continue
            raw = text[start:end]
            needle = next(part for part in raw.splitlines() if part.strip())
            line = _fragment_line(audit.lines, start_line, needle, seen[needle])
            seen[needle] += 1
            occurrence = f"{_where(path)}:{raw}:{seen[needle]}"
            if wants_folding:
                _report_folding(audit, node, raw, line, occurrence)
            if wants_secrets and _printed(path):
                _report_decoded_secrets(audit, path, node, raw, line, occurrence)


def _scalars(data: dict[str, Any]) -> Iterator[tuple[tuple[Any, ...], str]]:
    stack: list[tuple[Any, tuple[Any, ...]]] = [(data, ())]
    visited = 0
    while stack:
        value, path = stack.pop()
        visited += 1
        if visited > MAX_YAML_GRAPH_NODES or len(path) > MAX_YAML_GRAPH_DEPTH:
            return
        if isinstance(value, str):
            yield path, value
        elif isinstance(value, dict):
            for key, child in reversed(list(value.items())):
                stack.append((child, (*path, key)))
        elif isinstance(value, list):
            for index in range(len(value) - 1, -1, -1):
                stack.append((value[index], (*path, index)))


def _is_condition(path: tuple[Any, ...]) -> bool:
    if not path or path[-1] != "if":
        return False
    job_condition = len(path) == 3 and path[0] == "jobs"
    step_condition = len(path) == 5 and path[0] == "jobs" and path[2] == "steps"
    action_condition = len(path) == 4 and path[:2] == ("runs", "steps")
    return job_condition or step_condition or action_condition


def _printed(path: tuple[Any, ...]) -> bool:
    """Values GitHub writes to the log or the run page: scripts, action
    inputs, env, matrix values, outputs, names, images and runner labels.
    Conditions, timeouts and a reusable call's ``secrets:`` (masked again in
    the called workflow) are not printed."""
    if not path:
        return False
    if path[0] != "jobs":
        return path[0] in {"env", "name", "run-name"}
    if len(path) < 3:
        return False
    key = path[2]
    if key == "steps":
        return len(path) >= 5 and path[4] in _PRINTED_STEP_KEYS
    if key == "strategy":
        return len(path) >= 4 and path[3] == "matrix"
    if key == "container":
        return len(path) >= 4 and path[3] in _PRINTED_CONTAINER_KEYS
    if key == "services":
        return len(path) >= 5 and path[4] in _PRINTED_CONTAINER_KEYS
    return key in _PRINTED_JOB_KEYS


def _where(path: tuple[Any, ...]) -> str:
    return ".".join(str(part) for part in path)


def _report_decoded_secrets(
    audit: _Audit,
    path: tuple[Any, ...],
    node: Any,
    raw: str,
    line: int,
    occurrence: str,
) -> None:
    job = None
    step = None
    jobs = audit.data.get("jobs")
    if len(path) >= 2 and path[0] == "jobs" and isinstance(jobs, dict):
        job = jobs.get(path[1])
    if isinstance(job, dict) and len(path) >= 4 and path[2] == "steps":
        steps = job.get("steps")
        if isinstance(steps, list) and isinstance(path[3], int) and path[3] < len(steps):
            step = steps[path[3]]
    layers = _env_layers(audit.data, job, step)
    for decoded, secret in _decoded_secrets(node, layers):
        audit.report(
            RULE_UNREDACTED,
            "github-actions-unredacted-secret",
            (
                f"{raw.strip()} decodes secret {secret} with fromJSON(); GitHub masks "
                f"only the stored secret text, so {decoded} is printed unmasked "
                "wherever this value appears in the log. Store each value as its "
                "own secret."
            ),
            line,
            "MEDIUM",
            f"{occurrence}:{decoded}",
            yaml_only=False,
        )


def _decoded_secrets(node: Any, layers: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """(printed text, secret) for each decoded secret whose value flows out
    of an expression: ``fromJSON(secrets.X).field`` or ``fromJSON(secrets.X)``,
    also through an env variable that holds the secret."""
    decoders = [
        candidate
        for candidate in _walk(node)
        if isinstance(candidate, expressions.Invoke) and candidate.name == "fromjson"
    ]
    found: list[tuple[str, str]] = []
    for reference in expressions.flowing_references(node):
        if isinstance(reference.base, expressions.Invoke) and reference.base.name == "fromjson":
            secret = _decoded_input(reference.base, layers)
            if secret is not None:
                found.append((reference.span.text, secret))
            continue
        secret = _plain_secret(reference, layers)
        if secret is None:
            continue
        for decoder in decoders:
            inside = decoder.span.start <= reference.span.start
            if inside and reference.span.end <= decoder.span.end:
                found.append((decoder.span.text, secret))
                break
    return list(dict.fromkeys(found))


def _decoded_input(decoder: expressions.Invoke, layers: list[dict[str, Any]]) -> str | None:
    for argument in decoder.arguments:
        for reference in expressions.flowing_references(argument):
            secret = _plain_secret(reference, layers)
            if secret is not None:
                return secret
    return None


def _plain_secret(reference: expressions.Reference, layers: list[dict[str, Any]]) -> str | None:
    if reference.under("secrets"):
        return reference.only_member() or "secrets"
    if reference.under("env") and reference.only_member() is not None:
        return _secret_backing(_env_value(layers, reference.only_member()), layers)
    return None


def _walk(node: Any) -> Iterator[Any]:
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(_children(current)))


def _children(node: Any) -> list[Any]:
    if isinstance(node, (expressions.Logical, expressions.Comparison)):
        return [node.left, node.right]
    if isinstance(node, expressions.Negation):
        return [node.operand]
    if isinstance(node, expressions.Invoke):
        return list(node.arguments)
    if isinstance(node, expressions.Reference):
        children = [node.base]
        for step in node.steps:
            if isinstance(step, expressions.Subscript):
                children.append(step.key)
        return children
    return []


def _report_folding(audit: _Audit, node: Any, raw: str, line: int, occurrence: str) -> None:
    for part, message in _foldings(node):
        audit.report(
            RULE_OBFUSCATION,
            "github-actions-obfuscated-expression",
            (
                f"{message} (in {raw.strip()}); write the value or reference "
                "directly. An expression that hides a fixed value or a plain "
                "reference misleads reviewers and tools that read the text."
            ),
            line,
            "LOW",
            f"{occurrence}:{part}",
            yaml_only=False,
        )


class _FoldExceeded(Exception):
    pass


@dataclass
class _FoldBudget:
    """Work and size limits for folding one expression. ``format('{0}{0}',
    x)`` doubles its input, so a short expression can describe a huge
    string; sizes are checked before anything is built."""

    steps: int = FOLD_STEP_LIMIT
    text: int = FOLD_TEXT_LIMIT

    def spend(self) -> None:
        self.steps -= 1
        if self.steps < 0:
            raise _FoldExceeded()

    def fits(self, size: int) -> None:
        if size > self.text:
            raise _FoldExceeded()


def _foldings(root: Any) -> list[tuple[str, str]]:
    """The largest parts of an expression that fold to a constant, and calls
    that only wrap a value. A literal alone is how a value is written. When
    the budget runs out, nothing is reported for the expression."""
    budget = _FoldBudget()
    try:
        return _collect_foldings(root, budget)
    except (_FoldExceeded, RecursionError):
        return []


def _collect_foldings(root: Any, budget: _FoldBudget) -> list[tuple[str, str]]:
    found = []
    pending = [root]
    while pending:
        node = pending.pop()
        value = _fold(node, 0, budget)
        if value is not _UNKNOWN:
            if not isinstance(node, expressions.Value) and not _data_literal(node):
                found.append(
                    (node.span.text, f"{node.span.text} always evaluates to {_shown(value)}")
                )
            continue
        identity = _identity(node)
        if identity is not None:
            found.append((node.span.text, f"{node.span.text} is only {identity}"))
        pending.extend(reversed(_children(node)))
    return found


def _data_literal(node: Any) -> bool:
    """``fromJSON('[...]')`` is the expression language's only way to write a
    list, object or typed number (``contains(fromJSON('["OWNER","MEMBER"]'),
    ...)``); it is data, not obfuscation."""
    return (
        isinstance(node, expressions.Invoke)
        and node.name == "fromjson"
        and isinstance(node.arguments[0], expressions.Value)
    )


def _identity(node: Any) -> str | None:
    if not isinstance(node, expressions.Invoke):
        return None
    if node.name == "fromjson":
        inner = node.arguments[0]
        if isinstance(inner, expressions.Invoke) and inner.name == "tojson":
            return f"{inner.arguments[0].span.text} after a toJSON/fromJSON round trip"
    if node.name == "format" and len(node.arguments) == 2:
        template = node.arguments[0]
        if isinstance(template, expressions.Value) and template.value == "{0}":
            return f"{node.arguments[1].span.text} as text"
    return None


def _shown(value: Any) -> str:
    text = _as_text(value)
    if isinstance(value, str):
        text = json.dumps(value)
    if len(text) > 80:
        text = text[:77] + "..."
    return text


def _fold(node: Any, depth: int, budget: _FoldBudget | None = None) -> Any:
    """The value of an expression without contexts, or _UNKNOWN. Raises
    _FoldExceeded when the budget runs out."""
    if budget is None:
        budget = _FoldBudget()
    budget.spend()
    if depth > expressions.DEPTH_LIMIT:
        return _UNKNOWN
    if isinstance(node, expressions.Value):
        return node.value
    if isinstance(node, expressions.Negation):
        operand = _fold(node.operand, depth + 1, budget)
        if operand is _UNKNOWN:
            return _UNKNOWN
        return not _truthy(operand)
    if isinstance(node, (expressions.Logical, expressions.Comparison)):
        left = _fold(node.left, depth + 1, budget)
        right = _fold(node.right, depth + 1, budget)
        if left is _UNKNOWN or right is _UNKNOWN:
            return _UNKNOWN
        if isinstance(node, expressions.Comparison):
            return _compare(node.operator, left, right)
        if node.operator == "&&":
            if _truthy(left):
                return right
            return left
        if _truthy(left):
            return left
        return right
    if isinstance(node, expressions.Invoke):
        arguments = [_fold(argument, depth + 1, budget) for argument in node.arguments]
        if any(argument is _UNKNOWN for argument in arguments):
            return _UNKNOWN
        return _call(node.name, arguments, budget)
    if isinstance(node, expressions.Reference) and not isinstance(node.base, expressions.Field):
        value = _fold(node.base, depth + 1, budget)
        for step in node.steps:
            if value is _UNKNOWN:
                return _UNKNOWN
            value = _member(value, step, depth, budget)
        return value
    return _UNKNOWN


def _member(value: Any, step: Any, depth: int, budget: _FoldBudget) -> Any:
    if isinstance(step, expressions.Field):
        key: Any = step.name
    elif isinstance(step, expressions.Subscript) and not isinstance(
        step.key, expressions.Wildcard
    ):
        key = _fold(step.key, depth + 1, budget)
        if key is _UNKNOWN:
            return _UNKNOWN
    else:
        return _UNKNOWN
    if isinstance(value, dict) and isinstance(key, str):
        for name, item in value.items():
            if name.lower() == key.lower():
                return item
        return None
    if isinstance(value, list) and isinstance(key, (int, float)) and not isinstance(key, bool):
        if float(key).is_integer() and 0 <= int(key) < len(value):
            return value[int(key)]
    return None


def _call(name: str, arguments: list[Any], budget: _FoldBudget) -> Any:
    if name == "fromjson":
        if not isinstance(arguments[0], str):
            return _UNKNOWN
        budget.fits(len(arguments[0]))
        try:
            return json.loads(arguments[0])
        except (ValueError, RecursionError):
            return _UNKNOWN
    if name == "tojson":
        budget.fits(_json_size(arguments[0], budget.text))
        return json.dumps(arguments[0], indent=2)
    if name == "format":
        return _format(arguments, budget)
    if name == "join":
        separator = ","
        if len(arguments) > 1:
            separator = _as_text(arguments[1])
        if not isinstance(arguments[0], list):
            return _as_text(arguments[0])
        parts = [_as_text(item) for item in arguments[0]]
        budget.fits(sum(len(part) for part in parts) + len(separator) * len(parts))
        return separator.join(parts)
    if name == "contains":
        haystack, needle = arguments
        if isinstance(haystack, list):
            return any(_compare("==", item, needle) for item in haystack)
        return _as_text(needle).lower() in _as_text(haystack).lower()
    if name == "startswith":
        return _as_text(arguments[0]).lower().startswith(_as_text(arguments[1]).lower())
    if name == "endswith":
        return _as_text(arguments[0]).lower().endswith(_as_text(arguments[1]).lower())
    if name == "case":
        for index in range(0, len(arguments) - 1, 2):
            if _truthy(arguments[index]):
                return arguments[index + 1]
        return arguments[-1]
    return _UNKNOWN


def _format(arguments: list[Any], budget: _FoldBudget) -> Any:
    template = arguments[0]
    if not isinstance(template, str):
        return _UNKNOWN
    out = []
    size = 0
    index = 0
    while index < len(template):
        budget.spend()
        char = template[index]
        if template.startswith("{{", index) or template.startswith("}}", index):
            out.append(char)
            index += 2
            continue
        if char == "{":
            closing = template.find("}", index)
            slot = template[index + 1 : closing]
            if closing < 0 or not _SLOT_RE.fullmatch(slot) or int(slot) + 1 >= len(arguments):
                return _UNKNOWN
            piece = _as_text(arguments[int(slot) + 1])
            size += len(piece)
            budget.fits(size)
            out.append(piece)
            index = closing + 1
            continue
        if char == "}":
            return _UNKNOWN
        size += 1
        budget.fits(size)
        out.append(char)
        index += 1
    return "".join(out)


def _json_size(value: Any, cap: int) -> int:
    """An upper bound on toJSON's output length, counted only up to cap.
    Each value costs its text plus a line indented two spaces per level."""
    size = 0
    pending = [(value, 0)]
    while pending and size <= cap:
        current, depth = pending.pop()
        size += 2 * depth + 2
        if isinstance(current, str):
            size += 6 * len(current) + 2
        elif isinstance(current, dict):
            for key, item in current.items():
                size += 6 * len(str(key)) + 4
                pending.append((item, depth + 1))
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
        else:
            size += 32
    return size


def _truthy(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0 and not math.isnan(value)
    if isinstance(value, str):
        return value != ""
    return True


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            if value > 0:
                return "Infinity"
            return "-Infinity"
        if float(value).is_integer():
            return str(int(value))
        return repr(float(value))
    if isinstance(value, list):
        return "Array"
    if isinstance(value, dict):
        return "Object"
    return str(value)


def _as_number(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0.0
        if _HEX_NUMBER_RE.fullmatch(text):
            return float(int(text, 16))
        if _DECIMAL_NUMBER_RE.fullmatch(text):
            return float(text)
        if text in ("Infinity", "+Infinity", "-Infinity"):
            return float(text.replace("Infinity", "inf"))
        return math.nan
    return math.nan


def _compare(operator: str, left: Any, right: Any) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        first: Any = left.upper()
        second: Any = right.upper()
    elif isinstance(left, (list, dict)) or isinstance(right, (list, dict)):
        if operator == "==":
            return left is right
        if operator == "!=":
            return left is not right
        return False
    else:
        first = _as_number(left)
        second = _as_number(right)
    if operator == "==":
        return first == second
    if operator == "!=":
        return first != second
    if operator == "<":
        return first < second
    if operator == "<=":
        return first <= second
    if operator == ">":
        return first > second
    return first >= second


@dataclass
class _Trace:
    """Follows a checkout ref or a git command back to who chose it."""

    data: dict[str, Any]
    job: dict[str, Any]
    callers: list[tuple[Path, dict[str, Any], Any, dict[str, Any]]]
    events: frozenset[str] | None = None

    def present(self, reference: expressions.Reference) -> bool:
        """Whether the events that run here carry the payload field; on
        issue_comment, github.event.pull_request and github.head_ref are
        empty and a checkout of them gets the default branch."""
        if self.events is None:
            return True
        names = reference.names()
        carriers = None
        if names[:2] == ["github", "head_ref"]:
            carriers = _PAYLOAD_CARRIERS["pull_request"]
        elif len(names) >= 3 and names[:2] == ["github", "event"]:
            carriers = _PAYLOAD_CARRIERS.get(names[2])
        if carriers is None:
            return True
        return bool(self.events & carriers)

    def text(self, text: Any, layers: list[dict[str, Any]], depth: int = 0) -> str | None:
        if not isinstance(text, str) or depth > _TRACE_DEPTH:
            return None
        if _PULL_REF_TEXT_RE.search(text):
            return "a pull request ref"
        for reference in _references(text):
            reason = self.reference(reference, layers, depth)
            if reason is not None:
                return reason
        for match in _SHELL_VARIABLE_RE.finditer(text):
            value = _env_value(layers, match.group(1))
            if isinstance(value, str) and value != text:
                reason = self.text(value, layers, depth + 1)
                if reason is not None:
                    return reason
        return None

    def reference(
        self, reference: expressions.Reference, layers: list[dict[str, Any]], depth: int
    ) -> str | None:
        key = reference.key() or reference.span.text
        if not self.present(reference):
            return None
        if any(reference.under(context) for context in _PR_HEAD_CONTEXTS):
            return f"the pull request head ({key})"
        if any(reference.under(context) for context in _EVENT_TEXT_CONTEXTS):
            return f"event text ({key})"
        names = reference.names()
        if len(names) >= 4 and names[0] == "steps" and names[2] == "outputs":
            producer = _step_by_id(self.job, names[1])
            if producer is not None and _output_carries_head(producer, names[3]):
                return f"output {names[3]} of step {names[1]}, the pull request head"
            return None
        if len(names) >= 4 and names[0] == "needs" and names[2] == "outputs":
            other = _named(self.data.get("jobs"), names[1])
            if not isinstance(other, dict):
                return None
            value = _named(other.get("outputs"), names[3])
            inner = _Trace(self.data, other, self.callers, self.events)
            return inner.text(value, _env_layers(self.data, other, None), depth + 1)
        if names[0] == "env" and reference.only_member() is not None:
            return self.text(_env_value(layers, reference.only_member()), layers, depth + 1)
        if names[0] == "inputs" and reference.only_member() is not None:
            for _path, caller_data, _job_id, caller_job in self.callers:
                passed = _named(caller_job.get("with"), reference.only_member())
                inner = _Trace(caller_data, caller_job, [])
                caller_layers = _env_layers(caller_data, caller_job, None)
                reason = inner.text(passed, caller_layers, depth + 1)
                if reason is not None:
                    return f"{reason}, passed in by a caller"
        return None


def _named(mapping: Any, name: str | None) -> Any:
    if not isinstance(mapping, dict) or name is None:
        return None
    for key, value in mapping.items():
        if str(key).lower() == name.lower():
            return value
    return None


def _step_by_id(job: dict[str, Any], step_id: str | None) -> dict[str, Any] | None:
    steps = job.get("steps")
    if not isinstance(steps, list) or step_id is None:
        return None
    for step in steps:
        if isinstance(step, dict) and str(step.get("id", "")).lower() == step_id.lower():
            return step
    return None


def _step_text(step: dict[str, Any]) -> str:
    parts = [str(step.get("uses") or ""), str(step.get("run") or "")]
    for value in _with(step).values():
        parts.append(str(value))
    return "\n".join(parts)


def _output_carries_head(producer: dict[str, Any], output: str | None) -> bool:
    """Whether a step that looks the pull request up sets this output to its
    head: the value assigned to the output (or the variable it is assigned
    from) names the head ref or SHA. An action's own output counts by name."""
    if output is None or not _PR_LOOKUP_RE.search(_step_text(producer)):
        return False
    scripts = [producer.get("run"), _with(producer).get("script")]
    text = "\n".join(script for script in scripts if isinstance(script, str))
    name = re.escape(output)
    values = []
    for template in _OUTPUT_ASSIGNMENTS:
        pattern = template.format(name=name)
        values.extend(match.group("value") for match in re.finditer(pattern, text, re.IGNORECASE))
    uses_value = producer.get("uses")
    if output.lower() == "result" and isinstance(uses_value, str):
        if _uses_repo(uses_value) == "actions/github-script":
            values.extend(match.group(1) for match in re.finditer(r"\breturn\s+([^\n;]+)", text))
    if not values:
        return not text and "head" in output.lower()
    for value in values:
        if _HEAD_VALUE_RE.search(value):
            return True
        for variable in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value)[:4]:
            assigned = re.search(
                rf"(?<![\w.]){re.escape(variable)}\s*=\s*([^\n;]+)", text
            )
            if assigned is not None and _HEAD_VALUE_RE.search(assigned.group(1)):
                return True
    return False


def _code_arrival(trace: _Trace, step: _Step) -> tuple[str, bool] | None:
    """How a step brings pull request code into the workspace, and whether
    the step itself goes on to run more commands."""
    layers = _env_layers(trace.data, trace.job, step.step)
    uses_value = step.step.get("uses")
    if isinstance(uses_value, str) and _uses_matches(uses_value, "actions/checkout"):
        config = _with(step.step)
        for name in ("ref", "repository"):
            reason = trace.text(config.get(name), layers)
            if reason is not None:
                return f"actions/checkout {name} from {reason}", False
        return None
    run = step.step.get("run")
    if not isinstance(run, str):
        return None
    commands = [
        line for line in run.splitlines() if line.strip() and not line.strip().startswith("#")
    ]
    for position, line in enumerate(commands):
        reason = None
        if _PR_CHECKOUT_COMMAND_RE.search(line):
            reason = "the pull request branch"
        elif _GIT_REF_COMMAND_RE.search(line) and _PR_CODE_FETCH_RE.search(line):
            reason = "a pull request ref"
        elif _GIT_REF_COMMAND_RE.search(line):
            reason = trace.text(line, layers)
        if reason is not None:
            statements = split_shell_statements(line)
            trailing = bool(statements) and not _arrives_last(statements)
            return f"{line.strip()}: {reason}", trailing or position < len(commands) - 1
    return None


def _arrives_last(statements: list[str]) -> bool:
    last = statements[-1]
    return bool(
        _PR_CHECKOUT_COMMAND_RE.search(last)
        or _GIT_REF_COMMAND_RE.search(last)
    )


def _runs_code_after(steps: list[_Step], position: int) -> bool:
    """A later run block or local action, which executes what was checked out."""
    for later in steps[position + 1 :]:
        uses_value = later.step.get("uses")
        if isinstance(later.step.get("run"), str):
            return True
        if isinstance(uses_value, str) and uses_value.strip().startswith("./"):
            return True
    return False


def _outsider_step(audit: _Audit, step: _Step, event: str) -> bool:
    """Whether an account without write access gets this step to run on the
    event: the job and step conditions hold for it and no earlier step is a
    verified permission check that this step depends on."""
    if not _step_runs(audit, step, event, untrusted=True):
        return False
    raw = step.job.get("steps")
    for index in range(step.index):
        earlier = raw[index]
        if isinstance(earlier, dict) and _verified_gate(earlier, step.step):
            return False
    return True


def _step_runs(audit: _Audit, step: _Step, event: str, *, untrusted: bool) -> bool:
    reach = audit.reach()
    key = str(step.job_id)
    if key not in reach.jobs or not reach.job_runs(key, event, untrusted):
        return False
    context = EvalContext(
        event,
        untrusted,
        lambda dep: reach._blocked(dep, event, untrusted, (key,)),
        lambda dep: _job_routes_by_event(reach.jobs.get(dep)),
    )
    return evaluate(parse_condition(step.step.get("if")), context)[0]


@dataclass(frozen=True)
class _PermissionAction:
    """A permission-check action as its source behaves (checked 2026-10-21).

    ``level`` is the input naming the required repository permission (None
    for a team or allow-list check); ``fails`` says whether a refusal fails
    the step, unless ``unless`` (input, value) is set, or only when ``only``
    (input, value) is set; ``outputs`` are set to 'true' for an allowed user;
    ``actor`` is the input naming whose permission is checked."""

    level: str | None
    default_level: str | None = None
    fails: bool = True
    unless: tuple[str, str] | None = None
    only: tuple[str, str] | None = None
    outputs: tuple[str, ...] = ()
    actor: str | None = None


_PERMISSION_ACTIONS = {
    "actions-cool/check-user-permission": _PermissionAction(
        "require", only=("error-if-missing", "true"), outputs=("require-result",), actor="username"
    ),
    "prince-chrismc/check-actor-permissions-action": _PermissionAction(
        "permission", outputs=("permitted",)
    ),
    "sushichop/action-repository-permission": _PermissionAction(
        "required-permission", "admin", unless=("relax", "true"), outputs=("permitted",)
    ),
    "xt0rted/slash-command-action": _PermissionAction("permission-level", "write"),
    "lannonbr/repo-permission-check-action": _PermissionAction("permission"),
    "themoddinginquisition/actions-team-membership": _PermissionAction(
        None, unless=("exit", "false"), outputs=("permitted",)
    ),
    "skjnldsv/check-actor-permission": _PermissionAction("require", outputs=("result",)),
    "morfien101/actions-authorized-user": _PermissionAction(
        None, fails=False, outputs=("authorized",), actor="username"
    ),
}
_ELEVATED_LEVELS = frozenset({"admin", "maintain", "write", "triage"})
_ACTOR_CONTEXTS = (
    "github.actor",
    "github.triggering_actor",
    "github.event.sender",
    "github.event.comment.user",
    "github.event.pull_request.user",
    "github.event.review.user",
)
_SCRIPT_REJECTS_RE = re.compile(r"core\.setFailed\(|process\.exit\(\s*[1-9]|\bthrow\b")
_SHELL_REJECTS_RE = re.compile(r"\bexit\s+[1-9]")


def _verified_gate(gate: dict[str, Any], target: dict[str, Any]) -> bool:
    """Whether a step stops outsiders before ``target``: a known permission
    check that demands more than read access of the triggering account and
    either fails the job (``target`` then only runs on success) or sets an
    output that ``target``'s condition requires; or a script that checks
    the permission and exits non-zero. A name or keyword is not enough."""
    uses_value = gate.get("uses")
    if isinstance(uses_value, str):
        known = _PERMISSION_ACTIONS.get(_uses_repo(uses_value))
        if known is not None:
            return _action_gate(known, gate, target)
    if not _script_rejects(gate):
        return False
    return not _continues_on_error(gate) and not _overrides_status(target)


def _action_gate(known: _PermissionAction, gate: dict[str, Any], target: dict[str, Any]) -> bool:
    config = _with(gate)
    if known.level is not None:
        level = config.get(known.level, known.default_level)
        if not isinstance(level, str) or level.strip().lower() not in _ELEVATED_LEVELS:
            return False
    if known.actor is not None and known.actor in config:
        names = _references(config.get(known.actor))
        if not any(reference.under(context) for reference in names for context in _ACTOR_CONTEXTS):
            return False
    if _requires_output(target, gate, known.outputs):
        return True
    if not _action_fails(known, config):
        return False
    return not _continues_on_error(gate) and not _overrides_status(target)


def _action_fails(known: _PermissionAction, config: dict[str, Any]) -> bool:
    if not known.fails:
        return False
    if known.only is not None:
        name, value = known.only
        setting = config.get(name)
        return _is_literal(setting) and str(setting).strip().lower() == value
    if known.unless is not None:
        name, value = known.unless
        setting = config.get(name)
        if setting is None:
            return True
        return _is_literal(setting) and str(setting).strip().lower() != value
    return True


def _requires_output(
    target: dict[str, Any], gate: dict[str, Any], outputs: tuple[str, ...]
) -> bool:
    """Whether every way ``target``'s condition holds needs the gate's
    'allowed' output to be true: a conjunct ``steps.<id>.outputs.<name> ==
    'true'`` (or the output alone)."""
    gate_id = gate.get("id")
    condition = target.get("if")
    if not outputs or not isinstance(gate_id, str) or not isinstance(condition, str):
        return False
    body = condition.strip()
    spans = expressions.template_spans(body)
    if len(spans) == 1 and spans[0][1] == 0 and spans[0][2] == len(body):
        body = spans[0][0]
    node = _parse(body)
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, expressions.Logical) and current.operator == "&&":
            pending.extend([current.left, current.right])
        elif _allowed_output(current, gate_id, outputs):
            return True
    return False


def _allowed_output(node: Any, gate_id: str, outputs: tuple[str, ...]) -> bool:
    patterns = [f"steps.{gate_id}.outputs.{name}" for name in outputs]
    if isinstance(node, expressions.Reference):
        return any(node.is_exactly(pattern) for pattern in patterns)
    if not isinstance(node, expressions.Comparison) or node.operator != "==":
        return False
    for side, other in ((node.left, node.right), (node.right, node.left)):
        is_output = isinstance(side, expressions.Reference) and any(
            side.is_exactly(pattern) for pattern in patterns
        )
        is_true = isinstance(other, expressions.Value) and str(other.value).lower() == "true"
        if is_output and is_true:
            return True
    return False


def _script_rejects(gate: dict[str, Any]) -> bool:
    """A run block or github-script that checks the account's permission or
    association (not only prints it) and exits non-zero."""
    run = gate.get("run")
    script = _with(gate).get("script")
    checks = []
    if isinstance(run, str):
        checks.append((_PRINTED_LINE_RE.sub("", run), _SHELL_REJECTS_RE))
    uses_value = gate.get("uses")
    if isinstance(script, str) and isinstance(uses_value, str):
        if _uses_repo(uses_value) == "actions/github-script":
            checks.append((_PRINTED_LINE_RE.sub("", script), _SCRIPT_REJECTS_RE))
    for text, rejects in checks:
        looks_up = _PERMISSION_SCRIPT_RE.search(text) or (
            _ASSOCIATION_CHECK_RE.search(text) and _MEMBER_VALUE_RE.search(text)
        )
        if looks_up and rejects.search(text):
            return True
    return False


def _continues_on_error(step: dict[str, Any]) -> bool:
    flag = step.get("continue-on-error")
    return flag is not None and _actions_bool(flag) is not False


def _overrides_status(step: dict[str, Any]) -> bool:
    return has_status_override(parse_condition(step.get("if")))


class _StrictReach(_Reach):
    """Job reach where a needed job stops outsiders only through a verified
    failing permission check, not a permission-sounding step."""

    def _blocked(self, job_id: str, event: str, untrusted: bool, stack: tuple[str, ...]) -> bool:
        job = self.jobs.get(job_id)
        if job is None:
            return False
        if not self.job_runs(job_id, event, untrusted, stack):
            return True
        return untrusted and _job_rejects_outsiders(job)


def _job_rejects_outsiders(job: dict[str, Any]) -> bool:
    """A job that fails for outsiders: an unconditional verified check that
    fails the step, in a job that does not continue on error."""
    if _continues_on_error(job) or not isinstance(job.get("steps"), list):
        return False
    for gate in job["steps"]:
        if isinstance(gate, dict) and "if" not in gate and _verified_gate(gate, {}):
            return True
    return False


def _outsider_events(data: dict[str, Any], path: Path, root: Path | None) -> dict[str, list[str]]:
    """outsider_job_events with _StrictReach: the events on which an account
    without write access can make each job run."""
    events = _untrusted_events(data, path, root, {})
    if not events:
        return {}
    reach = _StrictReach(data)
    reachable = {}
    for job_id in reach.jobs:
        job_events = [event for event in events if reach.job_runs(job_id, event, True)]
        if job_events:
            reachable[job_id] = job_events
    return reachable


def _untrusted_input(trace: _Trace, step: _Step, events: set[str]) -> str | None:
    """Pull request code, pull request artifacts or event text that a step
    hands to the job."""
    arrival = _code_arrival(trace, step)
    if arrival is not None:
        return f"step {step.index + 1} checks out pull request code ({arrival[0]})"
    run = step.step.get("run")
    if isinstance(run, str) and "${{" in run and interpolates_untrusted(
        trace.data, trace.job, step.step, run
    ):
        return f"step {step.index + 1} expands event text into its script"
    uses_value = step.step.get("uses")
    downloads = isinstance(uses_value, str) and "download-artifact" in _uses_repo(uses_value)
    if "workflow_run" in events and downloads:
        config = _with(step.step)
        for name in ("run-id", "run_id"):
            for reference in _references(config.get(name)):
                if reference.under("github.event.workflow_run"):
                    return f"step {step.index + 1} downloads artifacts from the triggering run"
    return None


def _audit_comment_trigger(audit: _Audit) -> None:
    if not audit.wants(RULE_TRIGGER) or "issue_comment" not in _trigger_map(audit.data):
        return
    outsiders = audit.outsiders()
    for job_id, job in _jobs(audit.data):
        events = outsiders.get(str(job_id)) or []
        if "issue_comment" not in events or isinstance(job.get("uses"), str):
            continue
        trace = _Trace(audit.data, job, [], frozenset({"issue_comment"}))
        steps = list(_job_steps(job_id, job))
        for position, step in enumerate(steps):
            arrival = _code_arrival(trace, step)
            if arrival is None or not _outsider_step(audit, step, "issue_comment"):
                continue
            how, continues = arrival
            if not continues and not _runs_code_after(steps, position):
                continue
            exposure = _job_exposure(audit.data, job_id, job)
            if not exposure:
                break
            audit.report(
                RULE_TRIGGER,
                "github-actions-dangerous-trigger",
                (
                    f"issue_comment lets anyone who can comment start job {job_id}, "
                    f"which checks out pull request code ({how}) and runs it with "
                    f"{'; '.join(exposure)}. Require a maintainer (author_association "
                    "or a permission check that fails the job) before the checkout, "
                    "or build the pull request in an unprivileged pull_request workflow."
                ),
                _line_for_trigger(audit.data, audit.lines, "issue_comment"),
                "HIGH",
                f"issue_comment:{job_id}",
            )
            break


def _job_exposure(data: dict[str, Any], job_id: Any, job: dict[str, Any]) -> list[str]:
    """What code running in the job could take or tamper with."""
    exposure = []
    if "permissions" not in job and "permissions" not in data:
        exposure.append("an undeclared token (it may have write access)")
    else:
        permissions = data.get("permissions")
        if "permissions" in job:
            permissions = job.get("permissions")
        scopes, _oidc = _permissions_scopes(permissions)
        if scopes:
            exposure.append("a token with " + ", ".join(scopes))
    secrets = _secret_names([job, data.get("env")])
    if secrets:
        exposure.append("secrets " + ", ".join(secrets[:4]))
    if runner_may_be_self_hosted(job):
        exposure.append("a self-hosted runner")
    mode, _where_set = _cache_mode(data, job_id, job)
    if mode in _WRITING_CACHE_MODES:
        exposure.append(f"cache-mode: {mode}")
    return exposure


@dataclass(frozen=True)
class _CacheGrant:
    mode: str
    events: frozenset[str]
    where: tuple[Any, ...]
    origin: str


def _audit_cache_writes(audit: _Audit) -> None:
    """A low-trust run reads caches only, unless cache-mode grants writes.
    Report a grant in a job that outsiders start and that handles their input.
    pull_request_review runs, like pull_request, write only to the merge ref."""
    if not audit.wants(RULE_CACHE):
        return
    outsiders = audit.outsiders()
    for job_id, job in _jobs(audit.data):
        for grant in _cache_grants(audit, job_id, job, outsiders):
            if _report_cache_grant(audit, job_id, job, grant):
                break


def _cache_grants(
    audit: _Audit, job_id: Any, job: dict[str, Any], outsiders: dict[str, list[str]]
) -> list[_CacheGrant]:
    """Write-capable cache access for runs that outsiders start: the job's
    own cache-mode, or a local caller's, which a called workflow inherits
    when it sets none and which caps one it does set."""
    mode, where = _cache_mode(audit.data, job_id, job)
    grants = []
    direct = frozenset(outsiders.get(str(job_id)) or []) - _PULL_REQUEST_SCOPED_EVENTS
    if direct and mode in _WRITING_CACHE_MODES:
        grants.append(_CacheGrant(mode, direct, where, ""))
    if "workflow_call" not in _trigger_map(audit.data):
        return grants
    for caller_path, caller_data, caller_job_id, caller_job in audit.callers():
        cap, _cap_where = _cache_mode(caller_data, caller_job_id, caller_job)
        granted = _called_cache_mode(mode, cap)
        if granted not in _WRITING_CACHE_MODES:
            continue
        reached = _outsider_events(caller_data, caller_path, audit.root)
        events = frozenset(reached.get(str(caller_job_id)) or []) - _PULL_REQUEST_SCOPED_EVENTS
        if not events:
            continue
        place = where
        origin = f" (called from {caller_path.name})"
        if mode is None:
            place = ("jobs", job_id)
            origin = f" (passed down by {caller_path.name}, job {caller_job_id})"
        grants.append(_CacheGrant(granted, events, place, origin))
    return grants


def _called_cache_mode(own: str | None, cap: str | None) -> str | None:
    """A called workflow's cache access: a caller's explicit mode is passed
    down when the workflow sets none, and a request beyond it stops the run.
    Without either, a low-trust caller gives read access."""
    if own is None:
        return cap
    if cap is None:
        return own
    allowed = {
        "write": {"write", "write-only", "read", "none"},
        "write-only": {"write-only", "none"},
        "read": {"read", "none"},
        "none": {"none"},
    }
    if own in allowed.get(cap, set()):
        return own
    return None


def _report_cache_grant(
    audit: _Audit, job_id: Any, job: dict[str, Any], grant: _CacheGrant
) -> bool:
    callers = []
    if grant.origin:
        callers = audit.callers()
    trace = _Trace(audit.data, job, callers, grant.events)
    evidence = None
    for step in _job_steps(job_id, job):
        if not any(_outsider_step(audit, step, event) for event in sorted(grant.events)):
            continue
        evidence = _untrusted_input(trace, step, set(grant.events))
        if evidence is not None:
            break
    if evidence is None:
        return False
    savers = _cache_savers(audit, job_id, job, set(grant.events))
    saving = ""
    if savers:
        saving = " Steps here that save a cache: " + ", ".join(savers) + "."
    audit.report(
        RULE_CACHE,
        "github-actions-cache-poisoning",
        (
            f"Job {job_id} runs for {', '.join(sorted(grant.events))}, which accounts "
            f"without write access can start, and cache-mode: {grant.mode}{grant.origin} "
            "lifts GitHub's read-only cache default for those runs, while "
            f"{evidence}. Whatever that input does can save cache entries that trusted "
            "runs on the default branch restore. Use cache-mode: read here and save "
            f"caches from a push-triggered workflow.{saving}"
        ),
        audit.line(grant.where),
        "HIGH",
        f"cache-mode:{grant.mode}:{job_id}",
    )
    return True


def _cache_savers(audit: _Audit, job_id: Any, job: dict[str, Any], events: set[str]) -> list[str]:
    savers = []
    for step in _job_steps(job_id, job):
        uses_value = step.step.get("uses")
        if not isinstance(uses_value, str):
            continue
        repo = _uses_repo(uses_value)
        config = _with(step.step)
        if repo == "actions/cache/save" or _cache_action_enabled(uses_value, config):
            savers.append(f"{repo} (step {step.index + 1})")
            continue
        reason = _default_cache_reason(audit, step, events, saving=True)
        if reason is not None:
            savers.append(f"{repo} (step {step.index + 1}, on by default)")
    return savers


def _audit_default_caches(audit: _Audit) -> None:
    """Release workflows restoring a cache the action enables by default.
    Inputs set to enable caching are SKY-D308's existing check."""
    if not audit.wants(RULE_CACHE) or not _is_release_like_workflow(_on_value(audit.data)):
        return
    release_events = _release_events(audit.data)
    for job_id, job in _jobs(audit.data):
        mode, _where_set = _cache_mode(audit.data, job_id, job)
        if mode is not None and mode not in _RESTORING_CACHE_MODES:
            continue
        for step in _job_steps(job_id, job):
            released = any(
                _step_runs(audit, step, event, untrusted=False) for event in release_events
            )
            if not released:
                continue
            reason = _default_cache_reason(audit, step, set(release_events), saving=False)
            if reason is None:
                continue
            uses_value = str(step.step.get("uses")).strip()
            audit.report(
                RULE_CACHE,
                "github-actions-cache-poisoning",
                (
                    f"Release-like workflow restores a cache that {reason}. A release "
                    "build should not start from mutable cache state; turn the cache "
                    "off for this step or set cache-mode: none on the job."
                ),
                audit.line((*step.path, "uses"), key=False),
                "MEDIUM",
                f"{uses_value}:default-cache:{job_id}:{step.index}",
            )


def _release_events(data: dict[str, Any]) -> list[str]:
    """The events a release-like workflow publishes on: release, tag push."""
    triggers = _trigger_map(data)
    events = []
    if "release" in triggers:
        events.append("release")
    push = triggers.get("push")
    if isinstance(push, dict) and "tags" in push:
        events.append("push")
    return events


def _default_cache_reason(
    audit: _Audit, step: _Step, events: set[str], *, saving: bool
) -> str | None:
    """Why an action caches although no input asked it to, or None.

    Steps whose inputs explicitly enable a cache are left to the existing
    SKY-D308 check, so the two never report the same step."""
    uses_value = step.step.get("uses")
    if not isinstance(uses_value, str):
        return None
    repo = _uses_repo(uses_value)
    config = _with(step.step)
    if _cache_action_enabled(uses_value, config):
        return None
    if repo == "astral-sh/setup-uv":
        return _uv_cache_reason(audit, step, config, events, saving=saving)
    if repo == "actions/setup-node":
        return _node_cache_reason(audit, step, config)
    known = _DEFAULT_CACHES.get(repo)
    if known is None or not _default_cache_active(known, repo, config, saving=saving):
        return None
    version = _uses_version(audit, step)
    if known.since is not None and (version is None or version < known.since):
        return None
    if known.since is not None:
        return f"{repo} turns on by default from v{known.since[0]} ({known.toggle} is not set)"
    if known.opt_in:
        return f"{repo} turns on by default ({known.toggle} is not set)"
    return f"{repo} keeps on unless {known.toggle} turns it off"


def _default_cache_active(
    known: _DefaultCache, repo: str, config: dict[str, Any], *, saving: bool
) -> bool:
    """Whether the toggle leaves the default cache on. An opt-in toggle that
    is present is an explicit choice, which the existing check judges; an
    expression is not known to stop the cache or keep it."""
    if saving and repo == "swatinem/rust-cache" and _literal_false(config.get("save-if")):
        return False
    if known.toggle not in config:
        return True
    if known.opt_in:
        return False
    value = config.get(known.toggle)
    return _is_literal(value) and str(value).strip().lower() not in known.stops


def _uv_cache_reason(
    audit: _Audit, step: _Step, config: dict[str, Any], events: set[str], *, saving: bool
) -> str | None:
    if "enable-cache" in config or not _github_hosted(step.job):
        return None
    if saving and _literal_false(config.get("save-cache")):
        return None
    if not saving and _literal_false(config.get("restore-cache")):
        return None
    version = _uses_version(audit, step)
    if version is None or version < _UV_AUTO_CACHE:
        return None
    if version >= _UV_RELEASE_AWARE:
        quiet = {"release", "push", "pull_request_target", "workflow_run"}
        if not saving or events <= quiet:
            return None
        return "astral-sh/setup-uv turns on for GitHub-hosted runners (enable-cache: auto)"
    return (
        "astral-sh/setup-uv turns on for GitHub-hosted runners before v10, release "
        "and tag runs included (enable-cache: auto)"
    )


def _node_cache_reason(audit: _Audit, step: _Step, config: dict[str, Any]) -> str | None:
    if "cache" in config or "package-manager-cache" in config:
        return None
    checked_out = any(
        isinstance(earlier.step.get("uses"), str)
        and _uses_matches(earlier.step["uses"], "actions/checkout")
        for earlier in _job_steps(step.job_id, step.job)
        if earlier.index < step.index
    )
    if not checked_out:
        return None
    version = _uses_version(audit, step)
    if version is None or version < _NODE_PACKAGE_MANAGER_CACHE:
        return None
    if not _package_json_names_npm(audit):
        return None
    return (
        "actions/setup-node turns on for npm from v5 because package.json names npm "
        "as its package manager (package-manager-cache defaults to true)"
    )


def _package_json_names_npm(audit: _Audit) -> bool:
    """setup-node reads $GITHUB_WORKSPACE/package.json: devEngines.packageManager
    first, then packageManager (setup-node src/main.ts)."""
    return audit.cached("npm_package_manager", lambda: _workspace_names_npm(audit.path))


def _workspace_names_npm(workflow: Path) -> bool:
    if workflow.parent.name != "workflows" or workflow.parent.parent.name != ".github":
        return False
    repository = workflow.parent.parent.parent
    text = read_project_text_no_symlink(
        repository, repository / "package.json", max_bytes=1_000_000, encoding="utf-8"
    )
    return _names_npm(text)


def _names_npm(text: str | None) -> bool:
    if text is None:
        return False
    try:
        package = json.loads(text)
    except (ValueError, RecursionError):
        return False
    if not isinstance(package, dict):
        return False
    engines = package.get("devEngines")
    declared = None
    if isinstance(engines, dict):
        declared = engines.get("packageManager")
    if isinstance(declared, dict):
        declared = [declared]
    if isinstance(declared, list):
        for entry in declared:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                if _NPM_PACKAGE_MANAGER_RE.match(entry["name"]):
                    return True
    manager = package.get("packageManager")
    return isinstance(manager, str) and bool(_NPM_PACKAGE_MANAGER_RE.match(manager))


def _is_literal(value: Any) -> bool:
    return not (isinstance(value, str) and "${{" in value)


def _literal_false(value: Any) -> bool:
    return _is_literal(value) and _actions_bool(value) is False


@dataclass(frozen=True)
class _Publish:
    registry: str
    command: str
    line_text: str
    argv: tuple[str, ...]


def _audit_publishing(audit: _Audit) -> None:
    if not audit.wants(RULE_PUBLISHING):
        return
    triggers = set(_trigger_map(audit.data))
    if not triggers:
        return
    pypi_allowed = bool(triggers - {"pull_request_target", "issue_comment", "workflow_call"})
    for job_id, job in _jobs(audit.data):
        for step in _job_steps(job_id, job):
            found = _token_publish(audit, step, pypi_allowed)
            if found is None:
                continue
            publish, evidence, line = found
            registry = "PyPI"
            if publish.registry == "npm":
                registry = "npm"
            _scopes, oidc = _permissions_scopes(_job_permissions(audit.data, job))
            note = ""
            severity = "MEDIUM"
            if oidc and publish.registry == "npm":
                severity = "LOW"
                note = (
                    " The job already grants id-token: write, so npm tries trusted "
                    "publishing first and the token is only a fallback."
                )
            elif oidc:
                note = " The job already grants id-token: write."
            if triggers == {"workflow_call"}:
                note += (
                    " npm checks the calling workflow's name, so register the caller; "
                    "both workflows need id-token: write."
                )
            audit.report(
                RULE_PUBLISHING,
                "github-actions-long-lived-publish-token",
                (
                    f"{publish.command} publishes to {registry} with a stored token "
                    f"({evidence}). {registry} offers trusted publishing to this "
                    "workflow: OIDC with id-token: write and no secret to leak or "
                    f"rotate. Register the workflow as a trusted publisher, drop the "
                    f"token from the job and revoke it.{note}"
                ),
                line,
                severity,
                f"{publish.registry}:{job_id}:{step.index}",
                yaml_only=False,
            )


def _job_permissions(data: dict[str, Any], job: dict[str, Any]) -> Any:
    if "permissions" in job:
        return job.get("permissions")
    return data.get("permissions")


def _token_publish(
    audit: _Audit, step: _Step, pypi_allowed: bool
) -> tuple[_Publish, str, int] | None:
    layers = _env_layers(audit.data, step.job, step.step)
    uses_value = step.step.get("uses")
    config = _with(step.step)
    if isinstance(uses_value, str) and _uses_matches(uses_value, "pypa/gh-action-pypi-publish"):
        if not pypi_allowed:
            return None
        password = config.get("password")
        if not isinstance(password, str) or not password.strip():
            return None
        target = config.get("repository-url", config.get("repository_url"))
        if target is not None and not _pypi_url(target):
            return None
        secret = _secret_backing(password, layers)
        if secret is None:
            return None
        publish = _Publish("pypi", "pypa/gh-action-pypi-publish", "", ())
        evidence = f"password from secrets.{secret}"
        return publish, evidence, audit.line((*step.path, "with", "password"))
    scripts: list[tuple[tuple[Any, ...], str]] = []
    if isinstance(step.step.get("run"), str):
        scripts.append(((*step.path, "run"), step.step["run"]))
    if isinstance(uses_value, str) and _uses_repo(uses_value) == "changesets/action":
        if isinstance(config.get("publish"), str):
            scripts.append(((*step.path, "with", "publish"), config["publish"]))
    for path, script in scripts:
        for publish in _publish_commands(script):
            if publish.registry == "pypi" and not pypi_allowed:
                continue
            evidence = _credential_evidence(audit, step, publish, layers)
            if evidence is None or not _default_target(audit, step, publish, layers):
                continue
            start = audit.line(path, key=False)
            line = start
            if publish.line_text:
                line = _fragment_line(audit.lines, start, publish.line_text, 0)
            return publish, evidence, line
    return None


def _logical_lines(script: str) -> list[tuple[str, str]]:
    joined: list[tuple[str, str]] = []
    head = None
    parts: list[str] = []
    for raw in script.splitlines():
        if head is None:
            head = raw
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            parts.append(stripped[:-1])
            continue
        parts.append(raw)
        joined.append((head.strip(), " ".join(parts)))
        head = None
        parts = []
    if parts and head is not None:
        joined.append((head.strip(), " ".join(parts)))
    return joined


def _command_words(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if "=" in token and re.match(r"[A-Za-z_][A-Za-z0-9_]*=", token):
            index += 1
            continue
        if token.rsplit("/", 1)[-1].lower() in _COMMAND_PREFIXES:
            index += 1
            continue
        break
    return tokens[index:]


def _publish_commands(script: str) -> Iterator[_Publish]:
    for head, text in _logical_lines(script):
        if text.strip().startswith("#"):
            continue
        masked, held = _hold_expressions(text)
        for statement in split_shell_statements(masked):
            for part in split_pipeline(statement):
                argv = [
                    _release_expressions(token, held)
                    for token in _command_words(shell_tokens(part))
                ]
                found = _publish_kind(argv)
                if found is not None:
                    registry, command = found
                    yield _Publish(registry, command, head, tuple(argv))


def _hold_expressions(text: str) -> tuple[str, list[str]]:
    """Swap each ``${{ }}`` for a placeholder word, so its spaces, quotes and
    ``||`` do not split shell words before it is expanded."""
    held: list[str] = []
    pieces = []
    cursor = 0
    for _body, start, end in expressions.template_spans(text):
        pieces.append(text[cursor:start])
        pieces.append(f"__skylos_expression_{len(held)}__")
        held.append(text[start:end])
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), held


def _release_expressions(token: str, held: list[str]) -> str:
    for index, original in enumerate(held):
        token = token.replace(f"__skylos_expression_{index}__", original)
    return token


def _publish_kind(argv: list[str]) -> tuple[str, str] | None:
    """Which registry a simple command publishes to, judged by its command
    words with option values set aside, so ``npm view publish`` and
    ``npm run publish`` are not uploads."""
    if not argv:
        return None
    lowered = [token.lower() for token in argv]
    if "--dry-run" in lowered or "--help" in lowered:
        return None
    head = lowered[0].rsplit("/", 1)[-1]
    if "-d" in lowered and any("semantic-release" in token for token in lowered):
        return None
    python = bool(_PYTHON_RE.fullmatch(head))
    if head == "twine" or python or head in _PYPI_RUNNERS:
        if _twine_upload(lowered, python=python):
            return "pypi", "twine upload"
    rest = _positional(argv[1:])
    first = next(iter(rest), None)
    if head == "uv" and first == "publish":
        return "pypi", "uv publish"
    if head in _PYPI_PUBLISHERS and first == "publish":
        return "pypi", f"{head} publish"
    if head == "maturin" and first in {"publish", "upload"}:
        return "pypi", f"maturin {first}"
    tool = _node_publisher(head, rest)
    if tool is None:
        return None
    return "npm", tool


def _positional(argv: list[str]) -> list[str]:
    words = []
    skip = False
    for token in argv:
        if skip:
            skip = False
            continue
        if token in _VALUE_OPTIONS:
            skip = True
            continue
        if token.startswith("-"):
            continue
        words.append(token.lower())
    return words


def _twine_upload(words: list[str], *, python: bool) -> bool:
    for index, word in enumerate(words):
        if not _TWINE_RE.fullmatch(word.rsplit("/", 1)[-1]):
            continue
        if python and "-m" not in words[:index]:
            return False
        return "upload" in words[index + 1 :]
    return False


def _node_publisher(head: str, rest: list[str]) -> str | None:
    if head in _NODE_RUNNERS:
        return _node_tool(rest)
    if head not in _NODE_MANAGERS:
        return _node_tool([head, *rest])
    if rest[:1] == ["publish"] or (head == "yarn" and rest[:2] == ["npm", "publish"]):
        return f"{head} publish"
    if rest[:1] and rest[0] in _SCRIPT_SUBCOMMANDS - {"run", "run-script"}:
        return _node_tool(rest[1:])
    if head != "npm":
        return _node_tool(rest)
    return None


def _node_tool(words: list[str]) -> str | None:
    if not words:
        return None
    name = words[0]
    if name == "semantic-release" or name.startswith("semantic-release@"):
        return "semantic-release"
    if name in ("changeset", "@changesets/cli") and words[1:2] == ["publish"]:
        return "changeset publish"
    if (name == "npm" or name.startswith("npm@")) and words[1:2] == ["publish"]:
        return "npm publish"
    return None


def _flag_values(argv: tuple[str, ...], flags: frozenset[str]) -> list[str]:
    values = []
    for index, token in enumerate(argv):
        name, equals, value = token.partition("=")
        if equals and name in flags:
            values.append(value)
        elif token in flags and index + 1 < len(argv):
            values.append(argv[index + 1])
    return values


def _credential_evidence(
    audit: _Audit, step: _Step, publish: _Publish, layers: list[dict[str, Any]]
) -> str | None:
    names = _NPM_TOKEN_ENV
    text_re = _NPM_TOKEN_TEXT_RE
    if publish.registry == "pypi":
        names = _PYPI_TOKEN_ENV
        text_re = _PYPI_TOKEN_TEXT_RE
        for value in _flag_values(publish.argv, _PYPI_CREDENTIAL_FLAGS):
            secret = _secret_backing(value, layers)
            if secret is not None:
                return f"a command-line credential from secrets.{secret}"
    for layer in layers:
        for key, value in layer.items():
            name = str(key).upper()
            listed = name in names
            if publish.registry == "pypi" and _PYPI_TOKEN_ENV_RE.fullmatch(name):
                listed = True
            if not listed:
                continue
            secret = _secret_backing(value, layers)
            if secret is not None:
                return f"{key} from secrets.{secret}"
    for earlier in _job_steps(step.job_id, step.job):
        if earlier.index > step.index:
            break
        run = earlier.step.get("run")
        if not isinstance(run, str) or not text_re.search(run):
            continue
        secret = _secret_backing(run, _env_layers(audit.data, step.job, earlier.step))
        if secret is not None:
            return (
                f"registry credentials written from secrets.{secret} in step "
                f"{earlier.index + 1}"
            )
    return None


def _default_target(
    audit: _Audit, step: _Step, publish: _Publish, layers: list[dict[str, Any]]
) -> bool:
    """Whether the upload goes to a registry with trusted publishing: PyPI
    and TestPyPI, or the public npm registry from a GitHub-hosted runner."""
    if publish.registry == "pypi":
        for value in _flag_values(publish.argv, _PYPI_TARGET_FLAGS):
            if not _pypi_target(value):
                return False
        for name in _PYPI_TARGET_ENV:
            value = _env_value(layers, name)
            if value is not None and not _pypi_target(value):
                return False
        return True
    if not _github_hosted(step.job):
        return False
    targets = _flag_values(publish.argv, frozenset({"--registry"}))
    configured = _env_value(layers, "NPM_CONFIG_REGISTRY")
    if configured is not None:
        targets.append(configured)
    for earlier in _job_steps(step.job_id, step.job):
        if earlier.index > step.index:
            break
        uses_value = earlier.step.get("uses")
        if isinstance(uses_value, str) and _uses_matches(uses_value, "actions/setup-node"):
            registry = _with(earlier.step).get("registry-url")
            if registry is not None:
                targets.append(registry)
    return all(_host(value) in _NPM_HOSTS for value in targets)


def _host(value: Any) -> str | None:
    if not isinstance(value, str) or "${{" in value or "$" in value:
        return None
    parsed = urlparse(value.strip())
    if not parsed.hostname:
        return None
    return parsed.hostname.lower()


def _pypi_url(value: Any) -> bool:
    return _host(value) in _PYPI_HOSTS


def _pypi_target(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value.strip().lower() in _PYPI_INDEX_NAMES:
        return True
    return _pypi_url(value)


def dependabot_files(root: Path, changed_files: set[str] | None) -> list[Path]:
    """The repository's Dependabot file: GitHub reads only
    .github/dependabot.yml (or .yaml) at the repository root."""
    if root.is_file():
        if root.name in DEPENDABOT_FILENAMES and root.parent.name == ".github":
            return [root]
        return []
    candidates = [root / ".github" / name for name in DEPENDABOT_FILENAMES]
    if changed_files is not None:
        selected = set()
        for raw in changed_files:
            candidate = Path(raw)
            if not candidate.is_absolute():
                candidate = root / candidate
            selected.add(Path(os.path.abspath(candidate)))
        candidates = [path for path in candidates if path in selected]
    return [path for path in candidates if path.is_file() or path.is_symlink()]


def scan_dependabot(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
    analysis_errors: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    ignore = ignore or set()
    if RULE_DEPENDABOT_EXECUTION in ignore and RULE_DEPENDABOT_COOLDOWN in ignore:
        return []
    findings: list[dict[str, Any]] = []
    for path in dependabot_files(root_path, changed_files):
        loaded = _load_yaml(path, root=root_path, analysis_errors=analysis_errors)
        if loaded is None:
            continue
        data, lines = loaded
        audit = _Audit(data, path, lines, findings, ignore, root_path, False)
        _audit_dependabot(audit)
    return findings


def _audit_dependabot(audit: _Audit) -> None:
    updates = audit.data.get("updates")
    if audit.data.get("version") != 2 or not isinstance(updates, list):
        return
    short: list[tuple[str, str, _Cooldown]] = []
    for index, update in enumerate(updates):
        if not isinstance(update, dict):
            continue
        ecosystem = str(update.get("package-ecosystem", "")).strip().lower()
        place = _update_place(update)
        if audit.wants(RULE_DEPENDABOT_EXECUTION):
            _check_code_execution(audit, index, update, ecosystem, place)
        if not audit.wants(RULE_DEPENDABOT_COOLDOWN) or _version_updates_off(update):
            continue
        cooldown = _effective_cooldown(update, index, ecosystem)
        if cooldown is None or cooldown.days >= COOLDOWN_MINIMUM_DAYS:
            continue
        if _is_inline_ignored(audit.lines, audit.line(cooldown.path), RULE_DEPENDABOT_COOLDOWN):
            continue
        short.append((ecosystem, place, cooldown))
    if short:
        _report_cooldowns(audit, short)


def _version_updates_off(update: dict[str, Any]) -> bool:
    """``open-pull-requests-limit: 0`` stops version updates; security
    updates, which cooldown never delays, still run."""
    limit = update.get("open-pull-requests-limit")
    return isinstance(limit, int) and not isinstance(limit, bool) and limit == 0


def _update_place(update: dict[str, Any]) -> str:
    directories = update.get("directories")
    if isinstance(directories, list) and directories:
        return ", ".join(str(item) for item in directories[:3])
    return str(update.get("directory", "/"))


def _dependabot_report(
    audit: _Audit,
    rule_id: str,
    name: str,
    message: str,
    line: int,
    severity: str,
    value: str,
) -> None:
    _add_finding(
        audit.findings,
        audit.lines,
        config_finding(
            rule_id=rule_id,
            domain="cicd",
            provider="dependabot",
            name=name,
            message=message,
            file=audit.path,
            line=line,
            severity=severity,
            value=value,
            finding_type="dependency_updates",
        ),
        yaml_only=True,
    )


def _check_code_execution(
    audit: _Audit, index: int, update: dict[str, Any], ecosystem: str, place: str
) -> None:
    setting = update.get("insecure-external-code-execution")
    if not isinstance(setting, str) or setting.strip().lower() != "allow":
        return
    if ecosystem not in _CODE_RUNNING_ECOSYSTEMS:
        return
    registries = update.get("registries")
    if not registries:
        return
    severity = "HIGH"
    reach = "with the credentials of the private registries this update uses"
    _dependabot_report(
        audit,
        RULE_DEPENDABOT_EXECUTION,
        "dependabot-insecure-external-code-execution",
        (
            f"Dependabot runs code from {ecosystem} manifests in {place} while it "
            "updates them (insecure-external-code-execution: allow). A compromised "
            f"or typosquatted dependency's setup code then runs {reach}. "
            "Remove the option, or vendor what the manifest needs to run."
        ),
        audit.line(("updates", index, "insecure-external-code-execution")),
        severity,
        f"{ecosystem}:{place}",
    )


def _days(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


@dataclass(frozen=True)
class _Cooldown:
    days: int
    path: tuple[Any, ...]
    detail: str


def _report_cooldowns(audit: _Audit, short: list[tuple[str, str, _Cooldown]]) -> None:
    """One finding per Dependabot file, as the fix is one setting per entry;
    an ignore comment on an entry's own line takes that entry out."""
    entries = [
        f"{ecosystem} in {place} after {cooldown.days} day(s) ({cooldown.detail})"
        for ecosystem, place, cooldown in short
    ]
    _dependabot_report(
        audit,
        RULE_DEPENDABOT_COOLDOWN,
        "dependabot-short-cooldown",
        (
            "Dependabot proposes version updates soon after a release for "
            f"{'; '.join(entries)}. Malicious releases are usually found and pulled "
            f"within days, so a cooldown of at least {COOLDOWN_MINIMUM_DAYS} days keeps "
            "them out of update pull requests. Set cooldown.default-days to "
            f"{COOLDOWN_MINIMUM_DAYS} or more; security updates are not delayed."
        ),
        audit.line(short[0][2].path),
        "LOW",
        "cooldown:" + ",".join(
            f"{ecosystem}:{place}:{cooldown.days}" for ecosystem, place, cooldown in short
        ),
    )


def _effective_cooldown(update: dict[str, Any], index: int, ecosystem: str) -> _Cooldown | None:
    """The shortest wait any version update of this entry gets. SemVer bumps
    use their own days where the ecosystem supports them and default-days
    otherwise; without default-days Dependabot waits 3 days. For an
    ecosystem not in GitHub's table the longer reading is taken."""
    place = ("updates", index)
    cooldown = update.get("cooldown")
    if cooldown is None:
        return _Cooldown(
            DEPENDABOT_DEFAULT_COOLDOWN_DAYS,
            place,
            f"no cooldown is set, so Dependabot's {DEPENDABOT_DEFAULT_COOLDOWN_DAYS}-day "
            "default applies",
        )
    if not isinstance(cooldown, dict):
        return None
    excluded = cooldown.get("exclude")
    if isinstance(excluded, list) and "*" in excluded:
        return _Cooldown(
            0,
            (*place, "cooldown", "exclude"),
            "exclude: ['*'] takes every dependency out of the cooldown",
        )
    included = cooldown.get("include")
    if isinstance(included, list) and included and "*" not in included:
        return _Cooldown(
            DEPENDABOT_DEFAULT_COOLDOWN_DAYS,
            (*place, "cooldown", "include"),
            "include limits the cooldown to "
            + ", ".join(str(item) for item in included[:3])
            + "; other dependencies fall back to the "
            + f"{DEPENDABOT_DEFAULT_COOLDOWN_DAYS}-day default",
        )
    base = _Cooldown(
        DEPENDABOT_DEFAULT_COOLDOWN_DAYS,
        (*place, "cooldown"),
        f"cooldown sets no default-days, so the {DEPENDABOT_DEFAULT_COOLDOWN_DAYS}-day "
        "default applies",
    )
    if "default-days" in cooldown:
        days = _days(cooldown.get("default-days"))
        if days is None:
            return None
        base = _Cooldown(days, (*place, "cooldown", "default-days"), f"default-days: {days}")
    if ecosystem in _DAYS_ONLY_COOLDOWN_ECOSYSTEMS:
        return base
    keyed = []
    for key in _SEMVER_DAY_KEYS:
        if key not in cooldown:
            continue
        days = _days(cooldown.get(key))
        if days is None:
            return None
        keyed.append(_Cooldown(days, (*place, "cooldown", key), f"{key}: {days}"))
    bumps = list(keyed)
    if len(keyed) < len(_SEMVER_DAY_KEYS):
        bumps.insert(0, base)
    shortest = min(bumps, key=lambda candidate: candidate.days)
    if ecosystem in _SEMVER_COOLDOWN_ECOSYSTEMS:
        return shortest
    if len(keyed) == len(_SEMVER_DAY_KEYS) and shortest.days > base.days:
        return shortest
    return base
