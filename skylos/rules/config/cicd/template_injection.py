"""Template injection in GitHub Actions code sinks.

A ``${{ }}`` expression in a ``run:`` block or a code input is pasted into the
script before it runs. Each value that reaches the script is traced to its
origin: an event payload field, an input, an ``env`` or ``matrix`` value, a
step or job output. What a payload field can hold comes from
data/context_capabilities.json, generated from GitHub's webhook payload
schemas as Octokit publishes them (MIT, see data/NOTICE.txt); who can set it
comes from which accounts can make the job run."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from skylos.rules.config.cicd import actions_expressions as expressions

_DATA = Path(__file__).with_name("data")
_TRACE_LIMIT = 6
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

_OUTSIDER = "outsider"
_UNKNOWN = "unknown"
_WRITERS = "writers"

_RUN_CONTEXT_FIELDS = {
    "head_ref": ("arbitrary", True),
    "ref": ("structured", False),
    "ref_name": ("structured", False),
    "base_ref": ("structured", False),
    "workflow": ("arbitrary", False),
    "workflow_ref": ("structured", False),
    "action_ref": ("structured", False),
}
_FORMATTED_RUN_FIELDS = frozenset(
    {
        "action",
        "action_repository",
        "action_status",
        "actor",
        "actor_id",
        "api_url",
        "env",
        "event_path",
        "graphql_url",
        "output",
        "path",
        "ref_protected",
        "ref_type",
        "retention_days",
        "secret_source",
        "step_summary",
        "workflow_sha",
    }
)
_MAINTAINER_PAYLOAD = frozenset({"repository", "organization", "enterprise", "installation"})
_PAYLOAD_CARRIERS = {
    "inputs": {"workflow_dispatch"},
    "issue": {"issues", "issue_comment"},
    "comment": {
        "issue_comment",
        "pull_request_review_comment",
        "commit_comment",
        "discussion_comment",
    },
    "pull_request": {
        "pull_request",
        "pull_request_target",
        "pull_request_review",
        "pull_request_review_comment",
    },
    "review": {"pull_request_review"},
    "discussion": {"discussion", "discussion_comment"},
    "answer": {"discussion"},
    "workflow_run": {"workflow_run"},
    "head_commit": {"push"},
    "commits": {"push"},
    "pusher": {"push"},
    "compare": {"push"},
    "release": {"release"},
    "client_payload": {"repository_dispatch"},
    "forkee": {"fork"},
    "pages": {"gollum"},
}
_SETTLED_RESULTS = ("needs.*.result", "steps.*.outcome", "steps.*.conclusion")
_RUNNER_DEFAULT_ENV = re.compile(r"(?:CI|GITHUB_[A-Z_]+|RUNNER_[A-Z_]+)\Z")
_LOOSE_EXPRESSION = re.compile(r"github\s*\.\s*(?:event\b|head_ref\b)|\binputs\s*\.", re.I)
_WRITES_ENV_FILE = re.compile(
    r"(?i)(?:\$GITHUB_ENV|\$\{GITHUB_ENV\}|%GITHUB_ENV%|\$env:GITHUB_ENV)"
)
_WRITES_OUTPUT_FILE = re.compile(
    r"(?i)(?:\$GITHUB_OUTPUT|\$\{GITHUB_OUTPUT\}|%GITHUB_OUTPUT%|\$env:GITHUB_OUTPUT)"
)
_SHELL_VARIABLE = re.compile(
    r"\$\{?([A-Za-z_][A-Za-z0-9_]*)|\$env:([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%"
)


@lru_cache(maxsize=1)
def _context_catalog() -> dict[str, str]:
    groups = json.loads((_DATA / "context_capabilities.json").read_text(encoding="utf-8"))
    catalog = {}
    for capability, keys in groups.items():
        for key in keys:
            catalog[key] = capability
    return catalog


@lru_cache(maxsize=1)
def _code_inputs() -> dict[str, tuple[str, ...]]:
    raw = json.loads((_DATA / "code_inputs.json").read_text(encoding="utf-8"))
    return {action: tuple(inputs) for action, inputs in raw.items()}


def action_sink_inputs(uses: str) -> tuple[str, ...]:
    return _code_inputs().get(uses.strip().split("@", 1)[0].lower(), ())


@dataclass(frozen=True)
class Source:
    context: str
    severity: str
    reason: str


@dataclass(frozen=True)
class Injection:
    raw: str
    start: int
    end: int
    severity: str
    sources: tuple[Source, ...]


def _grade(shape: str, audience: str, *, caller: bool = False) -> str:
    if audience == _OUTSIDER and not caller:
        if shape == "arbitrary":
            return "HIGH"
        return "MEDIUM"
    if audience == _UNKNOWN or caller:
        if shape == "arbitrary":
            return "MEDIUM"
        return "LOW"
    return "LOW"


def _why(audience: str) -> str:
    if audience == _OUTSIDER:
        return "an account without write access can trigger this job"
    if audience == _UNKNOWN:
        return "who triggers this code is not known here"
    return "only accounts with write access, or a fork's own sandboxed run, set it here"


@dataclass
class Scope:
    data: dict[str, Any]
    path: Path
    root: Path | None
    is_workflow: bool
    job_id: Any = None
    job: dict[str, Any] | None = None
    step: dict[str, Any] | None = None
    audience: str = _WRITERS
    callers: list[tuple[Path, dict[str, Any], Any, dict[str, Any]]] | None = None
    audiences: dict[Any, tuple[str, frozenset[str]]] = field(default_factory=dict)
    events: frozenset[str] = frozenset()

    def injections(self, text: str) -> list[Injection]:
        found = []
        for body, start, end in expressions.template_spans(text):
            sources = _trace_expression(self, body, 0)
            if not sources:
                continue
            worst = max(sources, key=lambda source: _RANK[source.severity])
            found.append(
                Injection(
                    text[start:end], start, end, worst.severity, tuple(dict.fromkeys(sources))
                )
            )
        return found

    def env_layers(self) -> list[Any]:
        if self.is_workflow:
            return [self.step, self.job, self.data]
        return [self.step]

    def steps(self) -> list[Any]:
        steps = None
        if self.is_workflow and isinstance(self.job, dict):
            steps = self.job.get("steps")
        elif not self.is_workflow and isinstance(self.data.get("runs"), dict):
            steps = self.data["runs"].get("steps")
        if isinstance(steps, list):
            return steps
        return []


def _trace_text(scope: Scope, text: Any, depth: int) -> list[Source]:
    if not isinstance(text, str) or depth > _TRACE_LIMIT:
        return []
    sources = []
    for body, _start, _end in expressions.template_spans(text):
        sources.extend(_trace_expression(scope, body, depth))
    return sources


def _trace_expression(scope: Scope, body: str, depth: int) -> list[Source]:
    try:
        sources = []
        for reference in expressions.flowing_references(expressions.parse_expression(body)):
            sources.extend(_trace_reference(scope, reference, depth))
        return sources
    except (expressions.ExpressionError, RecursionError):
        if _LOOSE_EXPRESSION.search(body):
            return [Source(body.strip(), "MEDIUM", "expression could not be parsed")]
        return []


def _trace_reference(
    scope: Scope, reference: expressions.Reference, depth: int
) -> list[Source]:
    if not isinstance(reference.base, expressions.Field):
        sources = []
        for inner in expressions.invoke_inputs(reference):
            sources.extend(_trace_reference(scope, inner, depth))
        return sources
    if any(reference.is_exactly(settled) for settled in _SETTLED_RESULTS):
        return []
    handler = _ROOTS.get(reference.base.name.lower())
    if handler is None:
        return []
    return handler(scope, reference, depth)


def _via(sources: list[Source], label: str) -> list[Source]:
    return [
        Source(f"{label} = {source.context}", source.severity, source.reason)
        for source in sources
    ]


def _named(mapping: Any, name: str) -> tuple[bool, Any]:
    if not isinstance(mapping, dict):
        return False, None
    for key, value in mapping.items():
        if str(key).lower() == name.lower():
            return True, value
    return False, None


def _github_root(scope: Scope, reference: expressions.Reference, depth: int) -> list[Source]:
    names = reference.names()
    second = None
    if len(names) > 1:
        second = names[1]
    if second == "event":
        return _payload_field(scope, reference)
    if second in _FORMATTED_RUN_FIELDS:
        return []
    capability = _context_catalog().get(reference.key() or "")
    if capability == "fixed":
        return []
    shape, outsider_set = _RUN_CONTEXT_FIELDS.get(second, (capability or "arbitrary", True))
    if not outsider_set:
        return []
    return [Source(reference.span.text, _grade(shape, scope.audience), _why(scope.audience))]


def _payload_field(scope: Scope, reference: expressions.Reference) -> list[Source]:
    names = reference.names()
    section = None
    if len(names) > 2:
        section = names[2]
    if section in _MAINTAINER_PAYLOAD:
        return []
    capability = _context_catalog().get(reference.key() or "", "arbitrary")
    if capability == "fixed":
        return []
    audience = scope.audience
    carriers = _PAYLOAD_CARRIERS.get(section)
    if audience == _OUTSIDER and carriers is not None and not scope.events & carriers:
        audience = _WRITERS
    return [Source(reference.span.text, _grade(capability, audience), _why(audience))]


def _runner_root(scope: Scope, reference: expressions.Reference, depth: int) -> list[Source]:
    return []


def _env_root(scope: Scope, reference: expressions.Reference, depth: int) -> list[Source]:
    name = reference.only_member()
    if name is None:
        return [Source(reference.span.text, "LOW", "an env value read by a computed name")]
    computed: list[Source] = []
    for owner in scope.env_layers():
        if not isinstance(owner, dict) or "env" not in owner:
            continue
        env = owner["env"]
        if isinstance(env, str):
            computed.extend(_trace_text(scope, env, depth + 1))
            continue
        present, value = _named(env, name)
        if present:
            return _via(computed + _trace_text(scope, value, depth + 1), reference.span.text)
    if computed:
        return _via(computed, reference.span.text)
    if not scope.is_workflow or _RUNNER_DEFAULT_ENV.match(name.upper()):
        return []
    for step in scope.steps():
        run = None
        if isinstance(step, dict):
            run = step.get("run")
        if isinstance(run, str) and _WRITES_ENV_FILE.search(run):
            return [
                Source(
                    reference.span.text,
                    "LOW",
                    "set by a step that writes $GITHUB_ENV, which is not traced",
                )
            ]
    return []


def _env_value(scope: Scope, name: str, depth: int) -> list[Source]:
    for owner in scope.env_layers():
        if not isinstance(owner, dict):
            continue
        env = owner.get("env")
        if isinstance(env, str):
            return _trace_text(scope, env, depth)
        present, value = _named(env, name)
        if present:
            return _trace_text(scope, value, depth)
    return []


def _matrix_root(scope: Scope, reference: expressions.Reference, depth: int) -> list[Source]:
    strategy = (scope.job or {}).get("strategy")
    if not isinstance(strategy, dict) or "matrix" not in strategy:
        return []
    matrix = strategy["matrix"]
    if isinstance(matrix, str):
        return _via(_trace_text(scope, matrix, depth + 1), reference.span.text)
    if not isinstance(matrix, dict):
        return []
    sources = []
    for path, value in _matrix_values(matrix):
        wildcard = path.endswith(".*") and reference.under(path[:-2])
        if reference.is_exactly(path) or wildcard:
            sources.extend(_trace_text(scope, value, depth + 1))
    return _via(sources, reference.span.text)


def _matrix_values(matrix: dict[str, Any]) -> list[tuple[str, Any]]:
    values = []
    for key, value in matrix.items():
        if key == "exclude":
            continue
        if key != "include":
            if isinstance(value, str):
                values.append((f"matrix.{key}", value))
            else:
                values.extend(_flatten(value, f"matrix.{key}"))
        elif isinstance(value, list):
            for row in value:
                values.extend(_flatten(row, "matrix"))
        else:
            values.append(("matrix.*", value))
    return values


def _flatten(value: Any, path: str) -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        return [
            item for key, nested in value.items() for item in _flatten(nested, f"{path}.{key}")
        ]
    if isinstance(value, list):
        return [item for nested in value for item in _flatten(nested, path)]
    return [(path, value)]


def _inputs_root(scope: Scope, reference: expressions.Reference, depth: int) -> list[Source]:
    name = reference.only_member()
    if name is None:
        return []
    if not scope.is_workflow:
        declared, _spec = _named(scope.data.get("inputs"), name)
        if not declared:
            return []
        return [
            Source(
                reference.span.text,
                _grade("arbitrary", _UNKNOWN, caller=True),
                "an input of this composite action: its callers are not known here",
            )
        ]
    triggers = workflow_triggers(scope.data)
    sources = []
    if _declared_type(triggers.get("workflow_dispatch"), name) in ("string", ""):
        sources.append(
            Source(
                reference.span.text,
                "LOW",
                "a workflow_dispatch input: only accounts with write access set it",
            )
        )
    if _declared_type(triggers.get("workflow_call"), name) in ("string", ""):
        sources.extend(_passed_by_callers(scope, reference, name, depth))
    return sources


def _declared_type(trigger: Any, name: str) -> str | None:
    if not isinstance(trigger, dict):
        return None
    declared, spec = _named(trigger.get("inputs"), name)
    if not declared:
        return None
    if isinstance(spec, dict) and isinstance(spec.get("type"), str):
        return spec["type"].strip().lower()
    return ""


def workflow_triggers(data: dict[str, Any]) -> dict[str, Any]:
    trigger = data.get("on", data.get(True))
    if isinstance(trigger, str):
        return {trigger: None}
    if isinstance(trigger, list):
        return {item: None for item in trigger if isinstance(item, str)}
    if isinstance(trigger, dict):
        return {str(key): value for key, value in trigger.items()}
    return {}


def _passed_by_callers(
    scope: Scope, reference: expressions.Reference, name: str, depth: int
) -> list[Source]:
    if scope.callers is None:
        from skylos.rules.config.cicd.ai_agents import local_workflow_callers

        scope.callers = local_workflow_callers(scope.data, scope.path, scope.root)
    if not scope.callers:
        return [
            Source(
                reference.span.text,
                _grade("arbitrary", _UNKNOWN, caller=True),
                "a reusable-workflow input with no caller in this repository",
            )
        ]
    sources = []
    for caller_path, caller_data, caller_job_id, caller_job in scope.callers:
        passed, value = _named(caller_job.get("with"), name)
        if not passed:
            continue
        caller_audiences = job_audiences(caller_data, caller_path, scope.root)
        audience, events = caller_audiences.get(caller_job_id, (_WRITERS, frozenset()))
        caller_scope = Scope(
            caller_data,
            caller_path,
            scope.root,
            True,
            caller_job_id,
            caller_job,
            audience=audience,
            audiences=caller_audiences,
            events=events,
        )
        label = f"{reference.span.text} in {caller_path.name}"
        sources.extend(_via(_trace_text(caller_scope, value, depth + 1), label))
    return sources


def _output_reference(reference: expressions.Reference) -> tuple[str, str] | None:
    names = reference.names()
    if len(names) != 4 or names[2] != "outputs" or names[1] is None or names[3] is None:
        return None
    return names[1], names[3]


def _steps_root(scope: Scope, reference: expressions.Reference, depth: int) -> list[Source]:
    output = _output_reference(reference)
    if output is None:
        return []
    step_id, name = output
    producer = None
    for step in scope.steps():
        if isinstance(step, dict) and str(step.get("id", "")).lower() == step_id:
            producer = step
    if producer is None or not isinstance(producer.get("run"), str):
        return []
    producer_scope = replace(scope, step=producer)
    sources = []
    for line in _output_writes(producer["run"], name):
        sources.extend(_trace_text(producer_scope, line, depth + 1))
        for match in _SHELL_VARIABLE.finditer(line):
            variable = next(group for group in match.groups() if group)
            sources.extend(_env_value(producer_scope, variable, depth + 1))
    return _via(sources, reference.span.text)


def _output_writes(script: str, name: str) -> list[str]:
    assignment = re.compile(
        rf"(?<![\w-]){re.escape(name)}\s*(?:=|<<\s*['\"]?([A-Za-z_][\w-]*))"
        rf"|name={re.escape(name)}::",
        re.I,
    )
    written = []
    heredoc_end = None
    for line in re.sub(r"\\\n", " ", script).splitlines():
        if heredoc_end is not None:
            if _closes_heredoc(line, heredoc_end):
                heredoc_end = None
            else:
                written.append(line)
            continue
        match = assignment.search(line)
        if match is None:
            continue
        if not (_WRITES_OUTPUT_FILE.search(line) or "::set-output" in line):
            continue
        written.append(line)
        heredoc_end = match.group(1)
    return written


def _closes_heredoc(line: str, delimiter: str) -> bool:
    content = line.split(">>", 1)[0].strip()
    content = re.sub(r"^(?:echo|printf)\s+", "", content).strip().strip("'\"")
    return content == delimiter


def _needs_root(scope: Scope, reference: expressions.Reference, depth: int) -> list[Source]:
    output = _output_reference(reference)
    jobs = scope.data.get("jobs")
    if output is None or not scope.is_workflow or not isinstance(jobs, dict):
        return []
    job_name, name = output
    producer_id = None
    for key in jobs:
        if str(key).lower() == job_name:
            producer_id = key
    producer = jobs.get(producer_id)
    if not isinstance(producer, dict):
        return []
    present, value = _named(producer.get("outputs"), name)
    if not present:
        return []
    audience, events = scope.audiences.get(producer_id, (scope.audience, scope.events))
    producer_scope = replace(
        scope, job_id=producer_id, job=producer, step=None, audience=audience, events=events
    )
    return _via(_trace_text(producer_scope, value, depth + 1), reference.span.text)


_ROOTS: dict[str, Callable[[Scope, expressions.Reference, int], list[Source]]] = {
    "github": _github_root,
    "runner": _runner_root,
    "env": _env_root,
    "matrix": _matrix_root,
    "inputs": _inputs_root,
    "steps": _steps_root,
    "needs": _needs_root,
}


def job_audiences(
    data: dict[str, Any],
    path: Path,
    root: Path | None,
    seen: frozenset[Path] = frozenset(),
) -> dict[Any, tuple[str, frozenset[str]]]:
    from skylos.rules.config.cicd.ai_agents import (
        local_workflow_callers,
        outsider_job_events,
    )

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return {}
    called = (_WRITERS, frozenset())
    if "workflow_call" in workflow_triggers(data):
        called = (_UNKNOWN, frozenset())
        callers = []
        if path not in seen:
            callers = local_workflow_callers(data, path, root)
        if callers:
            called = (_WRITERS, frozenset())
        reached: set[str] = set()
        for caller_path, caller_data, caller_job_id, _caller_job in callers:
            audience, events = job_audiences(
                caller_data, caller_path, root, seen | {path}
            ).get(caller_job_id, (_WRITERS, frozenset()))
            if audience == _OUTSIDER:
                reached |= events
        if reached:
            called = (_OUTSIDER, frozenset(reached))
    outsiders = outsider_job_events(data, path, root)
    audiences = {}
    for job_id in jobs:
        events = outsiders.get(job_id) or outsiders.get(str(job_id))
        if events:
            audiences[job_id] = (_OUTSIDER, frozenset(events))
        else:
            audiences[job_id] = called
    return audiences


def interpolates_untrusted(
    data: dict[str, Any], job: dict[str, Any], step: dict[str, Any], text: str
) -> bool:
    every_event = frozenset().union(*_PAYLOAD_CARRIERS.values())
    scope = Scope(data, Path(), None, True, None, job, step, _OUTSIDER, [], events=every_event)
    return bool(scope.injections(text))
