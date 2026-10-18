"""Code-health metrics in diff/PR contexts.

Size, complexity and style metrics (function length, cyclomatic/cognitive
complexity, nesting, argument/return counts, try-block size, cohesion,
architecture distance, repeated literals, boolean traps, missing annotations)
describe how code is shaped, not a defect the change introduced. On real agent
commits they were most of Skylos' review noise (agent-pr-bench: 79 of 163
false positives).

In a diff-scoped scan (``--diff``, ``--diff-base``, ``skylos cicd review``)
these findings are therefore moved out of ``quality`` into a separate
``code_health`` section that is never counted as a finding and never trips
``--gate``/``--fail-on``:

* a metric the change **introduced or made worse** (compared with the same
  file at the merge base) is listed in ``code_health`` with
  ``code_health_change`` set to ``"introduced"`` or ``"worsened"``;
* a metric that was already over its threshold at the base and did not get
  worse is dropped from the report (counted in
  ``analysis_summary.code_health_preexisting_count``);
* when the base version cannot be analyzed (non-Python file, file added by
  the change, git failure) the finding is listed as ``"unverified"``.

A full-repository scan (``skylos .``) reports these rules under ``quality``,
except default advisory Q802/Q803, which are grouped under
``architecture_metrics.advisories``.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path
from typing import Any, Iterable

from skylos.core.git_safety import (
    read_only_git_environment,
    worktree_safe_git_command,
)

CODE_HEALTH_RULES = frozenset(
    {
        "SKY-C303",  # too many arguments
        "SKY-C304",  # function too long
        "SKY-Q301",  # cyclomatic complexity
        "SKY-Q302",  # nesting depth
        "SKY-Q306",  # cognitive complexity
        "SKY-L004",  # try block too large
        "SKY-L027",  # repeated string literal
        "SKY-L028",  # too many returns
        "SKY-L029",  # boolean trap parameter
        "SKY-Q702",  # low class cohesion
        "SKY-Q802",  # distance from main sequence
        "SKY-Q803",  # architecture zone
        "SKY-T101",  # missing parameter annotations
        "SKY-T102",  # missing return annotation
    }
)

_METRIC_BUCKETS = ("quality",)
_PYTHON_SUFFIXES = (".py", ".pyw")


def is_code_health_finding(finding: Any) -> bool:
    return (
        isinstance(finding, dict)
        and str(finding.get("rule_id", "")).upper() in CODE_HEALTH_RULES
    )


def _finding_key(finding: dict) -> tuple[str, str]:
    name = finding.get("name") or finding.get("simple_name") or finding.get("symbol")
    return str(finding.get("rule_id", "")).upper(), str(name or "")


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _git(args: list[str], cwd: Path) -> str | None:
    command = worktree_safe_git_command(args, cwd)
    if command is None:
        return None
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
            env=read_only_git_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def resolve_merge_base(base_ref: str, git_root: Path) -> str | None:
    out = _git(["merge-base", base_ref, "HEAD"], git_root)
    return out.strip() if out and out.strip() else None


def _revision_path(prefix: str, relative) -> str:
    """Project-relative path to a git tree path, never leaving the project."""
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise OSError("snapshot path leaves project")
    name = relative.as_posix()
    if name in {"", "."}:
        raise OSError("snapshot path names the project itself")
    return f"{prefix}/{name}" if prefix else name


class _BaseTypingSources:
    """Read only regular policy blobs from the same revision as the source.

    Paths are relative to the scan's project root, which may sit below the
    Git root (a monorepo service); ``prefix`` is that root inside the tree.
    ``root``/``revision`` identify the snapshot for policy caching.
    """

    def __init__(self, git_root, revision, project_root=None):
        self.git_root = Path(git_root)
        self.root = Path(project_root) if project_root is not None else self.git_root
        self.revision = revision
        self.prefix = _project_prefix(self.git_root, self.root)
        if self.prefix is None:
            raise ValueError("project root is outside the Git root")

    def __call__(self, relative):
        name = _revision_path(self.prefix, relative)
        entry = _git(["ls-tree", "-z", self.revision, "--", name], self.git_root)
        if entry is None:
            raise OSError("typing policy snapshot unavailable")
        if not entry:
            raise FileNotFoundError(name)
        records = entry.rstrip("\0").split("\0")
        if len(records) != 1:
            raise OSError("ambiguous typing policy snapshot")
        metadata, separator, path = records[0].partition("\t")
        fields = metadata.split()
        if (
            not separator or path != name or len(fields) != 3
            or fields[0] not in {"100644", "100755"} or fields[1] != "blob"
        ):
            raise OSError("typing policy is not a regular file")
        text = _git(["show", fields[2]], self.git_root)
        if text is None:
            raise OSError("typing policy snapshot unavailable")
        return text

    def workflow_paths(self):
        folder = _revision_path(self.prefix, ".github/workflows")
        entries = _git(
            ["ls-tree", "-rz", "--name-only", self.revision, "--", folder + "/"],
            self.git_root,
        )
        if entries is None:
            raise OSError("typing command snapshot unavailable")
        paths = [name for name in entries.split("\0") if name]
        if len(paths) > 128:
            raise OSError("typing command discovery limit")
        start = len(self.prefix) + 1 if self.prefix else 0
        return [
            name[start:] for name in paths if Path(name).suffix in {".yml", ".yaml"}
        ]


def _project_prefix(git_root: Path, project_root: Path) -> str | None:
    try:
        relative = Path(project_root).resolve().relative_to(Path(git_root).resolve())
    except (OSError, RuntimeError, ValueError):
        return None
    return "" if not relative.parts else relative.as_posix()


def _analysis_project_root(result: dict, git_root: Path) -> Path:
    """The project root the head scan used (nearest pyproject/setup root).

    The analyzer records it as ``comparison_scope.repository_root``. Rules
    resolve policy and imports relative to it, so the base scan must use the
    same root inside the base revision; otherwise fall back to the Git root.
    """
    summary = result.get("analysis_summary")
    scope = summary.get("comparison_scope") if isinstance(summary, dict) else None
    raw = scope.get("repository_root") if isinstance(scope, dict) else None
    if isinstance(raw, str) and raw:
        candidate = Path(raw)
        if candidate.is_absolute() and _project_prefix(git_root, candidate) is not None:
            return candidate
    return git_root


def _base_python_metrics(
    git_root: Path,
    base_commit: str,
    file_path: Path,
    project_root: Path | None = None,
) -> list[dict] | None:
    project_root = git_root if project_root is None else project_root
    prefix = _project_prefix(git_root, project_root)
    if prefix is None:
        return None
    try:
        rel = file_path.resolve().relative_to(git_root.resolve()).as_posix()
    except ValueError:
        return None
    source = _git(["show", f"{base_commit}:{rel}"], git_root)
    if source is None:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    from skylos.analysis.file_processing import scan_python_quality
    from skylos.config import load_config

    try:
        cfg = load_config(file_path)
    except Exception:
        cfg = {"ignore": []}
    cfg = dict(cfg)
    cfg.setdefault("ignore", [])

    def receiver_source(relative):
        # Absent or unavailable blobs are both None, as the rules expect.
        return _git(["show", f"{base_commit}:{_revision_path(prefix, relative)}"], git_root)

    try:
        # Same project root as the head scan, read from the base revision.
        findings = scan_python_quality(
            tree,
            source,
            file_path,
            cfg,
            project_root=project_root,
            receiver_source_reader=receiver_source,
            typing_source_reader=_BaseTypingSources(git_root, base_commit, project_root),
        )
    except Exception:
        return None
    return [f for f in findings if is_code_health_finding(f)]


def _classify(head: dict, base_findings: list[dict] | None) -> str:
    if base_findings is None:
        return "unverified"
    key = _finding_key(head)
    matches = [f for f in base_findings if _finding_key(f) == key]
    if not matches:
        return "introduced"
    head_value = _numeric(head.get("value"))
    base_values = [
        v for v in (_numeric(f.get("value")) for f in matches) if v is not None
    ]
    if head_value is not None and base_values and head_value > max(base_values):
        return "worsened"
    return "preexisting"


def partition_code_health(
    result: dict,
    *,
    git_root: Path | None,
    base_commit: str | None,
    buckets: Iterable[str] = _METRIC_BUCKETS,
    project_root: Path | None = None,
) -> dict:
    """Move metric findings out of the finding buckets (see module docstring).

    ``project_root`` is the head scan's project root; by default it is read
    from the report's ``comparison_scope``. Mutates and returns ``result``.
    """
    if git_root is not None and project_root is None:
        project_root = _analysis_project_root(result, git_root)
    moved: list[dict] = []
    for bucket in buckets:
        items = result.get(bucket)
        if not isinstance(items, list) or not items:
            continue
        kept = []
        for item in items:
            (moved if is_code_health_finding(item) else kept).append(item)
        result[bucket] = kept

    base_cache: dict[str, list[dict] | None] = {}
    listed: list[dict] = []
    preexisting = 0
    for finding in moved:
        file_value = finding.get("file")
        base_findings = None
        if (
            git_root is not None
            and base_commit
            and isinstance(file_value, str)
            and file_value.endswith(_PYTHON_SUFFIXES)
        ):
            if file_value not in base_cache:
                path = Path(file_value)
                if not path.is_absolute():
                    path = git_root / path
                base_cache[file_value] = _base_python_metrics(
                    git_root, base_commit, path, project_root
                )
            base_findings = base_cache[file_value]
        change = _classify(finding, base_findings)
        if change == "preexisting":
            preexisting += 1
            continue
        finding = dict(finding)
        finding["code_health_change"] = change
        listed.append(finding)

    existing = result.get("code_health")
    if isinstance(existing, list):
        listed = existing + listed
    result["code_health"] = listed
    summary = result.setdefault("analysis_summary", {})
    if isinstance(summary, dict):
        summary["code_health_count"] = len(listed)
        summary["code_health_preexisting_count"] = preexisting
        for bucket in buckets:
            count_key = f"{bucket}_count"
            if count_key in summary and isinstance(result.get(bucket), list):
                summary[count_key] = len(result[bucket])

    # I/A/D advisories are full-project context. They cannot be compared to a
    # changed file in isolation because the dependency graph determines their
    # values, so do not copy all of them into a diff-scoped report.
    architecture = result.get("architecture_metrics")
    if isinstance(architecture, dict) and isinstance(
        architecture.get("advisories"), list
    ):
        architecture = dict(architecture)
        architecture["advisories"] = []
        architecture["advisory_count"] = 0
        architecture["advisory_signal_count"] = 0
        result["architecture_metrics"] = architecture
        if isinstance(summary, dict):
            summary["architecture_advisory_count"] = 0
    return result
