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

A full-repository scan (``skylos .``) keeps reporting them under ``quality``.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path
from typing import Any, Iterable

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
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def resolve_merge_base(base_ref: str, git_root: Path) -> str | None:
    out = _git(["merge-base", base_ref, "HEAD"], git_root)
    return out.strip() if out and out.strip() else None


def _base_python_metrics(
    git_root: Path, base_commit: str, file_path: Path
) -> list[dict] | None:
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
    try:
        findings = scan_python_quality(tree, source, file_path, cfg)
    except Exception:
        return None
    return [f for f in findings if is_code_health_finding(f)]


def _classify(
    head: dict, base_findings: list[dict] | None
) -> str:
    if base_findings is None:
        return "unverified"
    key = _finding_key(head)
    matches = [f for f in base_findings if _finding_key(f) == key]
    if not matches:
        return "introduced"
    head_value = _numeric(head.get("value"))
    base_values = [v for v in (_numeric(f.get("value")) for f in matches) if v is not None]
    if head_value is not None and base_values and head_value > max(base_values):
        return "worsened"
    return "preexisting"


def partition_code_health(
    result: dict,
    *,
    git_root: Path | None,
    base_commit: str | None,
    buckets: Iterable[str] = _METRIC_BUCKETS,
) -> dict:
    """Move metric findings out of the finding buckets (see module docstring).

    Mutates and returns ``result``.
    """
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
                    git_root, base_commit, path
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
    return result
