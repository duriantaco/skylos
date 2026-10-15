"""Skylos risk review: which risk classes in a change need a human approval.

``skylos cicd risk-review --base origin/main`` compares a pull request with
its merge base and reports every risk class it finds: tests deleted or
weakened, an auth control removed, a dependency added or changed, CI
weakened, a linter or scanner silenced, a secret added, guardrail settings
edited, a database migration changed, or a very large diff. A change with
none of them is "eligible": an approval from anyone, a review bot included,
is enough. A change with any of them needs a human approval of its head
commit (see ``approval_github``).

The facts come from the checks ``skylos done`` already runs (without running
the tests), the CI permission rule SKY-A103, the AI-agent workflow rules
SKY-D350 to SKY-D354, and three comparisons that live here: dependency
manifests and lockfiles, migration paths and diff size.
Settings come from ``[tool.skylos.approval]`` at the base, never from the
change under review. An analysis that cannot finish is never eligible.
"""

from __future__ import annotations

import itertools
import logging
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from skylos.core.git_safety import read_only_git_command
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.done.base import Comparison, DoneError, _git_bytes, open_comparison

logger = logging.getLogger(__name__)

SCHEMA = "skylos.approval/v1"
CHECK_NAME = "Skylos risk review"

# Shared with Skylos Cloud: renaming a class breaks workspace policies.
VETO_CLASSES = (
    "tests_weakened",
    "auth_removed",
    "dependency_changed",
    "ci_weakened",
    "checks_silenced",
    "secret_added",
    "guardrail_config_changed",
    "migration_changed",
    "large_diff",
)
CLASS_TITLES = {
    "tests_weakened": "tests deleted, skipped or weakened",
    "auth_removed": "an auth, CSRF or rate-limit control removed",
    "dependency_changed": "a dependency added or changed",
    "ci_weakened": "CI weakened or its permissions widened",
    "checks_silenced": "a linter, type checker or scanner silenced",
    "secret_added": "a secret added",
    "guardrail_config_changed": "Skylos, agent or AI-reviewer settings changed",
    "migration_changed": "a database migration added or changed",
    "large_diff": "a very large change",
}
# Rule id -> class. Findings a check marks as blocking become risks; its
# advice is listed separately and needs no approval. Rules from releases
# that are not merged yet (A122-A125) apply as soon as a check emits them.
RULE_CLASSES = {
    **dict.fromkeys(
        (
            "SKY-A101",
            "SKY-A110",
            "SKY-A111",
            "SKY-A112",
            "SKY-A113",
            "SKY-A115",
            "SKY-A116",
            "SKY-A117",
        ),
        "tests_weakened",
    ),
    "SKY-L021": "auth_removed",
    **dict.fromkeys(
        ("SKY-D222", "SKY-D223", "SKY-D225", "SKY-A106"), "dependency_changed"
    ),
    **dict.fromkeys(
        (
            "SKY-A103",
            "SKY-A121",
            "SKY-A124",
            "SKY-D350",
            "SKY-D351",
            "SKY-D352",
            "SKY-D353",
            "SKY-D354",
        ),
        "ci_weakened",
    ),
    **dict.fromkeys(("SKY-A118", "SKY-A119", "SKY-A125"), "checks_silenced"),
    **dict.fromkeys(("SKY-S101", "SKY-S102"), "secret_added"),
    **dict.fromkeys(("SKY-A114", "SKY-A122", "SKY-A123"), "guardrail_config_changed"),
}
ANALYSIS_INCOMPLETE_RULE = "SKY-ANALYSIS-INCOMPLETE"
# Rules whose every finding needs approval, even where `done` only advises:
# a linter, type-checker or scanner setting weakened, test files included.
_ALWAYS_RISKS = frozenset({"SKY-A119"})
# A scanner suppression marker (SKY-A125) is advice, like `done`'s SKY-A118
# inline suppressions; one that names no rule and covers more than a line or
# statement needs approval (see _broad_scanner_marker_risks).
_MARKER = "SKY-A125"
_ADVICE_RULES = frozenset({_MARKER})

# Done checks that run the tests; the risk review never does.
_TEST_RUN_CHECKS = frozenset({"tests_pass", "changed_lines_checked"})
# Done checks no risk class reads: code left without callers (SKY-A135-A137)
# costs two dead-code analyses and maps to no class, so it is not run.
_NO_CLASS_CHECKS = frozenset({"branch_orphans"})
_CHECK_CLASSES = {
    "test_tampering": ("tests_weakened",),
    "test_special_casing": ("tests_weakened",),
    "gate_tampering": ("guardrail_config_changed",),
    "secrets": ("secret_added",),
    "unknown_imports": ("dependency_changed",),
    "silenced_checks": ("ci_weakened", "checks_silenced"),
    "security_controls": ("auth_removed",),
    # SKY-A122 AI-reviewer settings and SKY-A125 scanner suppression markers.
    "guardrail_tampering": ("guardrail_config_changed", "checks_silenced"),
}

DEFAULT_LARGE_DIFF_LINES = 800
DEFAULT_LARGE_DIFF_FILES = 40
_MAX_PATTERNS = 100
_MAX_LOGINS = 200
_DEPENDENCY_FILE_BYTES = 64 * 1024 * 1024
_GIT_TIMEOUT_SECONDS = 120

# Directory pairs that hold database migrations (Rails, Flyway, Alembic,
# Liquibase); any directory named "migrations" counts too.
_MIGRATION_DIR_PAIRS = frozenset(
    {
        ("db", "migrate"),
        ("db", "migration"),
        ("db", "changelog"),
        ("alembic", "versions"),
    }
)
_NOT_MIGRATION_SUFFIXES = frozenset(
    {
        ".md",
        ".markdown",
        ".mdx",
        ".rst",
        ".adoc",
        ".txt",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".pdf",
    }
)
_VENDORED_DIRS = frozenset({"node_modules", "vendor", "third_party", "third-party"})


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovalConfig:
    veto_classes: tuple[str, ...] = VETO_CLASSES
    large_diff_lines: int = DEFAULT_LARGE_DIFF_LINES
    large_diff_files: int = DEFAULT_LARGE_DIFF_FILES
    migration_globs: tuple[str, ...] = ()
    exclude: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    non_human_logins: tuple[str, ...] = ()
    configured: bool = False
    problems: tuple[str, ...] = ()


def parse_approval_config(pyproject_text: str | None) -> ApprovalConfig:
    """``[tool.skylos.approval]`` from a pyproject.toml's text, or
    ``[approval]`` from a skylos.toml's (None: no file)."""
    from skylos.done.config import skylos_settings_table
    from skylos.done.test_config import _toml

    if pyproject_text is None:
        return ApprovalConfig()
    data = _toml(pyproject_text)
    if data is None:
        return ApprovalConfig(
            problems=("pyproject.toml at the base is not valid TOML",)
        )
    table = skylos_settings_table(data)
    table = table.get("approval") if isinstance(table, dict) else None
    if table is None:
        return ApprovalConfig()
    if not isinstance(table, dict):
        return ApprovalConfig(problems=("[tool.skylos.approval] is not a table",))

    problems: list[str] = []
    classes = VETO_CLASSES
    raw = table.get("veto_classes")
    if raw is not None:
        if isinstance(raw, list) and all(isinstance(c, str) for c in raw):
            unknown = [c for c in raw if c not in VETO_CLASSES]
            for name in unknown:
                problems.append(f"veto_classes: unknown class {name!r} ignored")
            classes = tuple(c for c in VETO_CLASSES if c in raw)
        else:
            problems.append("veto_classes must be a list of class names")
    exclude: dict[str, tuple[str, ...]] = {}
    raw_exclude = table.get("exclude")
    if raw_exclude is not None:
        if not isinstance(raw_exclude, dict):
            problems.append("[tool.skylos.approval.exclude] is not a table")
        else:
            for name, patterns in raw_exclude.items():
                if name not in VETO_CLASSES:
                    problems.append(f"exclude: unknown class {name!r} ignored")
                    continue
                exclude[name] = _patterns(patterns, f"exclude.{name}", problems)
    return ApprovalConfig(
        veto_classes=classes,
        large_diff_lines=_bounded_int(
            table.get("large_diff_lines"),
            "large_diff_lines",
            DEFAULT_LARGE_DIFF_LINES,
            1,
            10_000_000,
            problems,
        ),
        large_diff_files=_bounded_int(
            table.get("large_diff_files"),
            "large_diff_files",
            DEFAULT_LARGE_DIFF_FILES,
            1,
            1_000_000,
            problems,
        ),
        migration_globs=_patterns(
            table.get("migration_globs"), "migration_globs", problems
        ),
        exclude=exclude,
        non_human_logins=_logins(table.get("non_human_logins"), problems),
        configured=True,
        problems=tuple(problems),
    )


def _bounded_int(value, name, default, minimum, maximum, problems) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        problems.append(f"{name} must be a whole number")
        return default
    if not minimum <= value <= maximum:
        problems.append(f"{name} must be between {minimum} and {maximum}")
        return min(max(value, minimum), maximum)
    return value


def _patterns(value, name: str, problems: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(p, str) for p in value):
        problems.append(f"{name} must be a list of path patterns")
        return ()
    cleaned = []
    for raw in value[:_MAX_PATTERNS]:
        pattern = raw.strip().replace("\\", "/")
        while pattern.startswith("./"):
            pattern = pattern[2:]
        if pattern and not pattern.startswith("/") and ".." not in pattern.split("/"):
            cleaned.append(pattern)
        else:
            problems.append(f"{name}: pattern {raw!r} ignored")
    if len(value) > _MAX_PATTERNS:
        problems.append(f"{name}: only the first {_MAX_PATTERNS} patterns apply")
    return tuple(dict.fromkeys(cleaned))


def _logins(value, problems: list[str]) -> tuple[str, ...]:
    import re

    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        problems.append("non_human_logins must be a list of GitHub logins")
        return ()
    cleaned = []
    for raw in value[:_MAX_LOGINS]:
        login = raw.strip()
        if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?", login):
            cleaned.append(login.lower())
        else:
            problems.append(f"non_human_logins: {raw!r} is not a GitHub login")
    return tuple(dict.fromkeys(cleaned))


def path_matches(path: str | None, patterns: tuple[str, ...]) -> bool:
    """``dir/`` matches below a folder, globs use fnmatch (``*`` crosses
    folders), anything else matches the path or a folder of that name."""
    from skylos.done.checks import _protected_match

    return bool(path) and _protected_match(path, patterns) is not None


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Risk:
    cls: str
    rule_id: str | None
    file: str | None
    line: int | None
    reason: str

    def to_dict(self) -> dict:
        return {
            "class": self.cls,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "reason": self.reason,
        }


@dataclass
class ApprovalResult:
    base_ref: str
    base: str
    head: str
    head_dirty: bool
    config: ApprovalConfig
    vetoes: list[Risk] = field(default_factory=list)
    advisories: list[Risk] = field(default_factory=list)
    classes_checked: list[str] = field(default_factory=list)
    classes_incomplete: dict[str, str] = field(default_factory=dict)
    excluded: int = 0
    files_changed: int = 0
    lines_changed: int = 0

    @property
    def complete(self) -> bool:
        return not self.classes_incomplete

    @property
    def eligible(self) -> bool:
        """No risk class found and nothing left unchecked."""
        return self.complete and not self.vetoes

    @property
    def classes_found(self) -> list[str]:
        found = {risk.cls for risk in self.vetoes}
        return [name for name in VETO_CLASSES if name in found]

    @property
    def classes_disabled(self) -> list[str]:
        return [c for c in VETO_CLASSES if c not in self.config.veto_classes]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def analyze_change(
    path: str, base_ref: str, *, config_ref: str | None = None
) -> ApprovalResult:
    """Every risk class in the change from ``base_ref``'s merge base to the
    working tree. Raises ``DoneError`` when the comparison cannot be set up.

    ``config_ref`` reads the settings from another commit than ``base_ref``:
    a merge queue analyses each pull request's part of a group with the
    queue base commit's settings, never with those of a pull request ahead."""
    from skylos.done.checks import CHECKS, RUN_ORDER, CheckContext, run_check
    from skylos.done.config import base_config_text, parse_done_config

    comparison = open_comparison(path, base_ref)
    if config_ref is not None:
        comparison.config_sha = config_ref
    pyproject = base_config_text(comparison, sha=comparison.config_sha)
    config = parse_approval_config(pyproject)
    enabled = set(config.veto_classes)
    result = ApprovalResult(
        base_ref=base_ref,
        base=comparison.base_sha,
        head=comparison.head_sha,
        head_dirty=comparison.head_dirty,
        config=config,
    )
    ctx = CheckContext(comparison, parse_done_config(pyproject), run_tests=False)

    check_ids = [*RUN_ORDER, *(c for c in CHECKS if c not in RUN_ORDER)]
    for check_id in check_ids:
        if check_id in _TEST_RUN_CHECKS:
            continue
        if check_id in _NO_CLASS_CHECKS:
            continue
        classes = _CHECK_CLASSES.get(check_id) or _rule_classes(CHECKS[check_id][1])
        if check_id in _CHECK_CLASSES and not enabled.intersection(classes):
            continue
        outcome = run_check(check_id, ctx)
        if outcome.status == "incomplete":
            for name in classes:
                _incomplete(result, name, outcome.summary)
        for finding in outcome.findings:
            if finding.rule == ANALYSIS_INCOMPLETE_RULE:
                for name in classes:
                    _incomplete(result, name, finding.message)
                continue
            name = RULE_CLASSES.get(finding.rule or "")
            if name is None and len(classes) == 1:
                # A rule this release does not know, from a check that covers
                # one class: it counts there rather than being dropped.
                name = classes[0]
            if name is None or name not in enabled:
                continue
            needs_approval = (
                finding.blocking or finding.rule in _ALWAYS_RISKS
            ) and finding.rule not in _ADVICE_RULES
            risk = Risk(
                name,
                finding.rule,
                finding.file,
                finding.line,
                _one_line(finding.message),
            )
            (result.vetoes if needs_approval else result.advisories).append(risk)

    own_checks = (
        ("checks_silenced", _blanket_suppression_risks),
        ("checks_silenced", _broad_scanner_marker_risks),
        ("ci_weakened", _ci_permission_risks),
        ("ci_weakened", _ai_agent_workflow_risks),
        ("dependency_changed", lambda c: _dependency_risks(c, ctx)),
        ("migration_changed", lambda c: _migration_risks(c, config)),
    )
    for name, function in own_checks:
        if name not in enabled:
            continue
        try:
            result.vetoes.extend(function(comparison))
        except Exception as exc:
            logger.debug("risk review: %s failed", name, exc_info=True)
            _incomplete(result, name, _error_text(exc))
    try:
        files, lines = diff_size(comparison, config.exclude.get("large_diff", ()))
        result.files_changed, result.lines_changed = files, lines
        if "large_diff" in enabled and (
            files > config.large_diff_files or lines > config.large_diff_lines
        ):
            result.vetoes.append(
                Risk(
                    "large_diff",
                    None,
                    None,
                    None,
                    f"changes {lines} lines in {files} files (limit: "
                    f"{config.large_diff_lines} lines or {config.large_diff_files} "
                    "files; lockfiles not counted)",
                )
            )
    except Exception as exc:
        logger.debug("risk review: diff size failed", exc_info=True)
        if "large_diff" in enabled:
            _incomplete(result, "large_diff", _error_text(exc))

    # A blanket suppression or broad scanner marker is a risk now; drop
    # `done`'s advice for its line.
    promoted = {
        (r.rule_id, r.file, r.line)
        for r in result.vetoes
        if r.rule_id in (_SUPPRESSION, _MARKER)
    }
    result.advisories = [
        a for a in result.advisories if (a.rule_id, a.file, a.line) not in promoted
    ]
    result.vetoes, dropped = _apply_exclusions(result.vetoes, config)
    result.advisories, _ = _apply_exclusions(result.advisories, config)
    result.excluded = dropped
    result.vetoes = _sorted(_unique(result.vetoes))
    result.advisories = _sorted(_unique(result.advisories))
    result.classes_checked = [
        name
        for name in VETO_CLASSES
        if name in enabled and name not in result.classes_incomplete
    ]
    return result


def _rule_classes(rule: str | None) -> tuple[str, ...]:
    name = RULE_CLASSES.get(rule or "")
    return (name,) if name else ()


def _incomplete(result: ApprovalResult, name: str, reason: str) -> None:
    if name in result.config.veto_classes:
        result.classes_incomplete.setdefault(name, _one_line(reason))


def _error_text(exc: Exception) -> str:
    if isinstance(exc, DoneError):
        return str(exc)
    return f"could not finish ({type(exc).__name__})"


def _one_line(text: str | None, limit: int = 240) -> str:
    value = " ".join(str(text or "").split())
    value = value.removeprefix("(advice) ")
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _apply_exclusions(risks: list[Risk], config: ApprovalConfig):
    kept, dropped = [], 0
    for risk in risks:
        patterns = config.exclude.get(risk.cls, ())
        if patterns and path_matches(risk.file, patterns):
            dropped += 1
        else:
            kept.append(risk)
    return kept, dropped


def _unique(risks: list[Risk]) -> list[Risk]:
    return list(dict.fromkeys(risks))


def _sorted(risks: list[Risk]) -> list[Risk]:
    order = {name: index for index, name in enumerate(VETO_CLASSES)}
    return sorted(
        risks,
        key=lambda r: (order.get(r.cls, 99), r.file or "", r.line or 0, r.reason),
    )


# -- checks_silenced: blanket suppressions (SKY-A118) -------------------------

_SUPPRESSION = "SKY-A118"


# Scopes of a scanner marker that cover one line or statement.
_NARROW_MARKER_SCOPES = frozenset(
    {"line", "line or next", "next line", "next statement"}
)


def _broad_scanner_marker_risks(comparison: Comparison) -> list[Risk]:
    """Added scanner suppression markers (SKY-A125) that name no rule and stop
    a scanner reporting a whole function, block, region or file
    (``@codescene(disable-all)``, ``kics-scan ignore``). ``done`` lists every
    marker; one that names a rule or covers one line stays advice here, like
    SKY-A118's inline suppressions."""
    from skylos.rules.ai_defect.guardrails import (
        RULE_SCANNER_MARKER,
        changes_from_comparison,
        detect_guardrail_tampering,
    )

    outcome = detect_guardrail_tampering(changes_from_comparison(comparison))
    return [
        Risk("checks_silenced", f.rule, f.file, f.line, _one_line(f.message))
        for f in outcome.findings
        if f.rule == RULE_SCANNER_MARKER
        and not f.details.get("rules")
        and f.details.get("scope") not in _NARROW_MARKER_SCOPES
    ]


def _blanket_suppression_risks(comparison: Comparison) -> list[Risk]:
    """New suppressions that stop a linter, type checker or scanner checking
    a whole file or region (``/* eslint-disable */``, ``@ts-nocheck``,
    ``# ruff: noqa``), test files included. ``done`` lists every suppression
    as advice; one that names a rule or covers one line stays advice here."""
    from skylos.done.answer_sites import _is_generated, _is_test_code
    from skylos.done.suppressions import added_suppressions, silences_everything

    def is_test(path: str) -> bool:
        return _is_test_code(path, set()) or path.endswith("_test.go")

    risks = []
    for item in added_suppressions(comparison, is_test, _is_generated):
        directive = item.directive
        if item.generated or not silences_everything(directive):
            continue
        reason = (
            f' (reason: "{_one_line(directive.reason, 60)}")'
            if directive.reason
            else " with no reason"
        )
        if directive.scope == "file":
            verb = "no longer checks" if item.existed else "skips"
            effect = f"{directive.tool} {verb} this whole file"
        else:
            effect = f"{directive.tool} stops checking every rule from this line on"
        risks.append(
            Risk(
                "checks_silenced",
                _SUPPRESSION,
                item.path,
                directive.line,
                f"adds {directive.shown}{reason}: {effect}",
            )
        )
    return risks


# -- ci_weakened: SKY-A103 ----------------------------------------------------


def _ci_permission_risks(comparison: Comparison) -> list[Risk]:
    from skylos.rules.ai_defect.ci_permission_expansion import (
        detect_ci_permission_expansion,
    )

    risks = []
    for changed in comparison.changed:
        if changed.head_path is None or not _is_workflow(changed.path):
            continue
        for item in detect_ci_permission_expansion(
            comparison.file_diff(changed), changed.path
        ):
            value = (item.get("metadata") or {}).get("added_value") or "a privilege"
            risks.append(
                Risk(
                    "ci_weakened",
                    str(item.get("rule_id") or "SKY-A103"),
                    changed.path,
                    item.get("line"),
                    f"widens what the workflow can do ({value})",
                )
            )
    return risks


# -- AI agents in CI workflows (SKY-D350 to SKY-D354) ----------------------------

_AI_AGENT_RULES = frozenset(
    {"SKY-D350", "SKY-D351", "SKY-D352", "SKY-D353", "SKY-D354"}
)
_AI_AGENT_SEVERITIES = frozenset({"HIGH", "CRITICAL"})


def _ai_agent_workflow_risks(comparison: Comparison) -> list[Risk]:
    """HIGH and CRITICAL AI-agent workflow findings (an agent on untrusted
    triggers with write tokens, secrets, shell tools, a widened write-access
    check, untrusted text in its prompt, or a version with a published
    advisory) in workflow files the change adds or edits, when the base
    version of that file did not already have them. Findings are matched by
    rule and job/step key, so moving lines does not count."""
    root = Path(comparison.root).resolve()
    risks = []
    for changed in comparison.changed:
        if changed.head_path is None or not _is_workflow(changed.head_path):
            continue
        head = _agent_findings(root / changed.head_path, root)
        if not head:
            continue
        base_text = (
            comparison.base_text(changed.base_path)
            if changed.base_path and _is_workflow(changed.base_path)
            else None
        )
        before = set()
        if base_text is not None:
            with tempfile.TemporaryDirectory(prefix="skylos-risk-review-") as tmp:
                base_root = Path(tmp).resolve()
                copy = base_root / changed.base_path
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_text(base_text, encoding="utf-8")
                before = {
                    (f.get("rule_id"), f.get("value"))
                    for f in _agent_findings(copy, base_root)
                }
        for finding in head:
            if (finding.get("rule_id"), finding.get("value")) in before:
                continue
            risks.append(
                Risk(
                    "ci_weakened",
                    str(finding.get("rule_id")),
                    changed.head_path,
                    finding.get("line"),
                    f"AI agent in CI ({finding.get('severity')}): "
                    + _one_line(finding.get("message"), 200),
                )
            )
    return risks


def _agent_findings(path: Path, root: Path) -> list[dict]:
    from skylos.rules.config.cicd.github_actions import scan_github_actions_file

    return [
        f
        for f in scan_github_actions_file(path, root=root, analysis_errors=[])
        if f.get("rule_id") in _AI_AGENT_RULES
        and str(f.get("severity") or "").upper() in _AI_AGENT_SEVERITIES
    ]


def _is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


# -- dependency_changed --------------------------------------------------------


def _dependency_risks(comparison: Comparison, ctx) -> list[Risk]:
    from skylos.cicd.approval_dependencies import dependency_changes

    _, head_paths, removed = ctx._repository_paths()
    changes = dependency_changes(
        comparison.changed,
        base_text=lambda p: _base_dependency_text(comparison, p),
        head_text=lambda p: _head_dependency_text(comparison, p),
        head_paths=[p for p in head_paths if p and p not in removed],
    )
    return [Risk("dependency_changed", None, c.file, c.line, c.reason) for c in changes]


def _base_dependency_text(comparison: Comparison, path: str) -> str | None:
    data = _git_bytes(
        comparison._context, "cat-file", "blob", f"{comparison.base_sha}:{path}"
    )
    if data is None or len(data) > _DEPENDENCY_FILE_BYTES:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _head_dependency_text(comparison: Comparison, path: str) -> str | None:
    try:
        return read_project_text_no_symlink(
            comparison.root, path, max_bytes=_DEPENDENCY_FILE_BYTES, errors="strict"
        )
    except (OSError, UnicodeDecodeError, ValueError):
        return None


# -- migration_changed ---------------------------------------------------------


def is_migration_path(path: str, extra_globs: tuple[str, ...] = ()) -> bool:
    if extra_globs and path_matches(path, extra_globs):
        return True
    pure = PurePosixPath(path)
    if pure.suffix.lower() in _NOT_MIGRATION_SUFFIXES:
        return False
    folders = [part.lower() for part in pure.parts[:-1]]
    if _VENDORED_DIRS.intersection(folders):
        return False
    if "migrations" in folders:
        return True
    return any(pair in _MIGRATION_DIR_PAIRS for pair in itertools.pairwise(folders))


def _migration_risks(comparison: Comparison, config: ApprovalConfig) -> list[Risk]:
    verbs = {
        "added": "adds",
        "modified": "changes",
        "deleted": "deletes",
        "renamed": "moves",
    }
    risks = []
    for changed in comparison.changed:
        paths = [p for p in (changed.base_path, changed.path) if p]
        if not any(is_migration_path(p, config.migration_globs) for p in paths):
            continue
        verb = verbs.get(changed.status, "changes")
        risks.append(
            Risk(
                "migration_changed",
                None,
                changed.path,
                None,
                f"{verb} database migration {changed.path}",
            )
        )
    return risks


# -- large_diff ----------------------------------------------------------------


def diff_size(comparison: Comparison, exclude: tuple[str, ...] = ()) -> tuple[int, int]:
    """(files, added + deleted lines) of the change, lockfiles left out.

    Binary files count as files with no lines. Repository attributes cannot
    hide a text file's lines: a file Git reports as binary only because of
    ``.gitattributes`` is counted from its text diff.
    """
    from skylos.cicd.approval_dependencies import is_lockfile

    counted = [
        changed
        for changed in comparison.changed
        if not any(
            is_lockfile(p) or (exclude and path_matches(p, exclude))
            for p in (changed.base_path, changed.path)
            if p
        )
    ]
    numstat = _numstat(comparison)
    lines = 0
    for changed in counted:
        key = changed.path
        if changed.path in comparison._untracked:
            text = comparison.head_text(changed.path)
            lines += len(text.splitlines()) if text else 0
            continue
        stat = numstat.get(key)
        if stat is None:
            continue
        if stat == (None, None):  # binary to Git
            if _really_binary(comparison, changed):
                continue
            stat = _text_line_counts(comparison.file_diff(changed))
        lines += stat[0] + stat[1]
    return len(counted), lines


def _numstat(comparison: Comparison) -> dict[str, tuple[int | None, int | None]]:
    context = comparison._context
    command = read_only_git_command(
        [
            "diff",
            "--numstat",
            "-z",
            "-M",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            comparison.base_sha,
            "--",
        ],
        config_overrides=[
            "core.quotePath=false",
            *(context.filter_config_overrides or ()),
        ],
    )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=_GIT_TIMEOUT_SECONDS,
            cwd=str(context.root),
            env=context.env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DoneError("git diff --numstat failed") from exc
    if completed.returncode != 0:
        raise DoneError("git diff --numstat failed")
    return parse_numstat(completed.stdout.decode("utf-8", errors="replace"))


def parse_numstat(output: str) -> dict[str, tuple[int | None, int | None]]:
    """``git diff --numstat -z`` output as {head path: (added, deleted)};
    (None, None) for a binary file."""
    stats: dict[str, tuple[int | None, int | None]] = {}
    tokens = output.split("\0")
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if not token:
            continue
        parts = token.split("\t", 2)
        if len(parts) != 3:
            continue
        added, deleted, path = parts
        if not path:  # a rename: the old and new paths follow
            if index + 1 >= len(tokens):
                break
            path = tokens[index + 1]
            index += 2
        stats[path] = (
            None if added == "-" else int(added),
            None if deleted == "-" else int(deleted),
        )
    return stats


def _really_binary(comparison: Comparison, changed) -> bool:
    """Git's own test (a NUL byte in the first 8000 bytes), ignoring
    .gitattributes, on either side."""
    samples = []
    if changed.base_path:
        data = _git_bytes(
            comparison._context,
            "cat-file",
            "blob",
            f"{comparison.base_sha}:{changed.base_path}",
        )
        samples.append(data or b"")
    if changed.head_path:
        text = read_project_text_no_symlink(
            comparison.root,
            changed.head_path,
            max_bytes=_DEPENDENCY_FILE_BYTES,
            encoding="latin-1",
        )
        if text is None:
            return True  # unreadable or huge: count no lines
        samples.append(text[:8000].encode("latin-1"))
    return any(b"\0" in sample[:8000] for sample in samples)


def _text_line_counts(diff: str) -> tuple[int, int]:
    added = deleted = 0
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++ "):
            added += 1
        elif line.startswith("-") and not line.startswith("--- "):
            deleted += 1
    return added, deleted
