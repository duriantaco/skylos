import importlib  # skylos: ignore[SKY-Q502] legacy gate flow module is being split incrementally
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.prompt import Confirm, Prompt

from skylos.core.gate_incomplete import analysis_coverage, incomplete_analysis_reasons


class _LazyInquirer:
    """Import inquirer only when an interactive prompt is actually used."""

    _module = None

    def _load(self):
        if self._module is None:
            self._module = importlib.import_module("inquirer")
        return self._module

    def __getattr__(self, name):
        return getattr(self._load(), name)


def _inquirer_available() -> bool:
    try:
        return importlib.util.find_spec("inquirer") is not None
    except (ImportError, ValueError):
        return False


INTERACTIVE = _inquirer_available()
inquirer = _LazyInquirer() if INTERACTIVE else None

console = Console()
DEAD_CODE_RESULT_KEYS = (
    "unused_functions",
    "unused_imports",
    "unused_variables",
    "unused_classes",
    "unused_parameters",
    "unused_files",
)
AGENT_GATE_PREFIX = "Agent gate: "
BASELINE_GATE_CONFIG = {
    "fail_on_critical": True,
    "max_critical": 0,
    "max_high": 5,
    "max_security": 10,
    "max_reliability": 0,
    "max_quality": 10,
    "max_secrets": 0,
    "max_dependency_vulnerabilities": 0,
    "max_dead_code": None,
}
# (gate key, noun used in failure reasons, its plural, label in the PASSED line)
GATE_LIMITS = (
    ("max_critical", "critical issue", None, "critical"),
    ("max_high", "high severity issue", None, "high"),
    ("max_security", "security issue", None, "security"),
    ("max_reliability", "reliability issue", None, "reliability"),
    ("max_quality", "quality issue", None, "quality"),
    ("max_ai_defects", "AI-defect issue", None, "AI defects"),
    ("max_secrets", "secret", None, "secrets"),
    (
        "max_dependency_vulnerabilities",
        "dependency vulnerability",
        "dependency vulnerabilities",
        "dependency vulnerabilities",
    ),
    ("max_dead_code", "dead code issue", None, "dead code"),
)
SECURITY_GATE_KEYS = ("max_critical", "max_high", "max_security")
GATE_ISSUE_LIST_LIMIT = 10
GATE_ISSUE_MESSAGE_CHARS = 80
ADVISORY_QUALITY_RULE_IDS = {"SKY-Q802", "SKY-Q803"}
# AI defects at these severities fail the gate whatever max_ai_defects allows.
# [tool.skylos.gate] block_ai_defect_severities replaces the list; [] turns
# the rule off and leaves only the max_ai_defects count.
BLOCK_AI_DEFECT_SEVERITIES_KEY = "block_ai_defect_severities"
DEFAULT_BLOCK_AI_DEFECT_SEVERITIES = ("CRITICAL",)
AI_DEFECT_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
AI_DEFECT_REASON_RULE_LIMIT = 3
SAFE_RULE_ID = re.compile(r"[A-Za-z0-9_.-]{1,40}")
DEFEND_GATE_HINT = (
    "Remove them from [tool.skylos.gate.agent] and run "
    "`skylos defend . --min-score 70 --fail-on critical` as its own CI step "
    "(`skylos cicd init --defend` adds it)."
)


INCOMPLETE_VERDICT = "Quality Gate: INCOMPLETE — could not decide (exit 2)"
INCOMPLETE_EXPLANATION = (
    "Required analysis did not finish, so the gate can neither pass nor fail. "
    "--force and advisory mode do not change this."
)


class GateReason(str):
    """A gate reason with the issues counted toward it and literal detail lines."""

    issues = ()
    hint = None
    details = ()

    def __new__(cls, text, issues=(), hint=None, details=()):
        reason = super().__new__(cls, text)
        reason.issues = list(issues)
        reason.hint = hint
        reason.details = tuple(details)
        return reason


def run_cmd(cmd_list, error_msg="Git command failed"):
    try:
        result = subprocess.run(cmd_list, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        console.print(
            f"[bold red]Error:[/bold red] {escape(str(error_msg))}\n"
            f"[dim]{escape(str(e.stderr or ''))}[/dim]"
        )
        return None


def get_git_status():
    out = run_cmd(
        ["git", "status", "--porcelain"], "Could not get git status. Is this a repo?"
    )
    if not out:
        return []

    files = []
    for line in out.splitlines():
        if len(line) > 3:
            files.append(line[3:])
    return files


def run_push():
    console.print("[dim]Pushing to remote...[/dim]")
    try:
        subprocess.run(["git", "push"], check=True)
        console.print("[bold green] Deployment Complete. Code is live.[/bold green]")
    except subprocess.CalledProcessError:
        console.print(
            "[bold red] Push failed. Check your git remote settings.[/bold red]"
        )


def start_deployment_wizard():
    if not INTERACTIVE:
        console.print(
            "[yellow]Install 'inquirer' (pip install inquirer) to use interactive deployment.[/yellow]"
        )
        return

    console.print("\n[bold cyan] Skylos Deployment Wizard[/bold cyan]")

    files = get_git_status()
    if not files:
        console.print("[green]Working tree is clean.[/green]")
        if Confirm.ask("Push existing commits?"):
            run_push()
        return

    q_scope = [
        inquirer.List(
            "scope",
            message="What do you want to stage?",
            choices=[
                "All changed files",
                "Select files manually",
                "Skip commit (Push only)",
            ],
        ),
    ]
    ans_scope = inquirer.prompt(q_scope)
    if not ans_scope:
        return

    if ans_scope["scope"] == "Select files manually":
        q_files = [inquirer.Checkbox("files", message="Select files", choices=files)]
        ans_files = inquirer.prompt(q_files)
        if not ans_files or not ans_files["files"]:
            console.print("[red]No files selected.[/red]")
            return
        run_cmd(["git", "add"] + ans_files["files"])
        console.print(f"[green]Staged {len(ans_files['files'])} files.[/green]")

    elif ans_scope["scope"] == "All changed files":
        run_cmd(["git", "add", "."])
        console.print("[green]Staged all files.[/green]")

    if ans_scope["scope"] != "Skip commit (Push only)":
        msg = Prompt.ask("[bold green]Enter commit message[/bold green]")
        if not msg:
            console.print("[red]Commit message required.[/red]")
            return
        if run_cmd(["git", "commit", "-m", msg]):
            console.print("[green]✓ Committed.[/green]")

    if Confirm.ask("Ready to git push?"):
        run_push()


def _get_finding_file(finding):
    return finding.get("file", finding.get("file_path", ""))


def _collect_dead_code_items(results):
    items = []
    for key in DEAD_CODE_RESULT_KEYS:
        items.extend(results.get(key, []) or [])
    return items


def _count_dead_code_findings(results):
    return sum(len(results.get(key, []) or []) for key in DEAD_CODE_RESULT_KEYS)


def _split_danger_by_severity(danger):
    critical_issues = []
    high_issues = []
    for issue in danger:
        sev = str(issue.get("severity", "")).lower()
        if sev == "critical":
            critical_issues.append(issue)
        elif sev == "high":
            high_issues.append(issue)
    return critical_issues, high_issues


def _is_advisory_quality_finding(finding):
    return (
        isinstance(finding, dict)
        and bool(finding.get("advisory"))
        and str(finding.get("rule_id", "")) in ADVISORY_QUALITY_RULE_IDS
    )


def _gate_quality_findings(quality, *, explicit_rules=(), use_listing_policy=False):
    from skylos.reporting.finding_types import get_finding_type
    from skylos.reporting.listing import is_listed, listing_decision

    def included(finding):
        rule = (
            str(finding.get("rule_id") or finding.get("id") or "").upper()
            if isinstance(finding, dict)
            else ""
        )
        if rule in explicit_rules:
            return True
        if use_listing_policy or listing_decision(finding) is not None:
            return is_listed(finding, "quality", explicit_rules=explicit_rules)
        if get_finding_type(finding, "quality") != "advice":
            return True
        return not _is_advisory_quality_finding(finding)

    return [finding for finding in quality if included(finding)]


def _quality_findings_with_custom_rules(results, *, gate_only=False, explicit_rules=()):
    quality = list(results.get("quality", []) or [])
    if results.get("listing_policy_version") == 1:
        from skylos.reporting.finding_types import iter_result_findings

        # Architecture signals are the additional Advice family carried
        # outside quality. Keep circular-dependency and code-health policies
        # independent of the ordinary quality threshold.
        quality = [
            row
            for category, row in iter_result_findings(
                {
                    "quality": quality,
                    "architecture_metrics": results.get("architecture_metrics"),
                }
            )
            if category == "quality"
        ]
    if explicit_rules:
        from skylos.reporting.finding_types import iter_result_findings

        for category, row in iter_result_findings(results):
            if (
                category == "quality"
                and str(row.get("rule_id") or row.get("id") or "").upper()
                in explicit_rules
                and row not in quality
            ):
                quality.append(row)
    if gate_only:
        quality = _gate_quality_findings(
            quality,
            explicit_rules=explicit_rules,
            use_listing_policy=results.get("listing_policy_version") == 1,
        )
    seen = {json.dumps(finding, sort_keys=True, default=str) for finding in quality}
    # Custom rules are quality findings, but are reported in a separate array.
    # Only built-in advisory rules may opt out of the gate. A custom rule must
    # still count if it reuses an advisory rule ID or advisory metadata.
    for finding in results.get("custom_rules", []) or []:
        key = json.dumps(finding, sort_keys=True, default=str)
        if key not in seen:
            quality.append(finding)
            seen.add(key)
    return quality


def _security_control_regressions(results):
    """Control removals cannot spend the ordinary quality/high issue allowance."""
    regressions = []
    seen = set()
    for category in ("quality", "danger"):
        for finding in results.get(category, []) or []:
            if not isinstance(finding, dict):
                continue
            if not (
                (
                    finding.get("rule_id") == "SKY-L021"
                    or finding.get("kind") == "security_regression"
                )
                and str(finding.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
            ):
                continue
            key = json.dumps(finding, sort_keys=True, default=str)
            if key not in seen:
                regressions.append(finding)
                seen.add(key)
    return regressions


def _count_noun(count, singular, plural=None):
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _append_threshold_reason(
    reasons,
    *,
    issues,
    limit,
    noun,
    plural=None,
    template="{counted} (max: {limit})",
):
    count = len(issues)
    if isinstance(limit, int) and count > limit:
        counted = _count_noun(count, noun, plural)
        reasons.append(
            GateReason(template.format(counted=counted, limit=limit), issues)
        )
        return False
    return True


def _gate_issue_groups(
    *, danger, reliability, ai_defects, quality, secrets, dead_code, dependencies=()
):
    critical_issues, high_issues = _split_danger_by_severity(danger)
    return {
        "max_critical": critical_issues,
        "max_high": high_issues,
        "max_security": danger,
        "max_reliability": reliability,
        "max_quality": quality,
        "max_ai_defects": ai_defects,
        "max_secrets": secrets,
        "max_dependency_vulnerabilities": dependencies,
        "max_dead_code": dead_code,
    }


def _safe_gate_limit(value, default):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return default
    return value


def _non_relaxable_gate_limit(value, baseline):
    safe_value = _safe_gate_limit(value, baseline)
    return min(safe_value, baseline)


def _block_ai_defect_severities(gate_config):
    """Severities at which one AI defect fails the gate.

    Missing or unusable values keep the default, so a typo cannot turn the
    rule off. Only an explicit empty list does that.
    """
    if BLOCK_AI_DEFECT_SEVERITIES_KEY not in gate_config:
        return DEFAULT_BLOCK_AI_DEFECT_SEVERITIES
    value = gate_config.get(BLOCK_AI_DEFECT_SEVERITIES_KEY)
    if not isinstance(value, (list, tuple)):
        return DEFAULT_BLOCK_AI_DEFECT_SEVERITIES
    if not value:
        return ()
    requested = {str(item).strip().upper() for item in value if isinstance(item, str)}
    severities = tuple(sev for sev in AI_DEFECT_SEVERITY_ORDER if sev in requested)
    return severities or DEFAULT_BLOCK_AI_DEFECT_SEVERITIES


def _effective_gate_config(config):
    gate_config = config.get("gate", {}) if isinstance(config, dict) else {}
    if not isinstance(gate_config, dict):
        gate_config = {}

    effective = dict(gate_config)
    effective["fail_on_critical"] = True
    for key in ("max_critical", "max_secrets"):
        effective[key] = _non_relaxable_gate_limit(
            gate_config.get(key),
            BASELINE_GATE_CONFIG[key],
        )
    for key in (
        "max_high",
        "max_security",
        "max_reliability",
        "max_quality",
        "max_dependency_vulnerabilities",
        "max_dead_code",
    ):
        effective[key] = _safe_gate_limit(
            gate_config.get(key),
            BASELINE_GATE_CONFIG[key],
        )
    if "max_ai_defects" in gate_config:
        effective["max_ai_defects"] = _safe_gate_limit(
            gate_config.get("max_ai_defects"),
            effective.get("max_quality", BASELINE_GATE_CONFIG["max_quality"]),
        )
    else:
        effective["max_ai_defects"] = effective.get(
            "max_quality",
            BASELINE_GATE_CONFIG["max_quality"],
        )
    effective[BLOCK_AI_DEFECT_SEVERITIES_KEY] = _block_ai_defect_severities(gate_config)
    return effective


def _cloud_gate_policy(config):
    from skylos.config import synced_gate_policy
    from skylos.core.cloud_gate import cloud_gate_policy

    return cloud_gate_policy(synced_gate_policy(config))


def active_cloud_gate(config):
    """The synced Skylos Cloud gate this run applies, or None.

    A disabled Cloud gate is None too: the built-in limits then apply, as
    they did before Cloud gates were read.
    """
    policy = _cloud_gate_policy(config)
    if policy is None or not policy["enabled"]:
        return None
    return policy


def _new_issues_only(results):
    from skylos.core.gate_incomplete import _is_diff_scoped

    summary = results.get("analysis_summary")
    if not isinstance(summary, dict):
        summary = {}
    return summary.get("baseline_scoped") is True or _is_diff_scoped(results, summary)


def cloud_gate_scope_note(results, config, *, strict=False):
    """One line when a Cloud gate checks a scan that is not limited to new issues."""
    from skylos.core.cloud_gate import CLOUD_GATE_SCOPE_NOTE

    if strict or active_cloud_gate(config) is None:
        return None
    if not isinstance(results, dict):
        results = {}
    if _new_issues_only(results):
        return None
    return CLOUD_GATE_SCOPE_NOTE


def _cloud_gate_notes(config):
    from skylos.config import synced_gate_left_out_by_policy_base
    from skylos.core.cloud_gate import (
        CLOUD_GATE_OFF_NOTE,
        UNUSED_CLOUD_GATE_NOTE,
    )

    notes = []
    if synced_gate_left_out_by_policy_base(config):
        notes.append(UNUSED_CLOUD_GATE_NOTE)
    policy = _cloud_gate_policy(config)
    if policy is None:
        return notes
    if not policy["enabled"]:
        notes.append(CLOUD_GATE_OFF_NOTE)
        return notes
    secret_limit = policy["by_category"]["SECRET"]
    if policy["mode"] in ("category", "both") and secret_limit > 0:
        notes.append(
            f"Your Skylos Cloud policy allows {_count_noun(secret_limit, 'new secret')}, "
            "but any secret still fails the local gate."
        )
    return notes


def gate_config_notes(config):
    """Plain-text notes for gate settings that have no effect."""
    from skylos.config import printable_text
    from skylos.reporting.listing import unrecognized_rule_ids

    if not isinstance(config, dict):
        return []
    gate_config = config.get("gate", {})
    if not isinstance(gate_config, dict):
        return []
    notes = _cloud_gate_notes(config)
    relaxed = []
    if gate_config.get("fail_on_critical") is False:
        relaxed.append("fail_on_critical = false")
    for key in ("max_critical", "max_secrets"):
        if _safe_gate_limit(gate_config.get(key), 0) > 0:
            relaxed.append(f"{key} = {gate_config[key]}")
    if relaxed:
        verb = "has"
        if len(relaxed) > 1:
            verb = "have"
        notes.append(
            f"[tool.skylos.gate] {', '.join(relaxed)} {verb} no effect: any "
            "critical security issue and any secret always fail the gate."
        )
    for entry in unrecognized_rule_ids(gate_config.get("rules")):
        notes.append(
            f"[tool.skylos.gate] rules entry '{printable_text(entry)}' is not a "
            "Skylos rule ID such as SKY-D211, so it is not enforced."
        )
    return notes


def _agent_gate_reason(message):
    return f"{AGENT_GATE_PREFIX}{message}"


def _agent_file_key(path, scan_root=None):
    if not isinstance(path, (str, Path)) or not str(path):
        return None
    if not isinstance(scan_root, (str, Path)) or not str(scan_root):
        return str(Path(path))
    try:
        root = Path(scan_root).resolve()
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = root / candidate
        return candidate.resolve().relative_to(root).as_posix()
    except (OSError, RuntimeError, ValueError):
        return None


def _collect_agent_findings(findings_lists, agent_file_set, scan_root=None):
    buckets = {
        "danger": [],
        "reliability": [],
        "ai_defects": [],
        "quality": [],
        "secrets": [],
        "dead_code": [],
    }

    # Analyzer findings use absolute paths; provenance uses Git-root-relative
    # paths. Match within the provenance root, without ambiguous basename matches.
    agent_file_set = {
        key
        for path in agent_file_set
        if (key := _agent_file_key(path, scan_root)) is not None
    }
    for category, items in findings_lists.items():
        bucket = buckets.get(category)
        if bucket is None:
            continue
        for finding in items:
            if _agent_file_key(_get_finding_file(finding), scan_root) in agent_file_set:
                bucket.append(finding)

    return buckets


def _apply_agent_thresholds(reasons, agent_cfg, groups):
    agent_passed = True
    limits = dict(agent_cfg)
    limits.setdefault("max_ai_defects", agent_cfg.get("max_quality"))

    for key, noun, plural, _label in GATE_LIMITS:
        if key == "max_dependency_vulnerabilities":
            # Dependency findings point at manifests, not authored code.
            continue
        if not _append_threshold_reason(
            reasons,
            issues=groups[key],
            limit=limits.get(key),
            noun=noun,
            plural=plural,
            template=_agent_gate_reason(
                "{counted} in AI-authored files (max: {limit})"
            ),
        ):
            agent_passed = False

    return agent_passed


def _check_agent_gate(
    findings_lists, agent_file_set, agent_cfg, reasons, scan_root=None
):
    """Evaluate agent-specific thresholds against findings in AI-authored files.

    Returns False if any agent threshold is exceeded.
    """
    agent_findings = _collect_agent_findings(findings_lists, agent_file_set, scan_root)
    agent_passed = _apply_agent_thresholds(
        reasons,
        agent_cfg,
        _gate_issue_groups(**agent_findings),
    )

    min_defend = agent_cfg.get("min_defend_score")
    require_defend = agent_cfg.get("require_defend", False)
    if require_defend or isinstance(min_defend, (int, float)):
        reasons.append(
            GateReason(
                _agent_gate_reason(
                    "require_defend and min_defend_score are not supported; "
                    "this gate never reads skylos defend results"
                ),
                hint=DEFEND_GATE_HINT,
            )
        )
        agent_passed = False

    return agent_passed


def _check_strict_gate(
    *,
    dead_code,
    danger,
    reliability,
    ai_defects,
    quality,
    circular_dependencies,
    secrets,
    dependencies,
):
    issues = [
        *secrets,
        *danger,
        *dependencies,
        *reliability,
        *ai_defects,
        *quality,
        *circular_dependencies,
        *dead_code,
    ]
    if issues:
        return False, [
            GateReason(
                f"Strict mode: {_count_noun(len(issues), 'issue')} found", issues
            )
        ]
    return True, []


def _issue_severity(issue):
    if not isinstance(issue, dict):
        return ""
    return str(issue.get("severity", "")).strip().upper()


def _rule_label(rule_id):
    from skylos.rules.catalog import get_rule_name

    name = get_rule_name(rule_id, default="")
    if len(name) > 1 and name[1].islower():
        name = name[0].lower() + name[1:]
    return f"{rule_id} {name}" if name else rule_id


def _ai_defect_block_reason(blocking):
    present = {_issue_severity(issue) for issue in blocking}
    severity_label = "/".join(
        sev.lower() for sev in AI_DEFECT_SEVERITY_ORDER if sev in present
    )
    counted = _count_noun(len(blocking), f"{severity_label} AI-code issue")

    rule_ids = []
    for issue in blocking:
        rule_id = str(issue.get("rule_id") or issue.get("rule") or "").strip()
        if SAFE_RULE_ID.fullmatch(rule_id) and rule_id not in rule_ids:
            rule_ids.append(rule_id)
    details = [
        _rule_label(rule_id) for rule_id in rule_ids[:AI_DEFECT_REASON_RULE_LIMIT]
    ]
    if len(rule_ids) > AI_DEFECT_REASON_RULE_LIMIT:
        hidden = len(rule_ids) - AI_DEFECT_REASON_RULE_LIMIT
        details.append(_count_noun(hidden, "more rule"))
    # Locations stay on the issue lines, which render repository text
    # literally; the reason itself is printed as Markdown.
    return f"{counted} ({', '.join(details)})" if details else counted


def _ai_defect_policy_hint(severities):
    if tuple(severities) == DEFAULT_BLOCK_AI_DEFECT_SEVERITIES:
        return (
            "Critical AI-code issues fail the gate by default. To allow them, "
            f"set {BLOCK_AI_DEFECT_SEVERITIES_KEY} = [] under [tool.skylos.gate] "
            "in pyproject.toml."
        )
    listed = ", ".join(f'"{sev}"' for sev in severities)
    return (
        "AI-code issues at these severities fail the gate "
        f"({BLOCK_AI_DEFECT_SEVERITIES_KEY} = [{listed}] under "
        "[tool.skylos.gate]). Edit that list to change it; [] turns it off."
    )


def _apply_ai_defect_severity_block(reasons, gate_config, ai_defects, *, hint=None):
    """Fail on any AI defect at a blocking severity, whatever the count limit.

    Returns the blocking issues; an empty list means the rule passed.
    """
    severities = gate_config.get(BLOCK_AI_DEFECT_SEVERITIES_KEY, ())
    if not severities:
        return []
    blocking = [issue for issue in ai_defects if _issue_severity(issue) in severities]
    if blocking:
        reasons.append(
            GateReason(
                _ai_defect_block_reason(blocking),
                blocking,
                hint=hint or _ai_defect_policy_hint(severities),
            )
        )
    return blocking


def _apply_gate_thresholds(reasons, gate_config, groups):
    passed = True

    critical_issues = groups["max_critical"]
    critical_blocks = bool(
        gate_config.get("fail_on_critical", True) and critical_issues
    )
    if critical_blocks:
        passed = False
        reasons.append(
            GateReason(
                _count_noun(len(critical_issues), "critical security issue"),
                critical_issues,
            )
        )

    ai_defects = groups["max_ai_defects"]
    blocking_ai_defects = _apply_ai_defect_severity_block(
        reasons, gate_config, ai_defects
    )
    if blocking_ai_defects:
        passed = False

    for key, noun, plural, _label in GATE_LIMITS:
        if key == "max_critical" and critical_blocks:
            continue
        # Skip the count reason when the severity reason already lists every
        # AI defect.
        if (
            key == "max_ai_defects"
            and blocking_ai_defects
            and len(blocking_ai_defects) == len(ai_defects)
        ):
            continue
        if not _append_threshold_reason(
            reasons,
            issues=groups[key],
            limit=gate_config.get(key),
            noun=noun,
            plural=plural,
        ):
            passed = False

    return passed


def _cloud_gate_conditions(policy, found, results):
    from skylos.core.cloud_gate import cloud_gate_conditions

    return cloud_gate_conditions(
        policy, found, custom_rules=results.get("custom_rules") or []
    )


def _apply_cloud_gate(reasons, gate_config, policy, found, results):
    """Skylos Cloud's checks for a synced gate, with the local floors kept.

    Like Cloud, any critical security issue fails, the mode decides the
    limits, and the AI-code severity rule applies outside zero-new (which
    already counts every AI-code issue).
    """
    from skylos.core.cloud_gate import CLOUD_AI_DEFECT_HINT

    passed = True
    conditions = _cloud_gate_conditions(policy, found, results)
    critical, limits = conditions[0], conditions[1:]
    if critical.failed:
        passed = False
        reasons.append(
            GateReason(
                _count_noun(len(critical.issues), critical.noun),
                critical.issues,
            )
        )
    if policy["mode"] != "zero-new" and _apply_ai_defect_severity_block(
        reasons, gate_config, found["ai_defects"], hint=CLOUD_AI_DEFECT_HINT
    ):
        passed = False
    listed = {id(issue) for issue in critical.issues if critical.failed}
    for condition in limits:
        if not condition.failed:
            continue
        passed = False
        if all(id(issue) in listed for issue in condition.issues):
            continue
        _append_threshold_reason(
            reasons,
            issues=list(condition.issues),
            limit=condition.limit,
            noun=condition.noun,
            plural=condition.plural,
        )
    return passed


def _cloud_gate_summary(results, config, policy):
    from skylos.core.cloud_gate import category_label, cloud_category_scanned

    conditions = _cloud_gate_conditions(
        policy, _gate_findings(results, config), results
    )
    parts = []
    not_scanned = []
    for condition in conditions:
        category = None
        if condition.kind == "critical":
            category = "SECURITY"
        elif condition.kind in ("category", "secrets"):
            category = condition.key
        if category and not cloud_category_scanned(category, results):
            label = category_label(category)
            if label not in not_scanned:
                not_scanned.append(label)
            continue
        parts.append(
            f"{len(condition.issues)} {condition.label} (limit {condition.limit})"
        )
    if not_scanned:
        parts.append(f"{', '.join(not_scanned)} not scanned (add -a)")
    return "Skylos Cloud policy: " + ", ".join(parts)


def _gate_findings(results, config=None):
    from skylos.reporting.listing import explicit_rule_ids

    return {
        "danger": results.get("danger", []) or [],
        "reliability": results.get("reliability", []) or [],
        "ai_defects": results.get("ai_defects", []) or [],
        "quality": _quality_findings_with_custom_rules(
            results, gate_only=True, explicit_rules=explicit_rule_ids(config)
        ),
        "secrets": results.get("secrets", []) or [],
        "dependencies": results.get("dependency_vulnerabilities", []) or [],
        "dead_code": _collect_dead_code_items(results),
    }


def _analysis_incomplete_reasons(results):
    """Everything not analysed, blockers and coverage gaps alike.

    For consumers that need a complete scan (baselines, GitLab completeness).
    Exit codes and gates use :func:`_analysis_blocking_reasons`.
    """
    return [_gate_reason(reason) for reason in incomplete_analysis_reasons(results)]


def _gate_reason(reason):
    return GateReason(reason.text, hint=reason.hint, details=reason.details)


def coverage_requires_complete(config):
    """``require_complete = true`` under ``[tool.skylos.gate.coverage]``."""
    gate = config.get("gate") if isinstance(config, dict) else None
    coverage = gate.get("coverage") if isinstance(gate, dict) else None
    if not isinstance(coverage, dict):
        return False
    value = coverage.get("require_complete")
    return value is True or value == "true"


def gate_analysis_coverage(results, *, strict=False, config=None):
    """Coverage as a gate or an exit code sees it (``strict`` blocks on gaps)."""
    return analysis_coverage(
        results,
        strict=bool(strict),
        require_complete=coverage_requires_complete(config),
    )


def _analysis_blocking_reasons(results, *, strict=False, config=None):
    """Why the analysis cannot be decided (exit 2); coverage gaps excluded.

    A file that did not parse, a language without its engine or unverified
    dead-code candidates are coverage gaps: the gate is decided on what was
    checked and they are reported as warnings, unless ``strict`` or the gate
    policy requires complete coverage, or most of the code went unchecked.
    """
    coverage = gate_analysis_coverage(results, strict=strict, config=config)
    return [_gate_reason(reason) for reason in coverage.blocking]


def _coverage_gap_reasons(results, *, strict=False, config=None):
    """Coverage gaps that are warnings for this run (empty when they block)."""
    coverage = gate_analysis_coverage(results, strict=strict, config=config)
    return [_gate_reason(reason) for reason in coverage.gaps]


def sca_coverage_warnings(results):
    """Describe requested dependency checks without implying full coverage."""
    summary = results.get("analysis_summary") if isinstance(results, dict) else None
    receipt = summary.get("sca_coverage") if isinstance(summary, dict) else None
    if not isinstance(receipt, dict):
        return []
    from skylos.core.sca_coverage import unsupported_inputs_line

    status = receipt.get("status")
    not_read = unsupported_inputs_line(receipt)
    if status == "no_supported_manifests":
        if not_read:
            return [
                "SCA coverage limited: 0 dependencies queried; no dependency file "
                f"Skylos reads was found. {not_read}"
            ]
        return [
            "SCA coverage limited: no supported dependency manifests found; "
            "0 dependencies queried"
        ]
    queried = receipt.get("queried_dependency_count", 0)
    unresolved = receipt.get("unresolved_dependency_count", 0)
    if (
        isinstance(unresolved, int)
        and not isinstance(unresolved, bool)
        and unresolved > 0
    ):
        return [
            f"SCA coverage limited: {queried} dependencies queried; "
            f"{unresolved} dependencies have unresolved versions"
            + (f". {not_read}" if not_read else "")
        ]
    if not_read:
        return [f"SCA coverage limited: {queried} dependencies queried. {not_read}"]
    return []


def _coverage_count(value):
    # Match Cloud's nonnegative safe-integer accounting contract.
    if (
        type(value) in (int, float)
        and 0 <= value <= 9_007_199_254_740_991
        and value == int(value)
    ):
        return int(value)
    return None


def _sca_required_coverage_reasons(receipt, *, require_resolved):
    if not isinstance(receipt, dict) or not receipt:
        return [
            GateReason(
                "Required SCA coverage missing: dependency scan was not recorded"
            )
        ]
    reasons = []
    supported = _coverage_count(receipt.get("supported_manifest_candidate_count"))
    if supported is None or supported == 0:
        reasons.append(
            GateReason(
                "Required SCA coverage missing: no supported dependency manifests found"
            )
        )
    status = receipt.get("status")
    supported_complete = (
        status == "complete_with_unsupported_inputs"
        and receipt.get("supported_inputs_complete") is True
    )  # the unsupported files get their own reason below
    if not supported_complete and (
        not isinstance(status, str)
        or status not in ("complete", "complete_with_unresolved_versions")
        or receipt.get("complete") is not True
    ):
        reasons.append(
            GateReason(
                "Required SCA coverage incomplete: supported dependency inventory was not completed"
            )
        )
    unsupported_counts = [
        _coverage_count(receipt[key]) if key in receipt else 0
        for key in ("unsupported_manifest_count", "unsupported_lockfile_count")
    ]
    if any(count is None for count in unsupported_counts):
        reasons.append(
            GateReason(
                "Required SCA coverage incomplete: invalid unsupported inventory accounting"
            )
        )
    elif any(count > 0 for count in unsupported_counts):
        reasons.append(
            GateReason(
                "Required SCA coverage incomplete: unsupported dependency manifest or lockfile inventory"
            )
        )
    dependencies = _coverage_count(receipt.get("dependency_count"))
    queried = _coverage_count(receipt.get("queried_dependency_count"))
    if dependencies is None or queried is None:
        reasons.append(
            GateReason("Required SCA coverage incomplete: missing query accounting")
        )
    else:
        query = receipt.get("query")
        query_complete = isinstance(query, dict) and query.get("complete") is True
        if queried < dependencies or (dependencies > 0 and not query_complete):
            reasons.append(
                GateReason(
                    "Required SCA coverage incomplete: not every inventoried dependency was queried"
                )
            )
    if require_resolved:
        unresolved = _coverage_count(receipt.get("unresolved_dependency_count"))
        unresolved_lockfile = _coverage_count(
            receipt.get("unresolved_lockfile_dependency_count")
        )
        if unresolved is None or unresolved_lockfile is None:
            reasons.append(
                GateReason(
                    "Required SCA coverage incomplete: dependency version resolution was not verified"
                )
            )
        elif (
            unresolved > 0
            or unresolved_lockfile > 0
            or status == "complete_with_unresolved_versions"
        ):
            reasons.append(
                GateReason(
                    "Required SCA coverage incomplete: dependency versions must be resolved"
                )
            )
    return reasons


def _required_coverage_reasons(results, gate_config):
    """Policy rejections are distinct from operational analysis failures."""
    coverage = gate_config.get("coverage")
    if not isinstance(coverage, dict):
        return []
    required = coverage.get("required", [])
    if isinstance(required, str):
        required = [required]
    if not isinstance(required, (list, tuple, set)):
        return [GateReason("Invalid required coverage policy: expected category names")]
    required = {str(category).strip().lower() for category in required}
    require_resolved = (
        coverage.get("require_resolved_versions") is True
        or coverage.get("require_resolved_versions") == "true"
    )
    if require_resolved:
        required.add("sca")
    reasons = []
    unsupported = required - {"sca", "custom_rules"}
    if unsupported:
        reasons.append(
            GateReason(
                "Unsupported required coverage categories: "
                + ", ".join(sorted(unsupported))
            )
        )
    summary = results.get("analysis_summary")
    if "custom_rules" in required:
        rules_receipt = (
            summary.get("custom_rules_coverage") if isinstance(summary, dict) else None
        )
        if (
            not isinstance(rules_receipt, dict)
            or rules_receipt.get("status") != "complete"
        ):
            reasons.append(
                GateReason(
                    "Required custom rule coverage missing: configured rules were not checked"
                )
            )
    if "sca" not in required:
        return reasons
    receipt = summary.get("sca_coverage") if isinstance(summary, dict) else None
    reasons.extend(
        _sca_required_coverage_reasons(
            receipt,
            require_resolved=require_resolved,
        )
    )
    return reasons


def check_gate(results, config, strict=False, provenance=None):
    """
    Evaluate scan results against gate thresholds.

    Calls: skylos/core/gatekeeper.py _check_strict_gate;
        skylos/core/gatekeeper.py _apply_gate_thresholds;
        skylos/core/gatekeeper.py _check_agent_gate.

    Called from: skylos/core/gatekeeper.py _resolve_gate_check;
        skylos/cli.py _formatted_output_gate_exit_code;
        skylos/cli.py _concise_scan_exit_code;
        skylos/cli.py _strict_scan_exit_code.
    """
    results = results or {}
    config = config or {}

    gate_strict = bool(strict or (_effective_gate_config(config).get("strict")))
    reasons = _analysis_blocking_reasons(results, strict=gate_strict, config=config)
    if reasons:
        return False, reasons

    found = _gate_findings(results, config)
    gate_config = _effective_gate_config(config)
    reasons.extend(_required_coverage_reasons(results, gate_config))

    if strict:
        strict_passed, strict_reasons = _check_strict_gate(
            **found,
            circular_dependencies=results.get("circular_dependencies", []) or [],
        )
        return strict_passed and not reasons, reasons + strict_reasons

    cloud_gate = active_cloud_gate(config)
    if cloud_gate is None:
        passed = _apply_gate_thresholds(
            reasons, gate_config, _gate_issue_groups(**found)
        )
    else:
        passed = _apply_cloud_gate(reasons, gate_config, cloud_gate, found, results)
    if reasons:
        passed = False
    regressions = _security_control_regressions(results)
    if regressions:
        reasons.append(
            GateReason(
                _count_noun(len(regressions), "security control regression")
                + " (security controls must be preserved)",
                regressions,
            )
        )
        passed = False

    # Agent-aware gating: apply stricter thresholds to AI-authored files
    agent_cfg = gate_config.get("agent")
    if provenance and agent_cfg and provenance.agent_files:
        agent_passed = _check_agent_gate(
            found,
            set(provenance.agent_files),
            agent_cfg,
            reasons,
            scan_root=getattr(provenance, "scan_root", None),
        )
        if not agent_passed:
            passed = False

    return passed, reasons


def _display_path(path):
    raw = Path(str(path))
    if not raw.is_absolute():
        return str(path)
    try:
        return raw.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def _short_message(message):
    message = " ".join(str(message).split())
    if len(message) <= GATE_ISSUE_MESSAGE_CHARS:
        return message
    first_sentence = message.split(". ", 1)[0] + "."
    if len(first_sentence) <= GATE_ISSUE_MESSAGE_CHARS:
        return first_sentence
    cut = message[: GATE_ISSUE_MESSAGE_CHARS - 1]
    return (cut.rsplit(" ", 1)[0] if " " in cut else cut).rstrip(" ,;:") + "…"


def _issue_line(issue):
    if not isinstance(issue, dict):
        return str(issue)

    parts = []
    rule_id = issue.get("rule_id") or issue.get("rule")
    if rule_id:
        parts.append(str(rule_id))

    file_path = _get_finding_file(issue)
    if file_path:
        line = issue.get("line") or issue.get("line_number")
        location = _display_path(file_path)
        parts.append(f"{location}:{line}" if line else location)

    message = issue.get("message") or issue.get("msg") or issue.get("detail")
    if not message:
        name = issue.get("name") or issue.get("simple_name")
        kind = issue.get("type")
        # Dead-code items carry no rule ID or message, only a kind and a name.
        message = f"unused {kind} {name}" if kind and name and not rule_id else name
    if message:
        parts.append(_short_message(message))

    return "  ".join(parts)


def _listed_gate_issues(reason):
    """Return the issue lines to show under a reason and how many are left out."""
    issues = list(getattr(reason, "issues", ()) or ())
    shown = [_issue_line(issue) for issue in issues[:GATE_ISSUE_LIST_LIMIT]]
    return shown, len(issues) - len(shown)


def gate_reason_lines(reason):
    """The literal lines shown under one reason, then its hint (or None).

    Issue lines come first (at most GATE_ISSUE_LIST_LIMIT, then "and N
    more"), then the reason's own detail lines.
    """
    shown, more = _listed_gate_issues(reason)
    lines = list(shown)
    if more:
        lines.append(f"and {more} more")
    lines.extend(str(detail) for detail in getattr(reason, "details", ()) or ())
    return lines, getattr(reason, "hint", None)


def gate_reasons_text(reasons):
    """Plain-text reason block for stderr and other non-Rich output."""
    lines = []
    for reason in reasons or []:
        detail_lines, hint = gate_reason_lines(reason)
        lines.append(f"   • {reason}")
        lines.extend(f"       {line}" for line in detail_lines)
        if hint:
            lines.append(f"       {hint}")
    return lines


def _security_scanned(results):
    summary = results.get("analysis_summary")
    categories = summary.get("grade_categories") if isinstance(summary, dict) else None
    if isinstance(categories, list):
        return "security" in categories
    return "danger" in results or "reliability" in results


def _passed_gate_summary(results, config, *, strict):
    """Say which limits a passing scan was held to and what they let through."""
    results = results if isinstance(results, dict) else {}
    config = config if isinstance(config, dict) else {}
    cloud_gate = active_cloud_gate(config)
    if cloud_gate is not None and not strict:
        return (
            _cloud_gate_summary(results, config, cloud_gate),
            cloud_gate_scope_note(results, config),
        )
    gate_config = _effective_gate_config(config)
    groups = _gate_issue_groups(**_gate_findings(results, config))
    security_scanned = _security_scanned(results)

    parts = []
    for key, _noun, _plural, label in GATE_LIMITS:
        limit = 0 if strict else gate_config.get(key)
        count = len(groups[key])
        if not isinstance(limit, int):
            continue
        if key in SECURITY_GATE_KEYS:
            if not security_scanned:
                continue
        elif not count:
            continue
        parts.append(f"{count} {label} (limit {limit})")
    if not security_scanned:
        parts.append("security not scanned (add -a)")

    hint = None
    high_count = len(groups["max_high"])
    raw_gate = config.get("gate")
    high_configured = (
        isinstance(raw_gate, dict)
        and _safe_gate_limit(raw_gate.get("max_high"), None) is not None
    )
    if high_count and not strict and not high_configured:
        one = high_count == 1
        hint = (
            f"{_count_noun(high_count, 'high issue')} {'is' if one else 'are'} "
            "allowed by the default limits. "
            f"To block {'it' if one else 'them'}, set max_high = 0 under "
            "[tool.skylos.gate] in pyproject.toml."
        )

    return ", ".join(parts), hint


def _build_summary_rows(
    *,
    critical_count,
    high_count,
    security_count,
    reliability_count,
    ai_defects_count,
    quality_count,
    secrets_count,
    dependency_count,
    dead_code_count,
    security_regression_count=0,
):
    return [
        f"| Security (critical) | {critical_count} |",
        f"| Security (high) | {high_count} |",
        f"| Security (total) | {security_count} |",
        *(
            [f"| Security control regressions | {security_regression_count} |"]
            if security_regression_count
            else []
        ),
        f"| Reliability | {reliability_count} |",
        f"| AI defects | {ai_defects_count} |",
        f"| Quality | {quality_count} |",
        f"| Secrets | {secrets_count} |",
        f"| Dependency vulnerabilities | {dependency_count} |",
        f"| Dead Code | {dead_code_count} |",
    ]


def _append_failure_reasons(lines, reasons, *, heading="Failure Reasons"):
    if reasons:
        lines.append("")
        lines.append(f"### {heading}")
        for reason in reasons:
            lines.append(f"- {reason}")
            shown, more = _listed_gate_issues(reason)
            details = getattr(reason, "details", ()) or ()
            for detail_line in [*shown, *details]:
                # A code span keeps repository paths and messages literal.
                literal = str(detail_line).replace("`", "'")
                lines.append(f"  - `{literal}`")
            if more:
                lines.append(f"  - and {more} more")
            hint = getattr(reason, "hint", None)
            if hint:
                lines.append(f"  - {hint}")


def _summary_status(passed, *, advisory, incomplete):
    if incomplete:
        return "⚠️", "INCOMPLETE - COULD NOT DECIDE", "Incomplete Analysis"
    if advisory and not passed:
        return "⚠️", "ADVISORY - WOULD FAIL", "Advisory Reasons"
    if passed:
        return "✅", "PASSED", "Failure Reasons"
    return "❌", "FAILED", "Failure Reasons"


def build_summary_markdown(
    results, passed, reasons, *, advisory=False, incomplete=False, coverage_gaps=()
):
    results = results or {}

    danger = results.get("danger", []) or []
    reliability = results.get("reliability", []) or []
    ai_defects = results.get("ai_defects", []) or []
    quality = _quality_findings_with_custom_rules(results)
    secrets = results.get("secrets", []) or []
    dependencies = results.get("dependency_vulnerabilities", []) or []
    critical_issues, high_issues = _split_danger_by_severity(danger)
    critical_count = len(critical_issues)
    high_count = len(high_issues)
    dead_code_count = _count_dead_code_findings(results)

    icon, status, heading = _summary_status(
        passed, advisory=advisory, incomplete=incomplete
    )

    lines = [
        "## Skylos Analysis Results",
        "",
        "| Category | Count |",
        "|----------|-------|",
        *_build_summary_rows(
            critical_count=critical_count,
            high_count=high_count,
            security_count=len(danger),
            reliability_count=len(reliability),
            ai_defects_count=len(ai_defects),
            quality_count=len(quality),
            secrets_count=len(secrets),
            dependency_count=len(dependencies),
            dead_code_count=dead_code_count,
            security_regression_count=len(_security_control_regressions(results)),
        ),
        "",
        f"**Result: {icon} {status}**",
    ]
    coverage_warnings = sca_coverage_warnings(results)
    if coverage_warnings:
        lines.extend(["", "### Coverage Limitations"])
        lines.extend(f"- {warning}" for warning in coverage_warnings)
    if coverage_gaps:
        lines.extend(
            [
                "",
                "### Incomplete Coverage",
                "The result above covers the code that was analysed. Not analysed:",
            ]
        )
        for gap in coverage_gaps:
            lines.append(f"- {gap}")
            for detail in getattr(gap, "details", ()) or ():
                # A code span keeps repository paths and messages literal.
                literal = str(detail).replace("`", "'")
                lines.append(f"  - `{literal}`")
            hint = getattr(gap, "hint", None)
            if hint:
                lines.append(f"  - {hint}")
    _append_failure_reasons(lines, reasons, heading=heading)

    return "\n".join(lines)


def write_github_summary(markdown):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a") as f:
                f.write(markdown + "\n")
        except OSError as e:
            console.print(
                f"[yellow]Could not write to GITHUB_STEP_SUMMARY: {e}[/yellow]"
            )
    else:
        console.print(markdown)


def _resolve_gate_check(results, config, strict, provenance):
    try:
        return check_gate(results, config, strict=strict, provenance=provenance)
    except TypeError:
        return check_gate(results, config)


def _print_gate_reasons(console, reasons):
    for reason in reasons or []:
        console.print(f"   • {escape(str(reason))}", soft_wrap=True)
        detail_lines, hint = gate_reason_lines(reason)
        for detail_line in detail_lines:
            console.print(f"       {escape(detail_line)}", soft_wrap=True)
        if hint:
            console.print(f"       [yellow]{escape(hint)}[/yellow]", soft_wrap=True)


def _handle_passed_gate(console, command_to_run, *, details="", hint=None):
    suffix = f": {escape(details)}" if details else ""
    console.print(
        f"\n[bold green]✅ Quality Gate: PASSED[/bold green]{suffix}", soft_wrap=True
    )
    if hint:
        console.print(f"   [yellow]{escape(hint)}[/yellow]", soft_wrap=True)

    if command_to_run:
        proc = subprocess.run(command_to_run)
        return getattr(proc, "returncode", 0)

    return 0


def _handle_failed_gate(console, reasons, *, force, strict, hint=None):
    console.print("\n[bold red] Quality Gate: FAILED[/bold red]")
    _print_gate_reasons(console, reasons)
    if hint:
        console.print(f"   [yellow]{escape(hint)}[/yellow]", soft_wrap=True)

    if force:
        console.print("[yellow] Forced pass (local only)[/yellow]")
        return 0

    if strict:
        return 1

    try:
        if sys.stdout.isatty():
            if Confirm.ask("Quality gate failed. Continue anyway?"):
                start_deployment_wizard()
                return 0
            return 1
    except Exception:
        pass

    return 1


def _handle_advisory_gate(console, reasons, *, hint=None):
    console.print("\n[bold yellow]Quality Gate: ADVISORY[/bold yellow]")
    _print_gate_reasons(console, reasons)
    if hint:
        console.print(f"   [yellow]{escape(hint)}[/yellow]", soft_wrap=True)
    console.print("[yellow]Advisory mode enabled; CI is allowed to pass.[/yellow]")
    return 0


def _handle_incomplete_gate(
    console, reasons, *, verdict=INCOMPLETE_VERDICT, explanation=INCOMPLETE_EXPLANATION
):
    """Print the could-not-decide verdict, then what stopped and what to do."""
    console.print(f"\n[bold red]{escape(verdict)}[/bold red]", soft_wrap=True)
    if explanation:
        console.print(f"   [red]{escape(explanation)}[/red]", soft_wrap=True)
    _print_gate_reasons(console, reasons)
    return 2


def run_gate_interaction(
    *,
    results=None,
    result=None,
    config=None,
    strict=False,
    force=False,
    command_to_run=None,
    summary=False,
    provenance=None,
    advisory=False,
):
    """
    Runs the interactive or CI quality gate flow.

    Calls: skylos/core/gatekeeper.py _resolve_gate_check;
        skylos/core/gatekeeper.py build_summary_markdown;
        skylos/core/gatekeeper.py write_github_summary.

    Called from: skylos/commands/scan_cmd.py run_scan_command;
        skylos/cli.py run_gate_interaction.
    """
    console = Console()

    if results is None:
        results = result or {}

    config = config or {}
    gate_cfg = config.get("gate") or {}

    strict = bool(strict or gate_cfg.get("strict", False))
    for warning in sca_coverage_warnings(results):
        console.print(f"[yellow]{escape(warning)}[/yellow]", soft_wrap=True)
    incomplete_reasons = _analysis_blocking_reasons(
        results, strict=strict, config=config
    )
    coverage_gaps = (
        []
        if incomplete_reasons
        else _coverage_gap_reasons(results, strict=strict, config=config)
    )
    passed, reasons = _resolve_gate_check(results, config, strict, provenance)
    if incomplete_reasons:
        reasons = incomplete_reasons

    if summary:
        md = build_summary_markdown(
            results,
            passed,
            reasons,
            advisory=advisory and not incomplete_reasons,
            incomplete=bool(incomplete_reasons),
            coverage_gaps=coverage_gaps,
        )
        write_github_summary(md)

    if incomplete_reasons:
        return _handle_incomplete_gate(console, incomplete_reasons)

    if passed:
        details, hint = _passed_gate_summary(results, config, strict=strict)
        exit_code = _handle_passed_gate(
            console, command_to_run, details=details, hint=hint
        )
    elif advisory:
        exit_code = _handle_advisory_gate(
            console, reasons, hint=cloud_gate_scope_note(results, config, strict=strict)
        )
    else:
        exit_code = _handle_failed_gate(
            console,
            reasons,
            force=force,
            strict=strict,
            hint=cloud_gate_scope_note(results, config, strict=strict),
        )
    _print_coverage_gaps(console, coverage_gaps)
    return exit_code


def _print_coverage_gaps(console, gaps):
    from skylos.core.gate_outcome import print_coverage_warning

    print_coverage_warning(console, gaps)
