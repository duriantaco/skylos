import importlib  # skylos: ignore[SKY-Q502] legacy gate flow module is being split incrementally
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.prompt import Confirm, Prompt


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


class GateReason(str):
    """A gate failure reason that also carries the issues counted toward it."""

    issues = ()

    def __new__(cls, text, issues=()):
        reason = super().__new__(cls, text)
        reason.issues = list(issues)
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


def _gate_quality_findings(quality):
    return [finding for finding in quality if not _is_advisory_quality_finding(finding)]


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
    return effective


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
            _agent_gate_reason(
                "require_defend/min_defend_score set but no defense data available (run skylos defend)"
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
        *_gate_quality_findings(quality),
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

    for key, noun, plural, _label in GATE_LIMITS:
        if key == "max_critical" and critical_blocks:
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


def _gate_findings(results):
    return {
        "danger": results.get("danger", []) or [],
        "reliability": results.get("reliability", []) or [],
        "ai_defects": results.get("ai_defects", []) or [],
        "quality": _gate_quality_findings(results.get("quality", []) or []),
        "secrets": results.get("secrets", []) or [],
        "dependencies": results.get("dependency_vulnerabilities", []) or [],
        "dead_code": _collect_dead_code_items(results),
    }


def _analysis_incomplete_reasons(results):
    results = results if isinstance(results, dict) else {}
    reasons = []

    analysis_errors = results.get("analysis_errors")
    if analysis_errors:
        try:
            error_count = len(analysis_errors)
        except TypeError:
            error_count = 1
        reasons.append(
            f"Analysis incomplete: {error_count} analysis error(s) prevented a "
            "complete scan"
        )

    summary = results.get("analysis_summary")
    summary = summary if isinstance(summary, dict) else {}
    raw_languages = summary.get("incomplete_languages")
    if isinstance(raw_languages, (list, tuple, set)):
        languages = sorted(
            {
                str(language).strip()
                for language in raw_languages
                if str(language).strip()
            }
        )
    elif raw_languages:
        languages = [str(raw_languages).strip()]
    else:
        languages = []
    if languages:
        reasons.append("Incomplete language engine coverage: " + ", ".join(languages))

    sca_coverage = summary.get("sca_coverage")
    if isinstance(sca_coverage, dict):
        status = sca_coverage.get("status")
        # Coverage limitations (including unresolved manifest ranges) are not
        # operational failures; only an interrupted or unavailable scan is.
        if status in ("incomplete", "unavailable", "unknown"):
            reasons.append(
                f"Dependency vulnerability scan incomplete (status: {status})"
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

    reasons = _analysis_incomplete_reasons(results)
    if reasons:
        return False, reasons

    found = _gate_findings(results)
    gate_config = _effective_gate_config(config)

    if strict:
        return _check_strict_gate(
            **found,
            circular_dependencies=results.get("circular_dependencies", []) or [],
        )

    passed = _apply_gate_thresholds(reasons, gate_config, _gate_issue_groups(**found))

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
    gate_config = _effective_gate_config(config)
    groups = _gate_issue_groups(**_gate_findings(results))
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
):
    return [
        f"| Security (critical) | {critical_count} | {'✅' if critical_count == 0 else '❌'} |",
        f"| Security (high) | {high_count} | {'✅' if high_count <= 5 else '⚠️'} |",
        f"| Security (total) | {security_count} | {'✅' if security_count <= 10 else '⚠️'} |",
        f"| Reliability | {reliability_count} | {'✅' if reliability_count == 0 else '❌'} |",
        f"| AI defects | {ai_defects_count} | {'✅' if ai_defects_count <= 10 else '⚠️'} |",
        f"| Quality | {quality_count} | {'✅' if quality_count <= 10 else '⚠️'} |",
        f"| Secrets | {secrets_count} | {'✅' if secrets_count == 0 else '❌'} |",
        (
            f"| Dependency vulnerabilities | {dependency_count} | "
            f"{'✅' if dependency_count == 0 else '❌'} |"
        ),
        f"| Dead Code | {dead_code_count} | ℹ️ |",
    ]


def _append_failure_reasons(lines, reasons, *, heading="Failure Reasons"):
    if reasons:
        lines.append("")
        lines.append(f"### {heading}")
        for reason in reasons:
            lines.append(f"- {reason}")
            shown, more = _listed_gate_issues(reason)
            for issue_line in shown:
                # A code span keeps repository paths and messages literal.
                literal = issue_line.replace("`", "'")
                lines.append(f"  - `{literal}`")
            if more:
                lines.append(f"  - and {more} more")


def build_summary_markdown(results, passed, reasons, *, advisory=False):
    results = results or {}

    danger = results.get("danger", []) or []
    reliability = results.get("reliability", []) or []
    ai_defects = results.get("ai_defects", []) or []
    quality = results.get("quality", []) or []
    secrets = results.get("secrets", []) or []
    dependencies = results.get("dependency_vulnerabilities", []) or []
    critical_issues, high_issues = _split_danger_by_severity(danger)
    critical_count = len(critical_issues)
    high_count = len(high_issues)
    dead_code_count = _count_dead_code_findings(results)

    if advisory and not passed:
        status = "ADVISORY - WOULD FAIL"
        icon = "⚠️"
    else:
        status = "PASSED" if passed else "FAILED"
        icon = "✅" if passed else "❌"

    lines = [
        "## Skylos Analysis Results",
        "",
        "| Category | Count | Status |",
        "|----------|-------|--------|",
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
        ),
        "",
        f"**Result: {icon} {status}**",
    ]
    _append_failure_reasons(
        lines,
        reasons,
        heading="Advisory Reasons" if advisory and not passed else "Failure Reasons",
    )

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
        console.print(f"   • {escape(str(reason))}")
        shown, more = _listed_gate_issues(reason)
        for issue_line in shown:
            console.print(f"       {escape(issue_line)}", soft_wrap=True)
        if more:
            console.print(f"       and {more} more")


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


def _handle_failed_gate(console, reasons, *, force, strict):
    console.print("\n[bold red] Quality Gate: FAILED[/bold red]")
    _print_gate_reasons(console, reasons)

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


def _handle_advisory_gate(console, reasons):
    console.print("\n[bold yellow]Quality Gate: ADVISORY[/bold yellow]")
    _print_gate_reasons(console, reasons)
    console.print("[yellow]Advisory mode enabled; CI is allowed to pass.[/yellow]")
    return 0


def _handle_incomplete_gate(console, reasons):
    console.print("\n[bold red]Analysis incomplete[/bold red]")
    for reason in reasons or []:
        console.print(f"   • {escape(str(reason))}")
    console.print(
        "[red]The quality gate cannot pass because required analysis did not "
        "complete.[/red]"
    )
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
    incomplete_reasons = _analysis_incomplete_reasons(results)
    passed, reasons = _resolve_gate_check(results, config, strict, provenance)

    if summary:
        md = build_summary_markdown(
            results,
            passed,
            reasons,
            advisory=advisory and not incomplete_reasons,
        )
        write_github_summary(md)

    if incomplete_reasons:
        return _handle_incomplete_gate(console, reasons or incomplete_reasons)

    if passed:
        details, hint = _passed_gate_summary(results, config, strict=strict)
        return _handle_passed_gate(console, command_to_run, details=details, hint=hint)

    if advisory:
        return _handle_advisory_gate(console, reasons)

    return _handle_failed_gate(console, reasons, force=force, strict=strict)
