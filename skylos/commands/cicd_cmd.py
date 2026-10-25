import argparse
import dataclasses
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from skylos.core.git_safety import (
    read_only_git_command,
    read_only_git_environment,
)

from rich.markup import escape

REVIEW_SIDECAR_MAX_BYTES = 2 * 1024 * 1024


GATE_ERROR_VERDICT = "Quality Gate: ERROR — could not decide (exit 1)"


def _print_gate_error(console, message: str) -> None:
    """`cicd gate` stopped before deciding: verdict line, then the reason."""
    console.print(f"[bold red]{escape(GATE_ERROR_VERDICT)}[/bold red]", soft_wrap=True)
    console.print(f"   • {escape(message)}", soft_wrap=True)


def _report_load_error(console_factory, message: str, *, gate: bool) -> None:
    console = console_factory()
    if gate:
        _print_gate_error(console, message)
    else:
        console.print(f"[bold red]{message}[/bold red]")


def _cicd_load_results(args, *, console_factory, load_config_func, gate=False):
    if getattr(args, "input_file", None):
        try:
            with open(args.input_file) as f:
                return json.load(f), 0
        except (FileNotFoundError, json.JSONDecodeError) as e:
            _report_load_error(
                console_factory, f"Error reading {args.input_file}: {e}", gate=gate
            )
            return None, 1

    path = getattr(args, "path", ".")
    try:
        from skylos import analyze
        from skylos.config import resolve_config_file_path
        from skylos.constants import parse_exclude_folders
        from skylos.core.file_discovery import find_git_root
        from skylos.core.review_decisions import (
            apply_trusted_review_decisions,
            review_scan_requirements,
        )

        target = Path(path).expanduser().resolve()
        scan_root = target.parent if target.is_file() else target
        project_root = find_git_root(scan_root) or scan_root
        config_file = resolve_config_file_path()
        project_config = load_config_func(project_root)
        exclude_folders = parse_exclude_folders(
            config_exclude_folders=project_config.get("exclude"),
        )
        include_review_context, include_review_proofs = review_scan_requirements(
            project_root
        )
        analyze_kwargs = {
            "exclude_folders": sorted(exclude_folders),
            "enable_danger": True,
            "enable_quality": True,
            "enable_secrets": True,
        }
        if config_file is not None:
            analyze_kwargs["config_file"] = config_file
        if include_review_context:
            analyze_kwargs["include_review_context"] = True
        if include_review_proofs:
            analyze_kwargs["include_review_proofs"] = True

        previous_diff_base = os.environ.get("SKYLOS_DIFF_BASE")
        diff_base = getattr(args, "diff_base", None)
        try:
            if diff_base:
                os.environ["SKYLOS_DIFF_BASE"] = diff_base
            result = json.loads(analyze(path, **analyze_kwargs))
            return apply_trusted_review_decisions(result, project_root), 0
        finally:
            if diff_base:
                if previous_diff_base is None:
                    os.environ.pop("SKYLOS_DIFF_BASE", None)
                else:
                    os.environ["SKYLOS_DIFF_BASE"] = previous_diff_base
    except Exception as e:
        _report_load_error(console_factory, f"Analysis failed: {e}", gate=gate)
        return None, 1


def _git_output(*args: str) -> str:
    try:
        return (
            subprocess.check_output(
                read_only_git_command(list(args)),
                stderr=subprocess.DEVNULL,
                timeout=10,
                env=read_only_git_environment(),
            )
            .decode()
            .strip()
        )
    except (subprocess.SubprocessError, OSError, UnicodeDecodeError):
        return ""


def _repo_root() -> Path:
    root = _git_output("rev-parse", "--show-toplevel")
    return Path(root) if root else Path.cwd()


def _default_workflow_output() -> str:
    return str(_repo_root() / ".github" / "workflows" / "skylos.yml")


def _detect_default_branch() -> str | None:
    """The branch origin/HEAD points to, as recorded by `git clone`."""
    ref = _git_output("symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
    branch = ref.removeprefix("origin/") if ref.startswith("origin/") else ""
    from skylos.cicd.workflow import is_valid_branch_name

    return branch if is_valid_branch_name(branch) else None


def _read_review_sidecar_json(raw_path: str, *, label: str) -> dict | list:
    path = _review_sidecar_path(raw_path, label=label)
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        raise ValueError(f"{label} must not be a symlink")
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a regular file")

    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow

    fd = os.open(  # skylos: ignore[SKY-D215] bounded sidecar path with no-follow checks
        path, flags
    )
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if st.st_size > REVIEW_SIDECAR_MAX_BYTES:
            raise ValueError(f"{label} is too large")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(REVIEW_SIDECAR_MAX_BYTES + 1)
        if len(data) > REVIEW_SIDECAR_MAX_BYTES:
            raise ValueError(f"{label} is too large")
    finally:
        if fd >= 0:
            os.close(fd)

    return json.loads(data.decode("utf-8"))


def _review_sidecar_path(raw_path: str, *, label: str) -> Path:
    raw = str(raw_path or "")
    if not raw or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ValueError(f"{label} must be a valid sidecar path")

    path = Path(raw)
    if not path.is_absolute():
        if path.name != raw:
            raise ValueError(f"{label} must be a filename in the current directory")
        return path

    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise ValueError(f"{label} must be a filename in the current directory")

    runner_root = Path(runner_temp).resolve()
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(runner_root)
    except ValueError as exc:
        raise ValueError(f"{label} must be inside RUNNER_TEMP") from exc
    return path


def _run_cicd_init(cicd_args, console) -> int:
    """
    Write the workflow for `skylos cicd init` and print the next steps.

    Calls: skylos/cicd/init_setup.py detect_done_setup;
        skylos/cicd/workflow.py generate_workflow;
        skylos/cicd/init_setup.py print_init_next_steps.

    Called from: skylos/commands/cicd_cmd.py run_cicd_command.
    """
    from skylos.cicd.init_setup import detect_done_setup, print_init_next_steps
    from skylos.cicd.workflow import (
        FALLBACK_DEFAULT_BRANCHES,
        display_path,
        generate_workflow,
        write_workflow,
    )

    selected = _select_init_platform(cicd_args, console)
    if selected is None:
        return 1
    platform, platform_name = selected
    if platform.key != "github":
        return _run_platform_init(cicd_args, console, platform, platform_name)
    use_upload = cicd_args.upload is not False

    done_setup = detect_done_setup(_repo_root())
    use_done = done_setup.enabled if cicd_args.done is None else cicd_args.done
    default_branch = cicd_args.default_branch or _detect_default_branch()
    try:
        yaml_content = generate_workflow(
            triggers=cicd_args.triggers,
            analysis_types=cicd_args.analysis,
            python_version=cicd_args.python_version,
            use_baseline=not cicd_args.no_baseline,
            use_llm=cicd_args.llm,
            model=cicd_args.model,
            use_claude_security=cicd_args.claude_security,
            use_upload=use_upload,
            use_defend=cicd_args.defend,
            advisory_gate=cicd_args.advisory_gate,
            scan_path=cicd_args.scan_path,
            use_done=use_done,
            done_install_commands=done_setup.install_commands,
            default_branch=default_branch,
            use_risk_review=cicd_args.risk_review,
        )
    except ValueError as e:
        console.print(f"[bold red]Invalid workflow option: {e}[/bold red]")
        return 1
    output_path = cicd_args.output or _default_workflow_output()
    try:
        existing = _existing_workflow_text(output_path)
        if existing == yaml_content:
            console.print(
                f"[green]Workflow already up to date: {escape(display_path(output_path))}[/green]",
                soft_wrap=True,
            )
        else:
            if (
                existing is not None
                and not cicd_args.force
                and not _confirm_workflow_replace(console, output_path)
            ):
                return 1
            write_workflow(
                yaml_content, output_path, out=console, expected_existing=existing
            )
    except OSError as exc:
        console.print(
            f"[bold red]Could not write workflow: {escape(str(exc))}[/bold red]",
            soft_wrap=True,
        )
        return 1
    if use_done and not done_setup.enabled:
        done_setup = dataclasses.replace(
            done_setup, enabled=True, reason="added with --done"
        )
    elif not use_done:
        done_setup = dataclasses.replace(done_setup, enabled=False)
    print_init_next_steps(
        console,
        output_path=output_path,
        triggers=cicd_args.triggers,
        upload=use_upload,
        done_requested=cicd_args.done,
        done_setup=done_setup,
        push_branches=(
            (default_branch,) if default_branch else FALLBACK_DEFAULT_BRANCHES
        ),
        branch_detected=bool(default_branch),
        risk_review=cicd_args.risk_review and "pull_request" in cicd_args.triggers,
    )
    return 0


_GITHUB_ONLY_INIT_FLAGS = (
    ("llm", "--llm"),
    ("model", "--model"),
    ("claude_security", "--claude-security"),
    ("defend", "--defend"),
    ("risk_review", "--risk-review"),
    ("advisory_gate", "--advisory-gate"),
    ("force", "--force"),
)


def _select_init_platform(cicd_args, console):
    """The CI `skylos cicd init` sets up, and the name to show for it.

    Returns None when the repository has several CIs and --ci was not given.
    """
    from skylos.cicd.platforms import (
        BY_KEY,
        OTHER,
        choose_platform,
        platform_from_output,
    )
    from skylos.cicd.workflow import display_path

    if cicd_args.ci == OTHER.key:
        return OTHER, "your CI"
    if cicd_args.ci:
        platform = BY_KEY[cicd_args.ci]
        return platform, platform.name
    if cicd_args.output:
        platform = platform_from_output(cicd_args.output)
        return platform, platform.name
    choice = choose_platform(_repo_root(), _git_output("remote", "get-url", "origin"))
    if choice.platform is None:
        listed = ", ".join(
            f"{f.platform.name} ({display_path(f.path)})" for f in choice.found
        )
        keys = [f.platform.key for f in choice.found if f.platform.config]
        console.print(
            f"[yellow]Found more than one CI: {escape(listed)}.[/yellow]",
            soft_wrap=True,
        )
        console.print(
            "Nothing was written. Pick one with --ci, e.g. "
            f"skylos cicd init --ci {keys[0]}",
            soft_wrap=True,
        )
        return None
    platform = choice.platform
    name = platform.name
    if platform.key == OTHER.key:
        name = choice.found[0].platform.name
    others = [f for f in choice.found if f.platform.key != platform.key]
    if choice.reason and (platform.key != "github" or others):
        console.print(
            f"Setting up {escape(name)} ({escape(choice.reason)}).", soft_wrap=True
        )
    for found in others:
        key = OTHER.key
        if found.platform.config:
            key = found.platform.key
        console.print(
            f"[dim]Also found {escape(display_path(found.path))} "
            f"({escape(found.platform.name)}); for it run: "
            f"skylos cicd init --ci {key}[/dim]",
            soft_wrap=True,
        )
    return platform, name


def _github_only_flags(cicd_args) -> list[str]:
    flags = [flag for attr, flag in _GITHUB_ONLY_INIT_FLAGS if getattr(cicd_args, attr)]
    if cicd_args.triggers != ["pull_request", "push"]:
        flags.insert(0, "--triggers")
    if cicd_args.done is not None:
        flags.append("--done")
    return flags


def _run_platform_init(cicd_args, console, platform, platform_name) -> int:
    """Write or print the pull request gate for a CI other than GitHub Actions.

    A new CI file is written; an existing one is never edited, the block to
    add is printed instead.

    Calls: skylos/cicd/platforms.py render;
        skylos/cicd/platforms.py print_platform_next_steps.

    Called from: skylos/commands/cicd_cmd.py _run_cicd_init.
    """
    from skylos.cicd.platforms import Settings, print_platform_next_steps, render
    from skylos.cicd.workflow import display_path, write_workflow

    settings = Settings(
        python_version=cicd_args.python_version,
        analysis_types=tuple(cicd_args.analysis),
        use_baseline=not cicd_args.no_baseline,
        scan_path=cicd_args.scan_path,
        default_branch=cicd_args.default_branch or _detect_default_branch(),
    )
    try:
        rendered = render(platform, settings)
    except ValueError as e:
        console.print(
            f"[bold red]Invalid workflow option: {escape(str(e))}[/bold red]"
        )
        return 1
    ignored = _github_only_flags(cicd_args)
    if ignored:
        console.print(
            f"[yellow]Not used for {escape(platform_name)} (GitHub Actions only): "
            f"{', '.join(ignored)}[/yellow]",
            soft_wrap=True,
        )
    written = None
    if platform.config:
        output_path = cicd_args.output or str(_repo_root() / platform.config)
        shown = escape(display_path(output_path))
        try:
            existing = _existing_workflow_text(output_path)
            if existing is None:
                write_workflow(
                    rendered.full, output_path, out=console, expected_existing=None
                )
                written = output_path
            elif existing == rendered.full:
                console.print(
                    f"[green]Already up to date: {shown}[/green]", soft_wrap=True
                )
                written = output_path
            else:
                note = "Skylos does not edit it."
                if "skylos" in existing.lower():
                    note = "It already mentions skylos; compare it with the block below."
                console.print(
                    f"[yellow]{shown} already exists. {note}[/yellow]", soft_wrap=True
                )
        except OSError as exc:
            console.print(
                f"[bold red]Could not write {shown}: {escape(str(exc))}[/bold red]",
                soft_wrap=True,
            )
            return 1
    if written is None:
        console.print()
        console.print(rendered.where, markup=False, highlight=False, soft_wrap=True)
        console.print()
        console.print(rendered.snippet, markup=False, highlight=False, soft_wrap=True)
    print_platform_next_steps(
        console,
        platform=platform,
        name=platform_name,
        rendered=rendered,
        written=written,
        upload_requested=cicd_args.upload is True,
    )
    return 0


def _existing_workflow_text(output_path: str) -> str | None:
    from skylos.cicd.workflow import read_workflow_text

    return read_workflow_text(output_path)


def _confirm_workflow_replace(console, output_path: str) -> bool:
    """Ask before replacing a workflow someone may have written by hand."""
    from skylos.cicd.workflow import display_path, workflow_backup_path

    shown = escape(display_path(output_path))
    backup = escape(display_path(workflow_backup_path(Path(output_path))))
    console.print(
        f"[yellow]{shown} already exists and is different from the workflow "
        "Skylos would write.[/yellow]",
        soft_wrap=True,
    )
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print(
            "Nothing was written. To replace it, run the same command with "
            f"--force; the old file is kept as {backup}.",
            soft_wrap=True,
        )
        return False
    try:
        answer = console.input(
            f"Replace it? The old file is kept as {backup}. {escape('[y/N]')} "
        )
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if str(answer).strip().lower() in {"y", "yes"}:
        return True
    console.print("Kept the existing workflow; nothing was written.")
    return False


def run_cicd_command(
    argv: list[str],
    *,
    console_factory,
    load_config_func,
    run_gate_interaction_func,
    emit_github_annotations_func,
) -> int:
    """
    Run the CI/CD subcommands for workflow generation, gates, annotations, and reviews.

    Calls: skylos/commands/cicd_cmd.py _run_cicd_init;
        skylos/core/gatekeeper.py run_gate_interaction;
        skylos/cicd/review.py run_pr_review.

    Called from: skylos/cli.py run_cicd_command.
    """
    cicd_parser = argparse.ArgumentParser(
        prog="skylos cicd", description="CI/CD integration for Skylos"
    )
    cicd_sub = cicd_parser.add_subparsers(dest="cicd_cmd")

    p_ci_init = cicd_sub.add_parser(
        "init",
        help="Set up a pull request gate for your CI",
        description=(
            "Set up a Skylos pull request gate for the CI this repository uses "
            "(GitHub Actions, GitLab CI, Jenkins, Bitbucket Pipelines, Azure "
            "Pipelines or CircleCI; other CIs get the commands to add). On "
            "GitHub it writes .github/workflows/skylos.yml: a pull request gate "
            "(changed-line scan, PR comments, `skylos done` when your tests can "
            "run) and a default-branch upload to Skylos Cloud through GitHub "
            "OIDC. Other CIs get a changed-line gate; an existing CI file is "
            "never edited, Skylos prints the block to add instead."
        ),
    )
    from skylos.cicd.platforms import CI_CHOICES

    p_ci_init.add_argument(
        "--ci",
        choices=CI_CHOICES,
        default=None,
        help=(
            "CI to set up (default: detected from the repository's CI files, "
            "then from origin's host, else github)"
        ),
    )
    p_ci_init.add_argument("--python-version", default="3.12")
    p_ci_init.add_argument(
        "--triggers",
        nargs="+",
        default=["pull_request", "push"],
        help="GitHub Actions triggers",
    )
    p_ci_init.add_argument(
        "--analysis",
        nargs="+",
        default=[
            "dead-code",
            "security",
            "quality",
            "ai-defects",
            "secrets",
            "dependency",
        ],
        help=(
            "Analysis types to run: dead-code, security, quality, ai-defects, "
            "secrets, dependency"
        ),
    )
    p_ci_init.add_argument("--no-baseline", action="store_true")
    p_ci_init.add_argument(
        "--llm", action="store_true", help="Include LLM-enhanced analysis"
    )
    p_ci_init.add_argument("--model", default=None, help="LLM model for agent mode")
    p_ci_init.add_argument(
        "--claude-security",
        action="store_true",
        help="Add parallel Claude Code Security scan job",
    )
    p_ci_init.add_argument(
        "--upload",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Upload full scans from default-branch pushes to Skylos Cloud with "
            "GitHub OIDC; no API key secret. Needs the Skylos GitHub App on the "
            "repository (default: on for GitHub Actions; --no-upload for "
            "local-only CI)"
        ),
    )
    p_ci_init.add_argument(
        "--done",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Add the Skylos Done job, which runs your tests on pull requests "
            "(default: only when a pytest project or [tool.skylos.done] "
            "test_command is found)"
        ),
    )
    p_ci_init.add_argument(
        "--default-branch",
        default=None,
        help="Branch whose pushes upload (default: origin/HEAD, else main or master)",
    )
    p_ci_init.add_argument(
        "--defend",
        action="store_true",
        help="Include AI Defense check step (skylos defend)",
    )
    p_ci_init.add_argument(
        "--risk-review",
        action="store_true",
        help=(
            'Add the "Skylos risk review" job: it fails while a pull request has '
            "risks (deleted tests, removed auth, new dependencies, weakened CI, "
            "...) that no person with write access has approved; bot approvals "
            "do not count. Also runs when a review is submitted or dismissed"
        ),
    )
    p_ci_init.add_argument(
        "--advisory-gate",
        action="store_true",
        help="Report gate failures but let the generated CI job pass.",
    )
    p_ci_init.add_argument(
        "--scan-path",
        default=".",
        help="Project path to scan inside the repository, e.g. apps/api",
    )
    p_ci_init.add_argument(
        "--output",
        "-o",
        default=None,
        help=(
            "Output path (default: the CI's own file at the repo root, e.g. "
            ".github/workflows/skylos.yml or Jenkinsfile)"
        ),
    )
    p_ci_init.add_argument(
        "--force",
        action="store_true",
        help=(
            "Replace an existing workflow without asking; the old file is kept "
            "next to it as <name>.bak"
        ),
    )

    p_ci_gate = cicd_sub.add_parser("gate", help="Check quality gate (CI exit code)")
    p_ci_gate.add_argument("path", nargs="?", default=".")
    p_ci_gate.add_argument(
        "--input", "-i", dest="input_file", help="Read results from JSON file"
    )
    p_ci_gate.add_argument("--strict", action="store_true")
    p_ci_gate.add_argument(
        "--summary",
        action="store_true",
        help="Write markdown to $GITHUB_STEP_SUMMARY",
    )
    p_ci_gate.add_argument(
        "--advisory",
        action="store_true",
        help="Report gate failures but return exit code 0 so CI can notify without blocking.",
    )
    p_ci_gate.add_argument(
        "--diff-base",
        default=None,
        help="Compare security controls and use policy from this base ref (default: auto-detect in PR CI)",
    )

    p_ci_ann = cicd_sub.add_parser("annotate", help="Emit GitHub Actions annotations")
    p_ci_ann.add_argument("path", nargs="?", default=".")
    p_ci_ann.add_argument(
        "--input", "-i", dest="input_file", help="Read results from JSON file"
    )
    p_ci_ann.add_argument("--max", type=int, default=50, dest="max_annotations")
    p_ci_ann.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity filter",
    )

    p_ci_rev = cicd_sub.add_parser("review", help="Post PR review comments via gh CLI")
    p_ci_rev.add_argument("path", nargs="?", default=".")
    p_ci_rev.add_argument(
        "--input", "-i", dest="input_file", help="Read results from JSON file"
    )
    p_ci_rev.add_argument("--pr", type=int, help="PR number (auto-detect in CI)")
    p_ci_rev.add_argument("--repo", help="owner/repo (auto-detect in CI)")
    p_ci_rev.add_argument("--summary-only", action="store_true")
    max_comments_help = (
        "Most inline comments on the pull request (default 25). Findings that "
        "already have one count toward it; later pushes comment only on new "
        "findings and edit the one summary comment"
    )
    p_ci_rev.add_argument("--max-comments", type=int, default=25, help=max_comments_help)
    p_ci_rev.add_argument("--diff-base", default="origin/main")
    p_ci_rev.add_argument("--llm-input", help="LLM agent review results JSON file")
    p_ci_rev.add_argument(
        "--defense-input",
        help=(
            "AI defense sidecar JSON from `skylos defend` "
            "(filename in the current directory or path under RUNNER_TEMP)"
        ),
    )
    p_ci_rev.add_argument(
        "--evidence-cards",
        action="store_true",
        help="Format PR comments with Proven, Likely, or Speculative evidence labels.",
    )

    from skylos.commands.risk_review_cmd import add_risk_review_parser
    from skylos.cicd.agent_review import add_agent_review_parser

    add_risk_review_parser(cicd_sub)
    add_agent_review_parser(cicd_sub)

    if not argv:
        cicd_parser.print_help()
        return 0

    cicd_args = cicd_parser.parse_args(argv)
    console = console_factory()

    if cicd_args.cicd_cmd == "init":
        return _run_cicd_init(cicd_args, console)

    if cicd_args.cicd_cmd == "agent-review":
        from skylos.cicd.agent_review import run_agent_review_command

        return run_agent_review_command(cicd_args, console=console)

    if cicd_args.cicd_cmd == "risk-review":
        from skylos.commands.risk_review_cmd import run_risk_review

        return run_risk_review(cicd_args, console=console)

    if cicd_args.cicd_cmd == "gate":
        from skylos.cicd.policy import base_policy_context
        from skylos.core.ci_env import github_or_ci_base_ref
        from skylos.security.contracts import resolve_diff_base_ref

        # CI supplies the comparison ref; repository TOML/YAML cannot choose it.
        cicd_args.diff_base = cicd_args.diff_base or resolve_diff_base_ref(
            cicd_args.path
        )
        if not cicd_args.diff_base:
            ci_base = github_or_ci_base_ref()
            if ci_base:
                cicd_args.diff_base = (
                    ci_base if ci_base.startswith("origin/") else f"origin/{ci_base}"
                )
        try:
            with base_policy_context(cicd_args.path, cicd_args.diff_base):
                results, exit_code = _cicd_load_results(
                    cicd_args,
                    console_factory=console_factory,
                    load_config_func=load_config_func,
                    gate=True,
                )
                if exit_code:
                    return exit_code
                config_path = (
                    cicd_args.path
                    if cicd_args.diff_base
                    else results.get("project_root", ".")
                )
                config = load_config_func(config_path)
                if cicd_args.input_file and cicd_args.diff_base:
                    from skylos.security.regression_gate import (
                        recheck_control_regressions,
                    )

                    results = recheck_control_regressions(
                        results, cicd_args.path, config
                    )
                gate_cfg = config.get("gate", {})
                prov_report = None
                if gate_cfg.get("agent"):
                    try:
                        from skylos.api import get_git_root
                        from skylos.reporting.provenance import analyze_provenance

                        git_root = get_git_root() or results.get("project_root", ".")
                        prov_report = analyze_provenance(
                            git_root, base_ref=cicd_args.diff_base
                        )
                    except Exception:
                        pass
                if cicd_args.diff_base:
                    from skylos.cicd.scope_receipt import report_scope

                    # An empty scope still reports: a passing check with a
                    # receipt, never a skipped or missing one.
                    report_scope(
                        cicd_args.path,
                        cicd_args.diff_base,
                        console=console,
                        summary=cicd_args.summary,
                    )
                return run_gate_interaction_func(
                    result=results,
                    config=config,
                    strict=cicd_args.strict,
                    summary=cicd_args.summary,
                    provenance=prov_report,
                    advisory=cicd_args.advisory,
                )
        except Exception as exc:
            _print_gate_error(console, f"PR gate failed: {exc}")
            return 1

    if cicd_args.cicd_cmd == "annotate":
        results, exit_code = _cicd_load_results(
            cicd_args,
            console_factory=console_factory,
            load_config_func=load_config_func,
        )
        if exit_code:
            return exit_code

        emit_github_annotations_func(
            results,
            max_annotations=cicd_args.max_annotations,
            severity_filter=cicd_args.severity,
        )
        return 0

    if cicd_args.cicd_cmd == "review":
        from skylos.cicd.review import run_pr_review

        results, exit_code = _cicd_load_results(
            cicd_args,
            console_factory=console_factory,
            load_config_func=load_config_func,
        )
        if exit_code:
            return exit_code

        llm_findings = None
        if getattr(cicd_args, "llm_input", None):
            try:
                llm_findings = json.loads(Path(cicd_args.llm_input).read_text())
            except Exception as e:
                console.print(f"[yellow]Could not read LLM results: {e}[/yellow]")

        defense_report = None
        if getattr(cicd_args, "defense_input", None):
            try:
                defense_report = _read_review_sidecar_json(
                    cicd_args.defense_input,
                    label="--defense-input",
                )
            except Exception as e:
                console.print(f"[yellow]Could not read defense results: {e}[/yellow]")

        run_pr_review(
            results,
            pr_number=cicd_args.pr,
            repo=cicd_args.repo,
            summary_only=cicd_args.summary_only,
            max_comments=cicd_args.max_comments,
            diff_base=cicd_args.diff_base,
            llm_findings=llm_findings,
            defense_report=defense_report,
            evidence_cards=cicd_args.evidence_cards,
        )
        return 0

    cicd_parser.print_help()
    return 0
