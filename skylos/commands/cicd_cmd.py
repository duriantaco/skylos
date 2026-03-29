import argparse
import json
from pathlib import Path


def _cicd_load_results(args, *, console_factory):
    if getattr(args, "input_file", None):
        try:
            with open(args.input_file) as f:
                return json.load(f), 0
        except (FileNotFoundError, json.JSONDecodeError) as e:
            console_factory().print(
                f"[bold red]Error reading {args.input_file}: {e}[/bold red]"
            )
            return None, 1

    path = getattr(args, "path", ".")
    try:
        from skylos import analyze

        return json.loads(analyze(path)), 0
    except Exception as e:
        console_factory().print(f"[bold red]Analysis failed: {e}[/bold red]")
        return None, 1


def run_cicd_command(
    argv: list[str],
    *,
    console_factory,
    load_config_func,
    run_gate_interaction_func,
    emit_github_annotations_func,
) -> int:
    cicd_parser = argparse.ArgumentParser(
        prog="skylos cicd", description="CI/CD integration for Skylos"
    )
    cicd_sub = cicd_parser.add_subparsers(dest="cicd_cmd")

    p_ci_init = cicd_sub.add_parser("init", help="Generate GitHub Actions workflow")
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
        default=["dead-code", "security", "quality", "secrets"],
        help="Analysis types to run",
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
        action="store_true",
        help="Include upload step to send scan results to the Skylos cloud dashboard. "
        "Requires SKYLOS_TOKEN in repo secrets.",
    )
    p_ci_init.add_argument(
        "--defend",
        action="store_true",
        help="Include AI Defense check step (skylos defend)",
    )
    p_ci_init.add_argument(
        "--output", "-o", default=".github/workflows/skylos.yml", help="Output path"
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
        "--diff-base",
        default=None,
        help="Base ref for provenance detection (default: auto-detect)",
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
    p_ci_rev.add_argument("--max-comments", type=int, default=25)
    p_ci_rev.add_argument("--diff-base", default="origin/main")
    p_ci_rev.add_argument("--llm-input", help="LLM agent review results JSON file")

    if not argv:
        cicd_parser.print_help()
        return 0

    cicd_args = cicd_parser.parse_args(argv)
    console = console_factory()

    if cicd_args.cicd_cmd == "init":
        from skylos.cicd.workflow import generate_workflow, write_workflow

        yaml_content = generate_workflow(
            triggers=cicd_args.triggers,
            analysis_types=cicd_args.analysis,
            python_version=cicd_args.python_version,
            use_baseline=not cicd_args.no_baseline,
            use_llm=cicd_args.llm,
            model=cicd_args.model,
            use_claude_security=cicd_args.claude_security,
            use_upload=cicd_args.upload,
            use_defend=cicd_args.defend,
        )
        write_workflow(yaml_content, cicd_args.output)
        return 0

    if cicd_args.cicd_cmd == "gate":
        results, exit_code = _cicd_load_results(cicd_args, console_factory=console_factory)
        if exit_code:
            return exit_code

        config = load_config_func(results.get("project_root", "."))

        gate_cfg = config.get("gate", {})
        prov_report = None
        if gate_cfg.get("agent"):
            try:
                from skylos.api import get_git_root
                from skylos.provenance import analyze_provenance

                git_root = get_git_root() or results.get("project_root", ".")
                diff_base = getattr(cicd_args, "diff_base", None)
                prov_report = analyze_provenance(git_root, base_ref=diff_base)
            except Exception:
                pass

        return run_gate_interaction_func(
            result=results,
            config=config,
            strict=cicd_args.strict,
            summary=cicd_args.summary,
            provenance=prov_report,
        )

    if cicd_args.cicd_cmd == "annotate":
        results, exit_code = _cicd_load_results(cicd_args, console_factory=console_factory)
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

        results, exit_code = _cicd_load_results(cicd_args, console_factory=console_factory)
        if exit_code:
            return exit_code

        llm_findings = None
        if getattr(cicd_args, "llm_input", None):
            try:
                llm_findings = json.loads(Path(cicd_args.llm_input).read_text())
            except Exception as e:
                console.print(f"[yellow]Could not read LLM results: {e}[/yellow]")

        run_pr_review(
            results,
            pr_number=cicd_args.pr,
            repo=cicd_args.repo,
            summary_only=cicd_args.summary_only,
            max_comments=cicd_args.max_comments,
            diff_base=cicd_args.diff_base,
            llm_findings=llm_findings,
        )
        return 0

    cicd_parser.print_help()
    return 0
