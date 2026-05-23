import argparse
from pathlib import Path


def _resolve_gate_settings(debt_args, policy) -> tuple[int | None, str | None]:
    min_score = debt_args.min_score
    if policy and policy.gate_min_score is not None and min_score is None:
        min_score = policy.gate_min_score

    fail_on_status = debt_args.fail_on_status
    if policy and policy.gate_fail_on_status and not fail_on_status:
        fail_on_status = policy.gate_fail_on_status

    return min_score, fail_on_status


def _baseline_status_counts(snapshot) -> dict[str, int]:
    counts: dict[str, int] = {}
    for hotspot in snapshot.hotspots:
        status = hotspot.baseline_status
        counts[status] = counts.get(status, 0) + 1
    return counts


def _gate_failures(snapshot, *, min_score, fail_on_status) -> list[str]:
    failures: list[str] = []
    if min_score is not None and snapshot.score.score_pct < min_score:
        failures.append(
            f"score {snapshot.score.score_pct}% is below min_score {min_score}%"
        )

    if fail_on_status:
        counts = _baseline_status_counts(snapshot)
        if fail_on_status == "new_or_worsened":
            count = counts.get("new", 0) + counts.get("worsened", 0)
            if count:
                failures.append(
                    f"{count} hotspot(s) are new or worsened versus baseline"
                )
        else:
            count = counts.get(fail_on_status, 0)
            if count:
                failures.append(
                    f"{count} hotspot(s) have baseline status {fail_on_status}"
                )

    return failures


def _record_gate_summary(snapshot, *, min_score, fail_on_status) -> list[str]:
    if min_score is None and not fail_on_status:
        return []

    failures = _gate_failures(
        snapshot,
        min_score=min_score,
        fail_on_status=fail_on_status,
    )
    snapshot.summary["gate"] = {
        "passed": not failures,
        "min_score": min_score,
        "fail_on_status": fail_on_status,
        "failures": failures,
        "status_counts": _baseline_status_counts(snapshot),
    }
    return failures


def run_debt_command(
    argv: list[str],
    *,
    console_factory,
    get_git_changed_files_func,
    resolve_llm_runtime_func,
    parse_exclude_folders_func,
    load_config_func,
    upload_debt_report_func,
) -> int:
    """
    Run the technical debt command and render, gate, history, or upload results.

    Calls: skylos/debt/__init__.py run_debt_analysis;
        skylos/debt/__init__.py load_history; skylos/debt/__init__.py append_history;
        skylos/api/__init__.py upload_debt_report.

    Called from: skylos/cli.py run_debt_command.
    """
    debt_parser = argparse.ArgumentParser(
        prog="skylos debt",
        description="Analyze technical debt hotspots in a codebase",
    )
    debt_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    debt_parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output as JSON"
    )
    debt_parser.add_argument(
        "-o", "--output", dest="output_file", help="Write output to file"
    )
    debt_parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload technical debt results to Skylos Cloud dashboard",
    )
    debt_parser.add_argument(
        "--top",
        type=int,
        default=None,
        help="Maximum number of hotspots to show in table output",
    )
    debt_parser.add_argument(
        "--changed",
        action="store_true",
        help="Limit hotspots to git-changed files",
    )
    debt_parser.add_argument(
        "--with-agent",
        action="store_true",
        help="Use an LLM to summarize the top static debt hotspots",
    )
    debt_parser.add_argument(
        "--agent-top",
        type=int,
        default=5,
        help="Maximum number of hotspots to summarize with the LLM",
    )
    debt_parser.add_argument(
        "--model",
        default="gpt-4.1",
        help="LLM model to use with --with-agent",
    )
    debt_parser.add_argument(
        "--provider",
        default=None,
        help="Optional provider override for --with-agent",
    )
    debt_parser.add_argument(
        "--base-url",
        default=None,
        help="Optional OpenAI-compatible base URL for --with-agent",
    )
    debt_parser.add_argument(
        "--baseline",
        action="store_true",
        help="Compare current debt against the saved debt baseline if present",
    )
    debt_parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Write the current debt snapshot as the baseline",
    )
    debt_parser.add_argument(
        "--history",
        action="store_true",
        help="Append the current debt summary to the history log",
    )
    debt_parser.add_argument(
        "--show-history",
        action="store_true",
        help="Show saved debt history without running a new scan",
    )
    debt_parser.add_argument(
        "--history-limit",
        type=int,
        default=None,
        help="Maximum number of saved history entries to show",
    )
    debt_parser.add_argument(
        "--policy",
        dest="policy_file",
        help="Path to skylos-debt.yaml policy file",
    )
    debt_parser.add_argument(
        "--min-score",
        type=int,
        help="Exit 1 if debt score percentage is below this value (0-100)",
    )
    debt_parser.add_argument(
        "--fail-on-status",
        choices=["new", "worsened", "new_or_worsened"],
        help="Exit 1 if hotspots matching the requested baseline status exist",
    )
    debt_parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        help="Additional folders to exclude",
    )
    debt_args = debt_parser.parse_args(argv)
    console = console_factory()

    from skylos.debt import (
        append_history as append_debt_history,
        augment_hotspots_with_advisories,
        compare_to_baseline as compare_debt_baseline,
        format_debt_history_json,
        format_debt_history_table,
        format_debt_json,
        format_debt_table,
        load_baseline as load_debt_baseline,
        load_history as load_debt_history,
        load_policy as load_debt_policy,
        run_debt_analysis,
        save_baseline as save_debt_baseline,
    )

    target = Path(debt_args.path).resolve()
    if not target.exists():
        console.print(f"[red]Error: path does not exist: {target}[/red]")
        return 1

    if debt_args.min_score is not None and not 0 <= debt_args.min_score <= 100:
        console.print(
            f"[red]Error: --min-score must be 0-100, got {debt_args.min_score}[/red]"
        )
        return 1

    if debt_args.top is not None and debt_args.top <= 0:
        console.print(f"[red]Error: --top must be > 0, got {debt_args.top}[/red]")
        return 1
    if debt_args.agent_top is not None and debt_args.agent_top <= 0:
        console.print(
            f"[red]Error: --agent-top must be > 0, got {debt_args.agent_top}[/red]"
        )
        return 1
    if debt_args.history_limit is not None and debt_args.history_limit <= 0:
        console.print(
            f"[red]Error: --history-limit must be > 0, got {debt_args.history_limit}[/red]"
        )
        return 1

    if debt_args.show_history:
        try:
            history_entries = load_debt_history(target)
        except ValueError as e:
            console.print(f"[red]Error reading debt history: {e}[/red]")
            return 1

        if debt_args.output_json:
            visible_entries = (
                history_entries[-debt_args.history_limit :]
                if debt_args.history_limit
                else history_entries
            )
            output = format_debt_history_json(visible_entries)
        else:
            output = format_debt_history_table(
                history_entries,
                limit=debt_args.history_limit,
            )

        if debt_args.output_file:
            try:
                Path(debt_args.output_file).write_text(
                    output, encoding="utf-8"
                )  # skylos: ignore[SKY-D215]
            except OSError as e:
                console.print(f"[red]Error writing output file: {e}[/red]")
                return 1
            console.print(f"[green]Output written to {debt_args.output_file}[/green]")
        elif debt_args.output_json:
            print(output)
        else:
            console.print(output)
        return 0

    exclude = set(
        parse_exclude_folders_func(
            use_defaults=True,
            config_exclude_folders=load_config_func(target).get("exclude"),
        )
    )
    if debt_args.exclude:
        exclude.update(debt_args.exclude)

    policy = None
    try:
        policy = load_debt_policy(debt_args.policy_file, start_path=target)
    except (FileNotFoundError, ValueError, ImportError) as e:
        console.print(f"[bold red]Policy error: {e}[/bold red]")
        return 1

    changed_files = None
    if debt_args.changed:
        changed_files = get_git_changed_files_func(
            target if target.is_dir() else target.parent
        )
        if not changed_files:
            console.print("[dim]No changed files found.[/dim]")
            return 0

    snapshot = run_debt_analysis(
        target,
        exclude_folders=sorted(exclude),
        changed_files=changed_files,
    )
    project_target = Path(snapshot.project).resolve()
    is_project_scope = target == project_target

    if debt_args.with_agent:
        model = debt_args.model
        provider_override = getattr(debt_args, "provider", None)
        if provider_override and model == "gpt-4.1":
            provider_default_models = {
                "anthropic": "claude-sonnet-4-20250514",
                "google": "gemini/gemini-2.0-flash",
                "mistral": "mistral/mistral-large-latest",
                "groq": "groq/llama3-70b-8192",
                "deepseek": "deepseek/deepseek-chat",
                "xai": "xai/grok-2",
                "together": "together/meta-llama/Meta-Llama-3-70B-Instruct-Turbo",
                "ollama": "ollama/llama3",
            }
            if provider_override in provider_default_models:
                model = provider_default_models[provider_override]

        provider, api_key, base_url, is_local = resolve_llm_runtime_func(
            model=model,
            provider_override=provider_override,
            base_url_override=debt_args.base_url,
            console=console,
            allow_prompt=True,
        )

        if api_key is None:
            return 1
        if api_key == "" and not is_local:
            console.print("[bad]No API key provided.[/bad]")
            return 1

        try:
            advised_count = augment_hotspots_with_advisories(
                snapshot.hotspots,
                project_root=snapshot.project,
                model=model,
                api_key=api_key,
                base_url=base_url,
                top=debt_args.agent_top,
                architecture_metrics=snapshot.summary.get("architecture_metrics") or {},
            )
            snapshot.summary["agent"] = {
                "enabled": True,
                "provider": provider,
                "model": model,
                "advised_hotspots": advised_count,
                "requested_top": debt_args.agent_top,
            }
        except Exception as e:
            console.print(f"[warn]Debt agent advisory failed: {e}[/warn]")

    if debt_args.baseline:
        try:
            baseline = load_debt_baseline(snapshot.project)
        except ValueError as e:
            console.print(f"[red]Error reading debt baseline: {e}[/red]")
            return 1
        if baseline is None:
            console.print("[dim]No debt baseline found.[/dim]")
        else:
            compare_debt_baseline(snapshot, baseline)

    if debt_args.save_baseline:
        if not is_project_scope:
            console.print(
                "[red]Error: --save-baseline only supports project-root scans. "
                f"Re-run against {project_target}[/red]"
            )
            return 1
        try:
            baseline_path = save_debt_baseline(snapshot.project, snapshot)
        except (OSError, ValueError) as e:
            console.print(f"[red]Error writing debt baseline: {e}[/red]")
            return 1
        console.print(f"[green]Debt baseline written to {baseline_path}[/green]")

    if debt_args.history:
        if not is_project_scope:
            console.print(
                "[red]Error: --history only supports project-root scans. "
                f"Re-run against {project_target}[/red]"
            )
            return 1
        try:
            history_path = append_debt_history(snapshot.project, snapshot)
        except (OSError, ValueError) as e:
            console.print(f"[red]Error writing debt history: {e}[/red]")
            return 1
        console.print(f"[dim]Debt history appended to {history_path}[/dim]")

    min_score, fail_on_status = _resolve_gate_settings(debt_args, policy)
    gate_failures = _record_gate_summary(
        snapshot,
        min_score=min_score,
        fail_on_status=fail_on_status,
    )

    if debt_args.output_json:
        output = format_debt_json(snapshot)
    else:
        top = debt_args.top
        if top is None and policy and policy.report_top is not None:
            top = policy.report_top
        if top is None:
            top = 20
        output = format_debt_table(snapshot, top=top)

    if debt_args.output_file:
        try:
            Path(debt_args.output_file).write_text(output, encoding="utf-8")
        except OSError as e:
            console.print(f"[red]Error writing output file: {e}[/red]")
            return 1
        console.print(f"[green]Output written to {debt_args.output_file}[/green]")
    elif debt_args.output_json:
        print(output)
    else:
        console.print(output)

    upload_failed = False
    if debt_args.upload:
        if not debt_args.output_json:
            from skylos.cloud.upload_manifest import (
                build_debt_manifest,
                print_upload_manifest,
            )

            print_upload_manifest(console, [build_debt_manifest()])

        upload_result = upload_debt_report_func(
            snapshot,
            quiet=debt_args.output_json,
        )
        if not upload_result.get("success"):
            upload_failed = True
            if not debt_args.output_json:
                console.print(
                    f"[red]Upload failed: {upload_result.get('error', 'Unknown')}[/red]"
                )

    return 1 if upload_failed or gate_failures else 0
