from __future__ import annotations

from types import ModuleType
from typing import Sequence


def run_scan_command(argv: Sequence[str], *, cli_module: ModuleType) -> None:
    INTERACTIVE_AVAILABLE = cli_module.INTERACTIVE_AVAILABLE
    Panel = cli_module.Panel
    Progress = cli_module.Progress
    Rule = cli_module.Rule
    SpinnerColumn = cli_module.SpinnerColumn
    TextColumn = cli_module.TextColumn
    _apply_display_filters = cli_module._apply_display_filters
    _attach_upload_project_context = cli_module._attach_upload_project_context
    _build_main_parser = cli_module._build_main_parser
    _build_main_scan_context = cli_module._build_main_scan_context
    _concise_scan_exit_code = cli_module._concise_scan_exit_code
    _detect_link_file = cli_module._detect_link_file
    _emit_github_annotations = cli_module._emit_github_annotations
    _format_concise_results = cli_module._format_concise_results
    _formatted_output_gate_exit_code = cli_module._formatted_output_gate_exit_code
    _generate_llm_report = cli_module._generate_llm_report
    _get_sarif_exporter_class = cli_module._get_sarif_exporter_class
    _is_ci = cli_module._is_ci
    _is_main_machine_output = cli_module._is_main_machine_output
    _is_tty = cli_module._is_tty
    _parse_main_cli_args = cli_module._parse_main_cli_args
    _print_main_scan_banner = cli_module._print_main_scan_banner
    _print_main_upload_manifest = cli_module._print_main_upload_manifest
    _print_upload_cta = cli_module._print_upload_cta
    _print_upload_destination = cli_module._print_upload_destination
    _render_upload_failure = cli_module._render_upload_failure
    _run_pre_analysis_steps = cli_module._run_pre_analysis_steps
    _strict_scan_exit_code = cli_module._strict_scan_exit_code
    _write_rich_report_output = cli_module._write_rich_report_output
    comment_out_unused_function = cli_module.comment_out_unused_function
    comment_out_unused_import = cli_module.comment_out_unused_import
    inquirer = cli_module.inquirer
    interactive_selection = cli_module.interactive_selection
    json = cli_module.json
    logging = cli_module.logging
    os = cli_module.os
    pathlib = cli_module.pathlib
    print_badge = cli_module.print_badge
    remove_unused_function = cli_module.remove_unused_function
    remove_unused_import = cli_module.remove_unused_import
    render_results = cli_module.render_results
    run_analyze = cli_module.run_analyze
    run_gate_interaction = cli_module.run_gate_interaction
    subprocess = cli_module.subprocess
    sys = cli_module.sys
    upload_report = cli_module.upload_report

    parser = _build_main_parser()
    args = _parse_main_cli_args(parser, argv)
    args._explicit_upload_requested = bool(getattr(args, "upload", False))
    context = _build_main_scan_context(args)
    project_root = context.project_root
    logger = context.logger
    console = context.console
    final_exclude_folders = context.final_exclude_folders
    config = context.config
    machine_output = _is_main_machine_output(args)

    if _print_main_scan_banner(args, console, final_exclude_folders):
        return

    pre_analysis = _run_pre_analysis_steps(args, project_root, console)
    pytest_fixtures_ok = pre_analysis.pytest_fixtures_ok
    custom_rules_data = pre_analysis.custom_rules_data
    changed_files = pre_analysis.changed_files
    trace_file = pre_analysis.trace_file

    try:
        scan_path = args.path if len(args.path) > 1 else args.path[0]

        def run_main_analysis(progress_callback=None):
            return run_analyze(
                scan_path,
                conf=args.confidence,
                enable_secrets=bool(args.secrets),
                enable_danger=bool(args.danger),
                enable_quality=bool(args.quality),
                exclude_folders=list(final_exclude_folders),
                progress_callback=progress_callback,
                custom_rules_data=custom_rules_data,
                changed_files=changed_files,
                grep_verify=not getattr(args, "no_grep_verify", False),
                enable_sca=bool(args.sca),
                trace_file=trace_file,
            )

        if machine_output:
            analyzer_logger = logging.getLogger("Skylos")
            analyzer_logger_level = analyzer_logger.level
            analyzer_logger.setLevel(logging.WARNING)
            try:
                result_json = run_main_analysis()
            finally:
                analyzer_logger.setLevel(analyzer_logger_level)
        else:
            with Progress(
                SpinnerColumn(style="brand"),
                TextColumn("[brand]Skylos[/brand] {task.description}"),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task("analyzing..", total=None)

                def update_progress(current, total, file):
                    progress.update(
                        task, description=f"[{current}/{total}] {file.name}"
                    )

                result_json = run_main_analysis(update_progress)

        result = json.loads(result_json)

        if getattr(args, "sca", False) and "dependency_vulnerabilities" not in result:
            try:
                from skylos.rules.sca.vulnerability_scanner import scan_dependencies

                sca_findings = scan_dependencies(project_root)
                if sca_findings:
                    try:
                        from skylos.rules.sca.reachability import (
                            enrich_with_reachability,
                        )

                        sca_findings = enrich_with_reachability(
                            sca_findings, project_root
                        )
                    except (ImportError, OSError, RuntimeError, ValueError) as exc:
                        logger.debug("SCA reachability enrichment failed: %s", exc)
                    result["dependency_vulnerabilities"] = sca_findings
                    result.setdefault("analysis_summary", {})["sca_count"] = len(
                        sca_findings
                    )
            except Exception as e:
                if args.verbose:
                    console.print(f"[warn]SCA scan error: {e}[/warn]")

        if args.baseline:
            from skylos.core.baseline import load_baseline, filter_new_findings

            baseline = load_baseline(project_root)
            if baseline is None:
                console.print(
                    "[warn]No baseline found. Run 'skylos baseline .' first.[/warn]"
                )
            else:
                result = filter_new_findings(result, baseline)
                result_json = json.dumps(result)

        if changed_files is not None:
            for category in [
                "unused_functions",
                "unused_imports",
                "unused_classes",
                "unused_variables",
                "unused_parameters",
                "unused_files",
                "danger",
                "quality",
                "secrets",
                "custom_rules",
            ]:
                items = result.get(category, [])
                if items:
                    result[category] = [
                        item
                        for item in items
                        if str((project_root / item.get("file", "")).resolve())
                        in changed_files
                    ]

        if getattr(args, "diff", None):
            from skylos.cicd.review import (
                get_changed_line_ranges,
                filter_findings_to_diff,
            )

            base_ref = args.diff
            if base_ref == "auto":
                base_ref = os.environ.get("GITHUB_BASE_REF", "origin/main")
                if base_ref and not base_ref.startswith("origin/"):
                    base_ref = f"origin/{base_ref}"

            changed_ranges = get_changed_line_ranges(base_ref)
            if changed_ranges:
                for category in [
                    "unused_functions",
                    "unused_imports",
                    "unused_classes",
                    "unused_variables",
                    "unused_parameters",
                    "unused_files",
                    "danger",
                    "quality",
                    "secrets",
                    "custom_rules",
                ]:
                    items = result.get(category, [])
                    if items:
                        result[category] = filter_findings_to_diff(
                            items, changed_ranges
                        )
                result_json = json.dumps(result)
                if not machine_output:
                    console.print(
                        f"[brand]--diff:[/brand] filtered to {len(changed_ranges)} changed line ranges "
                        f"from {base_ref}"
                    )
            elif not machine_output:
                console.print(
                    f"[warn]--diff: no changed lines found vs {base_ref}[/warn]"
                )

        if args.pytest_fixtures:
            report_path = project_root / ".skylos_unused_fixtures.json"

            if pytest_fixtures_ok is False:
                result["unused_fixtures"] = []
                result["unused_fixtures_counts"] = {}
            elif report_path.exists():
                try:
                    data = json.loads(report_path.read_text(encoding="utf-8"))
                    fixtures = data.get("unused_fixtures", []) or []
                    counts = data.get("counts", {}) or {}

                    p = pathlib.Path(args.path[0]).resolve()
                    if len(args.path) == 1 and p.is_file():
                        allowed = {str(p)}
                        allowed.add(str(p.parent / "conftest.py"))
                        fixtures = [
                            f for f in fixtures if str(f.get("file")) in allowed
                        ]

                    for f in fixtures:
                        f.setdefault("confidence", 100)

                    result["unused_fixtures"] = fixtures
                    result["unused_fixtures_counts"] = counts

                except Exception as e:
                    result["unused_fixtures"] = []
                    result["unused_fixtures_counts"] = {}
                    if args.verbose and not machine_output:
                        console.print(
                            f"[warn]Could not read unused fixture report: {e}[/warn]"
                        )
            else:
                result["unused_fixtures"] = []
                result["unused_fixtures_counts"] = {}

        if args.verify and not machine_output:
            try:
                from skylos.api import verify_report

                vresp = verify_report(result, quiet=False)
                if vresp.get("success"):
                    console.print(
                        "[good]✓ Verified evidence attached (Skylos Pro)[/good]"
                    )
                else:
                    msg = vresp.get("error") or "Verification unavailable."
                    console.print(f"[warn]{msg}[/warn]")
            except Exception as e:
                console.print(f"[warn]Verification failed: {e}[/warn]")

        prov_report = None
        result["provenance"] = None
        _skip_provenance = getattr(args, "no_provenance", False) or getattr(
            args, "concise", False
        )
        if not _skip_provenance:
            try:
                from skylos.reporting.provenance import (
                    analyze_provenance,
                    annotate_findings_with_provenance,
                    compute_ai_security_stats,
                )
                from skylos.api import get_git_root

                git_root = get_git_root()
                if not git_root:
                    raise RuntimeError("not a git repository")
                prov_base = getattr(args, "provenance_base", None)

                if machine_output:
                    prov_report = analyze_provenance(git_root, base_ref=prov_base)
                else:
                    with Progress(
                        SpinnerColumn(style="brand"),
                        TextColumn("[brand]Skylos[/brand] {task.description}"),
                        transient=True,
                        console=console,
                    ) as progress:
                        progress.add_task("detecting AI provenance...", total=None)
                        prov_report = analyze_provenance(git_root, base_ref=prov_base)

                _finding_categories = [
                    "danger",
                    "quality",
                    "secrets",
                    "custom_rules",
                    "unused_functions",
                    "unused_imports",
                    "unused_classes",
                    "unused_variables",
                    "unused_parameters",
                    "dependency_vulnerabilities",
                ]
                all_annotatable = []
                for cat in _finding_categories:
                    items = result.get(cat)
                    if items:
                        for item in items:
                            item.setdefault("category", cat)
                        all_annotatable.extend(items)

                annotate_findings_with_provenance(all_annotatable, prov_report)

                ai_stats = compute_ai_security_stats(all_annotatable)
                result["ai_security_stats"] = ai_stats
                result["provenance_summary"] = prov_report.summary
                result["provenance"] = prov_report.to_dict()

                result_json = json.dumps(result)

                if not machine_output:
                    ai_count = ai_stats["ai_authored_findings"]
                    ai_pct = ai_stats["ai_authored_pct"]
                    if ai_count > 0:
                        console.print(
                            f"[brand]Provenance:[/brand] [red]{ai_count}[/red] of "
                            f"{ai_stats['total_findings']} findings ({ai_pct}%) are AI-authored"
                        )
                        agents = ai_stats.get("by_agent", {})
                        if agents:
                            agent_parts = [
                                f"{name}: {cnt}" for name, cnt in sorted(agents.items())
                            ]
                            console.print(
                                f"  [muted]Agents: {', '.join(agent_parts)}[/muted]"
                            )
            except Exception as e:
                if args.verbose:
                    console.print(f"[warn]Provenance annotation failed: {e}[/warn]")

        if args.sarif:
            all_findings = []

            def _add(items, category, default_rule_id):
                for item in items or []:
                    f = dict(item)
                    rid = (
                        f.get("rule_id")
                        or f.get("rule")
                        or f.get("code")
                        or f.get("id")
                        or default_rule_id
                        or "SKYLOS-UNKNOWN"
                    )
                    f["rule_id"] = str(rid)
                    f["category"] = category
                    f["file_path"] = f.get("file_path") or f.get("file") or "unknown"

                    line_raw = f.get("line_number") or f.get("line") or 1
                    try:
                        line = int(line_raw)
                    except Exception:
                        line = 1

                    f["line_number"] = max(1, line)

                    f["file"] = f.get("file") or f.get("file_path") or "unknown"
                    f["line"] = f.get("line") or f.get("line_number") or 1

                    if not f.get("message"):
                        name = (
                            f.get("name") or f.get("symbol") or f.get("function") or ""
                        )
                        if category == "DEAD_CODE" and name:
                            f["message"] = f"Dead code: {name}"
                        else:
                            f["message"] = f.get("detail") or f.get("msg") or "Issue"
                    if not f.get("severity"):
                        f["severity"] = "LOW"
                    all_findings.append(f)

            _add(result.get("danger", []), "SECURITY", None)
            _add(result.get("quality", []), "QUALITY", None)
            _add(result.get("secrets", []), "SECRET", None)
            _add(result.get("custom_rules", []), "CUSTOM", None)

            _add(
                result.get("unused_functions", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_FUNCTION",
            )
            _add(
                result.get("unused_imports", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_IMPORT",
            )
            _add(
                result.get("unused_variables", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_VARIABLE",
            )
            _add(
                result.get("unused_classes", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_CLASS",
            )
            _add(
                result.get("unused_parameters", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_PARAMETER",
            )

            exporter = _get_sarif_exporter_class()(all_findings, tool_name="Skylos")
            sarif_data = exporter.generate()
            grade_data = result.get("grade")
            if grade_data:
                sarif_data["runs"][0].setdefault("properties", {})["grade"] = grade_data
            import json as _json

            with open(  # skylos: ignore[SKY-D215] user-selected SARIF output path
                args.sarif, "w", encoding="utf-8"
            ) as _sf:
                _json.dump(sarif_data, _sf, indent=2)

        if args.json:
            if args.output:
                pathlib.Path(args.output).write_text(  # skylos: ignore[SKY-D215] user-selected CLI output path
                    result_json
                )
            else:
                print(result_json)

            if args.upload:
                _attach_upload_project_context(result, project_root)
                upload_resp = upload_report(
                    result,
                    is_forced=args.force,
                    strict=args.strict,
                    quiet=True,
                )
                if not upload_resp.get("success"):
                    raise SystemExit(1)

                passed = upload_resp.get("quality_gate_passed")
                if passed is None:
                    passed = (upload_resp.get("quality_gate") or {}).get("passed", True)

                if passed is False and not args.force:
                    raise SystemExit(1)

            if args.gate:
                exit_code = _formatted_output_gate_exit_code(
                    result,
                    config,
                    args,
                    provenance=prov_report,
                )
                if exit_code:
                    raise SystemExit(exit_code)

            strict_exit_code = _strict_scan_exit_code(result, args)
            if strict_exit_code:
                raise SystemExit(strict_exit_code)

            return

        if args.concise:
            display_result = result
            _cli_severity = getattr(args, "severity", None)
            _cli_category = getattr(args, "category", None)
            _cli_file_filter = getattr(args, "file_filter", None)
            _cli_limit = getattr(args, "limit", None)
            if _cli_severity or _cli_category or _cli_file_filter:
                display_result = _apply_display_filters(
                    result,
                    severity=_cli_severity,
                    category=_cli_category,
                    file_filter=_cli_file_filter,
                )

            concise_output = _format_concise_results(
                display_result,
                root_path=project_root,
                limit=_cli_limit,
            )
            if args.output:
                pathlib.Path(args.output).write_text(  # skylos: ignore[SKY-D215] user-selected CLI output path
                    concise_output, encoding="utf-8"
                )
            elif concise_output:
                print(concise_output, end="")

            exit_code = _concise_scan_exit_code(
                result,
                config,
                args,
                provenance=prov_report,
            )
            if exit_code:
                raise SystemExit(exit_code)
            return

        if args.llm:
            llm_report = _generate_llm_report(result, project_root)
            if args.output:
                pathlib.Path(args.output).write_text(  # skylos: ignore[SKY-D215] user-selected CLI output path
                    llm_report, encoding="utf-8"
                )
            else:
                print(llm_report)

            if args.gate:
                exit_code = _formatted_output_gate_exit_code(
                    result,
                    config,
                    args,
                    provenance=prov_report,
                )
                if exit_code:
                    raise SystemExit(exit_code)

            strict_exit_code = _strict_scan_exit_code(result, args)
            if strict_exit_code:
                raise SystemExit(strict_exit_code)
            return

        if args.github:
            _emit_github_annotations(result)
            if args.gate:
                exit_code = _formatted_output_gate_exit_code(
                    result,
                    config,
                    args,
                    provenance=prov_report,
                )
                if exit_code:
                    raise SystemExit(exit_code)

            strict_exit_code = _strict_scan_exit_code(result, args)
            if strict_exit_code:
                raise SystemExit(strict_exit_code)
            return

    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        sys.exit(1)

    if args.gate:
        should_upload_gate = bool(getattr(args, "upload", False)) and not bool(
            getattr(args, "no_upload", False)
        )

        if should_upload_gate and not args.json:
            _print_upload_destination(console, project_root)
            _print_main_upload_manifest(console, args, result)

        if should_upload_gate:
            _attach_upload_project_context(result, project_root)
            upload_resp = upload_report(
                result,
                is_forced=args.force,
                strict=args.strict,
            )
            if not upload_resp.get("success"):
                _render_upload_failure(console, upload_resp)
                if getattr(args, "_explicit_upload_requested", False):
                    raise SystemExit(1)

        exit_code = run_gate_interaction(
            result=result,
            config=config,
            strict=bool(args.strict),
            force=bool(args.force),
            summary=bool(getattr(args, "summary", False)),
        )
        sys.exit(exit_code)

    if args.interactive:
        unused_functions = result.get("unused_functions", [])
        unused_imports = result.get("unused_imports", [])

        if not (unused_functions or unused_imports):
            console.print("[good]No unused functions/imports to process.[/good]")
        else:
            selected_functions, selected_imports = interactive_selection(
                console, unused_functions, unused_imports, root_path=project_root
            )

            if selected_functions or selected_imports:
                if not args.dry_run:
                    if args.comment_out:
                        action_func_fn = comment_out_unused_function
                        action_func_imp = comment_out_unused_import
                        action_past = "Commented out"
                        action_verb = "comment out"
                    else:
                        action_func_fn = remove_unused_function
                        action_func_imp = remove_unused_import
                        action_past = "Removed"
                        action_verb = "remove"

                    if INTERACTIVE_AVAILABLE:
                        confirm_q = [
                            inquirer.Confirm(
                                "confirm",
                                message="Proceed with changes?",
                                default=False,
                            )
                        ]
                        answers = inquirer.prompt(confirm_q)
                        proceed = answers and answers.get("confirm")
                    else:
                        proceed = True

                    if proceed:
                        console.print("[warn]Applying changes…[/warn]")
                        for func in selected_functions:
                            ok = action_func_fn(
                                func["file"], func["name"], func["line"]
                            )
                            if ok:
                                console.print(
                                    f"[good] ✓ {action_past} function:[/good] {func['name']}"
                                )
                            else:
                                console.print(
                                    f"[bad] x Failed to {action_verb} function:[/bad] {func['name']}"
                                )

                        for imp in selected_imports:
                            ok = action_func_imp(imp["file"], imp["name"], imp["line"])
                            if ok:
                                console.print(
                                    f"[good] ✓ {action_past} import:[/good] {imp['name']}"
                                )
                            else:
                                console.print(
                                    f"[bad] x Failed to {action_verb} import:[/bad] {imp['name']}"
                                )
                        console.print("[good]Cleanup complete![/good]")
                    else:
                        console.print("[warn]Operation cancelled.[/warn]")
                else:
                    console.print("[warn]Dry run — no files modified.[/warn]")
            else:
                console.print("[muted]No items selected.[/muted]")

    if args.tui:
        from skylos.ui.tui import run_tui

        run_tui(result, root_path=project_root)
    elif not args.upload:
        display_result = result
        _cli_severity = getattr(args, "severity", None)
        _cli_category = getattr(args, "category", None)
        _cli_file_filter = getattr(args, "file_filter", None)
        _cli_limit = getattr(args, "limit", None)
        if _cli_severity or _cli_category or _cli_file_filter:
            display_result = _apply_display_filters(
                result,
                severity=_cli_severity,
                category=_cli_category,
                file_filter=_cli_file_filter,
            )
        render_results(
            console,
            display_result,
            tree=args.tree,
            root_path=project_root,
            limit=_cli_limit,
        )
        if args.output:
            _write_rich_report_output(
                args.output,
                display_result,
                tree=args.tree,
                root_path=project_root,
                limit=_cli_limit,
            )

    unused_total = sum(
        len(result.get(k, []))
        for k in (
            "unused_functions",
            "unused_imports",
            "unused_variables",
            "unused_classes",
            "unused_parameters",
        )
    )
    danger_count = len(result.get("danger", []) or [])
    quality_count = len(result.get("quality", []) or [])
    print_badge(
        unused_total,
        logging.getLogger("skylos"),
        danger_enabled=bool(danger_count),
        danger_count=danger_count,
        quality_enabled=bool(quality_count),
        quality_count=quality_count,
    )

    strict_exit_code = _strict_scan_exit_code(result, args)
    if strict_exit_code:
        raise SystemExit(strict_exit_code)

    if (not args.json) and _is_tty() and (not args.upload):
        total_findings = 0
        for k in (
            "unused_functions",
            "unused_imports",
            "unused_variables",
            "unused_classes",
            "unused_parameters",
            "danger",
            "quality",
            "secrets",
            "custom_rules",
            "dependency_vulnerabilities",
        ):
            total_findings += len(result.get(k, []) or [])

        if total_findings > 0:
            workflow_path = project_root / ".github" / "workflows" / "skylos.yml"
            if not workflow_path.exists():
                console.print()
                console.print(
                    Panel.fit(
                        "[bold cyan]💡 Tip:[/bold cyan] Catch these issues automatically on every PR\n\n"
                        "[dim]Run:[/dim] [bold]skylos cicd init[/bold]\n"
                        "[dim]Then:[/dim] [bold]git add .github/workflows/skylos.yml && git push[/bold]\n\n"
                        "[muted]30-second setup for automated code analysis in CI/CD[/muted]",
                        title="[cyan]Set up CI/CD[/cyan]",
                        border_style="cyan",
                    )
                )

            from skylos.ui.nudge import pick_nudge

            nudge = pick_nudge(result, args, project_root)
            if nudge:
                console.print(f"\n  {nudge}")
            _print_upload_cta(console, project_root)
        else:
            console.print()
            console.print(
                "[good]✨ Clean codebase! No issues found.[/good]\n"
                "[dim]💡 Show others you maintain quality code: [/dim][bold cyan]skylos badge[/bold cyan]"
            )
            from skylos.ui.nudge import pick_nudge

            nudge = pick_nudge(result, args, project_root)
            if nudge:
                console.print(f"\n  {nudge}")

    if not args.upload and not getattr(args, "no_upload", False) and not args.json:
        is_linked = _detect_link_file(project_root) is not None
        has_env_token = bool(os.getenv("SKYLOS_TOKEN"))
        if is_linked or has_env_token:
            args.upload = True

    forgotten = result.get("forgotten", [])
    if forgotten:
        console.print(
            "\n[bold red]Forgotten / Dead Functions (Last 30 Days)[/bold red]"
        )
        console.print("=====================================================")
        for item in forgotten:
            status = item["status"]

            if "EXPIRED" in status:
                style = "dim"
            else:
                style = "bold red"

            console.print(f" [{style}]{status}[/{style}] {item['name']}")
            console.print(f"    └─ {item['file']}:{item['line']}")

    if args.upload and not args.json:
        from skylos.api import get_project_token as _check_token

        has_link, using_env = _print_upload_destination(console, project_root)

        if (not has_link) and (not using_env) and (not _check_token()):
            if _is_tty() and not _is_ci():
                console.print(
                    "\n[bold yellow]No Skylos token found.[/bold yellow] "
                    "Let's connect to Skylos Cloud.\n"
                )
                from skylos.cloud.login import run_login

                login_result = run_login(console=console)
                if login_result is None:
                    console.print("[dim]Upload cancelled.[/dim]")
                    raise SystemExit(0)
            elif _is_ci():
                console.print(
                    "[warn]No SKYLOS_TOKEN set. To upload from CI, add SKYLOS_TOKEN to your environment.[/warn]"
                )
                console.print("  See: https://docs.skylos.dev/ci-setup")
                raise SystemExit(1)
            else:
                from skylos.cloud.login import manual_token_fallback

                login_result = manual_token_fallback(console=console)
                if login_result is None:
                    raise SystemExit(1)

        from skylos.api import (
            get_credit_balance,
            get_project_token as _get_token,
            BASE_URL,
        )

        _token = _get_token()

        if _token:
            _balance_data = get_credit_balance(_token)
        else:
            _balance_data = None

        if _balance_data:
            _plan = _balance_data.get("plan", "free")
            _bal = _balance_data.get("balance", 0)
            if _plan != "enterprise" and _bal <= 0:
                console.print(
                    f"[bold red]0 credits remaining — upload skipped.[/bold red] "
                    f"Buy more: [link={BASE_URL}/dashboard/billing]{BASE_URL}/dashboard/billing[/link]"
                )
                console.print("[dim]Run 'skylos credits' to check your balance.[/dim]")
                return

        _print_main_upload_manifest(console, args, result)
        _attach_upload_project_context(result, project_root)
        upload_resp = upload_report(result, is_forced=args.force, strict=args.strict)

        if not upload_resp.get("success"):
            _render_upload_failure(console, upload_resp)
            if getattr(args, "_explicit_upload_requested", False):
                raise SystemExit(1)
        else:
            passed = upload_resp.get("quality_gate_passed")
            if passed is None:
                passed = (upload_resp.get("quality_gate") or {}).get("passed", True)

            qg = upload_resp.get("quality_gate") or {}
            new_v = qg.get("new_violations", 0)
            if new_v > 0:
                console.print(
                    f"[bold red]  {new_v} new violation{'s' if new_v != 1 else ''}[/bold red]"
                )

            if passed is False and not args.force:
                raise SystemExit(1)

    if args.command and not args.gate:
        cmd_list = args.command
        if cmd_list[0] == "--":
            cmd_list = cmd_list[1:]

        console.print(Rule(style="brand"))
        console.print(f"[brand]Executing Deployment:[/brand] {' '.join(cmd_list)}")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("[cyan]Initializing deployment...", total=None)

                process = subprocess.Popen(
                    cmd_list,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )

                for line in process.stdout:
                    line = line.strip()
                    if line:
                        progress.update(task, description=f"[cyan]{line}")
                        console.print(f"[dim]{line}[/dim]")

                process.wait()

            if process.returncode == 0:
                console.print("[bold green]✓ Deployment Successful[/bold green]")
                sys.exit(0)
            else:
                console.print(
                    f"[bold red]x Deployment Failed (Exit Code {process.returncode})[/bold red]"
                )
                sys.exit(process.returncode)

        except Exception as e:
            console.print(f"[bad]Failed to execute command: {e}[/bad]")
            sys.exit(1)
