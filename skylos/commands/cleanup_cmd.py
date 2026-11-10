"""Turn static findings into a bounded, read-only cleanup queue."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from skylos.core.cli_shared import quiet_analyzer_logs
from skylos.core.safe_cache_io import read_text_no_symlink

MAX_SAVED_REPORT_BYTES = 512_000_000


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos cleanup",
        description="Review cleanup tasks, preview focused patches, and check selected edits.",
        epilog=(
            "The default scan leaves source unchanged and saves local task history. "
            "--task ID previews a supported patch; add --apply to edit and rescan. "
            "Tests run only with --test-cmd. Skipped tests leave changes unverified. "
            "Exit 0 means the operation completed, 1 means checks failed, and "
            "2 means incomplete checks or invalid input."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", metavar="PATH")
    parser.add_argument(
        "--diff",
        metavar="BASE",
        help="Show tasks in files changed since BASE's merge base; analyze the full Git project.",
    )
    parser.add_argument(
        "--from-report",
        metavar="REPORT",
        help="Read a regular UTF-8 analyzer JSON file up to 512 MB instead of scanning.",
    )
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument(
        "--top",
        type=_positive_int,
        default=10,
        help="Maximum tasks to show (default: 10).",
    )
    parser.add_argument(
        "--all-advice",
        action="store_true",
        help="Include optional style advice in the task queue.",
    )
    parser.add_argument("--next", action="store_true", help="Show the next open task.")
    parser.add_argument(
        "--task", metavar="ID", help="Preview a deterministic patch for a task ID."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the selected task's validated patch and rescan.",
    )
    parser.add_argument(
        "--test-cmd",
        help="Explicitly authorize this test command after applying; never run through a shell.",
    )
    parser.add_argument(
        "--junit-report",
        metavar="PATH",
        help="Project-relative JUnit XML written by the explicitly authorized test command.",
    )
    parser.add_argument(
        "--defer",
        metavar="ID",
        help="Defer a task in local history without changing scan or gate policy.",
    )
    parser.add_argument("--reason", default="", help="Reason for deferring a task.")
    parser.add_argument(
        "--restore", metavar="ID", help="Restore a deferred task to the open queue."
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Read local cleanup history without scanning.",
    )
    parser.add_argument(
        "--no-state",
        action="store_true",
        help="Do not read or write local cleanup history.",
    )
    parser.add_argument(
        "--context",
        action="store_true",
        help="Include bounded source excerpts, imports and candidate callers.",
    )
    parser.add_argument(
        "--review",
        action="store_true",
        help="Send bounded source context to the configured model for advisory review.",
    )
    parser.add_argument("--model", default="gpt-4.1")
    parser.add_argument("--provider")
    parser.add_argument("--base-url")
    from skylos.commands.cleanup_workspace import add_workspace_arguments

    add_workspace_arguments(parser)
    return parser


def run_cleanup_command(
    argv: list[str],
    *,
    stdout: TextIO | None = None,
    analyze_func: Callable[..., str | dict[str, Any]] | None = None,
) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.apply and not args.task:
        parser.error("--apply requires --task ID")
    if args.test_cmd and not args.apply:
        parser.error("--test-cmd requires --task ID --apply")
    if args.junit_report and not (args.apply and args.test_cmd):
        parser.error("--junit-report requires --apply and --test-cmd")
    from skylos.commands.cleanup_workspace import validate_workspace_arguments

    validate_workspace_arguments(parser, args)
    if (
        sum(
            bool(value) for value in (args.task, args.defer, args.restore, args.history)
        )
        > 1
    ):
        parser.error("choose only one of --task, --defer, --restore or --history")
    if args.defer and not args.reason.strip():
        parser.error("--defer requires --reason")
    if args.from_report and any(
        (args.task, args.apply, args.defer, args.restore, args.history, args.review)
    ):
        parser.error(
            "saved reports cannot authorize edits, model review or state changes; run a live scan"
        )
    if args.no_state and any((args.defer, args.restore, args.history)):
        parser.error("history actions require local state")
    if args.review and any((args.task, args.defer, args.restore, args.history)):
        parser.error(
            "--review is a separate advisory step; run it before selecting a patch"
        )
    if args.diff is not None and (args.from_report or args.history):
        parser.error(
            "--diff requires a live scan and cannot be combined with --from-report or --history"
        )
    stdout = stdout if stdout is not None else sys.stdout
    root = None
    report = None
    try:
        target = Path(args.path).expanduser().resolve(strict=True)
        if (args.task or args.diff is not None) and Path(
            args.path
        ).expanduser().is_symlink():
            raise ValueError(
                "Cleanup patches require a direct source path, not a symlink"
            )
        root = target.parent if target.is_file() else target
        if not root.is_dir():
            raise ValueError("PATH must be a directory or source file")
        selection = None
        scope = None
        if args.diff is not None:
            from skylos.cleanup_diff import resolve_cleanup_diff

            selection = resolve_cleanup_diff(target, args.diff)
            root = selection.context.root
            target = root
            scope = {
                **_scope(target, root, verification=args.apply),
                **selection.scope_binding(),
            }

        if args.history:
            from skylos.cleanup_state import load_cleanup_state

            report = {
                "tool": "cleanup",
                "status": "history",
                "history": load_cleanup_state(root),
                "tasks": [],
                "advisories": [],
            }
            _emit(stdout, args.format, report)
            return 0

        if args.from_report:
            # The operator explicitly chooses the report, which may live outside
            # the scanned project. It is data only and cannot authorize edits.
            raw = read_text_no_symlink(
                Path(args.from_report).expanduser(), max_bytes=MAX_SAVED_REPORT_BYTES
            )
            if raw is None:
                raise ValueError(
                    "Saved report must be a readable regular UTF-8 file up to 512 MB, without a symlink"
                )
        else:
            if scope is None:
                scope = _scope(target, root, verification=args.apply)
            raw = _scan(
                target, root, analyze_func, selection=selection, verification=args.apply
            )
        if selection is not None:
            selection.assert_head_unchanged()
        if not args.from_report:
            current_scope = _scope(target, root, verification=args.apply)
            if selection is not None:
                current_scope.update(selection.scope_binding())
            if current_scope != scope:
                raise ValueError(
                    "Project configuration changed during cleanup; the scan is not comparable"
                )

        from skylos.cleanup import build_cleanup_plan

        result = json.loads(raw) if isinstance(raw, str) else raw
        report = build_cleanup_plan(
            result,
            project_root=root,
            top=None,
            all_advice=args.all_advice,
        )
        _run_workflow(
            args,
            target,
            root,
            report,
            result,
            analyze_func,
            selection=selection,
            scope=scope,
        )
    except (Exception, SystemExit) as exc:
        if isinstance(report, dict) and report.get("execution"):
            report["status"] = "incomplete"
            report.setdefault("limitations", []).append(
                f"Edit receipt retained, but a later cleanup step failed: {exc}"
            )
        else:
            report = _incomplete_report(root, exc)
    report["source"] = "saved_report" if args.from_report else "live_scan"
    _emit(stdout, args.format, report)
    if report.get("execution", {}).get("status") == "failed":
        return 1
    return 2 if report["status"] == "incomplete" else 0


def _incomplete_report(root, exc):
    return {
        "schema_version": 1,
        "tool": "cleanup",
        "status": "incomplete",
        "project_root": str(root) if root is not None else None,
        "scope": ["quality", "ai_defects", "dead_code"],
        "tasks": [],
        "advisories": [],
        "counts": {
            "tasks": 0,
            "advisories": 0,
            "shown_tasks": 0,
            "shown_advisories": 0,
            "optional_advice": 0,
        },
        "limitations": [f"Cleanup queue could not be built: {exc}"],
        "next_step": "Resolve the input or scan error, then rerun skylos cleanup.",
    }


def _run_workflow(
    args, target, root, report, result, analyze_func, *, selection=None, scope=None
):
    from hashlib import sha256
    from skylos.cleanup_state import update_cleanup_state

    scope = (
        scope if scope is not None else _scope(target, root, verification=args.apply)
    )
    inventory = report.pop("_inventory", None)
    all_tasks = report.get("tasks", []) + report.get("advisories", [])
    for task in all_tasks:
        task["scope"] = scope
    bucket = None
    if not args.no_state and not args.from_report:
        if selection is not None:
            selection.assert_head_unchanged()
        disposition = (
            {"id": args.defer, "status": "deferred", "reason": args.reason}
            if args.defer
            else {"id": args.restore, "status": "open"}
            if args.restore
            else None
        )
        bucket = update_cleanup_state(
            root, scope, report, disposition=disposition, inventory=inventory
        )
        for task in all_tasks:
            task["state"] = bucket["tasks"].get(task["id"], {}).get("status", "open")
        report["state"] = {
            "path": ".skylos/cache/cleanup.json",
            "scope_id": sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest(),
            "tasks": bucket["tasks"],
        }
    if selection is not None:
        from skylos.cleanup_diff import select_cleanup_diff

        select_cleanup_diff(report, selection, inventory)
        all_tasks = report["tasks"] + report["advisories"]
    from skylos.commands.cleanup_workspace import run_workspace_actions

    run_workspace_actions(args, root, scope, report)
    if args.task:
        from skylos.cleanup_execution import plan_cleanup_edit, apply_cleanup_edit

        matches = [task for task in all_tasks if task["id"].startswith(args.task)]
        if len(matches) != 1:
            raise ValueError(
                "Task ID is unknown or ambiguous; scan with --all-advice if it is an optional task"
            )
        task = {**matches[0], "baseline_report": result}
        if report.get("status") == "incomplete":
            raise ValueError("Incomplete analysis cannot authorize a cleanup patch")
        edit = plan_cleanup_edit(task, root)
        report["edit"] = {
            key: value
            for key, value in edit.items()
            if not key.startswith("_")
            and key not in {"original_source", "applied_source", "baseline_report"}
        }
        if args.apply:
            from skylos.cleanup_receipts import (
                capture_cleanup_revision,
                make_cleanup_receipt,
                store_cleanup_receipt,
            )

            source_revision = capture_cleanup_revision(root)

            def rescan():
                current_scope = _scope(target, root, verification=True)
                if selection is not None:
                    selection.assert_head_unchanged()
                    current_scope.update(selection.scope_binding())
                if current_scope != scope:
                    raise ValueError(
                        "Project configuration changed during checks; the rescan is not comparable"
                    )
                raw = _scan(
                    target, root, analyze_func, selection=selection, verification=True
                )
                if selection is not None:
                    selection.assert_head_unchanged()
                current_scope = _scope(target, root, verification=True)
                if selection is not None:
                    current_scope.update(selection.scope_binding())
                if current_scope != scope:
                    raise ValueError(
                        "Project configuration changed during checks; the rescan is not comparable"
                    )
                return json.loads(raw) if isinstance(raw, str) else raw

            receipt = apply_cleanup_edit(
                edit,
                root,
                test_cmd=args.test_cmd,
                rescan=rescan,
                junit_xml=args.junit_report,
            )
            if selection is not None:
                receipt["baseline"] = selection.baseline()
            report["execution"] = receipt
            if receipt["status"] == "incomplete":
                report["status"] = "incomplete"
            try:
                envelope = make_cleanup_receipt(
                    task,
                    scope,
                    receipt,
                    project_root=root,
                    source_revision=source_revision,
                    edit=edit,
                )
                report["cleanup_receipt"] = envelope
                if not args.no_state:
                    store_cleanup_receipt(root, scope, envelope)
            except (ValueError, OSError) as exc:
                report.setdefault("limitations", []).append(
                    f"Edit receipt retained, but its upload summary could not be saved: {exc}"
                )
                report["status"] = "incomplete"
            if bucket is not None:
                try:
                    updated = update_cleanup_state(
                        root, scope, report, receipt=receipt, inventory=inventory
                    )
                    report["state"]["tasks"] = updated["tasks"]
                except (ValueError, OSError) as exc:
                    report.setdefault("limitations", []).append(
                        f"Edit receipt retained, but history could not be saved: {exc}"
                    )
                    report["status"] = "incomplete"
    limit = 1 if args.next else args.top
    displayed = {}
    for section in ("tasks", "advisories"):
        displayed[section] = [
            task for task in report[section] if task.get("state") != "deferred"
        ][:limit]
    if args.next and displayed["tasks"]:
        displayed["advisories"] = []
    selected = sorted(
        displayed["tasks"] + displayed["advisories"],
        key=lambda task: 0 if task["finding_type"] == "defect" else 1,
    )
    if (args.context or args.review) and selected:
        from skylos.cleanup_context import build_cleanup_context, review_cleanup_context

        from skylos.constants import parse_exclude_folders
        from skylos.config import load_config, resolve_config_file_path

        context_config = load_config(root, config_file=resolve_config_file_path())
        exclusions = sorted(
            parse_exclude_folders(
                use_defaults=True, config_exclude_folders=context_config.get("exclude")
            )
        )
        context = build_cleanup_context(selected[:5], root, exclude_folders=exclusions)
        if report.get("execution"):
            context["limitations"].append(
                "Context was read after the edit; original finding locations may have shifted or disappeared."
            )
        report["context"] = context
        if args.review:
            if not context["files"]:
                raise ValueError(
                    "No supported source context is available for model review"
                )
            adapter = _review_adapter(args)
            report["context_review"] = review_cleanup_context(
                context, selected[:5], adapter
            )
            if report["context_review"]["status"] == "incomplete":
                report["status"] = "incomplete"
            elif report["context_review"]["status"] == "reviewed" and not args.no_state:
                from skylos.cleanup_review_state import store_cleanup_review

                report["stored_reviews"] = store_cleanup_review(
                    root,
                    scope,
                    report["context_review"],
                    context,
                    model=args.model,
                    provider=getattr(adapter, "_cleanup_provider", None)
                    or getattr(adapter, "explicit_provider", None)
                    or "unknown",
                )
    elif args.review:
        report["context_review"] = {
            "status": "skipped",
            "kind": "subjective_advice",
            "advice": [],
            "reason": "No open cleanup tasks are available for model review.",
        }
    for section in ("tasks", "advisories"):
        rows = [
            task for task in report.get(section, []) if task.get("state") != "deferred"
        ]
        report.setdefault("counts", {})["deferred_" + section] = len(
            report.get(section, [])
        ) - len(rows)
        report[section] = rows[:limit]
        report["counts"]["shown_" + section] = len(report[section])
    if args.next and report.get("tasks"):
        report["advisories"] = []
        report["counts"]["shown_advisories"] = 0


def _scope(target, root, *, verification=False):
    from hashlib import sha256
    from skylos.config import load_config, resolve_config_file_path
    import skylos

    config = load_config(root, config_file=resolve_config_file_path())
    scope = {
        "target": str(target),
        "project_root": str(root),
        "scanner_version": skylos.__version__,
        "config_digest": sha256(
            json.dumps(config, sort_keys=True, default=str).encode()
        ).hexdigest(),
    }
    if verification:
        scope["verification_checks"] = [
            "quality",
            "ai_defects",
            "dead_code",
            "security",
            "secrets",
        ]
    return scope


def _review_adapter(args):
    from skylos.llm.runtime import resolve_llm_runtime
    from skylos.llm.agents import AgentConfig, create_llm_adapter

    provider, key, base_url, local = resolve_llm_runtime(
        model=args.model,
        provider_override=args.provider,
        base_url_override=args.base_url,
        allow_prompt=False,
    )
    if not key and not local:
        raise ValueError(
            "Configure a model provider key or local model before --review"
        )
    config = AgentConfig(model=args.model, api_key=key)
    config.provider, config.base_url = provider, base_url
    adapter = create_llm_adapter(config)
    adapter._cleanup_provider = provider
    return adapter


def _scan(
    target: Path, root: Path, analyze_func, *, selection=None, verification=False
):
    from skylos.config import load_config, resolve_config_file_path
    from skylos.constants import parse_exclude_folders

    config_file = resolve_config_file_path()
    config = load_config(root, config_file=config_file)
    excluded = sorted(
        parse_exclude_folders(
            use_defaults=True,
            config_exclude_folders=config.get("exclude"),
        )
    )
    if analyze_func is None:
        from skylos.analyzer import analyze as analyze_func

    from skylos.core.file_discovery import find_git_root
    from skylos.core.review_decisions import (
        review_scan_requirements,
        apply_trusted_review_decisions,
    )

    review_root = find_git_root(root) or root
    context_required, proofs_required = review_scan_requirements(review_root)
    review_options = {}
    if context_required:
        review_options["include_review_context"] = True
    if proofs_required:
        review_options["include_review_proofs"] = True

    from inspect import Parameter, signature

    parameters = signature(analyze_func).parameters
    if "enable_dead_code" in parameters or any(
        parameter.kind == Parameter.VAR_KEYWORD for parameter in parameters.values()
    ):
        review_options["enable_dead_code"] = True
    # Earlier native analyzer APIs always enable dead-code analysis and have
    # no switch for it. Keep their static defaults without passing a new flag.

    with (
        quiet_analyzer_logs(),
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        from skylos.cleanup_diff import cleanup_diff_environment

        with cleanup_diff_environment(selection):
            raw = analyze_func(
                str(target),
                exclude_folders=excluded,
                enable_quality=True,
                enable_ai_defects=True,
                enable_danger=verification,
                enable_secrets=verification,
                enable_dependency_hallucinations=False,
                enable_sca=False,
                grep_verify=False,
                trace_file=False,
                config_file=config_file,
                all_advice=False,
                **review_options,
            )
        result = json.loads(raw) if isinstance(raw, str) else raw
        return apply_trusted_review_decisions(result, review_root)


def _plain(value: Any) -> str:
    return " ".join(
        "".join(char if char.isprintable() else " " for char in str(value)).split()
    )


def _emit(stdout: TextIO, output_format: str, report: dict[str, Any]) -> None:
    if output_format == "json":
        stdout.write(json.dumps(report, sort_keys=True) + "\n")
        return

    tasks = report.get("tasks", [])
    advisories = report.get("advisories", [])
    counts = report.get("counts", {})
    stdout.write(f"Skylos cleanup: {_plain(report['status'])}\n")
    if report.get("history") is not None:
        stdout.write(json.dumps(report["history"], indent=2) + "\n")
        return
    if report.get("selection"):
        selection = report["selection"]
        stdout.write(
            f"Selection: files changed since {_plain(selection['base'])} "
            f"(comparison {_plain(selection['merge_base_sha'][:12])}); findings may predate the change.\n"
        )
    if report.get("edit"):
        stdout.write(_plain(report["edit"].get("message", "Patch preview")) + "\n")
        stdout.write(
            report["edit"].get("patch") or report["edit"].get("unified_diff") or ""
        )
    if report.get("execution"):
        execution = report["execution"]
        stdout.write("\nExecution: " + _plain(execution["status"]) + "\n")
        tests = execution.get("tests", {})
        count = tests.get("count")
        exercised = tests.get("exercised_change")
        stdout.write(
            f"Tests: {_plain(tests.get('status', 'skipped'))}; "
            f"observed count: {count if count is not None else 'unknown'}; "
            f"changed lines exercised: {'yes' if exercised is True else 'no' if exercised is False else 'unknown'}\n"
        )
        rescan = execution.get("rescan", {})
        stdout.write(f"Rescan: {_plain(rescan.get('status', 'skipped'))}\n")
        for limitation in execution.get("limitations", []):
            stdout.write(f"Check limit: {_plain(limitation)}\n")
    for plan in [report["plan"]] if report.get("plan") else report.get("plans", []):
        stdout.write(
            f"\nPlan {_plain(plan['name'])}: {_plain(plan['status'])}; "
            f"{plan['completed_steps']}/{len(plan['steps'])} manually completed\n"
        )
        for index, step in enumerate(plan["steps"], 1):
            stdout.write(
                f"{index}. {_plain(step['id'][:12])} {_plain(step['file'])} "
                f"[{_plain(step['kind'])}, {_plain(step['refresh_status'])}, unverified]\n"
            )
        for label, key in (
            ("Prerequisite", "prerequisites"),
            ("Acceptance check", "acceptance_checks"),
        ):
            for text in plan.get(key, []):
                stdout.write(f"{label} (recorded text): {_plain(text)}\n")
    if "stored_reviews" in report:
        stdout.write(f"\nStored advisory reviews: {len(report['stored_reviews'])}\n")
        for row in report["stored_reviews"]:
            stdout.write(
                f"- {_plain(row['id'][:12])} {_plain(row['file'])}:{row['line']} "
                f"[{_plain(row['refresh_status'])}] {_plain(row['summary'])}\n"
                f"  Evidence: {_plain(row['evidence'])}\n"
                f"  Suggestion: {_plain(row['suggestion'])}\n"
            )
    if report.get("context_review"):
        stdout.write(
            "\nContext review: " + _plain(report["context_review"]["status"]) + "\n"
        )
        for row in report["context_review"].get("advice", []):
            stdout.write(
                f"- {_plain(row['file'])}:{row['line']} {_plain(row['summary'])}\n"
                f"  Evidence: {_plain(row['evidence'])}\n"
                f"  Suggestion: {_plain(row['suggestion'])}\n"
            )
    if report.get("context"):
        context = report["context"]
        stdout.write(
            "\nSource context (bounded; graph relationships are static observations):\n"
        )
        after_edit = bool(report.get("execution"))
        if after_edit:
            stdout.write(
                "Read after edit; original finding locations may have shifted or disappeared.\n"
            )
        selected = {
            task["file"]: int(task.get("line") or 1) for task in tasks + advisories
        }
        for row in context.get("files", []):
            if row["file"] not in selected:
                continue
            focus = selected[row["file"]]
            stdout.write(f"{_plain(row['file'])}:{focus}\n")
            for line, text in enumerate(row["source"].splitlines(), row["start_line"]):
                if focus - 2 <= line <= focus + 2:
                    stdout.write(
                        f"  {line:>5} {'>' if line == focus and not after_edit else ' '} {_plain(text)}\n"
                    )
        for row in context.get("suggested_tests", [])[:5]:
            stdout.write(
                f"Suggested test (not run): {_plain(row['file'])}:{row['line']}\n"
            )
        for limitation in context.get("limitations", []):
            stdout.write(f"Context limit: {_plain(limitation)}\n")
    if report.get("source") == "saved_report":
        stdout.write("Source: saved report; source files were not rescanned.\n")
    if tasks:
        stdout.write(
            f"\nNext cleanup tasks ({len(tasks)} of {counts.get('tasks', len(tasks))}):\n"
        )
        for index, task in enumerate(tasks, 1):
            stdout.write(
                f"{index}. {_plain(task['file'])}:{task['line']} "
                f"{_plain(task['rule_id'])} [{_plain(task['severity'])}, {_plain(task['finding_type'])}] "
                f"{_plain(task['message'])} (task {_plain(task['id'][:12])})\n"
                f"   {_plain(task['action'])}\n"
            )
    if advisories:
        stdout.write(
            "\nReview advice "
            f"({len(advisories)} of {counts.get('advisories', len(advisories))}):\n"
        )
        for task in advisories:
            stdout.write(
                f"- {_plain(task['file'])}:{task['line']} "
                f"{_plain(task['rule_id'])} {_plain(task['message'])} (task {_plain(task['id'][:12])})\n"
            )
    if counts.get("optional_advice"):
        stdout.write(
            f"\nOptional style advice: {counts['optional_advice']} "
            "(add --all-advice to include).\n"
        )
    for limitation in report.get("limitations", []):
        stdout.write(f"\nCoverage: {_plain(limitation)}\n")
    if report.get("selection"):
        stdout.write("\nNext: " + _plain(report["next_step"]) + "\n")
    else:
        stdout.write(
            "\nNext: review one task, make a focused change, run your checks, "
            "then rerun skylos cleanup.\n"
        )
