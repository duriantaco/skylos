"""``skylos cicd risk-review``: which risks in a pull request need a human
approval, and whether a human approved them."""

from __future__ import annotations

import json
import logging
import os
from collections import Counter

from rich.console import Console
from rich.text import Text

from skylos.cicd.approval import CHECK_NAME, SCHEMA, VETO_CLASSES, ApprovalResult

logger = logging.getLogger(__name__)

EXIT_PASS = 0
EXIT_NEEDS_HUMAN = 1
EXIT_INCOMPLETE = 2

_LISTED_RISKS = 50
_LISTED_ADVICE = 20


def add_risk_review_parser(subparsers) -> None:
    parser = subparsers.add_parser(
        "risk-review",
        help="List the risks in a PR that need a human approval (exit 1 until one approves)",
        description=(
            "Compare a pull request with its merge base and list the risk classes "
            "it contains: tests deleted or weakened, auth removed, dependencies "
            "added or changed, CI weakened, checks silenced, secrets added, "
            "guardrail settings changed, migrations changed, a very large diff. "
            "In GitHub Actions, a change with risks passes once a person with "
            "write access approves its head commit; bot approvals do not count. "
            "Settings come from [tool.skylos.approval] at the base. Exit 0 pass, "
            "1 needs a human approval, 2 could not decide."
        ),
    )
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument(
        "--base",
        metavar="REF",
        default=None,
        help=(
            "Target branch to compare with, e.g. origin/main (default in GitHub "
            "Actions: origin/<pull request base branch>)"
        ),
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text)",
    )


def run_risk_review(args, *, console: Console | None = None) -> int:
    from skylos.cicd.approval import analyze_change
    from skylos.cicd.approval_github import GitHubApiError
    from skylos.cicd.merge_group import merge_group_event
    from skylos.done.base import DoneError

    out = console or Console(highlight=False)
    err = Console(stderr=True, highlight=False)
    try:
        group = merge_group_event()
    except GitHubApiError as exc:
        return _report_error(
            args.format, err, f"could not read the merge_group event: {exc}"
        )
    base_ref = args.base or _ci_base_ref(group)
    if not base_ref:
        return _report_error(
            args.format,
            err,
            "no base to compare with: pass --base (for a pull request: its target, "
            "e.g. origin/main)",
        )
    try:
        result = analyze_change(args.path, base_ref)
    except DoneError as exc:
        return _report_error(args.format, err, str(exc), base_ref=base_ref)
    except Exception:
        logger.debug("risk review failed", exc_info=True)
        return _report_error(
            args.format, err, "the analysis could not complete", base_ref=base_ref
        )

    if group is not None:
        # The check must describe the commit the queue built, compared with
        # the queue's own base; anything else is a misconfigured workflow.
        problem = _merge_group_mismatch(result, group)
        if problem:
            return _report_error(args.format, err, problem, base_ref=base_ref)

    human = None
    if result.complete and result.vetoes:
        human = (
            _merge_group_approval(args.path, result, group)
            if group is not None
            else _human_approval(result)
        )
    exit_code, verdict = decide(result, human)
    payload = build_payload(
        result,
        human,
        exit_code=exit_code,
        verdict=verdict,
        merge_group=_merge_group_info(group, human),
    )

    if args.format == "json":
        print(json.dumps(payload, indent=2))
    elif args.format == "markdown":
        print(render_markdown(payload))
    else:
        _print_text(out, payload)
    _write_github_files(payload)
    return exit_code


def _ci_base_ref(group=None) -> str | None:
    from skylos.core.ci_env import github_or_ci_base_ref

    if group is not None:
        # A merge group is compared with the commit the queue built it on.
        return group.base_sha
    base = github_or_ci_base_ref() or _event_base_ref()
    if not base:
        return None
    return base if base.startswith("origin/") else f"origin/{base}"


def _merge_group_mismatch(result: ApprovalResult, group) -> str | None:
    if result.head != group.head_sha or result.head_dirty:
        return (
            f"checked commit {result.head[:12]} is not the merge-group commit "
            f"{group.head_sha[:12]}; check out github.sha on merge_group events"
        )
    if result.base != group.base_sha:
        return (
            f"compared with {result.base[:12]}, not the merge group's base "
            f"{group.base_sha[:12]}; pass --base with merge_group.base_sha"
        )
    return None


def _merge_group_approval(path, result: ApprovalResult, group):
    from skylos.cicd.merge_group import find_group_approval

    return find_group_approval(
        path,
        group,
        result.vetoes,
        non_human_logins=result.config.non_human_logins,
    )


def _merge_group_info(group, human) -> dict | None:
    if group is None:
        return None
    info = getattr(human, "merge_group", None)
    return dict(info) if info else {**group.to_dict(), "pull_requests": []}


def _event_base_ref() -> str | None:
    """pull_request_review runs have no GITHUB_BASE_REF; the event does."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return None
    try:
        if os.path.getsize(path) > 25 * 1024 * 1024:
            return None
        with open(path, encoding="utf-8") as handle:
            event = json.load(handle)
        ref = event["pull_request"]["base"]["ref"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return ref if isinstance(ref, str) and ref else None


def _human_approval(result: ApprovalResult):
    from skylos.cicd.approval_github import (
        GitHubApiError,
        HumanApproval,
        find_human_approval,
        pull_request_context,
    )

    try:
        context = pull_request_context()
    except GitHubApiError as exc:
        return HumanApproval("error", detail=str(exc))
    if context is None:
        return None  # a local run: report the risks only
    return find_human_approval(
        context,
        result.head,
        non_human_logins=result.config.non_human_logins,
    )


def decide(result: ApprovalResult, human) -> tuple[int, str]:
    """Exit code and verdict. Incomplete analysis and review errors never pass."""
    if not result.complete:
        return EXIT_INCOMPLETE, "incomplete"
    if not result.vetoes:
        return EXIT_PASS, "eligible"
    if human is None:
        return EXIT_NEEDS_HUMAN, "needs_human_approval"
    if human.status == "approved":
        return EXIT_PASS, "human_approved"
    if human.status == "error":
        return EXIT_INCOMPLETE, "review_check_failed"
    return EXIT_NEEDS_HUMAN, "needs_human_approval"


def build_payload(
    result: ApprovalResult,
    human,
    *,
    exit_code: int,
    verdict: str,
    merge_group: dict | None = None,
) -> dict:
    from skylos import __version__

    config = result.config
    payload = {
        "approval": {
            "schema": SCHEMA,
            "check": CHECK_NAME,
            "verdict": verdict,
            "passed": exit_code == EXIT_PASS,
            "eligible": result.eligible,
            "complete": result.complete,
            "needs_human_approval": result.classes_found,
            "human_approval": human.to_dict() if human is not None else None,
            "vetoes": [risk.to_dict() for risk in result.vetoes],
            "advisories": [risk.to_dict() for risk in result.advisories],
            "classes_checked": list(result.classes_checked),
            "classes_incomplete": [
                {"class": name, "reason": reason}
                for name, reason in result.classes_incomplete.items()
            ],
            "classes_disabled": result.classes_disabled,
            "base": result.base,
            "base_ref": result.base_ref,
            "head": result.head,
            "head_dirty": result.head_dirty,
            "diff": {"files": result.files_changed, "lines": result.lines_changed},
            "excluded": result.excluded,
            "settings": {
                "configured": config.configured,
                "large_diff_lines": config.large_diff_lines,
                "large_diff_files": config.large_diff_files,
                "problems": list(config.problems),
            },
            "exit_code": exit_code,
            "skylos_version": __version__,
        }
    }
    if merge_group is not None:
        payload["approval"]["merge_group"] = merge_group
    return payload


def _error_payload(message: str, base_ref: str | None) -> dict:
    from skylos import __version__

    return {
        "approval": {
            "schema": SCHEMA,
            "check": CHECK_NAME,
            "verdict": "error",
            "passed": False,
            "eligible": False,
            "complete": False,
            "error": message,
            "needs_human_approval": [],
            "human_approval": None,
            "vetoes": [],
            "advisories": [],
            "classes_checked": [],
            "classes_incomplete": [
                {"class": name, "reason": message} for name in VETO_CLASSES
            ],
            "classes_disabled": [],
            "base": None,
            "base_ref": base_ref,
            "head": None,
            "exit_code": EXIT_INCOMPLETE,
            "skylos_version": __version__,
        }
    }


def _report_error(fmt, err, message: str, *, base_ref: str | None = None) -> int:
    payload = _error_payload(message, base_ref)
    if fmt == "json":
        print(json.dumps(payload, indent=2))
    elif fmt == "markdown":
        print(render_markdown(payload))
    err.print(Text(f"skylos cicd risk-review: {message}", style="red"), soft_wrap=True)
    _write_github_files(payload)
    return EXIT_INCOMPLETE


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def headline(payload: dict) -> str:
    data = payload["approval"]
    verdict = data["verdict"]
    if verdict == "eligible":
        return "No risk class found: any approval is enough"
    if verdict == "human_approved":
        login = (data.get("human_approval") or {}).get("login") or "a person"
        counts = Counter(v["class"] for v in data["vetoes"])
        listed = ", ".join(f"{name} ({counts[name]})" for name in data["needs_human_approval"])
        return f"Human-approved: {login} approved these risks: {listed}"
    if verdict == "needs_human_approval":
        return "Needs a human approval: " + _class_summary(data)
    if verdict == "review_check_failed":
        detail = (data.get("human_approval") or {}).get("detail") or ""
        return (
            "Could not check for a human approval ("
            + detail
            + "); risks: "
            + _class_summary(data)
        )
    if verdict == "incomplete":
        names = ", ".join(item["class"] for item in data["classes_incomplete"])
        return f"Could not decide: {names} not fully checked"
    return f"Could not decide: {data.get('error') or 'the analysis failed'}"


def _class_summary(data: dict) -> str:
    parts = []
    for name in data["needs_human_approval"]:
        risks = [v for v in data["vetoes"] if v["class"] == name]
        where = _location(risks[0]) or risks[0]["reason"].split(" (", 1)[0][:80]
        more = f" +{len(risks) - 1} more" if len(risks) > 1 else ""
        parts.append(f"{name} ({where}{more})")
    return ", ".join(parts)


def _location(risk: dict) -> str:
    if not risk.get("file"):
        return ""
    return f"{risk['file']}:{risk['line']}" if risk.get("line") else risk["file"]


def _status_word(data: dict) -> str:
    return {
        "eligible": "PASSED",
        "human_approved": "PASSED",
        "needs_human_approval": "NEEDS A HUMAN APPROVAL",
    }.get(data["verdict"], "INCOMPLETE")


def _print_text(console: Console, payload: dict) -> None:
    data = payload["approval"]
    title = Text(f"{CHECK_NAME}: {_status_word(data)} (exit {data['exit_code']})")
    title.stylize("bold green" if data["passed"] else "bold red")
    console.print(title, soft_wrap=True)
    console.print(Text(headline(payload)), soft_wrap=True)
    console.print(
        Text(
            f"Compared {str(data['base'])[:12]} (merge base of {data['base_ref']}) "
            f"with {str(data['head'])[:12]}"
            + (" and uncommitted changes" if data.get("head_dirty") else "")
            + f"; {data['diff']['files']} files, {data['diff']['lines']} lines changed",
            style="dim",
        ),
        soft_wrap=True,
    )
    if data["vetoes"]:
        console.print()
        console.print(Text("Risks that need a human approval:", style="bold"))
        for risk in data["vetoes"][:_LISTED_RISKS]:
            console.print(Text("  " + _risk_line(risk)), soft_wrap=True)
        if len(data["vetoes"]) > _LISTED_RISKS:
            console.print(f"  ... {len(data['vetoes']) - _LISTED_RISKS} more (--format json lists all)")
    human = data.get("human_approval")
    if human and human.get("ignored"):
        console.print(
            Text("Approvals that do not count: " + "; ".join(human["ignored"][:10])),
            soft_wrap=True,
        )
    for line in merge_group_lines(data):
        console.print(Text(line), soft_wrap=True)
    if data["advisories"]:
        console.print()
        console.print(Text("Advice (needs no approval):", style="bold"))
        for risk in data["advisories"][:_LISTED_ADVICE]:
            console.print(Text("  " + _risk_line(risk), style="dim"), soft_wrap=True)
        if len(data["advisories"]) > _LISTED_ADVICE:
            console.print(f"  ... {len(data['advisories']) - _LISTED_ADVICE} more")
    console.print()
    for item in data["classes_incomplete"]:
        console.print(
            Text(f"Not fully checked: {item['class']}: {item['reason']}", style="yellow"),
            soft_wrap=True,
        )
    console.print(
        Text("Checked: " + (", ".join(data["classes_checked"]) or "none"), style="dim"),
        soft_wrap=True,
    )
    if data["classes_disabled"]:
        console.print(
            Text("Turned off in [tool.skylos.approval]: " + ", ".join(data["classes_disabled"]), style="dim"),
            soft_wrap=True,
        )
    for problem in data["settings"]["problems"]:
        console.print(Text(f"Setting ignored: {problem}", style="yellow"), soft_wrap=True)


def merge_group_lines(data: dict) -> list[str]:
    """What the merge queue run checked, one line per pull request with risks."""
    group = data.get("merge_group")
    if not isinstance(group, dict):
        return []
    number = group.get("pull_request")
    lines = [
        "Merge queue: compared the merge-group commit "
        f"{str(group.get('head_sha'))[:12]} with its base "
        f"{str(group.get('base_sha'))[:12]}"
        + (f" (queued pull request #{number})" if number else "")
    ]
    for entry in group.get("pull_requests") or []:
        if not entry.get("risk_count"):
            continue
        approval = entry.get("approval") or {}
        status = approval.get("status")
        if status == "approved":
            state = f"approved by {approval.get('login')}"
        elif status == "missing":
            state = "no person with write access approved its head commit"
        elif status == "error":
            state = f"could not check: {approval.get('detail')}"
        else:
            state = "not checked"
        head = entry.get("head_sha")
        lines.append(
            f"  #{entry['number']}: {', '.join(entry.get('risks') or [])}; {state}"
            + (f" (head {str(head)[:12]})" if head else "")
        )
    return lines


def _risk_line(risk: dict) -> str:
    parts = [risk["class"]]
    if risk.get("rule_id"):
        parts.append(risk["rule_id"])
    location = _location(risk)
    if location:
        parts.append(location)
    return "  ".join(parts) + f"  {risk['reason']}"


def render_markdown(payload: dict) -> str:
    from skylos.cicd.evidence import sanitize_markdown_text as clean

    data = payload["approval"]
    lines = [
        f"### {CHECK_NAME}: {_status_word(data)}",
        "",
        clean(headline(payload), max_length=1000),
        "",
    ]
    if data["vetoes"]:
        lines += [
            "| Risk class | Rule | Where | Why |",
            "|---|---|---|---|",
        ]
        for risk in data["vetoes"][:_LISTED_RISKS]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{risk['class']}`",
                        clean(risk.get("rule_id") or "-", max_length=40),
                        clean(_location(risk) or "-", max_length=200),
                        clean(risk["reason"], max_length=300),
                    ]
                )
                + " |"
            )
        if len(data["vetoes"]) > _LISTED_RISKS:
            lines.append(f"\n{len(data['vetoes']) - _LISTED_RISKS} more in `--format json`.")
        lines.append("")
    human = data.get("human_approval")
    if human and human.get("ignored"):
        lines.append(
            "Approvals that do not count: "
            + clean("; ".join(human["ignored"][:10]), max_length=1000)
        )
        lines.append("")
    group_lines = merge_group_lines(data)
    if group_lines:
        lines += [clean(line, max_length=500) for line in group_lines]
        lines.append("")
    if data["vetoes"] and data["verdict"] == "needs_human_approval":
        if data.get("merge_group"):
            lines.append(
                "A person with write access approving the pull request's head "
                "commit, then queueing it again, turns this check green; bot "
                "approvals and approvals of older commits do not."
            )
        else:
            lines.append(
                "A person with write access approving the head commit turns this "
                "check green; bot approvals and approvals of older commits do not."
            )
        lines.append("")
    for item in data["classes_incomplete"][:20]:
        lines.append(
            f"- Not fully checked: `{item['class']}`: "
            + clean(item["reason"], max_length=300)
        )
    checked = ", ".join(f"`{name}`" for name in data["classes_checked"]) or "none"
    lines.append(f"\nChecked: {checked}.")
    if data.get("advisories"):
        lines.append(
            f"{len(data['advisories'])} advice item(s) need no approval "
            "(see the job log)."
        )
    if data.get("base"):
        lines.append(
            f"Base `{str(data['base'])[:12]}` (merge base of "
            f"`{clean(data['base_ref'], max_length=100)}`), head "
            f"`{str(data['head'])[:12]}`."
        )
    return "\n".join(lines)


def _write_github_files(payload: dict) -> None:
    """Step summary and step outputs; never changes the exit code."""
    from skylos.commands.defend_cmd import (
        _append_github_step_summary,
        _github_step_summary_path,
    )

    data = payload["approval"]
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        path = _github_step_summary_path(summary)
        if path is not None:
            try:
                _append_github_step_summary(path, render_markdown(payload))
            except Exception:
                logger.debug("could not write the step summary", exc_info=True)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        path = _github_step_summary_path(output)
        if path is not None:
            values = {
                "passed": str(bool(data["passed"])).lower(),
                "eligible": str(bool(data["eligible"])).lower(),
                "classes": ",".join(data["needs_human_approval"]),
            }
            _append_github_step_summary(
                path, "\n".join(f"{key}={value}" for key, value in values.items())
            )
