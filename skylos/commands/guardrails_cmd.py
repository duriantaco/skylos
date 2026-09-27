"""``skylos agent guardrails``: show (and fetch) the agent guardrail policy.

Prints what the agent hooks enforce on this machine for this project: the
organization policy from Skylos Cloud (Agent guardrails) when there is one,
otherwise local ``[tool.skylos.guardrails]`` settings or the built-in
defaults, and whether block/warn events are reported to the organization.
``--refresh`` fetches the policy now instead of waiting for the hooks'
background refresh.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from pathlib import Path


def add_guardrails_parser(agent_sub) -> None:
    parser = agent_sub.add_parser(
        "guardrails",
        help="Show the agent guardrail policy the hooks enforce here",
        description=(
            "Show whether your organization's agent guardrail policy is in "
            "force on this machine, the effective settings, and whether "
            "guardrail events are reported. --refresh fetches it now."
        ),
    )
    parser.add_argument(
        "path", nargs="?", default=".", help="Project directory (default: .)."
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Fetch the organization policy from Skylos Cloud now.",
    )
    parser.add_argument(
        "--json", action="store_true", help="Print the effective settings as JSON."
    )


def run_guardrails_command(
    args: argparse.Namespace,
    *,
    print_func: Callable[[str], None] = print,
    env: dict[str, str] | None = None,
    home: Path | None = None,
    post=None,
) -> int:
    from skylos.cloud import guardrails
    from skylos.commands.hook_cmd import _git_root

    start = Path(getattr(args, "path", ".") or ".").expanduser()
    if not start.is_dir():
        print_func(f"Not a directory: {start}")
        return 1
    root = _git_root(start.resolve())
    env = dict(os.environ) if env is None else env
    if getattr(args, "json", False):
        if getattr(args, "refresh", False):
            guardrails.refresh_policy(
                root,
                env,
                home=home,
                agents=guardrails.detect_installed_agents(root),
                post=post,
            )
        context = guardrails.load_context(root, env, home=home)
        print_func(
            json.dumps(
                {
                    "source": context.source,
                    "organization": context.org_name,
                    "policy_version": context.org_version,
                    "allow_local_loosening": context.allow_local_loosening,
                    "report_events": context.report_events,
                    "settings": context.settings.to_dict(),
                    "reason": context.reason,
                    "ignored_local_settings": context.local_problems,
                },
                indent=2,
            )
        )
        return 0
    if getattr(args, "refresh", False):
        return guardrails.refresh_and_describe(
            root, env, print_func=print_func, home=home, post=post
        )
    context = guardrails.load_context(root, env, home=home)
    print_func("Agent guardrails:")
    for line in guardrails.describe(context, home=home):
        print_func(line if line.startswith("  ") else f"  {line}")
    for notice_id, _text in context.notices:
        if notice_id.startswith("reporting:"):
            guardrails.mark_notice_shown(context, notice_id)
    return 0


def refresh_quietly(
    start: Path | None = None,
    *,
    print_func: Callable[[str], None] = print,
) -> None:
    """Fetch the policy after login / sync pull / warm-cache. Never raises."""
    try:
        from skylos.cloud import guardrails
        from skylos.commands.hook_cmd import _git_root

        root = _git_root((start or Path.cwd()).resolve())
        guardrails.refresh_and_describe(
            root,
            dict(os.environ),
            print_func=print_func,
            quiet_when_not_logged_in=True,
        )
    except Exception as exc:  # the calling command already succeeded
        print_func(
            f"Agent guardrails: could not refresh the policy ({type(exc).__name__})."
        )
