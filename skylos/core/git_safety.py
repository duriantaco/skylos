from __future__ import annotations

import os
from collections.abc import Mapping, Sequence


_READ_ONLY_CONFIG_OVERRIDES = (
    "core.fsmonitor=false",
    f"core.hooksPath={os.devnull}",
    "core.untrackedCache=false",
    "diff.external=",
    "diff.trustExitCode=false",
)


def read_only_git_environment(
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return an environment that cannot inject Git configuration or helpers."""

    source = os.environ if environ is None else environ
    environment = {
        key: value for key, value in source.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def read_only_git_command(
    args: Sequence[str],
    *,
    config_overrides: Sequence[str] = (),
    literal_pathspecs: bool = False,
) -> list[str]:
    """Build a Git command with repository-configured execution disabled."""

    command = ["git", "--no-pager", "--no-replace-objects"]
    if literal_pathspecs:
        command.append("--literal-pathspecs")
    for override in (*_READ_ONLY_CONFIG_OVERRIDES, *config_overrides):
        command.extend(("-c", override))
    command.extend(args)
    return command
