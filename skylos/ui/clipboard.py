"""Guarded clipboard writes.

Skylos only touches the system clipboard for an interactive human: stdout is a
terminal, the run is not in CI, and the user has not opted out with
``--no-clipboard`` or ``SKYLOS_NO_CLIPBOARD=1``. Redirected, piped, CI and
machine-format runs must never overwrite the clipboard.
"""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)

_CI_ENV_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "JENKINS_URL",
    "BUILD_NUMBER",
    "CIRCLECI",
    "TRAVIS",
    "BITBUCKET_PIPELINE_UUID",
    "AZURE_PIPELINES",
    "TF_BUILD",
    "BUILDKITE",
)

_FALSEY = {"", "0", "false", "no", "off"}


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() not in _FALSEY


def clipboard_copy_allowed(console=None) -> bool:
    if _env_flag("SKYLOS_NO_CLIPBOARD"):
        return False
    if any(_env_flag(name) for name in _CI_ENV_VARS):
        return False
    try:
        if not sys.stdout.isatty():
            return False
    except (AttributeError, ValueError, OSError):
        return False
    if console is not None:
        stream = getattr(console, "file", None)
        try:
            if stream is not None and not stream.isatty():
                return False
        except (AttributeError, ValueError, OSError):
            return False
    return True


def copy_to_clipboard(text: str, console=None) -> str:
    """Copy ``text`` if allowed.

    Returns ``"copied"``, ``"skipped"`` (non-interactive session or opt-out),
    ``"missing"`` (pyperclip not installed) or ``"failed"``.
    """
    if not clipboard_copy_allowed(console):
        return "skipped"
    try:
        import pyperclip
    except ImportError:
        return "missing"
    try:
        pyperclip.copy(text)
    except Exception as exc:  # pyperclip raises its own exception types
        logger.debug("Failed to copy to clipboard: %s", exc)
        return "failed"
    return "copied"
