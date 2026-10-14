"""Say what a diff-scoped gate run had in scope, so "nothing to check" is a
visible, passing result rather than a missing one.

Monorepos often add ``paths:`` filters so a workflow skips changes outside a
package; GitHub then never reports the required check and the pull request
waits forever. The generated workflow has no path filter: the gate always
runs and reports. When none of the changed files is under the scan path, or
every one is an image, font, media or licence file, this module writes a one-line
receipt saying so (console and job summary). It never changes the gate's
exit code: an empty scope is not a finding.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

logger = logging.getLogger(__name__)

# Files no Skylos analyzer reads: images, fonts, media and PDFs. Anything
# else under the scan path might be read (source, manifests, lockfiles,
# workflows, Dockerfiles, secret-bearing config, and Markdown/RST/text, which
# the prompt-injection check SKY-D260 reads), so it counts as in scope.
_NOT_CHECKED_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".avif",
        ".bmp",
        ".tif",
        ".tiff",
        ".pdf",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp4",
        ".mov",
        ".webm",
        ".mp3",
        ".wav",
    }
)
# Extensionless legal files; LICENSE.txt or NOTICE.md are read like any text.
_NOT_CHECKED_NAMES = frozenset({"license", "licence", "notice", "authors"})
_EXAMPLES = 3
_MAX_FILES = 100_000


@dataclass
class ScopeReceipt:
    base: str
    scan_path: str
    changed: int
    under_path: int
    checked: int
    examples: list[str] = field(default_factory=list)

    @property
    def nothing_in_scope(self) -> bool:
        return self.checked == 0

    def reason(self) -> str:
        examples = ", ".join(self.examples)
        more = f" (e.g. {examples})" if examples else ""
        if self.changed == 0:
            return f"no file changed compared with {self.base}"
        if self.under_path == 0:
            return (
                f"none of the {self.changed} changed file(s) is under "
                f"{self.scan_path}{more}"
            )
        where = "" if self.scan_path == "." else f" under {self.scan_path}"
        return (
            f"the {self.under_path} changed file(s){where} are images, fonts, "
            f"media or licence files, which Skylos does not read{more}"
        )

    def line(self) -> str:
        return f"Nothing in scope: {self.reason()}. Skylos had nothing to check in this change."

    def markdown(self) -> str:
        return (
            "### Scope\n\n"
            f"**Nothing in scope:** {self.reason()}. Skylos had nothing to check "
            "in this change, so this check reports on it instead of being skipped.\n"
        )


def _not_checked(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return (
        name in _NOT_CHECKED_NAMES
        or PurePosixPath(name).suffix in _NOT_CHECKED_SUFFIXES
    )


def scope_receipt(path: str | Path, base_ref: str) -> ScopeReceipt | None:
    """The changed files compared with ``base_ref``'s merge base, against the
    scan path. None when Git cannot answer (the gate result stands alone)."""
    from skylos.core.git_context import GitContext

    try:
        target = Path(path).resolve()
        context = GitContext.from_path(target)
        root = Path(context.root).resolve()
        merge_base = context.run("merge-base", base_ref, "HEAD")
        base = merge_base.stdout.strip()
        if merge_base.returncode != 0 or not base:
            return None
        diff = context.run("diff", "--name-only", "-z", "--no-renames", base)
        if diff.returncode != 0:
            return None
        changed = [name for name in diff.stdout.split("\0") if name][:_MAX_FILES]
        scan_dir = target if target.is_dir() else target.parent
        relative = scan_dir.relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        logger.debug("scope receipt unavailable: %s", exc)
        return None
    except Exception:  # never let the receipt break a gate run
        logger.debug("scope receipt unavailable", exc_info=True)
        return None
    prefix = "" if relative in ("", ".") else relative.rstrip("/") + "/"
    under = [name for name in changed if not prefix or name.startswith(prefix)]
    checked = [name for name in under if not _not_checked(name)]
    examples = (under or changed)[:_EXAMPLES]
    return ScopeReceipt(
        base=base_ref,
        scan_path=relative if prefix else ".",
        changed=len(changed),
        under_path=len(under),
        checked=len(checked),
        examples=examples,
    )


def report_scope(path, base_ref, *, console, summary: bool) -> ScopeReceipt | None:
    """Print (and with ``summary`` add to $GITHUB_STEP_SUMMARY) the receipt
    when nothing is in scope. Returns the receipt either way."""
    receipt = scope_receipt(path, base_ref)
    if receipt is None or not receipt.nothing_in_scope:
        return receipt
    from rich.text import Text

    console.print(Text(receipt.line(), style="green"), soft_wrap=True)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and step_summary:
        from skylos.commands.defend_cmd import (
            _append_github_step_summary,
            _github_step_summary_path,
        )

        target = _github_step_summary_path(step_summary)
        if target is not None:
            try:
                _append_github_step_summary(target, receipt.markdown())
            except Exception:
                logger.debug("could not write the scope receipt", exc_info=True)
    return receipt
