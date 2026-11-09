#!/usr/bin/env python3
"""Deprecated alias: install Git pre-push only, never agent callbacks."""

from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import install_eval_push as push_installer  # noqa: E402


def install_hooks(repo: Path, python: Path, *, dry_run: bool = False) -> dict:
    """Compatibility name retained under the user's push-only policy."""
    return push_installer.install_push(repo, python, dry_run=dry_run)


def main(argv: list[str] | None = None) -> int:
    print(
        "install_eval_hooks.py is deprecated; only Git pre-push is installed.",
        file=sys.stderr,
    )
    return push_installer.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
