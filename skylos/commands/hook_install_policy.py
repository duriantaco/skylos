"""``[tool.skylos.hooks]``: what the pre-bash hook does with installs it
cannot verify and with git-hook bypasses.

```toml
[tool.skylos.hooks]
direct_source = "ask"        # git/URL/tarball installs, untrusted registries
on_unverified = "ask"        # registry unreachable, name only known at run time
block_hook_bypass = true     # git commit --no-verify, HUSKY=0, core.hooksPath
trusted_registries = ["https://pypi.corp.example/simple", "npm.corp.example"]
```

``"ask"`` asks the user in Claude Code and Cursor. Codex does not support
``ask`` (it would run the command), so ``"ask"`` denies there. ``"allow"``
lets the command run with a visible note; nothing is ever allowed silently.
Invalid values fall back to the defaults, which never allow.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink

ASK = "ask"
DENY = "deny"
ALLOW = "allow"
DECISIONS = (ASK, DENY, ALLOW)
MAX_PYPROJECT_BYTES = 2_000_000


@dataclass(frozen=True)
class InstallPolicy:
    direct_source: str = ASK
    on_unverified: str = ASK
    block_hook_bypass: bool = True
    trusted_registries: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()


def load_install_policy(root: Path | None) -> InstallPolicy:
    data = _hooks_table(root)
    if not data:
        return InstallPolicy()
    problems: list[str] = []
    direct = _decision(data, "direct_source", problems)
    unverified = _decision(data, "on_unverified", problems)
    bypass = data.get("block_hook_bypass", True)
    if not isinstance(bypass, bool):
        problems.append("block_hook_bypass must be true or false")
        bypass = True
    trusted_raw = data.get("trusted_registries", [])
    trusted: list[str] = []
    if isinstance(trusted_raw, list):
        trusted = [str(item).strip() for item in trusted_raw if str(item).strip()]
    else:
        problems.append("trusted_registries must be a list")
    return InstallPolicy(
        direct_source=direct,
        on_unverified=unverified,
        block_hook_bypass=bypass,
        trusted_registries=tuple(trusted),
        problems=tuple(problems),
    )


def _decision(data: dict[str, Any], key: str, problems: list[str]) -> str:
    value = data.get(key, ASK)
    if isinstance(value, str) and value.strip().lower() in DECISIONS:
        return value.strip().lower()
    problems.append(f'{key} must be "ask", "deny" or "allow"')
    return ASK


def _hooks_table(root: Path | None) -> dict[str, Any]:
    if root is None:
        return {}
    try:
        # Refuses symlinks and oversized files: the repository is agent-editable.
        text = read_project_text_no_symlink(Path(root), "pyproject.toml", max_bytes=MAX_PYPROJECT_BYTES)
        if text is None:
            return {}
        try:
            import tomllib
        except ModuleNotFoundError:  # Python < 3.11
            import tomli as tomllib  # type: ignore[no-redef]
        data = tomllib.loads(text)
    except (OSError, ValueError, ImportError):  # TOMLDecodeError is a ValueError
        return {}
    table: Any = data
    for key in ("tool", "skylos", "hooks"):
        table = table.get(key) if isinstance(table, dict) else None
    return table if isinstance(table, dict) else {}


__all__ = ["ALLOW", "ASK", "DENY", "InstallPolicy", "load_install_policy"]
