"""CI job and agent hook inventories for uploads (``ci_inventory``, ``agent_hooks``).

ca9 builds both (``ca9.api.ci_inventory`` and the ``inventory`` part of
``ca9.api.agent_config``). Skylos re-bounds them before they leave the
machine: known keys only, capped lists, names instead of values (secret
names must be identifiers, URLs are reduced to ``scheme://host``, token-like
text is replaced), and only files in the scanned folder that Git tracks or
does not ignore. Skylos Cloud uses them to tell which jobs could have
installed a malicious version, what they could reach, and which branches
carry agent or editor hooks.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

CI_INVENTORY_KEY = "ci_inventory"
AGENT_HOOKS_KEY = "agent_hooks"
CI_SCHEMA = "ca9.ci_inventory.v1"
AGENT_HOOKS_SCHEMA = "ca9.agent_hooks.v1"
CI_STATUSES = frozenset({"complete", "partial", "yaml_unavailable"})
AGENT_STATUSES = frozenset({"complete", "partial"})
MAX_WORKFLOWS = 200
MAX_JOBS = 500
MAX_LIST = 50
MAX_HOOKS = 200
MAX_SERVERS = 200
MAX_TEXT = 200
MAX_COMMAND = 200
MAX_DEPTH = 5
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,99}")
_URL = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*)://([^\s/'\"?#]+)[^\s'\"]*")
_TOKEN = re.compile(
    r"\b(?:gh[pousr]_|github_pat_|npm_|pypi-|sk-|xox[abprs]-|glpat-|AKIA)[A-Za-z0-9_\-]{8,}"
    r"|(?<![A-Za-z0-9])(?![0-9a-f]{40}(?![A-Za-z0-9]))[A-Za-z0-9+/_\-]{40,}={0,2}"
)
_SECRET_WORDS = (
    r"[A-Za-z0-9_-]*(?:token|secret|password|passwd|api[_-]?key|auth)[A-Za-z0-9_-]*"
)
_SECRET_ASSIGN = re.compile(
    r"(?i)\b(" + _SECRET_WORDS + r")(\s*[=:]\s*)(?!\$)(\"[^\"]*\"|'[^']*'|[^\s'\"]+)"
)
_SECRET_FLAG = re.compile(
    r"(?i)(?<!\S)(--?" + _SECRET_WORDS + r")(\s+)(?!-|\$)(\"[^\"]*\"|'[^']*'|[^\s'\"]+)"
)


def _url_host(match: re.Match) -> str:
    return f"{match.group(1)}://{match.group(2).rsplit('@', 1)[-1]}"


def _secret_value(match: re.Match) -> str:
    return f"{match.group(1)}{match.group(2)}[redacted]"


def redact(value: object, limit: int = MAX_TEXT) -> str:
    """Bounded text without credentials, query strings or token-like values."""
    if value is None:
        return ""
    text = " ".join(str(value).split())
    text = _URL.sub(_url_host, text)
    text = _SECRET_ASSIGN.sub(_secret_value, text)
    text = _SECRET_FLAG.sub(_secret_value, text)
    text = _TOKEN.sub("[redacted]", text)
    return text[:limit]


def _host(value: object) -> str:
    text = str(value or "").strip()
    match = _URL.match(text)
    if match:
        text = match.group(2)
    return text.rsplit("@", 1)[-1].split("/", 1)[0].split("?", 1)[0][:253]


def _relative(value: object) -> str | None:
    text = str(value or "").replace("\\", "/")
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or ".." in pure.parts or len(text) > 400:
        return None
    return pure.as_posix()


def _bounded(value: Any, depth: int = 0) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, str):
        return redact(value)
    if depth >= MAX_DEPTH:
        return None
    if isinstance(value, list):
        return [_bounded(item, depth + 1) for item in value[:MAX_LIST]]
    if isinstance(value, dict):
        kept = {}
        for key, item in list(value.items())[:40]:
            name = str(key)[:60]
            if name in {"host"}:
                kept[name] = _host(item)
            elif name in {"url", "target"}:
                kept[name] = redact(item)
            elif name in {"names", "publish_credentials"} and isinstance(item, list):
                kept[name] = [
                    entry
                    for entry in item[:MAX_LIST]
                    if isinstance(entry, str)
                    and (_IDENTIFIER.fullmatch(entry) or entry == "id-token: write")
                ]
            else:
                kept[name] = _bounded(item, depth + 1)
        return kept
    return None


class _Files:
    """Files of the scanned folder that may appear in an upload."""

    def __init__(self, root: Path):
        from skylos.rules.config.agent_publish import _Scope

        self.scope = _Scope(root, None)

    def keep(self, file: object) -> str | None:
        relative = _relative(file)
        if relative is None or self.scope.resolve(relative) is None:
            return None
        return relative


def _function(api, name: str):
    if api is None or not hasattr(api, name) or not callable(getattr(api, name)):
        return None
    return getattr(api, name)


def ci_inventory_block(root: str | Path, api) -> tuple[dict | None, dict]:
    """(``analysis_summary.ci_inventory`` or None, receipt)."""
    function = _function(api, "ci_inventory")
    if function is None:
        return None, {
            "status": "unavailable",
            "note": "ca9.api.ci_inventory is unavailable",
        }
    root_path = Path(root).resolve()
    try:
        raw = function(str(root_path), max_jobs=MAX_JOBS)
    except Exception as exc:  # noqa: BLE001 - an engine failure leaves the block out
        return None, {"status": "failed", "error_type": type(exc).__name__}
    if not isinstance(raw, dict) or raw.get("schema") != CI_SCHEMA:
        return None, {"status": "failed", "note": "unexpected ci_inventory schema"}
    files = _Files(root_path)
    workflows = []
    jobs = 0
    truncated = raw.get("truncated") is True
    for workflow in raw.get("workflows") or []:
        if not isinstance(workflow, dict):
            continue
        file = files.keep(workflow.get("file"))
        if file is None:
            continue
        if len(workflows) >= MAX_WORKFLOWS:
            truncated = True
            break
        kept = _bounded({key: item for key, item in workflow.items() if key != "jobs"})
        kept["file"] = file
        kept["jobs"] = []
        for job in workflow.get("jobs") or []:
            if not isinstance(job, dict):
                continue
            if jobs >= MAX_JOBS:
                truncated = True
                break
            kept["jobs"].append(_bounded(job))
            jobs += 1
        workflows.append(kept)
    status = str(raw.get("status") or "")
    if status not in CI_STATUSES:
        status = "partial"
    block = {
        "schema": CI_SCHEMA,
        "status": status,
        "truncated": truncated,
        "workflows": workflows,
    }
    skipped = [
        {
            "file": _relative(item.get("file")) or ".",
            "reason": redact(item.get("reason"), 120),
        }
        for item in (raw.get("skipped") or [])[:20]
        if isinstance(item, dict)
    ]
    if skipped:
        block["skipped"] = skipped
    return block, {"status": status, "workflows": len(workflows), "jobs": jobs}


def agent_hooks_block(root: str | Path, api) -> tuple[dict | None, dict]:
    """(``analysis_summary.agent_hooks`` or None, receipt)."""
    from skylos.core.safe_cache_io import read_project_text_no_symlink
    from skylos.rules.config.agent_publish import is_skylos_hook_command

    function = _function(api, "agent_config")
    if function is None:
        return None, {
            "status": "unavailable",
            "note": "ca9.api.agent_config is unavailable",
        }
    root_path = Path(root).resolve()
    try:
        raw = function(str(root_path))
    except Exception as exc:  # noqa: BLE001 - an engine failure leaves the block out
        return None, {"status": "failed", "error_type": type(exc).__name__}
    inventory = None
    if isinstance(raw, dict):
        inventory = raw.get("inventory")
    if not isinstance(inventory, dict) or inventory.get("schema") != AGENT_HOOKS_SCHEMA:
        return None, {"status": "failed", "note": "unexpected agent_hooks schema"}
    files = _Files(root_path)
    texts: dict[str, str | None] = {}
    truncated = inventory.get("truncated") is True
    hooks = []
    for hook in inventory.get("hooks") or []:
        if not isinstance(hook, dict):
            continue
        file = files.keep(hook.get("file"))
        if file is None:
            continue
        if len(hooks) >= MAX_HOOKS:
            truncated = True
            break
        if file not in texts:
            texts[file] = read_project_text_no_symlink(
                root_path, file, max_bytes=2_000_000
            )
        row = _bounded(
            {
                key: hook.get(key)
                for key in (
                    "kind",
                    "event",
                    "line",
                    "matcher",
                    "label",
                    "via",
                    "handler_type",
                )
                if key in hook
            }
        )
        row["file"] = file
        row["command"] = redact(hook.get("command"), MAX_COMMAND)
        row["skylos_hook"] = is_skylos_hook_command(
            hook.get("command"), root=root_path, settings_text=texts[file]
        )
        hooks.append(row)
    servers = []
    for server in inventory.get("mcp_servers") or []:
        if not isinstance(server, dict):
            continue
        file = files.keep(server.get("file"))
        if file is None:
            continue
        if len(servers) >= MAX_SERVERS:
            truncated = True
            break
        row = _bounded(
            {
                key: server.get(key)
                for key in (
                    "name",
                    "ecosystem",
                    "package",
                    "version",
                    "pinned",
                    "line",
                    "transport",
                    "fetches",
                    "launcher",
                    "url",
                )
                if key in server
            }
        )
        row["file"] = file
        row["command"] = redact(server.get("command"), MAX_COMMAND)
        servers.append(row)
    overrides = []
    for override in (inventory.get("env_overrides") or [])[:MAX_LIST]:
        if not isinstance(override, dict):
            continue
        file = files.keep(override.get("file"))
        if file is not None:
            row = _bounded(
                {key: override.get(key) for key in ("variable", "target", "line")}
            )
            row["file"] = file
            overrides.append(row)
    status = str(inventory.get("status") or "complete")
    if status not in AGENT_STATUSES:
        status = "partial"
    block = {
        "schema": AGENT_HOOKS_SCHEMA,
        "status": status,
        "truncated": truncated,
        "hooks": hooks,
        "mcp_servers": servers,
        "env_overrides": overrides,
    }
    return block, {"status": status, "hooks": len(hooks), "mcp_servers": len(servers)}


__all__ = [
    "AGENT_HOOKS_KEY",
    "AGENT_HOOKS_SCHEMA",
    "CI_INVENTORY_KEY",
    "CI_SCHEMA",
    "agent_hooks_block",
    "ci_inventory_block",
    "redact",
]
