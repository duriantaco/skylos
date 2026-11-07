"""CI job and agent hook inventories for uploads (``ci_inventory``, ``agent_hooks``).

ca9 builds both (``ca9.api.ci_inventory`` and the ``inventory`` part of
``ca9.api.agent_config``). Skylos re-bounds them before they leave the
machine: known keys only, capped lists, names instead of values (secret
names must be identifiers, URLs are reduced to ``scheme://host``, token-like
text is replaced), and only files Git tracks or does not ignore. Scans build
them for the whole repository (the Git top), even when only a subfolder was
scanned: CI workflows and agent configs live at the top. Skylos Cloud uses them to tell which jobs could have
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
MAX_CI_LIST = 100
MAX_KEYS = 40
MAX_HOOKS = 200
MAX_SERVERS = 200
MAX_TEXT = 200
MAX_COMMAND = 200
MAX_DEPTH = 5
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,99}")
_URL = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*)://([^\s/'\"?#]+)[^\s'\"]*")
_TOKEN = re.compile(
    r"\b(?:gh[pousr]_|github_pat_|npm_|pypi-|sk-ant-|sk-|xox[abprs]-|glpat-)[A-Za-z0-9_\-]{8,}"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_\-]{35}"
    r"|(?<![A-Za-z0-9])(?![0-9a-f]{40}(?![A-Za-z0-9]))[A-Za-z0-9+/_\-]{40,}={0,2}"
)
_VALUE = r"(\"[^\"]*\"|'[^']*'|[^\s'\"]+)"
_SECRET_NAME = (
    r"[A-Za-z0-9_.-]*(?:pass|passwd|password|secret|token|key|auth|credential)"
    r"[A-Za-z0-9_.-]*"
)
_AUTH_HEADER = re.compile(
    r"(?i)\b((?:proxy-)?authorization)(\s*:\s*)"
    r"(?:(?:bearer|basic|token|digest|negotiate)\s+)?[^\s'\"]+"
)
_BEARER = re.compile(r"(?i)\b(bearer)(\s+)[A-Za-z0-9._~+/=\-]{6,}")
_USER_OPTION = re.compile(
    r"(?<!\S)(-u|--user|--username-password)(\s+|=)([^\s:'\"]+):" + _VALUE
)
_USERINFO = re.compile(r"\b([\w.%+-]+):([^\s@/:'\"]+)@(?=[\w.-])")
_SECRET_OPTION = re.compile(
    r"(?i)(?<!\S)(--[a-z0-9-]*(?:password|passwd|pass|token|secret|api-?key|apikey|auth|credential)"
    r"[a-z0-9-]*)(=|\s+)(?!-|\$)" + _VALUE
)
_SECRET_ASSIGN = re.compile(
    r"(?i)\b(" + _SECRET_NAME + r")([\"']?\s*[=:]\s*)(?!\$)" + _VALUE
)
_SEGMENTS = re.compile(r"(\s*(?:&&|\|\||;|\|)\s*)")
_PASSWORD_P_PROGRAMS = frozenset(
    {
        "mysql",
        "mysqldump",
        "mysqladmin",
        "mysqlimport",
        "mysqlsh",
        "mariadb",
        "mariadb-dump",
        "sshpass",
    }
)


def _url_host(match: re.Match) -> str:
    return f"{match.group(1)}://{match.group(2).rsplit('@', 1)[-1]}"


def _secret_value(match: re.Match) -> str:
    return f"{match.group(1)}{match.group(2)}[redacted]"


def _program(tokens: list[str]) -> str:
    for token in tokens:
        if token in {"sudo", "env", "exec", "command"} or re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=\S*", token
        ):
            continue
        return token.rsplit("/", 1)[-1].strip("'\"")
    return ""


def _password_p(segment: str) -> str:
    """``-p`` takes a password for MySQL clients, ``sshpass`` and ``login``
    subcommands (``docker login -p``); elsewhere it is a port or a flag."""
    tokens = segment.split(" ")
    if _program(tokens) not in _PASSWORD_P_PROGRAMS and "login" not in tokens:
        return segment
    kept = []
    redact_next = False
    for token in tokens:
        if redact_next and token and not token.startswith(("-", "$")):
            kept.append("[redacted]")
            redact_next = False
            continue
        redact_next = token == "-p"
        if token.startswith("-p") and len(token) > 2 and not token.startswith("-p$"):
            token = "-p[redacted]"
        kept.append(token)
    return " ".join(kept)


def _redact_segments(text: str) -> str:
    parts = []
    for index, part in enumerate(_SEGMENTS.split(text)):
        if index % 2 == 0:
            part = _password_p(part)
        parts.append(part)
    return "".join(parts)


def redact(value: object, limit: int = MAX_TEXT) -> str:
    """Bounded text without credentials, query strings or token-like values.

    Removed: URL user info, query strings and paths (``scheme://host`` is
    kept), Authorization and Bearer header values, ``user:password`` pairs,
    values of password, token, secret, key, auth and credential options and
    assignments (``$VAR`` references are kept), ``-p`` passwords of MySQL
    clients, ``sshpass`` and ``login`` commands, and known token prefixes.
    """
    if value is None:
        return ""
    text = " ".join(str(value).split())
    text = _URL.sub(_url_host, text)
    text = _AUTH_HEADER.sub(_secret_value, text)
    text = _BEARER.sub(_secret_value, text)
    text = _USER_OPTION.sub(r"\1\2\3:[redacted]", text)
    text = _USERINFO.sub(r"\1:[redacted]@", text)
    text = _SECRET_OPTION.sub(_secret_value, text)
    text = _SECRET_ASSIGN.sub(_secret_value, text)
    text = _redact_segments(text)
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


class _Cut:
    """Set when ``_bounded`` dropped part of a value."""

    def __init__(self):
        self.cut = False

    def mark(self, dropped: bool) -> None:
        if dropped:
            self.cut = True


def _bounded(
    value: Any, depth: int = 0, *, limit: int = MAX_LIST, cut: _Cut | None = None
) -> Any:
    """``value`` with known shapes kept, strings redacted and lists cut at
    ``limit``; ``cut`` records whether anything was dropped, so a cut list is
    never uploaded as complete."""
    if cut is None:
        cut = _Cut()
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, str):
        return redact(value)
    if depth >= MAX_DEPTH:
        cut.mark(True)
        return None
    if isinstance(value, list):
        cut.mark(len(value) > limit)
        return [
            _bounded(item, depth + 1, limit=limit, cut=cut) for item in value[:limit]
        ]
    if isinstance(value, dict):
        items = list(value.items())
        cut.mark(len(items) > MAX_KEYS)
        kept = {}
        for key, item in items[:MAX_KEYS]:
            name = str(key)[:60]
            if name in {"host"}:
                kept[name] = _host(item)
            elif name in {"url", "target"}:
                kept[name] = redact(item)
            elif name in {"names", "publish_credentials"} and isinstance(item, list):
                cut.mark(len(item) > limit)
                kept[name] = [
                    entry
                    for entry in item[:limit]
                    if isinstance(entry, str)
                    and (_IDENTIFIER.fullmatch(entry) or entry == "id-token: write")
                ]
            else:
                kept[name] = _bounded(item, depth + 1, limit=limit, cut=cut)
        return kept
    return None


class _Files:
    """Files of the scanned folder that may appear in an upload."""

    def __init__(self, root: Path):
        from skylos.rules.config.agent_publish import _Scope

        self.scope = _Scope(root, None)
        self.seen: set[tuple] = set()

    def keep(self, file: object) -> str | None:
        relative = _relative(file)
        if relative is None or self.scope.resolve(relative) is None:
            return None
        return relative

    def first(self, file: str, *key) -> bool:
        """Whether this row is the first for its real file (a config reached
        through a link and directly is listed once)."""
        import os

        identity = (os.path.realpath(self.scope.root / file), *key)
        if identity in self.seen:
            return False
        self.seen.add(identity)
        return True


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
        workflow_cut = _Cut()
        kept = _bounded(
            {key: item for key, item in workflow.items() if key != "jobs"},
            limit=MAX_CI_LIST,
            cut=workflow_cut,
        )
        truncated = truncated or workflow_cut.cut
        kept["file"] = file
        kept["jobs"] = []
        for job in workflow.get("jobs") or []:
            if not isinstance(job, dict):
                continue
            if jobs >= MAX_JOBS:
                truncated = True
                break
            job_cut = _Cut()
            row = _bounded(job, limit=MAX_CI_LIST, cut=job_cut)
            if job_cut.cut:
                row["truncated"] = True
            kept["jobs"].append(row)
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
    """(``analysis_summary.agent_hooks`` or None, receipt).

    Configs reached through links inside the repository are listed under
    the path the client opens; a link that leaves the repository or points
    nowhere makes the block ``partial``."""
    from skylos.rules.config.agent_publish import agent_config_with_links, is_own_hook

    function = _function(api, "agent_config")
    if function is None:
        return None, {
            "status": "unavailable",
            "note": "ca9.api.agent_config is unavailable",
        }
    root_path = Path(root).resolve()
    files = _Files(root_path)
    try:
        raw, problem = agent_config_with_links(api, root_path, files.scope)
    except Exception as exc:  # noqa: BLE001 - an engine failure leaves the block out
        return None, {"status": "failed", "error_type": type(exc).__name__}
    if problem is not None:
        return None, {"status": "failed", "note": problem}
    inventory = None
    if isinstance(raw, dict):
        inventory = raw.get("inventory")
    if not isinstance(inventory, dict) or inventory.get("schema") != AGENT_HOOKS_SCHEMA:
        return None, {"status": "failed", "note": "unexpected agent_hooks schema"}
    texts: dict[str, str | None] = {}
    truncated = inventory.get("truncated") is True
    hooks = []
    for hook in inventory.get("hooks") or []:
        if not isinstance(hook, dict):
            continue
        file = files.keep(hook.get("file"))
        if file is None or not files.first(
            file, hook.get("line"), hook.get("event"), hook.get("command")
        ):
            continue
        if len(hooks) >= MAX_HOOKS:
            truncated = True
            break
        if file not in texts:
            texts[file] = files.scope.read(root_path / file)
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
                    "duplicate_keys",
                )
                if key in hook
            }
        )
        row["file"] = file
        row["command"] = redact(hook.get("command"), MAX_COMMAND)
        row["skylos_hook"] = is_own_hook(
            hook.get("command"), root=root_path, settings_text=texts[file]
        )
        hooks.append(row)
    servers = []
    for server in inventory.get("mcp_servers") or []:
        if not isinstance(server, dict):
            continue
        file = files.keep(server.get("file"))
        if file is None or not files.first(
            file, server.get("line"), server.get("name"), server.get("command")
        ):
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
                    "duplicate_keys",
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
        if file is not None and files.first(
            file, override.get("line"), override.get("variable")
        ):
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
    for key in ("duplicate_keys", "duplicates"):
        if key in inventory:
            block[key] = _bounded(inventory[key])
    receipt = {"status": status, "hooks": len(hooks), "mcp_servers": len(servers)}
    problems = raw.get("link_problems") or []
    if problems:
        receipt["link_problems"] = [
            {"file": _relative(item.get("file")) or ".", "reason": item.get("reason")}
            for item in problems[:20]
            if isinstance(item, dict)
        ]
    return block, receipt


__all__ = [
    "AGENT_HOOKS_KEY",
    "AGENT_HOOKS_SCHEMA",
    "CI_INVENTORY_KEY",
    "CI_SCHEMA",
    "agent_hooks_block",
    "ci_inventory_block",
    "redact",
]
