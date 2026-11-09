"""Agent/editor configuration and publish-job findings from ca9.

ca9 (``ca9.api.agent_config`` and ``ca9.api.audit_workflows``) reads the
files; this module turns its findings into Skylos rules:

- ``SKY-D365`` committed agent hook command (Claude Code, Gemini, Cursor,
  Codex), ``SKY-D366`` editor task that runs when the folder opens,
  ``SKY-D367`` MCP server without an exact version, ``SKY-D368`` MCP server
  launched from a hidden home path, ``SKY-D369`` MCP package imitating a
  vendor, ``SKY-D370`` agent API base URL overridden in the repository,
  ``SKY-D377`` agent config whose duplicated keys hide what runs.
- ``SKY-D371`` unpinned tool in a job holding publish credentials,
  ``SKY-D372`` unverified download reaching the publish step, ``SKY-D373``
  OIDC publish job without an environment, ``SKY-D374`` publish workflow
  started by ``workflow_dispatch`` or a push to any branch, ``SKY-D376``
  secrets passed to a reusable workflow from another repository.

Messages, values and evidence go through ``ci_agent_inventory.redact``:
findings are uploaded, and hook commands can carry credentials.

Every ca9 row must name a regular file inside the scanned folder. In a diff
scan only files Git tracks count; a full scan also keeps untracked files Git
does not ignore. Hooks written by ``skylos agent install-hooks`` are not
reported (see :func:`is_own_hook`). A missing or failing ca9 function adds
nothing here; diff scans record it as an analysis error when an agent or
workflow file changed (``supply_chain_diff``), and ``--sca`` scans note it in
``analysis_summary.supply_chain_checks``.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any

from skylos.core.skylos_hooks import is_skylos_hook_command
from skylos.rules.config.agent_files import (
    LinkedConfigs,
    call_on_copy,
    contained,
    link_components,
    read_text,
    repository_level,
    repository_texts,
)
from skylos.rules.config.findings import config_finding

AGENT_RULES = {
    "agent_hook_command": ("SKY-D365", "HIGH", "agent hook command"),
    "editor_folder_open_task": ("SKY-D366", "HIGH", "editor folder-open task"),
    "mcp_server_unpinned": ("SKY-D367", "MEDIUM", "unpinned MCP server"),
    "mcp_server_hidden_path": ("SKY-D368", "HIGH", "MCP server from a hidden path"),
    "mcp_server_impersonation": (
        "SKY-D369",
        "MEDIUM",
        "MCP package imitating a vendor",
    ),
    "agent_base_url_override": ("SKY-D370", "HIGH", "agent base URL override"),
    "agent_config_ambiguous": ("SKY-D377", "MEDIUM", "ambiguous agent config"),
}
PUBLISH_RULES = {
    "unpinned_tool_in_credentialed_job": (
        "SKY-D371",
        "HIGH",
        "unpinned tool in a publish job",
    ),
    "unverified_download_into_publish": (
        "SKY-D372",
        "HIGH",
        "unverified download reaching publish",
    ),
    "oidc_publish_without_environment": (
        "SKY-D373",
        "HIGH",
        "OIDC publish job without environment",
    ),
    "publish_on_dispatch_or_any_branch": (
        "SKY-D374",
        "HIGH",
        "publish on dispatch or any branch",
    ),
    "credentials_to_remote_reusable_workflow": (
        "SKY-D376",
        "MEDIUM",
        "credentials passed to a remote reusable workflow",
    ),
}
AGENT_RULE_IDS = frozenset(rule for rule, _severity, _name in AGENT_RULES.values())
PUBLISH_RULE_IDS = frozenset(rule for rule, _severity, _name in PUBLISH_RULES.values())
HOOK_RULE_IDS = frozenset({"SKY-D365", "SKY-D366"})
SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
MAX_FINDINGS = 500
MAX_TEXT = 300
MAX_SETTINGS_BYTES = 2_000_000
IDENTITY_KEY = "_change_identity"


def is_own_hook(command: object, *, root: Path, settings_text: str | None) -> bool:
    """Whether a committed hook is one Skylos wrote; scans and uploads ask here."""
    return is_skylos_hook_command(command, root=root, settings_text=settings_text)


def available_rule_ids(api) -> frozenset[str]:
    """Rules this ca9 engine can decide (agent_config, audit_workflows)."""
    found: set[str] = set()
    if api is not None and callable(getattr(api, "agent_config", None)):
        found |= AGENT_RULE_IDS
    if api is not None and callable(getattr(api, "audit_workflows", None)):
        found |= PUBLISH_RULE_IDS
    return frozenset(found)


def _diff_mode(changed_files) -> bool:
    return changed_files is not None or bool(
        str(os.environ.get("SKYLOS_DIFF_BASE") or "").strip()
    )


def _git_files(root: Path, *, tracked_only: bool) -> tuple[Path, set[str]] | None:
    """(git root, repository-relative paths) Git tracks, plus untracked files
    it does not ignore unless ``tracked_only``; None outside Git."""
    from skylos.core.file_discovery import find_git_root
    from skylos.core.git_context import GitContext

    if find_git_root(root) is None:
        return None
    args = ["ls-files", "-z", "--cached", "--full-name"]
    if not tracked_only:
        args += ["--others", "--exclude-standard"]
    try:
        context = GitContext.from_path(root)
        result = context.run(*args)
    except Exception:  # noqa: BLE001 - an unreadable index leaves every file out
        return Path(root), set()
    if result.returncode != 0:
        return Path(root), set()
    return Path(context.root), {item for item in result.stdout.split("\0") if item}


def _changed_paths(root: Path, changed_files) -> set[Path] | None:
    if changed_files is None:
        return None
    paths = set()
    for item in changed_files:
        path = Path(item)
        if not path.is_absolute():
            path = root / path
        paths.add(Path(os.path.abspath(path)))
    return paths


class _Scope:
    """Which ca9-reported files may carry findings.

    A row names the path the agent or editor opens. That path may go through
    symbolic links that stay inside the repository (the Git top, or the
    scanned folder outside Git): the target must be a regular file Git lists
    (a full scan also keeps untracked files Git does not ignore), and so must
    every link on the way. In a diff scan the row counts when the path, its
    target or one of those links changed.
    """

    def __init__(self, root: Path, changed_files):
        self.root = root
        self.changed = _changed_paths(root, changed_files)
        self.git = _git_files(root, tracked_only=_diff_mode(changed_files))
        top = root
        if self.git is not None:
            top = self.git[0]
        self.top = Path(os.path.realpath(top))

    def files(self) -> set[str] | None:
        if self.git is None:
            return None
        return self.git[1]

    def touched(self, path: Path) -> bool:
        if self.changed is None:
            return True
        lexical = Path(os.path.abspath(path))
        candidates = {lexical, Path(os.path.realpath(path))}
        candidates.update(link_components(lexical, self.top))
        return bool(candidates & self.changed)

    def resolve(self, file: object) -> Path | None:
        text = str(file or "")
        pure = PurePosixPath(text.replace("\\", "/"))
        if not text or pure.is_absolute() or ".." in pure.parts:
            return None
        path = self.root / Path(*pure.parts)
        lexical = Path(os.path.abspath(path))
        if not lexical.is_relative_to(self.root):
            return None
        real = Path(os.path.realpath(path))
        if not real.is_file() or not contained(real, self.top):
            return None
        if not self.touched(path):
            return None
        files = self.files()
        if files is not None:
            listed = [real, *link_components(lexical, self.top)]
            for item in listed:
                try:
                    relative = item.relative_to(self.top).as_posix()
                except ValueError:
                    return None
                if relative not in files:
                    return None
        return path

    def read(self, path: Path) -> str | None:
        return read_text(self.top, Path(os.path.realpath(path)))


def _text(value: object, limit: int = MAX_TEXT) -> str:
    """Bounded text with credentials removed: findings are uploaded."""
    from skylos.rules.sca.ci_agent_inventory import redact

    return redact(value, limit)


def _evidence(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    kept: dict[str, Any] = {}
    for key, item in list(value.items())[:24]:
        name = str(key)[:60]
        if isinstance(item, bool) or item is None or isinstance(item, (int, float)):
            kept[name] = item
        elif isinstance(item, str):
            kept[name] = _text(item, 200)
        elif isinstance(item, list):
            kept[name] = [
                _scalar(entry)
                for entry in item[:10]
                if isinstance(entry, (str, int, float, bool))
            ]
    return kept


def _scalar(value):
    if isinstance(value, str):
        return _text(value, 120)
    return value


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    return []


def _sentence(part: str) -> str:
    if part.endswith("."):
        return part
    return f"{part}."


def _severity(finding: dict, default: str) -> str:
    severity = str(finding.get("severity") or "").upper()
    if severity in SEVERITIES:
        return severity
    return default


def _line(finding: dict, path: Path, scope: _Scope, needle: str) -> int:
    line = finding.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        line = 1
    if line > 1 or not needle:
        return line
    text = scope.read(path)
    if not text:
        return line
    quoted = json.dumps(needle)
    for number, row in enumerate(text.splitlines(), 1):
        if quoted in row or f"{needle}:" in row or f"{needle} =" in row:
            return number
    return line


def _message(finding: dict, rule_id: str, label: str) -> str:
    title = _text(finding.get("title"), 240)
    reason = _text(finding.get("reason"), 400)
    remediation = _text(finding.get("remediation"), 240)
    parts = [part for part in (title, reason, remediation) if part]
    if not parts:
        return f"{rule_id}: {label}"
    return " ".join(_sentence(part) for part in parts)


def _raw_value(row: dict) -> object:
    evidence = row.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    return evidence.get("command") or evidence.get("target") or row.get("name")


def finding_identity(rule_id: str, name: object, value: object) -> str:
    """A digest of the rule, the event, task, server or job name, and the
    whole unredacted command or target.

    Shown values are redacted (URL paths, credentials) and cut to 200
    characters, so two different commands can look the same; the digest
    tells them apart. It is what baselines and diff scans compare. It stays
    local: uploads drop ``IDENTITY_KEY``."""
    payload = json.dumps(
        [str(rule_id), str(name or ""), str(value or "")],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def row_identity(rule_id: str, row: dict) -> str:
    return finding_identity(rule_id, row.get("name"), _raw_value(row))


def _finding(
    finding: dict, path: Path, scope: _Scope, rule: tuple, *, domain: str, provider: str
) -> dict:
    rule_id, default_severity, label = rule
    evidence = _evidence(finding.get("evidence"))
    name = _text(finding.get("name"), 120) or label
    needle = ""
    if rule_id in {"SKY-D367", "SKY-D368", "SKY-D369"}:
        needle = name
    value = _text(evidence.get("command") or evidence.get("target") or name, 200)
    result = config_finding(
        rule_id=rule_id,
        domain=domain,
        provider=provider,
        name=name,
        message=_message(finding, rule_id, label),
        file=path,
        line=_line(finding, path, scope, needle),
        severity=_severity(finding, default_severity),
        value=value,
        finding_type=label,
    )
    result["snippet"] = value
    result["metadata"] = {
        "engine": "ca9",
        "signal_type": _text(finding.get("signal_type"), 60),
        "action": _text(finding.get("action"), 20),
        "evidence": evidence,
    }
    result[IDENTITY_KEY] = row_identity(rule_id, finding)
    ecosystem = finding.get("ecosystem")
    if domain == "agent_config" and isinstance(ecosystem, str) and ecosystem:
        result["metadata"]["ecosystem"] = _text(ecosystem, 20)
        result["metadata"]["package_version"] = _text(finding.get("version"), 80)
    return result


def _provider(rule_id: str, finding: dict, path: Path) -> str:
    if rule_id in PUBLISH_RULE_IDS:
        if str(finding.get("ecosystem") or "") == "gitlab-ci":
            return "gitlab"
        return "github"
    kind = str((finding.get("evidence") or {}).get("kind") or "")
    if kind.startswith(("claude", "gemini", "cursor", "codex")):
        return kind.split("_", 1)[0]
    folder = path.parent.name.lstrip(".")
    if rule_id == "SKY-D366" or folder == "vscode":
        return "vscode"
    if rule_id == "SKY-D370" and folder in {"claude", "gemini", "cursor", "codex"}:
        return folder
    return "mcp"


def _call(api, name: str, root: Path):
    if api is None or not hasattr(api, name) or not callable(getattr(api, name)):
        return None, "ca9.api." + name + " is unavailable"
    try:
        result = getattr(api, name)(str(root))
    except Exception as exc:  # noqa: BLE001 - engine failures leave the files unchecked
        return None, f"ca9.api.{name} failed ({type(exc).__name__})"
    if not isinstance(result, dict):
        return None, f"ca9.api.{name} returned no result"
    return result, None


def _within(texts: dict[str, str], top: Path, root: Path) -> dict[str, str]:
    """Client paths relative to ``root`` (they are relative to ``top``)."""
    try:
        prefix = root.relative_to(top).as_posix()
    except ValueError:
        return {}
    if prefix == ".":
        return dict(texts)
    return {
        name[len(prefix) + 1 :]: text
        for name, text in texts.items()
        if name.startswith(prefix + "/")
    }


def _merged_inventory(main, extra, problems) -> dict | None:
    if not isinstance(main, dict):
        return main
    merged = dict(main)
    if isinstance(extra, dict):
        for key in ("hooks", "mcp_servers", "env_overrides"):
            merged[key] = _as_list(main.get(key)) + _as_list(extra.get(key))
        if extra.get("status") not in (None, "complete"):
            merged["status"] = "partial"
    if problems:
        merged["status"] = "partial"
        merged["link_problems"] = list(problems)
    return merged


def agent_config_with_links(api, root: Path, scope: _Scope):
    """``ca9.api.agent_config`` on ``root``, plus the configs behind links
    that stay inside the repository, copied for ca9 under the path the client
    opens (ca9 does not follow linked folders). ``(result, problem)``;
    ``result["link_problems"]`` lists links that leave the repository or
    point nowhere."""
    result, problem = _call(api, "agent_config", root)
    if problem is not None:
        return None, problem
    linked = LinkedConfigs(scope.top, scope.files(), root)
    extra, _extra_problem = call_on_copy(
        api, "agent_config", _within(linked.texts, scope.top, root), _call
    )
    findings = list(_as_list(result.get("findings")))
    if isinstance(extra, dict):
        findings.extend(_as_list(extra.get("findings")))
    inventory = result.get("inventory")
    extra_inventory = None
    if isinstance(extra, dict):
        extra_inventory = extra.get("inventory")
    problems = []
    for item in linked.problems:
        for name in _within({item["file"]: ""}, scope.top, root):
            problems.append({**item, "file": name})
    return {
        "findings": findings,
        "inventory": _merged_inventory(inventory, extra_inventory, problems),
        "link_problems": problems,
    }, None


def _rows(api, function: str, root: Path, scope: _Scope) -> list | None:
    if function == "agent_config":
        result, problem = agent_config_with_links(api, root, scope)
    else:
        result, problem = _call(api, function, root)
    if problem is not None:
        return None
    return _as_list(result.get("findings"))


def _repository_rows(api, function: str, repository: Path, scope: _Scope) -> list:
    """Repository-level configs for a scan of a subfolder: the workflows
    ca9 reads at the top, and the agent configs at the top (regular files
    and those behind in-repo links), copied for ca9."""
    if function != "agent_config":
        result, problem = _call(api, function, repository)
        if problem is not None:
            return []
        return _as_list(result.get("findings"))
    files = scope.files()
    texts = repository_texts(scope.top, files)
    linked = LinkedConfigs(scope.top, files)
    for name, text in linked.texts.items():
        if repository_level(name):
            texts.setdefault(name, text)
    result, problem = call_on_copy(api, function, texts, _call)
    if problem is not None or not isinstance(result, dict):
        return []
    return _as_list(result.get("findings"))


def scan_agent_publish(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
    api=None,
    repository: Path | None = None,
) -> list[dict[str, Any]]:
    """SKY-D365-D377 findings for a scanned folder.

    ``repository`` is the Git top when the scan covers only a subfolder of
    it: its repository-level workflows and agent configs are reported too,
    like the repository-level GitHub Actions and GitLab CI findings."""
    from skylos.rules.sca import supply_chain

    requested = Path(root)
    if requested.is_symlink() or not requested.is_dir():
        return []
    root_path = requested.resolve()
    ignore = {str(rule).upper() for rule in ignore or ()}
    wanted_agent = AGENT_RULE_IDS - ignore
    wanted_publish = PUBLISH_RULE_IDS - ignore
    if not wanted_agent and not wanted_publish:
        return []
    if api is None:
        api = supply_chain.load_ca9_api()
    if api is None:
        return []
    scope = _Scope(root_path, changed_files)
    findings: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    jobs = []
    if wanted_agent:
        jobs.append(("agent_config", AGENT_RULES, "agent_config"))
    if wanted_publish:
        jobs.append(("audit_workflows", PUBLISH_RULES, "cicd"))
    for function, rules, domain in jobs:
        rows = _rows(api, function, root_path, scope)
        if rows is None:
            continue
        findings.extend(_mapped(rows, rules, scope, domain, ignore, seen))
    if repository is not None:
        top = Path(repository).resolve()
        if top != root_path and root_path.is_relative_to(top):
            top_scope = _Scope(top, changed_files)
            for function, rules, domain in jobs:
                rows = _repository_rows(api, function, top, top_scope)
                findings.extend(_mapped(rows, rules, top_scope, domain, ignore, seen))
    return findings[:MAX_FINDINGS]


def _mapped(rows, rules, scope: _Scope, domain: str, ignore, seen: set) -> list[dict]:
    """Findings for ca9 rows; one per rule, real file, line and identity, so
    a config reached through a link and directly is reported once."""
    findings = []
    settings_cache: dict[Path, str | None] = {}
    for row in _as_list(rows):
        if not isinstance(row, dict):
            continue
        rule = rules.get(str(row.get("signal_type") or ""))
        if rule is None or rule[0] in ignore:
            continue
        path = scope.resolve(row.get("file"))
        if path is None:
            continue
        if rule[0] == "SKY-D365":
            if path not in settings_cache:
                settings_cache[path] = scope.read(path)
            command = (row.get("evidence") or {}).get("command")
            if is_own_hook(
                command, root=scope.root, settings_text=settings_cache[path]
            ):
                continue
        provider = _provider(rule[0], row, path)
        finding = _finding(row, path, scope, rule, domain=domain, provider=provider)
        identity = (
            finding["rule_id"],
            os.path.realpath(path),
            finding["line"],
            finding[IDENTITY_KEY],
        )
        if identity in seen:
            continue
        seen.add(identity)
        findings.append(finding)
    return findings


__all__ = [
    "AGENT_RULE_IDS",
    "HOOK_RULE_IDS",
    "IDENTITY_KEY",
    "PUBLISH_RULE_IDS",
    "agent_config_with_links",
    "available_rule_ids",
    "finding_identity",
    "is_own_hook",
    "is_skylos_hook_command",
    "scan_agent_publish",
]
