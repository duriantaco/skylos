"""Organization agent-guardrail policy for ``skylos hook``.

An organization owner or admin sets, in Skylos Cloud (Agent guardrails), what
the agent hooks block or only warn about on every developer's machine. This
module is the CLI half:

* **Fetch** the policy from ``POST /api/sync/agent-guardrails`` with the same
  project API key ``skylos login`` stored, and cache it on disk under
  ``~/.skylos/guardrails/``. Fetching happens at ``skylos login``,
  ``skylos sync pull``, ``skylos agent warm-cache``, ``skylos agent guardrails
  --refresh``, and in a detached background process a hook starts when the
  cached copy is older than the server's refresh interval. A hook itself never
  makes a network call.
* **Apply** it in the hooks: the hook reads the cached copy (bounded by
  ``LOAD_BUDGET_SECONDS``) and merges it with local settings from
  ``[tool.skylos.guardrails]`` in ``pyproject.toml``. When the organization
  forbids loosening, local settings can only make things stricter, and the
  local escape hatches (``SKYLOS_HOOKS_DISABLE``, ``hooks_allow_packages``) are
  ignored. When no policy is available, the hooks use local settings and say
  so once.
* **Report** (only when the organization turned it on): each block or warning
  becomes a minimal event -- hook, agent, category, rule id, decision,
  repository-relative file path, time -- queued on disk and sent by a
  background process. Never code, snippets, command lines, package names,
  secret values, prompts or absolute paths. Nothing is sent until the
  developer has been shown the one-time notice.

The last successfully fetched policy stays in force until a newer fetch
replaces it (being offline does not loosen it). Logging out, or a key the
server rejects, returns the machine to local settings.

This is a guardrail for AI agents, not a security boundary against the
developer who owns the machine.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

DEFAULT_API_URL = "https://skylos.dev"
POLICY_ENDPOINT = "/api/sync/agent-guardrails"
EVENTS_ENDPOINT = "/api/sync/agent-guardrails/events"
CACHE_DIR = "guardrails"
MACHINE_ID_FILE = "machine-id"
CACHE_SCHEMA = 1

DEFAULT_REFRESH_SECONDS = 900
MIN_REFRESH_SECONDS = 60
MAX_REFRESH_SECONDS = 24 * 3600
# A hook starts at most one background refresh / send per this interval.
SPAWN_BACKOFF_SECONDS = 120
FETCH_TIMEOUT_SECONDS = 8.0
SEND_TIMEOUT_SECONDS = 5.0
# A hook waits at most this long for the cached policy; after that it uses
# local settings for this call.
LOAD_BUDGET_SECONDS = 0.5
LOCK_TIMEOUT_SECONDS = 0.2
MAX_RESPONSE_BYTES = 256_000
MAX_CACHE_BYTES = 256_000
MAX_QUEUE_EVENTS = 200
MAX_BATCH_EVENTS = 50
MAX_EVENTS_PER_HOOK = 20
MAX_EVENT_AGE_SECONDS = 7 * 24 * 3600
MAX_PROTECTED_PATHS = 100
MAX_PATTERN_CHARS = 256
MAX_FILE_CHARS = 512
MAX_LOCAL_CONFIG_BYTES = 256_000

DECISIONS = ("block", "warn")
PACKAGE_KINDS = ("missing_package", "missing_version", "typosquat")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
AGENT_NAMES = {"claude": "claude-code", "codex": "codex", "cursor": "cursor"}
HOOK_NAMES = frozenset({"post-edit", "pre-edit", "pre-read", "pre-bash", "stop"})
EVENT_CATEGORIES = frozenset(
    {
        "secret",
        "secret_read",
        "security_finding",
        "dangerous_sink",
        "untrusted_input",
        "hallucination",
        "contract",
        "protected_path",
        "package_missing",
        "package_missing_version",
        "package_typosquat",
    }
)
_RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9-]{1,40}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,32}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DRIVE_RE = re.compile(r"^[A-Za-z]:")

REPORTING_NOTICE = (
    "Your organization receives guardrail events: rule, file path, agent — never code."
)


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------


def _default_packages() -> dict[str, str]:
    return {kind: "block" for kind in PACKAGE_KINDS}


@dataclass(frozen=True)
class GuardrailSettings:
    """What the hooks enforce. The defaults are Skylos's built-in behaviour."""

    secrets_in_edits: str = "block"
    package_installs: Mapping[str, str] = field(default_factory=_default_packages)
    security_min_severity: str | None = None
    protected_paths: tuple[str, ...] = ()

    def package_decision(self, kind: str) -> str:
        return self.package_installs.get(kind, "block")

    def to_dict(self) -> dict[str, Any]:
        return {
            "secrets_in_edits": self.secrets_in_edits,
            "package_installs": {k: self.package_decision(k) for k in PACKAGE_KINDS},
            "security_min_severity": self.security_min_severity,
            "protected_paths": list(self.protected_paths),
        }


DEFAULT_SETTINGS = GuardrailSettings()


def parse_settings(raw: Any) -> tuple[dict[str, Any], list[str]]:
    """Validated partial settings from a mapping, plus problems found.

    Only keys present and valid are returned, so a local config that sets
    one key leaves the others alone. Unknown keys are reported, not applied.
    """
    values: dict[str, Any] = {}
    problems: list[str] = []
    if raw is None:
        return values, problems
    if not isinstance(raw, Mapping):
        return values, ["guardrails settings must be a table"]
    for key, value in raw.items():
        if key == "secrets_in_edits":
            if value in DECISIONS:
                values[key] = value
            else:
                problems.append("secrets_in_edits must be 'block' or 'warn'")
        elif key == "package_installs":
            if not isinstance(value, Mapping):
                problems.append("package_installs must be a table")
                continue
            kinds: dict[str, str] = {}
            for kind, decision in value.items():
                if kind in PACKAGE_KINDS and decision in DECISIONS:
                    kinds[kind] = decision
                else:
                    problems.append(
                        f"package_installs.{kind} must be 'block' or 'warn'"
                        if kind in PACKAGE_KINDS
                        else f"unknown package_installs key {kind!r}"
                    )
            if kinds:
                values[key] = kinds
        elif key == "security_min_severity":
            if value is None or value in ("", "off", "none"):
                values[key] = None
            elif isinstance(value, str) and value.upper() in _SEVERITY_RANK:
                values[key] = value.upper()
            else:
                problems.append(
                    "security_min_severity must be CRITICAL, HIGH, MEDIUM, LOW or off"
                )
        elif key == "protected_paths":
            if not isinstance(value, (list, tuple)):
                problems.append("protected_paths must be a list of patterns")
                continue
            patterns: list[str] = []
            for item in value:
                pattern = item.strip() if isinstance(item, str) else ""
                if (
                    not pattern
                    or len(pattern) > MAX_PATTERN_CHARS
                    or compile_codeowners_pattern(pattern) is None
                ):
                    problems.append(f"invalid protected path pattern {item!r}")
                    continue
                if pattern not in patterns:
                    patterns.append(pattern)
            values[key] = tuple(patterns[:MAX_PROTECTED_PATHS])
        else:
            problems.append(f"unknown guardrails key {key!r}")
    return values, problems


def settings_from(
    values: Mapping[str, Any], base: GuardrailSettings = DEFAULT_SETTINGS
) -> GuardrailSettings:
    """``base`` with every key in ``values`` replaced (local may loosen)."""
    packages = dict(base.package_installs)
    packages.update(values.get("package_installs") or {})
    return GuardrailSettings(
        secrets_in_edits=values.get("secrets_in_edits", base.secrets_in_edits),
        package_installs=packages,
        security_min_severity=values.get(
            "security_min_severity", base.security_min_severity
        ),
        protected_paths=tuple(values.get("protected_paths", base.protected_paths)),
    )


def _stricter_decision(a: str, b: str) -> str:
    return "block" if "block" in (a, b) else "warn"


def _stricter_severity(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    # A lower threshold (LOW) blocks more findings, so it is stricter.
    return a if _SEVERITY_RANK[a] >= _SEVERITY_RANK[b] else b


def stricter_of(
    org: GuardrailSettings, local_values: Mapping[str, Any]
) -> GuardrailSettings:
    """Per setting, whichever of ``org`` and the local values is stricter."""
    local = settings_from(local_values, org)
    return GuardrailSettings(
        secrets_in_edits=_stricter_decision(
            org.secrets_in_edits, local.secrets_in_edits
        ),
        package_installs={
            kind: _stricter_decision(
                org.package_decision(kind), local.package_decision(kind)
            )
            for kind in PACKAGE_KINDS
        },
        security_min_severity=_stricter_severity(
            org.security_min_severity, local.security_min_severity
        ),
        protected_paths=tuple(
            dict.fromkeys([*org.protected_paths, *local.protected_paths])
        ),
    )


def severity_blocks(severity: Any, threshold: str | None) -> bool:
    if threshold is None:
        return False
    rank = _SEVERITY_RANK.get(str(severity or "").upper())
    return rank is not None and rank <= _SEVERITY_RANK[threshold]


# --------------------------------------------------------------------------
# Protected paths (same semantics as the cloud's compileCodeownersPattern)
# --------------------------------------------------------------------------

_MAX_DOUBLE_STAR_SEGMENTS = 8
# ReDoS / blow-up guards (the cloud validates the same limits): wildcards
# per path segment and per pattern, after collapsing runs of ``*``.
MAX_STARS_PER_SEGMENT = 3
MAX_WILDCARDS_PER_PATTERN = 12
MAX_MATCH_PATH_CHARS = 4096
_ESCAPED = set(".+^${}()|\\*?[]")


def _segment_regex(segment: str) -> str:
    out = []
    index = 0
    while index < len(segment):
        ch = segment[index]
        if ch == "*":
            while index + 1 < len(segment) and segment[index + 1] == "*":
                index += 1
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append("\\" + ch if ch in _ESCAPED else ch)
        index += 1
    return "".join(out)


def compile_codeowners_pattern(pattern: str) -> str | None:
    """Regex source for a GitHub CODEOWNERS pattern, or None if unsupported.

    A line-for-line port of ``compileCodeownersPattern`` in the cloud
    (src/lib/codeowners/parse.ts): ``*``/``?`` within a segment, ``**`` across
    segments, a leading or middle ``/`` anchors at the repository root, a
    trailing ``/`` means a directory, ``docs/*`` means direct children only.
    ``!`` negation, ``[ ]`` ranges and ``\\`` escapes are not supported.
    """
    if not isinstance(pattern, str) or not pattern:
        return None
    if pattern.startswith("!") or "[" in pattern or "]" in pattern or "\\" in pattern:
        return None
    if len(pattern) > 1024 or "\n" in pattern or "\x00" in pattern:
        return None
    body = pattern
    directory_only = body.endswith("/")
    body = body.rstrip("/")
    if not body:
        return None
    anchored = body.startswith("/") or "/" in body
    if body.startswith("/"):
        body = body[1:]
    if not body:
        return None
    raw = body.split("/")
    if any(segment == "" for segment in raw):
        return None
    segments = [
        segment
        for index, segment in enumerate(raw)
        if not (segment == "**" and index > 0 and raw[index - 1] == "**")
    ]
    if sum(1 for segment in segments if segment == "**") > _MAX_DOUBLE_STAR_SEGMENTS:
        return None
    if not _wildcards_within_limits(segments):
        return None
    if segments == ["**"]:
        return "^.*$"
    out = []
    last = len(segments) - 1
    for index, segment in enumerate(segments):
        if segment == "**":
            if index == 0:
                out.append("(?:.*/)?")
            elif index == last:
                out.append("/.*")
            else:
                out.append("/(?:.*/)?")
            continue
        if index > 0 and segments[index - 1] != "**":
            out.append("/")
        out.append(_segment_regex(segment))
    prefix = "^" if anchored else "^(?:.*/)?"
    if segments[last] == "**":
        suffix = "$"
    elif directory_only:
        suffix = "/.*$"
    elif len(segments) > 1 and segments[last] == "*":
        suffix = "$"
    else:
        suffix = "(?:/.*)?$"
    return f"{prefix}{''.join(out)}{suffix}"


def _collapse_stars(segment: str) -> str:
    return re.sub(r"\*{2,}", "*", segment) if segment != "**" else segment


def _wildcards_within_limits(segments: list[str]) -> bool:
    total = 0
    for segment in segments:
        if segment == "**":
            total += 1
            continue
        collapsed = _collapse_stars(segment)
        stars = collapsed.count("*")
        if stars > MAX_STARS_PER_SEGMENT:
            return False
        total += stars + collapsed.count("?")
    return total <= MAX_WILDCARDS_PER_PATTERN


# A compiled pattern for the linear-time matcher: a list of tokens, each
# ("seg", glob) for one path segment, ("any0",) for zero or more segments
# or ("any1",) for one or more segments. Equivalent to the regex that
# compile_codeowners_pattern returns, without a backtracking regex engine.
_Token = tuple


def _pattern_tokens(pattern: str) -> list[_Token] | None:
    if compile_codeowners_pattern(pattern) is None:
        return None
    body = pattern
    directory_only = body.endswith("/")
    body = body.rstrip("/")
    anchored = body.startswith("/") or "/" in body
    body = body.lstrip("/") if body.startswith("/") else body
    raw = body.split("/")
    segments = [
        segment
        for index, segment in enumerate(raw)
        if not (segment == "**" and index > 0 and raw[index - 1] == "**")
    ]
    if segments == ["**"]:
        return [("any1",)]
    tokens: list[_Token] = [] if anchored else [("any0",)]
    last = len(segments) - 1
    for index, segment in enumerate(segments):
        if segment == "**":
            tokens.append(("any1",) if index == last and index > 0 else ("any0",))
        else:
            tokens.append(("seg", _collapse_stars(segment)))
    if segments[last] == "**":
        pass
    elif directory_only:
        tokens.append(("any1",))
    elif len(segments) > 1 and segments[last] == "*":
        pass
    else:
        tokens.append(("any0",))
    return tokens


def _glob_segment(glob: str, text: str) -> bool:
    """``*`` / ``?`` match within one segment; O(len(glob) * len(text))."""
    g_len, t_len = len(glob), len(text)
    g = t = 0
    star = -1
    mark = 0
    while t < t_len:
        if g < g_len and (glob[g] == "?" or glob[g] == text[t]):
            g += 1
            t += 1
        elif g < g_len and glob[g] == "*":
            star, mark = g, t
            g += 1
        elif star != -1:
            g = star + 1
            mark += 1
            t = mark
        else:
            return False
    while g < g_len and glob[g] == "*":
        g += 1
    return g == g_len


def _tokens_match(tokens: list[_Token], parts: list[str]) -> bool:
    """Dynamic programming over (token, segment): polynomial, never exponential."""
    n_tok, n_seg = len(tokens), len(parts)
    # can[j]: tokens[i:] match parts[j:], computed from the last token back.
    can = [False] * n_seg + [True]
    for i in range(n_tok - 1, -1, -1):
        kind = tokens[i][0]
        nxt = can
        can = [False] * (n_seg + 1)
        if kind == "seg":
            glob = tokens[i][1]
            for j in range(n_seg - 1, -1, -1):
                can[j] = nxt[j + 1] and _glob_segment(glob, parts[j])
        else:
            # any0: nxt[j] or any later nxt; any1: some later nxt (k > j).
            later = False
            for j in range(n_seg, -1, -1):
                can[j] = later or (kind == "any0" and nxt[j])
                later = later or nxt[j]
    return can[0]


_PATTERN_CACHE: dict[str, list[_Token] | None] = {}


def case_insensitive_filesystem() -> bool:
    """macOS and Windows file systems are case-insensitive by default."""
    return sys.platform in ("darwin", "win32") or sys.platform.startswith("cygwin")


def protected_match(
    rel_path: str,
    patterns: Iterable[str],
    *,
    case_insensitive: bool | None = None,
) -> str | None:
    """The first pattern that protects ``rel_path`` (repo-relative, ``/``).

    On a case-insensitive file system ``INFRA/x.tf`` is the same file as
    ``infra/x.tf``, so matching ignores case there.
    """
    if not rel_path or "\n" in rel_path or rel_path.startswith("/"):
        return None
    if len(rel_path) > MAX_MATCH_PATH_CHARS:
        return None
    fold = (
        case_insensitive_filesystem() if case_insensitive is None else case_insensitive
    )
    parts = (rel_path.casefold() if fold else rel_path).split("/")
    for pattern in patterns:
        key = f"{int(fold)}\0{pattern}"
        if key not in _PATTERN_CACHE:
            tokens = _pattern_tokens(pattern)
            if tokens is not None and fold:
                tokens = [
                    (t[0], t[1].casefold()) if t[0] == "seg" else t for t in tokens
                ]
            _PATTERN_CACHE[key] = tokens
        tokens = _PATTERN_CACHE[key]
        if tokens is not None and _tokens_match(tokens, parts):
            return pattern
    return None


# --------------------------------------------------------------------------
# The context a hook runs with
# --------------------------------------------------------------------------


@dataclass
class GuardrailContext:
    settings: GuardrailSettings = DEFAULT_SETTINGS
    # "default" (nothing configured), "local" (pyproject only) or "org".
    source: str = "default"
    org_name: str | None = None
    org_version: int | None = None
    allow_local_loosening: bool = True
    report_events: bool = False
    key: str | None = None
    home: Path | None = None
    # (notice id, text) shown once per machine and organization credential.
    notices: list[tuple[str, str]] = field(default_factory=list)
    local_problems: list[str] = field(default_factory=list)
    reason: str = ""
    # The organization settings before local settings were merged in.
    org_settings: GuardrailSettings | None = None
    merged_workspaces: int = 0
    local_loaded: bool = False
    # Nothing could be read in time: treat local escape hatches as off.
    unverified: bool = False

    @property
    def org_enforced(self) -> bool:
        return self.source == "org" and not self.allow_local_loosening

    def ignores_local_escape_hatches(self) -> bool:
        return self.org_enforced or self.unverified


def default_home() -> Path:
    """``~/.skylos``: where ``skylos login`` keeps credentials.json."""
    return Path.home() / ".skylos"


def api_url(env: Mapping[str, str]) -> str:
    raw = (env.get("SKYLOS_API_URL") or DEFAULT_API_URL).strip().rstrip("/")
    return raw or DEFAULT_API_URL


def resolve_credential(
    root: Path | None, env: Mapping[str, str], home: Path
) -> str | None:
    """The project API key the hooks and the refresher both use.

    Same sources as ``skylos.cloud.sync.get_token`` (``SKYLOS_TOKEN``, the
    repo's ``.skylos/link.json`` project, the saved default), minus CI OIDC
    and minus any subprocess, so it is cheap enough for a hook. Every project
    of one organization shares the organization's policy, so picking the
    repo's top-level linked project is enough.
    """
    token = (env.get("SKYLOS_TOKEN") or "").strip()
    if token:
        return token
    creds = _read_json(home / "credentials.json", max_bytes=1_000_000)
    if not creds:
        return None
    project_id = None
    if root is not None:
        link = _read_json(root / ".skylos" / "link.json", max_bytes=200_000)
        entry = (
            (link.get("projects") or {}).get("")
            if isinstance(link.get("projects"), dict)
            else None
        )
        if isinstance(entry, dict) and entry.get("project_id"):
            project_id = str(entry["project_id"]).strip()
        elif link.get("project_id"):
            project_id = str(link["project_id"]).strip()
    tokens = creds.get("tokens") if isinstance(creds.get("tokens"), dict) else {}
    if project_id and isinstance(tokens.get(project_id), dict):
        value = tokens[project_id].get("token")
        if isinstance(value, str) and value.strip():
            return value.strip()
    value = creds.get("token")
    return value.strip() if isinstance(value, str) and value.strip() else None


PAID_PLANS = frozenset({"pro", "enterprise", "beta"})


def _credential_plan(home: Path, token: str) -> str | None:
    """The plan ``skylos login`` recorded for ``token`` (None if unknown)."""
    creds = _read_json(home / "credentials.json", max_bytes=1_000_000)
    tokens = creds.get("tokens") if isinstance(creds.get("tokens"), dict) else {}
    for entry in tokens.values():
        if isinstance(entry, dict) and entry.get("token") == token:
            return str(entry.get("plan") or "").lower() or None
    if creds.get("token") == token:
        return str(creds.get("plan") or "").lower() or None
    return None


def cache_key(url: str, token: str) -> str:
    return hashlib.sha256(f"{url}\n{token}".encode()).hexdigest()[:32]


def cache_path(home: Path, key: str) -> Path:
    return home / CACHE_DIR / f"{key}.json"


def saved_tokens(env: Mapping[str, str], home: Path) -> list[str]:
    """Every Skylos key on this machine: SKYLOS_TOKEN and all saved logins."""
    found: list[str] = []
    token = (env.get("SKYLOS_TOKEN") or "").strip()
    if token:
        found.append(token)
    creds = _read_json(home / "credentials.json", max_bytes=1_000_000)
    values = [creds.get("token")]
    tokens = creds.get("tokens") if isinstance(creds.get("tokens"), dict) else {}
    values += [e.get("token") for e in tokens.values() if isinstance(e, dict)]
    for value in values:
        if isinstance(value, str) and value.strip() and value.strip() not in found:
            found.append(value.strip())
    return found


def reporting_destination_trusted(
    env: Mapping[str, str], home: Path, token: str
) -> bool:
    """Require an operator-selected destination when multiple keys are saved.

    A repository-controlled ``.skylos/link.json`` can select a saved project
    key for policy fetches. It must not silently select another workspace as
    the recipient of this repository's guardrail events.
    """
    explicit = (env.get("SKYLOS_TOKEN") or "").strip()
    if explicit:
        return explicit == token
    return saved_tokens({}, home) == [token]


def _active_policy(
    doc: dict[str, Any],
) -> tuple[GuardrailSettings, dict[str, Any]] | None:
    if (
        not doc
        or doc.get("status") != "active"
        or not isinstance(doc.get("policy"), dict)
    ):
        return None
    values, _problems = parse_settings(
        {
            k: doc["policy"][k]
            for k in (
                "secrets_in_edits",
                "package_installs",
                "security_min_severity",
                "protected_paths",
            )
            if k in doc["policy"]
        }
    )
    return settings_from(values), doc["policy"]


def load_org_context(
    root: Path | None, env: Mapping[str, str], *, home: Path | None = None
) -> GuardrailContext:
    """Stage 1: the cached organization policy only (small files, no pyproject).

    The key this repository resolves to (``resolve_credential``) is used for
    fetching, notices and reporting. When this machine is logged in to more
    than one workspace, the enforced settings are the strictest of every
    cached organization policy, so a repository-controlled ``.skylos/link.json``
    cannot switch the hooks to a laxer workspace's policy.
    """
    home = home or default_home()
    context = GuardrailContext(home=home)
    token = resolve_credential(root, env, home)
    if not token:
        context.reason = "not logged in to Skylos Cloud"
        return context
    url = api_url(env)
    key = cache_key(url, token)
    context.key = key
    doc = _read_json(cache_path(home, key), max_bytes=MAX_CACHE_BYTES)
    status = doc.get("status") if doc else None
    primary = _active_policy(doc)
    others = []
    for other in saved_tokens(env, home):
        if other == token:
            continue
        other_doc = _read_json(
            cache_path(home, cache_key(url, other)), max_bytes=MAX_CACHE_BYTES
        )
        active = _active_policy(other_doc)
        if active is not None:
            others.append((active, other_doc))
    if primary is None and not others:
        context.reason = {
            None: "organization policy not fetched yet",
            "unavailable": "organization policy could not be fetched",
            "not_configured": "no organization policy is set",
            "plan_required": "organization policy needs a paid Skylos workspace",
            "unauthorized": "the saved Skylos key was rejected",
            "unsupported": "the Skylos server does not offer organization guardrails",
        }.get(status, "organization policy unavailable")
        # Never fetched yet: a background refresh starts; nothing to say.
        # A failed fetch is worth a notice only for a paid workspace (only
        # those can have an organization policy).
        if status == "unavailable" and _credential_plan(home, token) in PAID_PLANS:
            context.notices.append(
                (
                    "policy-unavailable",
                    "Skylos: could not fetch your organization's agent guardrail "
                    "policy, so the hooks use local settings. Run "
                    "`skylos agent guardrails --refresh` to retry.",
                )
            )
        elif status == "unauthorized":
            context.notices.append(
                (
                    "key-rejected",
                    "Skylos: Skylos Cloud rejected the saved key, so the hooks use "
                    "local settings. Run `skylos login` to reconnect.",
                )
            )
        return context
    policies = ([(primary, doc)] if primary is not None else []) + others
    (settings, policy), named_doc = policies[0]
    allow = policy.get("allow_local_loosening") is True
    for (other_settings, other_policy), _doc in policies[1:]:
        settings = stricter_of(settings, other_settings.to_dict())
        allow = allow and other_policy.get("allow_local_loosening") is True
    org = (
        named_doc.get("organization")
        if isinstance(named_doc.get("organization"), dict)
        else {}
    )
    context.org_name = clean_display_text(org.get("name")) or None
    version = named_doc.get("version")
    context.org_version = version if isinstance(version, int) else None
    context.source = "org"
    context.org_settings = settings
    context.settings = settings
    context.allow_local_loosening = allow
    context.merged_workspaces = len(policies)
    # Events go to the workspace this repository's key belongs to, and only
    # if that workspace turned reporting on.
    context.report_events = (
        primary is not None
        and primary[1].get("report_events") is True
        and reporting_destination_trusted(env, home, token)
    )
    context.reason = "organization policy" + (
        f" (strictest of {len(policies)} workspaces you are logged in to)"
        if len(policies) > 1
        else ""
    )
    if context.report_events:
        primary_org = (
            doc.get("organization") if isinstance(doc.get("organization"), dict) else {}
        )
        context.notices.append(
            (
                f"reporting:{primary_org.get('id') or ''}",
                reporting_notice(clean_display_text(primary_org.get("name")) or None),
            )
        )
    return context


def apply_local_settings(
    context: GuardrailContext, local_values: Mapping[str, Any], problems: list[str]
) -> GuardrailContext:
    """Stage 2: merge ``[tool.skylos.guardrails]`` into a stage-1 context."""
    context.local_problems = list(problems)
    if context.source == "org" and context.org_settings is not None:
        if context.allow_local_loosening:
            context.settings = settings_from(local_values, context.org_settings)
        else:
            context.settings = stricter_of(context.org_settings, local_values)
    elif local_values:
        context.settings = settings_from(local_values)
        context.source = "local"
    context.local_loaded = True
    return context


def load_context(
    root: Path | None,
    env: Mapping[str, str],
    *,
    home: Path | None = None,
    now: float | None = None,
) -> GuardrailContext:
    """Cached organization policy, then local settings merged in (no network)."""
    context = load_org_context(root, env, home=home)
    values, problems = read_local_settings(root)
    return apply_local_settings(context, values, problems)


def load_context_bounded(
    root: Path | None,
    env: Mapping[str, str],
    *,
    home: Path | None = None,
    budget: float = LOAD_BUDGET_SECONDS,
) -> GuardrailContext:
    """``load_context`` with a hard time budget; never raises.

    The organization policy is read first. If the local config is not read
    within the budget it is ignored (it could only have loosened or added to
    the organization policy). If not even the organization policy could be
    read in time, the call uses built-in defaults and ignores the local
    escape hatches: a slow disk must never loosen anything.
    """
    stages: list[GuardrailContext] = []

    def _load():
        try:
            context = load_org_context(root, env, home=home)
            stages.append(context)
            values, problems = read_local_settings(root)
            full = apply_local_settings(
                replace(context, notices=list(context.notices)), values, problems
            )
            stages.append(full)
        except Exception:
            return

    worker = threading.Thread(target=_load, name="skylos-guardrails", daemon=True)
    worker.start()
    worker.join(budget)
    snapshot = list(stages)
    if len(snapshot) >= 2:
        return snapshot[1]
    if snapshot:
        context = snapshot[0]
        context.reason += "; local settings not read in time, ignored"
        return context
    return GuardrailContext(
        reason="guardrail settings could not be read in time",
        unverified=True,
    )


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


def clean_display_text(value: Any, limit: int = 120) -> str:
    """Server-provided text for terminals / agent messages: no control or
    bidi characters, no Rich markup brackets, bounded length."""
    text = _CONTROL_RE.sub("", str(value or "")).replace("[", "(").replace("]", ")")
    return " ".join(text.split())[:limit]


def reporting_notice(org_name: str | None) -> str:
    who = f" ({org_name})" if org_name else ""
    return f"Skylos{who}: {REPORTING_NOTICE} Details: `skylos agent guardrails`."


def read_local_settings(root: Path | None) -> tuple[dict[str, Any], list[str]]:
    """``[tool.skylos.guardrails]`` from the project's pyproject.toml."""
    if root is None:
        return {}, []
    pyproject = root / "pyproject.toml"
    try:
        if pyproject.is_symlink() or not pyproject.is_file():
            return {}, []
        if pyproject.stat().st_size > MAX_LOCAL_CONFIG_BYTES:
            return {}, [
                "pyproject.toml is too large to read in a hook; local guardrail settings ignored"
            ]
        text = pyproject.read_text(encoding="utf-8")
    except OSError:
        return {}, []
    if "guardrails" not in text:
        return {}, []
    try:
        try:
            import tomllib
        except ModuleNotFoundError:  # Python < 3.11
            import tomli as tomllib  # type: ignore[no-redef]
        data = tomllib.loads(text)
    except Exception:
        return {}, ["pyproject.toml could not be parsed"]
    section = data.get("tool", {}).get("skylos", {}).get("guardrails")
    return parse_settings(section)


# --------------------------------------------------------------------------
# Notices
# --------------------------------------------------------------------------


def _notices_path(home: Path, key: str) -> Path:
    return home / CACHE_DIR / f"{key}.notices.json"


def pending_notice(context: GuardrailContext) -> tuple[str, str] | None:
    if not context.notices or context.key is None or context.home is None:
        return None
    shown = _read_json(_notices_path(context.home, context.key), max_bytes=64_000)
    for notice_id, text in context.notices:
        if notice_id not in shown:
            return notice_id, text
    return None


def mark_notice_shown(context: GuardrailContext, notice_id: str) -> None:
    if context.key is None or context.home is None:
        return
    path = _notices_path(context.home, context.key)
    shown = _read_json(path, max_bytes=64_000)
    shown[notice_id] = int(time.time())
    _write_json(context.home, path, shown)


def reporting_notice_shown(home: Path, key: str) -> bool:
    shown = _read_json(_notices_path(home, key), max_bytes=64_000)
    return any(str(notice_id).startswith("reporting:") for notice_id in shown)


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


def safe_rel_path(value: Any) -> str | None:
    """A repository-relative path that is safe to send, or None."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_FILE_CHARS:
        return None
    if text.startswith(("/", "~")) or "\\" in text or _DRIVE_RE.match(text):
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    return text


def make_event(
    *,
    hook: str,
    client: str,
    category: str,
    decision: str,
    rule_id: str | None = None,
    file: str | None = None,
    now: float | None = None,
) -> dict[str, Any] | None:
    """One event with exactly the allowed fields, or None if anything is off."""
    agent = AGENT_NAMES.get(client)
    if hook not in HOOK_NAMES or agent is None or category not in EVENT_CATEGORIES:
        return None
    if decision not in DECISIONS:
        return None
    rule = rule_id if isinstance(rule_id, str) and _RULE_ID_RE.match(rule_id) else None
    stamp = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc)
    return {
        "hook": hook,
        "agent": agent,
        "category": category,
        "rule_id": rule,
        "decision": decision,
        "file": safe_rel_path(file),
        "occurred_at": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _queue_path(home: Path, key: str) -> Path:
    return home / CACHE_DIR / f"{key}.events.json"


def queue_events(context: GuardrailContext, events: Sequence[dict[str, Any]]) -> int:
    """Append events to the bounded on-disk queue. Returns how many were kept."""
    if not context.report_events or context.key is None or context.home is None:
        return 0
    events = [e for e in events if e][:MAX_EVENTS_PER_HOOK]
    if not events:
        return 0
    from skylos.core.safe_cache_io import project_cache_lock

    home = context.home
    rel = Path(CACHE_DIR) / f"{context.key}.events.lock"
    with project_cache_lock(home, rel, timeout_seconds=LOCK_TIMEOUT_SECONDS) as locked:
        if not locked:
            return 0
        path = _queue_path(home, context.key)
        queue = _read_json(path, max_bytes=MAX_CACHE_BYTES).get("events")
        queue = (
            [e for e in queue if isinstance(e, dict)] if isinstance(queue, list) else []
        )
        queue.extend(events)
        # Bounded: the oldest events are dropped first.
        queue = queue[-MAX_QUEUE_EVENTS:]
        _write_json(home, path, {"events": queue})
    return len(events)


def queued_event_count(home: Path, key: str) -> int:
    queue = _read_json(_queue_path(home, key), max_bytes=MAX_CACHE_BYTES).get("events")
    return len(queue) if isinstance(queue, list) else 0


# --------------------------------------------------------------------------
# Background work (never in the hook's own process)
# --------------------------------------------------------------------------


def _marker_path(home: Path, key: str, action: str) -> Path:
    return home / CACHE_DIR / f"{key}.{action}.attempt"


def refresh_due(context: GuardrailContext, *, now: float | None = None) -> bool:
    if context.key is None or context.home is None:
        return False
    now = time.time() if now is None else now
    doc = _read_json(cache_path(context.home, context.key), max_bytes=MAX_CACHE_BYTES)
    fetched = doc.get("fetched_at") if doc else None
    interval = _refresh_interval(doc.get("refresh_after_seconds") if doc else None)
    if not isinstance(fetched, (int, float)):
        return True
    # A time in the future (clock skew or a tampered cache) is never "fresh".
    return fetched > now + 300 or now - fetched >= interval


def spawn_background(
    context: GuardrailContext,
    action: str,
    *,
    root: Path | None,
    client: str,
    env: Mapping[str, str],
    popen: Callable[..., Any] | None = None,
    now: float | None = None,
) -> bool:
    """Start ``python -m skylos.cloud.guardrails <action>`` detached.

    At most once per ``SPAWN_BACKOFF_SECONDS`` per credential and action.
    Returns True when a process was started.
    """
    if context.key is None or context.home is None or action not in ("refresh", "send"):
        return False
    now = time.time() if now is None else now
    marker = _marker_path(context.home, context.key, action)
    try:
        if now - marker.stat().st_mtime < SPAWN_BACKOFF_SECONDS:
            return False
    except OSError:
        pass
    if not _touch(context.home, marker):
        return False
    argv = [*python_command(), "skylos.cloud.guardrails", action]
    if root is not None:
        argv += ["--root", str(root)]
    if client in AGENT_NAMES:
        argv += ["--agent", client]
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        # Never run from the repository: a repo-level ``skylos/`` package
        # would shadow the installed one. The repo is only an argument.
        "env": {
            **{
                key: value
                for key, value in env.items()
                if key not in {"PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONINSPECT"}
            },
            "PYTHONSAFEPATH": "1",
        },
        "cwd": str(context.home),
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        kwargs["start_new_session"] = True
    try:
        (popen or subprocess.Popen)(argv, **kwargs)
    except (OSError, ValueError):
        return False
    return True


def python_command() -> list[str]:
    """``python -m`` without repo or Python environment import overrides."""
    safe = ["-P"] if sys.version_info >= (3, 11) else []
    return [sys.executable, "-E", *safe, "-m"]


def _refresh_interval(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return max(MIN_REFRESH_SECONDS, min(MAX_REFRESH_SECONDS, value))
    return DEFAULT_REFRESH_SECONDS


def machine_id(home: Path) -> str:
    """A random id for this machine (not derived from hardware or user)."""
    path = home / MACHINE_ID_FILE
    try:
        if not path.is_symlink() and path.is_file():
            value = path.read_text(encoding="utf-8").strip().lower()
            if _UUID_RE.match(value):
                return value
    except OSError:
        pass
    value = str(uuid.uuid4())
    _write_text(home, path, value + "\n")
    return value


def detect_installed_agents(
    root: Path | None, user_home: Path | None = None
) -> list[str]:
    """Agents whose hook config (project or user) runs ``skylos hook``."""
    from skylos.commands.install_hooks_cmd import OUR_COMMAND_RE, config_path_for

    found: list[str] = []
    user_home = user_home or Path.home()
    for client in ("claude", "codex", "cursor"):
        paths = [config_path_for(client, "user", Path("."), user_home)]
        if root is not None:
            paths.append(config_path_for(client, "project", root, user_home))
        for path in paths:
            try:
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or path.stat().st_size > 2_000_000
                ):
                    continue
                if OUR_COMMAND_RE.search(
                    path.read_text(encoding="utf-8", errors="ignore")
                ):
                    found.append(AGENT_NAMES[client])
                    break
            except OSError:
                continue
    return found


HttpPost = Callable[[str, dict[str, str], bytes, float], tuple[int, bytes]]


def _http_post(
    url: str, headers: dict[str, str], body: bytes, timeout: float
) -> tuple[int, bytes]:
    import urllib.error
    import urllib.request

    check_api_url(url)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        # A redirect would re-send the Authorization header elsewhere.
        def redirect_request(self, *_args, **_kwargs):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with (
            opener.open(  # skylos: ignore[SKY-D216] fixed Skylos API endpoint from SKYLOS_API_URL
                request, timeout=timeout
            ) as response
        ):
            return response.status, response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE_BYTES + 1) if exc.fp else b""


_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def check_api_url(url: str) -> None:
    """HTTPS only (plain HTTP only to this machine); no credentials in the URL."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("SKYLOS_API_URL must be a plain https:// URL")
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in _LOCAL_HOSTS:
        return
    raise ValueError("SKYLOS_API_URL must use HTTPS")


def _headers(token: str) -> dict[str, str]:
    from skylos import __version__

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": f"skylos-cli/{__version__}",
    }


def refresh_policy(
    root: Path | None,
    env: Mapping[str, str],
    *,
    home: Path | None = None,
    agents: Sequence[str] = (),
    post: HttpPost | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Fetch the organization policy now and update the cache.

    Returns the cache document (``status`` says what happened). On a network
    or server error the previous policy is kept and stays in force.
    """
    from skylos import __version__

    home = home or default_home()
    now = time.time() if now is None else now
    token = resolve_credential(root, env, home)
    if not token:
        return {"status": "not_logged_in"}
    url = api_url(env)
    key = cache_key(url, token)
    path = cache_path(home, key)
    previous = _read_json(path, max_bytes=MAX_CACHE_BYTES)
    body = {
        "machine_id": machine_id(home),
        "agents": sorted({a for a in agents if a in AGENT_NAMES.values()}),
        "cli_version": __version__ if _VERSION_RE.match(__version__) else None,
    }
    doc: dict[str, Any] = dict(previous) if previous else {"schema": CACHE_SCHEMA}
    doc["attempted_at"] = now
    try:
        status_code, raw = (post or _http_post)(
            url + POLICY_ENDPOINT,
            _headers(token),
            json.dumps(body).encode(),
            FETCH_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # network down, timeout, bad URL
        doc["last_error"] = type(exc).__name__
        doc.setdefault("status", "unavailable")
        _write_json(home, path, doc)
        return doc
    if status_code in (401, 403):
        doc = {
            "schema": CACHE_SCHEMA,
            "status": "unauthorized",
            "fetched_at": now,
            "attempted_at": now,
            "last_error": f"http {status_code}",
        }
        _write_json(home, path, doc)
        return doc
    parsed = _parse_policy_response(status_code, raw)
    if parsed is None:
        doc["last_error"] = f"http {status_code}"
        if status_code == 404 or status_code == 200:
            # A Skylos server without this endpoint (or not a Skylos answer):
            # there is no organization policy to apply. A previously fetched
            # policy stays in force.
            if doc.get("status") != "active":
                doc["status"] = "unsupported"
                doc["fetched_at"] = now
        else:
            doc.setdefault("status", "unavailable")
        _write_json(home, path, doc)
        return doc
    parsed.update({"schema": CACHE_SCHEMA, "fetched_at": now, "attempted_at": now})
    _write_json(home, path, parsed)
    return parsed


def _parse_policy_response(status_code: int, raw: bytes) -> dict[str, Any] | None:
    if status_code != 200 or len(raw) > MAX_RESPONSE_BYTES:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("ok") is not True:
        return None
    status = data.get("status")
    if status not in ("active", "not_configured", "plan_required"):
        return None
    org = data.get("organization") if isinstance(data.get("organization"), dict) else {}
    result: dict[str, Any] = {
        "status": status,
        "organization": {
            "id": str(org.get("id") or "")[:64],
            "name": clean_display_text(org.get("name"), 200),
        },
        "refresh_after_seconds": _refresh_interval(data.get("refresh_after_seconds")),
        "version": data.get("version")
        if isinstance(data.get("version"), int)
        else None,
        "policy": None,
    }
    if status == "active":
        policy = data.get("policy")
        if not isinstance(policy, dict):
            return None
        values, _problems = parse_settings(
            {
                k: policy[k]
                for k in (
                    "secrets_in_edits",
                    "package_installs",
                    "security_min_severity",
                    "protected_paths",
                )
                if k in policy
            }
        )
        settings = settings_from(values)
        result["policy"] = {
            **settings.to_dict(),
            "allow_local_loosening": policy.get("allow_local_loosening") is True,
            "report_events": policy.get("report_events") is True,
        }
    return result


def send_events(
    env: Mapping[str, str],
    root: Path | None,
    *,
    home: Path | None = None,
    post: HttpPost | None = None,
) -> dict[str, int]:
    """Send queued events in batches. Keeps what failed, drops what the
    server refused for good, never sends before the notice was shown."""
    from skylos import __version__
    from skylos.core.safe_cache_io import project_cache_lock

    home = home or default_home()
    token = resolve_credential(root, env, home)
    result = {"sent": 0, "dropped": 0, "kept": 0}
    if not token:
        return result
    url = api_url(env)
    key = cache_key(url, token)
    if not reporting_destination_trusted(env, home, token):
        result["kept"] = queued_event_count(home, key)
        return result
    doc = _read_json(cache_path(home, key), max_bytes=MAX_CACHE_BYTES)
    policy = doc.get("policy") if isinstance(doc.get("policy"), dict) else {}
    reporting = doc.get("status") == "active" and policy.get("report_events") is True
    path = _queue_path(home, key)
    lock = Path(CACHE_DIR) / f"{key}.events.lock"
    if not reporting:
        # Reporting was turned off (or the key logged out): discard the queue.
        with project_cache_lock(home, lock, timeout_seconds=2) as locked:
            if locked:
                result["dropped"] = queued_event_count(home, key)
                _write_json(home, path, {"events": []})
        return result
    if not reporting_notice_shown(home, key):
        result["kept"] = queued_event_count(home, key)
        return result
    with project_cache_lock(home, lock, timeout_seconds=2) as locked:
        if not locked:
            return result
        queue = _read_json(path, max_bytes=MAX_CACHE_BYTES).get("events")
        queue = (
            [e for e in queue if isinstance(e, dict)] if isinstance(queue, list) else []
        )
        remaining: list[dict[str, Any]] = []
        cutoff = time.time() - MAX_EVENT_AGE_SECONDS
        fresh = [e for e in queue if _event_time(e) >= cutoff]
        result["dropped"] += len(queue) - len(fresh)
        for start in range(0, len(fresh), MAX_BATCH_EVENTS):
            batch = [_wire_event(e) for e in fresh[start : start + MAX_BATCH_EVENTS]]
            batch = [e for e in batch if e is not None]
            if not batch:
                continue
            payload = {
                "cli_version": __version__ if _VERSION_RE.match(__version__) else None,
                "events": batch,
            }
            try:
                status_code, _raw = (post or _http_post)(
                    url + EVENTS_ENDPOINT,
                    _headers(token),
                    json.dumps(payload).encode(),
                    SEND_TIMEOUT_SECONDS,
                )
            except Exception:
                remaining.extend(fresh[start:])
                break
            if status_code == 200:
                result["sent"] += len(batch)
            elif status_code in (400, 401, 403, 413):
                # Refused for good (reporting off, bad key, invalid): never retried.
                result["dropped"] += len(batch)
                if status_code == 403:
                    remaining = []
                    break
            else:  # 429 / 5xx: retry later
                remaining.extend(fresh[start:])
                break
        remaining = remaining[-MAX_QUEUE_EVENTS:]
        result["kept"] = len(remaining)
        _write_json(home, path, {"events": remaining})
    return result


def _event_time(event: dict[str, Any]) -> float:
    try:
        stamp = datetime.strptime(str(event.get("occurred_at")), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return 0.0
    return stamp.replace(tzinfo=timezone.utc).timestamp()


_WIRE_FIELDS = (
    "hook",
    "agent",
    "category",
    "rule_id",
    "decision",
    "file",
    "occurred_at",
)


def _wire_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Re-validate a queued event and keep only the allowed fields."""
    if event.get("hook") not in HOOK_NAMES:
        return None
    if event.get("agent") not in AGENT_NAMES.values():
        return None
    if (
        event.get("category") not in EVENT_CATEGORIES
        or event.get("decision") not in DECISIONS
    ):
        return None
    rule = event.get("rule_id")
    wire = {name: event.get(name) for name in _WIRE_FIELDS}
    wire["rule_id"] = (
        rule if isinstance(rule, str) and _RULE_ID_RE.match(rule) else None
    )
    wire["file"] = safe_rel_path(event.get("file"))
    if _event_time(event) == 0.0:
        return None
    return wire


# --------------------------------------------------------------------------
# Human-facing status (skylos agent guardrails)
# --------------------------------------------------------------------------


def describe(
    context: GuardrailContext, *, home: Path | None = None, now: float | None = None
) -> list[str]:
    home = home or context.home or default_home()
    now = time.time() if now is None else now
    lines: list[str] = []
    if context.source == "org":
        loosen = (
            "local settings may loosen it"
            if context.allow_local_loosening
            else "local settings can only make it stricter"
        )
        version = f" v{context.org_version}" if context.org_version else ""
        lines.append(
            f"Organization policy{version} from {context.org_name or 'your organization'} is in force ({loosen})."
        )
    elif context.source == "local":
        lines.append(
            f"Local settings from pyproject.toml are in force ({context.reason})."
        )
    else:
        lines.append(f"Built-in defaults are in force ({context.reason}).")
    if context.key is not None:
        doc = _read_json(cache_path(home, context.key), max_bytes=MAX_CACHE_BYTES)
        fetched = doc.get("fetched_at") if doc else None
        if isinstance(fetched, (int, float)):
            lines.append(f"Policy last fetched {_ago(now - fetched)} ago.")
        if doc and doc.get("last_error"):
            lines.append(
                f"Last fetch attempt failed ({doc['last_error']}); the previous copy stays in force."
            )
    settings = context.settings
    lines.append(f"  Secrets written by agents: {settings.secrets_in_edits}")
    for kind, label in (
        ("missing_package", "Installing packages that don't exist"),
        ("missing_version", "Installing package versions that don't exist"),
        ("typosquat", "Installing look-alike (typosquat) packages"),
    ):
        lines.append(f"  {label}: {settings.package_decision(kind)}")
    lines.append(
        "  Security findings: "
        + (
            f"block everything at {settings.security_min_severity} or above"
            if settings.security_min_severity
            else "block only findings with evidence of untrusted input or always-dangerous calls"
        )
    )
    lines.append(
        "  Protected paths: "
        + (", ".join(settings.protected_paths) if settings.protected_paths else "none")
    )
    if context.org_enforced:
        lines.append(
            "  SKYLOS_HOOKS_DISABLE and hooks_allow_packages are ignored (your organization does not allow loosening)."
        )
    if context.report_events:
        lines.append(REPORTING_NOTICE)
        lines.append(
            "  Sent per block or warning: hook, agent, category, rule id, decision, "
            "repository-relative file path, time, CLI version. Never code, snippets, "
            "command lines, package names, secret values, prompts or absolute paths."
        )
        if context.key is not None:
            lines.append(
                f"  Events waiting to be sent: {queued_event_count(home, context.key)}"
            )
    else:
        lines.append("Guardrail events are not reported to your organization.")
    for problem in context.local_problems:
        lines.append(f"  Ignored local setting: {problem}")
    return lines


def _ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m"
    if seconds < 172800:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def refresh_and_describe(
    root: Path | None,
    env: Mapping[str, str],
    *,
    print_func: Callable[[str], None] = print,
    home: Path | None = None,
    post: HttpPost | None = None,
    quiet_when_not_logged_in: bool = False,
) -> int:
    """Fetch now (short timeout), then print the effective policy.

    Used by ``skylos agent guardrails --refresh``, ``skylos login``,
    ``skylos sync pull`` and ``skylos agent warm-cache``. Printing the
    reporting notice here counts as showing it.
    """
    home = home or default_home()
    doc = refresh_policy(
        root, env, home=home, agents=detect_installed_agents(root), post=post
    )
    if doc.get("status") == "not_logged_in":
        if not quiet_when_not_logged_in:
            print_func(
                "Agent guardrails: not logged in to Skylos Cloud; hooks use local settings."
            )
        return 0
    context = load_context(root, env, home=home)
    print_func("Agent guardrails:")
    for line in describe(context, home=home):
        print_func(f"  {line}" if not line.startswith("  ") else line)
    for notice_id, _text in context.notices:
        if notice_id.startswith("reporting:"):
            mark_notice_shown(context, notice_id)
    if (
        context.report_events
        and context.key is not None
        and queued_event_count(home, context.key)
    ):
        send_events(env, root, home=home, post=post)
    return 0


# --------------------------------------------------------------------------
# Small safe-IO helpers
# --------------------------------------------------------------------------


def _read_json(path: Path, *, max_bytes: int) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _ensure_dir(home: Path, directory: Path) -> bool:
    try:
        for current in (home, directory):
            if current.is_symlink():
                return False
            if not current.exists():
                current.mkdir(
                    mode=0o700
                )  # skylos: ignore[SKY-D215] fixed directory under ~/.skylos
        return directory.is_dir()
    except OSError:
        return False


def _write_text(home: Path, path: Path, text: str) -> bool:
    if not _ensure_dir(home, path.parent):
        return False
    if path.is_symlink():
        return False
    temp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(
            temp, flags, 0o600
        )  # skylos: ignore[SKY-D215] temp file under ~/.skylos/guardrails
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temp, path)
        return True
    except OSError:
        try:
            temp.unlink()
        except OSError:
            pass
        return False


def _write_json(home: Path, path: Path, payload: dict[str, Any]) -> bool:
    return _write_text(home, path, json.dumps(payload, sort_keys=True) + "\n")


def _touch(home: Path, path: Path) -> bool:
    return _write_text(home, path, str(int(time.time())) + "\n")


# --------------------------------------------------------------------------
# python -m skylos.cloud.guardrails refresh|send [--root DIR] [--agent NAME]
# --------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    action = args[0] if args else ""
    root: Path | None = None
    agent: str | None = None
    rest = iter(args[1:])
    for arg in rest:
        if arg == "--root":
            value = next(rest, "")
            root = Path(value) if value else None
        elif arg == "--agent":
            agent = next(rest, None)
    env = dict(os.environ)
    try:
        if action == "refresh":
            agents = set(detect_installed_agents(root))
            if agent in AGENT_NAMES:
                agents.add(AGENT_NAMES[agent])
            refresh_policy(root, env, agents=sorted(agents))
            send_events(env, root)
            return 0
        if action == "send":
            send_events(env, root)
            return 0
    except Exception:
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
