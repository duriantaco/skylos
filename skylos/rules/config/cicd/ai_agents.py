"""GitHub Actions rules for AI coding agents that run in CI (SKY-D350 to SKY-D354).

An agent step (claude-code-action, codex-action, run-gemini-cli, ai-inference,
the opencode action, or a claude/codex/gemini/copilot CLI in a run block)
follows instructions found in the text it reads. On events that anyone can
start (issues, comments, fork pull requests) that text is attacker-written,
so the questions are: who can start the step, what can the agent do, and what
does the job hold.

- SKY-D350: an untrusted event reaches the agent with no actor gate (no
  author_association, actor or permission check in the workflow, and no
  write-access check built into the action), while the job holds secrets or a
  write-capable token.
- SKY-D351: the action's own write-access check is switched off
  (``allowed_non_write_users: "*"``, ``allowed_bots: "*"``, ``allow-users: "*"``).
- SKY-D352: the agent can run arbitrary shell commands in a workflow that an
  untrusted event starts.
- SKY-D353: untrusted event text is interpolated into the agent's prompt.
- SKY-D354: the action version has a published GitHub security advisory.

Action inputs and built-in checks were verified against each action's
action.yml and source on 2026-10-13; see dictionary.md for the references.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.config.cicd.ai_agent_expressions import (
    ACTOR_ENTITY,
    EVENT_ENTITIES,
    EvalContext,
    evaluate,
    has_status_override,
    parse_condition,
)
from skylos.rules.config.cicd.ai_agent_versions import (
    CLAUDE_CODE_ACTION_RELEASES,
    RUN_GEMINI_CLI_RELEASES,
)
from skylos.rules.config.cicd.github_actions import (
    SECRETS_OUTSIDE_ENV_RE,
    WORKFLOW_SUFFIXES,
    _actions_bool,
    _add_finding,
    _finding,
    _iter_strings,
    _job_reads_pr_code,
    _jobs,
    _load_yaml,
    _on_value,
    _source_for_lines,
    _uses_repo,
)

RULE_NO_GATE = "SKY-D350"
RULE_WIDENED = "SKY-D351"
RULE_SHELL = "SKY-D352"
RULE_PROMPT = "SKY-D353"
RULE_ADVISORY = "SKY-D354"
AI_AGENT_RULES = (RULE_NO_GATE, RULE_WIDENED, RULE_SHELL, RULE_PROMPT, RULE_ADVISORY)

# Event types an account without write access can cause. None means every type.
# Types such as labeled or assigned need triage access, so the account that
# starts them is a maintainer.
UNTRUSTED_EVENT_TYPES: dict[str, frozenset[str] | None] = {
    "issues": frozenset({"opened", "edited", "closed", "reopened"}),
    "issue_comment": None,
    "pull_request_target": frozenset(
        {
            "opened",
            "edited",
            "closed",
            "reopened",
            "synchronize",
            "ready_for_review",
            "converted_to_draft",
        }
    ),
    "pull_request_review": frozenset({"submitted", "edited"}),
    "pull_request_review_comment": None,
    "discussion": frozenset(
        {"created", "edited", "answered", "unanswered", "category_changed"}
    ),
    "discussion_comment": None,
    "workflow_run": None,
}
# Upstream triggers that let an account without write access start a run.
_FORK_REACHABLE_EVENTS = frozenset(UNTRUSTED_EVENT_TYPES) | {"pull_request"}
# Events where a maintainer's comment starts the agent on a thread others wrote.
_THREAD_EVENTS = frozenset(
    {
        "issue_comment",
        "pull_request_review",
        "pull_request_review_comment",
        "discussion_comment",
    }
)
EVENT_DESCRIPTIONS = {
    "issues": "issues (anyone who can open an issue)",
    "issue_comment": "issue_comment (anyone who can comment)",
    "pull_request_target": "pull_request_target (fork pull requests)",
    "pull_request_review": "pull_request_review (any reviewer)",
    "pull_request_review_comment": "pull_request_review_comment (anyone who can comment)",
    "discussion": "discussion (anyone who can start a discussion)",
    "discussion_comment": "discussion_comment (anyone who can comment)",
    "workflow_run": "workflow_run (after runs that fork pull requests can start)",
}

# Events on which each action checks that the triggering account has write
# access (claude-code-action src/entrypoints/run.ts and
# src/github/validation/permissions.ts; codex-action src/checkActorPermissions.ts;
# opencode github/index.ts assertPermissions).
_CLAUDE_CHECKED_EVENTS = frozenset(
    {
        "issues",
        "issue_comment",
        "pull_request_target",
        "pull_request_review",
        "pull_request_review_comment",
        "workflow_run",
    }
)
_ALL_UNTRUSTED_EVENTS = frozenset(UNTRUSTED_EVENT_TYPES)
# claude-code-action checks the upstream actor of workflow_run events from
# v1.0.185 (commit acb0385805, PR #1590).
_CLAUDE_WORKFLOW_RUN_CHECK_VERSION = (1, 0, 185)

# Commands that run arbitrary code when allowed with any arguments.
_ARBITRARY_COMMANDS = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "dash",
        "fish",
        "pwsh",
        "powershell",
        "python",
        "python3",
        "node",
        "deno",
        "bun",
        "ruby",
        "perl",
        "php",
        "eval",
        "exec",
        "env",
        "xargs",
        "sudo",
        "curl",
        "wget",
        "npx",
        "bunx",
        "pnpx",
        "uvx",
        "pipx",
        "docker",
    }
)
# Package managers that run arbitrary scripts when allowed with any arguments.
_PACKAGE_RUNNERS = frozenset({"npm", "pnpm", "yarn", "uv", "pip", "make"})
_EXEC_SUBCOMMANDS = frozenset({"-c", "-e", "--eval", "eval", "exec", "run", "x", "dlx"})
_GEMINI_SHELL_TOOLS = frozenset({"run_shell_command", "shelltool"})
_GEMINI_WRITE_TOOLS = frozenset(
    {"write_file", "replace", "edit", "writefiletool", "edittool", "smartedittool"}
)

# Published advisories (github.com/advisories, fetched 2026-10-13).
_CLAUDE_ADVISORY = (
    "GHSA-8q5r-mmjf-575q",
    "CVE-2026-47751",
    "1.0.74",
    "MEDIUM",
    "a pull request's .mcp.json could run code on the runner and read workflow secrets",
)
_GEMINI_ADVISORY = (
    "GHSA-wpqr-6v78-jr5g",
    "CVE-2026-12537",
    "0.1.22",
    "CRITICAL",
    "headless runs trusted workspace settings and ignored tool allowlists under --yolo",
)
_GEMINI_CLI_FIXED = (0, 39, 1)

_UNTRUSTED_TEXT_RE = re.compile(
    r"\$\{\{[^}]*?\b("
    r"github\.event\.(?:"
    r"issue\.(?:title|body)"
    r"|comment\.body"
    r"|review\.body"
    r"|review_comment\.body"
    r"|pull_request\.(?:title|body|head\.ref|head\.label)"
    r"|discussion\.(?:title|body)"
    r"|workflow_run\.(?:head_branch|display_title|head_commit\.message)"
    r")"
    r"|github\.head_ref"
    r"|toJSON\(\s*github\.event"
    r"(?:\.(?:issue|comment|pull_request|review|discussion|workflow_run))?\s*\)"
    r")",
    re.IGNORECASE,
)
_FIELD_ENTITY = (
    ("github.event.issue.", "issue"),
    ("github.event.comment.", "comment"),
    ("github.event.review_comment.", "comment"),
    ("github.event.review.", "review"),
    ("github.event.pull_request.", "pull_request"),
    ("github.head_ref", "pull_request"),
    ("github.event.discussion.", "discussion"),
    ("github.event.workflow_run.", "workflow_run"),
)

_PERMISSION_ACTION_RE = re.compile(
    r"permission|collaborator|is-?member|membership|org-?member|team-?member"
    r"|check-?actor|authoriz|verify-?(?:user|actor)",
    re.IGNORECASE,
)
_PERMISSION_SCRIPT_RE = re.compile(
    r"getCollaboratorPermissionLevel|checkMembershipForUser|checkCollaborator"
    r"|collaborators/[^\s'\"]*/permission|/collaborators/\$"
    r"|orgs/[^\s'\"]+/members/|teams/[^\s'\"]+/memberships/",
    re.IGNORECASE,
)
# A script that compares author_association with a member value. A script that
# only looks for NONE or CONTRIBUTOR is spotting outsiders, not gating them.
_ASSOCIATION_CHECK_RE = re.compile(r"author_association", re.IGNORECASE)
_MEMBER_VALUE_RE = re.compile(r"\b(?:OWNER|MEMBER|COLLABORATOR)\b")
# A prompt that is about the triggering issue, pull request or comment.
_PROMPT_EVENT_RE = re.compile(
    r"github\.event\.(?:issue|pull_request|comment|review|discussion|number)"
    r"|\b(?:issues?|pull[ _-]?requests?|PRs?|comments?|discussions?)\b"
    r"|(?:^|\n)\s*/[A-Za-z]",
    re.IGNORECASE,
)
# Redirect or tee targets, and script file writes, in a run block or script.
_FILE_TARGET_RE = re.compile(r"(?:>>?|\btee\b(?:\s+-a)?)\s*[\"']?([^\s\"'|;&)]+)")
_SCRIPT_WRITE_RE = re.compile(r"writeFile|fs\.write|appendFile")
_NON_FILE_TARGETS = ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "/dev/null", "/dev/stderr", "/dev/stdout", "&")
# Claude Code allow rules that only read.
_CLAUDE_READ_TOOLS = frozenset(
    {"Read", "Grep", "Glob", "LS", "View", "GlobTool", "GrepTool", "BatchTool",
     "WebFetch", "WebSearch", "Task", "TodoWrite", "TodoRead", "NotebookRead"}
)
_READ_ONLY_COMMANDS = (
    ("gh", "issue", "view"), ("gh", "issue", "list"), ("gh", "pr", "view"),
    ("gh", "pr", "diff"), ("gh", "pr", "list"), ("gh", "pr", "checks"),
    ("gh", "search"), ("gh", "label", "list"), ("gh", "run", "view"),
    ("gh", "run", "list"), ("gh", "release", "view"), ("gh", "release", "list"),
    ("gh", "repo", "view"), ("gh", "workflow", "view"), ("git", "log"), ("git", "diff"), ("git", "show"),
    ("git", "blame"), ("git", "status"), ("ls",), ("cat",), ("grep",), ("rg",),
    ("find",), ("head",), ("tail",), ("wc",), ("echo",),
)
# A script or command in an earlier step that fetches issue, comment or pull
# request text (it then counts when that step also writes a file).
_EVENT_TEXT_FETCH_RE = re.compile(
    r"context\.payload\.(?:issue|comment|pull_request|review|discussion)\b"
    r"|\b(?:issues|pulls)\.(?:get|listComments|listReviewComments)\b"
    r"|\bgh\s+(?:issue|pr)\s+view\b|\bgh\s+api\s+[^\n]*\b(?:issues|pulls)/",
)
# Events whose jobs can check out a pull request's code with secrets present.
_PR_CODE_EVENTS = frozenset(
    {
        "pull_request_target",
        "workflow_run",
        "issue_comment",
        "pull_request_review",
        "pull_request_review_comment",
    }
)
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_MAX_SIBLING_WORKFLOWS = 80


@dataclass
class _Agent:
    label: str
    tier: str  # shell | tools | read | none
    tier_reason: str
    tier_key: str | None = None
    # Events on which the action checks the triggering account's write access.
    checked_events: frozenset[str] = frozenset()
    widened: list[tuple[str, str]] = field(default_factory=list)
    prompt_inputs: list[str] = field(default_factory=list)
    advisories: list[tuple[str, str, str, str, str, str | None]] = field(
        default_factory=list
    )
    anchor_key: str = "uses"
    bots_only_widening: bool = False
    # How attacker-written text can reach the agent.
    ingests_event: bool = False  # the action itself loads the triggering thread
    reads_github: str = ""  # a tool that can fetch issue or pull request text
    reads_env: bool = False  # it can read environment variables
    prompt_text: str = ""  # prompt-like inputs, or the run block of a CLI
    prompt_from_file: bool = False


@dataclass
class _Caller:
    """A local workflow job that calls this reusable workflow."""

    file: Path
    data: dict[str, Any]
    job_id: Any
    job: dict[str, Any]
    reach: _Reach


@dataclass
class _Privilege:
    secrets: list[str]
    write_scopes: list[str]
    undeclared: bool
    oidc: bool

    @property
    def present(self) -> bool:
        return bool(self.secrets or self.write_scopes or self.undeclared or self.oidc)

    def describe(self) -> str:
        parts = []
        if self.secrets:
            shown = ", ".join(self.secrets[:3])
            more = f" and {len(self.secrets) - 3} more" if len(self.secrets) > 3 else ""
            parts.append(f"secrets {shown}{more}")
        if self.write_scopes:
            parts.append(", ".join(self.write_scopes))
        elif self.undeclared:
            parts.append("undeclared token permissions (the repository default may be write)")
        if self.oidc and "id-token: write" not in self.write_scopes:
            parts.append("id-token: write")
        return "; ".join(parts) if parts else "no secrets or write token"


# ---------------------------------------------------------------- helpers


def _ref(uses: str) -> str:
    return uses.rsplit("@", 1)[1].strip() if "@" in uses else ""


def _semver(text: str | None) -> tuple[int, int, int] | None:
    if not isinstance(text, str):
        return None
    match = _SEMVER_RE.match(text.strip())
    return tuple(int(part) for part in match.groups()) if match else None  # type: ignore[return-value]


def _release(ref: str, table: dict[str, str]) -> tuple[int, int, int] | None:
    """The release a ref names: a semver tag or a known release commit."""
    version = _semver(ref)
    if version is not None:
        return version
    if _FULL_SHA_RE.match(ref):
        return _semver(table.get(ref.lower()))
    return None


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _with(step: dict[str, Any]) -> dict[str, Any]:
    config = step.get("with")
    return {str(key): value for key, value in config.items()} if isinstance(config, dict) else {}


def _split_tools(value: str) -> list[str]:
    """Split a tool list on commas, newlines and spaces outside parentheses."""
    items: list[str] = []
    depth = 0
    current: list[str] = []
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if depth == 0 and char in ",\n \t":
            if current:
                items.append("".join(current).strip().strip("'\""))
                current = []
            continue
        current.append(char)
    if current:
        items.append("".join(current).strip().strip("'\""))
    return [item for item in items if item]


def _flag_values(args: str, names: tuple[str, ...]) -> list[str]:
    """Values given to any of ``names`` in a CLI argument string."""
    values: list[str] = []
    pattern = re.compile(
        r"(?<![\w-])(?:" + "|".join(re.escape(name) for name in names) + r")"
        r"(?:=|\s+)((?:\"[^\"]*\"|'[^']*'|[^\s\"'-][^\s]*)"
        r"(?:\s+(?:\"[^\"]*\"|'[^']*'|[^\s\"'-][^\s]*))*)"
    )
    for match in pattern.finditer(args):
        values.extend(_split_tools(match.group(1)))
    return values


def _bash_entry_is_arbitrary(entry: str) -> bool:
    """Whether a Claude Code allow rule permits any shell command."""
    match = re.fullmatch(r"Bash(?:\((?P<inner>.*)\))?", entry.strip(), re.DOTALL)
    if match is None:
        return False
    inner = match.group("inner")
    if inner is None:
        return True
    inner = inner.strip()
    if inner in {"", "*", ":*"} or inner.startswith("*"):
        return True
    # Without a trailing wildcard a rule allows one exact command line.
    if not re.search(r"(?::\*|\s\*|\*)$", inner):
        return False
    prefix = re.sub(r"(?::\*|\s+\*|\*)$", "", inner).strip()
    words = prefix.split()
    if not words:
        return True
    command = words[0].rsplit("/", 1)[-1].lower()
    if command not in _ARBITRARY_COMMANDS and command not in _PACKAGE_RUNNERS:
        return False
    # `python:*`, `npm:*` or `bash -c:*` run anything; `bun test:*` runs one tool.
    return len(words) == 1 or (len(words) == 2 and words[1].lower() in _EXEC_SUBCOMMANDS)


def _settings_json(value: Any) -> dict[str, Any] | None:
    """Parse settings JSON, standing in a string for each ${{ }} expression."""
    if isinstance(value, str) and "${{" in value:
        value = re.sub(r'"\$\{\{.*?\}\}"', '"__expression__"', value, flags=re.DOTALL)
        value = re.sub(r"\$\{\{.*?\}\}", '"__expression__"', value, flags=re.DOTALL)
    return _json_object(value)


def _json_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip().startswith("{"):
        return None
    try:
        parsed = json.loads(value)
    except (ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, dict) else None


# ------------------------------------------------------------ agent models


def _bash_command_words(entry: str) -> list[str] | None:
    match = re.fullmatch(r"Bash\((?P<inner>.*)\)", entry.strip(), re.DOTALL)
    if match is None:
        return None
    prefix = re.sub(r"(?::\*|\s+\*|\*)$", "", match.group("inner").strip()).strip()
    return [word.lower() for word in prefix.split()]


def _claude_entry_reads_only(entry: str) -> bool:
    name = entry.split("(", 1)[0].strip()
    if name in _CLAUDE_READ_TOOLS:
        return True
    if name.startswith("mcp__github"):
        operation = name.rsplit("__", 1)[-1]
        return operation.startswith(("get_", "list_", "search_"))
    words = _bash_command_words(entry)
    if words:
        return any(tuple(words[: len(cmd)]) == cmd for cmd in _READ_ONLY_COMMANDS)
    return False


def _claude_reads_github(entries: list[str]) -> str:
    """The first allowed tool that can fetch issue or pull request text."""
    candidates = []
    for entry in entries:
        words = _bash_command_words(entry) or []
        if _bash_entry_is_arbitrary(entry):
            candidates.append((0, entry))
        elif (
            words[:2] in (["gh", "issue"], ["gh", "pr"], ["gh", "api"])
            or words == ["gh"]
            or (
                entry.startswith("mcp__github")
                and re.search(r"issue|pull|comment|discussion", entry, re.IGNORECASE)
            )
        ):
            candidates.append((1, entry))
        elif entry.startswith("WebFetch"):
            candidates.append((2, entry))
    return min(candidates)[1] if candidates else ""


def _frontmatter_tools(text: str) -> list[str]:
    """allowed-tools from a Claude Code slash command's YAML front matter."""
    match = re.match(r"\A---\s*\n(?P<body>.*?)\n---\s*(?:\n|\Z)", text, re.DOTALL)
    if match is None:
        return []
    for line in match.group("body").splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "allowed-tools":
            return _split_tools(value.replace("[", " ").replace("]", " "))
    return []


def _slash_command_tools(prompt: str, repo_root: Path | None) -> list[str]:
    match = re.match(r"\s*/(?P<name>[A-Za-z0-9_.-]+)(?:\s|$)", prompt)
    if match is None or repo_root is None:
        return []
    command = repo_root / ".claude" / "commands" / f"{match.group('name')}.md"
    text = read_project_text_no_symlink(repo_root, command, max_bytes=65_536, encoding="utf-8")
    return _frontmatter_tools(text) if text else []


def _claude_tier(
    config: dict[str, Any], *, legacy: bool, tag_mode: bool, extra_allowed: list[str]
) -> tuple[str, str, str | None, str]:
    """(tier, reason, input key, GitHub-reading tool) for a Claude Code action."""
    args = _text(config.get("claude_args"))
    allowed: list[tuple[str, str]] = [(item, "slash command") for item in extra_allowed]
    denied: set[str] = set()
    if args:
        if re.search(r"(?<![\w-])--dangerously-skip-permissions\b", args):
            return "shell", "--dangerously-skip-permissions", "claude_args", "Bash"
        if re.search(r"--permission-mode(?:=|\s+)[\"']?bypassPermissions\b", args):
            return "shell", "--permission-mode bypassPermissions", "claude_args", "Bash"
        allowed += [
            (item, "claude_args")
            for item in _flag_values(args, ("--allowedTools", "--allowed-tools"))
        ]
        denied |= set(_flag_values(args, ("--disallowedTools", "--disallowed-tools")))
    settings = _json_object(config.get("settings"))
    if settings is not None:
        permissions = settings.get("permissions")
        if isinstance(permissions, dict):
            if permissions.get("defaultMode") == "bypassPermissions":
                return "shell", "settings defaultMode bypassPermissions", "settings", "Bash"
            allow = permissions.get("allow")
            if isinstance(allow, list):
                allowed += [(str(item), "settings") for item in allow if isinstance(item, str)]
            deny = permissions.get("deny")
            if isinstance(deny, list):
                denied |= {str(item) for item in deny if isinstance(item, str)}
    if legacy:
        for key in ("allowed_tools", "disallowed_tools"):
            raw = _text(config.get(key))
            if not raw:
                continue
            items = _split_tools(raw)
            if key == "allowed_tools":
                allowed += [(item, key) for item in items]
            else:
                denied |= set(items)
    entries = [entry for entry, _ in allowed if entry not in denied]
    reads_github = _claude_reads_github(entries)
    if "Bash" not in denied:
        for entry, key in allowed:
            if _bash_entry_is_arbitrary(entry):
                where = "--allowedTools" if key == "claude_args" else key
                return "shell", f"{entry} in {where}", key, reads_github
    if tag_mode:
        return "tools", "its default tools (file edits, git, GitHub comments)", None, "tag mode"
    writers = [entry for entry in entries if not _claude_entry_reads_only(entry)]
    if writers:
        shown = ", ".join(writers[:3])
        return "tools", f"tools that can change things ({shown})", None, reads_github
    if entries:
        return "read", f"read-only tools ({', '.join(entries[:3])})", None, reads_github
    if {"Read", "Bash"} <= denied or "*" in denied:
        return "none", "all built-in tools denied", None, ""
    return "read", "read-only default tools", None, reads_github


def _claude_action(
    uses: str, config: dict[str, Any], *, base: bool, repo_root: Path | None
) -> _Agent:
    ref = _ref(uses)
    version = _release(ref, CLAUDE_CODE_ACTION_RELEASES)
    legacy = ref.lower() in {"beta", "v0"} or (version is not None and version[0] == 0)
    prompt = _text(config.get("prompt")) or _text(config.get("direct_prompt"))
    if base:
        tag_mode = False
    elif legacy:
        tag_mode = _text(config.get("mode")).strip().lower() != "agent"
    else:
        # src/modes/detector.ts: a prompt selects agent mode unless track_progress.
        tag_mode = not _text(config.get("prompt")).strip() or (
            _actions_bool(config.get("track_progress")) is True
        )
    tier, reason, key, reads_github = _claude_tier(
        config,
        # claude-code-base-action took allowed_tools until its v1 rewrite.
        legacy=legacy or (base and "allowed_tools" in config),
        tag_mode=tag_mode,
        extra_allowed=_slash_command_tools(prompt, repo_root),
    )
    label = "claude-code-base-action" if base else "claude-code-action"
    agent = _Agent(label=label, tier=tier, tier_reason=reason, tier_key=key)
    agent.prompt_inputs = ["prompt", "claude_args"]
    if legacy:
        agent.prompt_inputs += ["direct_prompt", "override_prompt", "custom_instructions"]
    agent.ingests_event = tag_mode
    agent.reads_github = reads_github
    agent.reads_env = tier == "shell"
    agent.prompt_from_file = bool(_text(config.get("prompt_file")).strip())
    if legacy or base:
        claude_env = _text(config.get("claude_env"))
        if claude_env:
            agent.prompt_inputs.append("claude_env")
    if base:
        return agent

    checks_workflow_run = not legacy and (
        version is None or version >= _CLAUDE_WORKFLOW_RUN_CHECK_VERSION
    )
    agent.checked_events = (
        _CLAUDE_CHECKED_EVENTS
        if checks_workflow_run
        else _CLAUDE_CHECKED_EVENTS - {"workflow_run"}
    )
    non_write = config.get("allowed_non_write_users")
    # The bypass only applies when github_token is passed (OVERRIDE_GITHUB_TOKEN).
    if (
        not legacy
        and isinstance(non_write, str)
        and non_write.strip() == "*"
        and _text(config.get("github_token")).strip()
    ):
        agent.widened.append(("allowed_non_write_users", "*"))
    bots = config.get("allowed_bots")
    if isinstance(bots, str) and bots.strip() == "*":
        agent.widened.append(("allowed_bots", "*"))
        agent.bots_only_widening = not any(
            name == "allowed_non_write_users" for name, _ in agent.widened
        )
    if version is not None and (1, 0, 0) <= version < (1, 0, 74):
        agent.advisories.append((*_CLAUDE_ADVISORY, None))
    return agent


def _codex_tier(config: dict[str, Any]) -> tuple[str, str, str | None]:
    strategy = _text(config.get("safety-strategy")).strip().lower() or "drop-sudo"
    sandbox = _text(config.get("sandbox")).strip().lower()
    profile = _text(config.get("permission-profile")).strip()
    raw_args = config.get("codex-args")
    args_text = _text(raw_args)
    parsed_args: list[str] = []
    if args_text.strip().startswith("["):
        try:
            loaded = json.loads(args_text)
            parsed_args = [str(item) for item in loaded] if isinstance(loaded, list) else []
        except (ValueError, RecursionError):
            parsed_args = []
    joined = " ".join(parsed_args) if parsed_args else args_text
    if strategy == "unsafe":
        return "shell", "safety-strategy: unsafe", "safety-strategy"
    if sandbox == "danger-full-access":
        return "shell", "sandbox: danger-full-access", "sandbox"
    protected = bool(profile) or strategy == "read-only" or sandbox == "read-only"
    if not protected:
        # codex-action rejects these only with a permission profile or read-only sandbox.
        if re.search(r"(?<![\w-])(?:--dangerously-bypass-approvals-and-sandbox|--yolo)\b", joined):
            return "shell", "codex-args bypass the sandbox", "codex-args"
        if re.search(r"(?<![\w-])(?:-s|--sandbox)(?:=|\s+)[\"']?danger-full-access", joined):
            return "shell", "codex-args sandbox danger-full-access", "codex-args"
    if strategy == "read-only" or sandbox == "read-only" or profile == ":read-only":
        return "read", "read-only sandbox", None
    if re.search(r"network_access\s*=\s*[\"']?true", joined, re.IGNORECASE):
        return "tools", "sandboxed commands with network access", "codex-args"
    # The workspace-write sandbox has no network; the API key stays in a proxy.
    return "read", "sandboxed commands without network access", None


def _codex_action(config: dict[str, Any]) -> _Agent:
    tier, reason, key = _codex_tier(config)
    agent = _Agent(label="codex-action", tier=tier, tier_reason=reason, tier_key=key)
    # The workspace-write and read-only sandboxes have no network access.
    agent.reads_github = "network access" if tier in {"shell", "tools"} else ""
    agent.reads_env = tier == "shell"
    agent.prompt_from_file = bool(_text(config.get("prompt-file")).strip())
    agent.checked_events = _ALL_UNTRUSTED_EVENTS
    agent.prompt_inputs = ["prompt"]
    users = config.get("allow-users")
    if isinstance(users, str) and users.strip() == "*":
        agent.widened.append(("allow-users", "*"))
    return agent


def _gemini_tool_names(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    return [str(item).strip() for item in value if isinstance(item, (str, int, float))]


def _gemini_tier(
    config: dict[str, Any], repo_root: Path | None, *, cli_old: bool, trusted: bool
) -> tuple[str, str, str | None]:
    """Gemini CLI runs with --yolo in run-gemini-cli (action.yml). Before CLI
    0.39.1 it applied project settings and ignored tool allowlists under
    --yolo; from 0.39.1 it applies them only in a trusted workspace
    (GEMINI_CLI_TRUST_WORKSPACE), and an untrusted one disables auto-approval."""
    if not (cli_old or trusted):
        # folderTrust.enabled defaults to true: an untrusted workspace ignores
        # .gemini/settings.json and turns off tool auto-approval in headless runs.
        return (
            "read",
            "read-only tools (no GEMINI_CLI_TRUST_WORKSPACE, so settings and YOLO approval are off)",
            None,
        )
    raw = config.get("settings")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        if repo_root is not None and (repo_root / ".gemini" / "settings.json").exists():
            return "tools", "project settings decide the tools", None
        return "shell", "YOLO mode with no tools.core allowlist", None
    settings = _settings_json(raw)
    if settings is None:
        return "tools", "settings decide the tools", None
    tools = settings.get("tools") if isinstance(settings.get("tools"), dict) else {}
    core = _gemini_tool_names(tools.get("core", settings.get("coreTools")))
    exclude = _gemini_tool_names(tools.get("exclude", settings.get("excludeTools"))) or []
    shell_excluded = any(name.lower() in _GEMINI_SHELL_TOOLS for name in exclude)
    has_mcp = bool(settings.get("mcpServers"))
    if core is None:
        if shell_excluded:
            return "tools", "YOLO mode without the shell tool", None
        return "shell", "YOLO mode with no tools.core allowlist", "settings"
    names = [name.split("(", 1)[0].strip().lower() for name in core]
    bare_shell = any(
        name.split("(", 1)[0].strip().lower() in _GEMINI_SHELL_TOOLS
        and ("(" not in name or name.split("(", 1)[1].strip(" )") in {"", "*"})
        for name in core
    )
    if not shell_excluded and bare_shell:
        return "shell", "run_shell_command in tools.core", "settings"
    if not shell_excluded and any(name in _GEMINI_SHELL_TOOLS for name in names):
        if cli_old:
            return (
                "shell",
                "tools.core command allowlist, ignored under --yolo before Gemini CLI 0.39.1",
                "settings",
            )
        commands = [
            entry.split("(", 1)[1].rstrip(") ").split()
            for entry in core
            if entry.split("(", 1)[0].strip().lower() in _GEMINI_SHELL_TOOLS and "(" in entry
        ]
        read_only = all(
            any(tuple(word.lower() for word in words[: len(cmd)]) == cmd for cmd in _READ_ONLY_COMMANDS)
            for words in commands
        )
        if not read_only or has_mcp or any(name in _GEMINI_WRITE_TOOLS for name in names):
            return "tools", "allowlisted shell commands", None
        return "read", "read-only allowlisted commands", None
    if has_mcp or any(name in _GEMINI_WRITE_TOOLS for name in names):
        return "tools", "write or MCP tools", None
    if not names:
        return "none", "no tools", None
    return "read", "read-only tools", None


def _gemini_action(
    uses: str, config: dict[str, Any], repo_root: Path | None, env_layers: list[Any]
) -> _Agent:
    ref = _ref(uses)
    version = _release(ref, RUN_GEMINI_CLI_RELEASES)
    cli_version_text = _text(config.get("gemini_cli_version")).strip()
    cli_version = _semver(cli_version_text)
    cli_old = (
        cli_version is not None and cli_version < _GEMINI_CLI_FIXED
    ) or cli_version_text.lower().lstrip("v") == "0.40.0-preview.2"
    action_vulnerable = version is not None and version < (0, 1, 22)
    trusted = _env_is_true(env_layers, ("GEMINI_CLI_TRUST_WORKSPACE", "GEMINI_TRUST_WORKSPACE"))
    tier, reason, key = _gemini_tier(config, repo_root, cli_old=cli_old, trusted=trusted)
    agent = _Agent(label="run-gemini-cli", tier=tier, tier_reason=reason, tier_key=key)
    agent.prompt_inputs = ["prompt"]
    agent.reads_env = tier == "shell"
    settings = _settings_json(config.get("settings")) or {}
    core_text = json.dumps(settings.get("tools", {})) + json.dumps(settings.get("coreTools", []))
    if tier == "shell":
        agent.reads_github = "shell commands"
    elif settings.get("mcpServers"):
        agent.reads_github = "MCP servers in settings"
    elif re.search(r"run_shell_command\(\s*(?:gh|curl)\b|web_fetch", core_text):
        agent.reads_github = "tools.core"
    if action_vulnerable:
        agent.advisories.append((*_GEMINI_ADVISORY, None))
    elif cli_old:
        agent.advisories.append((*_GEMINI_ADVISORY, "gemini_cli_version"))
    return agent


def _env_is_true(env_layers: list[Any], names: tuple[str, ...]) -> bool:
    for env in env_layers:
        if not isinstance(env, dict):
            continue
        for key, value in env.items():
            if str(key) in names and _actions_bool(value) is True:
                return True
    return False


def _ai_inference_action(config: dict[str, Any]) -> _Agent:
    allow = _split_tools(_text(config.get("copilot-allow-tools")))
    for entry in allow:
        inner = entry[len("shell"):].strip() if entry.lower().startswith("shell") else None
        if inner is not None and inner.strip("()* ") == "":
            return _Agent(
                label="ai-inference",
                tier="shell",
                tier_reason=f"{entry} in copilot-allow-tools",
                tier_key="copilot-allow-tools",
                prompt_inputs=["prompt", "system-prompt", "input"],
                reads_github="shell commands",
                reads_env=True,
                prompt_from_file=bool(_text(config.get("prompt-file")).strip()),
            )
    mcp = _actions_bool(config.get("enable-github-mcp")) is True
    if allow:
        tier, reason = "tools", "copilot-allow-tools"
    elif mcp:
        tier, reason = "tools", "GitHub MCP tools"
    else:
        tier, reason = "none", "no tools"
    return _Agent(
        label="ai-inference",
        tier=tier,
        tier_reason=reason,
        prompt_inputs=["prompt", "system-prompt", "input"],
        reads_github="GitHub MCP tools" if mcp else "",
        prompt_from_file=bool(_text(config.get("prompt-file")).strip()),
    )


def _opencode_action() -> _Agent:
    return _Agent(
        label="opencode",
        tier="tools",
        tier_reason="its default agent tools",
        checked_events=_ALL_UNTRUSTED_EVENTS,
        prompt_inputs=["prompt"],
        ingests_event=True,
    )


# CLI agents started from run blocks.
_CLI_COMMAND_RE = re.compile(
    r"(?m)(?:^|[;&|(`]|\$\()[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=\S*[ \t]+)*"
    r"(?:(?:sudo|time|exec|command|nohup)[ \t]+|timeout[ \t]+\S+[ \t]+)*"
    r"(?P<cmd>(?:\S*/)?(?:claude|codex|gemini|copilot)"
    r"|(?:npx|bunx|pnpx|pnpm[ \t]+dlx|yarn[ \t]+dlx)(?:[ \t]+(?:-y|--yes|-p[ \t]+\S+))*[ \t]+"
    r"@(?:anthropic-ai/claude-code|openai/codex|google/gemini-cli|github/copilot)(?:@\S+)?)"
    r"(?=[ \t\n]|$)"
)
_AWS_COPILOT_SUBCOMMANDS = frozenset(
    {"app", "env", "svc", "job", "pipeline", "init", "deploy", "storage", "secret", "task", "run", "version", "docs", "completion"}
)


def _command_span(text: str, start: int) -> str:
    """Text of one shell command from ``start``: quotes may span lines."""
    out: list[str] = []
    quote: str | None = None
    index = start
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\" and quote == '"' and index + 1 < len(text):
                out.append(text[index : index + 2])
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "\\" and text[index + 1 : index + 2] == "\n":
            out.append(" ")
            index += 2
            continue
        elif char in "\n;|&":
            break
        out.append(char)
        index += 1
        if len(out) > 20_000:
            break
    return "".join(out)


def _cli_name(command: str) -> str:
    lowered = command.lower()
    if "claude" in lowered:
        return "claude"
    if "codex" in lowered:
        return "codex"
    if "gemini" in lowered:
        return "gemini"
    return "copilot"


def _cli_agent_tier(name: str, span: str, env_text: str) -> tuple[str, str] | None:
    if name == "claude":
        if not re.search(r"(?<!\S)(?:-p|--print)(?!\S)", span):
            return None
        if re.search(r"(?<![\w-])--dangerously-skip-permissions\b", span):
            return "shell", "--dangerously-skip-permissions"
        if re.search(r"--permission-mode(?:=|\s+)[\"']?bypassPermissions\b", span):
            return "shell", "--permission-mode bypassPermissions"
        allowed = _flag_values(span, ("--allowedTools", "--allowed-tools"))
        denied = set(_flag_values(span, ("--disallowedTools", "--disallowed-tools")))
        if "Bash" not in denied:
            for entry in allowed:
                if _bash_entry_is_arbitrary(entry):
                    return "shell", f"{entry} in --allowedTools"
        if allowed:
            return "tools", "allowed tools"
        return "read", "print mode without allowed tools"
    if name == "codex":
        if not re.search(r"(?<![\w-])(?:exec|e)(?!\S)", span):
            return None
        if re.search(r"(?<![\w-])(?:--dangerously-bypass-approvals-and-sandbox|--yolo)\b", span):
            return "shell", "--dangerously-bypass-approvals-and-sandbox"
        if re.search(r"(?<![\w-])(?:-s|--sandbox)(?:=|\s+)[\"']?danger-full-access", span) or re.search(
            r"sandbox_mode\s*=\s*[\"']?danger-full-access", span
        ):
            return "shell", "sandbox danger-full-access"
        if re.search(r"(?<![\w-])--full-auto\b|workspace-write", span):
            return "tools", "workspace-write sandbox"
        return "read", "read-only sandbox"
    if name == "gemini":
        cleaned = re.sub(r"(?:npx|bunx|pnpx)(?:\s+(?:-y|--yes))+", "", span)
        if re.search(r"(?<![\w-])(?:--yolo|-y)(?![\w-])", cleaned) or re.search(
            r"--approval-mode(?:=|\s+)[\"']?yolo\b", cleaned
        ):
            return "shell", "--yolo"
        if re.search(r"--approval-mode(?:=|\s+)[\"']?auto_edit\b", cleaned):
            return "tools", "--approval-mode auto_edit"
        if not re.search(r"(?<![\w-])(?:-p|--prompt)(?![\w-])", cleaned):
            return None
        return "read", "non-interactive mode without --yolo"
    # GitHub Copilot CLI. AWS Copilot shares the command name.
    words = span.split()
    if len(words) > 1 and words[1].lower() in _AWS_COPILOT_SUBCOMMANDS:
        return None
    if not re.search(r"(?<![\w-])(?:-p|--prompt)(?![\w-])", span):
        return None
    if re.search(r"(?<![\w-])(?:--allow-all-tools|--allow-all|--yolo)\b", span) or re.search(
        r"COPILOT_ALLOW_ALL\s*[:=]\s*[\"']?(?:true|1|yes|on|y)\b", env_text, re.IGNORECASE
    ):
        return "shell", "--allow-all-tools"
    tools = _flag_values(span, ("--allow-tool",))
    for entry in tools:
        if entry.lower().startswith("shell") and entry[5:].strip("()* ") == "":
            return "shell", f"--allow-tool {entry}"
    if tools:
        return "tools", "--allow-tool"
    return "none", "no tools allowed"


_CLI_LABELS = {
    "claude": "Claude Code CLI",
    "codex": "Codex CLI",
    "gemini": "Gemini CLI",
    "copilot": "Copilot CLI",
}
_TIER_RANK = {"none": 0, "read": 1, "tools": 2, "shell": 3}


def _cli_agent(run: str, env_text: str) -> _Agent | None:
    best: _Agent | None = None
    for match in _CLI_COMMAND_RE.finditer(run):
        name = _cli_name(match.group("cmd"))
        span = _command_span(run, match.start("cmd"))
        result = _cli_agent_tier(name, span, env_text)
        if result is None:
            continue
        tier, reason = result
        reads_github = "shell commands" if tier == "shell" else ""
        if name == "claude" and not reads_github:
            reads_github = _claude_reads_github(
                _flag_values(span, ("--allowedTools", "--allowed-tools"))
            )
        agent = _Agent(
            label=_CLI_LABELS[name],
            tier=tier,
            tier_reason=reason,
            anchor_key="run",
            reads_github=reads_github,
            reads_env=tier == "shell",
            prompt_text=run,
        )
        if best is None or _TIER_RANK[tier] > _TIER_RANK[best.tier]:
            best = agent
    return best


def _action_agent(
    uses: str, config: dict[str, Any], repo_root: Path | None, env_layers: list[Any]
) -> _Agent | None:
    repo = _uses_repo(uses)
    if repo == "anthropics/claude-code-action":
        return _claude_action(uses, config, base=False, repo_root=repo_root)
    if repo == "anthropics/claude-code-base-action":
        return _claude_action(uses, config, base=True, repo_root=repo_root)
    if repo == "openai/codex-action":
        return _codex_action(config)
    if repo == "google-github-actions/run-gemini-cli":
        return _gemini_action(uses, config, repo_root, env_layers)
    if repo == "actions/ai-inference":
        return _ai_inference_action(config)
    if repo in {"anomalyco/opencode/github", "sst/opencode/github"}:
        return _opencode_action()
    return None


def _agent_for_step(
    step: dict[str, Any], env_layers: list[Any], repo_root: Path | None
) -> _Agent | None:
    uses = step.get("uses")
    env_text = "\n".join(_iter_strings(env_layers))
    if isinstance(uses, str):
        config = _with(step)
        agent = _action_agent(uses, config, repo_root, env_layers)
        if agent is not None:
            agent.prompt_text = "\n".join(
                "\n".join(_iter_strings(config.get(name))) for name in agent.prompt_inputs
            )
        return agent
    run = step.get("run")
    if isinstance(run, str):
        return _cli_agent(run, env_text)
    return None


# ------------------------------------------------------------ triggers


def _trigger_map(data: dict[str, Any]) -> dict[str, Any]:
    trigger = _on_value(data)
    if isinstance(trigger, str):
        return {trigger: None}
    if isinstance(trigger, list):
        return {item: None for item in trigger if isinstance(item, str)}
    if isinstance(trigger, dict):
        return {str(key): value for key, value in trigger.items()}
    return {}


def _event_types(config: Any) -> list[str] | None:
    if not isinstance(config, dict) or "types" not in config:
        return None
    types = config.get("types")
    if isinstance(types, str):
        return [types]
    if isinstance(types, list):
        return [str(item) for item in types]
    return None


def _sibling_workflows(path: Path, root: Path | None) -> list[tuple[Path, dict[str, Any]]]:
    directory = path.parent
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return []
    siblings: list[tuple[Path, dict[str, Any]]] = []
    for entry in entries[:_MAX_SIBLING_WORKFLOWS]:
        if entry == path or entry.suffix.lower() not in WORKFLOW_SUFFIXES:
            continue
        if entry.is_symlink() or not entry.is_file():
            continue
        loaded = _load_yaml(entry, root=root)
        if loaded is not None:
            siblings.append((entry, loaded[0]))
    return siblings


def _workflow_run_untrusted(
    config: Any, path: Path, root: Path | None, siblings_cache: dict, depth: int = 0
) -> bool:
    """Whether an upstream run that a fork pull request can start may trigger
    this workflow_run. Unresolvable names count as untrusted."""
    if not isinstance(config, dict) or "workflows" not in config:
        return True
    names = config.get("workflows")
    if isinstance(names, str):
        names = [names]
    if names is None or names == []:
        return False  # no upstream workflow is listed, so it never runs
    if not isinstance(names, list) or depth > 3:
        return True
    if "siblings" not in siblings_cache:
        siblings_cache["siblings"] = _sibling_workflows(path, root)
    siblings = siblings_cache["siblings"]
    for name in names:
        if not isinstance(name, str):
            return True
        matches = [
            (sibling, data)
            for sibling, data in siblings
            if data.get("name") == name
            or (data.get("name") is None and sibling.name == name)
        ]
        if not matches:
            return True
        for sibling, data in matches:
            triggers = _trigger_map(data)
            if set(triggers) & (_FORK_REACHABLE_EVENTS - {"workflow_run"}):
                return True
            if "workflow_run" in triggers and _workflow_run_untrusted(
                triggers["workflow_run"], sibling, root, siblings_cache, depth + 1
            ):
                return True
    return False


def _untrusted_events(
    data: dict[str, Any], path: Path, root: Path | None, siblings_cache: dict
) -> list[str]:
    events = []
    for event, config in _trigger_map(data).items():
        if event not in UNTRUSTED_EVENT_TYPES:
            continue
        allowed = UNTRUSTED_EVENT_TYPES[event]
        types = _event_types(config)
        if types is not None and allowed is not None and not any(t in allowed for t in types):
            continue
        if event == "workflow_run" and not _workflow_run_untrusted(config, path, root, siblings_cache):
            continue
        events.append(event)
    return events


# ------------------------------------------------------------ reachability


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs")
    if isinstance(needs, str):
        return [needs]
    if isinstance(needs, list):
        return [str(item) for item in needs if isinstance(item, (str, int))]
    return []


def _step_checks_permission(step: dict[str, Any]) -> bool:
    uses = step.get("uses")
    if isinstance(uses, str) and _PERMISSION_ACTION_RE.search(_uses_repo(uses)):
        return True
    texts = [step.get("run"), _with(step).get("script")]
    for text in texts:
        if not isinstance(text, str):
            continue
        if _PERMISSION_SCRIPT_RE.search(text):
            return True
        if _ASSOCIATION_CHECK_RE.search(text) and _MEMBER_VALUE_RE.search(text):
            return True
    return False


_EVENT_ROUTING_RE = re.compile(
    r"github\.event_name|github\.event\.action|context\.eventName|context\.payload\.action"
    r"|GITHUB_EVENT_NAME",
    re.IGNORECASE,
)


def _job_routes_by_event(job: dict[str, Any] | None) -> bool:
    """Whether a job's steps read the event type (a dispatcher job)."""
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        return False
    return any(
        _EVENT_ROUTING_RE.search(text)
        for step in job["steps"]
        if isinstance(step, dict)
        for text in _iter_strings([step.get("run"), step.get("with"), step.get("env")])
    )


def _literal_environment(job: dict[str, Any]) -> str:
    environment = job.get("environment")
    if isinstance(environment, dict):
        environment = environment.get("name")
    if isinstance(environment, str) and environment.strip() and "${{" not in environment:
        return environment.strip()
    return ""


def _job_authorizes(job: dict[str, Any]) -> bool:
    """A recognized permission check; an environment name proves no approval."""
    steps = job.get("steps")
    return isinstance(steps, list) and any(
        isinstance(step, dict) and _step_checks_permission(step) for step in steps
    )


class _Reach:
    """Whether a job or step can run for an event and actor assumption."""

    def __init__(self, data: dict[str, Any]):
        self.jobs = {str(job_id): job for job_id, job in _jobs(data)}
        self._memo: dict[tuple[str, str, bool], bool] = {}

    def _blocked(self, job_id: str, event: str, untrusted: bool, stack: tuple[str, ...]) -> bool:
        job = self.jobs.get(job_id)
        if job is None:
            return False
        if not self.job_runs(job_id, event, untrusted, stack):
            return True
        return untrusted and _job_authorizes(job)

    def job_runs(
        self, job_id: str, event: str, untrusted: bool, stack: tuple[str, ...] = ()
    ) -> bool:
        key = (job_id, event, untrusted)
        if key in self._memo:
            return self._memo[key]
        if job_id in stack or len(stack) > 50:
            return True
        job = self.jobs.get(job_id)
        if job is None:
            return True
        inner = stack + (job_id,)
        result = True
        condition = parse_condition(job.get("if"))
        if not has_status_override(condition):
            for dep in _needs(job):
                if self._blocked(dep, event, untrusted, inner):
                    result = False
                    break
        if result:
            ctx = EvalContext(
                event,
                untrusted,
                lambda dep: self._blocked(dep, event, untrusted, inner),
                lambda dep: _job_routes_by_event(self.jobs.get(dep)),
            )
            result = evaluate(condition, ctx)[0]
        self._memo[key] = result
        return result

    def step_runs(self, job_id: str, index: int, event: str, untrusted: bool) -> bool:
        if not self.job_runs(job_id, event, untrusted):
            return False
        job = self.jobs[job_id]
        steps = job.get("steps") if isinstance(job.get("steps"), list) else []
        step = steps[index]
        ctx = EvalContext(
            event,
            untrusted,
            lambda dep: self._blocked(dep, event, untrusted, (job_id,)),
            lambda dep: _job_routes_by_event(self.jobs.get(dep)),
        )
        if not evaluate(parse_condition(step.get("if")), ctx)[0]:
            return False
        if untrusted:
            for earlier in steps[:index]:
                if isinstance(earlier, dict) and _step_checks_permission(earlier):
                    return False
        return True


def outsider_job_events(
    data: dict[str, Any], path: Path, root: Path | None
) -> dict[str, list[str]]:
    """For each job, the events on which an account without write access can
    make it run: the workflow's untrusted triggers that the job's ``if``,
    ``needs`` and recognized permission checks do not shut out. An
    environment name does not prove required approval. Jobs no such event
    reaches are omitted."""
    events = _untrusted_events(data, path, root, {})
    if not events:
        return {}
    reach = _Reach(data)
    reachable = {}
    for job_id in reach.jobs:
        job_events = [event for event in events if reach.job_runs(job_id, event, True)]
        if job_events:
            reachable[job_id] = job_events
    return reachable


# ------------------------------------------------------------ privilege


def _permissions_scopes(permissions: Any) -> tuple[list[str], bool]:
    """(write scopes, id-token write) of a permissions value."""
    if isinstance(permissions, str):
        if permissions.strip() == "write-all":
            return ["write-all"], True
        return [], False
    if not isinstance(permissions, dict):
        return [], False
    scopes = [
        f"{key}: write" for key, value in permissions.items() if str(value).lower() == "write"
    ]
    return scopes, "id-token: write" in scopes


def _secret_names(values: list[Any]) -> list[str]:
    names: list[str] = []
    for value in values:
        for text in _iter_strings(value):
            for match in SECRETS_OUTSIDE_ENV_RE.finditer(text):
                name = match.group(1)
                if name.upper() != "GITHUB_TOKEN" and name not in names:
                    names.append(name)
    return names


def _privilege(
    data: dict[str, Any],
    job: dict[str, Any],
    step: dict[str, Any],
    caller: _Caller | None,
) -> _Privilege:
    secrets = _secret_names([step.get("with"), step.get("env"), job.get("env"), data.get("env")])
    if caller is not None:
        passed = caller.job.get("secrets")
        if passed == "inherit":
            pass
        elif isinstance(passed, dict):
            secrets = [name for name in secrets if name in {str(key) for key in passed}]
        else:
            secrets = []
    if "permissions" in job:
        permissions: Any = job.get("permissions")
        declared = True
    elif "permissions" in data:
        permissions, declared = data.get("permissions"), True
    elif caller is not None and "permissions" in caller.job:
        permissions, declared = caller.job.get("permissions"), True
    elif caller is not None and "permissions" in caller.data:
        permissions, declared = caller.data.get("permissions"), True
    else:
        permissions, declared = None, False
    scopes, oidc = _permissions_scopes(permissions)
    return _Privilege(secrets=secrets, write_scopes=scopes, undeclared=not declared, oidc=oidc)


# ------------------------------------------------------------ findings


@dataclass
class _Context:
    """One way an untrusted event reaches this workflow."""

    event: str
    caller: _Caller | None = None

    def describe(self, *, who: bool = True) -> str:
        text = EVENT_DESCRIPTIONS[self.event] if who else self.event
        if self.caller is not None:
            text += f" via {self.caller.file.name}"
        return text


def local_workflow_callers(
    data: dict[str, Any], path: Path, root: Path | None
) -> list[tuple[Path, dict[str, Any], Any, dict[str, Any]]]:
    if "workflow_call" not in _trigger_map(data):
        return []
    target = f".github/workflows/{path.name}"
    callers = []
    for sibling, sibling_data in _sibling_workflows(path, root):
        for job_id, job in _jobs(sibling_data):
            uses = job.get("uses")
            if not isinstance(uses, str):
                continue
            if uses.strip().split("@", 1)[0].removeprefix("./") == target:
                callers.append((sibling, sibling_data, job_id, job))
    return callers


def _caller_contexts(
    path: Path, root: Path | None, data: dict[str, Any], siblings_cache: dict
) -> list[_Context]:
    if "workflow_call" not in _trigger_map(data):
        return []
    if "siblings" not in siblings_cache:
        siblings_cache["siblings"] = _sibling_workflows(path, root)
    contexts: list[_Context] = []
    target = f".github/workflows/{path.name}"
    for sibling, sibling_data in siblings_cache["siblings"]:
        events = _untrusted_events(sibling_data, sibling, root, {})
        if not events:
            continue
        reach = _Reach(sibling_data)
        for job_id, job in _jobs(sibling_data):
            uses = job.get("uses")
            if not isinstance(uses, str):
                continue
            normalized = uses.strip().split("@", 1)[0].removeprefix("./")
            if normalized != target:
                continue
            caller = _Caller(sibling, sibling_data, job_id, job, reach)
            for event in events:
                contexts.append(_Context(event, caller))
    return contexts


def _status(
    agent: _Agent,
    reach: _Reach,
    job_id: str,
    index: int,
    context: _Context,
) -> str:
    """open | widened | gated | unreachable for one event context."""
    event = context.event
    caller = context.caller
    if caller is not None and not caller.reach.job_runs(str(caller.job_id), event, False):
        return "unreachable"
    if not reach.step_runs(job_id, index, event, False):
        return "unreachable"
    if event not in EVENT_ENTITIES:
        return "unreachable"
    open_to_untrusted = reach.step_runs(job_id, index, event, True) and (
        caller is None or caller.reach.job_runs(str(caller.job_id), event, True)
    )
    if not open_to_untrusted:
        return "gated"
    if event in agent.checked_events:
        return "widened" if agent.widened else "gated"
    return "open"


def _field_entity(expression: str) -> str:
    lowered = re.sub(r"^tojson\(\s*|\s*\)$", "", expression.lower())
    for prefix, entity in _FIELD_ENTITY:
        if lowered.startswith(prefix) or lowered == prefix.rstrip("."):
            return entity
    return "*"


def _capability(agent: _Agent) -> str:
    if agent.tier == "shell":
        return f"shell commands ({agent.tier_reason})"
    return agent.tier_reason


def _severity_for_tier(agent: _Agent, privilege: _Privilege) -> str | None:
    if agent.tier == "none":
        return None
    if not privilege.present:
        return "MEDIUM" if agent.tier == "shell" else None
    return {"shell": "CRITICAL", "tools": "HIGH", "read": "MEDIUM"}[agent.tier]


def _join_events(contexts: list[_Context], *, who: bool = True) -> str:
    seen: list[str] = []
    for context in contexts:
        text = context.describe(who=who)
        if text not in seen:
            seen.append(text)
    return ", ".join(seen)


def _untrusted_fields(text: str, event: str) -> list[str]:
    """Untrusted event fields in ``text`` that are set for ``event``."""
    present = EVENT_ENTITIES.get(event, frozenset())
    fields = []
    for match in _UNTRUSTED_TEXT_RE.finditer(text):
        entity = _field_entity(match.group(1))
        if entity == "*" or entity in present:
            fields.append(match.group(1))
    return fields


def _writes_file(step: dict[str, Any]) -> bool:
    script = _with(step).get("script")
    if isinstance(script, str) and _SCRIPT_WRITE_RE.search(script):
        return True
    run = step.get("run")
    if not isinstance(run, str):
        return False
    return any(
        not any(marker in target for marker in _NON_FILE_TARGETS)
        for target in _FILE_TARGET_RE.findall(run)
    )


def _input_evidence(
    agent: _Agent,
    step: dict[str, Any],
    earlier_steps: list[Any],
    job: dict[str, Any],
    data: dict[str, Any],
    context: _Context,
) -> str | None:
    """How attacker-written text for the event reaches the agent, or None."""
    event = context.event
    if agent.ingests_event and event != "workflow_run":
        return "the action loads the triggering issue, comment or pull request"
    fields = _untrusted_fields(agent.prompt_text, event)
    if fields:
        return f"the prompt interpolates {fields[0]}"
    if context.caller is not None:
        passed = context.caller.job.get("with")
        if isinstance(passed, dict):
            for name, value in passed.items():
                fields = _untrusted_fields("\n".join(_iter_strings(value)), event)
                if fields and re.search(
                    rf"\binputs\.{re.escape(str(name))}\b", agent.prompt_text, re.IGNORECASE
                ):
                    return f"{context.caller.file.name} passes {fields[0]} as input {name}"
    prompt_lower = agent.prompt_text.lower()
    for earlier in earlier_steps:
        if not isinstance(earlier, dict):
            continue
        earlier_text = "\n".join(
            _iter_strings([earlier.get("run"), earlier.get("with"), earlier.get("env")])
        )
        fields = _untrusted_fields(earlier_text, event)
        if not fields and event != "workflow_run" and _EVENT_TEXT_FETCH_RE.search(earlier_text):
            fields = ["the issue or pull request text it fetches"]
        if not fields:
            continue
        step_id = _text(earlier.get("id")).strip()
        if step_id and f"steps.{step_id.lower()}.outputs" in prompt_lower:
            return f"the prompt uses step {step_id}'s output built from {fields[0]}"
        if _writes_file(earlier):
            label = step_id or _text(earlier.get("name")).strip() or "an earlier step"
            return f"{label} writes {fields[0]} to a file first"
    for dep in re.findall(r"needs\.([A-Za-z0-9_-]+)\.outputs", agent.prompt_text, re.IGNORECASE):
        jobs = data.get("jobs") if isinstance(data.get("jobs"), dict) else {}
        needed = next((j for k, j in jobs.items() if str(k).lower() == dep.lower()), None)
        if not isinstance(needed, dict):
            continue
        needed_text = "\n".join(_iter_strings(needed.get("steps")))
        fields = _untrusted_fields(needed_text, event)
        if fields or (event != "workflow_run" and _EVENT_TEXT_FETCH_RE.search(needed_text)):
            return f"the prompt uses job {dep}'s output, built from the triggering text"
    for env in (data.get("env"), job.get("env"), step.get("env")):
        if not isinstance(env, dict):
            continue
        for name, value in env.items():
            fields = _untrusted_fields("\n".join(_iter_strings(value)), event)
            if fields and (agent.reads_env or str(name) in agent.prompt_text):
                return f"env {name} holds {fields[0]}"
    if agent.reads_github and (
        agent.prompt_from_file or _PROMPT_EVENT_RE.search(agent.prompt_text)
    ):
        return f"it can read the issue or pull request ({agent.reads_github})"
    if event in _PR_CODE_EVENTS and _job_reads_pr_code(job):
        return "the job checks out the pull request's code"
    return None


@dataclass
class _StepScan:
    """One agent step and what reaches it, shared by the per-rule reports."""

    path: Path
    lines: list[str]
    findings: list[dict[str, Any]]
    source: Any
    job_key: Any
    job: dict[str, Any]
    index: int
    step: dict[str, Any]
    agent: _Agent
    reachable: list[tuple[_Context, str]]
    evidence: dict[int, str | None]
    privilege: _Privilege

    @property
    def job_id(self) -> str:
        return str(self.job_key)

    @property
    def base_value(self) -> str:
        return f"{self.job_id}:{self.index}:{self.agent.label}"

    def contexts(self, status: str) -> list[_Context]:
        """Contexts with ``status`` where attacker text can reach the agent."""
        return [c for c, s in self.reachable if s == status and self.evidence[id(c)]]

    @property
    def exposed(self) -> list[_Context]:
        return self.contexts("open") + self.contexts("widened")

    @property
    def how(self) -> str:
        exposed = self.exposed
        return (self.evidence[id(exposed[0])] or "") if exposed else ""

    def line_for(self, *keys: str) -> int:
        if self.source is None:
            return 1
        for key in keys:
            parts: tuple[Any, ...] = ("jobs", self.job_key, "steps", self.index)
            parts += ("with", key) if key not in {"uses", "run"} else (key,)
            found = self.source.line_for_path(parts)
            if found:
                return found
        return self.source.line_for_path(("jobs", self.job_key, "steps", self.index)) or 1

    def emit(self, rule_id: str, name: str, message: str, line: int, severity: str, value: str) -> None:
        _add_finding(
            self.findings,
            self.lines,
            _finding(
                rule_id=rule_id,
                name=name,
                message=message,
                file=self.path,
                line=line,
                severity=severity,
                value=value,
            ),
            yaml_only=True,
        )


def _environment_note(scan: _StepScan) -> str:
    environment = _literal_environment(scan.job)
    if not environment:
        return ""
    # Required reviewers on the environment would gate the job; that setting
    # is not visible in the repository.
    return (
        f" Job {scan.job_id} uses environment {environment}; required reviewers "
        "there would gate it."
    )


def _report_no_gate(scan: _StepScan, severity: str) -> None:
    contexts = scan.contexts("open")
    if not contexts:
        return
    agent = scan.agent
    scan.emit(
        RULE_NO_GATE,
        "github-actions-ai-agent-untrusted-trigger",
        f"{_join_events(contexts)} → {agent.label} ({scan.how}) with "
        f"{_capability(agent)} and {scan.privilege.describe()}. Nothing checks "
        f"that the account starting job {scan.job_id} has write access "
        "(no author_association, actor or permission gate)." + _environment_note(scan),
        scan.line_for(agent.anchor_key),
        severity,
        scan.base_value,
    )


def _report_widened(scan: _StepScan, severity: str) -> None:
    contexts = scan.contexts("widened")
    if not contexts:
        return
    agent = scan.agent
    setting = ", ".join(f'{name}: "{value}"' for name, value in agent.widened)
    if agent.bots_only_widening and severity == "CRITICAL":
        severity = "HIGH"
    who = "any GitHub App" if agent.bots_only_widening else "any account"
    scan.emit(
        RULE_WIDENED,
        "github-actions-ai-agent-access-widened",
        f"{_join_events(contexts)} → {agent.label} ({scan.how}) with "
        f"{setting}, which lets {who} past the action's write-access check; "
        f"the agent has {_capability(agent)} and {scan.privilege.describe()}."
        + _environment_note(scan),
        scan.line_for(agent.widened[0][0]),
        severity,
        f"{scan.base_value}:{agent.widened[0][0]}",
    )


def _report_shell(scan: _StepScan) -> None:
    agent = scan.agent
    exposed = scan.exposed
    threads = [c for c in scan.contexts("gated") if c.event in _THREAD_EVENTS]
    if exposed:
        message = (
            f"{agent.label} can run any shell command ({agent.tier_reason}) in a "
            f"workflow that {_join_events(exposed)} starts; a prompt injection in "
            f"that text becomes commands run with {scan.privilege.describe()}."
        )
        severity = "HIGH"
    elif threads:
        message = (
            f"{agent.label} can run any shell command ({agent.tier_reason}). Only "
            f"accounts with write access start it, but on {_join_events(threads, who=False)} "
            "it reads issue, comment or pull request text that others wrote; a prompt "
            f"injection there becomes commands run with {scan.privilege.describe()}."
        )
        severity = "MEDIUM"
    else:
        return
    scan.emit(
        RULE_SHELL,
        "github-actions-ai-agent-shell",
        message,
        scan.line_for(agent.tier_key or agent.anchor_key, agent.anchor_key),
        severity,
        f"{scan.base_value}:shell",
    )


def _prompt_contexts(scan: _StepScan, expression: str) -> list[tuple[_Context, bool]]:
    """Contexts where ``expression`` holds text the starting account did not
    write, flagged True when anyone can start the agent."""
    entity = _field_entity(expression)
    result = []
    for context, status in scan.reachable:
        if entity != "*" and entity not in EVENT_ENTITIES.get(context.event, frozenset()):
            continue
        if status in {"open", "widened"}:
            result.append((context, True))
        elif entity != ACTOR_ENTITY.get(context.event):
            result.append((context, False))
    return result


def _report_prompt(scan: _StepScan) -> None:
    agent = scan.agent
    config = _with(scan.step)
    for input_name in agent.prompt_inputs:
        text = "\n".join(_iter_strings(config.get(input_name)))
        for match in _UNTRUSTED_TEXT_RE.finditer(text):
            expression = match.group(1)
            contexts = _prompt_contexts(scan, expression)
            if not contexts:
                continue
            anyone = any(flag for _, flag in contexts)
            acts = scan.privilege.present and agent.tier in {"shell", "tools"}
            author = (
                "anyone who can trigger the workflow"
                if anyone
                else "someone other than the account that starts the agent"
            )
            scan.emit(
                RULE_PROMPT,
                "github-actions-ai-agent-prompt-injection",
                f"{expression} is interpolated into {agent.label} input {input_name} on "
                f"{_join_events([c for c, _ in contexts], who=anyone)}; "
                f"text written by {author} becomes part of the agent's "
                f"instructions, and the agent has {_capability(agent)}.",
                scan.line_for(input_name),
                "HIGH" if anyone and acts else "MEDIUM",
                f"{scan.base_value}:{input_name}:{expression}",
            )


def _report_advisories(scan: _StepScan) -> None:
    # The advisories are exploitable through untrusted input (a planted
    # workspace config, an injected prompt), whatever reaches the prompt text.
    exposed_any = bool(scan.reachable)
    for ghsa, cve, fixed, advisory_severity, summary, key in scan.agent.advisories:
        if advisory_severity == "CRITICAL":
            level = "HIGH" if exposed_any else "MEDIUM"
        else:
            level = "MEDIUM" if exposed_any else "LOW"
        if key == "gemini_cli_version":
            version = _text(_with(scan.step).get("gemini_cli_version")).strip()
            subject, fixed_in = f"gemini_cli_version {version}", "Gemini CLI 0.39.1"
        else:
            subject, fixed_in = _text(scan.step.get("uses")), fixed
        scan.emit(
            RULE_ADVISORY,
            "github-actions-ai-agent-known-advisory",
            f"{subject} is affected by {ghsa} ({cve}): {summary}. "
            f"Upgrade to {fixed_in} or later.",
            scan.line_for(key or "uses", "uses"),
            level,
            f"{scan.base_value}:{ghsa}",
        )


def _agent_steps(
    data: dict[str, Any], repo_root: Path | None
) -> list[tuple[Any, dict[str, Any], int, dict[str, Any], _Agent]]:
    agents = []
    for job_key, job in _jobs(data):
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            env_layers = [data.get("env"), job.get("env"), step.get("env")]
            agent = _agent_for_step(step, env_layers, repo_root)
            if agent is not None:
                agents.append((job_key, job, index, step, agent))
    return agents


def scan_ai_agent_workflows(
    data: dict[str, Any],
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    ignore: set[str],
    *,
    root: Path | None = None,
) -> None:
    """Emit SKY-D350 to SKY-D354 for agent steps in one workflow file."""
    if all(rule in ignore for rule in AI_AGENT_RULES):
        return
    repo_root = path.parent.parent.parent if path.parent.name == "workflows" else None
    agents = _agent_steps(data, repo_root)
    if not agents:
        return

    siblings_cache: dict[str, Any] = {}
    contexts = [
        _Context(event) for event in _untrusted_events(data, path, root, siblings_cache)
    ]
    contexts += _caller_contexts(path, root, data, siblings_cache)
    reach = _Reach(data)
    source = _source_for_lines(lines)

    for job_key, job, index, step, agent in agents:
        earlier_steps = job["steps"][:index]
        statuses = [
            (context, _status(agent, reach, str(job_key), index, context))
            for context in contexts
        ]
        reachable = [(c, s) for c, s in statuses if s != "unreachable"]
        evidence = {
            id(context): _input_evidence(agent, step, earlier_steps, job, data, context)
            for context, _ in reachable
        }
        exposed = [c for c, s in reachable if s in {"open", "widened"} and evidence[id(c)]]
        privilege_contexts = exposed or [c for c, _ in reachable]
        caller = privilege_contexts[0].caller if privilege_contexts else None
        scan = _StepScan(
            path=path,
            lines=lines,
            findings=findings,
            source=source,
            job_key=job_key,
            job=job,
            index=index,
            step=step,
            agent=agent,
            reachable=reachable,
            evidence=evidence,
            privilege=_privilege(data, job, step, caller),
        )
        severity = _severity_for_tier(agent, scan.privilege)
        if severity == "CRITICAL" and _literal_environment(job):
            severity = "HIGH"
        if severity is not None and RULE_NO_GATE not in ignore:
            _report_no_gate(scan, severity)
        if severity is not None and RULE_WIDENED not in ignore:
            _report_widened(scan, severity)
        if agent.tier == "shell" and RULE_SHELL not in ignore:
            _report_shell(scan)
        if agent.tier != "none" and RULE_PROMPT not in ignore:
            _report_prompt(scan)
        if agent.advisories and RULE_ADVISORY not in ignore:
            _report_advisories(scan)
