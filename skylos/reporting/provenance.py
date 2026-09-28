import logging
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from skylos.constants import NETWORK_TIMEOUT_SHORT, SUBPROCESS_TIMEOUT
from skylos.core.ci_env import github_or_ci_base_ref
from skylos.core.git_safety import (
    read_only_git_command,
    read_only_git_environment,
)

logger = logging.getLogger(__name__)

# --- Commit attribution -----------------------------------------------------
#
# AI attribution is only granted on *explicit* agent signals:
#   * a Co-authored-by trailer (or the commit author) whose identity matches a
#     known coding agent's published identity (email / GitHub bot account);
#   * an explicit AI declaration trailer (Assisted-by / Generated-by / AI-Agent);
#   * a subject line that names a known agent ("Generated with Claude Code").
# A human whose *name* merely contains "claude"/"cursor"/... is not an agent,
# ``noreply@github.com`` (web-UI commits) is not an agent, and dependency /
# CI bots (Dependabot, Renovate, github-actions, other ``[bot]`` accounts) are
# classified as "automation", never as AI.

ATTRIBUTION_AI = "ai"
ATTRIBUTION_AUTOMATION = "automation"

_GITHUB_NOREPLY_RE = re.compile(
    r"^(?:\d+\+)?(?P<login>[^@\s]+)@(?:users\.)?noreply\.github\.com$",
    re.IGNORECASE,
)
_IDENTITY_RE = re.compile(r"^\s*(?P<name>.*?)\s*<(?P<email>[^<>]*)>\s*$")
_TRAILER_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9-]*)\s*:\s*(?P<value>.*)$")

# agent -> known commit emails (exact, lowercase) and GitHub logins
# (lowercase, without the "[bot]" suffix; "bot_only" logins must carry it).
KNOWN_AGENTS = {
    "claude": {
        "emails": {"noreply@anthropic.com", "claude@anthropic.com"},
        "bot_logins": {"claude", "anthropic-claude", "claude-code"},
        "user_logins": set(),
    },
    "copilot": {
        "emails": {"copilot@github.com"},
        "bot_logins": {"copilot", "copilot-swe-agent", "github-copilot"},
        # GitHub's own "Copilot" user used in Co-authored-by trailers.
        "user_logins": {"copilot"},
    },
    "cursor": {
        "emails": {"cursoragent@cursor.com", "agent@cursor.com"},
        "bot_logins": {"cursor", "cursor-agent"},
        "user_logins": set(),
    },
    "codex": {
        "emails": {"codex@openai.com", "noreply@openai.com"},
        "bot_logins": {"chatgpt-codex-connector", "openai-codex", "codex"},
        "user_logins": set(),
    },
    "devin": {
        "emails": {"devin@cognition.ai", "devin-ai-integration@cognition.ai"},
        "bot_logins": {"devin-ai-integration", "devin"},
        "user_logins": set(),
    },
    "aider": {
        "emails": {"noreply@aider.chat"},
        "bot_logins": {"aider"},
        "user_logins": set(),
    },
    "jules": {
        "emails": set(),
        "bot_logins": {"google-labs-jules"},
        "user_logins": set(),
    },
    "amazon-q": {
        "emails": set(),
        "bot_logins": {"amazon-q-developer"},
        "user_logins": set(),
    },
}

# Well-known automation identities (not AI agents).
AUTOMATION_EMAILS = {
    "github-actions@github.com": "github-actions",
    "action@github.com": "github-actions",
    "actions@github.com": "github-actions",
    "bot@renovateapp.com": "renovate",
    "support@dependabot.com": "dependabot",
}

# Trailers whose *key* is itself an explicit AI declaration.
AI_DECLARATION_TRAILERS = {
    "assisted-by",
    "generated-by",
    "ai-assisted-by",
    "ai-agent",
    "ai-generated-by",
    "x-ai-agent",
}
COAUTHOR_TRAILER = "co-authored-by"

_AGENT_KEYWORDS = r"claude(?:\s+code)?|copilot|cursor|codex|devin|aider|jules"
AI_MESSAGE_PATTERNS = [
    re.compile(
        r"\bgenerated\s+(?:by|with)\s+\[?(?:github\s+)?(?:" + _AGENT_KEYWORDS + r")\b",
        re.IGNORECASE,
    ),
]

# Legacy names kept for importers; detection no longer uses substring lists.
AI_COAUTHOR_PATTERNS: list = []
AI_EMAIL_PATTERNS: list = []

AGENT_NAME_MAP = {
    "copilot": "copilot",
    "claude": "claude",
    "cursor": "cursor",
    "codewhisperer": "codewhisperer",
    "amazon-q": "amazon-q",
    "tabnine": "tabnine",
    "devin": "devin",
    "codex": "codex",
    "aider": "aider",
    "jules": "jules",
    "anthropic": "claude",
}


def _split_identity(value):
    m = _IDENTITY_RE.match(value or "")
    if m:
        return m.group("name"), m.group("email").strip()
    return (value or "").strip(), ""


def _github_login(email):
    m = _GITHUB_NOREPLY_RE.match((email or "").strip())
    if not m:
        return None, False
    login = m.group("login").lower()
    is_bot = login.endswith("[bot]")
    if is_bot:
        login = login[: -len("[bot]")]
    return login, is_bot


def _agent_for_identity(name, email):
    """Return the agent name when (name, email) is a known agent identity."""
    email_l = (email or "").strip().lower()
    name_l = (name or "").strip().lower()
    for agent, sig in KNOWN_AGENTS.items():
        if email_l and email_l in sig["emails"]:
            return agent
    login, is_bot = _github_login(email_l)
    if login is not None:
        for agent, sig in KNOWN_AGENTS.items():
            if is_bot and login in sig["bot_logins"]:
                return agent
            if not is_bot and login in sig["user_logins"]:
                return agent
    # Author name "copilot-swe-agent[bot]" with a non-noreply email.
    if name_l.endswith("[bot]"):
        bot = name_l[: -len("[bot]")]
        for agent, sig in KNOWN_AGENTS.items():
            if bot in sig["bot_logins"]:
                return agent
    # aider --attribute-author marks the author name as "Name (aider)".
    if name_l.endswith("(aider)"):
        return "aider"
    return None


def _automation_for_identity(name, email):
    email_l = (email or "").strip().lower()
    if email_l in AUTOMATION_EMAILS:
        return AUTOMATION_EMAILS[email_l]
    login, is_bot = _github_login(email_l)
    if login is not None and is_bot:
        return login
    name_l = (name or "").strip().lower()
    if name_l.endswith("[bot]"):
        return name_l[: -len("[bot]")]
    return None


def _parse_trailers(trailers):
    """Parse the git-log trailer field into (key, value) pairs.

    Accepts ``Key: value`` items (``%(trailers:only)``) and legacy
    value-only items, which are treated as Co-authored-by.
    """
    items = []
    for raw in re.split(r"[\x00\x1f\n]", trailers or ""):
        raw = raw.strip()
        if not raw:
            continue
        m = _TRAILER_RE.match(raw)
        if m and "<" not in m.group("key"):
            items.append((m.group("key").lower(), m.group("value").strip()))
        else:
            items.append((COAUTHOR_TRAILER, raw))
    return items


def classify_commit(author_name, author_email, subject, trailers):
    """Classify one commit's authorship.

    Returns ``None`` for ordinary human commits, otherwise a dict with
    ``category`` ("ai" or "automation"), ``type``, ``agent_name`` and ``detail``.
    """
    for key, value in _parse_trailers(trailers):
        if key == COAUTHOR_TRAILER:
            name, email = _split_identity(value)
            agent = _agent_for_identity(name, email)
            if agent:
                return {
                    "category": ATTRIBUTION_AI,
                    "type": "co-author",
                    "agent_name": agent,
                    "detail": value[:100],
                }
        elif key in AI_DECLARATION_TRAILERS and value:
            name, email = _split_identity(value)
            agent = _agent_for_identity(name, email) or _detect_agent_name(value)
            # "Assisted-by"/"Generated-by" are also used for humans and code
            # generators (protoc, ...): require a named agent there. Keys that
            # say "ai" are an explicit declaration on their own.
            if agent is None and not key.startswith(("ai-", "x-ai-")):
                continue
            return {
                "category": ATTRIBUTION_AI,
                "type": "ai-trailer",
                "agent_name": agent,
                "detail": f"{key}: {value}"[:100],
            }

    agent = _agent_for_identity(author_name, author_email)
    if agent:
        return {
            "category": ATTRIBUTION_AI,
            "type": "author-email",
            "agent_name": agent,
            "detail": f"{author_name} <{author_email}>",
        }

    for pat in AI_MESSAGE_PATTERNS:
        if pat.search(subject or ""):
            return {
                "category": ATTRIBUTION_AI,
                "type": "commit-message",
                "agent_name": _detect_agent_name(subject),
                "detail": (subject or "")[:100],
            }

    bot = _automation_for_identity(author_name, author_email)
    if bot:
        return {
            "category": ATTRIBUTION_AUTOMATION,
            "type": "automation-author",
            "agent_name": bot,
            "detail": f"{author_name} <{author_email}>",
        }
    return None


GIT_LOG_FORMAT = "%H|%an|%ae|%s|%(trailers:only,unfold,separator=%x1f)"


HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class FileProvenance:
    file_path: str
    agent_authored: bool = False
    agent_lines: list = field(default_factory=list)
    indicators: list = field(default_factory=list)
    agent_name: str | None = None
    automation_authored: bool = False
    automation_name: str | None = None
    automation_indicators: list = field(default_factory=list)


@dataclass
class ProvenanceReport:
    files: dict = field(default_factory=dict)
    agent_files: list = field(default_factory=list)
    human_files: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    confidence: str = "low"
    automation_files: list = field(default_factory=list)
    # How complete the analysis was, so a consumer (Skylos Cloud) can tell
    # "no agent commits" apart from "could not look": ran, reason (when it
    # did not run or was partial), base_ref, base_sha (the merge base the
    # range starts at), fallback_range (True when no merge base was found and
    # only HEAD~10 was read), shallow (shallow clone), commits_analyzed.
    status: dict = field(
        default_factory=lambda: {"ran": False, "reason": "not analyzed"}
    )

    def to_dict(self):
        file_entries = {}
        for path, fp in self.files.items():
            file_entries[path] = {
                "file_path": fp.file_path,
                "agent_authored": fp.agent_authored,
                "agent_lines": fp.agent_lines,
                "indicators": fp.indicators,
                "agent_name": fp.agent_name,
                "automation_authored": fp.automation_authored,
                "automation_name": fp.automation_name,
            }
        return {
            "files": file_entries,
            "agent_files": self.agent_files,
            "human_files": self.human_files,
            "automation_files": self.automation_files,
            "summary": self.summary,
            "confidence": self.confidence,
            "status": dict(self.status),
        }


def _detect_agent_name(text):
    text_lower = text.lower()
    for keyword, name in AGENT_NAME_MAP.items():
        if keyword in text_lower:
            return name
    return None


_DIFF_GIT_RE = re.compile(
    r'^diff --git (?P<a>"(?:[^"\\]|\\.)*"|\S+) (?P<b>"(?:[^"\\]|\\.)*"|\S+)$'
)
_BINARY_RE = re.compile(r"^Binary files (?P<a>.+) and (?P<b>.+) differ$")
_C_ESCAPES = {
    "a": 7,
    "b": 8,
    "t": 9,
    "n": 10,
    "v": 11,
    "f": 12,
    "r": 13,
    '"': 34,
    "\\": 92,
}


def _unquote_git_path(value):
    """Undo git's C-style quoting of unusual paths ("a/sp\\303\\251.py")."""
    value = (value or "").strip()
    if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
        return value
    body = value[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in "01234567":
                octal = body[i + 1 : i + 4]
                if len(octal) == 3 and all(c in "01234567" for c in octal):
                    out.append(int(octal, 8))
                    i += 4
                    continue
            if nxt in _C_ESCAPES:
                out.append(_C_ESCAPES[nxt])
                i += 2
                continue
        out.extend(ch.encode("utf-8"))
        i += 1
    return out.decode("utf-8", errors="replace")


def _strip_side_prefix(path, prefix):
    # Git appends a tab to ---/+++ names that contain spaces.
    path = _unquote_git_path((path or "").rstrip("\t"))
    if path == "/dev/null":
        return None
    return path[len(prefix) :] if path.startswith(prefix) else path


def _parse_diff_hunks(diff_text):
    """Changed line ranges per file of one commit's patch.

    Every file the commit touches is recorded, including ones without added
    lines: a deleted file (under its old path), both sides of a rename,
    binary files and mode-only changes get an empty range list, meaning
    "touched, lines unknown". Quoted paths are unquoted.
    """
    file_ranges = {}
    current_file = None

    def touch(path):
        if path:
            file_ranges.setdefault(path, [])

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current_file = None
            m = _DIFF_GIT_RE.match(line)
            if m:
                old = _strip_side_prefix(m.group("a"), "a/")
                new = _strip_side_prefix(m.group("b"), "b/")
                touch(new or old)
                current_file = new or old
        elif line.startswith("rename from "):
            touch(_unquote_git_path(line[len("rename from ") :]))
        elif line.startswith("rename to "):
            current_file = _unquote_git_path(line[len("rename to ") :])
            touch(current_file)
        elif line.startswith("--- "):
            old = _strip_side_prefix(line[4:], "a/")
            touch(old)
        elif line.startswith("+++ "):
            new = _strip_side_prefix(line[4:], "b/")
            # A deletion keeps the old path as the touched file; its
            # hunks only remove lines, so no range is recorded.
            current_file = new
            touch(new)
        elif line.startswith("Binary files ") and line.endswith(" differ"):
            m = _BINARY_RE.match(line)
            if m:
                touch(_strip_side_prefix(m.group("a"), "a/"))
                touch(_strip_side_prefix(m.group("b"), "b/"))
        elif line.startswith("@@") and current_file is not None:
            m = HUNK_HEADER_RE.match(line)
            if m:
                start_line = int(m.group(1))
                count = int(m.group(2)) if m.group(2) else 1
                end_line = start_line + max(count - 1, 0)
                file_ranges.setdefault(current_file, []).append((start_line, end_line))

    return file_ranges


def _resolve_base_ref(explicit_base=None):
    if explicit_base:
        return explicit_base

    env_base = github_or_ci_base_ref()
    if env_base:
        return f"origin/{env_base}"

    return "origin/main"


def _git_merge_base(git_root, base_ref):
    try:
        return (
            subprocess.check_output(
                read_only_git_command(["merge-base", base_ref, "HEAD"]),
                cwd=git_root,
                env=read_only_git_environment(),
                stderr=subprocess.DEVNULL,
                timeout=NETWORK_TIMEOUT_SHORT,
            )
            .decode("utf-8", errors="ignore")
            .strip()
        )
    except (subprocess.SubprocessError, OSError):
        return None


def _git_is_shallow(git_root):
    try:
        out = subprocess.check_output(
            read_only_git_command(["rev-parse", "--is-shallow-repository"]),
            cwd=git_root,
            env=read_only_git_environment(),
            stderr=subprocess.DEVNULL,
            timeout=NETWORK_TIMEOUT_SHORT,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return out.decode("utf-8", errors="ignore").strip().lower() == "true"


def analyze_provenance(git_root, base_ref=None):
    if not git_root:
        return ProvenanceReport(status={"ran": False, "reason": "not a git repository"})

    base_ref = _resolve_base_ref(base_ref)
    shallow = _git_is_shallow(git_root)
    merge_base = _git_merge_base(git_root, base_ref)
    status = {
        "ran": True,
        "reason": None,
        "base_ref": base_ref,
        "base_sha": merge_base or None,
        "fallback_range": not merge_base,
        "shallow": shallow,
        "commits_analyzed": 0,
    }

    if not merge_base:
        logger.debug(
            "Could not find merge base for %s, falling back to HEAD~10", base_ref
        )
        range_spec = "HEAD~10..HEAD"
        status["reason"] = (
            f"no merge base with {base_ref}; only the last 10 commits were read"
            + (" (shallow clone)" if shallow else "")
        )
    else:
        range_spec = f"{merge_base}..HEAD"
        if shallow:
            status["reason"] = (
                "shallow clone; commits before the fetched depth are unknown"
            )

    indicators_by_commit = {}
    ai_commits = set()
    agents_seen = set()
    automation_commits = {}
    automation_seen = set()

    try:
        log_output = subprocess.check_output(
            read_only_git_command(
                [
                    "log",
                    f"--format={GIT_LOG_FORMAT}",
                    range_spec,
                ]
            ),
            cwd=git_root,
            env=read_only_git_environment(),
            stderr=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT,
        ).decode("utf-8", errors="ignore")
    except (subprocess.SubprocessError, OSError):
        logger.debug("Failed to get git log for provenance", exc_info=True)
        return ProvenanceReport(
            status={
                **status,
                "ran": False,
                "reason": f"git log {range_spec} failed"
                + (" (shallow clone)" if shallow else ""),
            }
        )

    for line in log_output.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 4)
        if len(parts) < 4:
            continue

        commit_sha = parts[0]
        author_name = parts[1]
        author_email = parts[2]
        subject = parts[3]
        trailers = parts[4] if len(parts) > 4 else ""
        status["commits_analyzed"] += 1

        attribution = classify_commit(author_name, author_email, subject, trailers)
        if attribution is None:
            continue
        category = attribution.pop("category")
        indicator = {"commit": commit_sha[:7], **attribution}
        if category == ATTRIBUTION_AUTOMATION:
            automation_commits[commit_sha] = indicator
            if indicator.get("agent_name"):
                automation_seen.add(indicator["agent_name"])
            continue
        is_ai_commit = True
        if indicator.get("agent_name"):
            agents_seen.add(indicator["agent_name"])

        if is_ai_commit:
            ai_commits.add(commit_sha)
            indicators_by_commit[commit_sha] = indicator

    file_provenance = {}
    all_changed_files = set()

    for commit_sha in ai_commits:
        file_ranges = _commit_file_ranges(git_root, commit_sha)
        if file_ranges is None:
            status["reason"] = (
                status["reason"]
                or f"could not read the changes of commit {commit_sha[:7]}"
            )
            status["incomplete_commits"] = status.get("incomplete_commits", 0) + 1
            continue
        indicator = indicators_by_commit.get(commit_sha, {})

        for fpath, ranges in file_ranges.items():
            all_changed_files.add(fpath)
            if fpath not in file_provenance:
                file_provenance[fpath] = FileProvenance(
                    file_path=fpath,
                    agent_authored=True,
                    agent_lines=[],
                    indicators=[],
                    agent_name=indicator.get("agent_name"),
                )
            fp = file_provenance[fpath]
            fp.agent_lines.extend(ranges)
            fp.indicators.append(indicator)
            if not fp.agent_name and indicator.get("agent_name"):
                fp.agent_name = indicator["agent_name"]

    for fp in file_provenance.values():
        fp.agent_lines = _merge_ranges(fp.agent_lines)

    automation_by_file = {}
    for commit_sha, indicator in automation_commits.items():
        file_ranges = _commit_file_ranges(git_root, commit_sha)
        if not file_ranges:
            continue
        for fpath in file_ranges:
            all_changed_files.add(fpath)
            automation_by_file.setdefault(fpath, []).append(indicator)

    try:
        all_files_output = subprocess.check_output(
            read_only_git_command(
                [
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--name-only",
                    range_spec,
                ]
            ),
            cwd=git_root,
            env=read_only_git_environment(),
            stderr=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT,
        ).decode("utf-8", errors="ignore")
        all_pr_files = {
            f.strip() for f in all_files_output.strip().splitlines() if f.strip()
        }
    except (subprocess.SubprocessError, OSError):
        all_pr_files = all_changed_files

    agent_files = sorted(file_provenance.keys())

    # Automation (Dependabot, Renovate, CI bots) is reported separately and is
    # never counted as AI. The three buckets are disjoint: a file is AI when
    # any AI commit touched it, otherwise automation when a bot commit touched
    # it, otherwise human. (Before automation existed, bot commits were
    # counted as AI, so ``human_files`` never contained bot-authored files.)
    automation_files = sorted(set(automation_by_file) - set(agent_files))
    human_files = sorted(all_pr_files - set(agent_files) - set(automation_files))

    for hf in human_files:
        file_provenance[hf] = FileProvenance(file_path=hf, agent_authored=False)

    for af in automation_files:
        fp = file_provenance.setdefault(
            af, FileProvenance(file_path=af, agent_authored=False)
        )
        fp.automation_authored = True
        fp.automation_indicators = automation_by_file[af]
        fp.automation_name = next(
            (
                i.get("agent_name")
                for i in automation_by_file[af]
                if i.get("agent_name")
            ),
            None,
        )

    total = len(all_pr_files)
    agent_count = len(agent_files)
    indicator_count = sum(len(fp.indicators) for fp in file_provenance.values())

    if indicator_count > 5:
        confidence = "high"
    elif indicator_count > 0:
        confidence = "medium"
    else:
        confidence = "low"

    return ProvenanceReport(
        files=file_provenance,
        agent_files=agent_files,
        human_files=human_files,
        automation_files=automation_files,
        summary={
            "total_files": total,
            "agent_count": agent_count,
            "human_count": len(human_files),
            "agents_seen": sorted(agents_seen),
            "automation_count": len(automation_files),
            "automation_seen": sorted(automation_seen),
        },
        confidence=confidence,
        status=status,
    )


def _commit_file_ranges(git_root, commit_sha):
    try:
        diff_output = subprocess.check_output(
            read_only_git_command(
                [
                    "diff-tree",
                    "--no-ext-diff",
                    "--no-textconv",
                    "-p",
                    "-r",
                    "-M",
                    "--no-commit-id",
                    commit_sha,
                ]
            ),
            cwd=git_root,
            env=read_only_git_environment(),
            stderr=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT,
        ).decode("utf-8", errors="ignore")
    except (subprocess.SubprocessError, OSError):
        logger.debug("Failed to get diff-tree for %s", commit_sha[:7], exc_info=True)
        return None
    return _parse_diff_hunks(diff_output)


def _merge_ranges(ranges):
    if not ranges:
        return []
    sorted_ranges = sorted(ranges, key=lambda r: r[0])
    merged = [sorted_ranges[0]]
    for start, end in sorted_ranges[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + 1:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def _line_in_ranges(line, ranges):
    for start, end in ranges:
        if start <= line <= end:
            return True
    return False


def annotate_findings_with_provenance(
    findings: list[dict],
    provenance_report: "ProvenanceReport",
) -> list[dict]:
    for finding in findings:
        file_path = finding.get("file")
        if not file_path:
            finding["ai_authored"] = False
            finding["ai_agent"] = None
            continue

        file_prov = provenance_report.files.get(file_path)

        if file_prov is None:
            for prov_path, prov in provenance_report.files.items():
                if file_path.endswith(prov_path) or prov_path.endswith(file_path):
                    file_prov = prov
                    break

        if file_prov is None or not file_prov.agent_authored:
            finding["ai_authored"] = False
            finding["ai_agent"] = None
            continue

        line = finding.get("line")
        if file_prov.agent_lines and line is not None:
            if _line_in_ranges(line, file_prov.agent_lines):
                finding["ai_authored"] = True
                finding["ai_agent"] = file_prov.agent_name
            else:
                finding["ai_authored"] = False
                finding["ai_agent"] = None
        else:
            finding["ai_authored"] = True
            finding["ai_agent"] = file_prov.agent_name

    return findings


def compute_ai_security_stats(
    findings: list[dict],
) -> dict:
    total = len(findings)
    ai_count = sum(1 for f in findings if f.get("ai_authored"))
    pct = (ai_count / total * 100) if total > 0 else 0.0

    by_agent: dict[str, int] = {}
    by_severity: dict[str, dict[str, int]] = {}
    by_category: dict[str, dict[str, int]] = {}

    for f in findings:
        is_ai = bool(f.get("ai_authored"))
        agent = f.get("ai_agent")
        severity = (f.get("severity") or "UNKNOWN").upper()
        category = (f.get("category") or "unknown").lower()

        if is_ai and agent:
            by_agent[agent] = by_agent.get(agent, 0) + 1

        if severity not in by_severity:
            by_severity[severity] = {"total": 0, "ai": 0}
        by_severity[severity]["total"] += 1
        if is_ai:
            by_severity[severity]["ai"] += 1

        if category not in by_category:
            by_category[category] = {"total": 0, "ai": 0}
        by_category[category]["total"] += 1
        if is_ai:
            by_category[category]["ai"] += 1

    return {
        "total_findings": total,
        "ai_authored_findings": ai_count,
        "ai_authored_pct": round(pct, 1),
        "by_agent": by_agent,
        "by_severity": by_severity,
        "by_category": by_category,
    }


def compute_ai_security_stats_for_report(
    report: dict, sections: Iterable[str]
) -> dict:
    """Count annotated findings by their top-level JSON result section."""
    findings = []
    for section in sections:
        for finding in report.get(section) or []:
            # A finding can have a more specific category such as SECURITY
            # while its result section is `danger`. Keep that field intact.
            findings.append(
                {
                    "ai_authored": finding.get("ai_authored"),
                    "ai_agent": finding.get("ai_agent"),
                    "severity": finding.get("severity"),
                    "category": section,
                }
            )
    return compute_ai_security_stats(findings)


@dataclass
class RiskIntersection:
    high_risk: list = field(default_factory=list)
    medium_risk: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "high_risk": self.high_risk,
            "medium_risk": self.medium_risk,
            "summary": self.summary,
        }


def compute_risk_intersections(git_root, provenance_report, exclude_folders=None):
    from skylos.discover.detector import detect_integrations
    from skylos.defend.engine import run_defense_checks

    if not provenance_report.agent_files:
        return RiskIntersection(summary={"high": 0, "medium": 0, "total_ai_files": 0})

    scan_path = Path(git_root)
    integrations, graph = detect_integrations(
        scan_path, exclude_folders=exclude_folders
    )
    defense_results, defense_score, ops_score = run_defense_checks(integrations, graph)

    integration_files = set()
    for integration in integrations:
        loc = integration.location
        if ":" in loc:
            loc = loc.split(":")[0]
        try:
            rel = str(Path(loc).relative_to(scan_path))
        except ValueError:
            rel = loc
        integration_files.add(rel)

    failed_defense_files = set()
    for result in defense_results:
        if not result.passed:
            loc = result.location
            if ":" in loc:
                loc = loc.split(":")[0]
            try:
                rel = str(Path(loc).relative_to(scan_path))
            except ValueError:
                rel = loc
            failed_defense_files.add(rel)

    high_risk = []
    medium_risk = []

    for agent_file in provenance_report.agent_files:
        has_integration = agent_file in integration_files
        has_failed_defense = agent_file in failed_defense_files

        if has_integration and has_failed_defense:
            high_risk.append(
                {
                    "file_path": agent_file,
                    "agent_name": provenance_report.files[agent_file].agent_name,
                    "reasons": [
                        "ai_authored",
                        "has_llm_integration",
                        "failed_defense_check",
                    ],
                }
            )
        elif has_integration or has_failed_defense:
            reasons = ["ai_authored"]
            if has_integration:
                reasons.append("has_llm_integration")
            if has_failed_defense:
                reasons.append("failed_defense_check")
            medium_risk.append(
                {
                    "file_path": agent_file,
                    "agent_name": provenance_report.files[agent_file].agent_name,
                    "reasons": reasons,
                }
            )

    return RiskIntersection(
        high_risk=high_risk,
        medium_risk=medium_risk,
        summary={
            "high": len(high_risk),
            "medium": len(medium_risk),
            "total_ai_files": len(provenance_report.agent_files),
        },
    )
