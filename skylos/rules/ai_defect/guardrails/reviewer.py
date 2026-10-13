"""SKY-A122: the change edits an AI code reviewer's instructions or settings.

Several AI reviewers read their instructions from the pull request's own
head branch (GitHub Copilot code review since 17 Jul 2026, CodeRabbit,
Macroscope, Bito), so a pull request can tell its reviewer what not to
flag, or what it may approve. The file list and the branch each reviewer
reads are in ``skylos/security/agent_instruction_paths.py``.

Reported:

* any change to a reviewer's own config or instruction file that alters what
  the reviewer reads. Edits to comments, whitespace, formatting or line
  order are not reported, and neither is a structured file whose parsed
  settings are equal. Changes that narrow the review are named first:
  exclusions or ignore patterns added, review or a review tool turned off, a
  higher comment threshold or fewer comments, a quieter profile, approval
  turned on or widened, and added instructions such as "do not flag",
  "ignore" or "approve";
* in AGENTS.md, CLAUDE.md and GEMINI.md, which Copilot code review and
  Claude Code Review also read, only added lines aimed at the reviewer
  ("do not flag", "approve this pull request", "reviewers should ignore").
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import replace
from pathlib import PurePosixPath

from skylos.rules.ai_defect.guardrails.core import (
    MISSING,
    RULE_REVIEWER_CONFIG,
    UNPARSED,
    FileChange,
    GuardrailFinding,
    SettingChange,
    compare_settings,
    first_added,
    join_changes,
    line_of,
    normalized_lines,
    number,
    parse_json,
    parse_toml,
    parse_yaml,
    shown,
    truthy,
)
from skylos.security.agent_instruction_paths import (
    ai_reviewer_entry,
    is_shared_reviewer_instruction_path,
)

# Files whose every added line excludes files from the review, or widens what
# the reviewer may approve.
_IGNORE_FILES = frozenset(
    {".macroscope/ignore", ".macroscope/ignore.md", ".macroscope-ignore"}
)
_APPROVAL_FILES = frozenset(
    {".macroscope/approvability.md", "macroscope_approvability.md"}
)

# Instructions in a reviewer's own files that ask it to say less or approve.
# "Ignore", "skip" and "exclude" count only as an instruction (at the start
# of a sentence or list item), and never after a negation: "Never silently
# ignore failures" and "do not skip heading levels" ask for more, not less.
_SUPPRESSIVE_PHRASES_RE = re.compile(
    r"\b(?:"
    r"auto-?approv\w*|approve\b(?!d)|lgtm\b|"
    r"(?:do\s+not|don'?t|never|no\s+need\s+to|should\s+not|must\s+not|avoid)\s+"
    r"(?:flag(?:ging)?|report(?:ing)?|comment(?:ing)?\s+on|mention(?:ing)?|"
    r"block(?:ing)?\s+(?:the\s+)?(?:PR|pull\s+request|merge)|request(?:ing)?\s+changes|"
    r"nitpick(?:ing)?|point(?:ing)?\s+out|warn(?:ing)?\s+about|complain(?:ing)?\s+about)\b|"
    r"not\s+(?:a|an)\s+(?:issue|problem|concern|bug|vulnerability)\b"
    r")",
    re.IGNORECASE,
)
_IMPERATIVE_EXCLUSION_RE = re.compile(
    r"(?:^|[.;:!?]\s+|^\s*(?:[-*+>]|\d+[.)])\s+)(?:please\s+|always\s+)?"
    r"(?:ignore|skip|exclude)\b",
    re.IGNORECASE,
)


def is_suppressive(text: str) -> bool:
    """Whether an instruction asks the reviewer to say less, look away or
    approve."""
    if not isinstance(text, str) or not text.strip():
        return False
    stripped = text.strip().strip("`*_#> ")
    return bool(
        _SUPPRESSIVE_PHRASES_RE.search(stripped)
        or _IMPERATIVE_EXCLUSION_RE.search(stripped)
    )


# Lines in shared agent instruction files that are aimed at a reviewer.
REVIEW_DIRECTED_RE = re.compile(
    r"(?:"
    r"\b(?:auto-?approve|approve)\s+(?:this\s+|the\s+|all\s+|any\s+|every\s+)?"
    r"(?:pull\s+requests?|PRs?|changes?|diffs?|merge\s+requests?|MRs?)\b|"
    r"\blgtm\b|"
    r"\b(?:do\s+not|don'?t|never|no\s+need\s+to|should\s+not|must\s+not)\s+"
    r"(?:flag|report|request\s+changes|block\s+(?:the\s+)?(?:PR|pull\s+request|merge))\b|"
    r"\b(?:when|while|during)\s+(?:reviewing|code\s+reviews?|reviews?|reviewing\s+code)\b"
    r"[^.\n]{0,80}\b(?:ignore|skip|do\s+not|don'?t|never|approve)\b|"
    r"\b(?:code\s+)?review(?:er|ers)?\b[^.\n]{0,40}\b(?:should|must|can|may)\s+"
    r"(?:ignore|skip|approve|not\s+flag|not\s+report)\b"
    r")",
    re.IGNORECASE,
)
_NARROWING_KEY_RE = re.compile(
    r"(?:ignore|exclude|skip|filter|disabled_?labels?|disabledrules|excludeauthors|"
    r"excludebranches)",
    re.IGNORECASE,
)
_ENABLE_LEAF_RE = re.compile(
    r"^(?:enabled?|auto_?review|autoreview|auto_?incremental_?review|code_?review|"
    r"review|summary|triggerOnUpdates)$",
    re.IGNORECASE,
)
_DISABLE_LEAF_RE = re.compile(r"^(?:disabled?|disable_\w+)$", re.IGNORECASE)
_THRESHOLD_LEAF_RE = re.compile(
    r"(?:threshold|min_?severity|riskceiling)", re.IGNORECASE
)
_MAX_COMMENTS_RE = re.compile(r"max\w*comments?", re.IGNORECASE)
_APPROVE_KEY_RE = re.compile(r"approv|request_changes_workflow", re.IGNORECASE)
_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "minor": 1,
    "medium": 2,
    "moderate": 2,
    "high": 3,
    "major": 3,
    "critical": 4,
    "blocker": 5,
}
# CodeRabbit review profiles, quietest first (default "chill").
_PROFILE_ORDER = {"quiet": 0, "chill": 1, "assertive": 2}
_BRANCH_NOTE = {
    "head": "read from the pull request's head",
    "base": "read from the default branch after merge",
}


def _leaf(key: str) -> str:
    leaf = key.rsplit(".", 1)[-1]
    return leaf.split("[", 1)[0] or leaf


def _lines_of(value) -> frozenset[str] | None:
    """A newline-separated setting (Greptile ``ignorePatterns``) as a set."""
    if isinstance(value, str) and "\n" in value.strip():
        return frozenset(line.strip() for line in value.splitlines() if line.strip())
    return None


def _describe(change: SettingChange) -> tuple[bool, str]:
    """(narrows the review, plain description) for one setting change."""
    key, before, after = change.key, change.before, change.after
    leaf = _leaf(key)
    old_lines = _lines_of(before) if before is not MISSING else None
    new_lines = _lines_of(after) if after is not MISSING else None
    if (old_lines is not None or new_lines is not None) and _NARROWING_KEY_RE.search(
        key
    ):
        before = (
            old_lines
            if old_lines is not None
            else frozenset(
                [before] if isinstance(before, str) and before.strip() else []
            )
        )
        after = (
            new_lines
            if new_lines is not None
            else frozenset([after] if isinstance(after, str) and after.strip() else [])
        )
    if isinstance(after, frozenset) or isinstance(before, frozenset):
        old = before if isinstance(before, frozenset) else frozenset()
        new = after if isinstance(after, frozenset) else frozenset()
        gained = sorted(new - old)
        lost = sorted(old - new)
        parts = []
        if gained:
            more = f" and {len(gained) - 3} more" if len(gained) > 3 else ""
            parts.append(
                f"{key} gained {', '.join(shown(g, 60) for g in gained[:3])}{more}"
            )
        if lost:
            more = f" and {len(lost) - 3} more" if len(lost) > 3 else ""
            parts.append(
                f"{key} lost {', '.join(shown(g, 60) for g in lost[:3])}{more}"
            )
        narrows = bool(gained) and bool(_NARROWING_KEY_RE.search(key))
        narrows = narrows or any(is_suppressive(item) for item in gained)
        narrows = narrows or (bool(gained) and bool(_APPROVE_KEY_RE.search(key)))
        if narrows and bool(_NARROWING_KEY_RE.search(key)):
            parts[0] += " (excluded from review)"
        return narrows, "; ".join(parts) or f"{key} changed"
    if before is MISSING:
        return _narrowing_value(key, leaf, None, after), f"{key} set to {shown(after)}"
    if after is MISSING:
        text = f"{key} removed (was {shown(before)})"
        narrows = (
            _NARROWING_KEY_RE.search(key) is None
            and bool(_ENABLE_LEAF_RE.match(leaf))
            and truthy(before) is True
        )
        return narrows, text
    return _narrowing_value(key, leaf, before, after), (
        f"{key} {shown(before)} → {shown(after)}"
    )


def _narrowing_value(key: str, leaf: str, before, after) -> bool:
    if isinstance(after, str) and is_suppressive(after) and not is_suppressive(before):
        return True
    new = truthy(after)
    old = truthy(before) if before is not None else None
    if _ENABLE_LEAF_RE.match(leaf) and new is False and old is not False:
        return True
    if _DISABLE_LEAF_RE.match(leaf) and new is True and old is not True:
        return True
    if _APPROVE_KEY_RE.search(key) and new is True and old is not True:
        return True
    if (
        _NARROWING_KEY_RE.search(key)
        and before is None
        and after not in (None, "", False)
    ):
        return True
    if _THRESHOLD_LEAF_RE.search(leaf):
        old_rank, new_rank = _rank(before), _rank(after)
        if old_rank is not None and new_rank is not None and new_rank > old_rank:
            return True
        if before is None and new_rank is not None and new_rank >= 3:
            return True
    if _MAX_COMMENTS_RE.search(leaf):
        # A negative maximum means no limit (Gemini Code Assist: -1).
        old_n, new_n = number(before), number(after)
        if (
            new_n is not None
            and new_n >= 0
            and (old_n is None or old_n < 0 or new_n < old_n)
        ):
            return True
    if leaf == "profile" and isinstance(after, str):
        old_rank = _PROFILE_ORDER.get(str(before).lower() if before else "chill", 1)
        new_rank = _PROFILE_ORDER.get(after.lower())
        return new_rank is not None and new_rank < old_rank
    return False


def _rank(value) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().lower()
    if text in _SEVERITY_ORDER:
        return float(_SEVERITY_ORDER[text])
    return number(text)


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------


def detect_reviewer_config_changes(
    changes: list[FileChange],
) -> tuple[list[GuardrailFinding], int, list[str]]:
    """Findings, files read and files that did not parse on one side."""
    findings: list[GuardrailFinding] = []
    unparsed: list[str] = []
    read = 0
    for change in changes:
        entry = ai_reviewer_entry(change.path)
        base_entry = (
            ai_reviewer_entry(change.base_path)
            if change.base_path and change.base_path != change.path
            else None
        )
        if entry is None and base_entry is not None and _same_skill_move(change):
            continue  # Copilot reads skills in all three skill folders
        if entry is None and base_entry is not None:
            # Moved out of the files the reviewer reads.
            read += 1
            finding = _moved_out(change, *base_entry)
        elif entry is not None:
            read += 1
            if (
                change.base_path
                and change.base_path != change.path
                and base_entry is None
            ):
                # Moved in from elsewhere: new to the reviewer.
                change = replace(change, base_text=None, base_path=None)
            finding = _compare(change, entry[0], entry[1], unparsed)
        elif is_shared_reviewer_instruction_path(change.path) and change.head_text:
            read += 1
            finding = _shared_instruction_change(change)
        else:
            continue
        if finding is not None:
            findings.append(finding)
    return findings, read, unparsed


# GitHub's agent-skills docs list three skill folders Copilot reads; only
# .github/skills is named for code review, so only it is an A122 path, but a
# skill moved between them has not left Copilot's view.
_SKILL_FOLDERS = (".github/skills/", ".agents/skills/", ".claude/skills/")


def _same_skill_move(change: FileChange) -> bool:
    def tail(path: str | None) -> str | None:
        for folder in _SKILL_FOLDERS:
            if path and path.startswith(folder):
                return path[len(folder) :]
        return None

    return tail(change.base_path) is not None and tail(change.path) is not None


def _moved_out(change: FileChange, tool: str, branch: str) -> GuardrailFinding | None:
    if not normalized_lines(change.base_text):
        return None
    return GuardrailFinding(
        RULE_REVIEWER_CONFIG,
        change.base_path,
        None,
        f"{change.base_path}: {tool} review instructions moved to {change.path}, "
        f"outside the files {tool} reads",
        "reviewer_config_deleted",
        details={
            "tool": tool,
            "branch": branch,
            "narrows": True,
            "moved_to": change.path,
        },
    )


def _label(change: FileChange, tool: str, branch: str, what: str) -> str:
    note = _BRANCH_NOTE.get(branch)
    return f"{change.path}: {tool} {what}{' (' + note + ')' if note else ''}"


def _compare(change: FileChange, tool: str, branch: str, unparsed: list[str]):
    path = change.path
    if change.head_text is None:
        if change.status != "deleted" or change.base_text is None:
            return None
        if not normalized_lines(change.base_text):
            return None
        what = "review settings" if _parser(path) else "review instructions"
        return GuardrailFinding(
            RULE_REVIEWER_CONFIG,
            path,
            None,
            f"{_label(change, tool, branch, what)} deleted; the "
            "reviewer falls back to its defaults or organization settings",
            "reviewer_config_deleted",
            details={"tool": tool, "branch": branch, "narrows": True},
        )
    parser = _parser(path)
    if parser is not None:
        before = parser(change.base_text) if change.base_text is not None else {}
        after = parser(change.head_text)
        if before is UNPARSED or after is UNPARSED:
            unparsed.append(path)
            return _text_change(change, tool, branch)
        return _structured_change(change, tool, branch, before or {}, after or {})
    return _text_change(change, tool, branch)


def _parser(path: str):
    name = PurePosixPath(path).name.lower()
    if name.endswith((".yaml", ".yml")):
        return parse_yaml
    if name.endswith(".toml"):
        return parse_toml
    if name.endswith(".json"):
        return parse_json
    return None


_ITEM_KEY_RE = re.compile(r"\[(?P<field>\w+)=[^\]]*\]\.(?P<leaf>\w+)$")


def _identity_field(item: SettingChange) -> bool:
    """``list[path=src/**].path`` of an added or removed item: the item's own
    name, already shown by its other fields."""
    match = _ITEM_KEY_RE.search(item.key)
    return bool(match) and match.group("field") == match.group("leaf")


def _structured_change(change, tool, branch, before, after) -> GuardrailFinding | None:
    settings = compare_settings(before, after)
    if not settings:
        return None
    named = [item for item in settings if not _identity_field(item)]
    settings = named or settings
    described = [_describe(item) for item in settings]
    narrowing = [text for narrows, text in described if narrows]
    other = [text for narrows, text in described if not narrows]
    verb = "added" if change.base_text is None else "changed"
    message = (
        f"{_label(change, tool, branch, 'review settings')} {verb}: "
        + join_changes(narrowing + other)
    )
    ordered = [item for item, (narrows, _) in zip(settings, described) if narrows]
    ordered += [item for item in settings if item not in ordered]
    line = _added_line_for(change, ordered)
    if line is None:
        line = first_added(change) or line_of(change.head_text, _leaf(ordered[0].key))
    return GuardrailFinding(
        RULE_REVIEWER_CONFIG,
        change.path,
        line,
        message,
        "reviewer_config_narrowed" if narrowing else "reviewer_config_changed",
        details={
            "tool": tool,
            "branch": branch,
            "narrows": bool(narrowing),
            "changed_settings": [item.key for item in settings][:20],
        },
    )


def _needles(item: SettingChange) -> list[str]:
    """Text that shows this change on an added line: the new values first,
    then the setting's own name."""
    needles: list[str] = []
    after, before = item.after, item.before
    if isinstance(after, frozenset):
        old = before if isinstance(before, frozenset) else frozenset()
        needles += sorted(after - old)
    elif after is not MISSING and isinstance(after, (str, int, float)):
        text = str(after).splitlines()[0] if str(after).strip() else ""
        if isinstance(after, bool):
            text = "true" if after else "false"
        if text:
            needles.append(text[:40])
    needles.append(_leaf(item.key))
    return [n for n in needles if n]


def _added_line_for(change: FileChange, settings: list[SettingChange]) -> int | None:
    if not change.head_text or not change.added_lines:
        return None
    lines = change.head_text.splitlines()
    for item in settings:
        for needle in _needles(item):
            for line_number in sorted(change.added_lines):
                if 1 <= line_number <= len(lines) and needle in lines[line_number - 1]:
                    return line_number
    return None


def _line_diff(change: FileChange) -> tuple[list[str], list[str]]:
    before = normalized_lines(change.base_text)
    after = normalized_lines(change.head_text)
    old, new = Counter(before), Counter(after)
    added = list(dict.fromkeys(line for line in after if new[line] > old[line]))
    removed = list(dict.fromkeys(line for line in before if old[line] > new[line]))
    return added, removed


def _front_matter_lines(text: str | None) -> set[str]:
    """Normalized lines of a leading ``---`` front-matter block."""
    lines = (text or "").splitlines()
    if not lines or lines[0].strip() != "---":
        return set()
    found = set()
    for line in lines[1:]:
        if line.strip() == "---":
            return found
        found.add(" ".join(line.split()))
    return set()


def _meaningful(line: str) -> bool:
    """A line worth quoting: not a delimiter, bare heading mark or rule."""
    bare = line.strip().strip("#*-_=`>|:~ ")
    return sum(ch.isalnum() for ch in bare) >= 3


def _text_change(change, tool, branch) -> GuardrailFinding | None:
    added, removed = _line_diff(change)
    if not added and not removed:
        return None  # formatting, blank lines or line order only
    path = change.path
    # A settings file that did not parse is still settings.
    what = "review settings" if _parser(path) else "review instructions"
    verb = "added" if change.base_text is None else "changed"
    parts = []
    narrows = False
    front = _front_matter_lines(change.head_text)
    prose = [line for line in added if _meaningful(line) and line not in front]
    patterns = [
        line
        for line in added
        if line not in front and line != "---" and not line.startswith("#")
    ]
    if path in _IGNORE_FILES and patterns:
        narrows = True
        parts.append(
            "excludes more files from review: "
            + ", ".join(shown(line, 60) for line in patterns[:3])
            + (f" and {len(patterns) - 3} more" if len(patterns) > 3 else "")
        )
        flagged = patterns[:1]
    elif path in _APPROVAL_FILES and prose:
        narrows = True
        parts.append(
            "adds auto-approval rules such as "
            + ", ".join(shown(line, 90) for line in prose[:2])
        )
        flagged = prose[:1]
    else:
        flagged = [line for line in prose if is_suppressive(line)]
        if flagged:
            narrows = True
            quoted = ", ".join(shown(line, 90) for line in flagged[:2])
            more = f" and {len(flagged) - 2} more" if len(flagged) > 2 else ""
            parts.append(f"adds instructions such as {quoted}{more}")
        elif prose:
            parts.append(f"adds {shown(prose[0], 90)}")
        elif removed:
            gone = [line for line in removed if _meaningful(line)] or removed
            parts.append(f"removes {shown(gone[0], 90)}")
    counts = []
    if added:
        counts.append(f"{len(added)} line(s) added")
    if removed:
        counts.append(f"{len(removed)} removed")
    parts.append(", ".join(counts))
    message = f"{_label(change, tool, branch, what)} {verb}: " + "; ".join(parts)
    line = _line_with(change, flagged[0]) if flagged else None
    if line is None and (prose or added):
        line = _line_with(change, (prose or added)[0])
    if line is None:
        line = first_added(change)
    return GuardrailFinding(
        RULE_REVIEWER_CONFIG,
        path,
        line,
        message,
        "reviewer_config_narrowed" if narrows else "reviewer_config_changed",
        details={
            "tool": tool,
            "branch": branch,
            "narrows": narrows,
            "lines_added": len(added),
            "lines_removed": len(removed),
        },
    )


def _shared_instruction_change(change: FileChange) -> GuardrailFinding | None:
    added, _ = _line_diff(change)
    directed = [line for line in added if REVIEW_DIRECTED_RE.search(line)]
    if not directed:
        return None
    name = PurePosixPath(change.path).name
    readers = (
        "Claude Code Review and Copilot code review"
        if name == "CLAUDE.md"
        else "Copilot code review"
    )
    if name != "CLAUDE.md" and "/" in change.path:
        return None  # Copilot reads only the root AGENTS.md and GEMINI.md
    quoted = ", ".join(shown(line, 90) for line in directed[:2])
    more = f" and {len(directed) - 2} more" if len(directed) > 2 else ""
    return GuardrailFinding(
        RULE_REVIEWER_CONFIG,
        change.path,
        _line_with(change, directed[0]) or first_added(change),
        f"{change.path} (instructions {readers} read from the pull request's head) "
        f"gained reviewer-directed instructions: {quoted}{more}",
        "reviewer_config_narrowed",
        details={"tool": readers, "branch": "head", "narrows": True},
    )


def _line_with(change: FileChange, normalized: str) -> int | None:
    if not change.head_text:
        return None
    fallback = None
    for index, line in enumerate(change.head_text.splitlines(), 1):
        if " ".join(line.split()) == normalized:
            if index in change.added_lines:
                return index
            fallback = fallback or index
    return fallback
