import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from skylos.constants import NETWORK_TIMEOUT_SHORT, SUBPROCESS_TIMEOUT

logger = logging.getLogger(__name__)

AI_COAUTHOR_PATTERNS = [
    re.compile(r"copilot", re.IGNORECASE),
    re.compile(r"claude", re.IGNORECASE),
    re.compile(r"cursor", re.IGNORECASE),
    re.compile(r"codewhisperer", re.IGNORECASE),
    re.compile(r"tabnine", re.IGNORECASE),
    re.compile(r"github-actions\[bot\]", re.IGNORECASE),
    re.compile(r"devin", re.IGNORECASE),
    re.compile(r"codex", re.IGNORECASE),
    re.compile(r"aider", re.IGNORECASE),
]

AI_EMAIL_PATTERNS = [
    re.compile(r"\[bot\]@", re.IGNORECASE),
    re.compile(r"copilot", re.IGNORECASE),
    re.compile(r"cursor", re.IGNORECASE),
    re.compile(r"claude", re.IGNORECASE),
    re.compile(r"noreply@anthropic\.com", re.IGNORECASE),
    re.compile(r"noreply@github\.com", re.IGNORECASE),
]

AI_MESSAGE_PATTERNS = [
    re.compile(r"generated\s+by\s+(copilot|claude|cursor|ai|codex)", re.IGNORECASE),
    re.compile(r"ai[- ]generated", re.IGNORECASE),
    re.compile(r"co-authored-by.*copilot", re.IGNORECASE),
    re.compile(r"co-authored-by.*claude", re.IGNORECASE),
    re.compile(r"co-authored-by.*cursor", re.IGNORECASE),
    re.compile(r"co-authored-by.*devin", re.IGNORECASE),
]

AGENT_NAME_MAP = {
    "copilot": "copilot",
    "claude": "claude",
    "cursor": "cursor",
    "codewhisperer": "codewhisperer",
    "tabnine": "tabnine",
    "devin": "devin",
    "codex": "codex",
    "aider": "aider",
    "anthropic": "claude",
    "github-actions[bot]": "github-actions",
}

HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class FileProvenance:
    file_path: str
    agent_authored: bool = False
    agent_lines: list = field(default_factory=list)
    indicators: list = field(default_factory=list)
    agent_name: str | None = None


@dataclass
class ProvenanceReport:
    files: dict = field(default_factory=dict)
    agent_files: list = field(default_factory=list)
    human_files: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    confidence: str = "low"

    def to_dict(self):
        file_entries = {}
        for path, fp in self.files.items():
            file_entries[path] = {
                "file_path": fp.file_path,
                "agent_authored": fp.agent_authored,
                "agent_lines": fp.agent_lines,
                "indicators": fp.indicators,
                "agent_name": fp.agent_name,
            }
        return {
            "files": file_entries,
            "agent_files": self.agent_files,
            "human_files": self.human_files,
            "summary": self.summary,
            "confidence": self.confidence,
        }


def _detect_agent_name(text):
    text_lower = text.lower()
    for keyword, name in AGENT_NAME_MAP.items():
        if keyword in text_lower:
            return name
    return None


def _parse_diff_hunks(diff_text):
    file_ranges = {}
    current_file = None

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("+++ /dev/null"):
            current_file = None
        elif line.startswith("@@") and current_file is not None:
            m = HUNK_HEADER_RE.match(line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) else 1
                end = start + max(count - 1, 0)
                if current_file not in file_ranges:
                    file_ranges[current_file] = []
                file_ranges[current_file].append((start, end))

    return file_ranges


def _resolve_base_ref(explicit_base=None):
    if explicit_base:
        return explicit_base

    env_base = os.environ.get("GITHUB_BASE_REF")
    if env_base:
        return f"origin/{env_base}"

    return "origin/main"


def _git_merge_base(git_root, base_ref):
    try:
        return (
            subprocess.check_output(
                ["git", "merge-base", base_ref, "HEAD"],
                cwd=git_root,
                stderr=subprocess.DEVNULL,
                timeout=NETWORK_TIMEOUT_SHORT,
            )
            .decode("utf-8", errors="ignore")
            .strip()
        )
    except (subprocess.SubprocessError, OSError):
        return None


def analyze_provenance(git_root, base_ref=None):
    if not git_root:
        return ProvenanceReport()

    base_ref = _resolve_base_ref(base_ref)
    merge_base = _git_merge_base(git_root, base_ref)

    if not merge_base:
        logger.debug(
            "Could not find merge base for %s, falling back to HEAD~10", base_ref
        )
        range_spec = "HEAD~10..HEAD"
    else:
        range_spec = f"{merge_base}..HEAD"

    indicators_by_commit = {}
    ai_commits = set()
    agents_seen = set()

    try:
        log_output = subprocess.check_output(
            [
                "git",
                "log",
                "--format=%H|%an|%ae|%s|%(trailers:key=Co-authored-by,valueonly,separator=%x00)",
                range_spec,
            ],
            cwd=git_root,
            stderr=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT,
        ).decode("utf-8", errors="ignore")
    except (subprocess.SubprocessError, OSError):
        logger.debug("Failed to get git log for provenance", exc_info=True)
        return ProvenanceReport()

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

        is_ai_commit = False
        indicator = None

        for pat in AI_COAUTHOR_PATTERNS:
            if pat.search(trailers):
                agent = _detect_agent_name(trailers)
                indicator = {
                    "type": "co-author",
                    "commit": commit_sha[:7],
                    "detail": trailers.strip()[:100],
                    "agent_name": agent,
                }
                is_ai_commit = True
                if agent:
                    agents_seen.add(agent)
                break

        if not is_ai_commit:
            for pat in AI_EMAIL_PATTERNS:
                if pat.search(author_email):
                    agent = _detect_agent_name(author_email) or _detect_agent_name(
                        author_name
                    )
                    indicator = {
                        "type": "author-email",
                        "commit": commit_sha[:7],
                        "detail": f"{author_name} <{author_email}>",
                        "agent_name": agent,
                    }
                    is_ai_commit = True
                    if agent:
                        agents_seen.add(agent)
                    break

        if not is_ai_commit:
            for pat in AI_MESSAGE_PATTERNS:
                if pat.search(subject):
                    agent = _detect_agent_name(subject)
                    indicator = {
                        "type": "commit-message",
                        "commit": commit_sha[:7],
                        "detail": subject[:100],
                        "agent_name": agent,
                    }
                    is_ai_commit = True
                    if agent:
                        agents_seen.add(agent)
                    break

        if is_ai_commit:
            ai_commits.add(commit_sha)
            indicators_by_commit[commit_sha] = indicator

    file_provenance = {}
    all_changed_files = set()

    for commit_sha in ai_commits:
        try:
            diff_output = subprocess.check_output(
                ["git", "diff-tree", "-p", "-r", "--no-commit-id", commit_sha],
                cwd=git_root,
                stderr=subprocess.DEVNULL,
                timeout=SUBPROCESS_TIMEOUT,
            ).decode("utf-8", errors="ignore")
        except (subprocess.SubprocessError, OSError):
            logger.debug(
                "Failed to get diff-tree for %s", commit_sha[:7], exc_info=True
            )
            continue

        file_ranges = _parse_diff_hunks(diff_output)
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

    try:
        all_files_output = subprocess.check_output(
            ["git", "diff", "--name-only", range_spec],
            cwd=git_root,
            stderr=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT,
        ).decode("utf-8", errors="ignore")
        all_pr_files = {
            f.strip() for f in all_files_output.strip().splitlines() if f.strip()
        }
    except (subprocess.SubprocessError, OSError):
        all_pr_files = all_changed_files

    agent_files = sorted(file_provenance.keys())
    human_files = sorted(all_pr_files - set(agent_files))

    for hf in human_files:
        file_provenance[hf] = FileProvenance(file_path=hf, agent_authored=False)

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
        summary={
            "total_files": total,
            "agent_count": agent_count,
            "human_count": len(human_files),
            "agents_seen": sorted(agents_seen),
        },
        confidence=confidence,
    )


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
