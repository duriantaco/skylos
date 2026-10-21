from __future__ import annotations

import bisect
import re
from pathlib import Path

from skylos.security.canonicalize import (
    MAX_BASE64_RESULTS,
    MAX_ZERO_WIDTH_HITS,
    decode_base64_blobs,
    detect_homoglyphs,
    normalize,
    strip_zero_width,
)
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.security.agent_instruction_paths import (
    AGENT_RULE_ID,
    agent_rule_id,
    agent_severity,
    is_agent_instruction_path,
    is_ai_reviewer_config_path,
)

RULE_ID = "SKY-D260"

MAX_SCANNABLE_FILE_BYTES = 1_000_000
MAX_FINDINGS_PER_FILE = 128
MAX_SCAN_FILES = 512
MAX_SCAN_FINDINGS = 1024

_DETERMINERS = r"(?:(?:all|the|your|any|every|those|these|my|our|their)\s+)*"
_CREDENTIAL_TOKEN_KINDS = (
    r"(?:access|auth|authentication|api|bearer|oauth|session|secret|refresh"
    r"|github|gitlab|npm|pypi|aws|private|personal\s+access)"
)
_SECRET_STORE = (
    r"(?:from|in|inside|within|stored\s+in|found\s+in|held\s+in)\s+"
    r"(?:[\w.'-]+\s+){0,3}?"
    r"(?:env\b|environment|\.env\b|keychain|keyring|vault|secrets?\b"
    r"|credentials?\b|~/|\$HOME\b|\w*password(?:s|\s+manager)?\b"
    r"|parameter\s+store|key\s+vault)"
)
_CLAUSE_START = (
    r"(?:^[\s>*#\-\"'`(\[]*|[.!?;:,]\s*"
    r"|\b(?:please|then|now|also|just|always|must|should|shall|will|can|could"
    r"|would|may|might|to|you|(?<!input\s)and)\s+)"
)

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.I), "HIGH"),
    (re.compile(r"ignore\s+(all\s+)?prior\s+instructions?", re.I), "HIGH"),
    (
        re.compile(
            r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I
        ),
        "HIGH",
    ),
    (
        re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
        "HIGH",
    ),
    (re.compile(r"override\s+(all\s+)?(previous|prior)\s+instructions?", re.I), "HIGH"),
    (re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.I), "HIGH"),
    (re.compile(r"(?:^|\.\s+)act\s+as\s+(a|an|the)\b", re.I), "HIGH"),
    (re.compile(r"pretend\s+(you\s+are|to\s+be)\b", re.I), "HIGH"),
    (re.compile(r"new\s+instructions?:\s", re.I), "HIGH"),
    (re.compile(r"do\s+not\s+(flag|report|detect|scan|warn|alert)\b", re.I), "MEDIUM"),
    (
        re.compile(r"skip\s+(security|analysis|review|scanning|checks?)\b", re.I),
        "MEDIUM",
    ),
    (re.compile(r"approve\s+all\s+(changes?|code|commits?)\b", re.I), "MEDIUM"),
    (re.compile(r"mark\s+(this|all|everything)\s+(as\s+)?safe\b", re.I), "MEDIUM"),
    (
        re.compile(
            r"this\s+(code|file)\s+is\s+(safe|secure|reviewed|approved)\b", re.I
        ),
        "MEDIUM",
    ),
    (
        re.compile(
            r"(output|reveal|display|leak)\s+(all\s+)?"
            r"(env\b|environment|secrets?|api.?keys?|credentials?|passwords?)"
            r"|(reveal|display|leak)\s+(all\s+)?tokens?"
            rf"|output\s+all\s+tokens?"
            rf"|output\s+{_DETERMINERS}{_CREDENTIAL_TOKEN_KINDS}[\s_-]+tokens?"
            rf"|{_CLAUSE_START}output\s+{_DETERMINERS}tokens?\s+{_SECRET_STORE}"
            rf"|{_CLAUSE_START}output\s+tokens?(?:\s*,\s*|\s+(?:and|or|&)\s+)(?:all\s+|the\s+|your\s+)*"
            r"(?:secrets?|api.?keys?|credentials?|passwords?)",
            re.I,
        ),
        "HIGH",
    ),
    (re.compile(r"send\s+(all\s+)?(data|content|file|code)\s+to\b", re.I), "HIGH"),
]

_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_FRONT_MATTER_RE = re.compile(r"\A---\n.*?\n---\n", re.S)

SCANNABLE_EXTENSIONS = {
    ".py",
    ".md",
    ".rst",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".env",
}

_SKIP_PREFIXES = ("test_", "conftest")

_DEFAULT_EXCLUDE_DIRS = {d for d in DEFAULT_EXCLUDE_FOLDERS if "*" not in d} | {
    "site-packages"
}

_HIGH_RISK_FILENAMES = {
    "readme.md",
    "readme.rst",
    "readme.txt",
    "contributing.md",
    "contributing.rst",
    "security.md",
}

_PROMPT_KEYS_RE = re.compile(
    r"""(?:^|\s|"|')"""
    r"(system_prompt|prompt|instructions|system_message|"
    r"user_prompt|assistant_prompt|template|prompt_template|"
    r"system_template|tool_description|function_description)"
    r"""(?:\s*[:=]|"|')""",
    re.I,
)


def scan_file(
    filepath: str | Path,
    *,
    scan_path: str | Path | None = None,
    high_only: bool = False,
) -> list[dict]:
    """Prompt-injection findings for one file.

    AI code reviewers' config and instruction files (``.coderabbit.yaml``,
    ``.gemini/styleguide.md``, ``.cursor/BUGBOT.md`` ...) are instructions to
    an agent: HIGH signals in them (instruction overrides, role changes,
    requests to reveal or send data, encoded payloads, invisible characters)
    are reported as SKY-D266 at CRITICAL. Reviewing vocabulary ("do not
    flag", "skip review") is what those files exist to say, so it keeps its
    ordinary SKY-D260 severity; SKY-A122 reports changes to them in a diff.
    ``high_only`` limits a file to the HIGH signals (used for reviewer files
    found by the full-scan walk, which did not read them before).
    """
    filepath = Path(filepath)
    if not filepath.is_file():
        return []

    if scan_path is not None:
        display_path = Path(scan_path)
    else:
        display_path = filepath
    is_agent_instruction = is_agent_instruction_path(display_path)
    is_reviewer_config = not is_agent_instruction and is_ai_reviewer_config_path(
        display_path
    )
    if not is_scannable_path(filepath, display_path):
        return []

    def high_signal(severity: str) -> tuple[str, str]:
        """(severity, rule) for a signal whose base severity is HIGH."""
        if is_agent_instruction or is_reviewer_config:
            return "CRITICAL", AGENT_RULE_ID
        return severity, RULE_ID

    ext = filepath.suffix.lower()
    basename = filepath.name
    if not is_agent_instruction and any(
        basename.startswith(p) for p in _SKIP_PREFIXES
    ):
        return []

    try:
        if filepath.stat().st_size > MAX_SCANNABLE_FILE_BYTES:
            return []
        source = filepath.read_text(
            errors="replace"
        )  # skylos: ignore[SKY-D215] scanner reads discovered source files
    except OSError:
        return []

    findings: list[dict] = []
    if not high_only:
        _add_path_homoglyph_findings(findings, filepath, scan_path or filepath.name)

    if not source.strip():
        return findings

    _, zero_width_hits = strip_zero_width(source, max_hits=MAX_ZERO_WIDTH_HITS)
    source_lines = source.split("\n")
    # A U+FEFF that starts the file is the UTF-8 byte-order mark (Windows
    # editors write it in any file type); it precedes all text and hides
    # nothing. Hits are in file order, so it is the first one. Agent
    # instruction files, and AI-reviewer configs other than JSON, stay strict.
    leading_bom = (
        source.startswith("\ufeff")
        and not is_agent_instruction
        and (not is_reviewer_config or ext == ".json")
    )
    for index, (char_hex, line_no) in enumerate(zero_width_hits):
        if index == 0 and leading_bom:
            continue
        hidden_severity, hidden_rule = high_signal("HIGH")
        if (
            is_reviewer_config
            and char_hex == "U+200D"
            and _only_emoji_joiners(source_lines, line_no)
        ):
            # A zero-width joiner between emoji (U+1F469 U+200D U+1F4BB, "woman technologist") hides nothing.
            if high_only:
                continue
            hidden_severity, hidden_rule = "HIGH", RULE_ID
        findings.append(
            _make_finding(
                filepath,
                line_no,
                "hidden_char",
                hidden_severity,
                char_hex,
                char_hex,
                f"Invisible Unicode character {char_hex} found. "
                f"Zero-width characters in source code can hide "
                f"prompt injection payloads from human reviewers.",
                rule_id=hidden_rule,
            )
        )
        if len(findings) >= MAX_FINDINGS_PER_FILE:
            return findings

    if not high_only:
        _add_source_homoglyph_findings(
            findings, filepath, source, is_agent_instruction
        )
    if len(findings) >= MAX_FINDINGS_PER_FILE:
        return findings

    segment_ext = ext
    if is_agent_instruction and ext not in SCANNABLE_EXTENSIONS:
        segment_ext = ".md"
    segments = _extract_segments(
        source,
        segment_ext,
        filepath,
        keep_comments=is_agent_instruction or is_reviewer_config,
    )

    is_high_risk_file = basename.lower() in _HIGH_RISK_FILENAMES
    seen_findings: set[tuple[int, str]] = set()

    for text, line_no, segment_type in segments:
        normalized = normalize(text)

        for pattern, base_severity in _PATTERNS:
            if high_only and base_severity != "HIGH":
                continue
            if pattern.search(normalized):
                severity = _adjust_severity(
                    base_severity, segment_type, is_high_risk_file
                )
                severity = agent_severity(severity, is_agent_instruction)
                rule_id = agent_rule_id(is_agent_instruction, RULE_ID)
                if base_severity == "HIGH":
                    severity, rule_id = high_signal(severity)

                finding_type = "literal_payload"
                if segment_type == "html_comment":
                    finding_type = "risky_placement"
                elif segment_type == "prompt_field":
                    finding_type = "risky_placement"

                dedup_key = (line_no, finding_type)
                if dedup_key in seen_findings:
                    break
                seen_findings.add(dedup_key)

                snippet = text.strip()[:100]
                if len(text.strip()) > 100:
                    snippet += "..."

                findings.append(
                    _make_finding(
                        filepath,
                        line_no,
                        finding_type,
                        severity,
                        "prompt_injection",
                        "prompt_injection",
                        f"Prompt injection pattern in {segment_type}: '{snippet}'. "
                        f"This may attempt to manipulate AI agents processing this content.",
                        rule_id=rule_id,
                    )
                )
                if len(findings) >= MAX_FINDINGS_PER_FILE:
                    return findings
                break

    decoded_blobs = decode_base64_blobs(source, max_results=MAX_BASE64_RESULTS)
    for decoded_text, line_no in decoded_blobs:
        normalized = normalize(decoded_text)
        for pattern, base_severity in _PATTERNS:
            if pattern.search(normalized):
                snippet = decoded_text.strip()[:80]
                payload_severity, payload_rule = high_signal("HIGH")
                findings.append(
                    _make_finding(
                        filepath,
                        line_no,
                        "obfuscated_payload",
                        payload_severity,
                        "prompt_injection",
                        "base64",
                        f"Base64-encoded string decodes to prompt injection: '{snippet}'. "
                        f"Encoded payloads bypass human review while remaining effective "
                        f"against AI agents.",
                        rule_id=payload_rule,
                    )
                )
                if len(findings) >= MAX_FINDINGS_PER_FILE:
                    return findings
                break

    return findings


def _is_pictographic(char: str) -> bool:
    code = ord(char)
    return (
        0x1F000 <= code <= 0x1FAFF
        or 0x2600 <= code <= 0x27BF
        or code in (0xFE0F, 0x2640, 0x2642, 0x2695, 0x2696, 0x2708, 0x2764)
        or 0x1F3FB <= code <= 0x1F3FF
    )


def _only_emoji_joiners(lines: list[str], line_no: int) -> bool:
    """Every U+200D on the line joins two emoji characters."""
    if not 1 <= line_no <= len(lines):
        return False
    line = lines[line_no - 1]
    for index, char in enumerate(line):
        if char != "\u200d":
            continue
        before = line[index - 1] if index > 0 else ""
        after = line[index + 1] if index + 1 < len(line) else ""
        if not (before and after and _is_pictographic(before) and _is_pictographic(after)):
            return False
    return True


def scan_directory(
    root: str | Path, exclude_dirs: set[str] | None = None
) -> list[dict]:
    root = Path(root)
    all_excludes = _DEFAULT_EXCLUDE_DIRS | (exclude_dirs or set())
    findings: list[dict] = []

    files_scanned = 0
    for filepath in root.rglob("*"):
        if files_scanned >= MAX_SCAN_FILES or len(findings) >= MAX_SCAN_FINDINGS:
            break
        if not filepath.is_file():
            continue

        rel = filepath.relative_to(root)
        if not is_scannable_path(filepath, rel):
            continue
        parts = rel.parts
        if any(p in all_excludes for p in parts[:-1]):
            continue
        if any(p.startswith(".") for p in parts[:-1]) and not is_agent_instruction_path(
            rel
        ):
            continue

        files_scanned += 1
        remaining = MAX_SCAN_FINDINGS - len(findings)
        findings.extend(scan_file(filepath, scan_path=rel)[:remaining])

    return findings


def _close_basic_string(line: str, start: int) -> int | None:
    index = start
    while index < len(line):
        char = line[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            return index + 1
        index += 1
    return None


def _yaml_token_spans(source: str) -> list[tuple[int, int]] | None:
    import yaml

    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    try:
        tokens = list(yaml.scan(source, Loader=loader))
    except (yaml.YAMLError, ValueError, RecursionError):
        return None
    return sorted(
        (token.start_mark.index, token.end_mark.index)
        for token in tokens
        if token.end_mark.index > token.start_mark.index
    )


def _yaml_lines_without_comments(source: str) -> list[str] | None:
    spans = _yaml_token_spans(source)
    if spans is None:
        return None
    starts = [start for start, _end in spans]
    lines = []
    offset = 0
    for line in source.splitlines(keepends=True):
        lines.append(_yaml_line_before_comment(line, offset, spans, starts))
        offset += len(line)
    return lines


def _yaml_line_before_comment(line, offset, spans, starts) -> str:
    index = line.find("#")
    while index >= 0:
        position = offset + index
        span = bisect.bisect_right(starts, position) - 1
        inside = span >= 0 and spans[span][0] <= position < spans[span][1]
        if not inside and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
        index = line.find("#", index + 1)
    return line


def _toml_parses(source: str) -> bool:
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return True
    try:
        tomllib.loads(source)
    except (ValueError, RecursionError):
        return False
    return True


class _TomlComments:
    def __init__(self) -> None:
        self.delimiter = ""

    def strip(self, line: str) -> str:
        index = 0
        if self.delimiter:
            index = self._close_multiline(line, 0)
            if index is None:
                return line
        while index < len(line):
            char = line[index]
            if char == "#":
                return line[:index]
            if line.startswith(('"""', "'''"), index):
                self.delimiter = line[index : index + 3]
                close = self._close_multiline(line, index + 3)
                if close is None:
                    return line
                index = close
                continue
            if char == '"':
                close = _close_basic_string(line, index + 1)
            elif char == "'":
                close = line.find("'", index + 1) + 1
                if close == 0:
                    close = None
            else:
                index += 1
                continue
            if close is None:
                return line
            index = close
        return line

    def _close_multiline(self, line: str, start: int) -> int | None:
        delimiter = self.delimiter
        index = start
        while index < len(line):
            if delimiter == '"""' and line[index] == "\\":
                index += 2
                continue
            if line.startswith(delimiter, index):
                end = index + 3
                while end < len(line) and end < index + 5 and line[end] == delimiter[0]:
                    end += 1
                self.delimiter = ""
                return end
            index += 1
        return None


def _toml_lines_without_comments(source: str) -> list[str] | None:
    if not _toml_parses(source):
        return None
    comments = _TomlComments()
    return [comments.strip(line) for line in source.splitlines(keepends=True)]


def _config_segments(
    source: str, ext: str, *, keep_comments: bool = False
) -> list[tuple[str, int, str]]:
    lines = None
    if not keep_comments and ext in (".yaml", ".yml"):
        lines = _yaml_lines_without_comments(source)
    elif not keep_comments and ext == ".toml":
        lines = _toml_lines_without_comments(source)
    segments: list[tuple[str, int, str]] = []
    for line_no, line in enumerate(source.splitlines(), 1):
        if lines is None:
            text = line.strip()
            if text.startswith("#"):
                continue
        else:
            text = lines[line_no - 1].strip()
        if not text:
            continue
        segment_type = "config"
        if _PROMPT_KEYS_RE.search(line):
            segment_type = "prompt_field"
        segments.append((text, line_no, segment_type))
    return segments


def _extract_segments(
    source: str, ext: str, filepath: Path, *, keep_comments: bool = False
) -> list[tuple[str, int, str]]:
    segments: list[tuple[str, int, str]] = []

    if ext == ".py":
        for line_no, line in enumerate(source.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                segments.append((stripped[1:], line_no, "comment"))

        for match in re.finditer(r'"""(.*?)"""|\'\'\'(.*?)\'\'\'', source, re.S):
            text = match.group(1) or match.group(2) or ""
            if len(text) >= 15:
                line_no = source[: match.start()].count("\n") + 1
                segments.append((text, line_no, "string"))

        for match in re.finditer(r'"([^"\\"\n]{15,})"', source):
            line_no = source[: match.start()].count("\n") + 1
            segments.append((match.group(1), line_no, "string"))

    elif ext in (".md", ".rst", ".txt"):
        fenced_lines = _matched_fenced_block_lines(source)

        for match in _FRONT_MATTER_RE.finditer(source):
            start_line = 1
            end_line = source[: match.end()].count("\n") + 1
            fenced_lines.update(range(start_line, end_line + 1))

        html_comment_lines: set[int] = set()
        for match in _HTML_COMMENT_RE.finditer(source):
            text = match.group(1).strip()
            if text:
                start_line = source[: match.start()].count("\n") + 1
                end_line = source[: match.end()].count("\n") + 1
                if start_line not in fenced_lines:
                    html_comment_lines.update(range(start_line, end_line + 1))
                    segments.append((text, start_line, "html_comment"))

        for line_no, line in enumerate(source.splitlines(), 1):
            if line_no in fenced_lines:
                continue
            if line_no in html_comment_lines:
                continue
            if line.strip():
                segments.append((line, line_no, "prose"))

    elif ext in (".yaml", ".yml", ".json", ".toml"):
        segments.extend(_config_segments(source, ext, keep_comments=keep_comments))

    elif ext == ".env" or filepath.name.startswith(".env"):
        for line_no, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                if "=" in stripped:
                    value = stripped.split("=", 1)[1].strip().strip("'\"")
                    if len(value) >= 15:
                        segments.append((value, line_no, "env_value"))

    return segments


def _markdown_fence_marker(line: str) -> tuple[str, int, str] | None:
    stripped = line.lstrip(" \t")
    if not stripped or stripped[0] not in ("`", "~"):
        return None

    marker = stripped[0]
    marker_len = 0
    for char in stripped:
        if char != marker:
            break
        marker_len += 1

    if marker_len < 3:
        return None

    return marker, marker_len, stripped[marker_len:]


def _matched_fenced_block_lines(source: str) -> set[int]:
    fenced_lines: set[int] = set()
    open_marker: tuple[str, int] | None = None
    open_line = 0

    for line_no, line in enumerate(source.splitlines(), 1):
        marker = _markdown_fence_marker(line)
        if marker is None:
            continue

        marker_char, marker_len, rest = marker
        if open_marker is None:
            open_marker = (marker_char, marker_len)
            open_line = line_no
            continue

        open_char, open_len = open_marker
        if (
            marker_char == open_char
            and marker_len >= open_len
            and not rest.strip(" \t")
        ):
            fenced_lines.update(range(open_line, line_no + 1))
            open_marker = None
            open_line = 0

    return fenced_lines


def _add_path_homoglyph_findings(
    findings: list[dict], filepath: Path, scan_path: str | Path
) -> None:
    path_text = Path(scan_path).as_posix()
    is_agent_instruction = is_agent_instruction_path(scan_path)
    for char, ascii_like, _line_no in detect_homoglyphs(path_text):
        char_hex = f"U+{ord(char):04X}"
        findings.append(
            _make_finding(
                filepath,
                1,
                "mixed_script_path",
                agent_severity("MEDIUM", is_agent_instruction),
                char_hex,
                f"{char}→{ascii_like}",
                f"Non-ASCII character '{char}' (U+{ord(char):04X}) in path "
                f"'{path_text}' visually resembles ASCII '{ascii_like}'. "
                f"Mixed-script paths can hide lookalike modules from human reviewers.",
                rule_id=agent_rule_id(is_agent_instruction, RULE_ID),
            )
        )
        return


def _add_source_homoglyph_findings(
    findings: list[dict],
    filepath: Path,
    source: str,
    is_agent_instruction: bool,
) -> None:
    seen_lines: set[int] = set()
    for char, ascii_like, line_no in detect_homoglyphs(source):
        if len(findings) >= MAX_FINDINGS_PER_FILE:
            return
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        char_hex = f"U+{ord(char):04X}"
        findings.append(
            _make_finding(
                filepath,
                line_no,
                "mixed_script",
                agent_severity("MEDIUM", is_agent_instruction),
                char_hex,
                f"{char}→{ascii_like}",
                f"Non-ASCII character '{char}' (U+{ord(char):04X}) visually resembles "
                f"ASCII '{ascii_like}'. Mixed-script text can hide instructions "
                f"from human reviewers while remaining readable to AI agents.",
                rule_id=agent_rule_id(is_agent_instruction, RULE_ID),
            )
        )


def _adjust_severity(
    base_severity: str,
    segment_type: str,
    is_high_risk_file: bool,
) -> str:
    levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx = levels.index(base_severity)

    if is_high_risk_file and idx < len(levels) - 1:
        idx += 1
    if segment_type == "html_comment" and idx < len(levels) - 1:
        idx += 1

    return levels[idx]


def _make_finding(
    filepath: Path,
    line_no: int,
    finding_type: str,
    severity: str,
    name: str,
    simple_name: str,
    message: str,
    *,
    rule_id: str = RULE_ID,
) -> dict:
    return {
        "rule_id": rule_id,
        "kind": "security",
        "severity": severity,
        "type": finding_type,
        "name": name,
        "simple_name": simple_name,
        "value": finding_type,
        "threshold": 0,
        "message": message,
        "file": str(filepath),
        "basename": filepath.name,
        "line": line_no,
        "col": 0,
    }


def is_scannable_path(filepath: str | Path, scan_path: str | Path | None = None) -> bool:
    if scan_path is not None:
        path = Path(scan_path)
    else:
        path = Path(filepath)
    if Path(filepath).suffix.lower() in SCANNABLE_EXTENSIONS:
        return True
    return is_agent_instruction_path(path)
