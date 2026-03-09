from __future__ import annotations

import re
from pathlib import Path

from skylos.canonicalize import (
    decode_base64_blobs,
    detect_homoglyphs,
    normalize,
    strip_zero_width,
)
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS

RULE_ID = "SKY-D260"

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
            r"(env\b|environment|secrets?|api.?keys?|tokens?|credentials?|passwords?)",
            re.I,
        ),
        "HIGH",
    ),
    (re.compile(r"send\s+(all\s+)?(data|content|file|code)\s+to\b", re.I), "HIGH"),
]

_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_FENCED_BLOCK_RE = re.compile(
    r"^[ \t]*(`{3,}|~{3,}).*?\n.*?^[ \t]*\1[ \t]*$", re.M | re.S
)
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


def scan_file(filepath: str | Path) -> list[dict]:
    filepath = Path(filepath)
    if not filepath.is_file():
        return []

    ext = filepath.suffix.lower()
    if ext not in SCANNABLE_EXTENSIONS:
        return []

    basename = filepath.name
    if any(basename.startswith(p) for p in _SKIP_PREFIXES):
        return []

    try:
        source = filepath.read_text(errors="replace")
    except OSError:
        return []

    if not source.strip():
        return []

    findings: list[dict] = []

    _, zero_width_hits = strip_zero_width(source)
    for char_hex, line_no in zero_width_hits:
        findings.append(
            _make_finding(
                filepath,
                line_no,
                "hidden_char",
                "HIGH",
                char_hex,
                char_hex,
                f"Invisible Unicode character {char_hex} found. "
                f"Zero-width characters in source code can hide "
                f"prompt injection payloads from human reviewers.",
            )
        )

    homoglyphs = detect_homoglyphs(source)
    if homoglyphs:
        seen_lines: set[int] = set()
        for char, ascii_like, line_no in homoglyphs:
            if line_no in seen_lines:
                continue
            seen_lines.add(line_no)
            char_hex = f"U+{ord(char):04X}"
            findings.append(
                _make_finding(
                    filepath,
                    line_no,
                    "mixed_script",
                    "MEDIUM",
                    char_hex,
                    f"{char}→{ascii_like}",
                    f"Non-ASCII character '{char}' (U+{ord(char):04X}) visually resembles "
                    f"ASCII '{ascii_like}'. Mixed-script text can hide instructions "
                    f"from human reviewers while remaining readable to AI agents.",
                )
            )

    segments = _extract_segments(source, ext, filepath)

    is_high_risk_file = basename.lower() in _HIGH_RISK_FILENAMES
    seen_findings: set[tuple[int, str]] = set()

    for text, line_no, segment_type in segments:
        normalized = normalize(text)

        for pattern, base_severity in _PATTERNS:
            if pattern.search(normalized):
                severity = _adjust_severity(
                    base_severity, segment_type, is_high_risk_file
                )

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
                    )
                )
                break

    decoded_blobs = decode_base64_blobs(source)
    for decoded_text, line_no in decoded_blobs:
        normalized = normalize(decoded_text)
        for pattern, base_severity in _PATTERNS:
            if pattern.search(normalized):
                snippet = decoded_text.strip()[:80]
                findings.append(
                    _make_finding(
                        filepath,
                        line_no,
                        "obfuscated_payload",
                        "HIGH",
                        "prompt_injection",
                        "base64",
                        f"Base64-encoded string decodes to prompt injection: '{snippet}'. "
                        f"Encoded payloads bypass human review while remaining effective "
                        f"against AI agents.",
                    )
                )
                break

    return findings


def scan_directory(
    root: str | Path, exclude_dirs: set[str] | None = None
) -> list[dict]:
    root = Path(root)
    all_excludes = _DEFAULT_EXCLUDE_DIRS | (exclude_dirs or set())
    findings: list[dict] = []

    for filepath in root.rglob("*"):
        if not filepath.is_file():
            continue
        if filepath.suffix.lower() not in SCANNABLE_EXTENSIONS:
            continue

        rel = filepath.relative_to(root)
        parts = rel.parts
        if any(p in all_excludes or p.startswith(".") for p in parts[:-1]):
            continue

        findings.extend(scan_file(filepath))

    return findings


def _extract_segments(
    source: str, ext: str, filepath: Path
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
        fenced_lines: set[int] = set()

        for match in _FRONT_MATTER_RE.finditer(source):
            start_line = 1
            end_line = source[: match.end()].count("\n") + 1
            fenced_lines.update(range(start_line, end_line + 1))

        for match in _FENCED_BLOCK_RE.finditer(source):
            start_line = source[: match.start()].count("\n") + 1
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
        for line_no, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            segment_type = "config"
            if _PROMPT_KEYS_RE.search(line):
                segment_type = "prompt_field"

            segments.append((stripped, line_no, segment_type))

    elif ext == ".env" or filepath.name.startswith(".env"):
        for line_no, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                if "=" in stripped:
                    value = stripped.split("=", 1)[1].strip().strip("'\"")
                    if len(value) >= 15:
                        segments.append((value, line_no, "env_value"))

    return segments


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
) -> dict:
    return {
        "rule_id": RULE_ID,
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
