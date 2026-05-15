from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from skylos.audit.redaction import sanitize_for_audit
from skylos.audit.types import (
    AuditCandidate,
    code_region_hash,
    language_for_path,
    normalize_relative_path,
    sha256_text,
)


@dataclass(frozen=True)
class PolyglotSignalRule:
    rule_id: str
    pattern_id: str
    severity: str
    reason: str
    regex: re.Pattern[str]


POLYGLOT_LANGUAGES = {
    "typescript",
    "javascript",
    "go",
    "java",
    "php",
    "rust",
    "dart",
}

_TS_JS_RULES = (
    PolyglotSignalRule(
        rule_id="SKY-D201",
        pattern_id="js-eval",
        severity="high",
        reason="Dynamic JavaScript execution should be reviewed for injection risk.",
        regex=re.compile(r"\b(?:eval|Function)\s*\("),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D212",
        pattern_id="js-child-process",
        severity="high",
        reason="Child process execution should be reviewed for command injection risk.",
        regex=re.compile(
            r"\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\("
        ),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D211",
        pattern_id="js-sql-concat",
        severity="high",
        reason="SQL execution with dynamic string construction needs review.",
        regex=re.compile(
            r"\b(?:query|execute|raw|sql)\s*\([^;\n]*(?:\+|\$\{)",
            re.IGNORECASE,
        ),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D216",
        pattern_id="js-ssrf-client",
        severity="high",
        reason="Outbound HTTP calls with dynamic URLs should be reviewed for SSRF.",
        regex=re.compile(
            r"\b(?:fetch|axios\.(?:get|post|put|request)|http\.get|https\.get)"
            r"\s*\([^;\n]*(?:req\.|request\.|\+|\$\{)",
            re.IGNORECASE,
        ),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D230",
        pattern_id="js-open-redirect",
        severity="medium",
        reason="Redirect sinks should be reviewed for open redirect risk.",
        regex=re.compile(
            r"\b(?:redirect|res\.redirect|NextResponse\.redirect)\s*\([^;\n]*"
            r"(?:req\.|request\.|\+|\$\{)",
            re.IGNORECASE,
        ),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D226",
        pattern_id="js-html-injection",
        severity="high",
        reason="HTML injection sinks should be reviewed for XSS risk.",
        regex=re.compile(
            r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML)\b",
            re.IGNORECASE,
        ),
    ),
)

_GO_RULES = (
    PolyglotSignalRule(
        rule_id="SKY-D212",
        pattern_id="go-exec-command",
        severity="high",
        reason="Process execution should be reviewed for command injection risk.",
        regex=re.compile(r"\bexec\.Command\s*\("),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D211",
        pattern_id="go-sql-dynamic",
        severity="high",
        reason="SQL calls with dynamic construction need review.",
        regex=re.compile(
            r"\.(?:Query|QueryContext|Exec|ExecContext)\s*\([^;\n]*(?:\+|fmt\.Sprintf)"
        ),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D216",
        pattern_id="go-http-client",
        severity="high",
        reason="Outbound HTTP calls with dynamic URLs should be reviewed for SSRF.",
        regex=re.compile(r"\bhttp\.(?:Get|Post|Do)\s*\([^;\n]*(?:r\.|req\.|\+)"),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D215",
        pattern_id="go-file-path",
        severity="medium",
        reason="File access from request-controlled values should be reviewed.",
        regex=re.compile(
            r"\b(?:os\.Open|os\.ReadFile|ioutil\.ReadFile)\s*\([^;\n]*"
            r"(?:r\.|req\.|Query\(|Param\()"
        ),
    ),
)

_JAVA_RULES = (
    PolyglotSignalRule(
        rule_id="SKY-D212",
        pattern_id="java-process",
        severity="high",
        reason="Runtime or ProcessBuilder execution needs command injection review.",
        regex=re.compile(
            r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\("
        ),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D211",
        pattern_id="java-sql-dynamic",
        severity="high",
        reason="SQL execution with dynamic construction needs review.",
        regex=re.compile(
            r"\b(?:executeQuery|executeUpdate|execute|query)\s*\([^;\n]*(?:\+|request\.)",
            re.IGNORECASE,
        ),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D204",
        pattern_id="java-deserialize",
        severity="high",
        reason="Java deserialization sinks should be reviewed for unsafe input.",
        regex=re.compile(r"\b(?:ObjectInputStream|readObject)\b"),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D230",
        pattern_id="java-redirect",
        severity="medium",
        reason="Servlet redirects should be reviewed for open redirect risk.",
        regex=re.compile(r"\bsendRedirect\s*\([^;\n]*(?:request\.|\+)"),
    ),
)

_PHP_RULES = (
    PolyglotSignalRule(
        rule_id="SKY-D212",
        pattern_id="php-command",
        severity="high",
        reason="Command execution should be reviewed for injection risk.",
        regex=re.compile(r"\b(?:shell_exec|exec|system|passthru|proc_open)\s*\("),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D211",
        pattern_id="php-sql-dynamic",
        severity="high",
        reason="SQL execution with request-controlled data needs review.",
        regex=re.compile(
            r"\b(?:mysqli_query|mysql_query|pg_query|->query)\s*\([^;\n]*"
            r"(?:\$_(?:GET|POST|REQUEST)|\.)",
            re.IGNORECASE,
        ),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D204",
        pattern_id="php-unserialize",
        severity="high",
        reason="unserialize on external data can lead to object injection.",
        regex=re.compile(r"\bunserialize\s*\([^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)"),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D230",
        pattern_id="php-redirect",
        severity="medium",
        reason="Location headers should be reviewed for open redirect risk.",
        regex=re.compile(r"\bheader\s*\(\s*['\"]Location:[^;\n]*(?:\$_|\.)"),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D215",
        pattern_id="php-file-path",
        severity="medium",
        reason="File access from external parameters should be reviewed.",
        regex=re.compile(
            r"\b(?:file_get_contents|fopen|readfile|include|require)\s*\("
            r"[^;\n]*\$_(?:GET|POST|REQUEST)",
            re.IGNORECASE,
        ),
    ),
)

_RUST_RULES = (
    PolyglotSignalRule(
        rule_id="SKY-D212",
        pattern_id="rust-command",
        severity="high",
        reason="Process execution should be reviewed for command injection risk.",
        regex=re.compile(r"\bCommand::new\s*\("),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D211",
        pattern_id="rust-sql-dynamic",
        severity="high",
        reason="SQL query construction with format or interpolation needs review.",
        regex=re.compile(r"\b(?:sqlx::query|query)\s*\(\s*(?:format!|&format!)"),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D216",
        pattern_id="rust-http-client",
        severity="high",
        reason="Outbound HTTP calls with dynamic URLs should be reviewed for SSRF.",
        regex=re.compile(r"\breqwest::(?:get|Client::new)\s*\([^;\n]*(?:url|format!)"),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D215",
        pattern_id="rust-file-path",
        severity="medium",
        reason="File access with dynamic paths should be reviewed.",
        regex=re.compile(
            r"\bfs::(?:read|read_to_string|File::open)\s*\([^;\n]*(?:path|req|param)"
        ),
    ),
)

_DART_RULES = (
    PolyglotSignalRule(
        rule_id="SKY-D212",
        pattern_id="dart-process",
        severity="high",
        reason="Process execution should be reviewed for command injection risk.",
        regex=re.compile(r"\bProcess\.(?:run|start)\s*\("),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D216",
        pattern_id="dart-http-client",
        severity="high",
        reason="Outbound HTTP calls with dynamic URLs should be reviewed for SSRF.",
        regex=re.compile(
            r"\bhttp\.(?:get|post|put|delete)\s*\([^;\n]*(?:Uri\.parse|url)"
        ),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D230",
        pattern_id="dart-redirect",
        severity="medium",
        reason="Redirect sinks should be reviewed for open redirect risk.",
        regex=re.compile(r"\bredirect\s*\([^;\n]*(?:request|query|url)", re.IGNORECASE),
    ),
    PolyglotSignalRule(
        rule_id="SKY-D215",
        pattern_id="dart-file-path",
        severity="medium",
        reason="File access with dynamic paths should be reviewed.",
        regex=re.compile(r"\bFile\s*\([^;\n]*(?:path|request|query|param)"),
    ),
)

_RULES_BY_LANGUAGE = {
    "typescript": _TS_JS_RULES,
    "javascript": _TS_JS_RULES,
    "go": _GO_RULES,
    "java": _JAVA_RULES,
    "php": _PHP_RULES,
    "rust": _RUST_RULES,
    "dart": _DART_RULES,
}

_SEVERITY_PRIORITY = {
    "critical": 1000,
    "high": 800,
    "medium": 500,
    "low": 200,
    "info": 100,
}


def build_polyglot_signal_candidates(
    file_path: str | Path,
    *,
    project_root: str | Path,
) -> list[AuditCandidate]:
    language = language_for_path(file_path)
    rules = _RULES_BY_LANGUAGE.get(language)
    if not rules:
        return []

    try:
        path = _resolve_polyglot_source_path(file_path, project_root=project_root)
        source = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, ValueError):
        return []

    rel_path = normalize_relative_path(project_root, path)
    candidates: list[AuditCandidate] = []
    seen: set[tuple[str, int, str]] = set()
    for line_no, line in enumerate(source.splitlines(), start=1):
        for rule in rules:
            if not rule.regex.search(line):
                continue
            key = (rule.rule_id, line_no, rule.pattern_id)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                AuditCandidate(
                    candidate_id=_candidate_id(
                        rel_path=rel_path,
                        language=language,
                        rule=rule,
                        line=line_no,
                        source=source,
                    ),
                    kind="polyglot_static_signal",
                    rule_id=rule.rule_id,
                    line=line_no,
                    severity_hint=rule.severity,
                    reason=rule.reason,
                    evidence="static",
                    redacted=False,
                    priority=_SEVERITY_PRIORITY.get(rule.severity, 400),
                    code_hash=code_region_hash(source, line_no),
                    data=sanitize_for_audit(
                        {
                            "language": language,
                            "pattern_id": rule.pattern_id,
                            "phase": "deep-mode-phase7",
                        }
                    ),
                )
            )
    return candidates


def _resolve_polyglot_source_path(
    file_path: str | Path,
    *,
    project_root: str | Path,
) -> Path:
    root = Path(project_root).resolve()
    rel_path = normalize_relative_path(root, file_path)
    candidate = (root / rel_path).resolve()
    candidate.relative_to(root)
    return candidate


def _candidate_id(
    *,
    rel_path: str,
    language: str,
    rule: PolyglotSignalRule,
    line: int,
    source: str,
) -> str:
    payload = "|".join(
        [
            rel_path,
            language,
            rule.rule_id,
            rule.pattern_id,
            str(line),
            code_region_hash(source, line),
        ]
    )
    return "cand-poly-" + sha256_text(payload)[:16]
