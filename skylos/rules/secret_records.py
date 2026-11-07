"""Source coordinates and safe evidence for structured secret records.

Credential validators own the format checks. This adapter keeps raw values out
of returned records and maps their exact component spans to physical lines.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass

from skylos.rules.secret_credentials import scan_credential_records
from skylos.rules.secret_key_material import scan_private_jwk_objects
from skylos.rules.secret_record_redaction import record_redaction_spans


@dataclass(frozen=True, slots=True)
class SecretRecord:
    provider: str
    start: int
    end: int
    evidence: dict
    related_spans: tuple = ()


@dataclass(frozen=True, slots=True)
class SecretRecordScan:
    matches: tuple[SecretRecord, ...]
    issues: tuple[str, ...]


def scan_secret_records(text: str, *, file_kind: str = "") -> SecretRecordScan:
    credentials = scan_credential_records(text, file_kind=file_kind)
    keys = scan_private_jwk_objects(text)
    matches = []
    issues = set((*credentials.issues, *keys.issues))
    seen = set()
    for match in (*credentials.matches, *keys.matches):
        if not 0 <= match.start < match.end <= len(text):
            issues.add("secret_record_invalid_source_span")
            continue
        identity = (match.provider, match.start, match.end)
        if identity in seen:
            continue
        seen.add(identity)
        matches.append(
            SecretRecord(
                match.provider,
                match.start,
                match.end,
                match.evidence,
                getattr(match, "related_spans", ()),
            )
        )
    return SecretRecordScan(tuple(matches), tuple(sorted(issues)))


def source_text_and_starts(lines) -> tuple[str, tuple[int, ...]]:
    """Also accept caller contexts whose physical lines omit their newlines."""
    chunks = []
    starts = []
    position = 0
    for index, line in enumerate(lines):
        starts.append(position)
        chunk = line
        if index + 1 < len(lines) and not line.endswith("\n"):
            chunk += "\n"
        chunks.append(chunk)
        position += len(chunk)
    return "".join(chunks), tuple(starts)


def source_location(starts, offset: int) -> tuple[int, int]:
    number = bisect_right(starts, offset)
    return number, offset - starts[number - 1]


def component_locations(match, starts) -> list[dict]:
    """Show pairing evidence without account identifiers or credential bytes."""
    result = []
    for component in match.related_spans:
        line, col = source_location(starts, component.start)
        end_line, end_col = source_location(starts, component.end - 1)
        result.append(
            {
                "role": component.role,
                "line": line,
                "col": col,
                "end_line": end_line,
                "end_col": end_col + 1,
            }
        )
    return result


def redact_secret_records(text: str, replacement: str) -> str:
    """Mask exact private components while leaving public key fields readable."""
    spans = record_redaction_spans(text, scan_secret_records)
    if not spans:
        return text
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    chunks = []
    previous = 0
    for start, end in merged:
        chunks.extend((text[previous:start], replacement))
        previous = end
    chunks.append(text[previous:])
    return "".join(chunks)
