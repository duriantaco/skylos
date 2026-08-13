from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
import math
import re
from typing import Any, Literal
import unicodedata

from skylos.core.evidence_contract import (
    STRUCTURED_SECURITY_FLOW_RULES as _STRUCTURED_SECURITY_FLOW_RULES,
    structured_security_evidence_is_complete,
)
from skylos.rules.secrets import (
    DEFAULT_MIN_ENTROPY,
    GENERIC_KEYED_VALUE,
    PROVIDER_PATTERNS,
    _SECRET_KEY_NAME_RE,
    _entropy as _secret_entropy,
)

EvidenceLabel = Literal["proven", "likely", "speculative"]
EvidenceKind = Literal[
    "security",
    "security_regression",
    "reliability",
    "secret",
    "quality",
    "dependency",
    "custom",
]


@dataclass(frozen=True)
class EvidenceCard:
    label: EvidenceLabel
    kind: EvidenceKind
    confidence: int
    title: str
    rule_id: str
    file: str
    line: int
    symbol: str | None = None
    evidence: tuple[str, ...] = ()
    impact: str = ""
    suggested_fix: str | None = None
    gate_blocking: bool = False


_SECRET_PATTERNS = tuple(pattern for _, pattern in PROVIDER_PATTERNS) + (
    re.compile(r"\bsk_(?:live|test|proj)_[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(
        r"(?i)AWS_SECRET_ACCESS_KEY\s*[:=]\s*['\"]?"
        r"[A-Za-z0-9/+=]{40,}"
    ),
)

_CONTEXTUAL_SECRET_KEY_RE = re.compile(rf"^(?:{_SECRET_KEY_NAME_RE})$")
_CONTEXTUAL_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?<![A-Za-z0-9_-])(?P<key_quote>['\"]?)"
    rf"(?P<key>{_SECRET_KEY_NAME_RE})(?P=key_quote)"
    r"(?![A-Za-z0-9_-])(?P<separator>[ \t]*[:=][ \t]*)"
    r"(?P<value>[^\n]*)"
)
_ASSIGNMENT_LINE_RE = re.compile(
    r"^(?:['\"]?[A-Za-z_$][A-Za-z0-9_$.-]*['\"]?)[ \t]*[:=]"
)
_YAML_BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?[1-9]?[ \t]*(?:#.*)?$")
_MARKDOWN_URI_SCHEME_RE = re.compile(r"(?i)\b(?P<scheme>https?|ftp|mailto|data):")
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9][A-Z0-9 -]{0,63})-----"
    r"[\s\S]{0,16000}?"
    r"-----END (?P=label)-----"
)
_PEM_REMAINDER_RE = re.compile(
    r"-----BEGIN [A-Z0-9][A-Z0-9 -]{0,63}-----[\s\S]{0,16000}"
)

_DEFAULT_UNTRUSTED_TEXT_LENGTH = 4_096
_MAX_REDACTION_SCAN_LENGTH = 16_384
_MAX_CONTEXTUAL_CONTINUATION_LINES = 8
_REDACTED_SENTINEL = "\x00SKYLOS_REDACTED\x00"
_PEM_REDACTED_SENTINEL = "\x00SKYLOS_PEM_REDACTED\x00"
_MARKDOWN_LINE_PREFIX_RE = re.compile(r"(?m)^(?P<space>[ \t]{0,3})(?P<mark>[#>|])")

_RULE_SUGGESTIONS: dict[str, str] = {
    "SKY-D201": "Replace dynamic evaluation with a safe parser for the expected input format.",
    "SKY-D203": "Use subprocess with an argument list and shell disabled.",
    "SKY-D211": "Use parameterized queries instead of building SQL with string interpolation.",
    "SKY-D212": "Validate or escape command input, or pass arguments without a shell.",
    "SKY-D215": "Resolve paths under an allowed directory before opening filesystem paths.",
    "SKY-D216": "Validate outbound URLs against an allowlist and block internal network targets.",
    "SKY-D223": "Declare the dependency in project metadata or remove the import.",
    "SKY-D290": "Use pull_request when you do not need a privileged token, or isolate untrusted checkout code.",
    "SKY-D291": "Set top-level permissions: {} and grant only required permissions per job.",
    "SKY-D292": "Pin third-party actions and reusable workflows to full commit SHAs.",
    "SKY-D293": "Set actions/checkout persist-credentials: false unless later git pushes need it.",
    "SKY-D294": "Move GitHub context values into env and reference the quoted environment variable in run blocks.",
    "SKY-D295": "Use GitHub-hosted runners or ephemeral isolated self-hosted runners for untrusted workflows.",
    "SKY-D296": "Pin container images by digest instead of mutable tags like latest.",
    "SKY-D297": "Pass only specific secrets to reusable workflows instead of secrets: inherit.",
    "SKY-D298": "Reference only the specific secret needed; avoid toJSON(secrets) and dynamic secret indexing.",
    "SKY-D299": "Move secret-dependent jobs into a dedicated GitHub environment.",
    "SKY-D300": "Only write static key/value pairs to GITHUB_ENV or GITHUB_PATH.",
    "SKY-D301": "Move container registry passwords to secrets and reference them with secrets.NAME.",
    "SKY-D302": "Scope GitHub App tokens to repositories and explicit permission-* inputs.",
    "SKY-D303": "Replace string contains checks with exact equality checks or fromJSON array membership.",
    "SKY-D304": "Use event-specific sender IDs instead of spoofable actor-name checks.",
    "SKY-D305": "Use an unfenced expression or stripped block scalar for multiline if conditions.",
    "SKY-D306": "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS from workflow, job, or step env.",
    "SKY-D307": "Add a name field to the workflow or action definition.",
    "SKY-D308": "Avoid cache-aware actions in release workflows, or disable cache restore/save for publishing jobs.",
    "SKY-D309": "Move secret environment variables from workflow/job env into only the step that needs them.",
    "SKY-D310": "Split OIDC token issuance into a minimal publish job after build artifacts are produced.",
    "SKY-D311": "Set actions/upload-artifact if-no-files-found: error for required build outputs.",
    "SKY-D312": "Use npm ci --ignore-scripts or equivalent unless lifecycle scripts are required.",
    "SKY-D313": "Add timeout-minutes to privileged or release-like jobs.",
    "SKY-D314": "Pin GitLab CI image and service references by digest, especially Docker-in-Docker images.",
    "SKY-D315": "Pin project includes to full commit SHAs and add integrity checksums to remote includes.",
    "SKY-D316": "Move secret-looking GitLab CI variables into protected and masked CI/CD variables.",
    "SKY-D317": "Avoid passing merge request or ref metadata into eval, sh -c, bash -c, or interpreter -c/-e sinks.",
    "SKY-D318": "Use TLS-enabled Docker-in-Docker or avoid privileged Docker socket access.",
    "SKY-D319": "Issue GitLab OIDC tokens only in small publish jobs that consume prebuilt artifacts.",
    "SKY-D320": "Disable cache restore in release/deploy jobs or isolate release caches from untrusted jobs.",
    "SKY-D321": "Set timeout on GitLab CI release, deploy, or OIDC jobs.",
    "SKY-D322": "Use static GitLab runner tags for privileged jobs.",
    "SKY-D323": "Set an explicit token for each GitLab CI secret when multiple id_tokens are defined.",
    "SKY-D327": "Do not send environment dumps, token command output, or `.env*`/credential files to external destinations.",
    "SKY-D328": "Download remote scripts to a file, inspect or verify them, then execute a pinned local copy only if trusted.",
    "SKY-D329": "Narrow destructive commands to explicit workspace paths and require human confirmation for broad deletes or resets.",
    "SKY-D330": "Remove privileged mode and grant only specific device or capability access.",
    "SKY-D331": "Replace broad host device or control mounts with specific read-only device mappings.",
    "SKY-D332": "Avoid host networking for edge services; bind only required ports.",
    "SKY-D333": "Run the systemd unit as a dedicated non-root user.",
    "SKY-D334": "Move the executable to a root-owned path and lock down permissions.",
    "SKY-D335": "Add systemd sandboxing controls such as NoNewPrivileges, ProtectSystem, and PrivateTmp.",
    "SKY-D336": "Reduce broad systemd capabilities, device rules, or privileged container access.",
    "SKY-D337": "Use the default trusted package registry, or pin and document the approved internal registry.",
    "SKY-D338": "Do not read host credential stores or mount the host root filesystem into agent or CI commands.",
    "SKY-D339": "Avoid persistent profile, scheduler, global git, or package-manager configuration changes in agent or CI tasks.",
    "SKY-D340": "Move publish commands into an explicit release workflow with protected approvals.",
    "SKY-D341": "Pin package-managed tools and avoid auto-install execution flags such as `npx -y`.",
    "SKY-D280": "Authenticate mutating API routes before performing protected actions.",
    "SKY-D281": "Use parameterized queries instead of building SQL with string interpolation.",
    "SKY-D282": "Use a webhook library or HMAC comparison that verifies the provider signature.",
    "SKY-S101": "Move the secret to environment variables or a secrets manager, then rotate it.",
    "SKY-S102": "Move the secret to server-only code and rotate it; expose only non-sensitive values through public client configuration.",
}

_REGRESSION_SUGGESTIONS: dict[str, str] = {
    "auth": "Re-add the authentication check before the protected handler runs.",
    "csrf": "Re-enable CSRF protection for the affected request path.",
    "tls": "Keep TLS certificate verification enabled.",
    "crypto": "Use a modern cryptographic primitive or hash algorithm.",
    "rate_limit": "Re-add rate limiting around the affected endpoint or action.",
    "validation": "Restore input validation before the value reaches the risky sink.",
    "headers": "Restore the security header or middleware.",
    "encryption": "Restore encryption before sensitive data is stored or transmitted.",
    "logging": "Restore audit logging for the security-relevant action.",
    "sanitization": "Restore output sanitization before rendering user-controlled content.",
    "permission": "Re-add the permission check before the protected action runs.",
}

_SEVERITY_CONFIDENCE = {
    "proven": {"CRITICAL": 96, "HIGH": 92, "MEDIUM": 84, "LOW": 76},
    "likely": {"CRITICAL": 86, "HIGH": 80, "MEDIUM": 72, "LOW": 64},
    "speculative": {"CRITICAL": 58, "HIGH": 55, "MEDIUM": 50, "LOW": 45},
}

_MAX_STRUCTURED_EVIDENCE_ITEMS = 3


def _redact_contextual_secret_match(match: re.Match[str]) -> str:
    value = match.group("val")
    if not _is_high_entropy_secret_value(value):
        return match.group(0)
    relative_start = match.start("val") - match.start()
    relative_end = match.end("val") - match.start()
    matched_text = match.group(0)
    return (
        f"{matched_text[:relative_start]}{_REDACTED_SENTINEL}"
        f"{matched_text[relative_end:]}"
    )


def _is_contextual_secret_value(key: object, value: str) -> bool:
    return bool(
        isinstance(key, str)
        and _CONTEXTUAL_SECRET_KEY_RE.fullmatch(key.strip())
        and _is_high_entropy_secret_value(value)
    )


def _is_high_entropy_secret_value(value: str) -> bool:
    candidate = value.strip()
    return len(candidate) >= 20 and _secret_entropy(candidate) >= DEFAULT_MIN_ENTROPY


def _redact_contextual_secrets(text: str) -> str:
    """Redact secret-key assignments, including wrapped and YAML values."""
    lines = text.splitlines(keepends=True)
    rendered: list[str] = []
    index = 0

    while index < len(lines):
        content, ending = _split_line_ending(lines[index])
        match = _CONTEXTUAL_SECRET_ASSIGNMENT_RE.search(content)
        if match is None:
            rendered.append(lines[index])
            index += 1
            continue

        raw_value = match.group("value")
        if _YAML_BLOCK_SCALAR_RE.fullmatch(raw_value.strip()):
            block_end, candidate = _yaml_secret_block(lines, index, match.start())
            if block_end > index + 1 and _is_high_entropy_secret_value(candidate):
                rendered.append(
                    f"{content[: match.start('value')]}{_REDACTED_SENTINEL}{ending}"
                )
                rendered.extend(
                    _line_ending(lines[block_index])
                    for block_index in range(index + 1, block_end)
                )
                index = block_end
                continue

        token = _contextual_value_token(raw_value)
        if token is None:
            rendered.append(lines[index])
            index += 1
            continue

        token_start, token_end, candidate, closed_quote = token
        continuation_indexes: list[int] = []
        continuation_values: list[str] = []
        if not closed_quote:
            for continuation_index in range(
                index + 1,
                min(
                    len(lines),
                    index + 1 + _MAX_CONTEXTUAL_CONTINUATION_LINES,
                ),
            ):
                continuation = _contextual_continuation_token(lines[continuation_index])
                if continuation is None:
                    break
                continuation_indexes.append(continuation_index)
                continuation_values.append(continuation)

        combined_candidate = "".join([candidate, *continuation_values])
        if not _is_high_entropy_secret_value(combined_candidate):
            rendered.append(lines[index])
            index += 1
            continue

        absolute_start = match.start("value") + token_start
        absolute_end = match.start("value") + token_end
        rendered.append(
            f"{content[:absolute_start]}{_REDACTED_SENTINEL}"
            f"{content[absolute_end:]}{ending}"
        )
        if continuation_indexes:
            rendered.extend(_line_ending(lines[item]) for item in continuation_indexes)
            index = continuation_indexes[-1] + 1
        else:
            index += 1

    return "".join(rendered)


def _yaml_secret_block(
    lines: list[str],
    start_index: int,
    assignment_column: int,
) -> tuple[int, str]:
    values: list[str] = []
    block_end = start_index + 1
    minimum_indent = assignment_column + 1

    while block_end < len(lines):
        content, _ = _split_line_ending(lines[block_end])
        if not content.strip():
            block_end += 1
            continue
        indentation = len(content) - len(content.lstrip(" \t"))
        if indentation < minimum_indent:
            break
        values.append(content.strip())
        block_end += 1

    return block_end, "".join(values)


def _contextual_value_token(value: str) -> tuple[int, int, str, bool] | None:
    leading = len(value) - len(value.lstrip(" \t"))
    remaining = value[leading:]
    if not remaining:
        return None

    quote = remaining[0] if remaining[0] in {"'", '"'} else ""
    if quote:
        closing = remaining.find(quote, 1)
        if closing >= 0:
            candidate = remaining[1:closing]
            return leading, leading + closing + 1, candidate, True
        candidate = remaining[1:]
        return leading, len(value), candidate, False

    token_end = next(
        (offset for offset, character in enumerate(remaining) if character.isspace()),
        len(remaining),
    )
    candidate = remaining[:token_end]
    if not candidate:
        return None
    return leading, leading + token_end, candidate, False


def _contextual_continuation_token(line: str) -> str | None:
    content, _ = _split_line_ending(line)
    stripped = content.strip()
    if (
        len(stripped) < 4
        or len(stripped) > 1_024
        or any(character.isspace() for character in stripped)
        or _ASSIGNMENT_LINE_RE.search(stripped)
        or not any(character.isalnum() for character in stripped)
    ):
        return None
    return stripped.strip("'\"")


def _split_line_ending(line: str) -> tuple[str, str]:
    if line.endswith("\n"):
        return line[:-1], "\n"
    return line, ""


def _line_ending(line: str) -> str:
    return "\n" if line.endswith("\n") else ""


def build_evidence_cards(findings: list[dict[str, Any]]) -> list[EvidenceCard]:
    return [build_evidence_card(finding) for finding in findings]


def build_evidence_card(finding: dict[str, Any]) -> EvidenceCard:
    kind = _evidence_kind(finding)
    label = _evidence_label(finding, kind)
    rule_id = str(finding.get("rule_id") or "")
    severity = str(finding.get("severity") or "MEDIUM").upper()
    control_type = str(finding.get("control_type") or "")

    return EvidenceCard(
        label=label,
        kind=kind,
        confidence=_confidence(label, severity, finding),
        title=_title(finding, kind),
        rule_id=rule_id,
        file=str(finding.get("file") or ""),
        line=_line_number(finding.get("line")),
        symbol=_optional_text(finding.get("symbol")),
        evidence=_evidence_lines(finding, kind, label),
        impact=_impact(kind, control_type, rule_id),
        suggested_fix=_suggested_fix(finding, kind, rule_id, control_type),
        gate_blocking=severity in {"CRITICAL", "HIGH"},
    )


def evidence_counts(cards: list[EvidenceCard]) -> dict[EvidenceLabel, int]:
    counts: dict[EvidenceLabel, int] = {
        "proven": 0,
        "likely": 0,
        "speculative": 0,
    }
    for card in cards:
        counts[card.label] += 1
    return counts


def evidence_label_title(label: EvidenceLabel) -> str:
    return {
        "proven": "Proven",
        "likely": "Likely",
        "speculative": "Speculative",
    }[label]


def sanitize_untrusted_text(
    value: Any,
    *,
    max_length: int = _DEFAULT_UNTRUSTED_TEXT_LENGTH,
    markdown: bool = False,
    preserve_newlines: bool = False,
    neutralize_mentions: bool = True,
) -> str:
    """Bound and neutralize attacker-controlled text before CI serialization."""
    max_length = max(0, int(max_length))
    if max_length == 0:
        return ""

    text = "" if value is None else str(value)
    scan_length = min(
        _MAX_REDACTION_SCAN_LENGTH,
        max(max_length + 512, max_length * 2),
    )
    text = text[:scan_length]
    text = _remove_unsafe_unicode_controls(text)
    text = _PEM_BLOCK_RE.sub(_PEM_REDACTED_SENTINEL, text)
    text = _PEM_REMAINDER_RE.sub(_PEM_REDACTED_SENTINEL, text)
    text = GENERIC_KEYED_VALUE.sub(_redact_contextual_secret_match, text)
    text = _redact_contextual_secrets(text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_REDACTED_SENTINEL, text)

    # GitHub mentions are active even when they arrive through otherwise plain
    # evidence. A full-width at-sign stays readable without notifying users.
    if neutralize_mentions:
        text = text.replace("@", "＠")
    if markdown:
        text = _neutralize_markdown(text)
    else:
        text = _restore_redaction_markers(text)
    if not preserve_newlines:
        text = " ".join(text.split())
    return _bounded_text(text, max_length)


def redact_sensitive_text(
    value: Any,
    max_length: int = _DEFAULT_UNTRUSTED_TEXT_LENGTH,
) -> str:
    return sanitize_untrusted_text(
        value,
        max_length=max_length,
        markdown=True,
        preserve_newlines=True,
    )


def sanitize_markdown_text(
    value: Any,
    *,
    max_length: int = _DEFAULT_UNTRUSTED_TEXT_LENGTH,
    preserve_newlines: bool = False,
) -> str:
    return sanitize_untrusted_text(
        value,
        max_length=max_length,
        markdown=True,
        preserve_newlines=preserve_newlines,
    )


def sanitize_bounded_payload(
    value: Any,
    *,
    max_depth: int = 4,
    max_items: int = 32,
    max_text_length: int = 500,
    max_nodes: int = 256,
    markdown: bool = False,
    neutralize_mentions: bool = True,
) -> Any:
    """Recursively copy a JSON-like payload through strict size budgets."""
    budget = [max(1, int(max_nodes))]
    return _sanitize_payload_value(
        value,
        depth=0,
        max_depth=max(0, int(max_depth)),
        max_items=max(1, int(max_items)),
        max_text_length=max(1, int(max_text_length)),
        markdown=markdown,
        neutralize_mentions=neutralize_mentions,
        budget=budget,
    )


_NON_SCALAR_PAYLOAD = object()


def _sanitize_payload_scalar(
    value: Any,
    *,
    contextual_key: object | None,
    max_text_length: int,
    markdown: bool,
    neutralize_mentions: bool,
) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if not isinstance(value, str):
        return _NON_SCALAR_PAYLOAD
    if _is_contextual_secret_value(contextual_key, value):
        return "[redacted]"
    return sanitize_untrusted_text(
        value,
        max_length=max_text_length,
        markdown=markdown,
        preserve_newlines=True,
        neutralize_mentions=neutralize_mentions,
    )


def _sanitize_payload_mapping(
    value: dict,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    max_text_length: int,
    markdown: bool,
    neutralize_mentions: bool,
    budget: list[int],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, raw_value in islice(value.items(), max_items):
        if budget[0] <= 0:
            break
        key = sanitize_untrusted_text(
            raw_key,
            max_length=80,
            markdown=markdown,
            neutralize_mentions=neutralize_mentions,
        )
        if not key:
            continue
        sanitized = _sanitize_payload_value(
            raw_value,
            depth=depth + 1,
            max_depth=max_depth,
            max_items=max_items,
            max_text_length=max_text_length,
            markdown=markdown,
            neutralize_mentions=neutralize_mentions,
            budget=budget,
            contextual_key=raw_key,
        )
        if sanitized is not None or raw_value is None:
            result[key] = sanitized
    return result


def _sanitize_payload_sequence(
    value: list | tuple,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    max_text_length: int,
    markdown: bool,
    neutralize_mentions: bool,
    budget: list[int],
) -> list[Any]:
    result = []
    for item in value[:max_items]:
        if budget[0] <= 0:
            break
        sanitized = _sanitize_payload_value(
            item,
            depth=depth + 1,
            max_depth=max_depth,
            max_items=max_items,
            max_text_length=max_text_length,
            markdown=markdown,
            neutralize_mentions=neutralize_mentions,
            budget=budget,
        )
        if sanitized is not None or item is None:
            result.append(sanitized)
    return result


def _sanitize_payload_value(
    value: Any,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    max_text_length: int,
    markdown: bool,
    neutralize_mentions: bool,
    budget: list[int],
    contextual_key: object | None = None,
) -> Any:
    if budget[0] <= 0:
        return None
    budget[0] -= 1

    scalar = _sanitize_payload_scalar(
        value,
        contextual_key=contextual_key,
        max_text_length=max_text_length,
        markdown=markdown,
        neutralize_mentions=neutralize_mentions,
    )
    if scalar is not _NON_SCALAR_PAYLOAD:
        return scalar
    if depth >= max_depth:
        return None
    if isinstance(value, dict):
        return _sanitize_payload_mapping(
            value,
            depth=depth,
            max_depth=max_depth,
            max_items=max_items,
            max_text_length=max_text_length,
            markdown=markdown,
            neutralize_mentions=neutralize_mentions,
            budget=budget,
        )
    if isinstance(value, (list, tuple)):
        return _sanitize_payload_sequence(
            value,
            depth=depth,
            max_depth=max_depth,
            max_items=max_items,
            max_text_length=max_text_length,
            markdown=markdown,
            neutralize_mentions=neutralize_mentions,
            budget=budget,
        )
    return None


def _remove_unsafe_unicode_controls(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return "".join(
        character
        for character in normalized
        if character in {"\n", "\t"}
        or unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
    )


def _neutralize_markdown(text: str) -> str:
    # Square brackets are Markdown control characters for inline, full,
    # collapsed, and shortcut links/images. Neutralize every occurrence rather
    # than attempting to parse attacker-controlled labels with a flat regex.
    # URI schemes are also broken so a destination left as readable text cannot
    # become a GitHub-flavored Markdown autolink.
    text = text.replace("[", "［").replace("]", "］")
    text = _MARKDOWN_URI_SCHEME_RE.sub(
        lambda match: f"{match.group('scheme')}：",
        text,
    )
    text = text.replace("`", "ˋ")
    text = text.replace("**", "∗∗").replace("__", "＿＿").replace("~~", "～～")
    text = text.replace("<", "＜").replace(">", "＞")
    text = text.replace("|", "￨")
    text = _MARKDOWN_LINE_PREFIX_RE.sub(
        lambda match: (
            match.group("space") + {"#": "＃", ">": "＞", "|": "￨"}[match.group("mark")]
        ),
        text,
    )
    return _restore_redaction_markers(text, markdown=True)


def _restore_redaction_markers(text: str, *, markdown: bool = False) -> str:
    if markdown:
        pem_marker = "［redacted PEM block］"
        marker = "［redacted］"
    else:
        pem_marker = "[redacted PEM block]"
        marker = "[redacted]"
    return text.replace(_PEM_REDACTED_SENTINEL, pem_marker).replace(
        _REDACTED_SENTINEL,
        marker,
    )


def _bounded_text(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    if max_length <= 3:
        return text[:max_length]
    return f"{text[: max_length - 3].rstrip()}..."


def _evidence_kind(finding: dict[str, Any]) -> EvidenceKind:
    category = str(finding.get("category") or "").lower()
    kind = str(finding.get("kind") or "").lower()

    if category == "security_regression" or kind == "security_regression":
        return "security_regression"
    if category in {"secrets", "secret"}:
        return "secret"
    if category in {"danger", "security"}:
        return "security"
    if category == "reliability":
        return "reliability"
    if category in {"dependency", "dependencies"}:
        return "dependency"
    if category == "custom_rules":
        return "custom"
    return "quality"


def _evidence_label(finding: dict[str, Any], kind: EvidenceKind) -> EvidenceLabel:
    if kind in {"security_regression", "secret"}:
        return "proven"

    if _has_incomplete_security_flow_proof(finding, kind):
        return "likely"

    if _verification_verdict(finding) == "VERIFIED":
        return "proven"

    source = str(finding.get("_source") or "").lower()
    security_evidence = _security_evidence(finding)
    if source == "llm" and security_evidence == "hypothesis":
        return "speculative"
    if source == "llm":
        return "likely" if security_evidence == "review_supported" else "speculative"

    rule_id = str(finding.get("rule_id") or "")
    if kind == "security" and rule_id.startswith(("SKY-D", "SKY-S")):
        return "proven"
    if kind == "quality" and rule_id.startswith("SKY-UC"):
        return "proven"

    if security_evidence == "hypothesis":
        return "speculative"

    return "likely"


def _confidence(label: EvidenceLabel, severity: str, finding: dict[str, Any]) -> int:
    explicit = finding.get("confidence")
    if isinstance(explicit, int):
        return max(1, min(99, explicit))
    return _SEVERITY_CONFIDENCE[label].get(
        severity, _SEVERITY_CONFIDENCE[label]["MEDIUM"]
    )


def _title(finding: dict[str, Any], kind: EvidenceKind) -> str:
    if kind == "secret":
        if str(finding.get("rule_id") or "") == "SKY-S102":
            return "Client-side secret exposure detected"
        return "Hardcoded secret detected"
    if kind == "security_regression":
        control_type = str(finding.get("control_type") or "")
        if control_type:
            control_label = control_type.replace("_", " ")
            return f"Security control regression: {control_label}"
        return "Security control regression"

    message = redact_sensitive_text(finding.get("message") or "")
    if not message:
        message = str(finding.get("rule_id") or kind.replace("_", " "))
    return _limit(message, 120)


def _evidence_lines(
    finding: dict[str, Any], kind: EvidenceKind, label: EvidenceLabel
) -> tuple[str, ...]:
    rule_id = str(finding.get("rule_id") or "")
    control_type = str(finding.get("control_type") or "")
    lines: list[str] = []

    if kind == "secret":
        if rule_id == "SKY-S102":
            return (
                "Static client-exposure analysis found secret material or a "
                "server-only environment variable in client-accessible code.",
                "The exposed value is intentionally omitted from PR output.",
            )
        return (
            "Static secret detection matched a credential pattern.",
            "The secret value is intentionally omitted from PR output.",
        )

    if kind == "security_regression":
        return (f"PR diff removed or weakened {_control_phrase(control_type)}.",)

    if _verification_verdict(finding) == "VERIFIED":
        lines.append("Skylos verification marked this finding as verified.")
    elif label == "speculative":
        lines.append("The finding is not backed by verifier-confirmed evidence yet.")
    elif str(finding.get("_source") or "").lower() == "llm":
        lines.append("LLM review supplied supporting evidence, but no verifier proof.")
    elif rule_id:
        prefix = "Configured custom rule" if kind == "custom" else "Static Skylos rule"
        lines.append(f"{prefix} {rule_id} matched this line.")
    else:
        lines.append("Static analysis matched this line.")

    reason = _review_reason(finding)
    if reason:
        lines.append(_limit(redact_sensitive_text(reason), 180))

    packet = _security_evidence_packet(finding)
    structured_packet_incomplete = (
        rule_id in _STRUCTURED_SECURITY_FLOW_RULES
        and not structured_security_evidence_is_complete(rule_id, packet)
    )
    if structured_packet_incomplete:
        lines.append(
            "Security-flow analysis was incomplete or its proof packet was "
            "malformed; the finding remains a review candidate."
        )
    if packet is not None:
        lines.extend(
            _structured_evidence_lines(packet, "guards_seen", "Guard observed")
        )
        lines.extend(
            _structured_evidence_lines(packet, "guards_missing", "Missing proof")
        )
        lines.extend(
            _structured_evidence_lines(
                packet,
                "analysis_diagnostics",
                "Analysis diagnostic",
            )
        )

    return tuple(lines)


def _impact(kind: EvidenceKind, control_type: str, rule_id: str) -> str:
    if kind == "secret":
        if rule_id == "SKY-S102":
            return (
                "Client-accessible code can expose the value to anyone who loads "
                "or inspects the application bundle."
            )
        return "A committed credential can be copied from the repository or logs."
    if kind == "security_regression":
        return f"The affected change may reduce protection from {_control_phrase(control_type)}."
    if kind == "security":
        return "The affected code may expose a security weakness if reachable."
    if kind == "reliability":
        return "The affected deployment may fail or behave inconsistently at runtime."
    if kind == "dependency":
        return "The dependency change may affect supply-chain or runtime safety."
    if kind == "custom":
        return "The change violates a configured project rule."
    return "The issue can increase maintenance cost or review risk."


def _suggested_fix(
    finding: dict[str, Any],
    kind: EvidenceKind,
    rule_id: str,
    control_type: str,
) -> str | None:
    if kind == "secret":
        if rule_id == "SKY-S102":
            return _RULE_SUGGESTIONS[rule_id]
        return "Rotate the exposed credential and move it to a secrets manager or environment variable."
    if kind == "security_regression":
        return _REGRESSION_SUGGESTIONS.get(
            control_type,
            "Restore or replace the removed security control before merging.",
        )

    suggestion = finding.get("suggestion")
    if suggestion:
        return _limit(redact_sensitive_text(suggestion), 220)
    return _RULE_SUGGESTIONS.get(rule_id) or _fallback_suggested_fix(kind)


def _fallback_suggested_fix(kind: EvidenceKind) -> str:
    if kind == "security":
        return "Review the risky data flow and add the narrowest validation, escaping, or guard needed."
    if kind == "reliability":
        return "Align the declared runtime, deployment, and compatibility requirements."
    if kind == "dependency":
        return "Review the dependency change and pin, update, or remove the package as appropriate."
    if kind == "custom":
        return "Update the code to satisfy the configured project rule, or adjust the rule if this case is intentional."
    return "Refactor the affected code to remove the reported maintainability issue."


def _control_phrase(control_type: str) -> str:
    control_label = control_type.replace("_", " ") if control_type else "security"
    if control_label.endswith("control"):
        return control_label
    return f"{control_label} control"


def _verification_verdict(finding: dict[str, Any]) -> str:
    verification = finding.get("verification")
    if isinstance(verification, dict):
        verdict = verification.get("verdict")
        if isinstance(verdict, str):
            return verdict.upper()

    verdict = finding.get("_review_verdict")
    if isinstance(verdict, str):
        return verdict.upper()
    return ""


def _security_evidence(finding: dict[str, Any]) -> str:
    evidence = finding.get("_security_evidence")
    if isinstance(evidence, str):
        return evidence

    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        evidence = metadata.get("security_evidence")
        if isinstance(evidence, str):
            return evidence
    return ""


def _security_evidence_packet(finding: dict[str, Any]) -> dict[str, Any] | None:
    evidence = finding.get("_security_evidence")
    if isinstance(evidence, dict):
        return evidence

    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        return None
    evidence = metadata.get("security_evidence")
    return evidence if isinstance(evidence, dict) else None


def _has_incomplete_security_flow_proof(
    finding: dict[str, Any], kind: EvidenceKind
) -> bool:
    if kind != "security":
        return False
    rule_id = str(finding.get("rule_id") or "")
    if rule_id not in _STRUCTURED_SECURITY_FLOW_RULES:
        return False
    packet = _security_evidence_packet(finding)
    return not structured_security_evidence_is_complete(rule_id, packet)


def _structured_evidence_lines(
    packet: dict[str, Any], key: str, prefix: str
) -> list[str]:
    raw_values = packet.get(key)
    if isinstance(raw_values, str):
        values = [raw_values]
    elif isinstance(raw_values, (list, tuple)):
        values = [value for value in raw_values if isinstance(value, str)]
    else:
        values = []

    lines: list[str] = []
    for value in values[:_MAX_STRUCTURED_EVIDENCE_ITEMS]:
        safe_value = _limit(" ".join(redact_sensitive_text(value).split()), 180)
        if safe_value:
            lines.append(f"{prefix}: {safe_value}")
    return lines


def _review_reason(finding: dict[str, Any]) -> str:
    reason = finding.get("_review_reason")
    if isinstance(reason, str):
        return reason

    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        reason = metadata.get("review_reason")
        if isinstance(reason, str):
            return reason
    return ""


def _line_number(value: Any) -> int:
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return 1


def _optional_text(value: Any) -> str | None:
    if not value:
        return None
    return _limit(redact_sensitive_text(value), 120)


def _limit(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3].rstrip()}..."
