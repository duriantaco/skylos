from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Literal

EvidenceLabel = Literal["proven", "likely", "speculative"]
EvidenceKind = Literal[
    "security",
    "security_regression",
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


_SECRET_PATTERNS = (
    re.compile(r"\bsk_(?:live|test|proj)_[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b[A-Za-z0-9_./+=-]{40,}\b"),
)

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
    "SKY-D280": "Verify webhook signatures before trusting webhook request bodies.",
    "SKY-D281": "Keep webhook signature verification before any request body parsing or side effects.",
    "SKY-D282": "Use a webhook library or HMAC comparison that verifies the provider signature.",
    "SKY-S101": "Move the secret to environment variables or a secrets manager, then rotate it.",
    "SKY-S102": "Move the credential to a secrets manager, then rotate the exposed value.",
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
        impact=_impact(kind, control_type),
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


def redact_sensitive_text(value: Any) -> str:
    text = "" if value is None else str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


def _evidence_kind(finding: dict[str, Any]) -> EvidenceKind:
    category = str(finding.get("category") or "").lower()
    kind = str(finding.get("kind") or "").lower()

    if category == "security_regression" or kind == "security_regression":
        return "security_regression"
    if category in {"secrets", "secret"}:
        return "secret"
    if category in {"danger", "security"}:
        return "security"
    if category in {"dependency", "dependencies"}:
        return "dependency"
    if category == "custom_rules":
        return "custom"
    return "quality"


def _evidence_label(finding: dict[str, Any], kind: EvidenceKind) -> EvidenceLabel:
    if kind in {"security_regression", "secret"}:
        return "proven"

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

    return tuple(lines)


def _impact(kind: EvidenceKind, control_type: str) -> str:
    if kind == "secret":
        return "A committed credential can be copied from the repository or logs."
    if kind == "security_regression":
        return f"The affected change may reduce protection from {_control_phrase(control_type)}."
    if kind == "security":
        return "The affected code may expose a security weakness if reachable."
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
