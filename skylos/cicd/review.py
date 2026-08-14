from __future__ import annotations

import json
import logging
import os
import posixpath
import re
import subprocess

import requests
from rich.console import Console

from skylos.cicd.evidence import (
    EvidenceCard,
    build_evidence_card,
    build_evidence_cards,
    evidence_counts,
    evidence_label_title,
    sanitize_markdown_text,
    sanitize_untrusted_text,
)
from skylos.cicd.risk_passport import (
    build_risk_passport,
    format_risk_passport_markdown,
)
from skylos.rules.quality.regression import detect_security_regressions

console = Console()
logger = logging.getLogger(__name__)


def run_pr_review(
    results: dict,
    *,
    pr_number: int | None = None,
    repo: str | None = None,
    summary_only: bool = False,
    max_comments: int = 25,
    diff_base: str = "origin/main",
    grade: dict | None = None,
    previous_grade: dict | None = None,
    llm_findings: list[dict] | None = None,
    defense_report: dict | None = None,
    evidence_cards: bool = False,
) -> None:
    pr_number = pr_number or _detect_pr_number()
    repo = repo or os.environ.get("GITHUB_REPOSITORY")

    if not pr_number:
        console.print(
            "[yellow]Could not detect PR number. Use --pr to specify.[/yellow]"
        )
        return

    if not repo:
        console.print("[yellow]Could not detect repo. Use --repo to specify.[/yellow]")
        return

    if not _gh_available():
        console.print(
            "[bold red]gh CLI not found. Install: https://cli.github.com[/bold red]"
        )
        return

    if grade and previous_grade is None:
        previous_grade = _fetch_previous_grade(diff_base)

    all_findings = _flatten_findings(results)

    if llm_findings:
        all_findings = _merge_llm_findings(all_findings, llm_findings)

    regression_findings = _detect_regressions_from_diff(diff_base)

    if not summary_only:
        changed_ranges = get_changed_line_ranges(diff_base)
        findings = filter_findings_to_diff(all_findings, changed_ranges)
        findings.extend(regression_findings)
    else:
        findings = all_findings + regression_findings

    all_findings.extend(regression_findings)
    provenance = _resolve_review_provenance(results, diff_base=diff_base)
    risk_passport = build_risk_passport(
        all_findings=all_findings,
        diff_findings=findings,
        provenance=provenance,
        defense_report=defense_report,
    )

    if findings and not summary_only:
        _post_pr_review(
            findings[:max_comments],
            pr_number,
            repo,
            evidence_cards=evidence_cards,
            changed_ranges=changed_ranges,
        )

    _post_summary_comment(
        all_findings,
        findings,
        pr_number,
        repo,
        grade=grade,
        previous_grade=previous_grade,
        evidence_cards=evidence_cards,
        risk_passport=risk_passport,
    )

    console.print(
        f"[green]Posted review on PR #{pr_number} "
        f"({len(findings)} inline, {len(all_findings)} total)[/green]"
    )


def _resolve_review_provenance(results: dict, *, diff_base: str) -> dict | None:
    provenance = results.get("provenance")
    if isinstance(provenance, dict):
        return provenance

    project_root = results.get("project_root") or "."
    try:
        from skylos.reporting.provenance import analyze_provenance

        return analyze_provenance(project_root, base_ref=diff_base).to_dict()
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        logger.debug("Failed to resolve review provenance: %s", exc)
        return None


def get_changed_line_ranges(base_ref: str = "origin/main") -> list[dict]:
    try:
        result = subprocess.run(
            ["git", "diff", "--unified=0", f"{base_ref}...HEAD"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return []
    except FileNotFoundError:
        return []

    return _parse_unified_diff(result.stdout)


def _parse_unified_diff(diff_output: str) -> list[dict]:
    entries = []
    current_file = None

    for line in diff_output.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        hunk_match = re.match(r"^@@ .+ \+(\d+)(?:,(\d+))? @@", line)
        if hunk_match and current_file:
            start = int(hunk_match.group(1))
            count = int(hunk_match.group(2) or 1)
            anchor = max(1, start)
            entries.append(
                {
                    "file": current_file,
                    "start": anchor,
                    "end": anchor if count == 0 else start + count - 1,
                }
            )

    return entries


def _get_per_file_diffs(base_ref: str = "origin/main") -> dict[str, str]:
    """Return a dict mapping file paths to their individual diff text."""
    try:
        result = subprocess.run(
            ["git", "diff", "--unified=3", f"{base_ref}...HEAD"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return {}
    except FileNotFoundError:
        return {}

    file_diffs: dict[str, str] = {}
    current_file = None
    current_lines: list[str] = []

    for line in result.stdout.splitlines():
        if line.startswith("diff --git"):
            if current_file and current_lines:
                file_diffs[current_file] = "\n".join(current_lines)
            current_file = None
            current_lines = [line]
        elif line.startswith("+++ b/"):
            current_file = line[6:]
            current_lines.append(line)
        else:
            current_lines.append(line)

    if current_file and current_lines:
        file_diffs[current_file] = "\n".join(current_lines)

    return file_diffs


def _detect_regressions_from_diff(base_ref: str = "origin/main") -> list[dict]:
    """Run security regression detection on the PR diff."""
    file_diffs = _get_per_file_diffs(base_ref)
    regression_findings: list[dict] = []

    for file_path, diff_text in file_diffs.items():
        findings = detect_security_regressions(diff_text, file_path)
        for f in findings:
            regression_findings.append(
                {
                    "file": f.get("file", ""),
                    "line": f.get("line", 1),
                    "message": f.get("message", ""),
                    "rule_id": f.get("rule_id", ""),
                    "severity": f.get("severity", "HIGH"),
                    "category": "security_regression",
                    "control_type": f.get("control_type", ""),
                    "kind": "security_regression",
                }
            )

    return regression_findings


def filter_findings_to_diff(
    findings: list[dict], changed_ranges: list[dict]
) -> list[dict]:
    if not changed_ranges:
        return []

    ranges_by_file = {}
    for r in changed_ranges:
        ranges_by_file.setdefault(r["file"], []).append((r["start"], r["end"]))

    filtered = []
    for finding in findings:
        if _location_overlaps_diff(
            finding.get("file", ""),
            finding.get("line", 0),
            finding.get("line", 0),
            ranges_by_file,
        ):
            filtered.append(finding)
            continue

        related_locations = finding.get("related_locations")
        if not isinstance(related_locations, list):
            continue

        for location in related_locations:
            if not isinstance(location, dict):
                continue
            if _location_overlaps_diff(
                location.get("file", ""),
                location.get("start_line", 0),
                location.get("end_line", location.get("start_line", 0)),
                ranges_by_file,
            ):
                filtered.append(finding)
                break

    return filtered


def _validated_location_span(
    file: object,
    start_line: object,
    end_line: object,
) -> tuple[str, int, int] | None:
    if not isinstance(file, str) or not file:
        return None
    if isinstance(start_line, bool) or not isinstance(start_line, int):
        return None
    if isinstance(end_line, bool) or not isinstance(end_line, int):
        return None
    if start_line < 1 or end_line < start_line:
        return None
    return file, start_line, end_line


def _same_location_file(left: str, right: str) -> bool:
    return left == right or left.endswith("/" + right) or right.endswith("/" + left)


def _spans_overlap(
    left_start: int,
    left_end: int,
    right_start: int,
    right_end: int,
) -> bool:
    return left_start <= right_end and right_start <= left_end


def _diff_ranges_for_file(
    file: str,
    ranges_by_file: dict[str, list[tuple[int, int]]],
) -> list[tuple[int, int]]:
    exact = ranges_by_file.get(file)
    if exact:
        return exact
    for diff_file, ranges in ranges_by_file.items():
        if _same_location_file(file, diff_file):
            return ranges
    return []


def _location_overlaps_diff(
    file: object,
    start_line: object,
    end_line: object,
    ranges_by_file: dict[str, list[tuple[int, int]]],
) -> bool:
    span = _validated_location_span(file, start_line, end_line)
    if span is None:
        return False
    normalized_file, normalized_start, normalized_end = span

    return any(
        _spans_overlap(normalized_start, normalized_end, changed_start, changed_end)
        for changed_start, changed_end in _diff_ranges_for_file(
            normalized_file, ranges_by_file
        )
    )


_SAFE_FINDING_METADATA_FIELDS = (
    "security_evidence",
    "review_verdict",
    "review_reason",
    "review_safety_proof",
    "review_proof_kind",
    "review_proof_lines",
)
_SAFE_VERIFICATION_FIELDS = ("verdict", "confidence", "reason")
_SAFE_SECURITY_EVIDENCE_TEXT_FIELDS = (
    "evidence_kind",
    "source",
    "sink",
    "confidence_reason",
    "test_hint",
    "fix_shape",
)
_SAFE_SECURITY_EVIDENCE_LIST_FIELDS = (
    "path",
    "guards_seen",
    "guards_missing",
    "analysis_diagnostics",
)
_SAFE_SECURITY_EVIDENCE_OPTIONS = frozenset({"httpOnly", "secure"})
_SAFE_SECURITY_EVIDENCE_OPTION_STATES = frozenset(
    {"absent", "false", "true", "unknown"}
)
_MAX_SECURITY_EVIDENCE_TEXT_LENGTH = 500
_MAX_SECURITY_EVIDENCE_LIST_ITEMS = 12


def _flatten_findings(results: dict) -> list[dict]:
    findings = []

    for category in (
        "danger",
        "reliability",
        "ai_defects",
        "quality",
        "secrets",
        "custom_rules",
    ):
        for f in results.get(category, []) or []:
            finding = {
                "file": f.get("file") or f.get("file_path") or "",
                "line": f.get("line") or f.get("line_number") or 1,
                "message": sanitize_untrusted_text(
                    f.get("message") or f.get("msg") or f.get("detail") or "",
                    max_length=4_000,
                    preserve_newlines=True,
                ),
                "rule_id": f.get("rule_id") or "",
                "severity": f.get("severity", "MEDIUM"),
                "category": category,
            }
            related_locations = f.get("related_locations")
            if isinstance(related_locations, list):
                finding["related_locations"] = related_locations
            _copy_safe_finding_metadata(f, finding)
            findings.append(finding)

    return findings


def _copy_safe_finding_metadata(source: dict, target: dict) -> None:
    for key in (
        "_security_evidence",
        "_review_verdict",
        "_review_reason",
        "_review_safety_proof",
        "_review_proof_kind",
        "_review_proof_lines",
    ):
        value = source.get(key)
        if key == "_security_evidence":
            safe_evidence = _sanitize_security_evidence(value)
            if safe_evidence is not None:
                target[key] = safe_evidence
        elif isinstance(value, str):
            target[key] = sanitize_untrusted_text(value, max_length=1_000)
        elif key == "_review_proof_lines" and isinstance(value, list):
            target[key] = [
                sanitize_untrusted_text(item, max_length=500)
                for item in value[:12]
                if isinstance(item, str)
            ]

    symbol = source.get("symbol")
    if isinstance(symbol, str):
        target["symbol"] = sanitize_untrusted_text(symbol, max_length=500)

    confidence = source.get("confidence")
    if isinstance(confidence, int):
        target["confidence"] = confidence

    ai_authored = source.get("ai_authored")
    if isinstance(ai_authored, bool):
        target["ai_authored"] = ai_authored

    ai_agent = source.get("ai_agent")
    if isinstance(ai_agent, str):
        target["ai_agent"] = sanitize_untrusted_text(ai_agent, max_length=120)

    verification = source.get("verification")
    if isinstance(verification, dict):
        safe_verification = {}
        for key, value in verification.items():
            if key not in _SAFE_VERIFICATION_FIELDS or not isinstance(
                value, (str, int, float, bool)
            ):
                continue
            safe_verification[key] = (
                sanitize_untrusted_text(value, max_length=1_000)
                if isinstance(value, str)
                else value
            )
        if safe_verification:
            target["verification"] = safe_verification

    metadata = source.get("metadata")
    if not isinstance(metadata, dict):
        return

    safe_metadata = {}
    for key, value in metadata.items():
        if key not in _SAFE_FINDING_METADATA_FIELDS:
            continue
        if key == "security_evidence":
            safe_evidence = _sanitize_security_evidence(value)
            if safe_evidence is not None:
                safe_metadata[key] = safe_evidence
        elif isinstance(value, str):
            safe_metadata[key] = sanitize_untrusted_text(value, max_length=1_000)
        elif key == "review_proof_lines" and isinstance(value, list):
            safe_metadata[key] = [
                sanitize_untrusted_text(item, max_length=500)
                for item in value[:12]
                if isinstance(item, str)
            ]
    if safe_metadata:
        target["metadata"] = safe_metadata
        if "security_evidence" in safe_metadata:
            target["_security_evidence"] = safe_metadata["security_evidence"]
        if "review_verdict" in safe_metadata:
            target["_review_verdict"] = safe_metadata["review_verdict"]
        if "review_reason" in safe_metadata:
            target["_review_reason"] = safe_metadata["review_reason"]
        if "review_safety_proof" in safe_metadata:
            target["_review_safety_proof"] = safe_metadata["review_safety_proof"]
        if "review_proof_kind" in safe_metadata:
            target["_review_proof_kind"] = safe_metadata["review_proof_kind"]
        if "review_proof_lines" in safe_metadata:
            target["_review_proof_lines"] = safe_metadata["review_proof_lines"]


def _sanitize_security_evidence(value: object) -> str | dict | None:
    if isinstance(value, str):
        return _sanitize_security_evidence_text(value)
    if not isinstance(value, dict):
        return None

    packet: dict = {}
    for key in _SAFE_SECURITY_EVIDENCE_TEXT_FIELDS:
        field_value = value.get(key)
        if isinstance(field_value, str):
            packet[key] = _sanitize_security_evidence_text(field_value)

    for key in _SAFE_SECURITY_EVIDENCE_LIST_FIELDS:
        field_value = value.get(key)
        if not isinstance(field_value, (list, tuple)):
            continue
        items = []
        for item in field_value[:_MAX_SECURITY_EVIDENCE_LIST_ITEMS]:
            if not isinstance(item, str):
                continue
            items.append(_sanitize_security_evidence_text(item))
        packet[key] = items

    options = value.get("options")
    if isinstance(options, dict):
        safe_options = {}
        for key in _SAFE_SECURITY_EVIDENCE_OPTIONS:
            state = options.get(key)
            if (
                isinstance(state, str)
                and state in _SAFE_SECURITY_EVIDENCE_OPTION_STATES
            ):
                safe_options[key] = state
        packet["options"] = safe_options

    analysis_complete = value.get("analysis_complete")
    if isinstance(analysis_complete, bool):
        packet["analysis_complete"] = analysis_complete

    return packet


def _sanitize_security_evidence_text(value: str) -> str:
    return sanitize_untrusted_text(
        value,
        max_length=_MAX_SECURITY_EVIDENCE_TEXT_LENGTH,
    )


def _merge_llm_findings(
    static_findings: list[dict], llm_findings: list[dict]
) -> list[dict]:
    llm_by_identity: dict[tuple[str, int, str], list[tuple[int, dict]]] = {}
    for index, finding in enumerate(llm_findings):
        identity = _review_finding_identity(finding)
        if identity is not None:
            llm_by_identity.setdefault(identity, []).append((index, finding))

    matched_indices: set[int] = set()
    for finding in static_findings:
        identity = _review_finding_identity(finding)
        candidates = llm_by_identity.get(identity, []) if identity else []
        if not candidates:
            continue
        llm_index, llm = candidates.pop(0)
        matched_indices.add(llm_index)
        for key in ("suggestion", "explanation", "vulnerable_code", "fixed_code"):
            if llm.get(key):
                finding[key] = llm[key]

    for index, llm in enumerate(llm_findings):
        if index not in matched_indices:
            category = str(llm.get("_category") or "security").strip().lower()
            if category in {"secret", "secrets", "security_regression"}:
                category = "security"
            finding = {
                "file": llm.get("file", ""),
                "line": llm.get("line", 0),
                "message": llm.get("message", ""),
                "rule_id": llm.get("rule_id", ""),
                "severity": llm.get("severity", "MEDIUM"),
                "category": category,
                "suggestion": llm.get("suggestion"),
                "explanation": llm.get("explanation"),
                "vulnerable_code": llm.get("vulnerable_code"),
                "fixed_code": llm.get("fixed_code"),
            }
            symbol = llm.get("symbol")
            if isinstance(symbol, str):
                finding["symbol"] = sanitize_untrusted_text(symbol, max_length=500)
            finding["_source"] = "llm"
            static_findings.append(finding)

    return static_findings


def _review_finding_identity(finding: object) -> tuple[str, int, str] | None:
    if not isinstance(finding, dict):
        return None
    file_path = _normalize_review_finding_path(finding.get("file"))
    rule_id = str(finding.get("rule_id") or "").strip().upper()
    line = finding.get("line")
    if isinstance(line, bool):
        return None
    try:
        line_number = int(line)
    except (TypeError, ValueError, OverflowError):
        return None
    if not file_path or not rule_id or line_number < 1:
        return None
    return file_path, line_number, rule_id


def _normalize_review_finding_path(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return ""
    normalized = posixpath.normpath(value.strip().replace("\\", "/"))
    cwd = posixpath.normpath(os.getcwd().replace("\\", "/"))
    if normalized.startswith(cwd + "/"):
        normalized = normalized[len(cwd) + 1 :]
    return "" if normalized in {"", "."} else normalized


_REGRESSION_SUGGESTIONS: dict[str, str] = {
    "auth": "Re-add the authentication decorator or dependency. Removing auth exposes the endpoint to unauthenticated access.",
    "csrf": "Re-enable CSRF protection. Without it, the endpoint is vulnerable to cross-site request forgery attacks.",
    "tls": "Re-enable TLS certificate verification (verify=True). Disabling it allows man-in-the-middle attacks.",
    "crypto": "Use a strong hash algorithm (SHA-256 or better). Weak hashes like MD5/SHA-1 are vulnerable to collision attacks.",
    "rate_limit": "Re-add rate limiting. Without it, the endpoint is vulnerable to brute-force and denial-of-service attacks.",
    "validation": "Re-add input validation or sanitization. Without it, the endpoint may be vulnerable to injection attacks.",
    "headers": "Re-add the security header or middleware. Security headers protect against XSS, clickjacking, and other attacks.",
    "encryption": "Re-add encryption. Removing it may expose sensitive data in plaintext.",
    "logging": "Re-add audit logging. Without it, security-relevant actions go untracked.",
    "sanitization": "Re-add output sanitization. Without it, user-supplied content may cause XSS or injection vulnerabilities.",
    "permission": "Re-add the permission check. Removing it may allow unauthorized access to restricted resources.",
}

_RULE_SUGGESTIONS: dict[str, str] = {
    "SKY-D201": "Replace `eval()` with `json.loads()`, `ast.literal_eval()`, or a safe parser. Never evaluate untrusted input.",
    "SKY-D203": "Replace `os.system()` with `subprocess.run()` with `shell=False`. Pass arguments as a list.",
    "SKY-D211": "Use parameterized queries: `cursor.execute('SELECT * FROM t WHERE x = ?', (val,))` instead of f-strings.",
    "SKY-D212": "Sanitize input before passing to shell commands, or use `subprocess.run()` with `shell=False` and argument lists.",
    "SKY-D215": "Validate file paths against an allowed directory: `Path(path).resolve().relative_to(allowed_dir)`.",
    "SKY-D216": "Validate URLs against an allowlist of domains. Block internal IPs (`127.0.0.1`, `169.254.x.x`, `10.x.x.x`).",
    "SKY-D223": "Add the package to `requirements.txt` or `pyproject.toml`, or remove the import if unused.",
    "SKY-D290": "Avoid `pull_request_target` for untrusted code, or keep checkout/build steps isolated from privileged tokens.",
    "SKY-D291": "Declare `permissions: {}` at workflow scope, then grant minimal permissions per job.",
    "SKY-D292": "Pin third-party actions and reusable workflows to full 40-character commit SHAs.",
    "SKY-D293": "Set `persist-credentials: false` on `actions/checkout` unless the job needs to push commits.",
    "SKY-D294": "Move GitHub context values into `env:` and reference the quoted environment variable inside `run:`.",
    "SKY-D295": "Use GitHub-hosted runners, or require ephemeral isolated self-hosted runners for untrusted workflows.",
    "SKY-D296": "Pin container images by digest, for example `image@sha256:...`, instead of mutable tags.",
    "SKY-D297": "Replace `secrets: inherit` with an explicit `secrets:` map containing only required values.",
    "SKY-D298": "Reference only a specific secret name; avoid `toJSON(secrets)` and dynamic `secrets[...]` lookups.",
    "SKY-D299": "Add a job `environment:` and scope the secret to that GitHub environment.",
    "SKY-D300": "Write only static key/value pairs to `$GITHUB_ENV` or `$GITHUB_PATH`; avoid command-derived writes.",
    "SKY-D301": "Move the container registry password to a GitHub secret and reference it via `${{ secrets.NAME }}`.",
    "SKY-D302": "Add repository scoping and explicit `permission-*` inputs for `actions/create-github-app-token`.",
    "SKY-D303": "Use exact equality checks or `contains(fromJSON('[...]'), value)` instead of substring checks.",
    "SKY-D304": "Use event-specific sender IDs instead of spoofable actor-name checks for bot logic.",
    "SKY-D305": "Use an unfenced expression or a stripped block scalar such as `|-` for multiline `if:`.",
    "SKY-D306": "Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS` from workflow, job, or step environment.",
    "SKY-D307": "Add a top-level `name:` to the workflow or action.",
    "SKY-D308": "Remove cache-aware actions from release workflows or disable cache restore/save in publishing jobs.",
    "SKY-D309": "Scope secrets to the individual step that needs them instead of workflow or job `env:`.",
    "SKY-D310": "Separate OIDC token issuance from repository-controlled build scripts; publish from prebuilt artifacts.",
    "SKY-D311": "Set `if-no-files-found: error` on `actions/upload-artifact` for required outputs.",
    "SKY-D312": "Use `npm ci --ignore-scripts` or an equivalent package-manager flag unless lifecycle scripts are required.",
    "SKY-D313": "Add `timeout-minutes` to privileged or release-like jobs.",
    "SKY-D314": "Pin GitLab CI `image:` and `services:` entries by digest, especially `docker:dind` services.",
    "SKY-D315": "Pin `include:project` entries to full commit SHAs and add `integrity:` to remote includes.",
    "SKY-D316": "Move literal secrets out of `.gitlab-ci.yml` and into protected, masked GitLab CI/CD variables.",
    "SKY-D317": "Do not pass merge request or ref metadata into `eval`, `sh -c`, `bash -c`, or interpreter `-c`/`-e` commands.",
    "SKY-D318": "Use TLS-enabled Docker-in-Docker, or avoid privileged Docker socket access in this job.",
    "SKY-D319": "Separate OIDC token issuance from repository-controlled scripts; publish from prebuilt artifacts.",
    "SKY-D320": "Remove cache restore from release/deploy jobs or use isolated release-only cache keys.",
    "SKY-D321": "Add `timeout:` to GitLab CI release, deploy, or OIDC jobs.",
    "SKY-D322": "Use static GitLab runner tags so untrusted refs cannot select privileged runners.",
    "SKY-D323": "Set an explicit `token:` for each GitLab CI secret when the job defines multiple `id_tokens`.",
    "SKY-D324": "Reject symlinks before writing, keep the resolved path inside the trusted root, or open with `O_NOFOLLOW`.",
    "SKY-D325": "Reject symlinks and non-regular files before reading, enforce root containment, and cap the read size.",
    "SKY-D326": "Manually validate archive members before extraction; reject absolute paths, `..`, symlinks, and hardlinks.",
    "SKY-D327": "Remove the upload of environment, token, or `.env*` data to external destinations.",
    "SKY-D328": "Download remote scripts to a file, inspect or verify them, then execute a pinned local copy only if trusted.",
    "SKY-D329": "Narrow destructive commands to explicit workspace paths and require human confirmation for broad deletes or resets.",
    "SKY-D330": "Remove `privileged: true` and grant only the specific Linux devices or capabilities the edge service requires.",
    "SKY-D331": "Avoid broad host control mounts; prefer specific read-only device mappings and never mount the Docker socket into edge services.",
    "SKY-D332": "Avoid `network_mode: host`; bind only required ports and keep robot or device control services off untrusted networks.",
    "SKY-D333": "Run the systemd unit as a dedicated non-root user and grant only the device access it needs.",
    "SKY-D334": "Move the systemd executable under a root-owned directory and lock down script permissions.",
    "SKY-D335": "Add systemd sandboxing such as `NoNewPrivileges=true`, `ProtectSystem=full`, and `PrivateTmp=true`.",
    "SKY-D336": "Reduce systemd capabilities, broad device access, or privileged container flags to the minimum required set.",
    "SKY-D337": "Use the default trusted package registry, or pin and document the approved internal registry.",
    "SKY-D338": "Do not read host credential stores or mount the host root filesystem into agent or CI commands.",
    "SKY-D339": "Avoid persistent profile, scheduler, global git, or package-manager configuration changes in agent or CI tasks.",
    "SKY-D340": "Move publish commands into an explicit release workflow with protected approvals.",
    "SKY-D341": "Pin package-managed tools and avoid auto-install execution flags such as `npx -y`.",
    "SKY-S101": "Move secrets to environment variables: `os.getenv('SECRET_KEY')`. Never hardcode credentials.",
}


def _format_review_comment(finding: dict) -> str:
    kind = finding.get("kind", "")
    raw_severity = str(finding.get("severity") or "MEDIUM").upper()
    severity = (
        raw_severity
        if raw_severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        else "MEDIUM"
    )
    rule_id = finding.get("rule_id", "")
    message = sanitize_markdown_text(finding.get("message", ""), max_length=1_000)
    safe_rule_id = sanitize_markdown_text(rule_id, max_length=120)
    rule_str = f" `{safe_rule_id}`" if safe_rule_id else ""

    if kind == "security_regression":
        control_type = finding.get("control_type", "")
        control_label = (
            control_type.replace("_", " ").title() if control_type else "Unknown"
        )
        parts = [
            f"⚠️ **SECURITY REGRESSION**{rule_str} — {control_label}",
            "",
            message,
        ]
        suggestion = _REGRESSION_SUGGESTIONS.get(control_type)
        if suggestion:
            parts.extend(["", f"**Fix:** {sanitize_markdown_text(suggestion)}"])
    else:
        badge = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
            severity, "⚪"
        )
        parts = [f"{badge} **{severity}**{rule_str}", "", message]

        explanation = finding.get("explanation")
        if explanation:
            parts.extend(
                [
                    "",
                    f"**Why:** {sanitize_markdown_text(explanation, max_length=1_000)}",
                ]
            )

        vulnerable_code = finding.get("vulnerable_code")
        fixed_code = finding.get("fixed_code")

        if vulnerable_code and fixed_code:
            parts.extend(
                [
                    "",
                    "**Vulnerable code:**",
                    "```python",
                    sanitize_markdown_text(
                        vulnerable_code,
                        max_length=4_000,
                        preserve_newlines=True,
                    ),
                    "```",
                    "",
                    "**Fixed code:**",
                    "```python",
                    sanitize_markdown_text(
                        fixed_code,
                        max_length=4_000,
                        preserve_newlines=True,
                    ),
                    "```",
                ]
            )
        else:
            suggestion = finding.get("suggestion") or _RULE_SUGGESTIONS.get(rule_id)
            if suggestion:
                parts.extend(["", f"**Fix:** {sanitize_markdown_text(suggestion)}"])

    footer = "\n\n---\n_🤖 Analyzed by [Skylos](https://github.com/duriantaco/skylos) • [Add to your repo](https://github.com/duriantaco/skylos#cicd)_"
    parts.append(footer)

    return "\n".join(parts)


def _format_evidence_card_comment(
    finding: dict, card: EvidenceCard | None = None
) -> str:
    card = card or build_evidence_card(finding)
    safe_rule_id = sanitize_markdown_text(card.rule_id, max_length=120)
    rule_str = f" `{safe_rule_id}`" if safe_rule_id else ""
    risk = {
        "security": "security finding",
        "security_regression": "security regression",
        "secret": "secret exposure",
        "reliability": "reliability issue",
        "quality": "quality issue",
        "dependency": "dependency issue",
        "custom": "custom rule match",
    }[card.kind]
    raw_location = f"{card.file}:{card.line}" if card.file else str(card.line)
    location = sanitize_markdown_text(raw_location, max_length=600)

    parts = [
        f"**Risk: {evidence_label_title(card.label)} {risk}**{rule_str}",
        "",
        sanitize_markdown_text(card.title, max_length=120),
        "",
        f"**Location:** `{location}`",
        "",
        "**Evidence:**",
    ]

    for item in card.evidence or ("No extra evidence attached.",):
        parts.append(f"- {sanitize_markdown_text(item, max_length=500)}")

    if card.impact:
        parts.extend(
            ["", f"**Impact:** {sanitize_markdown_text(card.impact, max_length=500)}"]
        )

    if card.suggested_fix:
        parts.extend(
            [
                "",
                "**Suggested fix:** "
                f"{sanitize_markdown_text(card.suggested_fix, max_length=500)}",
            ]
        )

    parts.extend(["", f"**Confidence:** {card.confidence}%"])

    footer = "\n\n---\n_🤖 Analyzed by [Skylos](https://github.com/duriantaco/skylos) • [Add to your repo](https://github.com/duriantaco/skylos#cicd)_"
    parts.append(footer)
    return "\n".join(parts)


def _to_relative_path(filepath: str) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            root = result.stdout.strip()
            if filepath.startswith(root):
                return filepath[len(root) :].lstrip("/")
    except OSError as exc:
        logger.debug("Failed to resolve git root for review path: %s", exc)
    return filepath


def _post_pr_review(
    findings: list[dict],
    pr_number: int,
    repo: str,
    *,
    evidence_cards: bool = False,
    changed_ranges: list[dict] | None = None,
) -> None:
    comments = []
    for f in findings:
        if not f.get("file") or not f.get("line"):
            continue
        comment_file, comment_line = _review_comment_location(f, changed_ranges)
        body = (
            _format_evidence_card_comment(f)
            if evidence_cards
            else _format_review_comment(f)
        )
        comments.append(
            {
                "path": _to_relative_path(comment_file),
                "line": comment_line,
                "body": body,
            }
        )

    if not comments:
        return

    payload = {
        "body": (
            f"Skylos found {len(comments)} issue(s) on changed lines.\n\n"
            "---\n"
            "_🤖 Analyzed by [Skylos](https://github.com/duriantaco/skylos) • "
            "[Set up in 30 seconds](https://github.com/duriantaco/skylos#cicd)_"
        ),
        "event": "COMMENT",
        "comments": comments,
    }

    try:
        subprocess.run(
            [
                "gh",
                "api",
                "--method",
                "POST",
                f"/repos/{repo}/pulls/{pr_number}/reviews",
                "--input",
                "-",
            ],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[yellow]Failed to post PR review: {e.stderr}[/yellow]")


def _related_location_spans(finding: dict) -> list[tuple[str, int, int]]:
    spans: list[tuple[str, int, int]] = []
    related_locations = finding.get("related_locations")
    if not isinstance(related_locations, list):
        return spans
    for location in related_locations:
        if not isinstance(location, dict):
            continue
        start_line = location.get("start_line")
        span = _validated_location_span(
            location.get("file"),
            start_line,
            location.get("end_line", start_line),
        )
        if span is not None:
            spans.append(span)
    return spans


def _changed_overlap_line(
    span: tuple[str, int, int], changed_ranges: list[dict]
) -> int | None:
    file, start_line, end_line = span
    for changed in changed_ranges:
        changed_start = changed.get("start") or 0
        changed_end = changed.get("end") or changed_start
        changed_span = _validated_location_span(
            str(changed.get("file", "")),
            changed_start,
            changed_end,
        )
        if changed_span is None or not _same_location_file(file, changed_span[0]):
            continue
        if _spans_overlap(start_line, end_line, changed_span[1], changed_span[2]):
            return max(start_line, changed_span[1])
    return None


def _review_comment_location(
    finding: dict, changed_ranges: list[dict] | None
) -> tuple[str, int]:
    primary = (str(finding.get("file", "")), int(finding.get("line") or 1))
    if not changed_ranges:
        return primary

    candidates = [(primary[0], primary[1], primary[1])]
    candidates.extend(_related_location_spans(finding))
    for candidate in candidates:
        comment_line = _changed_overlap_line(candidate, changed_ranges)
        if comment_line is not None:
            return candidate[0], comment_line
    return primary


def _post_summary_comment(
    all_findings: list[dict],
    diff_findings: list[dict],
    pr_number: int,
    repo: str,
    *,
    grade: dict | None = None,
    previous_grade: dict | None = None,
    evidence_cards: bool = False,
    risk_passport: dict | None = None,
) -> None:
    by_severity = {}
    for f in all_findings:
        sev = f.get("severity", "MEDIUM")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    by_category = {}
    for f in all_findings:
        cat = f.get("category", "other")
        by_category[cat] = by_category.get(cat, 0) + 1

    lines = [
        "## Skylos Analysis Summary",
        "",
        f"**{len(diff_findings)}** issue(s) on changed lines | "
        f"**{len(all_findings)}** total",
    ]
    lines.extend(format_risk_passport_markdown(risk_passport))
    lines.extend(
        [
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
    )

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = by_severity.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev} | {count} |")

    if by_category:
        lines.extend(
            [
                "",
                "| Category | Count |",
                "|----------|-------|",
            ]
        )
        for cat in (
            "danger",
            "reliability",
            "quality",
            "secrets",
            "custom_rules",
            "security_regression",
        ):
            count = by_category.get(cat, 0)
            if count > 0:
                lines.append(f"| {cat} | {count} |")

    regression_findings = [
        f for f in diff_findings if f.get("kind") == "security_regression"
    ]
    if regression_findings:
        lines.extend(
            [
                "",
                "### ⚠️ Security Regressions Detected",
                "",
                "| Control | File | Message |",
                "|---------|------|---------|",
            ]
        )
        for f in regression_findings:
            control = sanitize_markdown_text(
                f.get("control_type", "unknown"), max_length=80
            )
            file = sanitize_markdown_text(
                os.path.basename(f.get("file", "")), max_length=300
            )
            msg = sanitize_markdown_text(f.get("message", ""), max_length=1_000)
            lines.append(f"| {control} | {file} | {msg} |")

    if evidence_cards:
        cards = build_evidence_cards(all_findings)
        counts = evidence_counts(cards)
        if cards:
            lines.extend(
                [
                    "",
                    "### Evidence",
                    "",
                    "| Label | Count |",
                    "|-------|-------|",
                ]
            )
            for label in ("proven", "likely", "speculative"):
                count = counts[label]
                if count > 0:
                    lines.append(f"| {evidence_label_title(label)} | {count} |")

    critical_findings = [
        f for f in diff_findings if f.get("severity") in ("CRITICAL", "HIGH")
    ]
    if critical_findings:
        lines.extend(["", "### Top Issues", ""])
        for f in critical_findings[:5]:
            sev = f.get("severity", "MEDIUM")
            badge = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(sev, "🟡")
            safe_rule_id = sanitize_markdown_text(f.get("rule_id", ""), max_length=120)
            rule = f" `{safe_rule_id}`" if safe_rule_id else ""
            file = sanitize_markdown_text(
                os.path.basename(f.get("file", "")), max_length=300
            )
            line_no = f.get("line", "")
            loc = f" ({file}:{line_no})" if file else ""
            message = sanitize_markdown_text(f.get("message", ""), max_length=1_000)
            lines.append(f"- {badge} **{sev}**{rule}{loc}: {message}")

            vuln_code = f.get("vulnerable_code")
            fix_code = f.get("fixed_code")
            if vuln_code and fix_code:
                lines.append("")
                lines.append("  <details><summary>View fix</summary>")
                lines.append("")
                lines.append("  **Vulnerable:**")
                lines.append("  ```python")
                safe_vulnerable_code = sanitize_markdown_text(
                    vuln_code,
                    max_length=4_000,
                    preserve_newlines=True,
                )
                for code_line in safe_vulnerable_code.splitlines():
                    lines.append(f"  {code_line}")
                lines.append("  ```")
                lines.append("  **Fixed:**")
                lines.append("  ```python")
                safe_fixed_code = sanitize_markdown_text(
                    fix_code,
                    max_length=4_000,
                    preserve_newlines=True,
                )
                for code_line in safe_fixed_code.splitlines():
                    lines.append(f"  {code_line}")
                lines.append("  ```")
                lines.append("  </details>")
                lines.append("")
            else:
                fix = f.get("suggestion") or _RULE_SUGGESTIONS.get(f.get("rule_id", ""))
                if fix:
                    lines.append(
                        f"  - **Fix:** {sanitize_markdown_text(fix, max_length=500)}"
                    )

    if grade:
        overall = grade["overall"]
        cats = grade["categories"]

        lines.extend(["", "### Codebase Grade", ""])

        if previous_grade:
            prev = previous_grade["overall"]
            delta = overall["score"] - prev["score"]
            arrow = "+" if delta > 0 else ""
            direction = "\u2191" if delta > 0 else ("\u2193" if delta < 0 else "\u2194")
            lines.append(
                f"**{prev['letter']} ({prev['score']}) \u2192 "
                f"{overall['letter']} ({overall['score']}) {direction}** "
                f"({arrow}{delta})"
            )
        else:
            lines.append(f"**Overall: {overall['letter']} ({overall['score']}/100)**")

        lines.extend(
            [
                "",
                "| Category | Score | Grade | Key Issue |",
                "|----------|-------|-------|-----------|",
            ]
        )

        for cat_name in ("security", "quality", "dead_code", "dependencies", "secrets"):
            cat = cats[cat_name]
            display = cat_name.replace("_", " ").title()
            issue = sanitize_markdown_text(cat.get("key_issue") or "-", max_length=50)

            delta_str = ""
            if previous_grade and cat_name in previous_grade.get("categories", {}):
                prev_cat = previous_grade["categories"][cat_name]
                cat_delta = cat["score"] - prev_cat["score"]
                if cat_delta != 0:
                    d_arrow = "\u2191" if cat_delta > 0 else "\u2193"
                    delta_str = f" {d_arrow}{abs(cat_delta)}"

            lines.append(
                f"| {display} | {cat['score']}{delta_str} | {cat['letter']} | {issue} |"
            )

    body = "\n".join(lines)

    try:
        subprocess.run(
            ["gh", "pr", "comment", str(pr_number), "--body", body, "--repo", repo],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[yellow]Failed to post summary comment: {e.stderr}[/yellow]")


def _fetch_previous_grade(base_branch: str = "origin/main") -> dict | None:
    try:
        from skylos.api import BASE_URL, get_project_token

        token = get_project_token()
        if not token:
            return None

        branch = base_branch.replace("origin/", "")
        resp = requests.get(
            f"{BASE_URL}/api/grade/latest",
            params={"branch": branch},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("grade")
    except (
        ImportError,
        OSError,
        ValueError,
        requests.exceptions.RequestException,
    ) as exc:
        logger.debug("Failed to fetch previous grade: %s", exc)
    return None


def _detect_pr_number() -> int | None:
    ref = os.environ.get("GITHUB_REF", "")
    match = re.match(r"refs/pull/(\d+)/merge", ref)
    if match:
        return int(match.group(1))
    return None


def _gh_available() -> bool:
    try:
        subprocess.run(["gh", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
