from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from skylos.audit.redaction import redact_text, sanitize_for_audit
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    STATUS_DELETED,
    AuditFileRecord,
    AuditRevalidationSummary,
    normalize_relative_path,
    sha256_text,
    utc_now,
)

VALID_VERDICTS = {"true_positive", "false_positive", "fixed", "uncertain"}
SECURITY_AUDIT_ISSUE = "security_audit"


def revalidate_deep_audit_findings(
    *,
    store: AuditStore,
    verifier: Any,
    model: str,
    provider: str | None = None,
    force: bool = False,
    challenge: bool = False,
    allowed_files: list[str | Path] | None = None,
    limit: int | None = None,
    run_id: str | None = None,
) -> AuditRevalidationSummary:
    run_id = run_id or f"revalidate-{uuid4().hex[:12]}"
    allowed = _normalized_allowed_files(store, allowed_files)
    records = [
        record
        for record in store.iter_file_records()
        if record.findings
        and record.status != STATUS_DELETED
        and (allowed is None or record.file in allowed)
    ]

    considered = 0
    revalidated = 0
    challenged = 0
    skipped = 0
    errors = 0
    verdict_counts = {
        "true_positive": 0,
        "false_positive": 0,
        "fixed": 0,
        "uncertain": 0,
    }

    for record in records:
        current = store.read_file_record(record.file)
        if current is None:
            continue

        if _has_secret_candidate(current):
            skipped += len(current.findings)
            continue

        for finding in list(current.findings):
            if limit is not None and limit >= 0 and revalidated >= limit:
                break
            if not isinstance(finding, dict):
                continue
            finding_id = _finding_id(finding)
            considered += 1
            if challenge and _latest_verdict(current, finding_id) != "uncertain":
                continue
            if not force and _has_current_verdict(
                current,
                finding_id,
                model=model,
                provider=provider,
                challenge=challenge,
            ):
                continue

            try:
                verdict = _verify_finding(
                    verifier,
                    store=store,
                    record=current,
                    finding=finding,
                    mode="challenge" if challenge else "revalidate",
                )
            except Exception as exc:
                verdict = {
                    "verdict": "uncertain",
                    "reason": f"Revalidation failed: {exc}",
                }
                errors += 1

            normalized = _normalize_verdict(verdict)
            entry = sanitize_for_audit(
                {
                    "finding_id": finding_id,
                    "verdict": normalized["verdict"],
                    "reason": normalized["reason"],
                    "model": model,
                    "provider": provider,
                    "run_id": run_id,
                    "mode": "challenge" if challenge else "revalidate",
                    "revalidated_at": utc_now(),
                }
            )
            current.revalidation.append(entry)
            verdict_counts[normalized["verdict"]] += 1
            revalidated += 1
            if challenge:
                challenged += 1

        store.write_file_record(current)

    summary = AuditRevalidationSummary(
        run_id=run_id,
        project_id=store.project_id,
        project_root=str(store.project_root),
        considered_findings=considered,
        revalidated_findings=revalidated,
        challenged_findings=challenged,
        skipped_findings=skipped,
        error_findings=errors,
        true_positive=verdict_counts["true_positive"],
        false_positive=verdict_counts["false_positive"],
        fixed=verdict_counts["fixed"],
        uncertain=verdict_counts["uncertain"],
        forced=force,
        challenge=challenge,
        complete=skipped == 0 and errors == 0,
    )
    store.write_run(
        run_id,
        {
            "mode": "challenge" if challenge else "revalidate",
            "summary": summary.to_dict(),
        },
    )
    return summary


def _normalized_allowed_files(
    store: AuditStore,
    allowed_files: list[str | Path] | None,
) -> set[str] | None:
    if allowed_files is None:
        return None
    allowed: set[str] = set()
    for file_path in allowed_files:
        try:
            allowed.add(normalize_relative_path(store.project_root, file_path))
        except ValueError:
            continue
    return allowed


def _has_secret_candidate(record: AuditFileRecord) -> bool:
    return any(
        candidate.redacted or candidate.rule_id.startswith("SKY-S")
        for candidate in record.candidates
    )


def _finding_id(finding: dict[str, Any]) -> str:
    existing = finding.get("audit_finding_id")
    if existing:
        return str(existing)
    payload = json.dumps(finding, sort_keys=True, default=str)
    return "finding-" + sha256_text(payload)[:16]


def _has_current_verdict(
    record: AuditFileRecord,
    finding_id: str,
    *,
    model: str,
    provider: str | None,
    challenge: bool,
) -> bool:
    mode = "challenge" if challenge else "revalidate"
    return any(
        isinstance(item, dict)
        and str(item.get("finding_id") or "") == finding_id
        and item.get("model") == model
        and item.get("provider") == provider
        and item.get("mode", "revalidate") == mode
        for item in record.revalidation
    )


def _latest_verdict(record: AuditFileRecord, finding_id: str) -> str | None:
    for item in reversed(record.revalidation):
        if not isinstance(item, dict):
            continue
        if str(item.get("finding_id") or "") == finding_id:
            return str(item.get("verdict") or "").lower()
    return None


def _verify_finding(
    verifier: Any,
    *,
    store: AuditStore,
    record: AuditFileRecord,
    finding: dict[str, Any],
    mode: str,
) -> dict[str, Any]:
    context = _build_revalidation_context(store, record, finding, mode=mode)
    verify_finding = getattr(verifier, "verify_finding", None)
    if callable(verify_finding):
        return verify_finding(
            finding=sanitize_for_audit(finding),
            context=context,
            file_path=record.file,
            mode=mode,
        )

    adapter_payload = _verify_with_agent_adapter(verifier, context=context, mode=mode)
    if adapter_payload is not None:
        return adapter_payload

    return {
        "verdict": "uncertain",
        "reason": "No Deep Mode revalidation adapter was available.",
    }


def _build_revalidation_context(
    store: AuditStore,
    record: AuditFileRecord,
    finding: dict[str, Any],
    *,
    mode: str,
) -> dict[str, Any]:
    file_path = store.project_root / record.file
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        source = ""
    return sanitize_for_audit(
        {
            "mode": mode,
            "file": record.file,
            "language": record.language,
            "status": record.status,
            "finding": finding,
            "candidates": [candidate.to_dict() for candidate in record.candidates],
            "analysis_history": record.analysis_history[-5:],
            "redacted_source": redact_text(source),
        }
    )


def _verify_with_agent_adapter(
    verifier: Any,
    *,
    context: dict[str, Any],
    mode: str,
) -> dict[str, Any] | None:
    get_agent = getattr(verifier, "_get_agent", None)
    if not callable(get_agent):
        return None
    agent = get_agent(SECURITY_AUDIT_ISSUE)
    get_adapter = getattr(agent, "get_adapter", None)
    if not callable(get_adapter):
        return None
    adapter = get_adapter()
    complete = getattr(adapter, "complete", None)
    if not callable(complete):
        return None

    system = (
        "You are Skylos Deep Mode revalidator. Return JSON only with keys "
        "verdict and reason. verdict must be one of true_positive, "
        "false_positive, fixed, uncertain."
    )
    user = json.dumps(context, indent=2, sort_keys=True)
    response = complete(system, user)
    if not response:
        return None
    try:
        payload = json.loads(str(response))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _normalize_verdict(payload: dict[str, Any] | None) -> dict[str, str]:
    verdict = str((payload or {}).get("verdict") or "uncertain").lower()
    verdict_map = {
        "supported": "true_positive",
        "true": "true_positive",
        "tp": "true_positive",
        "refuted": "false_positive",
        "false": "false_positive",
        "fp": "false_positive",
    }
    verdict = verdict_map.get(verdict, verdict)
    if verdict not in VALID_VERDICTS:
        verdict = "uncertain"
    reason = str((payload or {}).get("reason") or "").strip()
    if not reason:
        reason = "No reason provided."
    return {"verdict": verdict, "reason": reason}
