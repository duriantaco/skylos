"""Best-effort upload of statically discovered application controls."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import requests

from skylos.analysis.fastapi_controls import discover_fastapi_controls_for_scan
from skylos.api._urls import _validate_api_request_url
from skylos.constants import NETWORK_TIMEOUT_SHORT


logger = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_MAX_IMPORT_BODY_BYTES = 4_500_000


def _registry_url(base_url: str) -> str:
    root = str(base_url).rstrip("/")
    suffix = (
        "/control-registry/import"
        if root.endswith("/api")
        else "/api/control-registry/import"
    )
    return _validate_api_request_url(f"{root}{suffix}")


def _status(
    name: str,
    *,
    discovered: int,
    imported: int = 0,
    skipped: int = 0,
    missing: int | None = None,
    registry_updated: bool | None = None,
    snapshot_complete: bool | None = None,
    reported_snapshot_complete: bool | None = None,
    authoritative: bool | None = None,
    lifecycle_updated: bool | None = None,
    idempotent_replay: bool | None = None,
    noop_reason: str | None = None,
    truncated: bool = False,
    reason: str | None = None,
    required_plan: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": name,
        "discovered_controls": max(0, int(discovered)),
        "imported_controls": max(0, int(imported)),
        "skipped_controls": max(0, int(skipped)),
        "truncated": bool(truncated),
    }
    if reason:
        result["reason"] = reason[:100]
    if required_plan:
        result["required_plan"] = required_plan[:40]
    if missing is not None:
        result["missing_controls"] = max(0, int(missing))
    if registry_updated is not None:
        result["registry_updated"] = bool(registry_updated)
    if snapshot_complete is not None:
        result["snapshot_complete"] = bool(snapshot_complete)
    if reported_snapshot_complete is not None:
        result["reported_snapshot_complete"] = bool(reported_snapshot_complete)
    if authoritative is not None:
        result["authoritative"] = bool(authoritative)
    if lifecycle_updated is not None:
        result["lifecycle_updated"] = bool(lifecycle_updated)
    if idempotent_replay is not None:
        result["idempotent_replay"] = bool(idempotent_replay)
    if noop_reason:
        result["noop_reason"] = noop_reason[:100]
    return result


def _nonnegative_int(value: object, fallback: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return max(0, fallback)


def capture_scan_controls(result_json: object) -> dict[str, Any]:
    """Capture discovery before a slow upload can outlive source state."""

    try:
        discovery = discover_fastapi_controls_for_scan(result_json)
    except Exception:
        logger.debug("FastAPI control discovery failed", exc_info=True)
        discovery = None
    if not isinstance(discovery, dict):
        return {
            "controls": [],
            "status": "unavailable",
            "reason": "discovery_failed",
            "complete": False,
        }
    return discovery


def _bounded_payload(
    *,
    controls: list[dict],
    scan_id: str,
    commit_hash: object,
    branch: object,
    snapshot_complete: bool,
) -> tuple[dict[str, Any], bool]:
    base = {
        "source": "skylos",
        "scan_id": scan_id,
        "commit_hash": str(commit_hash)[:200],
        "branch": str(branch)[:200],
    }

    def payload_for(count: int, *, complete: bool) -> dict[str, Any]:
        return {
            **base,
            "snapshot_complete": complete,
            "controls": controls[:count],
        }

    payload = payload_for(len(controls), complete=snapshot_complete)
    if (
        len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        <= _MAX_IMPORT_BODY_BYTES
    ):
        return payload, False

    # A bounded subset can update observations, but it must never retire
    # controls which may have been omitted from this request.
    low, high = 0, len(controls)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = payload_for(middle, complete=False)
        size = len(json.dumps(candidate, separators=(",", ":")).encode("utf-8"))
        if size <= _MAX_IMPORT_BODY_BYTES:
            low = middle
        else:
            high = middle - 1
    return payload_for(low, complete=False), low < len(controls)


def import_scan_controls(
    result_json: object,
    *,
    scan_id: object,
    commit_hash: object,
    branch: object,
    base_url: str,
    auth_headers: dict[str, str],
    project_root: object = None,
    discovery_snapshot: object = None,
) -> dict[str, Any]:
    """Discover and import controls without changing scan-upload success."""

    normalized_scan_id = str(scan_id or "").strip()
    if not _UUID_RE.fullmatch(normalized_scan_id):
        return _status(
            "skipped",
            discovered=0,
            reason="missing_or_invalid_scan_id",
        )
    normalized_commit = (
        str(commit_hash).strip()[:200] if isinstance(commit_hash, str) else ""
    )
    normalized_branch = str(branch).strip()[:200] if isinstance(branch, str) else ""
    if not normalized_commit or not normalized_branch:
        return _status(
            "skipped",
            discovered=0,
            reason="missing_git_identity",
        )

    discovery = (
        capture_scan_controls(result_json)
        if discovery_snapshot is None
        else discovery_snapshot
    )
    if not isinstance(discovery, dict) or discovery.get("status") == "unavailable":
        return _status("unavailable", discovered=0, reason="discovery_failed")

    controls = discovery.get("controls")
    if not isinstance(controls, list):
        controls = []
    discovery_truncated = bool(discovery.get("truncated"))
    if discovery.get("status") == "skipped":
        return _status(
            "skipped",
            discovered=0,
            truncated=discovery_truncated,
            reason=str(discovery.get("reason") or "unsupported_scope"),
        )
    discovery_complete = bool(discovery.get("complete")) and not discovery_truncated
    if not controls and not discovery_complete:
        return _status(
            "not_detected",
            discovered=0,
            registry_updated=False,
            snapshot_complete=False,
            truncated=discovery_truncated,
        )

    payload, body_truncated = _bounded_payload(
        controls=controls,
        scan_id=normalized_scan_id,
        commit_hash=normalized_commit,
        branch=normalized_branch,
        snapshot_complete=discovery_complete,
    )
    sent_controls = payload["controls"]
    truncated = discovery_truncated or body_truncated
    headers = dict(auth_headers)
    if isinstance(project_root, str):
        headers["X-Skylos-Project-Root"] = project_root

    try:
        response = requests.post(
            _registry_url(base_url),
            headers=headers,
            json=payload,
            timeout=NETWORK_TIMEOUT_SHORT,
        )
    except (OSError, ValueError, requests.RequestException):
        logger.debug("Control Registry import unavailable", exc_info=True)
        return _status(
            "unavailable",
            discovered=len(controls),
            snapshot_complete=bool(payload.get("snapshot_complete")),
            truncated=truncated,
            reason="request_failed",
        )

    try:
        data = response.json()
    except (TypeError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    if response.status_code in {200, 201} and data.get("success") is True:
        missing_count = _nonnegative_int(data.get("missing_controls"))
        imported_count = _nonnegative_int(
            data.get("stored_controls", data.get("imported_controls"))
        )
        skipped_count = _nonnegative_int(data.get("skipped_controls"))
        authoritative = (
            data.get("lifecycle_authoritative") is True
            or data.get("authoritative") is True
        )
        effective_snapshot_complete = data.get("snapshot_complete") is True
        registry_updated = data.get("registry_updated") is True
        lifecycle_updated = data.get("lifecycle_updated") is True
        idempotent_replay = data.get("idempotent_replay") is True
        noop_reason = data.get("noop_reason")
        if not isinstance(noop_reason, str) or not noop_reason.strip():
            noop_reason = "idempotent_replay" if idempotent_replay else None
        common = {
            "discovered": len(controls),
            "imported": imported_count,
            "skipped": skipped_count + max(0, len(controls) - len(sent_controls)),
            "missing": missing_count,
            "registry_updated": registry_updated,
            "snapshot_complete": effective_snapshot_complete,
            "reported_snapshot_complete": bool(payload.get("snapshot_complete")),
            "authoritative": authoritative,
            "lifecycle_updated": lifecycle_updated,
            "idempotent_replay": idempotent_replay,
            "noop_reason": noop_reason,
            "truncated": truncated,
        }
        if idempotent_replay:
            return _status("unchanged", **common)
        if not authoritative:
            return _status("recorded", **common)
        if not controls:
            return _status("not_detected", **common)
        return _status(
            "imported",
            **common,
        )

    code = str(data.get("code") or "").strip().upper()
    if response.status_code == 403 and code == "PLAN_REQUIRED":
        return _status(
            "plan_required",
            discovered=len(controls),
            snapshot_complete=bool(payload.get("snapshot_complete")),
            truncated=truncated,
            reason="paid_workspace_required",
            required_plan=str(data.get("required_plan") or "pro"),
        )
    if response.status_code in {400, 401, 403, 409, 413, 422}:
        return _status(
            "rejected",
            discovered=len(controls),
            snapshot_complete=bool(payload.get("snapshot_complete")),
            truncated=truncated,
            reason=(code.lower() if code else f"http_{response.status_code}"),
        )
    return _status(
        "unavailable",
        discovered=len(controls),
        snapshot_complete=bool(payload.get("snapshot_complete")),
        truncated=truncated,
        reason=f"http_{response.status_code}",
    )


def format_control_registry_status(status: object) -> str | None:
    if not isinstance(status, dict):
        return None
    state = status.get("status")
    discovered = int(status.get("discovered_controls") or 0)
    imported = int(status.get("imported_controls") or 0)
    missing = int(status.get("missing_controls") or 0)
    lifecycle_updated = bool(status.get("lifecycle_updated"))
    snapshot_complete = status.get("snapshot_complete")
    reported_snapshot_complete = status.get(
        "reported_snapshot_complete", snapshot_complete
    )
    truncated = bool(status.get("truncated"))
    suffix = (
        " (bounded partial snapshot; existing entries retained)"
        if truncated
        else " (partial snapshot; existing entries retained)"
        if reported_snapshot_complete is False
        else ""
    )
    if state == "imported":
        noun = "control" if imported == 1 else "controls"
        message = (
            f"Control Registry: stored {imported} FastAPI {noun} from this "
            f"trusted default-branch CI scan{suffix}."
        )
        if missing:
            missing_noun = "control" if missing == 1 else "controls"
            message += f" Marked {missing} previously seen {missing_noun} as missing."
        return message
    if state == "unchanged":
        return (
            "Control Registry: this scan receipt was already processed; "
            "the shared registry is unchanged."
        )
    if state == "recorded":
        noun = "control" if discovered == 1 else "controls"
        observed = (
            f"found {discovered} FastAPI {noun}"
            if discovered
            else "found no FastAPI access controls"
        )
        reason = status.get("noop_reason")
        explanation = {
            "not_trusted_default_branch": (
                "only trusted default-branch CI scans can update it"
            ),
            "incomplete_project_scope": (
                "this upload did not cover the complete project"
            ),
            "stale_or_equal_scan": (
                "an equally recent or newer trusted scan is already recorded"
            ),
        }.get(str(reason), "this scan was not an authoritative registry update")
        return (
            f"Control Registry: {observed}; scan receipt recorded. The shared "
            f"registry is unchanged because {explanation}{suffix}."
        )
    if state == "not_detected":
        if lifecycle_updated:
            message = (
                "Control Registry: no FastAPI access controls found in this "
                "trusted complete scan; registry snapshot recorded."
            )
        elif snapshot_complete is False:
            message = (
                "Control Registry: no FastAPI access controls found in this "
                "partial scan; registry unchanged."
            )
        else:
            message = f"Control Registry: no FastAPI access controls found{suffix}."
        if missing:
            noun = "control" if missing == 1 else "controls"
            message += f" Marked {missing} previously seen {noun} as missing."
        return message
    if state == "plan_required":
        noun = "control" if discovered == 1 else "controls"
        return (
            f"Control Registry: found {discovered} FastAPI {noun}; a paid "
            f"workspace is required to import them{suffix}."
        )
    if state in {"rejected", "unavailable"}:
        noun = "control" if discovered == 1 else "controls"
        return (
            f"Control Registry: found {discovered} FastAPI {noun}, but the "
            f"registry import is unavailable; the scan remains uploaded{suffix}."
        )
    return None


__all__ = [
    "capture_scan_controls",
    "format_control_registry_status",
    "import_scan_controls",
]
