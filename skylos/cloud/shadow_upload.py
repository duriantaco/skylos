from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


MAX_SHADOW_CLOUD_UPLOAD_BYTES = 4_000_000


def _selected(record: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    return {key: record[key] for key in keys if key in record}


def _normalized_local_path(value: Any) -> str:
    raw = str(value or "").strip()
    if raw.lower().startswith("file:"):
        parsed = urlparse(raw)
        if parsed.netloc and parsed.netloc.lower() != "localhost":
            raise ValueError("remote file URI")
        raw = parsed.path
    normalized = unquote(raw).replace("\\", "/").rstrip("/")
    # RFC 8089 file URIs encode a Windows drive path as /C:/path. Strip the
    # URI-only leading slash before applying drive-aware containment checks.
    if re.match(r"^/[A-Za-z]:/", normalized):
        normalized = normalized[1:]
    return normalized


def _reject_local_repository_identity(raw: str) -> None:
    normalized_path = raw.replace("\\", "/")
    if (
        normalized_path.startswith("/")
        or re.match(r"^[A-Za-z]:/", normalized_path)
        or normalized_path.startswith(("./", "../"))
        or raw.lower().startswith("file:")
    ):
        raise ValueError("repository identity contains a local path")


def _parse_network_git_remote(raw: str) -> tuple[str, str, bool]:
    scp_match = re.fullmatch(r"[^/@\s]+@([^:\s]+):(.+)", raw)
    if scp_match:
        host, path = scp_match.groups()
        return host, path, True

    scheme_was_explicit = "://" in raw
    parsed = urlparse(raw if scheme_was_explicit else f"https://{raw}")
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "ssh", "git"} or not parsed.hostname:
        raise ValueError("repository identity is not a network Git remote")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("repository identity has an invalid port") from exc
    default_port = {"http": 80, "https": 443, "ssh": 22, "git": 9418}.get(scheme)
    host = parsed.hostname
    if port and port != default_port:
        host = f"{host}:{port}"
    return host, parsed.path, scheme_was_explicit


def _safe_repository_component(value: str) -> bool:
    return (
        bool(value)
        and value not in {".", ".."}
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _canonical_network_repository(
    host: str, path: str, *, scheme_was_explicit: bool
) -> str:
    normalized_host = host.strip().lower()
    normalized_path = unquote(path).replace("\\", "/").strip("/")
    if normalized_path.lower().endswith(".git"):
        normalized_path = normalized_path[:-4]
    path_segments = normalized_path.split("/") if normalized_path else []
    if not _safe_repository_component(normalized_host) or not all(
        _safe_repository_component(segment) for segment in path_segments
    ):
        raise ValueError("repository identity is not a safe network Git remote")
    if not path_segments:
        raise ValueError("repository identity is not a safe network Git remote")
    if (
        not scheme_was_explicit
        and "." not in normalized_host
        and ":" not in normalized_host
    ):
        raise ValueError("repository identity is not a verifiable network Git remote")
    if normalized_host == "github.com":
        normalized_path = normalized_path.lower()
    return f"{normalized_host}/{normalized_path}"


def _cloud_repository_identity(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("repository identity is not a non-empty string")
    raw = value.strip()
    _reject_local_repository_identity(raw)
    host, path, scheme_was_explicit = _parse_network_git_remote(raw)
    return _canonical_network_repository(
        host,
        path,
        scheme_was_explicit=scheme_was_explicit,
    )


def _cloud_repository_identities(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("repository identities must be a list")
    return sorted({_cloud_repository_identity(identity) for identity in value})


def _strip_repository_root(path: str, root: str) -> str:
    if not root or root in {"/", "//"}:
        raise ValueError("absolute evidence path has no safe repository root")
    windows = bool(re.match(r"^[A-Za-z]:/", path) and re.match(r"^[A-Za-z]:/", root))
    compared_path = path.casefold() if windows else path
    compared_root = root.casefold() if windows else root
    if compared_path == compared_root:
        return ""
    if compared_path.startswith(f"{compared_root}/"):
        return path[len(root) + 1 :]
    raise ValueError("evidence path is outside the analyzed repository")


def _validated_relative_path(path: str) -> str:
    while path.startswith("./"):
        path = path[2:]
    segments = path.split("/") if path else []
    if not all(_safe_repository_component(segment) for segment in segments):
        raise ValueError("evidence path is not repository-relative")
    return "/".join(segments)


def _cloud_relative_path(value: Any, repository_root: Any) -> str:
    path = _normalized_local_path(value)
    if not path:
        return ""
    absolute = path.startswith("/") or bool(re.match(r"^[A-Za-z]:/", path))
    if absolute:
        path = _strip_repository_root(path, _normalized_local_path(repository_root))
    return _validated_relative_path(path)


def _cloud_finding(value: Any, repository_root: Any) -> dict[str, Any]:
    finding = _selected(
        value,
        (
            "source_tool",
            "rule_id",
            "line_number",
            "end_line",
            "severity",
            "category",
        ),
    )
    raw = value if isinstance(value, dict) else {}
    finding["file_path"] = _cloud_relative_path(raw.get("file_path"), repository_root)
    shadow = raw.get("shadow")
    if isinstance(shadow, dict):
        reachability = _selected(
            shadow.get("reachability"),
            ("state", "symbol", "start_line", "end_line"),
        )
        raw_reachability = shadow.get("reachability")
        if isinstance(raw_reachability, dict):
            reachability["file_path"] = _cloud_relative_path(
                raw_reachability.get("file_path"), repository_root
            )
        finding["shadow"] = {
            **_selected(
                shadow,
                (
                    "location_overlap",
                    "overlapping_skylos_rules",
                    "benefit_eligible",
                    "benefit_exclusion_reason",
                ),
            ),
            "reachability": reachability,
        }
    return finding


def prepare_shadow_report_for_cloud(  # skylos: ignore[SKY-C304] explicit cloud privacy allowlist
    report: dict[str, Any],
) -> dict[str, Any]:
    """Build a minimal receipt that never sends local paths or scanner prose."""
    scope = report.get("scope") if isinstance(report.get("scope"), dict) else {}
    skylos_scope = scope.get("skylos") if isinstance(scope.get("skylos"), dict) else {}
    incumbent_scope = (
        scope.get("incumbent") if isinstance(scope.get("incumbent"), dict) else {}
    )
    repository_root = skylos_scope.get("repository_root")
    incumbent_source_root = incumbent_scope.get("source_root")
    if isinstance(incumbent_source_root, str) and (
        incumbent_source_root.startswith("/")
        or re.match(r"^[A-Za-z]:[\\/]", incumbent_source_root)
        or incumbent_source_root.lower().startswith("file:")
    ):
        incumbent_source_root = "[redacted-absolute-root]"

    skylos_repository_identities = _cloud_repository_identities(
        skylos_scope.get("repository_identities")
    )
    incumbent_repository_identities = _cloud_repository_identities(
        incumbent_scope.get("repository_identities")
    )

    external = report.get("external")
    skylos = report.get("skylos")
    benefit = report.get("benefit")
    projection = _selected(
        report,
        (
            "schema_version",
            "mode",
            "complete",
            "usable",
            "completeness_state",
            "completeness_reasons",
            "coverage_attested",
        ),
    )
    projection.update(
        {
            "revision": _selected(
                report.get("revision"),
                (
                    "state",
                    "same_revision_verified",
                    "revision_ids_match",
                    "external_revisions",
                    "skylos_revisions",
                    "external_revision_source",
                    "skylos_revision_source",
                    "skylos_worktree_dirty",
                ),
            ),
            "scope": {
                **_selected(
                    scope,
                    (
                        "state",
                        "binding_verified",
                        "repository_identity_match",
                        "incumbent_complete_export_attested",
                    ),
                ),
                "skylos": {
                    **_selected(skylos_scope, ("kind", "complete_repository")),
                    "repository_identities": skylos_repository_identities,
                },
                "incumbent": {
                    **_selected(
                        incumbent_scope,
                        ("complete_repository",),
                    ),
                    "repository_identities": incumbent_repository_identities,
                    "source_root": incumbent_source_root,
                },
            },
            "external": _selected(
                external,
                (
                    "format",
                    "tools",
                    "tool_versions",
                    "revisions",
                    "canonical_json_sha256",
                    "execution_successful",
                    "input_complete",
                    "total_findings",
                    "excluded_findings_count",
                    "by_severity",
                    "by_category",
                ),
            ),
            "skylos": _selected(
                skylos,
                (
                    "total_findings",
                    "by_severity",
                    "by_category",
                    "canonical_json_sha256",
                    "version",
                    "complete",
                    "core_complete",
                    "recognized_result",
                    "comparison_surface_present",
                    "analysis_error_count",
                    "incomplete_languages",
                    "scanned_categories",
                    "incomplete_categories",
                ),
            ),
            "coverage": _selected(
                report.get("coverage"),
                (
                    "observed_external_categories",
                    "skylos_scanned_categories",
                    "observed_comparable_categories",
                    "incomplete_skylos_categories",
                    "uncovered_external_categories",
                    "comparison_incomplete_categories",
                    "coverage_limits_comparison",
                ),
            ),
            "comparison": _selected(
                report.get("comparison"),
                (
                    "location_overlap",
                    "external_only",
                    "skylos_only",
                    "skylos_only_in_observed_comparable_categories",
                    "skylos_only_by_category",
                    "external_in_likely_dead_code",
                    "external_dead_context_excluded_from_benefit",
                    "external_in_live_code",
                    "external_reachability_unknown",
                    "affected_likely_dead_symbols",
                    "affected_unused_files",
                ),
            ),
            "benefit": _selected(
                benefit,
                (
                    "claim_scope",
                    "provisional",
                    "review_or_deletion_candidates",
                    "candidate_symbols",
                    "candidate_files",
                ),
            ),
            "external_findings": [
                _cloud_finding(finding, repository_root)
                for finding in report.get("external_findings", [])
            ],
            "skylos_only_findings": [
                _cloud_finding(finding, repository_root)
                for finding in report.get("skylos_only_findings", [])
            ],
            "limitations": [],
        }
    )
    return projection


def _shadow_reports_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/api"):
        return f"{normalized}/shadow/reports"
    return f"{normalized}/api/shadow/reports"


def _cloud_web_base_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    return normalized[: -len("/api")] if normalized.endswith("/api") else normalized


def _resolve_cloud_web_url(base_url: str, value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    web_base = _cloud_web_base_url(base_url)
    if value.startswith("/") and not value.startswith("//"):
        return f"{web_base}{value}"
    if value.startswith(f"{web_base}/"):
        return value
    return None


def _validated_shadow_payload(
    report: dict[str, Any],
    *,
    context: dict[str, Any],
    cli_version: str,
    upload_client_session_id: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        cloud_report = prepare_shadow_report_for_cloud(report)
    except (TypeError, ValueError) as exc:
        return None, {
            "success": False,
            "error": f"Scanner Proof evidence cannot be safely uploaded: {exc}.",
            "code": "UNSAFE_SHADOW_PATH",
        }
    payload = {
        "project_root": context.get("project_root", ""),
        "cli_version": cli_version,
        "upload_client_session_id": upload_client_session_id,
        "report": cloud_report,
    }
    try:
        payload_size = len(
            # Match requests' `json=` serialization closely so the local
            # check cannot undercount whitespace or escaped Unicode bytes.
            json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
        )
    except (TypeError, ValueError, RecursionError) as exc:
        return None, {
            "success": False,
            "error": f"Scanner Proof report is not serializable: {exc}",
            "code": "INVALID_SHADOW_REPORT",
        }
    if payload_size > MAX_SHADOW_CLOUD_UPLOAD_BYTES:
        return None, {
            "success": False,
            "error": (
                "Scanner Proof uploads are currently limited to "
                "4,000,000 bytes (about 4 MB). "
                "Keep the complete local JSON receipt and upload a smaller comparison."
            ),
            "code": "PAYLOAD_TOO_LARGE",
        }
    return payload, None


def _shadow_response_data(response) -> dict[str, Any]:
    try:
        data = response.json()
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _shadow_upload_response(
    response,
    request_error: str | None,
    *,
    base_url: str,
) -> dict[str, Any]:
    if response is None:
        return {
            "success": False,
            "error": request_error or "Scanner Proof upload failed.",
        }
    data = _shadow_response_data(response)
    upgrade_url = _resolve_cloud_web_url(base_url, data.get("upgrade_url"))
    if response.status_code not in {200, 201}:
        return {
            "success": False,
            "error": str(data.get("error") or f"Server Error {response.status_code}"),
            **({"code": data["code"]} if isinstance(data.get("code"), str) else {}),
            **({"upgrade_url": upgrade_url} if upgrade_url else {}),
        }
    view_url = _resolve_cloud_web_url(base_url, data.get("view_url"))
    return {
        "success": True,
        **data,
        **({"view_url": view_url} if view_url else {}),
    }


def _upload_shadow_report(
    report: dict[str, Any],
    *,
    project_path: str | Path,
    api,
    project_context_for_upload,
    upload_timeout: int,
) -> dict[str, Any]:
    token = api.get_project_token()
    if not token:
        return {
            "success": False,
            "error": (
                "No token found. Run 'skylos login' or 'skylos project use', "
                "or set SKYLOS_TOKEN."
            ),
            "code": "NO_TOKEN",
        }

    context = project_context_for_upload(project_path, api.get_git_root())
    payload, payload_error = _validated_shadow_payload(
        report,
        context=context,
        cli_version=api._cli_version(),
        upload_client_session_id=api._new_upload_client_session_id(),
    )
    if payload_error is not None:
        return payload_error

    auth_headers = api._build_auth_headers(token)
    auth_headers["X-Skylos-Project-Root"] = str(context.get("project_root") or ".")
    response, request_error = api._post_json_with_retries(
        _shadow_reports_url(api.BASE_URL),
        auth_headers,
        payload,
        quiet=True,
        accepted_statuses=(200, 201, 400, 401, 402, 403, 409, 413, 429),
        timeout=upload_timeout,
    )
    return _shadow_upload_response(
        response,
        request_error,
        base_url=api.BASE_URL,
    )


def upload_shadow_report(
    report: dict[str, Any],
    *,
    project_path: str | Path = ".",
) -> dict[str, Any]:
    """Upload a bounded Scanner Proof receipt using the normal project identity."""
    import skylos.api as api
    from skylos.cloud.project_context import project_context_for_upload
    from skylos.constants import UPLOAD_TIMEOUT

    return _upload_shadow_report(
        report,
        project_path=project_path,
        api=api,
        project_context_for_upload=project_context_for_upload,
        upload_timeout=UPLOAD_TIMEOUT,
    )
