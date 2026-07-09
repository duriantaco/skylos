import os  # skylos: ignore[SKY-Q502] package facade is being split incrementally
import logging
import requests
import subprocess
from skylos.cloud.credentials import get_key
from skylos.reporting.sarif import SarifExporter
import sys
from pathlib import Path
import json
from typing import Any
from uuid import uuid4

from skylos.api._ai_detection import detect_ai_code as _detect_ai_code
from skylos.api._artifacts import (
    UPLOAD_PROTOCOL_VERSION as UPLOAD_PROTOCOL_VERSION,
    PreparedReportUpload,
    UploadArtifact as UploadArtifact,
    _append_skipped_artifact,
    _build_report_artifacts,
    _build_report_complete_payload,
    _build_report_init_idempotency_key as _build_report_init_idempotency_key,
    _build_report_init_payload,
    _build_uploaded_artifact_record,
    _missing_artifact_instruction_result,
    _sha256_file as _sha256_file,
    _write_gzip_json_artifact as _write_gzip_json_artifact,
    upload_artifact,
)
from skylos.api._findings import (
    UPLOAD_FINDING_SPECS,
    VERIFY_FINDING_SPECS,
    _normalize_findings as _normalize_findings,
    _normalize_result_sections,
)
from skylos.api._payloads import (
    _build_legacy_payload,
    _build_report_scan_summary,
    _coerce_debt_snapshot_dict,
    _compact_finding_metadata as _compact_finding_metadata,
    _compact_upload_finding,
    _extract_workspace_upload_metadata,
    _infer_upload_project_root,
    _int_upload_value as _int_upload_value,
    _json_size_bytes,
    _truncate_upload_text as _truncate_upload_text,
)
from skylos.api._snippets import (
    _resolve_snippet_path as _resolve_snippet_path,
    extract_snippet as extract_snippet,
)
from skylos.api._urls import (
    _append_query_param,
    _host_is_private_or_metadata as _host_is_private_or_metadata,
    _normalize_http_url as _normalize_http_url,
    _validate_api_request_url,
    _validate_artifact_upload_url as _validate_artifact_upload_url,
    _validate_github_oidc_request_url,
)

from skylos.constants import (
    NETWORK_TIMEOUT_SHORT,
    NETWORK_TIMEOUT_DEFAULT,
    NETWORK_TIMEOUT_LONG,
    SNIPPET_CONTEXT_LINES as SNIPPET_CONTEXT_LINES,
    SUBPROCESS_TIMEOUT,
    UPLOAD_TIMEOUT,
)

logger = logging.getLogger(__name__)

LINK_FILE = ".skylos/link.json"
GLOBAL_CREDS_FILE = Path.home() / ".skylos" / "credentials.json"

__all__ = [
    "BASE_URL",
    "REPORT_URL",
    "REPORT_INIT_URL",
    "REPORT_COMPLETE_URL",
    "WHOAMI_URL",
    "VERIFY_URL",
    "AGENT_RUNS_URL",
    "UPLOAD_PROTOCOL_VERSION",
    "LINK_FILE",
    "GLOBAL_CREDS_FILE",
    "_detect_ci",
    "_extract_pr_number",
    "_normalize_branch",
    "_read_json",
    "_get_repo_root_for_link",
    "_normalize_http_url",
    "_host_is_private_or_metadata",
    "_validate_api_request_url",
    "_validate_artifact_upload_url",
    "_validate_github_oidc_request_url",
    "_append_query_param",
    "_try_github_oidc_token",
    "get_project_token",
    "get_project_info",
    "get_credit_balance",
    "print_credit_status",
    "get_git_root",
    "_resolve_repo_link_path",
    "_load_repo_link",
    "_current_repo_subpath",
    "_linked_project_id_for_current_path",
    "get_git_info",
    "_resolve_snippet_path",
    "extract_snippet",
    "_build_auth_headers",
    "_truthy_env",
    "_legacy_inline_upload_limit_bytes",
    "_json_size_bytes",
    "_cli_version",
    "_new_upload_client_session_id",
    "_sha256_file",
    "UploadArtifact",
    "PreparedReportUpload",
    "_write_gzip_json_artifact",
    "detect_ai_code",
    "_get_blame_map",
    "_normalize_findings",
    "_normalize_result_sections",
    "_prepare_report_upload",
    "_coerce_debt_snapshot_dict",
    "_prepare_debt_upload",
    "_annotate_findings_with_blame",
    "_detect_report_provenance_data",
    "_infer_upload_project_root",
    "_extract_workspace_upload_metadata",
    "_build_report_metadata",
    "_truncate_upload_text",
    "_compact_finding_metadata",
    "_int_upload_value",
    "_compact_upload_finding",
    "_build_compatibility_inline_payload",
    "_build_legacy_payload",
    "_build_report_scan_summary",
    "_build_report_init_idempotency_key",
    "_build_report_artifacts",
    "_build_report_init_payload",
    "_finalize_report_upload",
    "_post_json_with_retries",
    "_post_report_payload",
    "_looks_like_server_error",
    "_build_large_upload_protocol_error",
    "_build_compatibility_upload_too_large_error",
    "upload_artifact",
    "upload_report_legacy",
    "upload_report_compatibility",
    "_missing_artifact_instruction_result",
    "_append_skipped_artifact",
    "_build_uploaded_artifact_record",
    "_build_report_complete_payload",
    "upload_report_v2",
    "upload_report",
    "upload_debt_report",
    "_should_use_legacy_inline_report_upload",
    "_should_retry_with_degraded_large_upload",
    "upload_defense_report",
    "upload_agent_run",
    "verify_report",
]


def _detect_ci():
    if os.getenv("GITHUB_ACTIONS") == "true":
        return "github_actions", {
            "run_id": os.getenv("GITHUB_RUN_ID"),
            "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
            "workflow": os.getenv("GITHUB_WORKFLOW"),
            "actor": os.getenv("GITHUB_ACTOR"),
            "repo": os.getenv("GITHUB_REPOSITORY"),
            "ref": os.getenv("GITHUB_REF"),
            "sha": os.getenv("GITHUB_SHA"),
        }

    if os.getenv("JENKINS_URL") or os.getenv("BUILD_NUMBER"):
        return "jenkins", {
            "build_number": os.getenv("BUILD_NUMBER"),
            "build_url": os.getenv("BUILD_URL"),
            "job_name": os.getenv("JOB_NAME"),
            "change_id": os.getenv("CHANGE_ID"),
            "change_branch": os.getenv("CHANGE_BRANCH"),
            "change_target": os.getenv("CHANGE_TARGET"),
            "git_branch": os.getenv("GIT_BRANCH"),
            "git_commit": os.getenv("GIT_COMMIT"),
        }

    if os.getenv("CIRCLECI") == "true":
        return "circleci", {
            "build_num": os.getenv("CIRCLE_BUILD_NUM"),
            "workflow_id": os.getenv("CIRCLE_WORKFLOW_ID"),
            "username": os.getenv("CIRCLE_USERNAME"),
            "branch": os.getenv("CIRCLE_BRANCH"),
            "sha1": os.getenv("CIRCLE_SHA1"),
            "pr_url": os.getenv("CIRCLE_PULL_REQUEST"),
        }

    if os.getenv("GITLAB_CI") == "true":
        return "gitlab", {
            "pipeline_id": os.getenv("CI_PIPELINE_ID"),
            "job_id": os.getenv("CI_JOB_ID"),
            "commit_sha": os.getenv("CI_COMMIT_SHA"),
            "commit_branch": os.getenv("CI_COMMIT_BRANCH"),
            "merge_request_iid": os.getenv("CI_MERGE_REQUEST_IID"),
            "user_login": os.getenv("GITLAB_USER_LOGIN"),
        }

    return None, {}


def _parse_optional_int(value: Any) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_pr_number(provider, meta):
    env_pr = _parse_optional_int(os.getenv("SKYLOS_PR_NUMBER"))
    if env_pr is not None:
        return env_pr

    if provider == "github_actions":
        ref = os.getenv("GITHUB_REF", "")
        if ref.startswith("refs/pull/"):
            parts = ref.split("/")
            pr_number = _parse_optional_int(parts[2] if len(parts) > 2 else None)
            if pr_number is not None:
                return pr_number

    if provider == "jenkins":
        pr_number = _parse_optional_int(meta.get("change_id"))
        if pr_number is not None:
            return pr_number

    if provider == "circleci":
        pr_url = meta.get("pr_url") or ""
        if "/pull/" in pr_url:
            pr_number = _parse_optional_int(
                pr_url.split("/pull/")[-1].strip().rstrip("/")
            )
            if pr_number is not None:
                return pr_number

    if provider == "gitlab":
        pr_number = _parse_optional_int(meta.get("merge_request_iid"))
        if pr_number is not None:
            return pr_number

    return None


def _normalize_branch(branch):
    if not branch or not isinstance(branch, str):
        return branch
    branch = branch.removeprefix("refs/heads/")
    branch = branch.removeprefix("origin/")
    return branch


def _read_json(path: Path):
    try:
        if path and _is_bounded_regular_file(path):
            return json.loads(path.read_text(encoding="utf-8"))  # skylos: ignore[SKY-D325] _is_bounded_regular_file rejects symlinks and caps size
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return None


def _is_bounded_regular_file(path: Path, *, max_bytes: int = 1_000_000) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    return path.stat().st_size <= max_bytes


def _get_repo_root_for_link():
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
        )
        p = out.decode().strip()
        if p:
            return Path(p)
    except (subprocess.SubprocessError, OSError):
        pass
    return Path.cwd()


BASE_URL = os.getenv("SKYLOS_API_URL", "https://skylos.dev").rstrip("/")

if BASE_URL.endswith("/api"):
    REPORT_URL = f"{BASE_URL}/report"
    REPORT_INIT_URL = f"{BASE_URL}/report/init"
    REPORT_COMPLETE_URL = f"{BASE_URL}/report/complete"
    WHOAMI_URL = f"{BASE_URL}/sync/whoami"
else:
    REPORT_URL = f"{BASE_URL}/api/report"
    REPORT_INIT_URL = f"{BASE_URL}/api/report/init"
    REPORT_COMPLETE_URL = f"{BASE_URL}/api/report/complete"
    WHOAMI_URL = f"{BASE_URL}/api/sync/whoami"

if BASE_URL.endswith("/api"):
    VERIFY_URL = f"{BASE_URL}/verify"
    AGENT_RUNS_URL = f"{BASE_URL}/agent-runs"
else:
    VERIFY_URL = f"{BASE_URL}/api/verify"
    AGENT_RUNS_URL = f"{BASE_URL}/api/agent-runs"


def _try_github_oidc_token():
    oidc_url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
    oidc_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not oidc_url or not oidc_token:
        return None
    try:
        oidc_url = _append_query_param(
            _validate_github_oidc_request_url(oidc_url),
            "audience",
            "skylos",
        )
        resp = requests.get(
            oidc_url,
            headers={"Authorization": f"Bearer {oidc_token}"},
            timeout=SUBPROCESS_TIMEOUT,
        )
        if resp.status_code == 200:
            jwt_token = resp.json().get("value")
            if jwt_token:
                return f"oidc:{jwt_token}"
    except (OSError, ValueError):
        logger.debug("Failed to fetch GitHub OIDC token", exc_info=True)
    return None


def get_project_token() -> str | None:
    token = os.getenv("SKYLOS_TOKEN")
    if token:
        return token

    oidc = _try_github_oidc_token()
    if oidc:
        return oidc

    repo_root = _get_repo_root_for_link()
    link_path = repo_root / LINK_FILE
    link = _read_json(link_path) or {}
    linked_project_id = _linked_project_id_for_current_path(link, repo_root)

    creds = _read_json(GLOBAL_CREDS_FILE) or {}

    if linked_project_id:
        tokens_map = creds.get("tokens") or {}
        entry = tokens_map.get(linked_project_id) or {}
        t = entry.get("token")
        if t:
            return t

    legacy = creds.get("token")
    if legacy:
        return legacy

    return get_key("skylos_token")


def get_project_info(token) -> dict | None:
    if not token:
        return None
    if token.startswith("oidc:"):
        return None
    try:
        resp = requests.get(
            WHOAMI_URL,
            headers={"Authorization": f"Bearer {token}"},
            timeout=SUBPROCESS_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()
    except (OSError, ValueError):
        logger.debug("Failed to get project info", exc_info=True)
    return None


def get_credit_balance(token=None) -> dict | None:
    if token is None:
        token = get_project_token()
    if not token or token.startswith("oidc:"):
        return None
    try:
        resp = requests.get(
            _validate_api_request_url(f"{BASE_URL}/api/credits/balance"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=SUBPROCESS_TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json()
    except (OSError, ValueError):
        logger.debug("Failed to get credit balance", exc_info=True)
    return None


def print_credit_status(token=None, quiet=False):
    data = get_credit_balance(token)
    if not data or quiet:
        return data

    balance = data.get("balance", 0)
    plan = data.get("plan", "free")

    if plan == "enterprise":
        print("Credits: unlimited (Enterprise)")
    else:
        print(f"Credits: {balance:,}")
        if balance < 10:
            print(f"Low credits! Buy more: {BASE_URL}/dashboard/billing")

    return data


def get_git_root() -> str | None:
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
    except (subprocess.SubprocessError, OSError):
        return None


def _resolve_repo_link_path(git_root) -> Path | None:
    if not git_root:
        return None
    root = Path(git_root).resolve()
    candidate = (root / ".skylos" / "link.json").resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _load_repo_link(git_root):
    try:
        p = _resolve_repo_link_path(git_root)
        if p is None:
            return {}
        if not p.exists():
            return {}

        return json.loads(p.read_text(encoding="utf-8") or "{}")
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _current_repo_subpath(git_root) -> str:
    try:
        if not git_root:
            return ""
        from skylos.cloud.project_context import repo_subpath_for_project

        return repo_subpath_for_project(Path.cwd(), git_root)
    except (ImportError, OSError, ValueError) as exc:
        logger.debug("Failed to resolve current repo subpath: %s", exc)
        return ""


def _linked_project_id_for_current_path(link: dict, git_root) -> str | None:
    repo_subpath = _current_repo_subpath(git_root)
    projects = link.get("projects") if isinstance(link, dict) else None
    if isinstance(projects, dict):
        entry = projects.get(repo_subpath)
        if isinstance(entry, dict):
            project_id = entry.get("project_id") or entry.get("projectId")
            if project_id:
                return str(project_id)

    project_id = link.get("project_id") or link.get("projectId")
    return str(project_id) if project_id else None


def get_git_info() -> tuple[str, str, str, dict]:
    override_sha = os.getenv("SKYLOS_COMMIT")
    override_branch = os.getenv("SKYLOS_BRANCH")
    override_actor = os.getenv("SKYLOS_ACTOR")
    provider, meta = _detect_ci()
    git_commit, git_branch = _read_git_head()
    commit = override_sha or _ci_commit(meta) or git_commit or "unknown"
    branch = override_branch or _ci_branch(provider, meta) or git_branch or "unknown"
    actor = override_actor or _ci_actor(meta) or os.getenv("USER") or "unknown"
    branch = _normalize_branch(branch)
    pr_number = _extract_pr_number(provider, meta)
    return commit, branch, actor, _build_ci_metadata(provider, meta, pr_number)


def _ci_commit(meta: dict) -> str | None:
    return (
        meta.get("sha")
        or meta.get("git_commit")
        or meta.get("sha1")
        or meta.get("commit_sha")
    )


def _ci_branch(provider: str | None, meta: dict) -> str | None:
    branch = (
        meta.get("change_branch")
        or meta.get("git_branch")
        or meta.get("branch")
        or meta.get("commit_branch")
    )
    if branch or provider != "github_actions":
        return branch
    ref = meta.get("ref") or ""
    return ref if ref.startswith("refs/heads/") else None


def _ci_actor(meta: dict) -> str | None:
    return meta.get("actor") or meta.get("username") or meta.get("user_login")


def _read_git_head() -> tuple[str | None, str | None]:
    try:
        git_commit = (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
        git_branch = (
            subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
        return git_commit, git_branch
    except (subprocess.SubprocessError, OSError):
        return None, None


def _build_ci_metadata(provider: str | None, meta: dict, pr_number: int | None) -> dict:
    ci = {"provider": provider} if provider else {}
    ci.update({key: value for key, value in meta.items() if value})
    if pr_number:
        ci["pr_number"] = pr_number
    return ci


def _build_auth_headers(token):
    if token and token.startswith("oidc:"):
        return {
            "Authorization": f"Bearer {token[5:]}",
            "X-Skylos-Auth": "oidc",
        }
    return {"Authorization": f"Bearer {token}"}


def _truthy_env(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _legacy_inline_upload_limit_bytes() -> int:
    raw = os.getenv("SKYLOS_INLINE_UPLOAD_LIMIT_BYTES", "4000000").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 4_000_000
    return max(value, 1)


def _cli_version() -> str | None:
    try:
        from skylos import __version__

        return str(__version__)
    except (ImportError, AttributeError) as exc:
        logger.debug("Failed to read Skylos package version: %s", exc)
        return None


def _new_upload_client_session_id() -> str:
    override = os.getenv("SKYLOS_UPLOAD_SESSION_ID", "").strip()
    if override:
        return override
    return f"cli-{uuid4()}"


def detect_ai_code(git_root=None) -> dict:
    return _detect_ai_code(git_root, get_git_root_func=get_git_root)


def _get_blame_map(findings: list, git_root: str | None) -> dict:
    if not git_root:
        return {}
    blame_map = {}
    for file_path, lines in _collect_finding_lines(findings).items():
        blame_map.update(_get_file_blame_map(git_root, file_path, lines))
    return blame_map


def _collect_finding_lines(findings: list) -> dict:
    from collections import defaultdict

    files_lines = defaultdict(set)
    for f in findings:
        fp = f.get("file_path", "")
        ln = f.get("line_number", 0)
        if fp and ln and ln > 0:
            files_lines[fp].add(ln)
    return files_lines


def _get_file_blame_map(git_root: str, file_path: str, lines: set[int]) -> dict:
    abs_path = os.path.join(git_root, file_path)
    if not os.path.isfile(abs_path):
        return {}

    try:
        out = subprocess.check_output(
            _build_blame_command(file_path, lines),
            cwd=git_root,
            stderr=subprocess.DEVNULL,
            timeout=NETWORK_TIMEOUT_DEFAULT,
        ).decode("utf-8", errors="ignore")
    except (subprocess.SubprocessError, OSError):
        return {}
    return _parse_blame_output(file_path, out)


def _build_blame_command(file_path: str, lines: set[int]) -> list[str]:
    cmd = ["git", "blame", "--porcelain"]
    for line in sorted(lines):
        cmd.extend(["-L", f"{line},{line}"])
    cmd.extend(["--", file_path])
    return cmd


def _parse_blame_output(file_path: str, output: str) -> dict:
    blame_map = {}
    current_line = None
    for raw in output.splitlines():
        parsed_line = _parse_blame_line_number(raw)
        if parsed_line is not None:
            current_line = parsed_line
            continue
        if raw.startswith("author-mail ") and current_line is not None:
            email = raw[len("author-mail ") :].strip().strip("<>")
            if email and email != "not.committed.yet":
                blame_map[(file_path, current_line)] = email
    return blame_map


def _parse_blame_line_number(raw: str) -> int | None:
    parts = raw.split()
    if len(parts) < 3 or len(parts[0]) != 40:
        return None
    try:
        return int(parts[2])
    except ValueError:
        return None


def _prepare_report_upload(
    result_json,
    *,
    is_forced=False,
    analysis_mode="static",
    scan_bundle_id=None,
) -> PreparedReportUpload:
    commit, branch, actor, ci = get_git_info()
    git_root = get_git_root()
    project_root = _infer_upload_project_root(result_json, git_root)

    all_findings = _normalize_result_sections(
        result_json,
        UPLOAD_FINDING_SPECS,
        git_root,
        extract_metadata=True,
    )
    _annotate_findings_with_blame(all_findings, git_root)

    exporter = SarifExporter(all_findings, tool_name="Skylos")
    core_payload = exporter.generate()

    ai_code = detect_ai_code(git_root)
    if isinstance(result_json, dict) and "provenance" in result_json:
        raw_provenance = result_json.get("provenance")
        provenance_data = raw_provenance if isinstance(raw_provenance, dict) else None
    else:
        provenance_data = _detect_report_provenance_data(git_root)

    definitions = result_json.get("definitions")
    grade_data = result_json.get("grade") if isinstance(result_json, dict) else None
    workspace_data = _extract_workspace_upload_metadata(result_json)
    link = _load_repo_link(git_root)
    project_id = link.get("project_id")

    metadata = _build_report_metadata(
        commit_hash=commit,
        branch=branch,
        actor=actor,
        is_forced=is_forced,
        ci=ci,
        analysis_mode=analysis_mode,
        ai_code=ai_code,
        provenance_data=provenance_data,
        grade_data=grade_data,
        project_id=project_id,
        scan_bundle_id=scan_bundle_id,
        project_root=project_root,
        workspace_data=workspace_data,
    )
    core_payload.update(metadata)
    legacy_payload = _build_legacy_payload(core_payload, definitions)
    compatibility_payload = _build_compatibility_inline_payload(
        all_findings,
        result_json,
        metadata,
    )
    scan_summary = _build_report_scan_summary(all_findings, core_payload, definitions)

    return PreparedReportUpload(
        legacy_payload=legacy_payload,
        core_payload=core_payload,
        compatibility_payload=compatibility_payload,
        definitions_payload={"definitions": definitions} if definitions else None,
        metadata=metadata,
        scan_summary=scan_summary,
        grade_data=grade_data,
        legacy_payload_size_bytes=_json_size_bytes(legacy_payload),
        compatibility_payload_size_bytes=_json_size_bytes(compatibility_payload),
    )


DEBT_UPLOAD_HOTSPOT_LIMIT = 50
DEBT_UPLOAD_SIGNAL_LIMIT = 5
DEBT_UPLOAD_CHANGED_FILE_SAMPLE_LIMIT = 25


def _debt_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _debt_int(value: Any, fallback: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        try:
            return max(0, int(float(value)))
        except (TypeError, ValueError):
            return fallback


def _debt_hotspot_sort_key(hotspot: dict[str, Any]) -> tuple[float, float, str]:
    return (
        -_debt_float(hotspot.get("priority_score") or hotspot.get("score")),
        -_debt_float(hotspot.get("score")),
        str(hotspot.get("file") or ""),
    )


def _compact_debt_hotspot(
    hotspot: Any,
    *,
    signal_limit: int = DEBT_UPLOAD_SIGNAL_LIMIT,
) -> dict[str, Any] | None:
    if not isinstance(hotspot, dict):
        return None

    compact = dict(hotspot)
    signals = hotspot.get("signals")
    if isinstance(signals, list):
        compact["signals"] = signals[: max(0, signal_limit)]
    elif "signals" in compact:
        compact["signals"] = []
    return compact


def _compact_debt_hotspots_for_upload(
    hotspots: Any,
    *,
    hotspot_limit: int = DEBT_UPLOAD_HOTSPOT_LIMIT,
    signal_limit: int = DEBT_UPLOAD_SIGNAL_LIMIT,
) -> tuple[list[dict[str, Any]], int]:
    if not isinstance(hotspots, list):
        return [], 0

    valid_hotspots = [item for item in hotspots if isinstance(item, dict)]
    ordered = sorted(valid_hotspots, key=_debt_hotspot_sort_key)
    compacted = [
        compact
        for compact in (
            _compact_debt_hotspot(item, signal_limit=signal_limit)
            for item in ordered[: max(0, hotspot_limit)]
        )
        if compact is not None
    ]
    return compacted, len(valid_hotspots)


def _compact_debt_summary_for_upload(
    summary: Any,
    *,
    uploaded_hotspot_count: int,
    total_hotspot_count: int,
    project_hotspot_count: int | None = None,
) -> dict[str, Any]:
    compact = dict(summary) if isinstance(summary, dict) else {}

    changed_files = compact.get("changed_files")
    if isinstance(changed_files, list):
        compact["changed_file_count"] = len(changed_files)
        compact["changed_file_sample"] = [
            str(item)[:500]
            for item in changed_files[:DEBT_UPLOAD_CHANGED_FILE_SAMPLE_LIMIT]
        ]
        compact.pop("changed_files", None)

    upload_policy = {
        "hotspot_limit": DEBT_UPLOAD_HOTSPOT_LIMIT,
        "signal_limit_per_hotspot": DEBT_UPLOAD_SIGNAL_LIMIT,
        "changed_file_sample_limit": DEBT_UPLOAD_CHANGED_FILE_SAMPLE_LIMIT,
        "uploaded_hotspot_count": uploaded_hotspot_count,
        "total_hotspot_count": total_hotspot_count,
        "omitted_hotspot_count": max(total_hotspot_count - uploaded_hotspot_count, 0),
        "ranking": "priority_score desc, score desc, file asc",
    }
    if project_hotspot_count is not None:
        upload_policy["project_hotspot_count"] = project_hotspot_count
    compact["upload_policy"] = upload_policy
    return compact


def _prepare_debt_upload(
    debt_report, *, is_forced=False, scan_bundle_id=None
) -> PreparedReportUpload:
    commit, branch, actor, ci = get_git_info()
    git_root = get_git_root()
    project_root = _infer_upload_project_root(debt_report, git_root)
    link = _load_repo_link(git_root)
    project_id = link.get("project_id")

    debt_payload = _coerce_debt_snapshot_dict(debt_report)
    raw_debt_score = debt_payload.get("score")
    debt_score = raw_debt_score if isinstance(raw_debt_score, dict) else {}
    raw_debt_summary = debt_payload.get("summary") or {}
    debt_hotspots, total_hotspot_count = _compact_debt_hotspots_for_upload(
        debt_payload.get("hotspots") or []
    )
    score_hotspot_count = _debt_int(
        debt_score.get("hotspot_count"),
        fallback=total_hotspot_count or len(debt_hotspots),
    )
    debt_summary = _compact_debt_summary_for_upload(
        raw_debt_summary,
        uploaded_hotspot_count=len(debt_hotspots),
        total_hotspot_count=total_hotspot_count,
        project_hotspot_count=score_hotspot_count,
    )

    metadata = _build_report_metadata(
        commit_hash=commit,
        branch=branch,
        actor=actor,
        is_forced=is_forced,
        ci=ci,
        analysis_mode="debt",
        project_id=project_id,
        scan_bundle_id=scan_bundle_id,
        project_root=project_root,
    )

    core_payload = {
        "tool": "skylos-debt",
        "summary": {
            "debt_score_pct": int(debt_score.get("score_pct") or 100),
            "debt_hotspots": score_hotspot_count,
            "debt_hotspots_uploaded": len(debt_hotspots),
            "debt_hotspots_omitted": max(total_hotspot_count - len(debt_hotspots), 0),
            "debt_signals": int(debt_score.get("signal_count") or 0),
            "files_scanned": int(debt_payload.get("files_scanned") or 0),
            "total_loc": int(debt_payload.get("total_loc") or 0),
        },
        "findings": [],
        "debt_score": debt_score,
        "debt_summary": debt_summary,
        "debt_hotspots": debt_hotspots,
        "debt_version": debt_payload.get("version"),
        "debt_timestamp": debt_payload.get("timestamp"),
    }
    core_payload.update(metadata)

    scan_summary = {
        "finding_count": 0,
        "sarif_result_count": 0,
        "sarif_rule_count": 0,
        "definitions_count": 0,
        "debt_hotspot_count": score_hotspot_count,
        "debt_hotspot_upload_count": len(debt_hotspots),
        "debt_signal_count": int(debt_score.get("signal_count") or 0),
    }

    return PreparedReportUpload(
        legacy_payload=dict(core_payload),
        core_payload=core_payload,
        compatibility_payload=dict(core_payload),
        definitions_payload=None,
        metadata=metadata,
        scan_summary=scan_summary,
        grade_data=None,
        legacy_payload_size_bytes=_json_size_bytes(core_payload),
        compatibility_payload_size_bytes=_json_size_bytes(core_payload),
    )


def _annotate_findings_with_blame(all_findings: list[dict], git_root) -> None:
    blame_map = _get_blame_map(all_findings, git_root)
    for finding in all_findings:
        email = blame_map.get((finding["file_path"], finding.get("line_number", 0)))
        if email:
            metadata = finding.get("metadata") or {}
            metadata["blame_email"] = email
            finding["metadata"] = metadata


def _detect_report_provenance_data(git_root):
    provenance_data = None
    try:
        from skylos.reporting.provenance import analyze_provenance

        prov_report = analyze_provenance(git_root)
        if prov_report.agent_files:
            provenance_data = prov_report.to_dict()
    except (ImportError, subprocess.SubprocessError, OSError):
        logger.debug("Provenance detection failed", exc_info=True)
    return provenance_data


def _build_report_metadata(
    *,
    commit_hash,
    branch,
    actor,
    is_forced=False,
    ci=None,
    analysis_mode="static",
    ai_code=None,
    provenance_data=None,
    grade_data=None,
    project_id=None,
    scan_bundle_id=None,
    project_root=None,
    workspace_data=None,
    upload_client_session_id=None,
    cli_version=None,
) -> dict[str, Any]:
    metadata = {
        "commit_hash": commit_hash,
        "branch": branch,
        "actor": actor,
        "is_forced": bool(is_forced),
        "ci": ci,
        "analysis_mode": analysis_mode,
        "ai_code": ai_code if ai_code and ai_code.get("detected") else None,
        "provenance": provenance_data,
        "upload_client_session_id": upload_client_session_id
        or _new_upload_client_session_id(),
        "cli_version": cli_version or _cli_version(),
    }
    if grade_data:
        metadata["grade"] = grade_data
    if project_id:
        metadata["project_id"] = project_id
    if scan_bundle_id:
        metadata["scan_bundle_id"] = str(scan_bundle_id)
    if project_root is not None:
        metadata["project_root"] = str(project_root)
    if workspace_data:
        metadata["workspaces"] = workspace_data
    return metadata


def _build_compatibility_inline_payload(
    all_findings: list[dict[str, Any]],
    result_json: Any,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    result = result_json if isinstance(result_json, dict) else {}
    summary = result.get("analysis_summary")
    if not isinstance(summary, dict):
        summary = {}

    payload = {
        **metadata,
        "tool": "skylos",
        "summary": summary,
        "findings": [
            _compact_upload_finding(finding, include_snippet=True)
            for finding in all_findings
        ],
    }

    if _json_size_bytes(payload) <= _legacy_inline_upload_limit_bytes():
        return payload

    payload["findings"] = [
        _compact_upload_finding(finding, include_snippet=False)
        for finding in all_findings
    ]
    return payload


def _finalize_report_upload(
    response,
    *,
    grade_data,
    quiet=False,
    strict=False,
    is_forced=False,
) -> dict:
    error_result = _report_upload_error_result(response)
    if error_result:
        return error_result

    data = response.json()
    scan_id = data.get("scanId") or data.get("scan_id")
    quality_gate = data.get("quality_gate", {})
    passed = quality_gate.get("passed", True)
    new_violations = quality_gate.get("new_violations", 0)
    plan = data.get("plan", "free")

    if not quiet:
        _print_report_upload_success(
            grade_data=grade_data,
            passed=passed,
            new_violations=new_violations,
            plan=plan,
            scan_id=scan_id,
            credits_left=data.get("credits_remaining"),
        )
    _enforce_report_quality_gate(passed, strict=strict, is_forced=is_forced, quiet=quiet)
    return _report_upload_success_result(data, scan_id, passed, plan)


def _report_upload_error_result(response) -> dict | None:
    if response.status_code == 401:
        return {
            "success": False,
            "error": "Invalid API token. Run 'skylos login' to reconnect or 'skylos sync connect' to set a token manually.",
        }
    if response.status_code != 402:
        return None
    data = _safe_response_json(response)
    return {
        "success": False,
        "error": data.get(
            "error",
            "No credits remaining. Buy more at skylos.dev/dashboard/credits",
        ),
        "code": "NO_CREDITS",
    }


def _safe_response_json(response) -> dict:
    try:
        data = response.json()
    except (ValueError, KeyError):
        return {}
    return data if isinstance(data, dict) else {}


def _print_report_upload_success(
    *,
    grade_data,
    passed: bool,
    new_violations: int,
    plan: str,
    scan_id: str | None,
    credits_left,
) -> None:
    print(" done!\n✓ Scan uploaded")
    _print_report_grade(grade_data)
    _print_quality_gate_result(passed, new_violations, plan)
    if scan_id:
        print(f"\nView: {BASE_URL}/dashboard/scans/{scan_id}")
        print(f"\n🔗 View details: {BASE_URL}/dashboard/scans/{scan_id}")
    _print_credit_balance_after_upload(credits_left)


def _print_report_grade(grade_data) -> None:
    if grade_data:
        grade = grade_data["overall"]
        print(f"Grade: {grade['letter']} ({grade['score']}/100)")


def _print_quality_gate_result(passed: bool, new_violations: int, plan: str) -> None:
    if passed:
        print("✅ PASS Quality gate: PASSED")
        return
    suffix = "" if new_violations == 1 else "s"
    print(f"❌ FAIL Quality gate: FAILED ({new_violations} new violation{suffix})")
    if plan == "free":
        print("\n⚠️  Quality gate failed but continuing (Free plan)")
        print("💡 Upgrade to Pro to automatically block commits/CI on failures")
        print(f"   Learn more: {BASE_URL}/dashboard/settings?upgrade=true")


def _print_credit_balance_after_upload(credits_left) -> None:
    if credits_left is None:
        return
    if credits_left < 50:
        print(
            f"\n⚠️  Credits remaining: {credits_left}. Top up at skylos.dev/dashboard/billing"
        )
        return
    print(f"\n💰 Credits remaining: {credits_left}")


def _enforce_report_quality_gate(
    passed: bool,
    *,
    strict: bool,
    is_forced: bool,
    quiet: bool,
) -> None:
    if passed:
        return
    if strict and not is_forced:
        if not quiet:
            print("\n Commit blocked by quality gate")
        sys.exit(1)
    if not quiet:
        print("\n⚠️ Quality gate failed, but not enforcing in local mode.")


def _report_upload_success_result(
    data: dict,
    scan_id: str | None,
    passed: bool,
    plan: str,
) -> dict:
    return {
        "success": True,
        "scan_id": scan_id,
        "quality_gate_passed": passed,
        "plan": plan,
        "credits_warning": data.get("credits_warning", False),
    }


def _post_json_with_retries(
    url,
    headers,
    payload,
    *,
    quiet=False,
    initial_message=None,
    accepted_statuses=(200, 201, 401, 402),
    timeout=NETWORK_TIMEOUT_LONG,
):
    try:
        safe_url = _validate_api_request_url(url)
    except ValueError as exc:
        return None, f"Unsafe API URL: {exc}"

    last_err = None
    for attempt in range(3):
        try:
            if not quiet:
                if attempt == 0 and initial_message:
                    print(initial_message, end="", flush=True)
                elif attempt > 0:
                    print(f" retrying ({attempt + 1}/3)...", end="", flush=True)
            response = requests.post(
                safe_url,
                json=payload,
                headers=headers,
                timeout=timeout,
            )
            if response.status_code in accepted_statuses:
                return response, None
            if not quiet and response.status_code >= 400:
                print(" failed.")
            last_err = f"Server Error {response.status_code}: {response.text}"
        except requests.exceptions.RequestException as e:
            last_err = f"Connection Error: {str(e)}"

    return None, last_err or "Unknown error"


def _post_report_payload(token, payload, *, quiet=False, initial_message=None):
    return _post_json_with_retries(
        REPORT_URL,
        _build_auth_headers(token),
        payload,
        quiet=quiet,
        initial_message=initial_message,
        timeout=UPLOAD_TIMEOUT,
    )


def _looks_like_server_error(error: str | None) -> bool:
    return bool(error and error.startswith("Server Error 5"))


def _build_large_upload_protocol_error(
    prepared: PreparedReportUpload,
    detail: str | None = None,
) -> dict:
    limit = _legacy_inline_upload_limit_bytes()
    error = (
        "Connected Skylos Cloud endpoint does not support large scan uploads yet. "
        f"This scan requires artifact upload because the inline payload is "
        f"{prepared.legacy_payload_size_bytes} bytes and the client safety limit is "
        f"{limit} bytes. Upgrade the Skylos Cloud endpoint to support "
        f"{REPORT_INIT_URL} and {REPORT_COMPLETE_URL}."
    )
    if detail:
        error += f" Artifact init failed with: {detail}"
    return {
        "success": False,
        "error": error,
        "code": "UPLOAD_PROTOCOL_UNSUPPORTED",
    }


def _build_compatibility_upload_too_large_error(
    prepared: PreparedReportUpload,
) -> dict[str, Any]:
    limit = _legacy_inline_upload_limit_bytes()
    return {
        "success": False,
        "error": (
            "Skylos Cloud artifact upload is unavailable, and the compact "
            f"compatibility payload is {prepared.compatibility_payload_size_bytes} "
            f"bytes, above the client safety limit of {limit} bytes."
        ),
        "code": "UPLOAD_COMPATIBILITY_PAYLOAD_TOO_LARGE",
    }


def upload_report_legacy(
    token,
    payload,
    *,
    grade_data,
    quiet=False,
    strict=False,
    is_forced=False,
    initial_message: str | None = "Uploading scan results...",
) -> dict:
    response, last_err = _post_report_payload(
        token,
        payload,
        quiet=quiet,
        initial_message=initial_message,
    )
    if response is None:
        return {"success": False, "error": last_err or "Unknown error"}
    return _finalize_report_upload(
        response,
        grade_data=grade_data,
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
    )


def upload_report_compatibility(
    token,
    prepared: PreparedReportUpload,
    *,
    quiet=False,
    strict=False,
    is_forced=False,
    initial_message=None,
) -> dict:
    if prepared.compatibility_payload_size_bytes > _legacy_inline_upload_limit_bytes():
        return _build_compatibility_upload_too_large_error(prepared)
    return upload_report_legacy(
        token,
        prepared.compatibility_payload,
        grade_data=prepared.grade_data,
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
        initial_message=initial_message,
    )


def upload_report_v2(
    token,
    prepared: PreparedReportUpload,
    *,
    quiet=False,
    strict=False,
    is_forced=False,
) -> dict:
    artifacts = _build_report_artifacts(prepared)
    try:
        init_result = _start_report_artifact_upload(
            token,
            prepared,
            artifacts,
            quiet,
            strict=strict,
            is_forced=is_forced,
        )
        if init_result.get("complete"):
            return init_result["result"]

        artifact_result = _upload_report_artifacts(
            artifacts,
            init_result["artifact_instructions"],
            init_result.get("skipped_artifacts"),
        )
        if not artifact_result.get("success", True):
            return artifact_result

        complete_response = _complete_report_artifact_upload(
            token,
            init_result["init_data"],
            artifact_result["uploaded_artifacts"],
            artifact_result["skipped_artifacts"],
            prepared.metadata,
        )
        if complete_response.get("error"):
            return complete_response["error"]
        return _finalize_report_upload(
            complete_response["response"],
            grade_data=prepared.grade_data,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
        )
    finally:
        for artifact in artifacts.values():
            artifact.cleanup()


def _start_report_artifact_upload(
    token,
    prepared: PreparedReportUpload,
    artifacts: dict,
    quiet: bool,
    *,
    strict: bool,
    is_forced: bool,
) -> dict[str, Any]:
    skipped_artifacts = []
    initial_message = "Uploading scan results..."

    while True:
        init_response, last_err = _post_json_with_retries(
            REPORT_INIT_URL,
            _build_auth_headers(token),
            _build_report_init_payload(prepared, artifacts),
            quiet=quiet,
            initial_message=initial_message,
            accepted_statuses=(200, 201, 400, 401, 402, 404, 405, 501),
        )
        if _retry_artifact_init_without_optional_artifact(
            init_response,
            artifacts,
            skipped_artifacts,
        ):
            initial_message = None
            continue
        break

    if init_response is None:
        if _looks_like_server_error(last_err):
            return {
                "complete": True,
                "result": _build_large_upload_protocol_error(prepared, last_err),
            }
        return {
            "complete": True,
            "result": {"success": False, "error": last_err or "Unknown error"},
        }
    if init_response.status_code in (404, 405, 501):
        return {"complete": True, "result": _build_large_upload_protocol_error(prepared)}
    if init_response.status_code == 400:
        return {
            "complete": True,
            "result": _build_report_init_error(init_response),
        }
    if init_response.status_code in (401, 402):
        return {
            "complete": True,
            "result": _finalize_report_upload(
                init_response,
                grade_data=prepared.grade_data,
                quiet=quiet,
                strict=strict,
                is_forced=is_forced,
            ),
        }
    init_data = init_response.json() or {}
    artifact_instructions = init_data.get("artifacts") or {}
    if not isinstance(artifact_instructions, dict):
        return {
            "complete": True,
            "result": {
                "success": False,
                "error": "Invalid large-upload response: missing artifact instructions.",
            },
        }
    return {
        "complete": False,
        "init_data": init_data,
        "artifact_instructions": artifact_instructions,
        "skipped_artifacts": skipped_artifacts,
    }


def _retry_artifact_init_without_optional_artifact(
    init_response,
    artifacts: dict,
    skipped_artifacts: list,
) -> bool:
    artifact_name = _unsupported_optional_artifact_name(init_response, artifacts)
    if artifact_name is None:
        return False

    artifact = artifacts.pop(artifact_name)
    artifact.cleanup()
    _append_skipped_artifact(skipped_artifacts, artifact_name, "unsupported")
    return True


def _unsupported_optional_artifact_name(init_response, artifacts: dict) -> str | None:
    if init_response is None:
        return None
    if init_response.status_code != 400:
        return None

    message = _report_init_error_message(init_response)
    if "Unsupported artifact" not in message:
        return None

    for artifact_name, artifact in artifacts.items():
        if artifact.required:
            continue
        single_quoted_name = f"'{artifact_name}'"
        double_quoted_name = f'"{artifact_name}"'
        if single_quoted_name in message or double_quoted_name in message:
            return artifact_name
    return None


def _report_init_error_message(response) -> str:
    parts = []
    try:
        data = response.json()
    except (TypeError, ValueError):
        data = {}

    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, str):
            parts.append(error)
        code = data.get("code")
        if isinstance(code, str):
            parts.append(code)

    text = getattr(response, "text", "")
    if isinstance(text, str):
        parts.append(text)
    return " ".join(parts)


def _build_report_init_error(response) -> dict[str, Any]:
    error = f"Server Error {response.status_code}: {response.text}"
    result = {
        "success": False,
        "error": error,
    }
    try:
        data = response.json()
    except (TypeError, ValueError):
        data = {}
    if isinstance(data, dict) and isinstance(data.get("code"), str):
        result["code"] = data["code"]
    return result


def _upload_report_artifacts(
    artifacts: dict,
    artifact_instructions: dict,
    skipped_artifacts: list | None = None,
) -> dict[str, Any]:
    uploaded_artifacts = {}
    if skipped_artifacts is None:
        skipped_artifacts = []
    else:
        skipped_artifacts = list(skipped_artifacts)
    for artifact_name, artifact in artifacts.items():
        result = _upload_one_report_artifact(
            artifact_name,
            artifact,
            artifact_instructions,
            skipped_artifacts,
        )
        if not result.get("success", True):
            return result
        if result.get("uploaded_record"):
            uploaded_artifacts[artifact_name] = result["uploaded_record"]
    return {
        "success": True,
        "uploaded_artifacts": uploaded_artifacts,
        "skipped_artifacts": skipped_artifacts,
    }


def _upload_one_report_artifact(
    artifact_name: str,
    artifact,
    artifact_instructions: dict,
    skipped_artifacts: list,
) -> dict[str, Any]:
    artifact_info = artifact_instructions.get(artifact_name)
    if not artifact_info:
        return _handle_missing_report_artifact(artifact_name, artifact, skipped_artifacts)

    upload_spec = artifact_info.get("upload") or artifact_info
    upload_result = upload_artifact(artifact, upload_spec)
    if not upload_result["success"]:
        return _handle_failed_report_artifact(
            artifact_name,
            artifact,
            upload_result,
            skipped_artifacts,
        )
    return {
        "success": True,
        "uploaded_record": _build_uploaded_artifact_record(
            artifact,
            artifact_info,
            upload_result,
        ),
    }


def _handle_missing_report_artifact(
    artifact_name: str,
    artifact,
    skipped_artifacts: list,
) -> dict[str, Any]:
    missing_result = _missing_artifact_instruction_result(artifact_name, artifact)
    if not missing_result.get("success", True):
        return missing_result
    _append_skipped_artifact(skipped_artifacts, artifact_name, missing_result["reason"])
    return {"success": True}


def _handle_failed_report_artifact(
    artifact_name: str,
    artifact,
    upload_result: dict,
    skipped_artifacts: list,
) -> dict[str, Any]:
    if artifact.required:
        return {"success": False, "error": upload_result["error"]}
    _append_skipped_artifact(
        skipped_artifacts,
        artifact_name,
        "upload_failed",
        upload_result["error"],
    )
    return {"success": True}


def _complete_report_artifact_upload(
    token,
    init_data: dict,
    uploaded_artifacts: dict,
    skipped_artifacts: list,
    metadata: dict,
) -> dict[str, Any]:
    complete_response, last_err = _post_json_with_retries(
        REPORT_COMPLETE_URL,
        _build_auth_headers(token),
        _build_report_complete_payload(
            init_data,
            uploaded_artifacts,
            skipped_artifacts,
            metadata,
        ),
        quiet=True,
        accepted_statuses=(200, 201, 401, 402),
        timeout=UPLOAD_TIMEOUT,
    )
    if complete_response is None:
        return {"error": {"success": False, "error": last_err or "Unknown error"}}
    return {"response": complete_response}


def upload_report(
    result_json,
    is_forced=False,
    quiet=False,
    strict=False,
    analysis_mode="static",
    scan_bundle_id=None,
) -> dict:
    token = get_project_token()
    if not token:
        return {
            "success": False,
            "error": "No token found. Run 'skylos login' or 'skylos project use', or set SKYLOS_TOKEN.",
        }

    if not quiet:
        info = get_project_info(token)
        if info and info.get("ok"):
            project_name = info.get("project", {}).get("name", "Unknown")
            print(f"Uploading to: {project_name}")

    prepared = _prepare_report_upload(
        result_json,
        is_forced=is_forced,
        analysis_mode=analysis_mode,
        scan_bundle_id=scan_bundle_id,
    )

    if _should_use_legacy_inline_report_upload(prepared):
        return upload_report_legacy(
            token,
            prepared.legacy_payload,
            grade_data=prepared.grade_data,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
        )

    upload_result = upload_report_v2(
        token,
        prepared,
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
    )
    if _should_retry_with_degraded_large_upload(upload_result):
        if not quiet:
            print(
                " Skylos Cloud artifact upload unavailable; retrying compact compatibility upload...",
                end="",
                flush=True,
            )
        return upload_report_compatibility(
            token,
            prepared,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
            initial_message=None,
        )
    return upload_result


def upload_debt_report(
    debt_report,
    *,
    is_forced=False,
    quiet=False,
    strict=False,
    scan_bundle_id=None,
) -> dict:
    token = get_project_token()
    if not token:
        return {
            "success": False,
            "error": "No token found. Run 'skylos login' or 'skylos project use', or set SKYLOS_TOKEN.",
        }

    if not quiet:
        info = get_project_info(token)
        if info and info.get("ok"):
            project_name = info.get("project", {}).get("name", "Unknown")
            print(f"Uploading to: {project_name}")

    prepared = _prepare_debt_upload(
        debt_report,
        is_forced=is_forced,
        scan_bundle_id=scan_bundle_id,
    )

    if _should_use_legacy_inline_report_upload(prepared):
        return upload_report_legacy(
            token,
            prepared.legacy_payload,
            grade_data=prepared.grade_data,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
            initial_message="Uploading debt results...",
        )

    upload_result = upload_report_v2(
        token,
        prepared,
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
    )
    if _should_retry_with_degraded_large_upload(upload_result):
        if not quiet:
            print(
                " Skylos Cloud artifact upload unavailable; retrying compact compatibility upload...",
                end="",
                flush=True,
            )
        return upload_report_compatibility(
            token,
            prepared,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
            initial_message="Uploading debt results...",
        )
    return upload_result


def _should_use_legacy_inline_report_upload(
    prepared: PreparedReportUpload,
) -> bool:
    return prepared.legacy_payload_size_bytes <= _legacy_inline_upload_limit_bytes()


def _should_retry_with_degraded_large_upload(upload_result: dict[str, Any]) -> bool:
    return (not upload_result.get("success")) and upload_result.get(
        "code"
    ) == "UPLOAD_PROTOCOL_UNSUPPORTED"


def upload_defense_report(defense_json_str, quiet=False, scan_bundle_id=None) -> dict:
    """Upload defense scan results to the cloud dashboard."""
    token = get_project_token()
    if not token:
        return {
            "success": False,
            "error": "No token found. Run 'skylos login' or 'skylos project use', or set SKYLOS_TOKEN.",
        }

    defense_data, error = _parse_defense_upload_data(defense_json_str)
    if error:
        return error

    payload = _build_defense_upload_payload(defense_data, scan_bundle_id)

    response, last_err = _post_report_payload(
        token,
        payload,
        quiet=quiet,
        initial_message="Uploading defense results...",
    )
    if response is None:
        if not quiet:
            print(" failed.")
        return {"success": False, "error": last_err or "Unknown error"}

    error_result = _defense_upload_error_result(response, quiet)
    if error_result:
        return error_result

    if not quiet:
        _print_defense_upload_success(defense_data, response)

    scan_id = _response_scan_id(response)
    return {
        "success": True,
        "scan_id": scan_id,
    }


def _parse_defense_upload_data(defense_json_str) -> tuple[dict | None, dict | None]:
    try:
        return json.loads(defense_json_str), None
    except (ValueError, TypeError) as exc:
        return None, {"success": False, "error": f"Invalid defense JSON: {exc}"}


def _build_defense_upload_payload(
    defense_data: dict,
    scan_bundle_id=None,
) -> dict[str, Any]:
    commit, branch, actor, ci = get_git_info()
    git_root = get_git_root()
    link = _load_repo_link(git_root)
    payload = _base_defense_upload_payload(defense_data, commit, branch, actor, ci)
    project_root = _infer_upload_project_root(defense_data, git_root)
    if project_root is not None:
        payload["project_root"] = project_root
    if link.get("project_id"):
        payload["project_id"] = link["project_id"]
    if scan_bundle_id:
        payload["scan_bundle_id"] = str(scan_bundle_id)
    return payload


def _base_defense_upload_payload(
    defense_data: dict,
    commit: str,
    branch: str,
    actor: str,
    ci: dict,
) -> dict[str, Any]:
    return {
        "commit_hash": commit,
        "branch": branch,
        "actor": actor,
        "ci": ci,
        "upload_client_session_id": _new_upload_client_session_id(),
        "cli_version": _cli_version(),
        "tool": "skylos-defend",
        "summary": {},
        "findings": [],
        "defense_score": defense_data.get("summary"),
        "ops_score": defense_data.get("ops_score"),
        "owasp_coverage": defense_data.get("owasp_coverage"),
        "defense_findings": defense_data.get("findings", []),
        "defense_integrations": defense_data.get("integrations", []),
        "attestation": defense_data.get("attestation"),
        "framework_evidence": defense_data.get("framework_evidence"),
        "skylos_version": defense_data.get("skylos_version"),
    }


def _defense_upload_error_result(response, quiet: bool) -> dict | None:
    if response.status_code not in (401, 402):
        return None
    if not quiet:
        print(" failed.")
    if response.status_code == 401:
        return {
            "success": False,
            "error": "Invalid API token. Run 'skylos login' to reconnect or 'skylos sync connect' to set a token manually.",
        }
    return {
        "success": False,
        "error": "No credits remaining. Buy more at skylos.dev/dashboard/credits",
        "code": "NO_CREDITS",
    }


def _print_defense_upload_success(defense_data: dict, response) -> None:
    data = _safe_response_json(response)
    scan_id = data.get("scanId") or data.get("scan_id")
    score = defense_data.get("summary", {})
    print(" done!")
    print("✓ Defense scan uploaded")
    print(
        f"  Defense Score: {score.get('score_pct', 0)}% ({score.get('risk_rating', 'UNKNOWN')})"
    )
    if scan_id:
        print(f"\n🔗 View: {BASE_URL}/dashboard/scans/{scan_id}")
    credits_left = data.get("credits_remaining")
    if credits_left is not None and credits_left < 50:
        print(
            f"\n⚠️  Credits remaining: {credits_left}. Top up at skylos.dev/dashboard/billing"
        )


def _response_scan_id(response) -> str | None:
    data = _safe_response_json(response)
    return data.get("scanId") or data.get("scan_id")


def upload_agent_run(
    command,
    summary,
    *,
    model=None,
    provider=None,
    duration_seconds=None,
    status="completed",
):
    """Upload agent run telemetry to the cloud dashboard. Fire-and-forget."""
    try:
        token = get_project_token()
        if not token:
            return

        commit, branch, actor, _ci = get_git_info()

        payload = {
            "command": command,
            "summary": summary or {},
            "model": model,
            "provider": provider,
            "duration_seconds": duration_seconds,
            "commit_hash": commit,
            "branch": branch,
            "actor": actor,
            "status": status,
        }

        requests.post(
            AGENT_RUNS_URL,
            json=payload,
            headers=_build_auth_headers(token),
            timeout=NETWORK_TIMEOUT_SHORT,
        )
    except Exception as exc:
        logger.debug("Failed to upload agent run telemetry: %s", exc)


def verify_report(result_json, quiet=False) -> dict:
    token = get_project_token()
    if not token:
        return {
            "success": False,
            "error": "Verification requires a valid Skylos token. Run 'skylos login' or set SKYLOS_TOKEN.",
        }

    if not _token_allows_verification(token):
        return {
            "success": False,
            "error": "Verification requires Skylos Pro. Upgrade to enable --verify.",
        }

    commit, branch, actor, ci = get_git_info()
    git_root = get_git_root()

    findings = _normalize_result_sections(
        result_json,
        VERIFY_FINDING_SPECS,
        git_root,
        default_severity="LOW",
        generate_finding_id=True,
    )

    if not findings:
        return {"success": False, "error": "No security findings to verify."}

    response = _post_verification_request(token, commit, branch, actor, findings)
    if response.get("error"):
        return response["error"]

    data = response["response"].json() or {}
    results = data.get("results") or []
    _merge_verification_results(result_json, results)
    verdict_counts = _verification_verdict_counts(results)

    if not quiet:
        _print_verification_counts(verdict_counts)

    return {"success": True, "counts": verdict_counts}


def _token_allows_verification(token: str) -> bool:
    info = get_project_info(token) or {}
    plan = (info.get("plan") or "free").lower()
    return plan in ["pro", "enterprise", "beta"]


def _post_verification_request(
    token: str,
    commit: str,
    branch: str,
    actor: str,
    findings: list[dict],
) -> dict[str, Any]:
    payload = {
        "commit_hash": commit,
        "branch": branch,
        "actor": actor,
        "findings": findings,
    }
    try:
        response = requests.post(
            VERIFY_URL,
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=UPLOAD_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        return {
            "error": {
                "success": False,
                "error": f"Verification connection failed: {exc}",
            }
        }
    error = _verification_error_response(response)
    return {"error": error} if error else {"response": response}


def _verification_error_response(response) -> dict | None:
    if response.status_code in (401, 403):
        return {
            "success": False,
            "error": "Verification denied (token invalid or not paid).",
        }
    if response.status_code == 402:
        return {
            "success": False,
            "error": "Verification requires Skylos Pro (payment required).",
        }
    if response.status_code != 200:
        return {
            "success": False,
            "error": f"Verifier error {response.status_code}: {response.text[:2000]}",
        }
    return None


def _merge_verification_results(result_json: dict, results: list[dict]) -> None:
    by_id = _verification_results_by_id(results)
    _merge_verified_items(result_json.get("danger", []), by_id)
    _merge_verified_items(result_json.get("secrets", []), by_id)


def _verification_results_by_id(results: list[dict]) -> dict:
    return {
        finding_id: result
        for result in results
        for finding_id in [result.get("finding_id") or result.get("id")]
        if finding_id
    }


def _merge_verified_items(items, by_id: dict) -> None:
    for item in items or []:
        verification = by_id.get(_verification_item_id(item))
        if verification:
            item["verification"] = verification


def _verification_item_id(item: dict) -> str:
    rule_id = str(item.get("rule_id") or item.get("rule") or item.get("code") or "UNKNOWN")
    file_path = (item.get("file_path") or item.get("file") or "unknown").replace(
        "\\", "/"
    )
    line = _coerce_verification_line(item.get("line_number") or item.get("line") or 1)
    return f"{rule_id}::{file_path}::{line}"


def _coerce_verification_line(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 1


def _verification_verdict_counts(results: list[dict]) -> dict[str, int]:
    verdict_counts = {"VERIFIED": 0, "REFUTED": 0, "UNKNOWN": 0}
    for result in results:
        verdict = (result.get("verdict") or "UNKNOWN").upper()
        verdict_counts[verdict if verdict in verdict_counts else "UNKNOWN"] += 1
    return verdict_counts


def _print_verification_counts(verdict_counts: dict[str, int]) -> None:
    print(
        f"Verifier results: ✅{verdict_counts['VERIFIED']}  ❌{verdict_counts['REFUTED']}  ⚠️{verdict_counts['UNKNOWN']}"
    )
