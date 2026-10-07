import os  # skylos: ignore[SKY-Q502] package facade is being split incrementally
import contextlib
import logging
import requests
import signal
import subprocess
import threading
import time
from requests import Request as _RequestsRequest
from requests import exceptions as _request_exceptions
from skylos.cloud.credentials import get_key
from skylos.reporting.sarif import SarifExporter
import sys
from pathlib import Path
import json
import re
from typing import Any
from uuid import uuid4

from skylos.api._ai_detection import detect_ai_code as _detect_ai_code
from skylos.core import ci_env as _ci_env
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
    _restore_report_artifacts,
    _sha256_file as _sha256_file,
    _snapshot_report_artifacts,
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
from skylos.api._source_revision import source_revision_state
from skylos.api._scan_coverage import (
    architecture_advisory_summary,
    quality_rule_classification,
    scan_coverage_receipt,
)
from skylos.api._contract_check import (
    contract_check_url as _contract_check_url,
    newer_contract_notice as _newer_contract_notice,
    start_contract_version_check as _start_contract_version_check,
)
from skylos.api._pending_uploads import (
    TOO_OLD_REASON as _TOO_OLD_REASON,
    count_pending_uploads as _count_pending_uploads,
    decode_request_body as _decode_request_body,
    delete_pending_upload as _delete_pending_upload,
    is_within_resend_window as _pending_within_resend_window,
    legacy_pending_uploads as _legacy_pending_uploads,
    list_pending_uploads as _list_pending_uploads,
    mark_pending_upload_failed as _mark_pending_upload_failed,
    pending_uploads_dir as _pending_uploads_dir,
    save_pending_upload as _save_pending_upload,
)
from skylos.api._upload_contract import (
    client_read_timeout_seconds as _client_read_timeout_seconds,
)
from skylos.api._upload_paths import upload_location_uri
from skylos.api._upload_preflight import apply_upload_contract, strip_secret_snippets
from skylos.api._upload_transport import (
    SAVED_HINT as _SAVED_HINT,
    RetryPolicy,
    UploadFailure,
    UploadSession,
    backoff_delay as _backoff_delay,
    conflict_delay as _conflict_delay,
    is_retryable_conflict as _is_retryable_conflict,
    describe_http_failure as _describe_http_failure,
    describe_transport_exception as _describe_transport_exception,
    is_idempotent_replay as _is_idempotent_replay,
    is_retryable_transport_exception as _is_retryable_transport_exception,
    should_retry_now as _should_retry_now,
    upload_contract_headers as _upload_contract_headers,
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
    NETWORK_TIMEOUT_DEFAULT,
    NETWORK_TIMEOUT_SHORT,
    NETWORK_TIMEOUT_LONG,
    SNIPPET_CONTEXT_LINES as SNIPPET_CONTEXT_LINES,
    SUBPROCESS_TIMEOUT,
    UPLOAD_TIMEOUT,
)
from skylos.core.git_context import GitContext
from skylos.core.git_safety import (
    read_only_git_command,
    read_only_git_environment,
)
from skylos.core.safe_cache_io import read_text_no_symlink

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
    "_try_gitlab_oidc_token",
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
    "resend_pending_uploads",
    "RetryPolicy",
    "UploadFailure",
    "UploadSession",
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

    # Checked before Jenkins: its BUILD_NUMBER marker is generic enough to be
    # set by hand in other CIs, while these markers are provider-specific.
    if _ci_env.is_bitbucket_pipelines():
        return _ci_env.BITBUCKET_PIPELINES, _ci_env.bitbucket_pipelines_metadata()

    if _ci_env.is_azure_pipelines():
        return _ci_env.AZURE_PIPELINES, _ci_env.azure_pipelines_metadata()

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
            # Routing hints only. Cloud must independently verify the signed
            # token and GitLab API context before trusting any CI identity.
            "server_url": os.getenv("CI_SERVER_URL"),
            "project_id": os.getenv("CI_PROJECT_ID"),
            "project_path": os.getenv("CI_PROJECT_PATH"),
            "project_namespace": os.getenv("CI_PROJECT_NAMESPACE"),
            "pipeline_id": os.getenv("CI_PIPELINE_ID"),
            "pipeline_source": os.getenv("CI_PIPELINE_SOURCE"),
            "job_id": os.getenv("CI_JOB_ID"),
            "commit_sha": os.getenv("CI_COMMIT_SHA"),
            "commit_branch": os.getenv("CI_COMMIT_BRANCH"),
            "default_branch": os.getenv("CI_DEFAULT_BRANCH"),
            "ref_protected": os.getenv("CI_COMMIT_REF_PROTECTED"),
            "merge_request_iid": os.getenv("CI_MERGE_REQUEST_IID"),
            "merge_request_source_project_id": os.getenv(
                "CI_MERGE_REQUEST_SOURCE_PROJECT_ID"
            ),
            "merge_request_target_project_id": os.getenv(
                "CI_MERGE_REQUEST_TARGET_PROJECT_ID"
            ),
            "merge_request_source_project_path": os.getenv(
                "CI_MERGE_REQUEST_SOURCE_PROJECT_PATH"
            ),
            "merge_request_target_project_path": os.getenv(
                "CI_MERGE_REQUEST_TARGET_PROJECT_PATH"
            ),
            "merge_request_source_branch_name": os.getenv(
                "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
            ),
            "merge_request_target_branch_name": os.getenv(
                "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
            ),
            "merge_request_diff_base_sha": os.getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA"),
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

    if provider in (_ci_env.BITBUCKET_PIPELINES, _ci_env.AZURE_PIPELINES):
        pr_number = _parse_optional_int(_ci_env.pr_number_env(provider))
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
        if not path:
            return None
        content = read_text_no_symlink(
            path,
            max_bytes=1_000_000,
            encoding="utf-8",
        )
        if content is not None:
            return json.loads(content)
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return None


def _get_repo_root_for_link():
    root = get_git_root()
    if root:
        return Path(root)
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


def _try_gitlab_oidc_token() -> str | None:
    """Use an explicit GitLab.com job ID token, without trusting its claims here.

    No JWT decoding or network discovery belongs on this path. Cloud owns
    signature, audience, issuer, job and repository authorization checks.
    """
    if (
        os.getenv("GITLAB_CI") != "true"
        or os.getenv("CI_SERVER_URL") != "https://gitlab.com"
    ):
        return None
    token = os.getenv("SKYLOS_GITLAB_ID_TOKEN", "")
    if not token or len(token) > 16_384:
        return None
    if any(ord(char) < 33 or ord(char) > 126 for char in token):
        return None
    return f"gitlab_oidc:{token}"


def get_project_token() -> str | None:
    token = os.getenv("SKYLOS_TOKEN")
    if token:
        return token

    oidc = _try_github_oidc_token()
    if oidc:
        return oidc

    gitlab_oidc = _try_gitlab_oidc_token()
    if gitlab_oidc:
        return gitlab_oidc

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
            headers=_build_auth_headers(token),
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
    if not token or token.startswith(("oidc:", "gitlab_oidc:")):
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
                read_only_git_command(["rev-parse", "--show-toplevel"]),
                env=read_only_git_environment(),
                stderr=subprocess.DEVNULL,
                timeout=SUBPROCESS_TIMEOUT,
            )
            .decode()
            .strip()
            or None
        )
    except (subprocess.SubprocessError, OSError):
        pass
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
    # CI event SHAs can name a merge commit even when the workflow checks out
    # a PR head. Attribute the scan to its actual checkout; retain the event
    # SHA in CI metadata and explicit overrides for artifact publishing.
    commit = override_sha or git_commit or _ci_commit(meta) or "unknown"
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
    if provider == "gitlab" and meta.get("merge_request_source_branch_name"):
        return meta["merge_request_source_branch_name"]
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
                read_only_git_command(["rev-parse", "HEAD"]),
                env=read_only_git_environment(),
                stderr=subprocess.DEVNULL,
                timeout=SUBPROCESS_TIMEOUT,
            )
            .decode()
            .strip()
        )
        git_branch = (
            subprocess.check_output(
                read_only_git_command(["rev-parse", "--abbrev-ref", "HEAD"]),
                env=read_only_git_environment(),
                stderr=subprocess.DEVNULL,
                timeout=SUBPROCESS_TIMEOUT,
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
    if token and token.startswith("gitlab_oidc:"):
        headers = {
            "Authorization": f"Bearer {token[len('gitlab_oidc:') :]}",
            "X-Skylos-Auth": "gitlab_oidc",
        }
        from skylos.cloud.gitlab import managed_project_root

        project_root = managed_project_root(get_git_root())
        if project_root is not None:
            headers["X-Skylos-Project-Root"] = project_root
        return headers
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
    root = Path(git_root).resolve()
    candidate = root / file_path
    if candidate.is_symlink() or not candidate.is_file():
        return {}

    try:
        context = GitContext.from_path(root)
        repo_path = context.relative_path(candidate)
        if repo_path is None:
            return {}
        result = context.run(*_build_blame_command(repo_path, lines)[1:])
        if result.returncode != 0:
            return {}
        out = result.stdout
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
    analyzer_owned=False,
    gitlab_managed=False,
    gitlab_full_scan=False,
) -> PreparedReportUpload:
    commit, branch, actor, ci = get_git_info()
    git_root = get_git_root()
    if gitlab_managed:
        from skylos.cloud.gitlab import managed_checkout_root

        checkout_root = managed_checkout_root()
        if checkout_root is not None:
            git_root = str(checkout_root)
    project_root = _infer_upload_project_root(result_json, git_root)

    normalization_input = result_json
    if gitlab_managed:
        from skylos.cloud.gitlab import managed_report_paths

        normalization_input = managed_report_paths(result_json, git_root, project_root)

    all_findings = _normalize_result_sections(
        normalization_input,
        UPLOAD_FINDING_SPECS,
        git_root,
        extract_metadata=True,
        analyzer_owned=analyzer_owned,
    )
    reviewed_findings = (
        normalization_input.get("reviewed_findings", []) if analyzer_owned else []
    )
    if isinstance(reviewed_findings, list):
        for reviewed in reviewed_findings:
            if not isinstance(reviewed, dict):
                continue
            category = str(reviewed.get("category") or "QUALITY").upper()
            all_findings.extend(
                _normalize_findings(
                    [reviewed],
                    category,
                    git_root,
                    extract_metadata=True,
                    analyzer_owned=True,
                )
            )
    _annotate_findings_with_blame(all_findings, git_root)
    # Managed GitLab uploads keep their existing, stricter path handling.
    base_dir = git_root or os.getcwd()
    preflight = (
        None
        if gitlab_managed
        else apply_upload_contract(all_findings, project_root, base_dir=base_dir)
    )

    exporter = SarifExporter(
        all_findings,
        tool_name="Skylos",
        analyzer_owned=analyzer_owned,
        allow_empty_location=not gitlab_managed,
        location_uri=(
            None if gitlab_managed else (lambda raw: upload_location_uri(raw, base_dir))
        ),
    )
    core_payload = exporter.generate()
    strip_secret_snippets(core_payload)

    ai_code = detect_ai_code(git_root)
    if isinstance(result_json, dict) and "provenance" in result_json:
        raw_provenance = result_json.get("provenance")
        if isinstance(raw_provenance, dict):
            provenance_data = raw_provenance
        else:
            # The scan chose not to (or could not) analyze provenance. Say so,
            # with the real reason, so Skylos Cloud never reads a missing
            # provenance section as "no agent-written code".
            provenance_data = _provenance_not_run(
                _provenance_skip_reason(result_json.get("provenance_status"))
            )
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
        source_revision_state=source_revision_state(result_json, git_root, commit),
        scanned_checks=_scanned_checks(result_json),
        scan_coverage=scan_coverage_receipt(
            result_json,
            analyzer_owned=analyzer_owned,
            analysis_mode=analysis_mode,
        ),
        quality_rule_classification=quality_rule_classification(result_json),
        architecture_advisories=architecture_advisory_summary(result_json),
        done_receipt=_done_receipt_for_upload(
            result_json, commit_hash=commit, repo_root=git_root
        ),
    )
    if gitlab_managed:
        from skylos.cloud.gitlab import scan_receipt

        metadata["gitlab_scan_receipt"] = scan_receipt(
            result_json,
            analyzer_owned=analyzer_owned,
            full_scan=gitlab_full_scan,
        )
    core_payload.update(metadata)
    legacy_payload = _build_legacy_payload(core_payload, definitions)
    compatibility_payload = _build_compatibility_inline_payload(
        all_findings,
        result_json,
        metadata,
    )
    strip_secret_snippets(compatibility_payload)
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
        preflight=preflight,
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


_PROVENANCE_NOT_RUN_REASON = "provenance was not run for this scan"


def _provenance_skip_reason(status) -> str:
    if isinstance(status, dict):
        reason = status.get("reason")
        if isinstance(reason, str) and reason.strip():
            return reason.strip()[:200]
    return _PROVENANCE_NOT_RUN_REASON


def _provenance_not_run(reason: str) -> dict[str, Any]:
    """Upload shape for a scan whose provenance was not analyzed."""
    return {
        "files": {},
        "agent_files": [],
        "status": {"ran": False, "reason": reason},
    }


def _provenance_status(prov_report) -> dict[str, Any]:
    status = getattr(prov_report, "status", None)
    if isinstance(status, dict):
        return dict(status)
    return {"ran": False, "reason": "provenance status unavailable"}


def _detect_report_provenance_data(git_root):
    """Provenance for the upload, always with its status.

    With agent-written files the full report is sent. Without them only the
    summary and status are sent (not every human file), which still tells
    Skylos Cloud "checked, no agent code" apart from "could not check".
    """
    try:
        from skylos.reporting.provenance import analyze_provenance

        prov_report = analyze_provenance(git_root)
    except (ImportError, subprocess.SubprocessError, OSError) as exc:
        logger.debug("Provenance detection failed", exc_info=True)
        return _provenance_not_run(
            f"provenance detection failed ({type(exc).__name__})"
        )
    if prov_report.agent_files:
        return prov_report.to_dict()
    summary = getattr(prov_report, "summary", None)
    confidence = getattr(prov_report, "confidence", None)
    return {
        "files": {},
        "agent_files": [],
        "human_files": [],
        "automation_files": [],
        "summary": summary if isinstance(summary, dict) else {},
        "confidence": confidence if isinstance(confidence, str) else "low",
        "status": _provenance_status(prov_report),
    }


def _scanned_checks(result_json: Any) -> list[str] | None:
    """The checks this scan ran (result_builder sets them before grading)."""
    if not isinstance(result_json, dict):
        return None
    summary = result_json.get("analysis_summary")
    checks = summary.get("grade_categories") if isinstance(summary, dict) else None
    if isinstance(checks, list) and all(isinstance(check, str) for check in checks):
        return list(checks)
    return None


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
    source_revision_state=None,
    scanned_checks=None,
    scan_coverage=None,
    quality_rule_classification=None,
    architecture_advisories=None,
    done_receipt=None,
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
    if source_revision_state in {"clean", "dirty", "unknown"}:
        metadata["source_revision_state"] = source_revision_state
    if grade_data:
        metadata["grade"] = grade_data
    # The checks this scan ran, sent even when the grade is withheld, so
    # Skylos Cloud tracks each check on its own (a check that did not run is
    # "not checked", never 0 findings).
    if isinstance(scanned_checks, list) and all(
        isinstance(check, str) for check in scanned_checks
    ):
        metadata["scanned_checks"] = list(scanned_checks)
    if isinstance(scan_coverage, dict):
        metadata["scan_coverage"] = scan_coverage
    if isinstance(quality_rule_classification, dict):
        metadata["quality_rule_classification"] = quality_rule_classification
    if isinstance(architecture_advisories, dict):
        metadata["architecture_advisories"] = architecture_advisories
    if isinstance(done_receipt, dict):
        metadata["done_receipt"] = done_receipt
    if project_id:
        metadata["project_id"] = project_id
    if scan_bundle_id:
        metadata["scan_bundle_id"] = str(scan_bundle_id)
    if project_root is not None:
        metadata["project_root"] = str(project_root)
    if workspace_data:
        metadata["workspaces"] = workspace_data
    return metadata


def _done_receipt_for_upload(
    result_json, *, commit_hash=None, repo_root=None
) -> dict[str, Any] | None:
    """The `skylos done` receipt attached with --done-receipt, if valid."""
    receipt = result_json.get("done_receipt") if isinstance(result_json, dict) else None
    if not isinstance(receipt, dict):
        return None
    from skylos.done.receipt import receipt_upload_error, validate_receipt

    if validate_receipt(receipt):
        return None
    if commit_hash is not None:
        if not repo_root:
            raise ValueError(
                "cannot bind the done receipt to this upload without a Git checkout"
            )
        error = receipt_upload_error(receipt, repo_root, commit_hash=commit_hash)
        if error:
            raise ValueError(error)
    return receipt


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
    gitlab_managed=False,
) -> dict:
    if gitlab_managed and response.status_code in (401, 402):
        return _managed_report_rejected()
    error_result = _report_upload_error_result(response)
    if error_result:
        return error_result

    data = _safe_response_json(response)
    scan_id = data.get("scanId") or data.get("scan_id")
    quality_gate = data.get("quality_gate", {})
    # A 2xx response without a usable scan identifier cannot confirm where
    # the upload went. Keep the original idempotency key so retry can recover
    # the server's receipt without saving or charging a duplicate scan.
    if not isinstance(scan_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", scan_id
    ):
        if gitlab_managed:
            return _report_transport_failure(_GITLAB_DELIVERY_UNKNOWN)
        return UploadFailure(
            "Skylos Cloud did not return a valid scan ID for this upload.",
            code="UPLOAD_RESPONSE_INVALID",
            status=response.status_code,
            retryable=True,
        ).as_result()
    if gitlab_managed and not isinstance(quality_gate, dict):
        return _report_transport_failure(_GITLAB_DELIVERY_UNKNOWN)
    if not isinstance(quality_gate, dict):
        quality_gate = {}
    passed = quality_gate.get("passed", True)
    new_violations = quality_gate.get("new_violations", 0)
    plan = data.get("plan", "free")
    replayed = (not gitlab_managed) and _is_idempotent_replay(response, data)

    if not quiet:
        _print_report_upload_success(
            grade_data=grade_data,
            passed=passed,
            new_violations=new_violations,
            plan=plan,
            scan_id=scan_id,
            credits_left=data.get("credits_remaining"),
            replayed=replayed,
            finding_warnings=data.get("finding_warnings"),
            gate_message=quality_gate.get("message"),
            trust_notice=data.get("upload_trust_notice"),
        )
    result = _report_upload_success_result(data, scan_id, passed, plan)
    if replayed:
        result["replayed"] = True
    if gitlab_managed:
        from skylos.cloud.gitlab import delivery_receipt

        result.update(delivery_receipt(data.get("gitlab_delivery")))
        # The CLI evaluates this independent delivery status before its gate;
        # retaining the saved scan ID and gate result avoids a misleading retry.
        return result
    _enforce_report_quality_gate(
        passed, strict=strict, is_forced=is_forced, quiet=quiet
    )
    return result


def _report_upload_error_result(response) -> dict | None:
    if response.status_code not in (401, 402):
        return None
    return _describe_http_failure(response).as_result()


def _safe_response_json(response) -> dict:
    try:
        data = response.json()
    except (ValueError, TypeError, KeyError):
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
    replayed: bool = False,
    finding_warnings=None,
    gate_message=None,
    trust_notice=None,
) -> None:
    if replayed:
        print(
            " done!\n✓ Scan was already saved by an earlier attempt; "
            "it was not saved twice."
        )
    else:
        print(" done!\n✓ Scan uploaded")
    if isinstance(finding_warnings, list) and finding_warnings:
        count = len(finding_warnings)
        noun = "finding" if count == 1 else "findings"
        print(
            f"Skylos Cloud stored {count} {noun} with a warning "
            "(for example, without a file location)."
        )
    _print_report_grade(grade_data)
    _print_quality_gate_result(passed, new_violations, plan, gate_message)
    _print_upload_trust_notice(trust_notice)
    if scan_id:
        print(f"\n🔗 View the scan: {BASE_URL}/dashboard/scans/{scan_id}")
    _print_credit_balance_after_upload(credits_left)


def _print_upload_trust_notice(notice) -> None:
    """Skylos Cloud's note when it stored the upload as unverified.

    Uploads with the `skylos login` key do not publish GitHub checks or mark
    issues fixed: any coding agent on this machine can read that key.
    """
    if not isinstance(notice, str):
        return
    text = "".join(char for char in notice[:600] if char.isprintable()).strip()
    if text:
        print(f"\n⚠️  {text}")


def _print_report_grade(grade_data) -> None:
    if grade_data:
        grade = grade_data["overall"]
        print(f"Grade: {grade['letter']} ({grade['score']}/100)")


_GATE_FAILED_PREFIX = "Quality Gate Failed!"


def _quality_gate_reasons(message) -> list[str]:
    """The reasons in Skylos Cloud's gate message, e.g.
    "Quality Gate Failed! 3 critical security issues; 1 new exposed secret."
    """
    if not isinstance(message, str) or not message.startswith(_GATE_FAILED_PREFIX):
        return []
    text = message[len(_GATE_FAILED_PREFIX) :].strip().rstrip(".")
    # Reasons are separated by ";" outside brackets, e.g.
    # "agent rules block the change (2 reasons; see the scan page)".
    reasons, current, depth = [], [], 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        if char == ";" and depth == 0:
            reasons.append("".join(current))
            current = []
            continue
        current.append(char)
    reasons.append("".join(current))
    return [reason.strip() for reason in reasons if reason.strip()]


def _print_quality_gate_result(
    passed: bool, new_violations: int, plan: str, message=None
) -> None:
    if passed:
        print("✅ PASS Quality gate: PASSED")
        return
    reasons = _quality_gate_reasons(message)
    if reasons:
        print("❌ FAIL Quality gate: FAILED because of")
        for reason in reasons:
            print(f"   - {reason}")
    else:
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
    result = {
        "success": True,
        "scan_id": scan_id,
        "quality_gate_passed": passed,
        "plan": plan,
        "credits_warning": data.get("credits_warning", False),
    }
    # Older servers do not report it; only verified uploads publish checks.
    if isinstance(data.get("upload_trust"), str):
        result["upload_trust"] = data["upload_trust"]
    return result


def _post_json_with_retries(
    url,
    headers,
    payload,
    *,
    quiet=False,
    initial_message=None,
    accepted_statuses=(200, 201, 401, 402),
    timeout=NETWORK_TIMEOUT_LONG,
    idempotency_key=None,
    raw_body: bytes | None = None,
):
    """POST JSON with the upload contract's retry policy.

    Returns ``(response, None)`` for a status in ``accepted_statuses`` and
    ``(None, error)`` otherwise. For non-managed uploads the error is an
    :class:`UploadFailure` (a ``str`` with ``code``/``status``/``retryable``).

    Only connection errors, timeouts and the contract's retryable statuses are
    retried, with exponential backoff and full jitter, honouring Retry-After.
    Every attempt sends the same ``Idempotency-Key`` so the server can tell a
    retry from a new upload. Managed GitLab uploads make exactly one attempt.
    ``raw_body`` sends already-serialised JSON bytes unchanged (resends of a
    saved upload) instead of ``payload``.
    """
    managed = headers.get("X-Skylos-Auth") == "gitlab_oidc"
    try:
        safe_url = _validate_api_request_url(url)
    except ValueError as exc:
        if managed:
            return None, "Invalid managed Cloud endpoint configuration."
        return None, f"Unsafe API URL: {exc}"

    if managed:
        return _post_managed_json_once(
            safe_url,
            headers,
            payload,
            quiet=quiet,
            initial_message=initial_message,
            accepted_statuses=accepted_statuses,
        )

    request_headers = _upload_contract_headers(
        headers,
        idempotency_key or UploadSession.new().idempotency_key,
        _cli_version(),
    )
    policy = RetryPolicy.from_env()
    failure: UploadFailure | None = None
    failed_attempts = 0  # attempts that count toward policy.max_attempts
    requests_sent = 0
    waited = 0.0
    started = time.monotonic()
    if not quiet and initial_message:
        print(initial_message, end="", flush=True)
    while requests_sent < _MAX_REQUESTS_PER_UPLOAD:
        requests_sent += 1
        try:
            if raw_body is not None:
                response = requests.post(
                    safe_url,
                    data=raw_body,
                    headers={**request_headers, "Content-Type": "application/json"},
                    timeout=timeout,
                )
            else:
                response = requests.post(
                    safe_url,
                    json=payload,
                    headers=request_headers,
                    timeout=timeout,
                )
        except _request_exceptions.RequestException as exc:
            failure = _describe_transport_exception(exc, safe_url)
            if not _is_retryable_transport_exception(exc):
                break
        else:
            if response.status_code in accepted_statuses:
                return response, None
            failure = _describe_http_failure(response)

        if failure.status is not None and _is_retryable_conflict(failure):
            # The same upload is still being processed (for example after a
            # read timeout). Wait as asked, within the conflict budget; a
            # later answer is the finished scan, replayed.
            delay = _conflict_delay(failure)
            spent = max(time.monotonic() - started, waited)
            if spent + delay > policy.conflict_budget_seconds:
                break
            if not quiet:
                print(
                    f" still processing; checking again in {delay:.0f}s...",
                    end="",
                    flush=True,
                )
            _upload_sleep(delay)
            waited += delay
            continue

        if failure.status is not None and not _should_retry_now(failure):
            break
        failed_attempts += 1
        if failed_attempts >= policy.max_attempts:
            break
        delay = _retry_delay(failure, failed_attempts, policy)
        if delay is None:
            break
        if not quiet:
            print(
                f" retrying ({failed_attempts + 1}/{policy.max_attempts}) in {delay:.1f}s...",
                end="",
                flush=True,
            )
        _upload_sleep(delay)
        waited += delay

    if not quiet:
        print(" failed.")
    return None, failure or UploadFailure("The upload did not complete.")


# Upper bound on requests for one upload, whatever the server answers.
_MAX_REQUESTS_PER_UPLOAD = 100


def _report_request_timeout() -> tuple[float, float]:
    """(connect, read) timeout for the report endpoints.

    The read timeout is the contract's ``client_read_timeout_seconds``, so a
    slow but working upload is not cut off and retried while it still runs.
    """
    return (NETWORK_TIMEOUT_DEFAULT, float(_client_read_timeout_seconds()))


def _retry_delay(
    failure: UploadFailure | None, retry_number: int, policy: RetryPolicy
) -> float | None:
    """Seconds before the next attempt, or None to stop retrying now."""
    retry_after = getattr(failure, "retry_after", None)
    if retry_after is not None:
        # The server asked for a longer wait than this run will spend;
        # stop here so the scan can be saved and sent later.
        if retry_after > policy.max_seconds:
            return None
        return max(retry_after, 0.0)
    return _backoff_delay(retry_number, policy)


def _upload_sleep(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)


def _post_managed_json_once(
    safe_url,
    headers,
    payload,
    *,
    quiet,
    initial_message,
    accepted_statuses,
):
    """Managed GitLab: one long attempt, no redirects, no automatic re-upload."""
    try:
        destination = _validate_api_request_url(safe_url)
        allowed_destinations = {
            _validate_api_request_url(REPORT_URL),
            _validate_api_request_url(REPORT_INIT_URL),
            _validate_api_request_url(REPORT_COMPLETE_URL),
        }
    except ValueError:
        return None, "Invalid managed Cloud endpoint configuration."
    if destination not in allowed_destinations:
        return None, "Invalid managed Cloud endpoint configuration."

    try:
        if not quiet and initial_message:
            print(initial_message, end="", flush=True)
        response = requests.post(
            destination,
            json=payload,
            headers=headers,
            timeout=300,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return None, _GITLAB_DELIVERY_UNKNOWN
    if response.status_code >= 500:
        return None, _GITLAB_DELIVERY_UNKNOWN
    if response.status_code in accepted_statuses:
        return response, None
    if not quiet and response.status_code >= 400:
        print(" failed.")
    return None, _GITLAB_DELIVERY_UNKNOWN


_GITLAB_DELIVERY_UNKNOWN = (
    "GitLab upload/delivery outcome unknown. Check Cloud before starting a fresh "
    "pipeline; the scan may already be saved and comments may have changed. "
    "No automatic re-upload was attempted."
)


def _report_transport_failure(error: str | None) -> dict:
    if isinstance(error, UploadFailure):
        return error.as_result()
    result = {"success": False, "error": error or "Unknown error"}
    if error == _GITLAB_DELIVERY_UNKNOWN:
        result.update(
            {
                "code": "GITLAB_DELIVERY_UNKNOWN",
                "gitlab_delivery_exit_code": 2,
                "gitlab_delivery_message": _GITLAB_DELIVERY_UNKNOWN,
            }
        )
    return result


def _managed_report_rejected() -> dict:
    message = "Managed GitLab upload was rejected. Check the job identity, Cloud plan and project integration setup."
    return {
        "success": False,
        "error": message,
        "code": "GITLAB_UPLOAD_REJECTED",
        "gitlab_delivery_exit_code": 2,
        "gitlab_delivery_message": message,
    }


def _post_report_payload(
    token, payload, *, quiet=False, initial_message=None, idempotency_key=None
):
    return _post_json_with_retries(
        REPORT_URL,
        _build_auth_headers(token),
        payload,
        quiet=quiet,
        initial_message=initial_message,
        timeout=_report_request_timeout(),
        idempotency_key=idempotency_key,
    )


def _looks_like_server_error(error: str | None) -> bool:
    status = getattr(error, "status", None)
    if isinstance(status, int):
        return status >= 500
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
    session: UploadSession | None = None,
) -> dict:
    if session is not None:
        session.request_payload = payload
    response, last_err = _post_report_payload(
        token,
        payload,
        quiet=quiet,
        initial_message=initial_message,
        idempotency_key=session.idempotency_key if session else None,
    )
    if response is None:
        return _report_transport_failure(last_err)
    return _finalize_report_upload(
        response,
        grade_data=grade_data,
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
        gitlab_managed=token.startswith("gitlab_oidc:"),
    )


def upload_report_compatibility(
    token,
    prepared: PreparedReportUpload,
    *,
    quiet=False,
    strict=False,
    is_forced=False,
    initial_message=None,
    session: UploadSession | None = None,
) -> dict:
    if token.startswith("gitlab_oidc:"):
        message = (
            "Managed GitLab uploads require full report data. "
            "The local report is retained; upgrade Cloud before a fresh pipeline. "
            "Lossy compatibility fallback is disabled."
        )
        return {
            "success": False,
            "code": "UPLOAD_PROTOCOL_UNSUPPORTED",
            "error": message,
            "gitlab_delivery_exit_code": 2,
            "gitlab_delivery_message": message,
        }
    if prepared.compatibility_payload_size_bytes > _legacy_inline_upload_limit_bytes():
        return _build_compatibility_upload_too_large_error(prepared)
    if session is not None:
        # A different payload needs its own idempotency key.
        session.switch("compat")
    return upload_report_legacy(
        token,
        prepared.compatibility_payload,
        grade_data=prepared.grade_data,
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
        initial_message=initial_message,
        session=session,
    )


def upload_report_v2(
    token,
    prepared: PreparedReportUpload,
    *,
    quiet=False,
    strict=False,
    is_forced=False,
    session: UploadSession | None = None,
    initial_message: str | None = "Uploading scan results...",
) -> dict:
    if session is None:
        session = UploadSession.new()
    session.switch("artifact")
    artifacts = _build_report_artifacts(prepared)
    return _run_artifact_upload(
        token,
        prepared,
        artifacts,
        session=session,
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
        initial_message=initial_message,
    )


def _run_artifact_upload(
    token,
    prepared: PreparedReportUpload,
    artifacts: dict,
    *,
    session: UploadSession,
    quiet: bool,
    strict: bool,
    is_forced: bool,
    initial_message: str | None,
    init_body: bytes | None = None,
) -> dict:
    """init -> upload artifacts -> complete, then remove the temp files.

    If the upload does not finish, the artifact bytes are kept on the
    session first so the scan can be saved and resent unchanged.
    """
    finished = False
    try:
        init_result = _start_report_artifact_upload(
            token,
            prepared,
            artifacts,
            quiet,
            strict=strict,
            is_forced=is_forced,
            session=session,
            initial_message=initial_message,
            init_body=init_body,
        )
        if init_result.get("complete"):
            finished = bool(init_result["result"].get("success"))
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
            idempotency_key=session.idempotency_key,
        )
        if complete_response.get("error"):
            return complete_response["error"]
        result = _finalize_report_upload(
            complete_response["response"],
            grade_data=prepared.grade_data,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
            gitlab_managed=token.startswith("gitlab_oidc:"),
        )
        finished = bool(result.get("success"))
        return result
    finally:
        if not finished and not token.startswith("gitlab_oidc:"):
            with contextlib.suppress(OSError):
                session.artifact_snapshot = _snapshot_report_artifacts(artifacts)
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
    session: UploadSession | None = None,
    initial_message: str | None = "Uploading scan results...",
    init_body: bytes | None = None,
) -> dict[str, Any]:
    skipped_artifacts = []

    while True:
        init_payload = None
        if init_body is None:
            init_payload = _build_report_init_payload(prepared, artifacts)
            if session is not None:
                session.request_payload = init_payload
        init_response, last_err = _post_json_with_retries(
            REPORT_INIT_URL,
            _build_auth_headers(token),
            init_payload,
            quiet=quiet,
            initial_message=initial_message,
            accepted_statuses=(200, 201, 400, 401, 402, 404, 405, 501),
            timeout=_report_request_timeout(),
            idempotency_key=session.idempotency_key if session else None,
            raw_body=init_body,
        )
        if not token.startswith(
            "gitlab_oidc:"
        ) and _retry_artifact_init_without_optional_artifact(
            init_response,
            artifacts,
            skipped_artifacts,
        ):
            initial_message = None
            # The init request changed, so it is rebuilt and needs a new key.
            init_body = None
            if session is not None:
                session.rotate()
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
            "result": _report_transport_failure(last_err),
        }
    if init_response.status_code in (404, 405, 501):
        return {
            "complete": True,
            "result": _build_large_upload_protocol_error(prepared),
        }
    if init_response.status_code == 400:
        if token.startswith("gitlab_oidc:"):
            return {"complete": True, "result": _managed_report_rejected()}
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
                gitlab_managed=token.startswith("gitlab_oidc:"),
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
    return _describe_http_failure(response).as_result()


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
        return _handle_missing_report_artifact(
            artifact_name, artifact, skipped_artifacts
        )

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
        return {
            "success": False,
            "error": upload_result["error"],
            "retryable": bool(upload_result.get("retryable")),
        }
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
    idempotency_key: str | None = None,
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
        timeout=_report_request_timeout(),
        idempotency_key=idempotency_key,
    )
    if complete_response is None:
        return {"error": _report_transport_failure(last_err)}
    return {"response": complete_response}


_NO_TOKEN_ERROR = (
    "No token found. Run 'skylos login' or 'skylos project use', or set SKYLOS_TOKEN."
)


def upload_report(
    result_json,
    is_forced=False,
    quiet=False,
    strict=False,
    analysis_mode="static",
    scan_bundle_id=None,
    analyzer_owned=False,
    gitlab_full_scan=False,
) -> dict:
    token = get_project_token()
    if not token:
        return {"success": False, "error": _NO_TOKEN_ERROR}
    managed = token.startswith("gitlab_oidc:")

    if not quiet:
        info = get_project_info(token)
        if info and info.get("ok"):
            project_name = info.get("project", {}).get("name", "Unknown")
            print(f"Uploading to: {project_name}")
    if not managed and not quiet:
        _print_pending_upload_reminder()

    prepared = _prepare_report_upload(
        result_json,
        is_forced=is_forced,
        analysis_mode=analysis_mode,
        scan_bundle_id=scan_bundle_id,
        analyzer_owned=analyzer_owned,
        gitlab_managed=managed,
        gitlab_full_scan=gitlab_full_scan,
    )

    if managed:
        from skylos.cloud.gitlab import managed_project_root

        try:
            root_hint = managed_project_root(get_git_root())
        except ValueError:
            return {"success": False, "error": "Invalid GitLab project-root binding."}
        if root_hint is not None and prepared.metadata.get("project_root") != root_hint:
            return {
                "success": False,
                "error": "GitLab project-root binding does not match scan root.",
            }
    else:
        _print_preflight_notice(prepared, quiet=quiet)

    return _send_prepared_upload(
        token,
        prepared,
        kind="report",
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
    )


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
        return {"success": False, "error": _NO_TOKEN_ERROR}

    if not quiet:
        info = get_project_info(token)
        if info and info.get("ok"):
            project_name = info.get("project", {}).get("name", "Unknown")
            print(f"Uploading to: {project_name}")
    if not token.startswith("gitlab_oidc:") and not quiet:
        _print_pending_upload_reminder()

    prepared = _prepare_debt_upload(
        debt_report,
        is_forced=is_forced,
        scan_bundle_id=scan_bundle_id,
    )
    return _send_prepared_upload(
        token,
        prepared,
        kind="debt",
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
    )


_UPLOAD_MESSAGES = {
    "report": "Uploading scan results...",
    "debt": "Uploading debt results...",
}


def _send_prepared_upload(
    token,
    prepared: PreparedReportUpload,
    *,
    kind: str,
    quiet: bool,
    strict: bool,
    is_forced: bool,
) -> dict:
    """Upload a prepared scan; keep it for ``skylos upload --retry`` if needed."""
    managed = token.startswith("gitlab_oidc:")
    session = UploadSession.new(
        mode="inline" if _should_use_legacy_inline_report_upload(prepared) else None
    )
    if managed:
        return _upload_prepared_report(
            token,
            prepared,
            session=session,
            kind=kind,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
        )

    if not quiet:
        _begin_contract_check()
    pending_dir = _pending_uploads_dir(_get_repo_root_for_link())
    with _save_pending_on_interrupt(session, prepared, kind, pending_dir):
        result = _upload_prepared_report(
            token,
            prepared,
            session=session,
            kind=kind,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
        )
    result = _save_pending_if_retryable(
        result, session, prepared, kind=kind, pending_dir=pending_dir, quiet=quiet
    )
    if not quiet:
        notice = _newer_contract_notice()
        if notice:
            print(notice)
    return result


def _upload_prepared_report(
    token,
    prepared: PreparedReportUpload,
    *,
    session: UploadSession,
    kind: str,
    quiet: bool,
    strict: bool,
    is_forced: bool,
) -> dict:
    if session.mode == "inline":
        return upload_report_legacy(
            token,
            prepared.legacy_payload,
            grade_data=prepared.grade_data,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
            initial_message=_UPLOAD_MESSAGES.get(kind, _UPLOAD_MESSAGES["report"]),
            session=session,
        )

    upload_result = upload_report_v2(
        token,
        prepared,
        quiet=quiet,
        strict=strict,
        is_forced=is_forced,
        session=session,
    )
    if not _should_retry_with_degraded_large_upload(upload_result):
        return upload_result
    if kind == "report" and token.startswith("gitlab_oidc:"):
        return {
            **upload_result,
            "gitlab_delivery_exit_code": 2,
            "gitlab_delivery_message": "Managed GitLab upload requires a compatible Cloud artifact endpoint. The local report is retained; upgrade Cloud before a fresh pipeline. Lossy compatibility fallback is disabled.",
        }
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
        initial_message=None if kind == "report" else _UPLOAD_MESSAGES[kind],
        session=session,
    )


def _begin_contract_check() -> None:
    _start_contract_version_check(
        _contract_check_url(BASE_URL),
        requests.get,
        validate=_validate_api_request_url,
    )


def _print_preflight_notice(prepared, *, quiet: bool) -> None:
    preflight = getattr(prepared, "preflight", None)
    message = preflight.no_location_message() if preflight is not None else None
    if not message:
        return
    print(message, file=sys.stderr if quiet else sys.stdout)


def _display_path(path: Path) -> str:
    try:
        relative = os.path.relpath(path)
    except ValueError:
        return str(path)
    return str(path) if relative.startswith("..") else relative


def _print_pending_upload_reminder() -> None:
    try:
        root = _get_repo_root_for_link()
        count = _count_pending_uploads(_pending_uploads_dir(root))
    except OSError:
        return
    if count == 1:
        print(
            "1 earlier upload did not finish. Run 'skylos upload --retry' to send it."
        )
    elif count:
        print(
            f"{count} earlier uploads did not finish. "
            "Run 'skylos upload --retry' to send them."
        )
    notice = legacy_pending_notice(root)
    if notice:
        print(notice)


def legacy_pending_notice(project_root) -> str | None:
    """One line about uploads an older Skylos saved inside the repository.

    They are never sent: anyone who can write to the repository could have
    written them. The user can rerun the scan and delete the folder.
    """
    directory, count = _legacy_pending_uploads(project_root)
    if not count:
        return None
    noun = "upload" if count == 1 else "uploads"
    return (
        f"{count} {noun} saved by an older Skylos are in {_display_path(directory)}; "
        "they are not sent automatically. Rerun the scan to upload, then delete "
        "that folder."
    )


def _exact_json_body(payload: Any) -> bytes:
    """The bytes ``requests.post(json=payload)`` puts on the wire.

    Built with requests' own request preparation, so a saved upload keeps
    exactly what the first attempt sent (the upload contract's resend rule).
    """
    body = (
        _RequestsRequest("POST", "http://skylos.invalid/", json=payload).prepare().body
    )
    return body if isinstance(body, bytes) else str(body).encode("utf-8")


def _pending_request_parts(
    session: UploadSession, prepared: PreparedReportUpload
) -> tuple[bytes, dict[str, Any] | None]:
    """Request body and artifact bytes to keep for a resend of this upload."""
    mode = session.mode or "artifact"
    if mode != "artifact":
        payload = session.request_payload
        if payload is None:  # stopped before the first request was sent
            payload = (
                prepared.compatibility_payload
                if mode == "compat"
                else prepared.legacy_payload
            )
        return _exact_json_body(payload), None
    snapshot = session.artifact_snapshot
    payload = session.request_payload
    if snapshot is None or payload is None:
        # Stopped before the artifact files were written or init was sent;
        # build them now (deterministic: same bytes the upload would send).
        artifacts = _build_report_artifacts(prepared)
        try:
            snapshot = _snapshot_report_artifacts(artifacts)
            payload = _build_report_init_payload(prepared, artifacts)
        finally:
            for artifact in artifacts.values():
                artifact.cleanup()
    return _exact_json_body(payload), snapshot


def _pending_endpoint(mode: str) -> str:
    return REPORT_INIT_URL if mode == "artifact" else REPORT_URL


def _save_pending_for_session(
    session: UploadSession,
    prepared: PreparedReportUpload,
    kind: str,
    pending_dir: Path | None,
    last_error: dict[str, Any],
) -> Path | None:
    mode = session.mode or "artifact"
    metadata = getattr(prepared, "metadata", None) or {}
    summary = getattr(prepared, "scan_summary", None) or {}
    try:
        body, artifacts = _pending_request_parts(session, prepared)
        context: dict[str, Any] = {"grade_data": getattr(prepared, "grade_data", None)}
        if mode == "artifact":
            # Needed only if Cloud asks for the init request to be rebuilt.
            context.update(
                metadata=metadata,
                scan_summary=summary,
                legacy_payload_size_bytes=getattr(
                    prepared, "legacy_payload_size_bytes", 0
                ),
            )
        return _save_pending_upload(
            pending_dir,
            idempotency_key=session.idempotency_key,
            kind=kind,
            mode=mode,
            endpoint=_pending_endpoint(mode),
            api_base=BASE_URL,
            project_id=metadata.get("project_id"),
            cli_version=_cli_version(),
            request_body=body,
            artifacts=artifacts,
            context=context,
            finding_count=summary.get("finding_count"),
            last_error=last_error,
        )
    except (OSError, TypeError, ValueError, AttributeError) as exc:
        logger.debug("Could not save pending upload: %s", exc)
        return None


def _failure_details(result: dict[str, Any]) -> dict[str, Any]:
    error = result.get("error")
    return {
        "code": result.get("code"),
        "status": result.get("status"),
        "request_id": result.get("request_id"),
        "error": str(error) if error is not None else None,
    }


def _save_pending_if_retryable(
    result: dict,
    session: UploadSession,
    prepared: PreparedReportUpload,
    *,
    kind: str,
    pending_dir: Path | None,
    quiet: bool,
) -> dict:
    if result.get("success") or not result.get("retryable"):
        return result
    path = _save_pending_for_session(
        session, prepared, kind, pending_dir, _failure_details(result)
    )
    if path is None:
        return result
    error = result.get("error")
    if isinstance(error, UploadFailure):
        result["error"] = error.with_hint(_SAVED_HINT)
    elif error:
        result["error"] = f"{error} {_SAVED_HINT}"
    result["pending_upload"] = str(path)
    if quiet:
        print(
            f"Scan saved to {_display_path(path)}; "
            "run 'skylos upload --retry' to send it.",
            file=sys.stderr,
        )
    return result


class _UploadTerminated(SystemExit):
    """SIGTERM during an upload, raised so the scan can be saved first."""


def _raise_upload_terminated(signum, _frame):
    raise _UploadTerminated(128 + signum)


def _install_sigterm_guard():
    """Turn SIGTERM into an exception during an upload; returns the signal.

    Only when nothing else handles SIGTERM, and only on the main thread.
    """
    sigterm = getattr(signal, "SIGTERM", None)
    installed = None
    if sigterm is not None and threading.current_thread() is threading.main_thread():
        try:
            if signal.getsignal(sigterm) is signal.SIG_DFL:
                signal.signal(sigterm, _raise_upload_terminated)
                installed = sigterm
        except (ValueError, OSError):
            installed = None
    return installed


def _remove_sigterm_guard(sigterm) -> None:
    if sigterm is None:
        return
    with contextlib.suppress(ValueError, OSError):
        signal.signal(sigterm, signal.SIG_DFL)


@contextlib.contextmanager
def _save_pending_on_interrupt(session, prepared, kind, pending_dir):
    """Keep the scan if Ctrl-C or SIGTERM stops the upload part-way."""
    guard = _install_sigterm_guard()
    try:
        yield
    except (KeyboardInterrupt, _UploadTerminated):
        _remove_sigterm_guard(guard)
        guard = None
        path = _save_pending_for_session(
            session, prepared, kind, pending_dir, {"code": "INTERRUPTED"}
        )
        if path is not None:
            print(
                f"\nUpload interrupted. Scan saved to {_display_path(path)}; "
                "run 'skylos upload --retry' to send it.",
                file=sys.stderr,
                flush=True,
            )
        raise
    finally:
        _remove_sigterm_guard(guard)


def _prepared_from_pending(context: dict[str, Any]) -> PreparedReportUpload:
    metadata = context.get("metadata")
    scan_summary = context.get("scan_summary")
    size = context.get("legacy_payload_size_bytes")
    return PreparedReportUpload(
        legacy_payload={},
        core_payload={},
        compatibility_payload={},
        definitions_payload=None,
        metadata=metadata if isinstance(metadata, dict) else {},
        scan_summary=scan_summary if isinstance(scan_summary, dict) else {},
        grade_data=context.get("grade_data"),
        legacy_payload_size_bytes=size if isinstance(size, int) else 0,
        compatibility_payload_size_bytes=0,
    )


def _resend_saved_request(token, pending, session, *, quiet, message) -> dict:
    """Send a saved upload's exact bytes again with its original key."""
    record = pending.record
    body = _decode_request_body(record)
    context = record.get("context") if isinstance(record.get("context"), dict) else {}
    if session.mode != "artifact":
        response, last_err = _post_json_with_retries(
            REPORT_URL,
            _build_auth_headers(token),
            None,
            quiet=quiet,
            initial_message=message,
            timeout=_report_request_timeout(),
            idempotency_key=session.idempotency_key,
            raw_body=body,
        )
        if response is None:
            return _report_transport_failure(last_err)
        return _finalize_report_upload(
            response,
            grade_data=context.get("grade_data"),
            quiet=quiet,
            strict=False,
            is_forced=False,
        )
    artifacts = _restore_report_artifacts(record.get("artifacts") or {})
    return _run_artifact_upload(
        token,
        _prepared_from_pending(context),
        artifacts,
        session=session,
        quiet=quiet,
        strict=False,
        is_forced=False,
        initial_message=message,
        init_body=body,
    )


def _format_saved_time(created_at: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(created_at))
    except (OverflowError, OSError, ValueError):
        return "an earlier run"


def _resend_one_pending_upload(token, pending, linked_project_id, *, quiet: bool):
    record = pending.record
    mode = record.get("mode")
    if mode not in {"inline", "compat", "artifact"}:
        return {"status": "skipped", "reason": "unknown upload format"}
    expected_endpoint = _pending_endpoint(mode)
    if record.get("endpoint") != expected_endpoint:
        return {
            "status": "skipped",
            "reason": (
                f"it was saved for {record.get('endpoint')}, but Skylos is now "
                f"configured for {expected_endpoint}. Set SKYLOS_API_URL to resend it."
            ),
        }
    # The saved scan must belong to the project this folder uploads to now
    # (both unlinked counts as the same token-selected project).
    if record.get("project_id") != linked_project_id:
        return {
            "status": "skipped",
            "reason": "it belongs to a different linked project than this folder.",
        }

    if not _pending_within_resend_window(pending):
        moved = _mark_pending_upload_failed(
            pending, {"reason": _TOO_OLD_REASON, "code": "TOO_OLD"}
        )
        return {
            "status": "failed",
            "error": f"Saved scan is {_TOO_OLD_REASON}.",
            "failed_path": str(moved) if moved else None,
        }

    session = UploadSession(idempotency_key=pending.idempotency_key, mode=mode)
    count = pending.finding_count
    count_text = f", {count:,} findings" if isinstance(count, int) else ""
    message = (
        f"Resending scan saved {_format_saved_time(pending.created_at)}{count_text}..."
    )
    try:
        result = _resend_saved_request(
            token, pending, session, quiet=quiet, message=message
        )
    except (ValueError, TypeError, KeyError, AttributeError, OSError) as exc:
        result = {
            "success": False,
            "error": f"The saved upload could not be read ({type(exc).__name__}).",
            "code": "PENDING_UPLOAD_INVALID",
            "retryable": False,
        }

    if result.get("success"):
        _delete_pending_upload(pending)
        return {
            "status": "already_saved" if result.get("replayed") else "sent",
            "scan_id": result.get("scan_id"),
        }
    if result.get("retryable"):
        return {"status": "kept", "error": str(result.get("error") or "")}
    moved = _mark_pending_upload_failed(pending, _failure_details(result))
    return {
        "status": "failed",
        "error": str(result.get("error") or ""),
        "failed_path": str(moved) if moved else None,
    }


def resend_pending_uploads(project_root=None, *, quiet: bool = False) -> dict[str, Any]:
    """Send scans saved by failed uploads again, each with its original key.

    A scan the server accepts (or already had) is deleted; one it rejects for
    a reason a retry cannot fix moves to ``failed/`` with the reason; one that
    fails for a temporary reason stays for the next ``skylos upload --retry``.
    """
    root = Path(project_root) if project_root is not None else _get_repo_root_for_link()
    directory = _pending_uploads_dir(root)
    pending, unreadable = _list_pending_uploads(directory)
    summary: dict[str, Any] = {
        "directory": str(directory) if directory is not None else None,
        "total": len(pending),
        "unreadable": unreadable,
        "sent": 0,
        "already_saved": 0,
        "kept": 0,
        "failed": 0,
        "skipped": 0,
        "results": [],
    }
    legacy_notice = legacy_pending_notice(root)
    if legacy_notice:
        summary["legacy_notice"] = legacy_notice
    if not pending:
        return summary

    token = get_project_token()
    if not token:
        summary["error"] = _NO_TOKEN_ERROR
        return summary
    if token.startswith("gitlab_oidc:"):
        summary["error"] = (
            "Managed GitLab uploads are never re-sent automatically. "
            "Start a fresh pipeline instead."
        )
        return summary

    if not quiet:
        _begin_contract_check()
    git_root = get_git_root()
    linked_project_id = _load_repo_link(git_root).get("project_id")
    for item in pending:
        outcome = _resend_one_pending_upload(
            token, item, linked_project_id, quiet=quiet
        )
        outcome["idempotency_key"] = item.idempotency_key
        summary[outcome["status"]] += 1
        summary["results"].append(outcome)
    if not quiet:
        notice = _newer_contract_notice()
        if notice:
            summary["contract_notice"] = notice
    return summary


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
    rule_id = str(
        item.get("rule_id") or item.get("rule") or item.get("code") or "UNKNOWN"
    )
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
