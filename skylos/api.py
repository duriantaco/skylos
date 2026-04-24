import os
import logging
import requests
import subprocess
import contextlib
import gzip
import hashlib
import io
from skylos.credentials import get_key
from skylos.sarif_exporter import SarifExporter
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
import json
from typing import Any

from skylos.constants import (
    NETWORK_TIMEOUT_SHORT,
    NETWORK_TIMEOUT_DEFAULT,
    NETWORK_TIMEOUT_LONG,
    SNIPPET_CONTEXT_LINES,
    SUBPROCESS_TIMEOUT,
    UPLOAD_TIMEOUT,
)

logger = logging.getLogger(__name__)

LINK_FILE = ".skylos/link.json"
GLOBAL_CREDS_FILE = Path.home() / ".skylos" / "credentials.json"


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


def _extract_pr_number(provider, meta):
    env_pr = os.getenv("SKYLOS_PR_NUMBER")
    if env_pr:
        try:
            return int(env_pr)
        except ValueError:
            pass

    if provider == "github_actions":
        ref = os.getenv("GITHUB_REF", "")
        if ref.startswith("refs/pull/"):
            try:
                return int(ref.split("/")[2])
            except (IndexError, ValueError):
                pass

    if provider == "jenkins":
        change_id = meta.get("change_id")
        if change_id:
            try:
                return int(change_id)
            except ValueError:
                pass

    if provider == "circleci":
        pr_url = meta.get("pr_url") or ""
        if "/pull/" in pr_url:
            try:
                return int(pr_url.split("/pull/")[-1].strip().rstrip("/"))
            except ValueError:
                pass

    if provider == "gitlab":
        mr_iid = meta.get("merge_request_iid")
        if mr_iid:
            try:
                return int(mr_iid)
            except ValueError:
                pass

    return None


def _normalize_branch(branch):
    if not branch or not isinstance(branch, str):
        return branch
    branch = branch.removeprefix("refs/heads/")
    branch = branch.removeprefix("origin/")
    return branch


def _read_json(path: Path):
    try:
        if path and path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return None


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


UPLOAD_PROTOCOL_VERSION = 1


def _try_github_oidc_token():
    oidc_url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
    oidc_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not oidc_url or not oidc_token:
        return None
    try:
        sep = "&" if "?" in oidc_url else "?"
        resp = requests.get(
            f"{oidc_url}{sep}audience=skylos",
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
            f"{BASE_URL}/api/credits/balance",
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


def _load_repo_link(git_root):
    try:
        if not git_root:
            return {}
        p = os.path.join(git_root, ".skylos", "link.json")
        if not os.path.exists(p):
            return {}
        import json

        return json.loads(open(p, "r", encoding="utf-8").read() or "{}")
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _current_repo_subpath(git_root) -> str:
    try:
        if not git_root:
            return ""
        from skylos.project_context import repo_subpath_for_project

        return repo_subpath_for_project(Path.cwd(), git_root)
    except Exception:
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

    commit = (
        override_sha
        or meta.get("sha")
        or meta.get("git_commit")
        or meta.get("sha1")
        or meta.get("commit_sha")
    )

    branch = (
        override_branch
        or meta.get("change_branch")
        or meta.get("git_branch")
        or meta.get("branch")
        or meta.get("commit_branch")
    )
    if not branch and provider == "github_actions":
        ref = meta.get("ref") or ""
        if ref.startswith("refs/heads/"):
            branch = ref

    actor = (
        override_actor
        or meta.get("actor")
        or meta.get("username")
        or meta.get("user_login")
        or os.getenv("USER")
        or "unknown"
    )

    if not commit or not branch:
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
            commit = commit or git_commit
            branch = branch or git_branch
        except (subprocess.SubprocessError, OSError):
            commit = commit or "unknown"
            branch = branch or "unknown"

    branch = _normalize_branch(branch)

    pr_number = _extract_pr_number(provider, meta)
    ci = {}
    if provider:
        ci["provider"] = provider

    for key, value in meta.items():
        if value:
            ci[key] = value

    if pr_number:
        ci["pr_number"] = pr_number

    return commit, branch, actor, ci


def extract_snippet(file_abs, line_number, context=SNIPPET_CONTEXT_LINES) -> str | None:
    if not file_abs:
        return None
    try:
        with open(file_abs, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        return "\n".join([line.rstrip("\n") for line in lines[start:end]])
    except (OSError, UnicodeDecodeError):
        return None


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


def _json_size_bytes(payload: Any) -> int:
    return len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class UploadArtifact:
    name: str
    file_path: Path
    filename: str
    required: bool
    content_type: str
    content_encoding: str
    size_bytes: int
    sha256: str

    def to_manifest(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "filename": self.filename,
            "content_type": self.content_type,
            "content_encoding": self.content_encoding,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }

    def cleanup(self) -> None:
        with contextlib.suppress(OSError):
            self.file_path.unlink()


@dataclass
class PreparedReportUpload:
    legacy_payload: dict[str, Any]
    core_payload: dict[str, Any]
    definitions_payload: dict[str, Any] | None
    metadata: dict[str, Any]
    scan_summary: dict[str, Any]
    grade_data: dict[str, Any] | None
    legacy_payload_size_bytes: int


def _write_gzip_json_artifact(
    name: str,
    payload: dict[str, Any],
    *,
    required: bool,
) -> UploadArtifact:
    fd, path_str = tempfile.mkstemp(prefix=f"skylos-upload-{name}-", suffix=".json.gz")
    os.close(fd)
    path = Path(path_str)
    try:
        with path.open("wb") as raw_handle:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=raw_handle,
                mtime=0,
            ) as gzip_handle:
                with io.TextIOWrapper(gzip_handle, encoding="utf-8") as handle:
                    json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
        return UploadArtifact(
            name=name,
            file_path=path,
            filename=f"{name}.json.gz",
            required=required,
            content_type="application/json",
            content_encoding="gzip",
            size_bytes=path.stat().st_size,
            sha256=_sha256_file(path),
        )
    except Exception:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def detect_ai_code(git_root=None) -> dict:
    if not git_root:
        git_root = get_git_root()
    if not git_root:
        return {
            "detected": False,
            "indicators": [],
            "ai_files": [],
            "confidence": "low",
        }

    import re as _re

    indicators = []
    ai_files = set()

    AI_COAUTHOR_PATTERNS = [
        _re.compile(r"copilot", _re.IGNORECASE),
        _re.compile(r"claude", _re.IGNORECASE),
        _re.compile(r"cursor", _re.IGNORECASE),
        _re.compile(r"codewhisperer", _re.IGNORECASE),
        _re.compile(r"tabnine", _re.IGNORECASE),
        _re.compile(r"github-actions\[bot\]", _re.IGNORECASE),
        _re.compile(r"devin", _re.IGNORECASE),
    ]

    AI_EMAIL_PATTERNS = [
        _re.compile(r"\[bot\]@", _re.IGNORECASE),
        _re.compile(r"copilot", _re.IGNORECASE),
        _re.compile(r"cursor", _re.IGNORECASE),
        _re.compile(r"claude", _re.IGNORECASE),
    ]

    AI_MESSAGE_PATTERNS = [
        _re.compile(r"generated\s+by\s+(copilot|claude|cursor|ai)", _re.IGNORECASE),
        _re.compile(r"ai[- ]generated", _re.IGNORECASE),
        _re.compile(r"co-authored-by.*copilot", _re.IGNORECASE),
        _re.compile(r"co-authored-by.*claude", _re.IGNORECASE),
    ]

    try:
        log_output = subprocess.check_output(
            [
                "git",
                "log",
                "--format=%H|%an|%ae|%s|%(trailers:key=Co-authored-by,valueonly,separator=%x00)",
                "-50",
            ],
            cwd=git_root,
            stderr=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT,
        ).decode("utf-8", errors="ignore")

        for line in log_output.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split("|", 4)
            if len(parts) < 4:
                continue

            commit_sha = parts[0]
            author_name = parts[1]
            author_email = parts[2]
            subject = parts[3]

            if len(parts) > 4:
                trailers = parts[4]
            else:
                trailers = ""

            is_ai_commit = False

            for pat in AI_COAUTHOR_PATTERNS:
                if pat.search(trailers):
                    indicators.append(
                        {
                            "type": "co-author",
                            "commit": commit_sha[:7],
                            "detail": trailers.strip()[:100],
                        }
                    )
                    is_ai_commit = True
                    break

            if not is_ai_commit:
                for pat in AI_EMAIL_PATTERNS:
                    if pat.search(author_email):
                        indicators.append(
                            {
                                "type": "author-email",
                                "commit": commit_sha[:7],
                                "detail": f"{author_name} <{author_email}>",
                            }
                        )
                        is_ai_commit = True
                        break

            if not is_ai_commit:
                for pat in AI_MESSAGE_PATTERNS:
                    if pat.search(subject):
                        indicators.append(
                            {
                                "type": "commit-message",
                                "commit": commit_sha[:7],
                                "detail": subject[:100],
                            }
                        )
                        is_ai_commit = True
                        break

            if is_ai_commit:
                try:
                    diff_output = subprocess.check_output(
                        [
                            "git",
                            "diff-tree",
                            "--no-commit-id",
                            "--name-only",
                            "-r",
                            commit_sha,
                        ],
                        cwd=git_root,
                        stderr=subprocess.DEVNULL,
                        timeout=NETWORK_TIMEOUT_SHORT,
                    ).decode("utf-8", errors="ignore")
                    for f in diff_output.strip().splitlines():
                        if f.strip():
                            ai_files.add(f.strip())
                except (subprocess.SubprocessError, OSError):
                    logger.debug(
                        "Failed to get git diff-tree for AI detection", exc_info=True
                    )

    except (subprocess.SubprocessError, OSError):
        logger.debug("Failed to detect AI code from git log", exc_info=True)

    detected = len(indicators) > 0
    if len(indicators) > 5:
        confidence = "high"
    elif len(indicators) > 0:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "detected": detected,
        "indicators": indicators[:20],
        "ai_files": sorted(ai_files)[:100],
        "confidence": confidence,
    }


def _get_blame_map(findings: list, git_root: str | None) -> dict:
    if not git_root:
        return {}

    from collections import defaultdict

    files_lines = defaultdict(set)
    for f in findings:
        fp = f.get("file_path", "")
        ln = f.get("line_number", 0)
        if fp and ln and ln > 0:
            files_lines[fp].add(ln)

    blame_map = {}
    for file_path, lines in files_lines.items():
        abs_path = os.path.join(git_root, file_path)
        if not os.path.isfile(abs_path):
            continue

        cmd = ["git", "blame", "--porcelain"]
        for ln in sorted(lines):
            cmd.extend(["-L", f"{ln},{ln}"])
        cmd.extend(["--", file_path])

        try:
            out = subprocess.check_output(
                cmd,
                cwd=git_root,
                stderr=subprocess.DEVNULL,
                timeout=NETWORK_TIMEOUT_DEFAULT,
            ).decode("utf-8", errors="ignore")
        except (subprocess.SubprocessError, OSError):
            continue

        current_line = None
        for raw in out.splitlines():
            parts = raw.split()
            if len(parts) >= 3 and len(parts[0]) == 40:
                try:
                    current_line = int(parts[2])
                except ValueError:
                    current_line = None
            elif raw.startswith("author-mail ") and current_line is not None:
                email = raw[len("author-mail ") :].strip().strip("<>")
                if email and email != "not.committed.yet":
                    blame_map[(file_path, current_line)] = email

    return blame_map


def _normalize_findings(
    items,
    category,
    git_root,
    default_rule_id=None,
    default_severity=None,
    extract_metadata=False,
    generate_finding_id=False,
) -> list[dict]:
    """Unified finding normalization used by upload and verify paths."""
    if not isinstance(category, str):
        raise ValueError(f"category must be a string, got {type(category).__name__}")
    processed = []
    for item in items or []:
        finding = dict(item)

        rid = (
            finding.get("rule_id")
            or finding.get("rule")
            or finding.get("code")
            or finding.get("id")
            or default_rule_id
            or "UNKNOWN"
        )
        finding["rule_id"] = str(rid)

        raw_path = finding.get("file_path") or finding.get("file") or ""
        file_abs = os.path.abspath(raw_path) if raw_path else ""

        line_raw = finding.get("line_number") or finding.get("line") or 1
        try:
            line = int(line_raw)
        except (TypeError, ValueError):
            line = 1
        if line < 1:
            line = 1
        finding["line_number"] = line

        if git_root and file_abs:
            try:
                finding["file_path"] = os.path.relpath(file_abs, git_root).replace(
                    "\\", "/"
                )
            except (ValueError, OSError):
                finding["file_path"] = (
                    raw_path.replace("\\", "/") if raw_path else "unknown"
                )
        else:
            finding["file_path"] = (
                raw_path.replace("\\", "/") if raw_path else "unknown"
            )

        finding["category"] = category

        if default_severity:
            finding["severity"] = finding.get("severity") or default_severity

        if not finding.get("message"):
            name = (
                finding.get("name")
                or finding.get("symbol")
                or finding.get("function")
                or ""
            )
            if category == "DEAD_CODE" and name:
                finding["message"] = f"Dead code: {name}"
            else:
                finding["message"] = (
                    finding.get("detail") or finding.get("msg") or "Issue"
                )

        if file_abs and line:
            finding["snippet"] = (
                finding.get("snippet") or extract_snippet(file_abs, line) or None
            )

        if extract_metadata:
            metadata = {}
            for meta_key in (
                "_source",
                "_confidence",
                "_llm_verdict",
                "_llm_rationale",
                "_llm_challenged",
                "_needs_review",
                "_llm_uncertain",
                "_ci_blocking",
                "_security_evidence",
                "_review_verdict",
                "_review_reason",
            ):
                val = finding.pop(meta_key, None)
                if val is not None:
                    metadata[meta_key.lstrip("_")] = val
            if metadata:
                finding["metadata"] = metadata

        if generate_finding_id:
            finding_id = f"{finding['rule_id']}::{finding['file_path']}::{finding['line_number']}"
            finding["finding_id"] = finding_id

        processed.append(finding)

    return processed


UPLOAD_FINDING_SPECS = (
    ("danger", "SECURITY", "SKY-D000"),
    ("quality", "QUALITY", "SKY-Q000"),
    ("secrets", "SECRET", "SKY-S000"),
    ("unused_functions", "DEAD_CODE", "SKY-U001"),
    ("unused_imports", "DEAD_CODE", "SKY-U002"),
    ("unused_variables", "DEAD_CODE", "SKY-U003"),
    ("unused_classes", "DEAD_CODE", "SKY-U004"),
    ("dependency_vulnerabilities", "DEPENDENCY", "SKY-SCA-000"),
)

VERIFY_FINDING_SPECS = (
    ("danger", "SECURITY", "SKY-D000"),
    ("secrets", "SECRET", "SKY-S000"),
)


def _normalize_result_sections(
    result_json,
    section_specs,
    git_root,
    *,
    default_severity=None,
    extract_metadata=False,
    generate_finding_id=False,
) -> list[dict]:
    findings: list[dict] = []
    for section_name, category, default_rule_id in section_specs:
        findings.extend(
            _normalize_findings(
                result_json.get(section_name, []),
                category,
                git_root,
                default_rule_id=default_rule_id,
                default_severity=default_severity,
                extract_metadata=extract_metadata,
                generate_finding_id=generate_finding_id,
            )
        )
    return findings


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
    )
    core_payload.update(metadata)
    legacy_payload = _build_legacy_payload(core_payload, definitions)
    scan_summary = _build_report_scan_summary(all_findings, core_payload, definitions)

    return PreparedReportUpload(
        legacy_payload=legacy_payload,
        core_payload=core_payload,
        definitions_payload={"definitions": definitions} if definitions else None,
        metadata=metadata,
        scan_summary=scan_summary,
        grade_data=grade_data,
        legacy_payload_size_bytes=_json_size_bytes(legacy_payload),
    )


def _coerce_debt_snapshot_dict(debt_report) -> dict[str, Any]:
    if isinstance(debt_report, dict):
        return dict(debt_report)
    to_dict = getattr(debt_report, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, dict):
            return dict(payload)
    raise TypeError("Debt report must be a dict or expose to_dict().")


def _prepare_debt_upload(
    debt_report, *, is_forced=False, scan_bundle_id=None
) -> PreparedReportUpload:
    commit, branch, actor, ci = get_git_info()
    git_root = get_git_root()
    project_root = _infer_upload_project_root(debt_report, git_root)
    link = _load_repo_link(git_root)
    project_id = link.get("project_id")

    debt_payload = _coerce_debt_snapshot_dict(debt_report)
    debt_score = debt_payload.get("score") or {}
    debt_hotspots = debt_payload.get("hotspots") or []
    debt_summary = debt_payload.get("summary") or {}

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
            "debt_hotspots": len(debt_hotspots),
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
        "debt_hotspot_count": len(debt_hotspots),
        "debt_signal_count": int(debt_score.get("signal_count") or 0),
    }

    return PreparedReportUpload(
        legacy_payload=dict(core_payload),
        core_payload=core_payload,
        definitions_payload=None,
        metadata=metadata,
        scan_summary=scan_summary,
        grade_data=None,
        legacy_payload_size_bytes=_json_size_bytes(core_payload),
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
        from skylos.provenance import analyze_provenance

        prov_report = analyze_provenance(git_root)
        if prov_report.agent_files:
            provenance_data = prov_report.to_dict()
    except (ImportError, subprocess.SubprocessError, OSError):
        logger.debug("Provenance detection failed", exc_info=True)
    return provenance_data


def _infer_upload_project_root(payload, git_root) -> str | None:
    if not isinstance(payload, dict):
        return None

    candidates = []
    for key in ("project_root", "repo_subpath"):
        if key in payload:
            candidates.append(payload.get(key))
    summary = payload.get("analysis_summary")
    if isinstance(summary, dict) and "project_root" in summary:
        candidates.append(summary.get("project_root"))
    if "project" in payload:
        candidates.append(payload.get("project"))

    try:
        from skylos.project_context import normalize_repo_subpath, repo_subpath_for_project
    except Exception:
        return None

    for candidate in candidates:
        if candidate is None:
            continue
        if isinstance(candidate, str):
            if candidate.strip() == "":
                return ""
            if Path(candidate).is_absolute():
                return repo_subpath_for_project(candidate, git_root)
            normalized = normalize_repo_subpath(candidate)
            if normalized is not None:
                return normalized
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
    }
    if grade_data:
        metadata["grade"] = grade_data
    if project_id:
        metadata["project_id"] = project_id
    if scan_bundle_id:
        metadata["scan_bundle_id"] = str(scan_bundle_id)
    if project_root is not None:
        metadata["project_root"] = str(project_root)
    return metadata


def _build_legacy_payload(core_payload, definitions) -> dict[str, Any]:
    legacy_payload = dict(core_payload)
    legacy_payload["definitions"] = definitions
    return legacy_payload


def _build_report_scan_summary(
    all_findings: list[dict], core_payload: dict[str, Any], definitions
) -> dict[str, int]:
    runs = core_payload.get("runs") or []
    return {
        "finding_count": len(all_findings),
        "sarif_result_count": sum(len(run.get("results") or []) for run in runs),
        "sarif_rule_count": sum(
            len((run.get("tool") or {}).get("driver", {}).get("rules") or [])
            for run in runs
        ),
        "definitions_count": len(definitions or {}),
    }


def _build_report_init_idempotency_key(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"report-upload:{digest}"


def _build_report_artifacts(
    prepared: PreparedReportUpload,
) -> dict[str, UploadArtifact]:
    artifacts = {
        "scan_report": _write_gzip_json_artifact(
            "scan-report", prepared.core_payload, required=True
        )
    }
    if prepared.definitions_payload:
        artifacts["definitions"] = _write_gzip_json_artifact(
            "definitions", prepared.definitions_payload, required=False
        )
    return artifacts


def _build_report_init_payload(
    prepared: PreparedReportUpload,
    artifacts: dict[str, UploadArtifact],
) -> dict[str, Any]:
    init_payload = dict(prepared.metadata)
    init_payload.update(
        {
            "upload_protocol_version": UPLOAD_PROTOCOL_VERSION,
            "summary": {
                **prepared.scan_summary,
                "legacy_payload_size_bytes": prepared.legacy_payload_size_bytes,
            },
            "artifacts": {
                name: artifact.to_manifest() for name, artifact in artifacts.items()
            },
        }
    )
    init_payload["idempotency_key"] = _build_report_init_idempotency_key(init_payload)
    return init_payload


def _finalize_report_upload(
    response,
    *,
    grade_data,
    quiet=False,
    strict=False,
    is_forced=False,
) -> dict:
    if response.status_code == 401:
        return {
            "success": False,
            "error": "Invalid API token. Run 'skylos login' to reconnect or 'skylos sync connect' to set a token manually.",
        }

    if response.status_code == 402:
        data = {}
        try:
            data = response.json()
        except (ValueError, KeyError):
            pass
        return {
            "success": False,
            "error": data.get(
                "error",
                "No credits remaining. Buy more at skylos.dev/dashboard/credits",
            ),
            "code": "NO_CREDITS",
        }

    data = response.json()
    scan_id = data.get("scanId") or data.get("scan_id")
    quality_gate = data.get("quality_gate", {})
    passed = quality_gate.get("passed", True)
    new_violations = quality_gate.get("new_violations", 0)

    plan = data.get("plan", "free")

    if not quiet:
        print(" done!\n✓ Scan uploaded")
        if grade_data:
            g = grade_data["overall"]
            print(f"Grade: {g['letter']} ({g['score']}/100)")
        if passed:
            print("✅ PASS Quality gate: PASSED")
        else:
            print(
                f"❌ FAIL Quality gate: FAILED ({new_violations} new violation{'' if new_violations == 1 else 's'})"
            )

        if scan_id:
            print(f"\nView: {BASE_URL}/dashboard/scans/{scan_id}")

        if not passed and plan == "free":
            print("\n⚠️  Quality gate failed but continuing (Free plan)")
            print("💡 Upgrade to Pro to automatically block commits/CI on failures")
            print(f"   Learn more: {BASE_URL}/dashboard/settings?upgrade=true")

        if scan_id:
            print(f"\n🔗 View details: {BASE_URL}/dashboard/scans/{scan_id}")

    credits_left = data.get("credits_remaining")
    if not quiet and credits_left is not None:
        if credits_left < 50:
            print(
                f"\n⚠️  Credits remaining: {credits_left}. Top up at skylos.dev/dashboard/billing"
            )
        else:
            print(f"\n💰 Credits remaining: {credits_left}")

    if not passed:
        if strict and (not is_forced):
            if not quiet:
                print("\n Commit blocked by quality gate")
            sys.exit(1)

        if not quiet:
            print("\n⚠️ Quality gate failed, but not enforcing in local mode.")

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
):
    last_err = None
    for attempt in range(3):
        try:
            if not quiet:
                if attempt == 0 and initial_message:
                    print(initial_message, end="", flush=True)
                elif attempt > 0:
                    print(f" retrying ({attempt + 1}/3)...", end="", flush=True)
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=NETWORK_TIMEOUT_LONG,
            )
            if response.status_code in accepted_statuses:
                return response, None
            if not quiet and response.status_code >= 400:
                print(" failed.")
            last_err = f"Server Error {response.status_code}: {response.text}"
        except Exception as e:
            last_err = f"Connection Error: {str(e)}"

    return None, last_err or "Unknown error"


def _post_report_payload(token, payload, *, quiet=False, initial_message=None):
    return _post_json_with_retries(
        REPORT_URL,
        _build_auth_headers(token),
        payload,
        quiet=quiet,
        initial_message=initial_message,
    )


def _build_large_upload_protocol_error(prepared: PreparedReportUpload) -> dict:
    limit = _legacy_inline_upload_limit_bytes()
    error = (
        "Connected Skylos Cloud endpoint does not support large scan uploads yet. "
        f"This scan requires artifact upload because the inline payload is "
        f"{prepared.legacy_payload_size_bytes} bytes and the client safety limit is "
        f"{limit} bytes. Upgrade the Skylos Cloud endpoint to support "
        f"{REPORT_INIT_URL} and {REPORT_COMPLETE_URL}."
    )
    if not _truthy_env("SKYLOS_ALLOW_DEGRADED_LARGE_UPLOAD"):
        error += (
            " During rollout, you can opt into a condensed compatibility upload "
            "with SKYLOS_ALLOW_DEGRADED_LARGE_UPLOAD=1."
        )
    return {
        "success": False,
        "error": error,
        "code": "UPLOAD_PROTOCOL_UNSUPPORTED",
    }


def upload_artifact(
    artifact: UploadArtifact, instruction: dict[str, Any]
) -> dict[str, Any]:
    method = str(instruction.get("method") or "PUT").upper()
    url = instruction.get("url")
    if not url:
        return {"success": False, "error": f"Missing upload URL for {artifact.name}."}

    headers = dict(instruction.get("headers") or {})
    accepted_statuses = tuple(instruction.get("accepted_statuses") or (200, 201, 204))
    timeout = instruction.get("timeout_seconds") or UPLOAD_TIMEOUT
    last_err = None

    for _attempt in range(3):
        try:
            with artifact.file_path.open("rb") as handle:
                if method == "PUT":
                    req_headers = {
                        "Content-Type": artifact.content_type,
                        "Content-Encoding": artifact.content_encoding,
                        **headers,
                    }
                    response = requests.put(
                        url,
                        data=handle,
                        headers=req_headers,
                        timeout=timeout,
                    )
                elif method == "POST":
                    file_field = instruction.get("file_field") or "file"
                    fields = dict(instruction.get("fields") or {})
                    response = requests.post(
                        url,
                        data=fields,
                        files={
                            file_field: (
                                artifact.filename,
                                handle,
                                artifact.content_type,
                            )
                        },
                        headers=headers,
                        timeout=timeout,
                    )
                else:
                    return {
                        "success": False,
                        "error": f"Unsupported upload method for {artifact.name}: {method}",
                    }

            if response.status_code in accepted_statuses:
                return {
                    "success": True,
                    "etag": response.headers.get("ETag"),
                }
            last_err = f"Upload Error {response.status_code}: {response.text}"
        except Exception as e:
            last_err = f"Upload connection error: {e}"

    return {"success": False, "error": last_err or "Unknown artifact upload error"}


def upload_report_legacy(
    token,
    payload,
    *,
    grade_data,
    quiet=False,
    strict=False,
    is_forced=False,
    initial_message="Uploading scan results...",
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


def _missing_artifact_instruction_result(
    artifact_name: str, artifact: UploadArtifact
) -> dict[str, Any]:
    if artifact.required:
        return {
            "success": False,
            "error": f"Large-upload response omitted required artifact instructions for {artifact_name}.",
        }
    return {"name": artifact_name, "reason": "not_requested"}


def _append_skipped_artifact(
    skipped_artifacts: list[dict[str, Any]],
    artifact_name: str,
    reason: str,
    error: str | None = None,
) -> None:
    record = {"name": artifact_name, "reason": reason}
    if error is not None:
        record["error"] = error
    skipped_artifacts.append(record)


def _build_uploaded_artifact_record(
    artifact: UploadArtifact,
    artifact_info: dict[str, Any],
    upload_result: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "artifact_id": artifact_info.get("artifact_id") or artifact_info.get("id"),
        "key": artifact_info.get("key") or artifact_info.get("artifact_key"),
        "filename": artifact.filename,
        "size_bytes": artifact.size_bytes,
        "sha256": artifact.sha256,
        "content_type": artifact.content_type,
        "content_encoding": artifact.content_encoding,
    }
    if upload_result.get("etag"):
        record["etag"] = upload_result["etag"]
    return record


def _build_report_complete_payload(
    init_data: dict[str, Any],
    uploaded_artifacts: dict[str, dict[str, Any]],
    skipped_artifacts: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "upload_protocol_version": UPLOAD_PROTOCOL_VERSION,
        "scan_id": init_data.get("scan_id") or init_data.get("scanId"),
        "upload_id": init_data.get("upload_id") or init_data.get("uploadId"),
        "artifacts": uploaded_artifacts,
    }
    if metadata and "project_root" in metadata:
        payload["project_root"] = metadata["project_root"]
    if skipped_artifacts:
        payload["skipped_artifacts"] = skipped_artifacts
    return payload


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
        init_payload = _build_report_init_payload(prepared, artifacts)
        init_response, last_err = _post_json_with_retries(
            REPORT_INIT_URL,
            _build_auth_headers(token),
            init_payload,
            quiet=quiet,
            initial_message="Uploading scan results...",
            accepted_statuses=(200, 201, 401, 402, 404, 405, 501),
        )
        if init_response is None:
            return {"success": False, "error": last_err or "Unknown error"}
        if init_response.status_code in (404, 405, 501):
            return _build_large_upload_protocol_error(prepared)
        if init_response.status_code == 401:
            return _finalize_report_upload(
                init_response,
                grade_data=prepared.grade_data,
                quiet=quiet,
                strict=strict,
                is_forced=is_forced,
            )
        if init_response.status_code == 402:
            return _finalize_report_upload(
                init_response,
                grade_data=prepared.grade_data,
                quiet=quiet,
                strict=strict,
                is_forced=is_forced,
            )

        init_data = init_response.json() or {}
        artifact_instructions = init_data.get("artifacts") or {}
        if not isinstance(artifact_instructions, dict):
            return {
                "success": False,
                "error": "Invalid large-upload response: missing artifact instructions.",
            }

        uploaded_artifacts = {}
        skipped_artifacts = []

        for artifact_name, artifact in artifacts.items():
            artifact_info = artifact_instructions.get(artifact_name)
            if not artifact_info:
                missing_result = _missing_artifact_instruction_result(
                    artifact_name, artifact
                )
                if not missing_result.get("success", True):
                    return missing_result
                _append_skipped_artifact(
                    skipped_artifacts,
                    artifact_name,
                    missing_result["reason"],
                )
                continue

            upload_spec = artifact_info.get("upload") or artifact_info
            upload_result = upload_artifact(artifact, upload_spec)
            if not upload_result["success"]:
                if artifact.required:
                    return {
                        "success": False,
                        "error": upload_result["error"],
                    }
                _append_skipped_artifact(
                    skipped_artifacts,
                    artifact_name,
                    "upload_failed",
                    upload_result["error"],
                )
                continue

            uploaded_artifacts[artifact_name] = _build_uploaded_artifact_record(
                artifact,
                artifact_info,
                upload_result,
            )

        complete_payload = _build_report_complete_payload(
            init_data,
            uploaded_artifacts,
            skipped_artifacts,
            prepared.metadata,
        )

        complete_response, last_err = _post_json_with_retries(
            REPORT_COMPLETE_URL,
            _build_auth_headers(token),
            complete_payload,
            quiet=True,
            accepted_statuses=(200, 201, 401, 402),
        )
        if complete_response is None:
            return {"success": False, "error": last_err or "Unknown error"}

        return _finalize_report_upload(
            complete_response,
            grade_data=prepared.grade_data,
            quiet=quiet,
            strict=strict,
            is_forced=is_forced,
        )
    finally:
        for artifact in artifacts.values():
            artifact.cleanup()


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
                " Skylos Cloud artifact upload unavailable; retrying condensed compatibility upload...",
                end="",
                flush=True,
            )
        return upload_report_legacy(
            token,
            prepared.core_payload,
            grade_data=prepared.grade_data,
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
                " Skylos Cloud artifact upload unavailable; retrying condensed compatibility upload...",
                end="",
                flush=True,
            )
        return upload_report_legacy(
            token,
            prepared.core_payload,
            grade_data=prepared.grade_data,
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
    return (
        (not upload_result.get("success"))
        and upload_result.get("code") == "UPLOAD_PROTOCOL_UNSUPPORTED"
        and _truthy_env("SKYLOS_ALLOW_DEGRADED_LARGE_UPLOAD")
    )


def upload_defense_report(defense_json_str, quiet=False, scan_bundle_id=None) -> dict:
    """Upload defense scan results to the cloud dashboard."""
    token = get_project_token()
    if not token:
        return {
            "success": False,
            "error": "No token found. Run 'skylos login' or 'skylos project use', or set SKYLOS_TOKEN.",
        }

    import json as _json

    try:
        defense_data = _json.loads(defense_json_str)
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Invalid defense JSON: {e}"}

    commit, branch, actor, ci = get_git_info()
    git_root = get_git_root()
    project_root = _infer_upload_project_root(defense_data, git_root)

    link = _load_repo_link(git_root)

    payload = {
        "commit_hash": commit,
        "branch": branch,
        "actor": actor,
        "tool": "skylos-defend",
        "summary": {},
        "findings": [],
        "defense_score": defense_data.get("summary"),
        "ops_score": defense_data.get("ops_score"),
        "owasp_coverage": defense_data.get("owasp_coverage"),
        "defense_findings": defense_data.get("findings", []),
        "defense_integrations": defense_data.get("integrations", []),
    }
    if project_root is not None:
        payload["project_root"] = project_root

    if link.get("project_id"):
        payload["project_id"] = link["project_id"]
    if scan_bundle_id:
        payload["scan_bundle_id"] = str(scan_bundle_id)

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

    if response.status_code == 401:
        if not quiet:
            print(" failed.")
        return {
            "success": False,
            "error": "Invalid API token. Run 'skylos login' to reconnect or 'skylos sync connect' to set a token manually.",
        }

    if response.status_code == 402:
        if not quiet:
            print(" failed.")
        return {
            "success": False,
            "error": "No credits remaining. Buy more at skylos.dev/dashboard/credits",
            "code": "NO_CREDITS",
        }

    data = response.json()
    scan_id = data.get("scanId") or data.get("scan_id")

    if not quiet:
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

    return {
        "success": True,
        "scan_id": scan_id,
    }


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
    except Exception:
        pass


def verify_report(result_json, quiet=False) -> dict:
    token = get_project_token()
    if not token:
        return {
            "success": False,
            "error": "Verification requires a valid Skylos token. Run 'skylos login' or set SKYLOS_TOKEN.",
        }

    info = get_project_info(token) or {}
    plan = (info.get("plan") or "free").lower()

    if plan not in ["pro", "enterprise", "beta"]:
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

    payload = {
        "commit_hash": commit,
        "branch": branch,
        "actor": actor,
        "findings": findings,
    }

    try:
        resp = requests.post(
            VERIFY_URL,
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=UPLOAD_TIMEOUT,
        )
    except Exception as e:
        return {"success": False, "error": f"Verification connection failed: {e}"}

    if resp.status_code in (401, 403):
        return {
            "success": False,
            "error": "Verification denied (token invalid or not paid).",
        }

    if resp.status_code == 402:
        return {
            "success": False,
            "error": "Verification requires Skylos Pro (payment required).",
        }

    if resp.status_code != 200:
        return {
            "success": False,
            "error": f"Verifier error {resp.status_code}: {resp.text[:2000]}",
        }

    data = resp.json() or {}
    results = data.get("results") or []

    by_id = {}
    for r in results:
        fid = r.get("finding_id") or r.get("id")
        if fid:
            by_id[fid] = r

    def _merge_into(items):
        for it in items or []:
            rule_id = str(
                it.get("rule_id") or it.get("rule") or it.get("code") or "UNKNOWN"
            )
            file_path = (it.get("file_path") or it.get("file") or "unknown").replace(
                "\\", "/"
            )
            line = it.get("line_number") or it.get("line") or 1
            try:
                line = int(line)
            except (TypeError, ValueError):
                line = 1
            fid = f"{rule_id}::{file_path}::{line}"
            vr = by_id.get(fid)
            if vr:
                it["verification"] = vr

    _merge_into(result_json.get("danger", []))
    _merge_into(result_json.get("secrets", []))

    verdict_counts = {"VERIFIED": 0, "REFUTED": 0, "UNKNOWN": 0}
    for r in results:
        v = (r.get("verdict") or "UNKNOWN").upper()
        if v not in verdict_counts:
            v = "UNKNOWN"
        verdict_counts[v] += 1

    if not quiet:
        print(
            f"Verifier results: ✅{verdict_counts['VERIFIED']}  ❌{verdict_counts['REFUTED']}  ⚠️{verdict_counts['UNKNOWN']}"
        )

    return {"success": True, "counts": verdict_counts}
