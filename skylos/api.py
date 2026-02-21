import os
import requests
import subprocess
from skylos.credentials import get_key
from skylos.sarif_exporter import SarifExporter
import sys
from pathlib import Path
import json

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
    except Exception:
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
    except Exception:
        pass
    return Path.cwd()


BASE_URL = os.getenv("SKYLOS_API_URL", "https://skylos.dev").rstrip("/")

if BASE_URL.endswith("/api"):
    REPORT_URL = f"{BASE_URL}/report"
    WHOAMI_URL = f"{BASE_URL}/sync/whoami"
else:
    REPORT_URL = f"{BASE_URL}/api/report"
    WHOAMI_URL = f"{BASE_URL}/api/sync/whoami"

if BASE_URL.endswith("/api"):
    VERIFY_URL = f"{BASE_URL}/verify"
else:
    VERIFY_URL = f"{BASE_URL}/api/verify"


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
            timeout=10,
        )
        if resp.status_code == 200:
            jwt_token = resp.json().get("value")
            if jwt_token:
                return f"oidc:{jwt_token}"
    except Exception:
        pass
    return None


def get_project_token():
    token = os.getenv("SKYLOS_TOKEN")
    if token:
        return token

    oidc = _try_github_oidc_token()
    if oidc:
        return oidc

    repo_root = _get_repo_root_for_link()
    link_path = repo_root / LINK_FILE
    link = _read_json(link_path) or {}
    linked_project_id = link.get("project_id") or link.get("projectId")

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


def get_project_info(token):
    if not token:
        return None
    if token.startswith("oidc:"):
        return None
    try:
        resp = requests.get(
            WHOAMI_URL,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def get_credit_balance(token=None):
    if token is None:
        token = get_project_token()
    if not token or token.startswith("oidc:"):
        return None
    try:
        resp = requests.get(
            f"{BASE_URL}/api/credits/balance",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def print_credit_status(token=None, quiet=False):
    data = get_credit_balance(token)
    if not data or quiet:
        return data

    balance = data.get("balance", 0)
    plan = data.get("plan", "free")

    if plan == "enterprise":
        print(f"Credits: unlimited (Enterprise)")
    else:
        print(f"Credits: {balance:,}")
        if balance < 10:
            print(f"Low credits! Buy more: {BASE_URL}/dashboard/billing")

    return data


def get_git_root():
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
    except Exception:
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
    except Exception:
        return {}


def get_git_info():
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
        except Exception:
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


def extract_snippet(file_abs, line_number, context=3):
    if not file_abs:
        return None
    try:
        with open(file_abs, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        return "\n".join([line.rstrip("\n") for line in lines[start:end]])
    except Exception:
        return None


def _build_auth_headers(token):
    if token and token.startswith("oidc:"):
        return {
            "Authorization": f"Bearer {token[5:]}",
            "X-Skylos-Auth": "oidc",
        }
    return {"Authorization": f"Bearer {token}"}


def detect_ai_code(git_root=None):
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
            timeout=10,
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
                        timeout=5,
                    ).decode("utf-8", errors="ignore")
                    for f in diff_output.strip().splitlines():
                        if f.strip():
                            ai_files.add(f.strip())
                except Exception:
                    pass

    except Exception:
        pass

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


def upload_report(
    result_json, is_forced=False, quiet=False, strict=False, analysis_mode="static"
):
    token = get_project_token()
    if not token:
        return {
            "success": False,
            "error": "No token found. Run 'skylos login' or set SKYLOS_TOKEN.",
        }

    if not quiet:
        info = get_project_info(token)
        if info and info.get("ok"):
            project_name = info.get("project", {}).get("name", "Unknown")
            print(f"Uploading to: {project_name}")

    commit, branch, actor, ci = get_git_info()
    git_root = get_git_root()

    def prepare_for_sarif(items, category, default_rule_id=None):
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
            except Exception:
                line = 1
            if line < 1:
                line = 1
            finding["line_number"] = line

            if git_root and file_abs:
                try:
                    finding["file_path"] = os.path.relpath(file_abs, git_root).replace(
                        "\\", "/"
                    )
                except Exception:
                    finding["file_path"] = (
                        raw_path.replace("\\", "/") if raw_path else "unknown"
                    )
            else:
                finding["file_path"] = (
                    raw_path.replace("\\", "/") if raw_path else "unknown"
                )

            finding["category"] = category

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

            metadata = {}
            for meta_key in (
                "_source",
                "_confidence",
                "_llm_verdict",
                "_llm_rationale",
                "_llm_challenged",
                "_needs_review",
                "_llm_uncertain",
            ):
                val = finding.pop(meta_key, None)
                if val is not None:
                    metadata[meta_key.lstrip("_")] = val
            if metadata:
                finding["metadata"] = metadata

            processed.append(finding)

        return processed

    all_findings = []

    all_findings.extend(
        prepare_for_sarif(result_json.get("danger", []), "SECURITY", "SKY-D000")
    )

    all_findings.extend(
        prepare_for_sarif(result_json.get("quality", []), "QUALITY", "SKY-Q000")
    )

    all_findings.extend(
        prepare_for_sarif(result_json.get("secrets", []), "SECRET", "SKY-S000")
    )

    all_findings.extend(
        prepare_for_sarif(
            result_json.get("unused_functions", []), "DEAD_CODE", "SKY-U001"
        )
    )
    all_findings.extend(
        prepare_for_sarif(
            result_json.get("unused_imports", []), "DEAD_CODE", "SKY-U002"
        )
    )
    all_findings.extend(
        prepare_for_sarif(
            result_json.get("unused_variables", []), "DEAD_CODE", "SKY-U003"
        )
    )
    all_findings.extend(
        prepare_for_sarif(
            result_json.get("unused_classes", []), "DEAD_CODE", "SKY-U004"
        )
    )

    all_findings.extend(
        prepare_for_sarif(
            result_json.get("dependency_vulnerabilities", []),
            "DEPENDENCY",
            "SKY-SCA-000",
        )
    )

    exporter = SarifExporter(all_findings, tool_name="Skylos")
    payload = exporter.generate()

    info = get_project_info(token) or {}
    plan = (info.get("plan") or "free").lower()
    ai_code = detect_ai_code(git_root)

    payload.update(
        {
            "commit_hash": commit,
            "branch": branch,
            "actor": actor,
            "is_forced": bool(is_forced),
            "ci": ci,
            "analysis_mode": analysis_mode,
            "ai_code": ai_code if ai_code.get("detected") else None,
        }
    )

    grade_data = result_json.get("grade") if isinstance(result_json, dict) else None
    if grade_data:
        payload["grade"] = grade_data

    link = _load_repo_link(git_root)
    if link.get("project_id"):
        payload["project_id"] = link["project_id"]

    last_err = None
    for _ in range(3):
        try:
            response = requests.post(
                REPORT_URL,
                json=payload,
                headers=_build_auth_headers(token),
                timeout=30,
            )
            if response.status_code in (200, 201):
                data = response.json()
                scan_id = data.get("scanId") or data.get("scan_id")
                quality_gate = data.get("quality_gate", {})
                passed = quality_gate.get("passed", True)
                new_violations = quality_gate.get("new_violations", 0)

                plan = data.get("plan", "free")

                if not quiet:
                    print(f"✓ Scan uploaded")
                    if grade_data:
                        g = grade_data["overall"]
                        print(f"Grade: {g['letter']} ({g['score']}/100)")
                    if passed:
                        print(f"✅ PASS Quality gate: PASSED")
                    else:
                        print(
                            f"❌ FAIL Quality gate: FAILED ({new_violations} new violation{'' if new_violations == 1 else 's'})"
                        )

                    if scan_id:
                        print(f"\nView: {BASE_URL}/dashboard/scans/{scan_id}")

                    if not passed and plan == "free":
                        print(f"\n⚠️  Quality gate failed but continuing (Free plan)")
                        print(
                            f"💡 Upgrade to Pro to automatically block commits/CI on failures"
                        )
                        print(
                            f"   Learn more: {BASE_URL}/dashboard/settings?upgrade=true"
                        )

                    if scan_id:
                        print(
                            f"\n🔗 View details: {BASE_URL}/dashboard/scans/{scan_id}"
                        )

                if not quiet and data.get("credits_warning"):
                    print("\n Low credits. Top up at skylos.dev/dashboard/billing")

                if not passed:
                    if strict and (not is_forced):
                        if not quiet:
                            print(f"\n Commit blocked by quality gate")
                        sys.exit(1)

                    if not quiet:
                        print(
                            "\n⚠️ Quality gate failed, but not enforcing in local mode."
                        )

                return {
                    "success": True,
                    "scan_id": scan_id,
                    "quality_gate_passed": passed,
                    "plan": plan,
                    "credits_warning": data.get("credits_warning", False),
                }

            if response.status_code == 401:
                return {
                    "success": False,
                    "error": "Invalid API token. Run 'skylos sync connect' to reconnect.",
                }

            last_err = f"Server Error {response.status_code}: {response.text}"
        except Exception as e:
            last_err = f"Connection Error: {str(e)}"

    return {"success": False, "error": last_err or "Unknown error"}


def upload_github_check(report_json, sha, repo_owner, repo_name):
    token = get_project_token()
    if not token:
        print("Error: No token. Run 'skylos sync connect'")
        return False

    url = f"{BASE_URL}/api/github/check"

    payload = {
        "sha": sha,
        "report": report_json,
        "repo_owner": repo_owner,
        "repo_name": repo_name,
    }

    try:
        response = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )

        if response.status_code == 200:
            data = response.json()
            print(f"✓ GitHub check created: {data['summary']}")
            return data["conclusion"] == "success"
        else:
            print(f"✗ Failed to create check: {response.status_code}")
            return False

    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def verify_report(result_json, quiet=False):
    token = get_project_token()
    if not token:
        return {
            "success": False,
            "error": "Verification requires Pro token. Run 'skylos sync connect' or set SKYLOS_TOKEN.",
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

    def _norm_findings(items, category, default_rule_id=None):
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
            except Exception:
                line = 1
            if line < 1:
                line = 1
            finding["line_number"] = line

            if git_root and file_abs:
                try:
                    finding["file_path"] = os.path.relpath(file_abs, git_root).replace(
                        "\\", "/"
                    )
                except Exception:
                    finding["file_path"] = (
                        raw_path.replace("\\", "/") if raw_path else "unknown"
                    )
            else:
                finding["file_path"] = (
                    raw_path.replace("\\", "/") if raw_path else "unknown"
                )

            finding["category"] = category
            finding["severity"] = finding.get("severity") or "LOW"

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

            finding_id = f"{finding['rule_id']}::{finding['file_path']}::{finding['line_number']}"
            finding["finding_id"] = finding_id

            processed.append(finding)
        return processed

    findings = []
    findings.extend(
        _norm_findings(result_json.get("danger", []), "SECURITY", "SKY-D000")
    )
    findings.extend(
        _norm_findings(result_json.get("secrets", []), "SECRET", "SKY-S000")
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
            timeout=60,
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
            except Exception:
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
