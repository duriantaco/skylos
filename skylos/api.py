import os
import requests
import subprocess
from skylos.credentials import get_key
from skylos.sarif_exporter import SarifExporter
import sys

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


def get_project_token():
    token = os.getenv("SKYLOS_TOKEN")
    if token:
        return token
    
    creds_file = os.path.expanduser("~/.skylos/credentials.json")
    if os.path.exists(creds_file):
        try:
            import json
            with open(creds_file, "r") as f:
                creds = json.load(f)
            token = creds.get("token")
            if token:
                return token
        except Exception:
            pass
    
    return get_key("skylos_token")


def get_project_info(token):
    if not token:
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


def get_git_info():
    try:
        commit = (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
        branch = (
            subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
        actor = os.getenv("GITHUB_ACTOR") or os.getenv("USER") or "unknown"
        return commit, branch, actor
    except Exception:
        return "unknown", "unknown", "unknown"


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


def upload_report(result_json, is_forced=False, quiet=False, strict=False):
    token = get_project_token()
    if not token:
        return {
            "success": False,
            "error": "No token found. Run 'skylos sync connect' or set SKYLOS_TOKEN.",
        }

    if not quiet:
        info = get_project_info(token)
        if info and info.get("ok"):
            project_name = info.get("project", {}).get("name", "Unknown")
            print(f"Uploading to: {project_name}")

    commit, branch, actor = get_git_info()
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

    exporter = SarifExporter(all_findings, tool_name="Skylos")
    payload = exporter.generate()

    info = get_project_info(token) or {}
    plan = (info.get("plan") or "free").lower()

    payload.update(
        {
            "commit_hash": commit,
            "branch": branch,
            "actor": actor,
            "is_forced": bool(is_forced),
        }
    )

    last_err = None
    for _ in range(3):
        try:
            response = requests.post(
                REPORT_URL,
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
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

    commit, branch, actor = get_git_info()
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
