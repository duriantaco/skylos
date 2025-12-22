import os
import requests
import subprocess
from skylos.credentials import get_key

API_URL = os.getenv("SKYLOS_API_URL", "http://localhost:3000/api")


def get_project_token():
    return os.getenv("SKYLOS_TOKEN") or get_key("skylos_token")


def get_git_root():
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
    except:
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
        try:
            actor = (
                subprocess.check_output(
                    ["git", "config", "user.email"], stderr=subprocess.DEVNULL
                )
                .decode()
                .strip()
            )
        except:
            actor = os.getenv("USER", "unknown")
        return commit, branch, actor
    except Exception:
        return "unknown", "unknown", "unknown"


def extract_snippet(file_path, line_number, context=3):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        snippet_lines = [line.rstrip() for line in lines[start:end]]
        return "\n".join(snippet_lines)
    except Exception:
        return None


def check_scan_status(scan_id):
    token = get_project_token()
    try:
        response = requests.get(
            f"{API_URL}/scans/{scan_id}/poll",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        if response.status_code == 200:
            return response.json()
        return None
    except (requests.RequestException, ValueError):
        return None


def upload_report(result_json):
    token = get_project_token()
    if not token:
        return {"success": False, "error": "No token found"}

    commit, branch, actor = get_git_info()

    git_root = get_git_root()

    def process_findings(items, category):
        processed = []
        for item in items:
            file_abs = os.path.abspath(item["file"])
            snippet = extract_snippet(file_abs, item["line"])

            file_rel = item["file"]
            if git_root:
                try:
                    file_rel = os.path.relpath(file_abs, git_root)
                except:
                    file_rel = item["file"]

            processed.append(
                {
                    "rule_id": item.get("rule_id", "UNKNOWN"),
                    "file_path": file_rel,
                    "line_number": item["line"],
                    "message": item.get("message", f"Unused {item.get('name')}"),
                    "severity": item.get("severity", "MEDIUM"),
                    "category": category,
                    "snippet": snippet,
                }
            )
        return processed

    all_findings = []
    all_findings.extend(process_findings(result_json.get("danger", []), "SECURITY"))
    all_findings.extend(process_findings(result_json.get("quality", []), "QUALITY"))
    all_findings.extend(process_findings(result_json.get("secrets", []), "SECRET"))

    unused_raw = (
        result_json.get("unused_functions", [])
        + result_json.get("unused_imports", [])
        + result_json.get("unused_variables", [])
        + result_json.get("unused_classes", [])
    )
    all_findings.extend(process_findings(unused_raw, "DEAD_CODE"))

    payload = {
        "summary": result_json.get("analysis_summary", {}),
        "findings": all_findings,
        "commit_hash": commit,
        "branch": branch,
        "actor": actor,
        "is_forced": True,
    }

    try:
        response = requests.post(
            f"{API_URL}/report",
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )

        if response.status_code in (200, 201):
            data = response.json()
            return {
                "success": True,
                "scan_id": data.get("scanId"),
                "quality_gate": data.get("quality_gate"),
            }
        else:
            return {
                "success": False,
                "error": f"Server Error ({response.status_code}): {response.text}",
            }

    except Exception as e:
        return {"success": False, "error": f"Connection Error: {str(e)}"}
