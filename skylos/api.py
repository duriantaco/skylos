import os
import requests
import subprocess
from skylos.credentials import get_key
from skylos.sarif_exporter import SarifExporter

BASE_URL = os.getenv("SKYLOS_API_URL", "https://skylos.dev").rstrip("/")

if BASE_URL.endswith("/api"):
    REPORT_URL = f"{BASE_URL}/report"
    WHOAMI_URL = f"{BASE_URL}/sync/whoami"
else:
    REPORT_URL = f"{BASE_URL}/api/report"
    WHOAMI_URL = f"{BASE_URL}/api/sync/whoami"


def get_project_token():
    return os.getenv("SKYLOS_TOKEN") or get_key("skylos_token")


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


def upload_report(result_json, is_forced=False, quiet=False):
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
                passed = data.get("quality_gate_passed", True)

                if not quiet:
                    print(f"✓ Scan uploaded")
                    print(
                        f"{'PASS' if passed else 'FAIL'} Quality gate: {'PASSED' if passed else 'FAILED'}"
                    )
                    if scan_id:
                        print(f"\nView: {BASE_URL}/dashboard/scans/{scan_id}")

                return {
                    "success": True,
                    "scan_id": scan_id,
                    "quality_gate_passed": passed,
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
