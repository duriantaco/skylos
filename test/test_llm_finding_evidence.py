from pathlib import Path

from skylos.llm.analyzer import AnalyzerConfig, SkylosLLM
from skylos.llm.finding_evidence import filter_findings_with_evidence
from skylos.llm.schemas import CodeLocation, Confidence, Finding, IssueType, Severity


def _write_hard_project(tmp_path: Path) -> list[Path]:
    (tmp_path / "app.py").write_text(
        """
from flow import handle_api, handle_cli


def accept_request(event):
    if event.get("channel") == "batch":
        return handle_cli(event)
    return handle_api(event)
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "flow.py").write_text(
        """
from hooks import run_allowed, run_dynamic
from repository import compose_archive, compose_lookup


def handle_api(event):
    user = event.get("user", {})
    rows = compose_lookup(user.get("email", ""), event.get("sort", "created_at"))
    archive = compose_archive(user.get("id", "guest"))
    return {"rows": rows, "archive": archive}


def handle_cli(event):
    if event.get("mode") == "builtin":
        return run_allowed("status")
    return run_dynamic(event.get("hook", "status"), event.get("repo", "."))
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "repository.py").write_text(
        """
from storage import fetch_all


def compose_lookup(email, sort):
    query = (
        f"SELECT id, email FROM customers "
        f"WHERE email = '{email}' "
        f"ORDER BY {sort}"
    )
    return fetch_all(query)


def compose_archive(user_id):
    query = "SELECT id, closed_at FROM archived_customers WHERE id = ?"
    return fetch_all(query, [user_id])


def lab_debug_query(where_clause):
    query = f"SELECT id FROM diagnostics WHERE {where_clause}"
    return fetch_all(query)
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "hooks.py").write_text(
        """
import subprocess


ALLOWED = {
    "status": ["git", "status", "--short"],
    "version": ["git", "--version"],
}


def run_dynamic(hook_name, repo_path):
    command = f"cd {repo_path} && ./hooks/{hook_name}"
    return subprocess.run(command, shell=True, capture_output=True, text=True)


def run_allowed(name):
    return subprocess.run(ALLOWED[name], check=False, capture_output=True, text=True)


def run_sample(template, repo_path):
    command = f"cd {repo_path} && {template}"
    return subprocess.run(command, shell=True, capture_output=True, text=True)
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "storage.py").write_text(
        """
def fetch_all(query, params=None):
    return []
""".lstrip(),
        encoding="utf-8",
    )
    return sorted(tmp_path.glob("*.py"))


def _write_dynamic_project(tmp_path: Path) -> list[Path]:
    (tmp_path / "app.py").write_text(
        """
from dispatcher import dispatch


def main(event):
    return dispatch(event)
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "dispatcher.py").write_text(
        """
import importlib

HANDLERS = {
    "pay": "plugins.payments:charge_card",
    "tool": "plugins.tools:run_mutable_registered",
}


def dispatch(event):
    module_name, func_name = HANDLERS[event["type"]].split(":")
    return getattr(importlib.import_module(module_name), func_name)(event["payload"])
""".lstrip(),
        encoding="utf-8",
    )
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "__init__.py").write_text("", encoding="utf-8")
    (plugins / "payments.py").write_text(
        """
def charge_card(payload):
    query = f"SELECT id FROM payments WHERE customer = '{payload['customer']}'"
    return query


def debug_query(payload):
    query = f"SELECT id FROM diagnostics WHERE {payload['where']}"
    return query
""".lstrip(),
        encoding="utf-8",
    )
    (plugins / "tools.py").write_text(
        """
import subprocess


def run_mutable_registered(payload):
    COMMANDS = {"status": ["git", "status", "--short"]}
    key = payload.get("name", "custom")
    COMMANDS[key] = [payload.get("tool", "git"), payload.get("arg", "--version")]
    return subprocess.run(COMMANDS[key], check=False)
""".lstrip(),
        encoding="utf-8",
    )
    return sorted(tmp_path.rglob("*.py"))


def _finding(path: Path, symbol: str, message: str) -> Finding:
    return Finding(
        rule_id="SKY-L212",
        issue_type=IssueType.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        message=message,
        location=CodeLocation(file=str(path), line=1),
        symbol=symbol,
    )


def test_filter_refutes_unreachable_decoys_and_safe_sinks(tmp_path):
    files = _write_hard_project(tmp_path)
    by_name = {path.name: path for path in files}
    findings = [
        _finding(
            by_name["repository.py"],
            "compose_lookup",
            "SQL injection in compose_lookup",
        ),
        _finding(
            by_name["hooks.py"],
            "run_dynamic",
            "Command injection via subprocess.run shell=True",
        ),
        _finding(
            by_name["repository.py"],
            "compose_archive",
            "SQL injection in compose_archive",
        ),
        _finding(
            by_name["hooks.py"],
            "run_allowed",
            "Command injection via subprocess.run",
        ),
        _finding(
            by_name["repository.py"],
            "lab_debug_query",
            "SQL injection in lab_debug_query",
        ),
        _finding(
            by_name["hooks.py"],
            "run_sample",
            "Command injection via subprocess.run shell=True",
        ),
    ]

    filtered = filter_findings_with_evidence(findings, files)

    assert {finding.symbol for finding in filtered} == {"compose_lookup", "run_dynamic"}


def test_filter_keeps_security_findings_when_no_entrypoint_evidence(tmp_path):
    (tmp_path / "repository.py").write_text(
        """
from storage import fetch_all


def lab_debug_query(where_clause):
    query = f"SELECT id FROM diagnostics WHERE {where_clause}"
    return fetch_all(query)
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "storage.py").write_text(
        """
def fetch_all(query, params=None):
    return []
""".lstrip(),
        encoding="utf-8",
    )
    files = sorted(tmp_path.glob("*.py"))
    finding = _finding(
        tmp_path / "repository.py",
        "lab_debug_query",
        "SQL injection in lab_debug_query",
    )

    filtered = filter_findings_with_evidence([finding], files)

    assert filtered == [finding]


def test_filter_keeps_dynamic_registry_handlers_and_mutable_allowlist(tmp_path):
    files = _write_dynamic_project(tmp_path)
    by_name = {path.name: path for path in files}
    findings = [
        _finding(
            by_name["payments.py"],
            "charge_card",
            "SQL injection in charge_card",
        ),
        _finding(
            by_name["payments.py"],
            "debug_query",
            "SQL injection in debug_query",
        ),
        _finding(
            by_name["tools.py"],
            "run_mutable_registered",
            "Command injection via user-controlled subprocess executable",
        ),
    ]

    filtered = filter_findings_with_evidence(findings, files)

    assert {finding.symbol for finding in filtered} == {
        "charge_card",
        "run_mutable_registered",
    }


def test_filter_keeps_uppercase_allowlist_assigned_from_untrusted_payload(tmp_path):
    (tmp_path / "app.py").write_text(
        """
from tools import run_untrusted


def main(event):
    return run_untrusted(event)
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "tools.py").write_text(
        """
import subprocess


def run_untrusted(payload):
    COMMANDS = payload.get("commands", {})
    return subprocess.run(COMMANDS[payload["name"]], check=False)
""".lstrip(),
        encoding="utf-8",
    )
    files = sorted(tmp_path.glob("*.py"))
    finding = _finding(
        tmp_path / "tools.py",
        "run_untrusted",
        "Command injection via user-controlled subprocess executable",
    )

    filtered = filter_findings_with_evidence([finding], files)

    assert filtered == [finding]


def test_analyze_files_filters_after_collecting_project_graph(tmp_path, monkeypatch):
    files = _write_hard_project(tmp_path)
    by_name = {path.name: path for path in files}
    fake_findings = {
        "repository.py": [
            _finding(
                by_name["repository.py"],
                "compose_lookup",
                "SQL injection in compose_lookup",
            ),
            _finding(
                by_name["repository.py"],
                "lab_debug_query",
                "SQL injection in lab_debug_query",
            ),
        ],
        "hooks.py": [
            _finding(
                by_name["hooks.py"],
                "run_dynamic",
                "Command injection via subprocess.run shell=True",
            ),
            _finding(
                by_name["hooks.py"],
                "run_sample",
                "Command injection via subprocess.run shell=True",
            ),
        ],
    }

    def fake_analyze_file(self, file_path, *args, **kwargs):
        return list(fake_findings.get(Path(file_path).name, []))

    monkeypatch.setattr(SkylosLLM, "analyze_file", fake_analyze_file)
    analyzer = SkylosLLM(AnalyzerConfig(quiet=True))

    result = analyzer.analyze_files(files, issue_types=["security_audit"])

    assert {finding.symbol for finding in result.findings} == {
        "compose_lookup",
        "run_dynamic",
    }
