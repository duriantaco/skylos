"""Tool runners and output normalizers.

Every runner executes the real tool as a subprocess, records wall time, exit
code and raw output, and a normalizer converts the raw output into a common
finding schema:

    {"tool", "rule", "file", "line", "end_line", "severity", "category", "message"}

``category`` is one of: security, secret, dead_code, ai_defect, quality,
dependency. Normalizers also extract *incompleteness signals*: parse errors,
skipped targets, or analysis errors that the tool itself reported.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .corpus import Workspace

CATEGORIES = ("security", "secret", "ai_defect", "dead_code", "quality", "dependency")
TOOL_TIMEOUT_S = 900

SEMGREP_PACKS = ("p/python", "p/javascript", "p/typescript", "p/security-audit", "p/secrets")
SEMGREP_REGISTRY = "https://semgrep.dev/c/"


@dataclass
class RunRecord:
    tool: str
    workspace: str
    status: str  # ok | error | timeout | not_run | not_applicable
    exit_code: int | None
    wall_s: float | None
    command: list[str]
    raw_path: str | None
    stderr_tail: str = ""
    targets: list[str] = field(default_factory=list)
    note: str = ""


def _run(cmd: list[str], cwd: Path, raw_path: Path, env: dict | None = None, stdout_is_raw: bool = False) -> tuple[int | None, float, str, str]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=TOOL_TIMEOUT_S, env=env
        )
    except subprocess.TimeoutExpired:
        return None, time.perf_counter() - start, "timeout", ""
    wall = time.perf_counter() - start
    if stdout_is_raw:
        raw_path.write_text(proc.stdout)
    return proc.returncode, wall, proc.stderr[-4000:], proc.stdout


# ------------------------------------------------------------------ Skylos


class Skylos:
    name = "skylos"
    # Dead code is on by default; these flags add the source analyzers of `-a`
    # except --sca (dependency CVE lookups), which no other tool here performs.
    flags = ("--danger", "--secrets", "--quality", "--ai-defects")

    def __init__(self, repo: Path, python: str = sys.executable):
        self.repo = repo
        self.python = python

    def version(self) -> str:
        env = {**os.environ, "PYTHONPATH": str(self.repo)}
        out = subprocess.run(
            [self.python, "-m", "skylos.entry", "--version"], capture_output=True, text=True, env=env
        ).stdout.strip()
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, capture_output=True, text=True
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "skylos"], cwd=self.repo, capture_output=True, text=True
        ).stdout.strip()
        tree_digest = _tree_digest(self.repo / "skylos")
        return f"{out} (run from source @ {commit}{' + uncommitted changes' if dirty else ''}; skylos/ tree sha256 {tree_digest[:16]})"

    def run(self, ws: Workspace, out_dir: Path) -> RunRecord:
        raw = out_dir / f"{ws.id}.json"
        cmd = [
            self.python, "-m", "skylos.entry", ".", *self.flags,
            "--diff-base", ws.diff_base, "--format", "json", "--no-upload", "-o", str(raw),
        ]
        env = {**os.environ, "PYTHONPATH": str(self.repo), "SKYLOS_NO_UPLOAD": "1"}
        if raw.exists():
            raw.unlink()
        code, wall, err, _ = _run(cmd, ws.path, raw, env=env)
        # Exit 2 means "analysis incomplete" (e.g. a file failed to parse); the
        # JSON report is still written and lists the failure under analysis_errors.
        status = "timeout" if code is None else ("ok" if raw.exists() and code in (0, 1, 2) else "error")
        note = "exit 2: analysis incomplete" if code == 2 else ""
        if status == "ok":
            self._trim(raw)
        return RunRecord(self.name, ws.id, status, code, wall, cmd, str(raw) if raw.exists() else None, err, ["."], note)

    # Bulk sections that are not findings (symbol tables, liveness evidence,
    # allow-listed symbols, metrics). Dropped after each run to bound disk use;
    # finding buckets, analysis_errors and analysis_summary are kept verbatim.
    TRIM_KEYS = ("definitions", "dead_code_evidence", "whitelisted", "architecture_metrics", "provenance", "workspaces")

    @classmethod
    def _trim(cls, raw: Path) -> None:
        data = json.loads(raw.read_text())
        for key in cls.TRIM_KEYS:
            data.pop(key, None)
        raw.write_text(json.dumps(data))

    BUCKET_CATEGORY = {
        "unused_functions": "dead_code", "unused_imports": "dead_code", "unused_variables": "dead_code",
        "unused_classes": "dead_code", "unused_parameters": "dead_code", "unused_files": "dead_code",
        "unused_exports": "dead_code", "unused_fixtures": "dead_code",
        "danger": "security", "secrets": "secret", "ai_defects": "ai_defect",
        "quality": "quality", "reliability": "quality", "circular_dependencies": "quality",
        "custom_rules": "quality", "dependency_vulnerabilities": "dependency",
    }
    DEFAULT_RULE = {
        "unused_functions": "SKY-U001", "unused_imports": "SKY-U002", "unused_variables": "SKY-U003",
        "unused_classes": "SKY-U004", "unused_parameters": "SKY-U006", "unused_files": "SKY-E002",
    }
    FINDING_CATEGORY = {
        "ai_defect": "ai_defect", "ai_defects": "ai_defect", "secret": "secret", "secrets": "secret",
        "security": "security", "danger": "security", "dead_code": "dead_code", "dependency": "dependency",
    }

    def normalize(self, rec: RunRecord, ws: Workspace) -> tuple[list[dict], dict]:
        data = json.loads(Path(rec.raw_path).read_text())
        findings = []
        for bucket, category in self.BUCKET_CATEGORY.items():
            for item in data.get(bucket) or []:
                if not isinstance(item, dict):
                    continue
                file = item.get("file") or item.get("file_path")
                line = item.get("line") or item.get("line_number") or 1
                if not file:
                    continue
                own = str(item.get("category") or "").lower()
                cat = self.FINDING_CATEGORY.get(own, category)
                rule_id = str(item.get("rule_id") or "")
                if rule_id.startswith("SKY-S") and bucket != "dependency_vulnerabilities":
                    cat = "secret"  # secret rules can be emitted through the danger bucket for JS/TS
                findings.append(
                    {
                        "tool": self.name,
                        "rule": item.get("rule_id") or self.DEFAULT_RULE.get(bucket, bucket),
                        "file": _rel(file, ws.path),
                        "line": int(line),
                        "end_line": int(item.get("end_line") or line),
                        "severity": str(item.get("severity") or "").upper() or None,
                        "category": cat,
                        "message": item.get("message") or f"Unused {item.get('type', 'symbol')}: {item.get('name')}",
                    }
                )
        errors = data.get("analysis_errors") or []
        summary = data.get("analysis_summary") or {}
        signals = {
            "reported_errors": [
                {"file": _rel(e.get("file", ""), ws.path) if isinstance(e, dict) else "", "message": (e.get("message") or e.get("error") or str(e))[:300] if isinstance(e, dict) else str(e)[:300]}
                for e in errors
            ],
            "analysis_error_count": summary.get("analysis_error_count"),
            "files_analyzed": summary.get("total_files"),
        }
        return findings, signals


# ------------------------------------------------------------------ Semgrep


class Semgrep:
    name = "semgrep"

    def __init__(self, binary: str, rules_dir: Path):
        self.binary = binary
        self.rules_dir = rules_dir

    def fetch_rules(self) -> dict:
        """Snapshot each registry pack once so every run in a benchmark uses identical rules."""
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        manifest = {}
        for pack in SEMGREP_PACKS:
            path = self.rules_dir / (pack.replace("/", "_") + ".yaml")
            if not path.exists():
                with urllib.request.urlopen(SEMGREP_REGISTRY + pack, timeout=60) as resp:
                    path.write_bytes(resp.read())
            body = path.read_bytes()
            manifest[pack] = {
                "file": path.name,
                "sha256": hashlib.sha256(body).hexdigest(),
                "rules": body.decode().count("\n- id: "),
                "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime)),
            }
        (self.rules_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
        return manifest

    def version(self) -> str:
        return subprocess.run([self.binary, "--version"], capture_output=True, text=True).stdout.strip()

    def run(self, ws: Workspace, out_dir: Path) -> RunRecord:
        raw = out_dir / f"{ws.id}.json"
        targets = ws.changed_files
        if not targets:
            return RunRecord(self.name, ws.id, "not_applicable", None, None, [], None, note="no changed files")
        configs = []
        for pack in SEMGREP_PACKS:
            configs += ["--config", str(self.rules_dir / (pack.replace("/", "_") + ".yaml"))]
        cmd = [
            self.binary, "scan", *configs, "--json", "--metrics", "off", "--disable-version-check",
            "--no-git-ignore", "--quiet", "--", *targets,
        ]
        env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
        code, wall, err, _ = _run(cmd, ws.path, raw, env=env, stdout_is_raw=True)
        ok = code is not None and code in (0, 1) and raw.stat().st_size > 0
        status = "timeout" if code is None else ("ok" if ok else "error")
        return RunRecord(self.name, ws.id, status, code, wall, cmd, str(raw), err, targets)

    @staticmethod
    def _category(check_id: str, meta: dict) -> str:
        cid = check_id.lower()
        if ".secrets." in cid or "secret" in cid.split(".")[-1] or ("hardcoded" in cid and "token" in cid):
            return "secret"
        if "secrets" in [str(t).lower() for t in meta.get("technology", []) or []]:
            return "secret"
        cat = str(meta.get("category") or "").lower()
        return "security" if cat == "security" else "quality"

    def normalize(self, rec: RunRecord, ws: Workspace) -> tuple[list[dict], dict]:
        data = json.loads(Path(rec.raw_path).read_text())
        findings = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {}) or {}
            findings.append(
                {
                    "tool": self.name,
                    "rule": _short_semgrep_id(r["check_id"]),
                    "file": _rel(r["path"], ws.path),
                    "line": r["start"]["line"],
                    "end_line": r["end"]["line"],
                    "severity": r.get("extra", {}).get("severity"),
                    "category": self._category(r["check_id"], meta),
                    "message": " ".join(str(r.get("extra", {}).get("message", "")).split())[:400],
                }
            )
        scanned = {_rel(p, ws.path) for p in (data.get("paths", {}) or {}).get("scanned", [])}
        signals = {
            "reported_errors": [
                {
                    "file": _rel(e.get("path", "") or "", ws.path),
                    "type": e.get("type") if isinstance(e.get("type"), str) else json.dumps(e.get("type"))[:120],
                    "level": e.get("level"),
                    "message": str(e.get("message", ""))[:300],
                }
                for e in data.get("errors", [])
            ],
            "targets_not_scanned": sorted(set(rec.targets) - scanned) if scanned else None,
            "files_analyzed": len(scanned) if scanned else None,
        }
        return findings, signals


def _short_semgrep_id(check_id: str) -> str:
    """Semgrep prefixes rules loaded from local files with the dotted path of
    their directory (``<work>/semgrep-rules``); strip it so rule IDs and label
    fingerprints do not depend on where the work directory lives."""
    marker = "semgrep-rules."
    return check_id.split(marker, 1)[1] if marker in check_id else check_id


# ------------------------------------------------------------------ Bandit


class Bandit:
    name = "bandit"
    SECRET_TESTS = {"B105", "B106", "B107"}

    def __init__(self, binary: str):
        self.binary = binary

    def version(self) -> str:
        return " ".join(subprocess.run([self.binary, "--version"], capture_output=True, text=True).stdout.split()[:2])

    def run(self, ws: Workspace, out_dir: Path) -> RunRecord:
        raw = out_dir / f"{ws.id}.json"
        targets = [f for f in ws.changed_files if f.endswith(".py")]
        if not targets:
            return RunRecord(self.name, ws.id, "not_applicable", None, None, [], None, note="no changed Python files")
        cmd = [self.binary, "-f", "json", "-o", str(raw), "-q", *targets]
        if raw.exists():
            raw.unlink()
        code, wall, err, _ = _run(cmd, ws.path, raw)
        status = "timeout" if code is None else ("ok" if raw.exists() and code in (0, 1) else "error")
        return RunRecord(self.name, ws.id, status, code, wall, cmd, str(raw) if raw.exists() else None, err, targets)

    def normalize(self, rec: RunRecord, ws: Workspace) -> tuple[list[dict], dict]:
        data = json.loads(Path(rec.raw_path).read_text())
        findings = []
        for r in data.get("results", []):
            line_range = r.get("line_range") or [r["line_number"]]
            findings.append(
                {
                    "tool": self.name,
                    "rule": f"{r['test_id']}:{r['test_name']}",
                    "file": _rel(r["filename"], ws.path),
                    "line": r["line_number"],
                    "end_line": max(line_range),
                    "severity": f"{r['issue_severity']}/{r['issue_confidence']}",
                    "category": "secret" if r["test_id"] in self.SECRET_TESTS else "security",
                    "message": r["issue_text"][:400],
                }
            )
        totals = (data.get("metrics") or {}).get("_totals", {})
        signals = {
            "reported_errors": [
                {"file": _rel(e.get("filename", ""), ws.path), "message": str(e.get("reason", ""))[:300]}
                for e in data.get("errors", [])
            ],
            "files_analyzed": len([k for k in (data.get("metrics") or {}) if k != "_totals"]),
            "loc": totals.get("loc"),
        }
        return findings, signals


# ------------------------------------------------------------------ SonarQube


class Sonar:
    """SonarQube (Community Build or Server) via sonar-scanner and the Web API.

    Requires SONAR_HOST_URL and SONAR_TOKEN, and a ``sonar-scanner`` binary
    (override with SONAR_SCANNER). Each workspace is analyzed as its own
    project ``agent-pr-bench-<workspace id>`` restricted to the changed files;
    issues come from ``api/issues/search`` and security hotspots from
    ``api/hotspots/search``.
    """

    name = "sonarqube"

    def __init__(self):
        self.url = (os.environ.get("SONAR_HOST_URL") or "").rstrip("/")
        self.token = os.environ.get("SONAR_TOKEN") or ""
        self.scanner = os.environ.get("SONAR_SCANNER") or shutil.which("sonar-scanner") or ""

    def availability(self) -> str | None:
        missing = [n for n, v in (("SONAR_HOST_URL", self.url), ("SONAR_TOKEN", self.token), ("sonar-scanner", self.scanner)) if not v]
        if missing:
            return "not configured: missing " + ", ".join(missing)
        try:
            status = self._get("api/system/status")
        except Exception as exc:  # noqa: BLE001 - report any connectivity failure verbatim
            return f"server unreachable: {exc}"
        if status.get("status") != "UP":
            return f"server status {status.get('status')}"
        return None

    def version(self) -> str:
        try:
            req = urllib.request.Request(f"{self.url}/api/server/version", headers=self._headers())
            with urllib.request.urlopen(req, timeout=30) as resp:
                return "SonarQube " + resp.read().decode().strip()
        except Exception as exc:  # noqa: BLE001
            return f"unknown ({exc})"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def _get(self, path: str, params: dict | None = None) -> dict:
        query = ("?" + urllib.parse.urlencode(params)) if params else ""
        req = urllib.request.Request(f"{self.url}/{path}{query}", headers=self._headers())
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())

    def project_key(self, ws: Workspace) -> str:
        return f"agent-pr-bench-{ws.id}"

    def run(self, ws: Workspace, out_dir: Path) -> RunRecord:
        raw = out_dir / f"{ws.id}.json"
        reason = self.availability()
        if reason:
            return RunRecord(self.name, ws.id, "not_run", None, None, [], None, note=reason)
        targets = ws.changed_files
        key = self.project_key(ws)
        work = out_dir / f"{ws.id}.scannerwork"
        cmd = [
            self.scanner,
            f"-Dsonar.projectKey={key}",
            f"-Dsonar.host.url={self.url}",
            "-Dsonar.sources=.",
            "-Dsonar.inclusions=" + ",".join(targets),
            "-Dsonar.scm.disabled=true",
            "-Dsonar.python.version=3.14",
            f"-Dsonar.working.directory={work}",
            "-Dsonar.qualitygate.wait=false",
        ]
        env = {**os.environ, "SONAR_TOKEN": self.token}
        start = time.perf_counter()
        code, _, err, _ = _run(cmd, ws.path, raw, env=env)
        if code != 0:
            return RunRecord(self.name, ws.id, "timeout" if code is None else "error", code, time.perf_counter() - start, cmd, None, err, targets)
        task_id = None
        report = work / "report-task.txt"
        if report.exists():
            for line in report.read_text().splitlines():
                if line.startswith("ceTaskId="):
                    task_id = line.split("=", 1)[1]
        if not task_id:
            return RunRecord(self.name, ws.id, "error", code, time.perf_counter() - start, cmd, None, "no ceTaskId in report-task.txt", targets)
        deadline = time.time() + TOOL_TIMEOUT_S
        while True:
            task = self._get("api/ce/task", {"id": task_id}).get("task", {})
            if task.get("status") in {"SUCCESS", "FAILED", "CANCELED"}:
                break
            if time.time() > deadline:
                return RunRecord(self.name, ws.id, "timeout", code, time.perf_counter() - start, cmd, None, "compute engine task timed out", targets)
            time.sleep(2)
        wall = time.perf_counter() - start  # scanner + server-side processing
        if task.get("status") != "SUCCESS":
            return RunRecord(self.name, ws.id, "error", code, wall, cmd, None, f"CE task {task.get('status')}: {task.get('errorMessage', '')}", targets)
        payload = {"issues": self._paged("api/issues/search", {"components": key}, "issues"), "hotspots": []}
        try:
            payload["hotspots"] = self._paged("api/hotspots/search", {"projectKey": key}, "hotspots")
        except urllib.error.HTTPError as exc:
            if exc.code != 400:
                raise
            payload["hotspots"] = self._paged("api/hotspots/search", {"project": key}, "hotspots")
        payload["project_key"] = key
        payload["ce_task"] = {k: task.get(k) for k in ("id", "status", "executionTimeMs", "warnings")}
        raw.write_text(json.dumps(payload, indent=1))
        return RunRecord(self.name, ws.id, "ok", code, wall, cmd, str(raw), err, targets)

    def _paged(self, path: str, params: dict, key: str) -> list[dict]:
        out, page = [], 1
        while True:
            data = self._get(path, {**params, "ps": 500, "p": page})
            items = data.get(key, [])
            out += items
            total = (data.get("paging") or {}).get("total", data.get("total", len(out)))
            if not items or len(out) >= total or page * 500 >= 10_000:
                return out
            page += 1

    @staticmethod
    def normalize_payload(payload: dict, ws_id: str = "") -> list[dict]:
        """Convert api/issues/search + api/hotspots/search JSON into normalized findings."""

        def path_of(component: str) -> str:
            return component.split(":", 1)[1] if ":" in component else component

        findings = []
        for issue in payload.get("issues", []):
            rng = issue.get("textRange") or {}
            line = issue.get("line") or rng.get("startLine") or 1
            rule = issue.get("rule", "")
            itype = issue.get("type", "")
            if rule.startswith("secrets:"):
                category = "secret"
            elif itype == "VULNERABILITY":
                category = "security"
            else:
                category = "quality"
            findings.append(
                {
                    "tool": "sonarqube",
                    "rule": rule,
                    "file": path_of(issue.get("component", "")),
                    "line": int(line),
                    "end_line": int(rng.get("endLine") or line),
                    "severity": issue.get("severity") or ",".join(
                        f"{i.get('softwareQuality')}:{i.get('severity')}" for i in issue.get("impacts", [])
                    ),
                    "category": category,
                    "message": issue.get("message", "")[:400],
                }
            )
        for hs in payload.get("hotspots", []):
            rng = hs.get("textRange") or {}
            line = hs.get("line") or rng.get("startLine") or 1
            findings.append(
                {
                    "tool": "sonarqube",
                    "rule": hs.get("ruleKey", ""),
                    "file": path_of(hs.get("component", "")),
                    "line": int(line),
                    "end_line": int(rng.get("endLine") or line),
                    "severity": f"HOTSPOT/{hs.get('vulnerabilityProbability')}",
                    "category": "security",
                    "message": hs.get("message", "")[:400],
                }
            )
        return findings

    def normalize(self, rec: RunRecord, ws: Workspace) -> tuple[list[dict], dict]:
        payload = json.loads(Path(rec.raw_path).read_text())
        warnings = (payload.get("ce_task") or {}).get("warnings") or []
        return self.normalize_payload(payload, ws.id), {"reported_errors": [{"file": "", "message": w} for w in warnings]}


# ------------------------------------------------------------------ helpers


def _rel(path: str, root: Path) -> str:
    if not path:
        return ""
    p = Path(path)
    try:
        if p.is_absolute():
            return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()
    return p.as_posix().removeprefix("./")


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            h.update(path.relative_to(root).as_posix().encode())
            h.update(path.read_bytes())
    return h.hexdigest()


def record_to_json(rec: RunRecord) -> dict:
    return asdict(rec)
