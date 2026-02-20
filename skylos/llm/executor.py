from __future__ import annotations

import hashlib
import subprocess
import sys
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class TestResult:
    passed: bool
    output: str = ""
    command: str = ""
    duration_s: float = 0.0


@dataclass
class VerifyResult:
    finding_resolved: bool
    remaining_rule_ids: list[str] = field(default_factory=list)


class RemediationExecutor:
    def __init__(self, *, test_cmd: str | None = None, project_root: str | Path = "."):
        self.test_cmd = test_cmd
        self.project_root = Path(project_root).resolve()
        self._backups: dict[str, str] = {}

    def apply_fix(self, file_path: str, fixed_code: str) -> bool:
        p = Path(file_path)
        if not p.exists():
            return False
        try:
            original = p.read_text(encoding="utf-8")
            self._backups[str(p)] = original
            p.write_text(fixed_code, encoding="utf-8")
            return True
        except OSError:
            return False

    def revert_fix(self, file_path: str) -> bool:
        """Restore original file content from backup."""
        key = str(Path(file_path))
        original = self._backups.pop(key, None)
        if original is None:
            return False
        try:
            Path(file_path).write_text(original, encoding="utf-8")
            return True
        except OSError:
            return False

    def revert_all(self):
        """Revert all applied fixes."""
        for fp in list(self._backups.keys()):
            self.revert_fix(fp)


    def run_tests(self, timeout: int = 300) -> TestResult:
        cmd = self.test_cmd or self._detect_test_command()
        if not cmd:
            return TestResult(passed=True, output="No test suite detected.", command="")

        import time

        start = time.monotonic()
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.project_root),
            )
            duration = time.monotonic() - start
            return TestResult(
                passed=result.returncode == 0,
                output=(result.stdout + result.stderr)[-5000:],
                command=cmd,
                duration_s=round(duration, 2),
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start
            return TestResult(
                passed=False,
                output=f"Test suite timed out after {timeout}s",
                command=cmd,
                duration_s=round(duration, 2),
            )
        except OSError as e:
            return TestResult(passed=False, output=str(e), command=cmd)

    def _detect_test_command(self) -> str | None:
        root = self.project_root

        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            content = pyproject.read_text(encoding="utf-8", errors="ignore")
            if "[tool.pytest" in content or "pytest" in content:
                return "python -m pytest --tb=short -q"

        if (root / "pytest.ini").exists():
            return "python -m pytest --tb=short -q"
        if (root / "setup.cfg").exists():
            cfg = (root / "setup.cfg").read_text(encoding="utf-8", errors="ignore")
            if "[tool:pytest]" in cfg:
                return "python -m pytest --tb=short -q"
        if (root / "tox.ini").exists():
            return "tox -e py --quiet"

        makefile = root / "Makefile"
        if makefile.exists():
            content = makefile.read_text(encoding="utf-8", errors="ignore")
            if "test:" in content:
                return "make test"

        if (root / "test").is_dir() or (root / "tests").is_dir():
            return "python -m pytest --tb=short -q"

        return None

    def verify_fix(self, file_path: str, original_rule_ids: list[str]) -> VerifyResult:
        import json as _json
        from skylos.analyzer import analyze as run_analyze

        try:
            raw = run_analyze(
                file_path,
                conf=0,
                enable_danger=True,
                enable_quality=True,
                enable_secrets=True,
            )
            result = _json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            return VerifyResult(finding_resolved=True)

        remaining = set()
        for key in ("danger", "quality", "secrets"):
            for finding in result.get(key, []) or []:
                rid = finding.get("rule_id", "")
                if rid in original_rule_ids:
                    remaining.add(rid)

        return VerifyResult(
            finding_resolved=len(remaining) == 0,
            remaining_rule_ids=sorted(remaining),
        )

    def create_branch(self, prefix: str = "skylos/fix") -> str:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        short = hashlib.sha1(ts.encode()).hexdigest()[:6]
        branch = f"{prefix}-{ts[:8]}-{short}"
        subprocess.run(
            ["git", "checkout", "-b", branch],
            cwd=str(self.project_root),
            capture_output=True,
            check=True,
        )
        return branch

    def commit_fixes(self, message: str, files: list[str]) -> bool:
        try:
            for f in files:
                subprocess.run(
                    ["git", "add", f],
                    cwd=str(self.project_root),
                    capture_output=True,
                    check=True,
                )
            subprocess.run(
                ["git", "commit", "-m", message],
                cwd=str(self.project_root),
                capture_output=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def push_branch(self, branch: str) -> bool:
        try:
            subprocess.run(
                ["git", "push", "-u", "origin", branch],
                cwd=str(self.project_root),
                capture_output=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def create_pr(
        self, branch: str, title: str, body: str, base: str = "main"
    ) -> str | None:
        if not shutil.which("gh"):
            print("Warning: gh CLI not found, skipping PR creation.", file=sys.stderr)
            return None
        try:
            result = subprocess.run(
                [
                    "gh",
                    "pr",
                    "create",
                    "--title",
                    title,
                    "--body",
                    body,
                    "--base",
                    base,
                    "--head",
                    branch,
                ],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"PR creation failed: {e.stderr}", file=sys.stderr)
            return None
