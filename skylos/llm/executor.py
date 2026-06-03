from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
import sys
import shutil
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from skylos.core.safe_cache_io import (
    read_text_no_symlink,
    write_existing_text_no_symlink,
)
from skylos.remediation.regression_tests import RegressionTestCandidate

MAX_REMEDIATION_FILE_BYTES = 5_000_000


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
    verification_error: str = ""


_SHELL_METACHAR_RE = re.compile(r"[;&|<>`$]")


class RemediationExecutor:
    def __init__(
        self,
        *,
        test_cmd: str | None = None,
        project_root: str | Path = ".",
        allow_test_execution: bool = False,
        auto_detect_tests: bool = False,
    ):
        self.test_cmd = test_cmd
        self.project_root = Path(project_root).resolve()
        self.allow_test_execution = allow_test_execution
        self.auto_detect_tests = auto_detect_tests
        self._backups: dict[str, str] = {}

    def _safe_file_path(self, file_path: str) -> Path | None:
        p = Path(file_path)
        if p.is_symlink():
            return None
        try:
            resolved = p.resolve(strict=True)
            resolved.relative_to(self.project_root)
        except (OSError, ValueError):
            return None
        if not resolved.is_file():
            return None
        return resolved

    def is_safe_file_path(self, file_path: str) -> bool:
        return self._safe_file_path(file_path) is not None

    def apply_fix(self, file_path: str, fixed_code: str) -> bool:
        p = self._safe_file_path(file_path)
        if p is None:
            return False
        original = read_text_no_symlink(
            p,
            max_bytes=MAX_REMEDIATION_FILE_BYTES,
            encoding="utf-8",
        )
        if original is None:
            return False
        self._backups[str(p)] = original
        return write_existing_text_no_symlink(p, fixed_code, encoding="utf-8")

    def revert_fix(self, file_path: str) -> bool:
        p = self._safe_file_path(file_path)
        if p is None:
            return False
        key = str(p)
        original = self._backups.pop(key, None)
        if original is None:
            return False
        return write_existing_text_no_symlink(p, original, encoding="utf-8")

    def revert_all(self):
        for fp in list(self._backups.keys()):
            self.revert_fix(fp)

    def write_regression_test(self, candidate: RegressionTestCandidate) -> bool:
        destination = self._safe_new_project_file(candidate.test_file)
        if destination is None:
            return False
        return _write_new_text_no_symlink(destination, candidate.content)

    def _safe_new_project_file(self, file_path: str) -> Path | None:
        raw = Path(file_path)
        if raw.is_absolute():
            return None

        destination = self.project_root / raw
        parent = destination.parent
        if parent.is_symlink():
            return None
        if not parent.is_dir():
            return None
        if destination.exists():
            return None

        try:
            resolved_parent = parent.resolve(strict=True)
            resolved_parent.relative_to(self.project_root)
        except (OSError, ValueError):
            return None

        return destination

    def run_tests(self, timeout: int = 300) -> TestResult:
        if not self.allow_test_execution:
            return TestResult(
                passed=True,
                output="Test execution disabled.",
                command="",
            )

        cmd = self.test_cmd
        if not cmd and self.auto_detect_tests:
            cmd = self._detect_test_command()
        if not cmd:
            return TestResult(passed=True, output="No test suite detected.", command="")

        argv = self._safe_test_argv(cmd)
        if argv is None:
            return TestResult(
                passed=False,
                output="Rejected test command containing shell syntax.",
                command=cmd,
            )

        import time

        start = time.monotonic()
        try:
            result = subprocess.run(
                argv,
                shell=False,
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

    def _safe_test_argv(self, cmd: str) -> list[str] | None:
        if _SHELL_METACHAR_RE.search(cmd):
            return None
        try:
            argv = shlex.split(cmd)
        except ValueError:
            return None
        if not argv:
            return None
        return argv

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
            if isinstance(raw, str):
                result = _json.loads(raw)
            else:
                result = raw
        except Exception as exc:
            return VerifyResult(
                finding_resolved=False,
                verification_error=str(exc),
            )

        remaining = set()
        for key in ("danger", "quality", "secrets"):
            findings = result.get(key)
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                rid = finding.get("rule_id", "")
                if rid in original_rule_ids:
                    remaining.add(rid)

        return VerifyResult(
            finding_resolved=len(remaining) == 0,
            remaining_rule_ids=sorted(remaining),
        )

    def create_branch(self, prefix: str = "skylos/fix") -> str:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        short = hashlib.sha256(ts.encode()).hexdigest()[:6]
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


def _write_new_text_no_symlink(path: Path, text: str) -> bool:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(path, flags, 0o644)  # skylos: ignore[SKY-D215] path was contained by _safe_new_project_file
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        return True
    except (OSError, UnicodeError):
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
