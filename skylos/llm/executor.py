from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
import sys
import shutil
import stat
from copy import deepcopy
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
    # None means no tests ran; callers must not count it as a pass or failure.
    passed: bool | None
    output: str = ""
    command: str = ""
    duration_s: float = 0.0
    reason: str = ""
    exit_code: int | None = None

    @property
    def status(self) -> str:
        return (
            "passed"
            if self.passed is True
            else "failed"
            if self.passed is False
            else "skipped"
        )

    def to_receipt(self) -> dict:
        return {
            "status": self.status,
            "command": self.command,
            "duration_s": self.duration_s,
            "reason": self.reason,
            "exit_code": self.exit_code,
        }


@dataclass
class VerifyResult:
    finding_resolved: bool
    remaining_rule_ids: list[str] = field(default_factory=list)
    verification_error: str = ""
    static_status: str = "skipped"
    new_findings: list[dict] = field(default_factory=list)
    resolution_reason: str = ""

    def to_receipt(self) -> dict:
        return {
            "status": self.static_status,
            "finding_resolved": self.finding_resolved,
            "remaining_rule_ids": self.remaining_rule_ids,
            "new_findings": self.new_findings,
            "error": self.verification_error,
            "finding_resolution": {
                "status": "passed"
                if self.finding_resolved
                else "failed"
                if self.remaining_rule_ids
                else "skipped",
                "reason": self.resolution_reason,
            },
        }


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
        original = self._backups.get(key)
        if original is None:
            return False
        restored = write_existing_text_no_symlink(p, original, encoding="utf-8")
        if restored:
            self._backups.pop(key, None)
        return restored

    def revert_all(self):
        for fp in list(self._backups.keys()):
            self.revert_fix(fp)

    def write_regression_test(self, candidate: RegressionTestCandidate) -> bool:
        destination = self._safe_new_project_file(candidate.test_file)
        if destination is None:
            return False
        return _write_new_text_no_symlink(
            destination, candidate.content, project_root=self.project_root
        )

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
                passed=None,
                output="Test execution disabled.",
                command="",
                reason="execution_disabled",
            )

        cmd = self.test_cmd
        if not cmd and self.auto_detect_tests:
            cmd = self._detect_test_command()
        if not cmd:
            return TestResult(
                passed=None,
                output="No test suite detected.",
                command="",
                reason="no_test_command",
            )

        argv = self._safe_test_argv(cmd)
        if argv is None:
            return TestResult(
                passed=False,
                output="Rejected test command containing shell syntax.",
                command=cmd,
                reason="rejected_command",
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
                reason="" if result.returncode == 0 else "nonzero_exit",
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start
            return TestResult(
                passed=False,
                output=f"Test suite timed out after {timeout}s",
                command=cmd,
                duration_s=round(duration, 2),
                reason="timeout",
            )
        except OSError as e:
            return TestResult(
                passed=False, output=str(e), command=cmd, reason="execution_error"
            )

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

    def capture_static_report(self, file_path: str) -> dict:
        """Capture comparable static evidence without registry or target execution."""
        import json as _json
        import inspect
        from skylos.analyzer import analyze as run_analyze
        from skylos.cleanup_execution import compare_cleanup_reports

        path = self._safe_file_path(file_path)
        if path is None:
            raise ValueError("verification file is outside the project root or unsafe")
        source = read_text_no_symlink(
            path, max_bytes=MAX_REMEDIATION_FILE_BYTES, encoding="utf-8"
        )
        if source is None:
            raise ValueError("verification source could not be safely read")
        options = {
            "conf": 0,
            "enable_danger": True,
            "enable_quality": True,
            "enable_ai_defects": True,
            "enable_secrets": True,
            "enable_dependency_hallucinations": False,
            "enable_sca": False,
            "grep_verify": False,
            "trace_file": False,
        }
        # Older native analyzers always include dead code and have no switch.
        # Keep their extra static analysis without passing an unsupported flag.
        parameters = inspect.signature(run_analyze).parameters
        if "enable_dead_code" in parameters or any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        ):
            options["enable_dead_code"] = False
        raw = run_analyze(file_path, **options)
        result = _json.loads(raw) if isinstance(raw, str) else deepcopy(raw)
        if (
            read_text_no_symlink(
                path, max_bytes=MAX_REMEDIATION_FILE_BYTES, encoding="utf-8"
            )
            != source
        ):
            raise ValueError("verification source changed during analysis")
        summary = result.get("analysis_summary") if isinstance(result, dict) else None
        required = {"security", "quality", "ai_defects", "secrets"}
        categories = (
            summary.get("grade_categories") if isinstance(summary, dict) else None
        )
        if not isinstance(categories, list) or not required.issubset(categories):
            raise ValueError(
                "static verification is missing required analyzer coverage"
            )
        # A self-comparison validates completeness without claiming a fix occurred.
        check = compare_cleanup_reports(
            result,
            result,
            project_root=self.project_root,
            required_categories=("security", "quality", "ai_defects", "secrets"),
        )
        if check["status"] != "passed":
            raise ValueError(
                "; ".join(check.get("limitations", []))
                or "static verification incomplete"
            )
        result["_verification_sources"] = {
            path.relative_to(self.project_root).as_posix(): source
        }
        return result

    def verify_fix(
        self,
        file_path: str,
        original_rule_ids: list[str],
        *,
        before_report: dict | None = None,
    ) -> VerifyResult:
        from skylos.cleanup_execution import compare_cleanup_reports

        try:
            result = self.capture_static_report(file_path)
            if before_report is not None:
                comparison = compare_cleanup_reports(
                    before_report,
                    result,
                    project_root=self.project_root,
                    required_categories=(
                        "security",
                        "quality",
                        "ai_defects",
                        "secrets",
                    ),
                    before_sources=before_report.get("_verification_sources"),
                    after_sources=result.get("_verification_sources"),
                )
                if comparison["status"] != "passed":
                    return VerifyResult(
                        finding_resolved=False,
                        verification_error="; ".join(comparison.get("limitations", []))
                        or "new high-risk static findings after remediation",
                        static_status="failed"
                        if comparison["status"] == "failed"
                        else "skipped",
                        new_findings=comparison.get("new_findings", []),
                    )
        except Exception as exc:
            return VerifyResult(
                finding_resolved=False,
                verification_error=str(exc),
            )

        remaining = set()
        for key in ("danger", "quality", "secrets", "ai_defects"):
            findings = result.get(key)
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                rid = finding.get("rule_id", "")
                if rid in original_rule_ids:
                    remaining.add(rid)

        original_detected = bool(original_rule_ids)
        if before_report is not None and original_rule_ids:
            before_ids = {
                finding.get("rule_id")
                for key in ("danger", "quality", "secrets", "ai_defects")
                for finding in before_report.get(key, [])
                if isinstance(finding, dict)
            }
            original_detected = set(original_rule_ids).issubset(before_ids)

        return VerifyResult(
            # Standards-only LLM findings have no deterministic rule identity.
            # A clean regression check cannot prove that their requested fix worked.
            finding_resolved=original_detected and len(remaining) == 0,
            remaining_rule_ids=sorted(remaining),
            static_status="failed" if remaining else "passed",
            resolution_reason="" if original_detected else "no_matching_static_finding",
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


def _write_new_text_no_symlink(path: Path, text: str, *, project_root: Path) -> bool:
    """Create a new project file through pinned, no-follow directory handles."""
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or any(
            operation not in os.supports_dir_fd
            for operation in (os.open, os.stat, os.unlink)
        )
    ):
        return False
    try:
        root = Path(project_root)
        candidate = Path(path)
        if not root.is_absolute() or ".." in root.parts:
            return False
        if not candidate.is_absolute():
            candidate = root / candidate
        relative = candidate.relative_to(root)
        if not relative.parts or ".." in relative.parts:
            return False
    except (TypeError, ValueError):
        return False

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
        flags |= os.O_CLOEXEC
    directory_fds: list[int] = []
    directory_links: list[tuple[int, str, int]] = []
    fd: int | None = None
    created: os.stat_result | None = None
    completed = False

    def directories_unchanged() -> bool:
        for parent_fd, component, child_fd in directory_links:
            named = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            held = os.fstat(child_fd)
            if not stat.S_ISDIR(named.st_mode) or (named.st_dev, named.st_ino) != (
                held.st_dev,
                held.st_ino,
            ):
                return False
        return True

    try:
        directory_fds.append(os.open(os.sep, directory_flags))
        for component in (*root.parts[1:], *relative.parts[:-1]):
            parent_fd = directory_fds[-1]
            child_fd = os.open(  # skylos: ignore[SKY-D215] single component, pinned parent and O_NOFOLLOW directory
                component, directory_flags, dir_fd=parent_fd
            )
            directory_fds.append(child_fd)
            directory_links.append((parent_fd, component, child_fd))
        if not directories_unchanged():
            return False
        fd = os.open(  # skylos: ignore[SKY-D215] root-contained basename, pinned no-follow parents and exclusive create
            relative.name, flags, 0o644, dir_fd=directory_fds[-1]
        )
        created = os.fstat(fd)
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_nlink != 1
            or not directories_unchanged()
        ):
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
            held = os.fstat(handle.fileno())
            named = os.stat(
                relative.name, dir_fd=directory_fds[-1], follow_symlinks=False
            )
            if (
                held.st_nlink != 1
                or not stat.S_ISREG(named.st_mode)
                or (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino)
                or not directories_unchanged()
            ):
                return False
        completed = True
        return True
    except (OSError, UnicodeError, ValueError):
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if not completed and created is not None and directory_fds:
            try:
                named = os.stat(
                    relative.name, dir_fd=directory_fds[-1], follow_symlinks=False
                )
                if (named.st_dev, named.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(  # skylos: ignore[SKY-D215] contained basename, pinned parent and owned inode
                        relative.name, dir_fd=directory_fds[-1]
                    )
            except OSError:
                pass
        for directory_fd in reversed(directory_fds):
            try:
                os.close(directory_fd)
            except OSError:
                pass
