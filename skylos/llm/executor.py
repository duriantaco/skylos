from __future__ import annotations

import hashlib
import ast
import tempfile
import xml.etree.ElementTree as ET
import difflib
from collections import Counter
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

from skylos.core.git_safety import read_only_git_command, read_only_git_environment
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
    status: str = "not_run"
    executed: bool = False
    returncode: int | None = None
    source_digests: dict[str, str] = field(default_factory=dict)
    case_counts: dict[str, int] = field(default_factory=dict)

    def to_summary(self) -> dict:
        return {
            "status": self.status,
            "executed": self.executed,
            "command": self.command,
            "returncode": self.returncode,
            "duration_s": self.duration_s,
            "output": self.output,
            "source_digests": dict(self.source_digests),
            "case_counts": dict(self.case_counts),
            "evidence_kind": "test_cases"
            if self.case_counts
            else "command_exit"
            if self.executed
            else "not_run",
        }


@dataclass
class VerifyResult:
    finding_resolved: bool
    remaining_rule_ids: list[str] = field(default_factory=list)
    verification_error: str = ""
    new_findings: list[dict] = field(default_factory=list)
    status: str = "incomplete"
    source_digest: str = ""
    baseline_digest: str = ""
    limitations: list[str] = field(
        default_factory=lambda: [
            "Static comparison covers security, quality, secrets, AI-defect and reliability findings in the edited file only; it does not prove runtime behavior or whole-project regression safety."
        ]
    )

    def to_summary(self) -> dict:
        return {
            "status": self.status,
            "finding_resolved": self.finding_resolved,
            "remaining_rule_ids": self.remaining_rule_ids,
            "new_findings": self.new_findings,
            "error": self.verification_error,
            "source_digest": self.source_digest,
            "baseline_digest": self.baseline_digest,
            "limitations": self.limitations,
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
        self._applied_digests: dict[str, str] = {}
        self._verification_baselines: dict[str, tuple[str, list[dict]]] = {}
        self._verification_errors: dict[str, str] = {}
        self._generated_tests: dict[str, str] = {}

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

    def apply_fix(
        self, file_path: str, fixed_code: str, *, expected_source: str | None = None
    ) -> bool:
        p = self._safe_file_path(file_path)
        if p is None:
            return False
        original = read_text_no_symlink(
            p,
            max_bytes=MAX_REMEDIATION_FILE_BYTES,
            encoding="utf-8",
            newline="",
        )
        if original is None or (
            expected_source is not None and original != expected_source
        ):
            return False
        self._backups[str(p)] = original
        written = write_existing_text_no_symlink(p, fixed_code, encoding="utf-8")
        if written:
            self._applied_digests[str(p)] = _digest(fixed_code)
        return written

    def revert_fix(self, file_path: str) -> bool:
        p = self._safe_file_path(file_path)
        if p is None:
            return False
        key = str(p)
        original = self._backups.get(key)
        current = read_text_no_symlink(
            p, max_bytes=MAX_REMEDIATION_FILE_BYTES, encoding="utf-8", newline=""
        )
        if (
            original is None
            or current is None
            or _digest(current) != self._applied_digests.get(key)
        ):
            return False
        restored = write_existing_text_no_symlink(p, original, encoding="utf-8")
        if restored:
            self._backups.pop(key, None)
            self._applied_digests.pop(key, None)
        return restored

    def revert_all(self):
        for fp in list(self._backups.keys()):
            self.revert_fix(fp)

    def write_regression_test(self, candidate: RegressionTestCandidate) -> bool:
        destination = self._safe_new_project_file(candidate.test_file)
        if destination is None:
            return False
        written = _write_new_text_no_symlink(destination, candidate.content)
        if written:
            self._generated_tests[str(destination)] = _digest(candidate.content)
        return written

    def revert_regression_tests(
        self, candidates: list[RegressionTestCandidate]
    ) -> None:
        selected = {
            str(self.project_root / candidate.test_file) for candidate in candidates
        }
        for filename, digest in list(self._generated_tests.items()):
            if filename not in selected:
                continue
            path = self._safe_file_path(filename)
            if path is None:
                continue
            content = read_text_no_symlink(
                path, max_bytes=MAX_REMEDIATION_FILE_BYTES, encoding="utf-8", newline=""
            )
            if content is not None and _digest(content) == digest:
                path.unlink()
                self._generated_tests.pop(filename, None)

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

    def run_tests(
        self, timeout: int = 300, *, source_files: list[str] | None = None
    ) -> TestResult:
        if not self.allow_test_execution:
            return TestResult(passed=False, output="Test execution disabled.")
        cmd = self.test_cmd
        if not cmd and self.auto_detect_tests:
            cmd = self._detect_test_command()
        if not cmd:
            return TestResult(
                passed=False, output="No test suite detected or command selected."
            )
        argv = self._safe_test_argv(cmd)
        if argv and _is_pytest_command(argv):
            if any(arg.startswith(("--junitxml", "--junit-xml")) for arg in argv):
                result = self._run_test_command(cmd, timeout, source_files or [])
                if result.status == "passed":
                    result.status = "incomplete"
                    result.passed = False
                    result.output += "\nCustom pytest receipt path; individual case execution was not certified."
                return result
            with tempfile.TemporaryDirectory(
                prefix="skylos-project-check-"
            ) as receipt_dir:
                receipt_path = Path(receipt_dir) / "cases.xml"
                actual_cmd = shlex.join([*argv, f"--junitxml={receipt_path}"])
                result = self._run_test_command(actual_cmd, timeout, source_files or [])
                if result.status != "passed":
                    return result
                receipt = read_text_no_symlink(
                    receipt_path, max_bytes=1_000_000, encoding="utf-8"
                )
                try:
                    cases = list(ET.fromstring(receipt or "").iter("testcase"))
                    passed = sum(
                        not any(
                            case.find(tag) is not None
                            for tag in ("skipped", "failure", "error")
                        )
                        for case in cases
                    )
                    result.case_counts = {
                        "total": len(cases),
                        "passed": passed,
                        "skipped": sum(
                            case.find("skipped") is not None for case in cases
                        ),
                    }
                    if not passed:
                        result.passed = False
                        result.status = "incomplete"
                        result.output += "\nNo test body was observed passing."
                except ET.ParseError:
                    result.status = "incomplete"
                    result.passed = False
                    result.output += "\nNo valid case execution receipt was produced."
                return result
        return self._run_test_command(cmd, timeout, source_files or [])

    def run_regression_tests(
        self,
        candidates: list[RegressionTestCandidate],
        *,
        source_files: list[str] | None = None,
    ) -> TestResult:
        if not self.allow_test_execution:
            return TestResult(passed=False, output="Test execution disabled.")
        if not candidates:
            return TestResult(
                passed=False, output="No generated static regression check available."
            )
        files = [candidate.test_file for candidate in candidates]
        try:
            actual = self._source_digests(files)
            if any(
                actual.get(candidate.test_file) != _digest(candidate.content)
                for candidate in candidates
            ):
                return TestResult(
                    passed=False,
                    status="outdated",
                    output="Generated check changed before execution.",
                )
            expected = {
                node.name
                for candidate in candidates
                for node in ast.walk(ast.parse(candidate.content))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test_")
            }
        except (ValueError, SyntaxError) as exc:
            return TestResult(passed=False, status="incomplete", output=str(exc))
        with tempfile.TemporaryDirectory(prefix="skylos-static-check-") as receipt_dir:
            receipt_path = Path(receipt_dir) / "cases.xml"
            cmd = shlex.join(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    *files,
                    f"--junitxml={receipt_path}",
                ]
            )
            result = self._run_test_command(cmd, 300, [*(source_files or []), *files])
            if result.status != "passed":
                return result
            receipt = read_text_no_symlink(
                receipt_path, max_bytes=1_000_000, encoding="utf-8"
            )
            try:
                cases = list(ET.fromstring(receipt or "").iter("testcase"))
                passed = {
                    case.get("name")
                    for case in cases
                    if not any(
                        case.find(tag) is not None
                        for tag in ("skipped", "failure", "error")
                    )
                }
                result.case_counts = {
                    "total": len(cases),
                    "passed": len(passed),
                    "skipped": sum(case.find("skipped") is not None for case in cases),
                }
                if (
                    not expected
                    or not expected.issubset(passed)
                    or result.case_counts["skipped"]
                ):
                    result.status = "incomplete"
                    result.passed = False
                    result.output += (
                        "\nGenerated check cases did not all execute and pass."
                    )
            except ET.ParseError:
                result.status = "incomplete"
                result.passed = False
                result.output += "\nNo valid case execution receipt was produced."
            return result

    def _source_digests(self, filenames: list[str]) -> dict[str, str]:
        digests = {}
        for filename in filenames:
            raw = Path(filename)
            path = self._safe_file_path(
                str(raw if raw.is_absolute() else self.project_root / raw)
            )
            if path is None:
                raise ValueError(f"Source unavailable for check: {filename}")
            source = read_text_no_symlink(
                path, max_bytes=MAX_REMEDIATION_FILE_BYTES, encoding="utf-8", newline=""
            )
            if source is None:
                raise ValueError(f"Source unavailable for check: {filename}")
            digests[path.relative_to(self.project_root).as_posix()] = _digest(source)
        return digests

    def _run_test_command(
        self, cmd: str, timeout: int, source_files: list[str]
    ) -> TestResult:
        argv = self._safe_test_argv(cmd)
        if argv is None:
            return TestResult(
                passed=False,
                status="failed",
                output="Rejected test command containing shell syntax.",
                command=cmd,
            )
        try:
            digests = self._source_digests(source_files)
        except ValueError as exc:
            return TestResult(
                passed=False, status="incomplete", output=str(exc), command=cmd
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
            duration = round(time.monotonic() - start, 2)
            try:
                unchanged = digests == self._source_digests(source_files)
            except ValueError:
                unchanged = False
            passed = result.returncode == 0 and unchanged
            status = ("passed" if passed else "failed") if unchanged else "outdated"
            output = (result.stdout + result.stderr)[-5000:]
            if not unchanged:
                output += (
                    "\nChecked source changed during execution; results are outdated."
                )
            return TestResult(
                passed=passed,
                status=status,
                executed=True,
                returncode=result.returncode,
                output=output,
                command=cmd,
                duration_s=duration,
                source_digests=digests,
            )
        except subprocess.TimeoutExpired:
            return TestResult(
                passed=False,
                status="failed",
                executed=True,
                output=f"Test suite timed out after {timeout}s",
                command=cmd,
                duration_s=round(time.monotonic() - start, 2),
                source_digests=digests,
            )
        except OSError as exc:
            return TestResult(
                passed=False,
                status="failed",
                output=str(exc),
                command=cmd,
                source_digests=digests,
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

    def capture_verification_baseline(
        self, file_path: str, original_rule_ids: list[str] | None = None
    ) -> bool:
        try:
            source, findings = self._scan_verification_file(file_path)
            if original_rule_ids and not set(original_rule_ids).issubset(
                {f.get("rule_id") for f in findings}
            ):
                raise ValueError(
                    "The edited-file baseline could not reproduce every planned static rule finding"
                )
            self._verification_baselines[file_path] = (source, findings)
            self._verification_errors.pop(file_path, None)
            return True
        except Exception as exc:
            self._verification_errors[file_path] = str(exc)
            return False

    def _scan_verification_file(self, file_path: str) -> tuple[str, list[dict]]:
        import json
        from skylos.analyzer import analyze as run_analyze

        path = self._safe_file_path(file_path)
        if path is None:
            raise ValueError("File unavailable or outside project root")
        source = read_text_no_symlink(
            path, max_bytes=MAX_REMEDIATION_FILE_BYTES, encoding="utf-8", newline=""
        )
        if source is None:
            raise ValueError("Cannot read source for static verification")
        raw = run_analyze(
            str(path),
            conf=0,
            enable_danger=True,
            enable_quality=True,
            enable_ai_defects=True,
            enable_secrets=True,
        )
        result = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(result, dict):
            raise ValueError("Invalid static verification result")
        summary = result.get("analysis_summary")
        if (
            not isinstance(summary, dict)
            or not isinstance(summary.get("total_files"), int)
            or summary["total_files"] < 1
        ):
            raise ValueError("Static verification did not analyze the edited file")
        assessment = result.get("assessment", {})
        coverage = (
            assessment.get("coverage", {}) if isinstance(assessment, dict) else {}
        )
        if isinstance(coverage, dict) and (
            coverage.get("status") == "incomplete" or coverage.get("incomplete_checks")
        ):
            raise ValueError("Static verification assessment reports incomplete checks")
        engines = summary.get("language_engines", {})
        if summary.get("incomplete_languages") or (
            isinstance(engines, dict)
            and any(
                not isinstance(engine, dict)
                or engine.get("status") != "available"
                or engine.get("complete") is False
                for engine in engines.values()
            )
        ):
            raise ValueError("Static verification language analysis was incomplete")
        if result.get("analysis_errors") or summary.get("analysis_error_count", 0):
            raise ValueError("Static verification reported incomplete analysis")
        after = read_text_no_symlink(
            path, max_bytes=MAX_REMEDIATION_FILE_BYTES, encoding="utf-8", newline=""
        )
        if source != after:
            raise ValueError("Source changed during static verification")
        findings = []
        for section in ("danger", "quality", "secrets", "ai_defects", "reliability"):
            values = result.get(section, [])
            if not isinstance(values, list) or any(
                not isinstance(row, dict) for row in values
            ):
                raise ValueError("Invalid static verification findings")
            if any(
                isinstance(row.get("metadata"), dict)
                and row["metadata"].get("analysis_complete") is False
                for row in values
            ):
                raise ValueError("Static verification reported partial rule analysis")
            findings.extend(dict(row, _section=section) for row in values)
        # A suppression is not remediation. Preserve explicit inline-ignored
        # findings for comparison so an added ignore cannot manufacture closure.
        for row in result.get("suppressed", []):
            if isinstance(row, dict) and row.get("reason") == "inline ignore comment":
                findings.append(dict(row, _section="inline_ignored"))
        return source, findings

    def verify_fix(self, file_path: str, original_rule_ids: list[str]) -> VerifyResult:
        if file_path in self._verification_errors:
            return VerifyResult(
                finding_resolved=False,
                verification_error=self._verification_errors[file_path],
            )
        try:
            source, findings = self._scan_verification_file(file_path)
        except Exception as exc:
            return VerifyResult(finding_resolved=False, verification_error=str(exc))
        remaining = sorted(
            {
                str(f.get("rule_id", ""))
                for f in findings
                if f.get("rule_id") in original_rule_ids
            }
        )
        baseline = self._verification_baselines.get(file_path)
        new_findings = []
        limits = VerifyResult(False).limitations
        if baseline is not None:
            old_source, old_findings = baseline
            line_map = {}
            matcher = difflib.SequenceMatcher(
                a=old_source.splitlines(), b=source.splitlines(), autojunk=False
            )
            for old_start, new_start, count in matcher.get_matching_blocks():
                line_map.update(
                    {
                        old_start + offset + 1: new_start + offset + 1
                        for offset in range(count)
                    }
                )
            previous = Counter(
                _finding_key(f, line_map.get(f.get("line"))) for f in old_findings
            )
            for finding in findings:
                key = _finding_key(finding, finding.get("line"))
                if previous[key]:
                    previous[key] -= 1
                else:
                    new_findings.append(
                        {k: v for k, v in finding.items() if k != "_section"}
                    )
        else:
            limits.append(
                "No baseline scan was captured; introduced findings were not compared."
            )
        resolved = not remaining and not new_findings
        return VerifyResult(
            finding_resolved=resolved,
            remaining_rule_ids=remaining,
            new_findings=new_findings,
            status="passed"
            if resolved and baseline is not None
            else "failed"
            if not resolved
            else "incomplete",
            source_digest=_digest(source),
            baseline_digest=_digest(baseline[0]) if baseline else "",
            limitations=limits,
        )

    def current_commit(self) -> str:
        try:
            result = subprocess.run(
                read_only_git_command(["rev-parse", "HEAD"]),
                cwd=self.project_root,
                env=read_only_git_environment(),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            value = result.stdout.strip()
            return (
                value
                if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value)
                else ""
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""

    def publication_sources_match(
        self,
        expected: dict[str, str],
        *,
        commit: str = "",
        base_commit: str | None = None,
    ) -> bool:
        if not expected or any(
            not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            for digest in expected.values()
        ):
            return False
        try:
            if self._source_digests(list(expected)) != expected:
                return False
            if not commit:
                index = subprocess.run(
                    read_only_git_command(
                        [
                            "diff",
                            "--cached",
                            "--name-only",
                            "-z",
                            "--no-ext-diff",
                            "--no-textconv",
                            "--",
                        ]
                    ),
                    cwd=self.project_root,
                    env=read_only_git_environment(),
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                staged = {
                    name.decode("utf-8") for name in index.stdout.split(b"\0") if name
                }
                return index.returncode == 0 and staged.issubset(expected)
            if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
                return False
            parents = subprocess.run(
                read_only_git_command(["rev-list", "--parents", "-n", "1", commit]),
                cwd=self.project_root,
                env=read_only_git_environment(),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            actual_parents = parents.stdout.strip().split()[1:]
            if parents.returncode or (
                base_commit is not None
                and actual_parents != ([base_commit] if base_commit else [])
            ):
                return False
            changed = subprocess.run(
                read_only_git_command(
                    [
                        "diff-tree",
                        "--root",
                        "--no-commit-id",
                        "--name-only",
                        "-r",
                        "-z",
                        "--no-ext-diff",
                        "--no-textconv",
                        commit,
                    ]
                ),
                cwd=self.project_root,
                env=read_only_git_environment(),
                capture_output=True,
                timeout=10,
                check=False,
            )
            changed_paths = {
                name.decode("utf-8") for name in changed.stdout.split(b"\0") if name
            }
            if changed.returncode or not changed_paths.issubset(expected):
                return False
            listing = subprocess.run(
                read_only_git_command(
                    ["ls-tree", "-rzl", commit, "--", *expected], literal_pathspecs=True
                ),
                cwd=self.project_root,
                env=read_only_git_environment(),
                capture_output=True,
                timeout=10,
                check=False,
            )
            if listing.returncode:
                return False
            seen = set()
            for entry in listing.stdout.split(b"\0"):
                if not entry:
                    continue
                header, raw_name = entry.split(b"\t", 1)
                mode, kind, oid, size = header.split()
                name = raw_name.decode("utf-8")
                if (
                    name not in expected
                    or mode not in (b"100644", b"100755")
                    or kind != b"blob"
                    or int(size) > MAX_REMEDIATION_FILE_BYTES
                ):
                    return False
                if not re.fullmatch(rb"[0-9a-f]{40,64}", oid):
                    return False
                blob = subprocess.run(
                    read_only_git_command(["cat-file", "blob", oid.decode("ascii")]),
                    cwd=self.project_root,
                    env=read_only_git_environment(),
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                if (
                    blob.returncode
                    or "sha256:" + hashlib.sha256(blob.stdout).hexdigest()
                    != expected[name]
                ):
                    return False
                seen.add(name)
            return seen == set(expected)
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            return False

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

    def push_branch(self, branch: str, *, expected_commit: str = "") -> bool:
        if expected_commit and not re.fullmatch(r"[0-9a-f]{40,64}", expected_commit):
            return False
        argv = (
            ["git", "push", "origin", f"{expected_commit}:refs/heads/{branch}"]
            if expected_commit
            else ["git", "push", "-u", "origin", branch]
        )
        try:
            subprocess.run(
                argv,
                cwd=str(self.project_root),
                capture_output=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def create_pr(
        self,
        branch: str,
        title: str,
        body: str,
        base: str = "main",
        *,
        draft: bool = False,
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
                    *(["--draft"] if draft else []),
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
        fd = os.open(
            path, flags, 0o644
        )  # skylos: ignore[SKY-D215] path was contained by _safe_new_project_file
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


def _digest(source: str) -> str:
    return "sha256:" + hashlib.sha256(source.encode("utf-8")).hexdigest()


def _finding_key(finding: dict, line) -> tuple:
    return (
        finding.get("_section"),
        finding.get("file"),
        finding.get("rule_id"),
        finding.get("severity"),
        finding.get("message"),
        finding.get("symbol"),
        line,
        finding.get("col", 0),
    )


def _is_pytest_command(argv: list[str]) -> bool:
    name = Path(argv[0]).name.lower()
    return name in {"pytest", "pytest.exe", "py.test"} or (
        "python" in name and len(argv) > 2 and argv[1:3] == ["-m", "pytest"]
    )
