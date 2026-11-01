from __future__ import annotations

import sys
import hashlib
from pathlib import Path

from .planner import RemediationPlanner, RemediationPlan, FixBatch
from .executor import RemediationExecutor, MAX_REMEDIATION_FILE_BYTES
from skylos.core.safe_cache_io import read_text_no_symlink
from .prompts import build_pr_description
from skylos.remediation.regression_tests import generate_regression_test_candidate


class RemediationAgent:
    def __init__(
        self,
        *,
        model: str = "gpt-4.1",
        api_key: str | None = None,
        test_cmd: str | None = None,
        severity_filter: str | None = None,
        provider: str | None = None,
        base_url: str | None = None,
        allow_test_execution: bool = False,
        auto_detect_tests: bool = False,
    ):
        self.model = model
        self.api_key = api_key
        self.test_cmd = test_cmd
        self.severity_filter = severity_filter
        self.provider = provider
        self.base_url = base_url
        self.allow_test_execution = allow_test_execution
        self.auto_detect_tests = auto_detect_tests
        self.planner = RemediationPlanner(severity_filter=severity_filter)
        self._pending_model_start = None

    def run(
        self,
        path: str | Path,
        *,
        dry_run: bool = False,
        max_fixes: int = 10,
        auto_pr: bool = False,
        branch_prefix: str = "skylos/fix",
        quiet: bool = False,
        before_model_call=None,
    ) -> dict:
        path = Path(path).resolve()
        log = _logger(quiet)

        log("Step 1/5: Scanning project...")
        results = self._scan(path)
        danger_count = _section_count(results, "danger")
        quality_count = _section_count(results, "quality")
        secrets_count = _section_count(results, "secrets")
        total = danger_count + quality_count + secrets_count
        log(
            f"  Found {total} findings ({danger_count} danger, "
            f"{quality_count} quality, {secrets_count} secrets)"
        )

        if total == 0:
            log("No findings — nothing to remediate.")
            return RemediationPlan().summary()

        log("Step 2/5: Creating remediation plan...")
        plan = self.planner.create_plan(results, max_fixes=max_fixes)
        log(
            f"  Planned {sum(len(b.findings) for b in plan.batches)} fixes "
            f"across {len(plan.batches)} files "
            f"({plan.skipped_findings} skipped)"
        )

        if dry_run:
            log("\n[Dry run] No changes applied. Plan:")
            self._print_plan(plan, log)
            return plan.summary()

        branch_name = None
        if auto_pr:
            log("Step 3/6: Creating remediation branch...")
            branch_root = _project_root_for_path(path)
            branch_name = self._prepare_pr_branch(
                branch_root,
                branch_prefix,
                log,
            )
            if not branch_name:
                summary = plan.summary()
                summary["branch_error"] = "Could not create remediation branch"
                return summary

        log("Step 4/6: Generating and applying fixes...")
        executor = RemediationExecutor(
            test_cmd=self.test_cmd,
            project_root=_project_root_for_path(path),
            allow_test_execution=self.allow_test_execution,
            auto_detect_tests=self.auto_detect_tests,
        )

        fixer = self._create_fixer()
        fixed_files: list[str] = []

        self._pending_model_start = before_model_call
        try:
            for batch in plan.batches:
                log(f"\n  Fixing {batch.file} ({len(batch.findings)} findings)...")
                self._process_batch(batch, fixer, executor, log)

                if batch.status == "fixed":
                    fixed_files.append(batch.file)
                    label = (
                        "Checks passed"
                        if batch.fix_status == "checks_passed"
                        else "Fix applied; checks incomplete"
                    )
                    log(f"    ✓ {label}")
                else:
                    log(f"    ✗ Status: {batch.status} — {batch.fix_description}")
        finally:
            self._pending_model_start = None

        self._finalize_batch_checks(plan, executor, log)
        fixed_count = sum(1 for b in plan.batches if b.status == "fixed")
        log(f"\n  Results: {fixed_count}/{len(plan.batches)} files changed")

        pr_url = None
        if auto_pr and fixed_files:
            log("Step 5/6: Creating pull request...")
            pr_url = self._create_pr(executor, plan, branch_name, log)
        else:
            if not fixed_files:
                log("Step 5/6: No fixes applied — skipping PR.")
            else:
                log("Step 5/6: Skipped (--auto-pr not set).")

        log("Step 6/6: Summary")
        summary = plan.summary()
        if pr_url:
            summary["pr_url"] = pr_url
        if branch_name:
            summary["branch"] = branch_name
        self._print_plan(plan, log)

        return summary

    def _scan(self, path: Path) -> dict:
        import json
        from skylos.analyzer import analyze as run_analyze
        from skylos.config import load_config, resolve_config_file_path
        from skylos.constants import parse_exclude_folders
        from skylos.core.review_decisions import (
            apply_trusted_review_decisions,
            review_scan_requirements,
        )

        project_root = _project_root_for_path(path)
        config_file = resolve_config_file_path()
        project_config = load_config(project_root, config_file=config_file)
        exclude_folders = parse_exclude_folders(
            config_exclude_folders=project_config.get("exclude"),
        )
        options = {
            "conf": 0,
            "enable_danger": True,
            "enable_quality": True,
            "enable_ai_defects": True,
            "enable_secrets": True,
            "exclude_folders": list(exclude_folders),
            "config_file": config_file,
        }
        include_review_context, include_review_proofs = review_scan_requirements(
            project_root
        )
        if include_review_context:
            options["include_review_context"] = True
        if include_review_proofs:
            options["include_review_proofs"] = True
        raw = run_analyze(str(path), **options)
        if isinstance(raw, str):
            result = json.loads(raw)
        else:
            result = raw
        return apply_trusted_review_decisions(result, project_root)

    def _create_fixer(self):
        from .agents import FixerAgent, AgentConfig

        config = AgentConfig()
        config.model = self.model
        if self.api_key:
            config.api_key = self.api_key
        if self.provider:
            config.provider = self.provider
        if self.base_url:
            config.base_url = self.base_url
        return FixerAgent(config)

    def _start_model_work(self) -> None:
        start = self._pending_model_start
        self._pending_model_start = None
        if start is not None:
            start()

    def _process_batch(
        self,
        batch: FixBatch,
        fixer,
        executor: RemediationExecutor,
        log,
    ):
        file_path = batch.file
        p = Path(file_path)
        if not p.exists():
            batch.status = "failed"
            batch.fix_status = "failed"
            batch.fix_description = "File not found"
            return
        if not p.is_file():
            batch.status = "skipped"
            batch.fix_description = "Repository-level finding; no file to edit"
            return

        if not executor.is_safe_file_path(file_path):
            batch.status = "failed"
            batch.fix_status = "failed"
            batch.fix_description = "File unavailable or outside project root"
            return
        source = read_text_no_symlink(
            p, max_bytes=MAX_REMEDIATION_FILE_BYTES, encoding="utf-8", newline=""
        )
        if source is None:
            batch.status = "failed"
            batch.fix_status = "failed"
            batch.fix_description = "Could not read source file"
            return
        batch.source = source

        primary = batch.findings[0]

        if not executor.capture_verification_baseline(
            file_path, [item.rule_id for item in batch.findings]
        ):
            batch.status = "failed"
            batch.fix_status = "incomplete"
            batch.fix_description = (
                "Could not capture a complete static baseline before editing"
            )
            return
        try:
            context = self._fix_context(batch, executor)
        except Exception as exc:
            batch.status = "failed"
            batch.fix_status = "incomplete"
            batch.fix_description = f"Could not build source-bound fix context: {exc}"
            return
        self._start_model_work()
        try:
            fix = fixer.fix(
                source,
                file_path,
                primary.line,
                primary.message,
                context=context,
            )
        except Exception as e:
            batch.status = "failed"
            batch.fix_status = "failed"
            batch.fix_description = f"Fix generation error: {e}"
            return

        if fix is None:
            batch.status = "skipped"
            batch.fix_description = "LLM could not generate a fix"
            return

        confidence = getattr(fix.confidence, "value", str(fix.confidence))
        if confidence == "low":
            batch.status = "skipped"
            batch.fix_description = "Fix confidence too low"
            return

        if not executor.apply_fix(file_path, fix.fixed_code, expected_source=source):
            batch.status = "failed"
            batch.fix_status = "failed"
            batch.fix_description = "Could not write fixed file"
            return

        self._attach_regression_test(batch, executor)
        source_files = [file_path]
        test_result = executor.run_tests(source_files=source_files)
        batch.checks.append(_check_summary(test_result, "project_command"))
        if getattr(test_result, "status", "") in ("failed", "outdated"):
            executor.revert_fix(file_path)
            executor.revert_regression_tests(batch.regression_tests)
            batch.regression_tests.clear()
            batch.status = "test_failed"
            batch.fix_status = (
                "outdated" if test_result.status == "outdated" else "failed"
            )
            batch.fix_description = (
                f"Tests did not pass after fix ({test_result.command})"
            )
            return
        if batch.regression_tests:
            regression_result = executor.run_regression_tests(
                batch.regression_tests, source_files=source_files
            )
            batch.checks.append(
                _check_summary(regression_result, "generated_static_regression")
            )
            if regression_result.status in ("failed", "outdated"):
                executor.revert_fix(file_path)
                executor.revert_regression_tests(batch.regression_tests)
                batch.regression_tests.clear()
                batch.status = "test_failed"
                batch.fix_status = (
                    "outdated" if regression_result.status == "outdated" else "failed"
                )
                batch.fix_description = "Generated static regression check did not pass"
                return

        rule_ids = [f.rule_id for f in batch.findings]
        verify = executor.verify_fix(file_path, rule_ids)
        batch.static_verification = verify.to_summary()
        if not verify.finding_resolved:
            executor.revert_fix(file_path)
            executor.revert_regression_tests(batch.regression_tests)
            batch.regression_tests.clear()
            batch.status = "not_resolved"
            batch.fix_status = "incomplete" if verify.verification_error else "failed"
            if verify.verification_error:
                batch.fix_description = f"Could not verify fix after remediation: {verify.verification_error}"
            elif verify.new_findings:
                batch.fix_description = "Fix introduced new static findings; reverted"
            else:
                batch.fix_description = (
                    f"Finding still present after fix: {verify.remaining_rule_ids}"
                )
            return
        relative_file = (
            p.resolve().relative_to(Path(executor.project_root).resolve()).as_posix()
        )
        checked_digests = [
            check.get("source_digests", {}).get(relative_file)
            for check in batch.checks
            if check.get("executed")
        ]
        if checked_digests and any(
            value != verify.source_digest for value in checked_digests
        ):
            batch.fix_status = "outdated"
        elif verify.status == "passed" and all(
            check["status"] == "passed" and check["executed"] for check in batch.checks
        ):
            batch.fix_status = "checks_passed"
        else:
            batch.fix_status = "incomplete"

        batch.status = "fixed"
        desc = getattr(fix, "description", "")
        if desc:
            batch.fix_description = desc[:200]
        else:
            batch.fix_description = primary.message

    def _finalize_batch_checks(
        self, plan: RemediationPlan, executor: RemediationExecutor, log
    ) -> None:
        applied = [batch for batch in plan.batches if batch.status == "fixed"]
        if len(applied) < 2:
            return
        if not self.allow_test_execution:
            for batch in applied[:-1]:
                batch.fix_status = "outdated"
                for check in batch.checks:
                    check["current"] = False
                batch.static_verification.setdefault("limitations", []).append(
                    "Later files were edited after this check; a final shared check was not run."
                )
            return

        log("  Rechecking all applied files after the final edit...")
        candidates = [
            candidate for batch in applied for candidate in batch.regression_tests
        ]
        files = [batch.file for batch in applied]
        files.extend(candidate.test_file for candidate in candidates)
        checks = [
            _check_summary(
                executor.run_tests(source_files=files), "final_project_command"
            )
        ]
        if candidates:
            checks.append(
                _check_summary(
                    executor.run_regression_tests(candidates, source_files=files),
                    "final_generated_static_regression",
                )
            )
        for batch in applied:
            for prior in batch.checks:
                prior["current"] = False
            batch.checks.extend(dict(check, current=True) for check in checks)
            verification = executor.verify_fix(
                batch.file, [item.rule_id for item in batch.findings]
            )
            batch.static_verification = verification.to_summary()
            if not verification.finding_resolved:
                batch.fix_status = (
                    "incomplete" if verification.verification_error else "failed"
                )
            elif any(check["status"] == "outdated" for check in checks):
                batch.fix_status = "outdated"
            elif any(check["status"] == "failed" for check in checks):
                batch.fix_status = "failed"
            elif verification.status != "passed" or any(
                check["status"] != "passed" or not check["executed"] for check in checks
            ):
                batch.fix_status = "incomplete"
            else:
                relative = (
                    Path(batch.file)
                    .resolve()
                    .relative_to(executor.project_root)
                    .as_posix()
                )
                batch.fix_status = (
                    "checks_passed"
                    if all(
                        check.get("source_digests", {}).get(relative)
                        == verification.source_digest
                        for check in checks
                    )
                    else "outdated"
                )
            if batch.fix_status != "checks_passed":
                batch.fix_description += f" (Final checks: {batch.fix_status.replace('_', ' ')}; changes kept for review.)"

    def _fix_context(self, batch: FixBatch, executor: RemediationExecutor) -> str:
        from skylos.cicd.context_packet import (
            build_pr_context,
            format_context_for_model,
        )
        from .context import ContextBuilder

        findings = [
            dict(
                item.raw,
                file=item.file,
                line=item.line,
                rule_id=item.rule_id,
                message=item.message,
            )
            for item in batch.findings
        ]
        packet = build_pr_context(executor.project_root, findings)
        batch.context_snapshot = str(packet.get("snapshot_id", ""))
        primary = batch.findings[0]
        local = ContextBuilder().build_fix_context(
            batch.source, batch.file, primary.line, primary.message
        )
        return format_context_for_model(packet) + "\n\n" + local

    def _attach_regression_test(
        self,
        batch: FixBatch,
        executor: RemediationExecutor,
    ) -> None:
        for finding in batch.findings:
            candidate = generate_regression_test_candidate(
                finding,
                executor.project_root,
            )
            if candidate is None:
                continue
            if executor.write_regression_test(candidate):
                batch.regression_tests.append(candidate)
            return

    def _prepare_pr_branch(
        self,
        project_root: Path,
        branch_prefix: str,
        log,
    ) -> str | None:
        executor = RemediationExecutor(project_root=project_root)
        try:
            branch = executor.create_branch(branch_prefix)
            log(f"  Branch: {branch}")
            return branch
        except Exception as e:
            log(f"  Failed to create branch: {e}")
            return None

    def _create_pr(
        self,
        executor: RemediationExecutor,
        plan: RemediationPlan,
        branch: str | None,
        log,
    ) -> str | None:
        fixed_batches = [b for b in plan.batches if b.status == "fixed"]
        if not fixed_batches or not branch:
            return None

        files = [b.file for b in fixed_batches]
        files.extend(
            str(executor.project_root / candidate.test_file)
            for batch in fixed_batches
            for candidate in batch.regression_tests
        )
        finding_count = sum(len(b.findings) for b in fixed_batches)
        expected = {}
        for batch in fixed_batches:
            relative = (
                Path(batch.file).resolve().relative_to(executor.project_root).as_posix()
            )
            expected[relative] = batch.static_verification.get("source_digest", "")
            for candidate in batch.regression_tests:
                expected[candidate.test_file] = (
                    "sha256:"
                    + hashlib.sha256(candidate.content.encode("utf-8")).hexdigest()
                )
        if not executor.publication_sources_match(expected):
            _publication_outdated(fixed_batches)
            log(
                "  Checked source changed or its receipt is unavailable; PR publication refused."
            )
            return None

        commit_msg = (
            f"fix: remediate {finding_count} security/quality findings\n\n"
            f"Automated by Skylos DevOps Agent.\n"
            f"Files: {', '.join(Path(f).name for f in files)}"
        )

        base_commit = executor.current_commit()
        if not executor.commit_fixes(commit_msg, files):
            log("  Failed to commit.")
            return None

        checked_commit = executor.current_commit()
        if not checked_commit or not executor.publication_sources_match(
            expected, commit=checked_commit, base_commit=base_commit
        ):
            _publication_outdated(fixed_batches)
            log(
                "  Committed source differs from checked bytes; PR publication refused."
            )
            return None
        for batch in fixed_batches:
            batch.static_verification["commit"] = checked_commit
        if not executor.push_branch(branch, expected_commit=checked_commit):
            log("  Failed to push branch.")
            return None

        summary = plan.summary()
        body = build_pr_description(summary)
        title = f"fix: skylos remediation ({finding_count} issues)"
        draft = any(batch.fix_status != "checks_passed" for batch in fixed_batches)
        pr_url = executor.create_pr(branch, title, body, draft=draft)
        if pr_url:
            log(f"  PR created: {pr_url}")
        return pr_url

    def _print_plan(self, plan: RemediationPlan, log):
        s = plan.summary()
        log(f"\n  Total findings: {s['total_findings']}")
        log(f"  Planned: {s['planned']}")
        log(f"  Fixes applied: {s['fixed']}")
        log(f"  Checks passed: {s['checks_passed']}")
        log(f"  Checks incomplete: {s['incomplete']}")
        log(f"  Checks failed: {s['checks_failed']}")
        log(f"  Failed: {s['failed']}")
        log(f"  Skipped: {s['skipped']}")

        if s["batches"]:
            log("")
            log(f"  {'File':<40} {'Status':<15} {'Sev':<10} {'#':<5}")
            log(f"  {'─' * 40} {'─' * 15} {'─' * 10} {'─' * 5}")
            for b in s["batches"]:
                fname = b["file"]
                if len(fname) > 38:
                    fname = "…" + fname[-37:]
                log(
                    f"  {fname:<40} {b['status']:<15} "
                    f"{b['top_severity']:<10} {b['findings']:<5}"
                )


def _logger(quiet: bool):
    if quiet:
        return lambda msg: None

    def _log(msg):
        print(msg, file=sys.stderr)

    return _log


def _section_count(results: dict, key: str) -> int:
    values = results.get(key)
    if not isinstance(values, list):
        return 0
    return len(values)


def _project_root_for_path(path: Path) -> Path:
    if path.is_dir():
        return path
    return path.parent


def _check_summary(result, kind: str) -> dict:
    if hasattr(result, "to_summary"):
        record = result.to_summary()
    else:
        # Legacy integrations without an execution receipt cannot claim checks passed.
        record = {
            "status": "not_run",
            "executed": False,
            "command": getattr(result, "command", ""),
            "source_digests": {},
        }
    return dict(record, kind=kind)


def _publication_outdated(batches: list[FixBatch]) -> None:
    for batch in batches:
        batch.fix_status = "outdated"
        batch.fix_description += " (Source changed after checks; publication refused.)"
        for check in batch.checks:
            check["current"] = False
