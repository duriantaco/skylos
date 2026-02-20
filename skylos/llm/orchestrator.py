from __future__ import annotations

import sys
from pathlib import Path

from .planner import RemediationPlanner, RemediationPlan, FixBatch
from .executor import RemediationExecutor
from .prompts import build_pr_description


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
    ):
        self.model = model
        self.api_key = api_key
        self.test_cmd = test_cmd
        self.severity_filter = severity_filter
        self.provider = provider
        self.base_url = base_url
        self.planner = RemediationPlanner(severity_filter=severity_filter)

    def run(
        self,
        path: str | Path,
        *,
        dry_run: bool = False,
        max_fixes: int = 10,
        auto_pr: bool = False,
        branch_prefix: str = "skylos/fix",
        quiet: bool = False,
    ) -> dict:
        path = Path(path).resolve()
        log = _logger(quiet)

        log("Step 1/5: Scanning project...")
        results = self._scan(path)
        danger_count = len(results.get("danger", []) or [])
        quality_count = len(results.get("quality", []) or [])
        secrets_count = len(results.get("secrets", []) or [])
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

        log("Step 3/5: Generating and applying fixes...")
        executor = RemediationExecutor(
            test_cmd=self.test_cmd,
            project_root=path if path.is_dir() else path.parent,
        )

        fixer = self._create_fixer()
        fixed_files: list[str] = []

        for batch in plan.batches:
            log(f"\n  Fixing {batch.file} ({len(batch.findings)} findings)...")
            self._process_batch(batch, fixer, executor, log)

            if batch.status == "fixed":
                fixed_files.append(batch.file)
                log(f"    ✓ Fixed successfully")
            else:
                log(f"    ✗ Status: {batch.status} — {batch.fix_description}")

        fixed_count = sum(1 for b in plan.batches if b.status == "fixed")
        log(f"\n  Results: {fixed_count}/{len(plan.batches)} files fixed")

        pr_url = None
        if auto_pr and fixed_files:
            log("Step 4/5: Creating pull request...")
            pr_url = self._create_pr(executor, plan, branch_prefix, log)
        else:
            if not fixed_files:
                log("Step 4/5: No fixes applied — skipping PR.")
            else:
                log("Step 4/5: Skipped (--auto-pr not set).")

        log("Step 5/5: Summary")
        summary = plan.summary()
        if pr_url:
            summary["pr_url"] = pr_url
        self._print_plan(plan, log)

        return summary

    def _scan(self, path: Path) -> dict:
        import json
        from skylos.analyzer import analyze as run_analyze

        raw = run_analyze(
            str(path),
            conf=0,
            enable_danger=True,
            enable_quality=True,
            enable_secrets=True,
        )
        return json.loads(raw) if isinstance(raw, str) else raw

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
            batch.fix_description = "File not found"
            return

        source = p.read_text(encoding="utf-8")
        batch.source = source

        primary = batch.findings[0]

        try:
            fix = fixer.fix(
                source,
                file_path,
                primary.line,
                primary.message,
            )
        except Exception as e:
            batch.status = "failed"
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

        if not executor.apply_fix(file_path, fix.fixed_code):
            batch.status = "failed"
            batch.fix_description = "Could not write fixed file"
            return

        test_result = executor.run_tests()
        if not test_result.passed:
            executor.revert_fix(file_path)
            batch.status = "test_failed"
            batch.fix_description = f"Tests failed after fix ({test_result.command})"
            return

        rule_ids = [f.rule_id for f in batch.findings]
        verify = executor.verify_fix(file_path, rule_ids)
        if not verify.finding_resolved:
            executor.revert_fix(file_path)
            batch.status = "not_resolved"
            batch.fix_description = (
                f"Finding still present after fix: {verify.remaining_rule_ids}"
            )
            return

        batch.status = "fixed"
        desc = getattr(fix, "description", "")
        batch.fix_description = desc[:200] if desc else primary.message

    def _create_pr(
        self,
        executor: RemediationExecutor,
        plan: RemediationPlan,
        branch_prefix: str,
        log,
    ) -> str | None:
        fixed_batches = [b for b in plan.batches if b.status == "fixed"]
        if not fixed_batches:
            return None

        try:
            branch = executor.create_branch(branch_prefix)
            log(f"  Branch: {branch}")
        except Exception as e:
            log(f"  Failed to create branch: {e}")
            return None

        files = [b.file for b in fixed_batches]
        finding_count = sum(len(b.findings) for b in fixed_batches)

        commit_msg = (
            f"fix: remediate {finding_count} security/quality findings\n\n"
            f"Automated by Skylos DevOps Agent.\n"
            f"Files: {', '.join(Path(f).name for f in files)}"
        )

        if not executor.commit_fixes(commit_msg, files):
            log("  Failed to commit.")
            return None

        if not executor.push_branch(branch):
            log("  Failed to push branch.")
            return None

        summary = plan.summary()
        body = build_pr_description(summary)
        title = f"fix: skylos remediation ({finding_count} issues)"
        pr_url = executor.create_pr(branch, title, body)
        if pr_url:
            log(f"  PR created: {pr_url}")
        return pr_url

    def _print_plan(self, plan: RemediationPlan, log):
        s = plan.summary()
        log(f"\n  Total findings: {s['total_findings']}")
        log(f"  Planned: {s['planned']}")
        log(f"  Fixed: {s['fixed']}")
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
