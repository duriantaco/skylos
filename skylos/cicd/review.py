from __future__ import annotations

import json
import os
import re
import subprocess

from rich.console import Console

console = Console()


def run_pr_review(
    results: dict,
    *,
    pr_number: int | None = None,
    repo: str | None = None,
    summary_only: bool = False,
    max_comments: int = 25,
    diff_base: str = "origin/main",
    grade: dict | None = None,
    previous_grade: dict | None = None,
    llm_findings: list[dict] | None = None,
) -> None:
    pr_number = pr_number or _detect_pr_number()
    repo = repo or os.environ.get("GITHUB_REPOSITORY")

    if not pr_number:
        console.print(
            "[yellow]Could not detect PR number. Use --pr to specify.[/yellow]"
        )
        return

    if not repo:
        console.print("[yellow]Could not detect repo. Use --repo to specify.[/yellow]")
        return

    if not _gh_available():
        console.print(
            "[bold red]gh CLI not found. Install: https://cli.github.com[/bold red]"
        )
        return

    if grade and previous_grade is None:
        previous_grade = _fetch_previous_grade(repo, diff_base)

    all_findings = _flatten_findings(results)

    if llm_findings:
        all_findings = _merge_llm_findings(all_findings, llm_findings)

    if not summary_only:
        changed_ranges = get_changed_line_ranges(diff_base)
        findings = filter_findings_to_diff(all_findings, changed_ranges)
    else:
        findings = all_findings

    if findings and not summary_only:
        _post_pr_review(findings[:max_comments], pr_number, repo)

    _post_summary_comment(
        all_findings,
        findings,
        pr_number,
        repo,
        grade=grade,
        previous_grade=previous_grade,
    )

    console.print(
        f"[green]Posted review on PR #{pr_number} "
        f"({len(findings)} inline, {len(all_findings)} total)[/green]"
    )


def get_changed_line_ranges(base_ref: str = "origin/main") -> list[dict]:
    try:
        result = subprocess.run(
            ["git", "diff", "--unified=0", f"{base_ref}...HEAD"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return []
    except FileNotFoundError:
        return []

    return _parse_unified_diff(result.stdout)


def _parse_unified_diff(diff_output: str) -> list[dict]:
    entries = []
    current_file = None

    for line in diff_output.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        hunk_match = re.match(r"^@@ .+ \+(\d+)(?:,(\d+))? @@", line)
        if hunk_match and current_file:
            start = int(hunk_match.group(1))
            count = int(hunk_match.group(2) or 1)
            if count > 0:
                entries.append(
                    {
                        "file": current_file,
                        "start": start,
                        "end": start + count - 1,
                    }
                )

    return entries


def filter_findings_to_diff(
    findings: list[dict], changed_ranges: list[dict]
) -> list[dict]:
    if not changed_ranges:
        return []

    ranges_by_file = {}
    for r in changed_ranges:
        ranges_by_file.setdefault(r["file"], []).append((r["start"], r["end"]))

    filtered = []
    for finding in findings:
        file = finding.get("file", "")
        line = finding.get("line", 0)

        file_ranges = ranges_by_file.get(file, [])
        if not file_ranges:
            for diff_file, ranges in ranges_by_file.items():
                if file.endswith("/" + diff_file) or diff_file.endswith("/" + file):
                    file_ranges = ranges
                    break
        for start, end in file_ranges:
            if start <= line <= end:
                filtered.append(finding)
                break

    return filtered


def _flatten_findings(results: dict) -> list[dict]:
    findings = []

    for category in ("danger", "quality", "secrets", "custom_rules"):
        for f in results.get(category, []) or []:
            findings.append(
                {
                    "file": f.get("file") or f.get("file_path") or "",
                    "line": f.get("line") or f.get("line_number") or 1,
                    "message": f.get("message")
                    or f.get("msg")
                    or f.get("detail")
                    or "",
                    "rule_id": f.get("rule_id") or "",
                    "severity": f.get("severity", "MEDIUM"),
                    "category": category,
                }
            )

    return findings


def _merge_llm_findings(
    static_findings: list[dict], llm_findings: list[dict]
) -> list[dict]:
    llm_by_loc: dict[tuple, dict] = {}
    for f in llm_findings:
        file = f.get("file", "")
        line = f.get("line", 0)
        key = (os.path.basename(file), line)
        llm_by_loc[key] = f

    matched_keys = set()
    for finding in static_findings:
        file = finding.get("file", "")
        line = finding.get("line", 0)
        key = (os.path.basename(file), line)
        if key in llm_by_loc:
            llm = llm_by_loc[key]
            if llm.get("suggestion"):
                finding["suggestion"] = llm["suggestion"]
            if llm.get("explanation"):
                finding["explanation"] = llm["explanation"]
            if llm.get("vulnerable_code"):
                finding["vulnerable_code"] = llm["vulnerable_code"]
            if llm.get("fixed_code"):
                finding["fixed_code"] = llm["fixed_code"]
            matched_keys.add(key)

    for key, llm in llm_by_loc.items():
        if key not in matched_keys:
            static_findings.append(
                {
                    "file": llm.get("file", ""),
                    "line": llm.get("line", 0),
                    "message": llm.get("message", ""),
                    "rule_id": llm.get("rule_id", ""),
                    "severity": llm.get("severity", "MEDIUM"),
                    "category": llm.get("_category", "security"),
                    "suggestion": llm.get("suggestion"),
                    "explanation": llm.get("explanation"),
                    "vulnerable_code": llm.get("vulnerable_code"),
                    "fixed_code": llm.get("fixed_code"),
                    "_source": "llm",
                }
            )

    return static_findings


_RULE_SUGGESTIONS: dict[str, str] = {
    "SKY-D201": "Replace `eval()` with `json.loads()`, `ast.literal_eval()`, or a safe parser. Never evaluate untrusted input.",
    "SKY-D203": "Replace `os.system()` with `subprocess.run()` with `shell=False`. Pass arguments as a list.",
    "SKY-D211": "Use parameterized queries: `cursor.execute('SELECT * FROM t WHERE x = ?', (val,))` instead of f-strings.",
    "SKY-D212": "Sanitize input before passing to shell commands, or use `subprocess.run()` with `shell=False` and argument lists.",
    "SKY-D215": "Validate file paths against an allowed directory: `Path(path).resolve().relative_to(allowed_dir)`.",
    "SKY-D216": "Validate URLs against an allowlist of domains. Block internal IPs (`127.0.0.1`, `169.254.x.x`, `10.x.x.x`).",
    "SKY-D223": "Add the package to `requirements.txt` or `pyproject.toml`, or remove the import if unused.",
    "SKY-S101": "Move secrets to environment variables: `os.getenv('SECRET_KEY')`. Never hardcode credentials.",
}


def _format_review_comment(finding: dict) -> str:
    severity = finding.get("severity", "MEDIUM")
    badge = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
        severity, "⚪"
    )
    rule_id = finding.get("rule_id", "")
    message = finding.get("message", "")
    rule_str = f" `{rule_id}`" if rule_id else ""

    parts = [f"{badge} **{severity}**{rule_str}", "", message]

    explanation = finding.get("explanation")
    if explanation:
        parts.extend(["", f"**Why:** {explanation}"])

    vulnerable_code = finding.get("vulnerable_code")
    fixed_code = finding.get("fixed_code")

    if vulnerable_code and fixed_code:
        parts.extend(
            [
                "",
                "**Vulnerable code:**",
                "```python",
                vulnerable_code,
                "```",
                "",
                "**Fixed code:**",
                "```python",
                fixed_code,
                "```",
            ]
        )
    else:
        suggestion = finding.get("suggestion") or _RULE_SUGGESTIONS.get(rule_id)
        if suggestion:
            parts.extend(["", f"**Fix:** {suggestion}"])

    footer = "\n\n---\n_🤖 Analyzed by [Skylos](https://github.com/duriantaco/skylos) • [Add to your repo](https://github.com/duriantaco/skylos#cicd)_"
    parts.append(footer)

    return "\n".join(parts)


def _to_relative_path(filepath: str) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            root = result.stdout.strip()
            if filepath.startswith(root):
                return filepath[len(root) :].lstrip("/")
    except Exception:
        pass
    return filepath


def _post_pr_review(findings: list[dict], pr_number: int, repo: str) -> None:
    comments = []
    for f in findings:
        if not f.get("file") or not f.get("line"):
            continue
        comments.append(
            {
                "path": _to_relative_path(f["file"]),
                "line": f["line"],
                "body": _format_review_comment(f),
            }
        )

    if not comments:
        return

    payload = {
        "body": (
            f"Skylos found {len(comments)} issue(s) on changed lines.\n\n"
            "---\n"
            "_🤖 Analyzed by [Skylos](https://github.com/duriantaco/skylos) • "
            "[Set up in 30 seconds](https://github.com/duriantaco/skylos#cicd)_"
        ),
        "event": "COMMENT",
        "comments": comments,
    }

    try:
        subprocess.run(
            [
                "gh",
                "api",
                "--method",
                "POST",
                f"/repos/{repo}/pulls/{pr_number}/reviews",
                "--input",
                "-",
            ],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[yellow]Failed to post PR review: {e.stderr}[/yellow]")


def _post_summary_comment(
    all_findings: list[dict],
    diff_findings: list[dict],
    pr_number: int,
    repo: str,
    *,
    grade: dict | None = None,
    previous_grade: dict | None = None,
) -> None:
    by_severity = {}
    for f in all_findings:
        sev = f.get("severity", "MEDIUM")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    by_category = {}
    for f in all_findings:
        cat = f.get("category", "other")
        by_category[cat] = by_category.get(cat, 0) + 1

    lines = [
        "## Skylos Analysis Summary",
        "",
        f"**{len(diff_findings)}** issue(s) on changed lines | "
        f"**{len(all_findings)}** total",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = by_severity.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev} | {count} |")

    if by_category:
        lines.extend(
            [
                "",
                "| Category | Count |",
                "|----------|-------|",
            ]
        )
        for cat in ("danger", "quality", "secrets", "custom_rules"):
            count = by_category.get(cat, 0)
            if count > 0:
                lines.append(f"| {cat} | {count} |")

    critical_findings = [
        f for f in diff_findings if f.get("severity") in ("CRITICAL", "HIGH")
    ]
    if critical_findings:
        lines.extend(["", "### Top Issues", ""])
        for f in critical_findings[:5]:
            sev = f.get("severity", "MEDIUM")
            badge = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(sev, "🟡")
            rule = f" `{f['rule_id']}`" if f.get("rule_id") else ""
            file = os.path.basename(f.get("file", ""))
            line_no = f.get("line", "")
            loc = f" ({file}:{line_no})" if file else ""
            lines.append(f"- {badge} **{sev}**{rule}{loc}: {f.get('message', '')}")

            vuln_code = f.get("vulnerable_code")
            fix_code = f.get("fixed_code")
            if vuln_code and fix_code:
                lines.append("")
                lines.append("  <details><summary>View fix</summary>")
                lines.append("")
                lines.append("  **Vulnerable:**")
                lines.append("  ```python")
                for code_line in vuln_code.splitlines():
                    lines.append(f"  {code_line}")
                lines.append("  ```")
                lines.append("  **Fixed:**")
                lines.append("  ```python")
                for code_line in fix_code.splitlines():
                    lines.append(f"  {code_line}")
                lines.append("  ```")
                lines.append("  </details>")
                lines.append("")
            else:
                fix = f.get("suggestion") or _RULE_SUGGESTIONS.get(f.get("rule_id", ""))
                if fix:
                    lines.append(f"  - **Fix:** {fix}")

    if grade:
        overall = grade["overall"]
        cats = grade["categories"]

        lines.extend(["", "### Codebase Grade", ""])

        if previous_grade:
            prev = previous_grade["overall"]
            delta = overall["score"] - prev["score"]
            arrow = "+" if delta > 0 else ""
            direction = "\u2191" if delta > 0 else ("\u2193" if delta < 0 else "\u2194")
            lines.append(
                f"**{prev['letter']} ({prev['score']}) \u2192 "
                f"{overall['letter']} ({overall['score']}) {direction}** "
                f"({arrow}{delta})"
            )
        else:
            lines.append(f"**Overall: {overall['letter']} ({overall['score']}/100)**")

        lines.extend(
            [
                "",
                "| Category | Score | Grade | Key Issue |",
                "|----------|-------|-------|-----------|",
            ]
        )

        for cat_name in ("security", "quality", "dead_code", "dependencies", "secrets"):
            cat = cats[cat_name]
            display = cat_name.replace("_", " ").title()
            issue = (cat.get("key_issue") or "-")[:50]

            delta_str = ""
            if previous_grade and cat_name in previous_grade.get("categories", {}):
                prev_cat = previous_grade["categories"][cat_name]
                cat_delta = cat["score"] - prev_cat["score"]
                if cat_delta != 0:
                    d_arrow = "\u2191" if cat_delta > 0 else "\u2193"
                    delta_str = f" {d_arrow}{abs(cat_delta)}"

            lines.append(
                f"| {display} | {cat['score']}{delta_str} | {cat['letter']} | {issue} |"
            )

    body = "\n".join(lines)

    try:
        subprocess.run(
            ["gh", "pr", "comment", str(pr_number), "--body", body, "--repo", repo],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        console.print(f"[yellow]Failed to post summary comment: {e.stderr}[/yellow]")


def _fetch_previous_grade(repo: str, base_branch: str = "origin/main") -> dict | None:
    try:
        from skylos.api import get_project_token, BASE_URL
        import requests

        token = get_project_token()
        if not token:
            return None

        branch = base_branch.replace("origin/", "")
        resp = requests.get(
            f"{BASE_URL}/api/grade/latest",
            params={"branch": branch},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("grade")
    except Exception:
        pass
    return None


def _detect_pr_number() -> int | None:
    ref = os.environ.get("GITHUB_REF", "")
    match = re.match(r"refs/pull/(\d+)/merge", ref)
    if match:
        return int(match.group(1))
    return None


def _gh_available() -> bool:
    try:
        subprocess.run(["gh", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
