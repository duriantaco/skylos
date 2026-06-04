from __future__ import annotations

from typing import Any


def format_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"Benchmark: {summary.get('name')}",
        (
            "Cases: "
            f"{summary['passed_count']} passed, "
            f"{summary['failed_count']} failed, "
            f"{summary['case_count']} total"
        ),
        (
            "Findings: "
            f"{summary['matched_findings']} matched / "
            f"{summary['expected_findings']} expected"
        ),
        f"Precision: {float(summary['precision']):.2f}",
        f"Recall: {float(summary['recall']):.2f}",
        f"F1: {float(summary['f1']):.2f}",
    ]
    for case in summary["cases"]:
        status = "PASS"
        if not case["passed"]:
            status = "FAIL"
        lines.append(f"- {case['id']}: {status}")
    return "\n".join(lines)


def format_report(summary: dict[str, Any]) -> str:
    lines = [
        "# Verify Benchmark Report",
        "",
        f"Benchmark: {summary.get('name')}",
        "",
        str(summary.get("description", "")),
        "",
        "## Methodology",
        "",
        (
            "This benchmark treats the verifier as a black box. The manifest "
            "uses neutral defect labels instead of Skylos rule IDs, and the "
            "runner invokes the configured CLI command without importing "
            "verifier internals."
        ),
        "",
        "Methodology references:",
    ]

    lines.extend(_methodology_source_lines(summary))
    lines.extend(_command_lines())
    lines.extend(_summary_lines(summary))
    lines.extend(_case_table_lines(summary))
    lines.extend(_interpretation_lines(summary))
    lines.extend(_failure_lines(summary))
    return "\n".join(lines) + "\n"


def _methodology_source_lines(summary: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for source in _methodology_sources(summary):
        lines.append(
            f"- {source.get('name')}: {source.get('principle')} "
            f"({source.get('url')})"
        )
    return lines


def _command_lines() -> list[str]:
    return [
        "",
        "## Command",
        "",
        "```bash",
        "python scripts/verify_benchmark.py "
        "--tool-command .venv/bin/skylos "
        "--report /private/tmp/skylos-verify-benchmark-report.md",
        "```",
        "",
    ]


def _summary_lines(summary: dict[str, Any]) -> list[str]:
    return [
        "## Summary",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Cases | {summary['case_count']} |",
        f"| Passed | {summary['passed_count']} |",
        f"| Failed | {summary['failed_count']} |",
        f"| Expected findings | {summary['expected_findings']} |",
        f"| Matched findings | {summary['matched_findings']} |",
        f"| False negatives | {summary['false_negatives']} |",
        f"| False positives / noise | {summary['false_positives']} |",
        f"| Precision | {float(summary['precision']):.2f} |",
        f"| Recall | {float(summary['recall']):.2f} |",
        f"| F1 | {float(summary['f1']):.2f} |",
        f"| Runtime | {float(summary['elapsed_seconds']):.2f}s |",
        "",
    ]


def _case_table_lines(summary: dict[str, Any]) -> list[str]:
    lines = [
        "## Case Results",
        "",
        "| Case | Result | Expected | Matched | Findings |",
        "|---|---|---:|---:|---:|",
    ]
    for case in summary["cases"]:
        status = "PASS"
        if not case["passed"]:
            status = "FAIL"
        lines.append(
            f"| {case['id']} | {status} | {case['expected_count']} | "
            f"{case['matched_count']} | {case['finding_count']} |"
        )
    lines.append("")
    return lines


def _interpretation_lines(summary: dict[str, Any]) -> list[str]:
    return [
        "## Interpretation",
        "",
        _interpretation(summary),
        "",
        "## Failures",
        "",
    ]


def _failure_lines(summary: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    failures_written = False
    for case in summary["cases"]:
        if case["passed"]:
            continue
        failures_written = True
        lines.extend(_case_failure_lines(case))

    if not failures_written:
        lines.append("No failing cases.")
    return lines


def _methodology_sources(summary: dict[str, Any]) -> list[dict[str, Any]]:
    sources = summary.get("methodology_sources")
    if not isinstance(sources, list):
        return []

    safe_sources: list[dict[str, Any]] = []
    for source in sources:
        if isinstance(source, dict):
            safe_sources.append(source)
    return safe_sources


def _interpretation(summary: dict[str, Any]) -> str:
    failed_count = int(summary["failed_count"])
    precision = float(summary["precision"])
    recall = float(summary["recall"])

    if failed_count == 0:
        return (
            "The tool passed every neutral-label case. Treat this as a stronger "
            "signal than the regression suite, but still not as a substitute "
            "for a larger real-world corpus."
        )

    lines = [
        (
            "This is not a pass-preserving regression result. The failures are "
            "useful because they identify product gaps under neutral labels."
        ),
        f"Recall is {recall:.2f}, so some expected defects were missed.",
        f"Precision is {precision:.2f}, so observed noise is limited in this run.",
    ]
    return "\n\n".join(lines)


def _case_failure_lines(case: dict[str, Any]) -> list[str]:
    lines = [
        f"### {case['id']}",
        "",
    ]
    if case["missed"]:
        lines.append("Missed expected findings:")
        for item in case["missed"]:
            lines.append(f"- `{item.get('kind')}` {item.get('evidence', [])}")
        lines.append("")

    if case["forbidden"]:
        lines.append("Forbidden findings observed:")
        for item in case["forbidden"]:
            finding = item.get("finding")
            lines.append(f"- `{finding}`")
        lines.append("")

    if case["unexpected"]:
        lines.append("Unexpected findings:")
        for finding in case["unexpected"]:
            lines.append(f"- `{finding}`")
        lines.append("")
    return lines
