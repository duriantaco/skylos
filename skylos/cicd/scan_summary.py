"""Report source scan coverage and listed findings in GitHub Actions."""

import json
import os
import sys
from itertools import islice
from pathlib import Path

from skylos.cicd.evidence import sanitize_markdown_text
from skylos.core.gate_incomplete import analysis_coverage
from skylos.reporting.issue_summary import issue_summary

PARTIAL_SCAN_NOTICE = "**Scan coverage is incomplete.** Finding counts are provisional."


def _parse_locations(errors, root):
    locations = {}
    if not isinstance(errors, list):
        return locations
    for row in errors:
        if not isinstance(row, dict) or row.get("kind") not in (
            "syntax_error",
            "cpp_parse_error",
        ):
            continue
        path = row.get("file")
        if not isinstance(path, str) or not path:
            continue
        if isinstance(root, str) and root:
            prefix = root.rstrip("/\\")
            path = path.removeprefix(prefix + "/").removeprefix(prefix + "\\")
        locations.setdefault(path, row.get("line"))
    return locations


def scan_coverage_notice(result):
    summary = result.get("analysis_summary")
    summary = summary if isinstance(summary, dict) else {}
    record = summary.get("analysis_coverage")
    record = record if isinstance(record, dict) else {}
    if (
        record.get("status") not in ("partial", "incomplete")
        and analysis_coverage(result).status == "complete"
    ):
        return ""

    # A diff-scoped parse error can block the scan before it becomes a file
    # gap. Older reports have raw errors only. Both still name the failed files.
    scope = summary.get("comparison_scope")
    root = scope.get("repository_root") if isinstance(scope, dict) else None
    errors = result.get("analysis_errors") or record.get("unchecked_files")
    locations = _parse_locations(errors, root)
    recorded_count = record.get("unchecked_file_count")
    count = max(len(locations), recorded_count if type(recorded_count) is int else 0)
    if not count:
        return PARTIAL_SCAN_NOTICE
    total = record.get("source_file_count", summary.get("total_files"))
    if type(total) is int and total >= count:
        scope_text = f"{count} of {total} source {'file' if total == 1 else 'files'}"
    else:
        scope_text = f"{count} source {'file' if count == 1 else 'files'}"
    notice = f"{PARTIAL_SCAN_NOTICE} Skylos could not fully check {scope_text}."
    if locations:
        examples = []
        for path, line in islice(locations.items(), 3):
            location = f"{path}:{line}" if type(line) is int and line > 0 else path
            examples.append(f"`{sanitize_markdown_text(location, max_length=200)}`")
        if len(locations) > len(examples):
            examples.append(f"{len(locations) - len(examples)} more")
        notice += " Parse errors in " + ", ".join(examples) + "."
    return notice


def write_action_summary(report_file):
    with open(report_file, encoding="utf-8") as stream:
        result = json.load(stream)
    count = issue_summary(result)["total"]
    notice = scan_coverage_notice(result)
    path = sanitize_markdown_text(os.environ["SKYLOS_PATH"], max_length=200)
    lines = ["### Skylos Scan Results", ""]
    if notice:
        lines.extend([notice, ""])
    noun = "finding" if count == 1 else "findings"
    lines.append(f"Found **{count}** listed {noun} in `{path}`.")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        stream.write(f"findings_count={count}\n")


if __name__ == "__main__":
    write_action_summary(sys.argv[1])
