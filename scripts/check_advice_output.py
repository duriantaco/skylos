"""Check lossless advice views against saved local scan JSON, without rescanning.

Example:
    python scripts/check_advice_output.py report.json --project-root /path/to/repo
"""

from __future__ import annotations

import argparse
from collections import Counter
import copy
import json
from pathlib import Path

from skylos.core.gatekeeper import check_gate
from skylos.core.safe_cache_io import read_text_no_symlink, write_text_no_symlink
from skylos.reporting.advice_display import (
    advice_display,
    advice_display_counts,
    combine_advice,
)
from skylos.reporting.advice_policy import prepare_advice_view
from skylos.reporting.finding_types import get_finding_type, iter_result_findings
from skylos.reporting.listing import is_listed, listing_decision


def _key(category, finding):
    return json.dumps([category, finding], sort_keys=True, separators=(",", ":"))


def _load_json(path, *, max_bytes=64 * 1024 * 1024):
    text = read_text_no_symlink(path, max_bytes=max_bytes)
    if text is None:
        raise ValueError("Expected a readable regular JSON file within the size limit")
    return json.loads(text)


def check_report(result, project_root):
    """Assert evidence recovery, risk visibility and input/gate preservation."""
    before = json.dumps(result, sort_keys=True)
    original = list(iter_result_findings(result))
    original_records = Counter(_key(category, row) for category, row in original)
    gate_config = {"gate": {"max_quality": 0, "max_high": 0}}
    gate_before = check_gate(copy.deepcopy(result), gate_config)

    complete, complete_visibility = prepare_advice_view(
        result, project_root=project_root, all_advice=True
    )
    assert complete is result, "All-advice view replaced the input report"
    assert complete_visibility.omitted_checks == 0, "All-advice view omitted evidence"
    grouped = combine_advice(iter_result_findings(complete))
    recovered = []
    for category, row in grouped:
        metadata = advice_display(row)
        recovered.extend(
            (category, original_row)
            for original_row in (metadata.findings if metadata else (row,))
        )
    assert (
        Counter(_key(category, row) for category, row in recovered) == original_records
    ), "Grouped output cannot recover every original finding and evidence record"
    assert combine_advice(grouped) == grouped, "Grouping is not idempotent"

    focused, visibility = prepare_advice_view(result, project_root=project_root)
    focus_rows = list(iter_result_findings(focused))
    focus_records = Counter(_key(category, row) for category, row in focus_rows)
    assert not focus_records - original_records, (
        "Focused view invented or changed a finding"
    )
    original_risk = [
        _key(category, row)
        for category, row in original
        if category != "quality" or get_finding_type(row, category) != "advice"
    ]
    focused_risk = [
        _key(category, row)
        for category, row in focus_rows
        if category != "quality" or get_finding_type(row, category) != "advice"
    ]
    assert original_risk == focused_risk, (
        "Focused advice changed risk or custom records"
    )
    marked = result.get("listing_policy_version") == 1
    if marked:
        assert all(listing_decision(row) is not None for _, row in original), (
            "A versioned report contains an unmarked finding"
        )
        expected = Counter(
            _key(category, row)
            for category, row in original
            if is_listed(row, category)
        )
        assert focus_records == expected, "Focused view disagrees with listing marks"
    assert json.dumps(result, sort_keys=True) == before, "Presentation mutated raw JSON"
    assert check_gate(copy.deepcopy(result), gate_config) == gate_before, (
        "Raw gate outcome changed"
    )

    all_counts = advice_display_counts(complete)
    focus_counts = advice_display_counts(focused)
    assert (
        all_counts["raw_advice"] - focus_counts["raw_advice"]
        == visibility.omitted_checks
    ), "Optional advice notice does not match the findings omitted from the view"
    return {
        "raw_advice_checks": all_counts["raw_advice"],
        "all_advice_entries": all_counts["advice"],
        "focused_advice_checks": focus_counts["raw_advice"],
        "focused_advice_entries": focus_counts["advice"],
        "optional_advice_checks": visibility.omitted_checks,
        "optional_reasons": dict(visibility.reasons),
        "lossless_grouping": True,
        "raw_json_unchanged": True,
        "risk_records_unchanged": True,
        "raw_gate_unchanged": True,
        "shared_listing_verified": marked,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    roots = parser.add_mutually_exclusive_group(required=True)
    roots.add_argument("--project-root", type=Path)
    roots.add_argument(
        "--targets",
        type=Path,
        help="JSON list with name/path entries; report filenames must match names",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    targets = {}
    if args.targets:
        targets = {
            entry["name"]: Path(entry["path"])
            for entry in _load_json(args.targets, max_bytes=1024 * 1024)
        }
    checked = []
    for report in args.reports:
        root = args.project_root or targets.get(report.stem)
        if root is None:
            parser.error(f"No target root for {report.name}")
        try:
            result = check_report(_load_json(report), root)
        except (AssertionError, OSError, ValueError, TypeError, KeyError) as exc:
            raise SystemExit(
                f"Advice output check failed for {report.name}: {type(exc).__name__}"
            ) from exc
        checked.append({"report": str(report), "project_root": str(root), **result})
    output = (
        json.dumps({"reports_checked": len(checked), "reports": checked}, indent=2)
        + "\n"
    )
    if args.output:
        if not write_text_no_symlink(args.output, output):
            raise SystemExit("Could not safely write the advice output summary")
    print(output, end="")


if __name__ == "__main__":
    main()
