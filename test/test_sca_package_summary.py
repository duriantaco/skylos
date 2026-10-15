"""Terminal output rolls dependency advisories up per package; JSON does not."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from skylos.reporting.sca_summary import group_advisories
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import render_pretty_results


def _advisory(name, version, vuln, severity, fixed, line=3):
    return {
        "rule_id": f"SKY-SCA-{vuln}",
        "category": "DEPENDENCY",
        "severity": severity,
        "message": f"{name}@{version}: advisory {vuln}",
        "file": "package.json",
        "line": line,
        "metadata": {
            "vuln_id": vuln,
            "display_id": vuln,
            "fixed_version": fixed,
            "ecosystem": "npm",
            "package_name": name,
            "package_version": version,
        },
    }


ADVISORIES = [
    *[
        _advisory("next", "16.0.10", f"GHSA-n{i}", "HIGH", fixed)
        for i, fixed in enumerate(["16.0.11", "16.1.2", "16.0.9-canary.3", None])
    ],
    _advisory("next", "16.0.10", "GHSA-crit", "CRITICAL", "16.0.12"),
    _advisory("lodash", "4.17.15", "GHSA-l1", "MEDIUM", "4.17.21", line=4),
]
LICENSE = {
    "rule_id": "SKY-SCA-LIC001",
    "severity": "HIGH",
    "message": "left-pad uses a denied licence",
    "file": "package.json",
    "line": 5,
    "metadata": {"package_name": "left-pad", "package_version": "1.0.0"},
}


def test_group_per_package_with_highest_fix_and_worst_severity():
    groups = group_advisories([*ADVISORIES, LICENSE])

    assert [(g.name, g.count, g.worst_severity) for g in groups] == [
        ("next", 5, "CRITICAL"),
        ("lodash", 1, "MEDIUM"),
    ]
    assert groups[0].fix_version == "16.1.2"
    # 16.0.9-canary.3 is below the installed version: no fix above it.
    assert groups[0].fix_text() == "16.1.2 (2 without a fix)"
    assert groups[0].ids_text() == "GHSA-n0, GHSA-n1, GHSA-n2 +2 more"


def test_fix_on_several_release_lines_uses_the_lowest_above_installed():
    advisory = _advisory("next", "14.0.0", "GHSA-x", "HIGH", None)
    advisory["metadata"]["fixed_versions"] = ["16.3.3", "15.5.24"]

    [group] = group_advisories([advisory])

    assert group.fix_text() == "15.5.24"


def _render(renderer, result):
    buffer = StringIO()
    from skylos.cli import _skylos_console_theme

    console = Console(
        file=buffer, width=160, force_terminal=False, theme=_skylos_console_theme()
    )
    renderer(console, result)
    return buffer.getvalue()


def _result():
    return {
        "analysis_summary": {"total_files": 1},
        "dependency_vulnerabilities": [*ADVISORIES, LICENSE],
    }


def test_rich_table_shows_one_row_per_package_and_keeps_licences():
    text = _render(render_results, _result())

    assert "by package" in text
    assert "16.1.2 (2 without a fix)" in text
    assert "6 advisories in 2 packages" in text
    assert "--format json" in text
    # Each advisory message is not printed as its own row.
    assert "advisory GHSA-n1" not in text
    assert "denied licence" in text


def test_pretty_output_shows_one_line_per_package():
    text = _render(render_pretty_results, _result())

    assert "next@16.0.10" in text
    assert "upgrade to 16.1.2" in text
    assert "advisory GHSA-n1" not in text
    assert "denied licence" in text


def test_result_is_not_modified_for_display():
    result = _result()
    _render(render_pretty_results, result)
    _render(render_results, result)

    assert len(result["dependency_vulnerabilities"]) == 7
