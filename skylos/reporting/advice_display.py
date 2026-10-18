"""Human-facing advice views; canonical findings and counts remain untouched."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from skylos.reporting.finding_types import (
    get_finding_type,
    iter_result_findings,
    summarize_finding_types,
)
from skylos.rules.catalog import get_rule_name


_COMPLEXITY_RULES = ("SKY-Q301", "SKY-Q306")
_METRIC_NAMES = {
    "SKY-Q301": "Cyclomatic complexity",
    "SKY-Q306": "Cognitive complexity",
}
_SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "WARN": 2,
    "WARNING": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass(frozen=True)
class ComplexityDisplay:
    """Two original checks represented by one human-facing function entry."""

    findings: tuple[dict, dict]

    @property
    def rule_ids(self) -> tuple[str, str]:
        return _COMPLEXITY_RULES

    @property
    def rule_label(self) -> str:
        return " + ".join(self.rule_ids)

    @property
    def name(self) -> str:
        return "Function complexity"

    @property
    def metric_lines(self) -> tuple[str, str]:
        return tuple(_metric_line(finding) for finding in self.findings)

    @property
    def message(self) -> str:
        lines = []
        for finding, metric_line in zip(self.findings, self.metric_lines):
            lines.append(metric_line)
            original = finding.get("message")
            if original:
                lines.append(str(original))
        return "\n".join(lines)


def _rule_id(finding: Mapping) -> str:
    return str(finding.get("rule_id") or finding.get("id") or "").upper()


def _metric_line(finding: dict) -> str:
    rule_id = _rule_id(finding)
    value = finding.get("value")
    if value is None:
        value = finding.get("complexity")
    threshold = finding.get("threshold")
    detail = _METRIC_NAMES[rule_id]
    if value is not None:
        detail += f": {value}"
    if threshold is not None:
        detail += f" (threshold: {threshold})"
    return f"{rule_id}: {detail}"


def complexity_display(item) -> ComplexityDisplay | None:
    """Return metadata created by this module, never an input JSON flag."""
    if isinstance(item, Mapping):
        display = item.get("_complexity_display")
        if isinstance(display, ComplexityDisplay):
            return display
    return None


def _complexity_identity(category, finding):
    if (
        category != "quality"
        or _rule_id(finding) not in _COMPLEXITY_RULES
        or get_finding_type(finding, category) != "advice"
        or complexity_display(finding) is not None
        or finding.get("type") not in (None, "function")
    ):
        return None
    file = finding.get("file") or finding.get("file_path")
    line = finding.get("line")
    name = next(
        (
            finding[field]
            for field in ("full_name", "symbol", "name", "simple_name")
            if finding.get(field)
        ),
        None,
    )
    if (
        not isinstance(file, str)
        or not file.strip()
        or not isinstance(line, int)
        or isinstance(line, bool)
        or line <= 0
        or not isinstance(name, str)
        or not name.strip()
        or name in {"<?>", "<module>", "anonymous", "<anonymous>"}
    ):
        return None
    column = finding.get("col", finding.get("column"))
    if column is not None and (
        not isinstance(column, int) or isinstance(column, bool) or column < 0
    ):
        return None
    language = finding.get("language")
    if language is not None and not isinstance(language, str):
        return None
    return file, line, name, column, language


def combine_complexity_advice(
    rows: Iterable[tuple[str, dict]],
) -> list[tuple[str, dict]]:
    """Pair unambiguous built-in complexity checks without changing raw records.

    Missing or conflicting identities, duplicate checks, and evidence variants
    remain individual entries. Both originals stay available on the display
    metadata, including when input order places the cognitive check first.
    """
    rows = list(rows)
    candidates = {}
    for index, (category, finding) in enumerate(rows):
        identity = _complexity_identity(category, finding)
        if identity is not None:
            candidates.setdefault(identity, []).append(index)

    replacements = {}
    consumed = set()
    for indices in candidates.values():
        if len(indices) != 2:
            continue
        by_rule = {_rule_id(rows[index][1]): index for index in indices}
        if len(by_rule) != 2:
            continue
        originals = tuple(rows[by_rule[rule]][1] for rule in _COMPLEXITY_RULES)
        metadata = ComplexityDisplay(originals)
        view = dict(originals[0])
        view["rule_id"] = _COMPLEXITY_RULES[0]
        view["_complexity_display"] = metadata
        view["message"] = metadata.message
        view["severity"] = min(
            (str(finding.get("severity") or "MEDIUM").upper() for finding in originals),
            key=lambda severity: _SEVERITY_RANK.get(severity, 99),
        )
        replacements[min(indices)] = ("quality", view)
        consumed.update(indices)

    return [
        replacements[index] if index in replacements else row
        for index, row in enumerate(rows)
        if index in replacements or index not in consumed
    ]


def group_advice_for_display(result) -> list[dict]:
    """Group human-facing entries, sharing one family for both complexity IDs."""
    rows = [
        finding
        for category, finding in combine_complexity_advice(iter_result_findings(result))
        if get_finding_type(finding, category) == "advice"
    ]
    complexity_rules = {
        rule
        for finding in rows
        for rule in (
            complexity_display(finding).rule_ids
            if complexity_display(finding)
            else (_rule_id(finding),)
        )
        if rule in _COMPLEXITY_RULES
    }
    share_complexity_family = complexity_rules == set(_COMPLEXITY_RULES)
    grouped = {}
    for finding in rows:
        rule = _rule_id(finding)
        family = share_complexity_family and rule in _COMPLEXITY_RULES
        key = _COMPLEXITY_RULES[0] if family else rule
        group = grouped.setdefault(
            key,
            {
                "rule_id": " + ".join(_COMPLEXITY_RULES) if family else rule,
                "name": "Function complexity"
                if family
                else get_rule_name(rule, "Maintainability advice"),
                "count": 0,
                "files": set(),
                "findings": [],
            },
        )
        group["count"] += 1
        file = finding.get("file") or finding.get("file_path")
        if file:
            group["files"].add(str(file))
        group["findings"].append(finding)
    for group in grouped.values():
        group["files"] = sorted(group["files"])
    return [grouped[key] for key in sorted(grouped)]


def advice_display_counts(result) -> dict[str, int]:
    """Return human-facing counts alongside the unchanged raw advice total."""
    counts = summarize_finding_types(result)
    counts["raw_advice"] = counts["advice"]
    counts["advice"] = sum(
        get_finding_type(finding, category) == "advice"
        for category, finding in combine_complexity_advice(iter_result_findings(result))
    )
    counts["advice_groups"] = len(group_advice_for_display(result))
    return counts
