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
_FUNCTION_RULES = (*_COMPLEXITY_RULES, "SKY-C304", "SKY-Q302", "SKY-L028")
_ARCHITECTURE_RULES = ("SKY-Q802", "SKY-Q803")
_METRIC_NAMES = {
    "SKY-Q301": "Cyclomatic complexity",
    "SKY-Q306": "Cognitive complexity",
    "SKY-C304": "Code lines",
    "SKY-Q302": "Maximum nesting",
    "SKY-L028": "Return statements",
    "SKY-Q802": "Distance from main sequence",
    "SKY-Q803": "Architecture zone",
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
_UNKNOWN_NAMES = {"<?>", "<module>", "anonymous", "<anonymous>"}
ADVICE_PRIORITY_NOTE = (
    "Advice priority is capped at MEDIUM; original severities remain in JSON and gates."
)


@dataclass(frozen=True)
class ComplexityDisplay:
    """Original advice signals represented by one human-facing entry.

    The historical class name remains available to existing renderers. Every
    original record, including its evidence and extra metrics, is retained.
    """

    findings: tuple[dict, ...]

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(_rule_id(finding) for finding in self.findings)

    @property
    def rule_label(self) -> str:
        return " + ".join(self.rule_ids)

    @property
    def name(self) -> str:
        return _family_name(self.rule_ids)

    @property
    def metric_lines(self) -> tuple[str, ...]:
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


def _family_name(rule_ids) -> str:
    if set(rule_ids).issubset(_ARCHITECTURE_RULES):
        return "Module architecture"
    if tuple(rule_ids) == _COMPLEXITY_RULES:
        return "Function complexity"
    return "Function maintainability"


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


def advice_priority(finding: Mapping, category=None) -> str:
    """Human advice priority; original severity remains evidence and gate input."""
    severity = str(finding.get("severity") or "MEDIUM").strip().upper()
    if (
        category in (None, "quality")
        and get_finding_type(finding, category) == "advice"
        and severity in {"HIGH", "CRITICAL"}
    ):
        return "MEDIUM"
    return severity


def _compatible_names(names) -> bool:
    """Permit a bare name alongside its qualification, never conflicting names."""
    return all(
        left == right or left.endswith(f".{right}") or right.endswith(f".{left}")
        for left in names
        for right in names
    )


def _advice_identity(category, finding):
    rule_id = _rule_id(finding)
    family = (
        _FUNCTION_RULES
        if rule_id in _FUNCTION_RULES
        else _ARCHITECTURE_RULES
        if rule_id in _ARCHITECTURE_RULES
        else None
    )
    if (
        category != "quality"
        or family is None
        or get_finding_type(finding, category) != "advice"
        or complexity_display(finding) is not None
        or finding.get("type")
        not in (None, "function" if family == _FUNCTION_RULES else "module")
    ):
        return None
    files = [finding[field] for field in ("file", "file_path") if finding.get(field)]
    line = finding.get("line")
    names = [
        finding[field]
        for field in ("full_name", "symbol", "name", "simple_name")
        if finding.get(field)
    ]
    if (
        not files
        or any(not isinstance(file, str) or not file.strip() for file in files)
        or len(set(files)) != 1
        or not isinstance(line, int)
        or isinstance(line, bool)
        or line <= 0
        or not names
        or any(
            not isinstance(name, str) or not name.strip() or name in _UNKNOWN_NAMES
            for name in names
        )
        or not _compatible_names(names)
    ):
        return None
    columns = [
        finding[field] for field in ("col", "column") if finding.get(field) is not None
    ]
    if (
        any(
            not isinstance(column, int) or isinstance(column, bool) or column < 0
            for column in columns
        )
        or len(set(columns)) > 1
    ):
        return None
    language = finding.get("language")
    if language is not None and not isinstance(language, str):
        return None
    return (family, files[0], line), (names, columns, language)


def combine_complexity_advice(
    rows: Iterable[tuple[str, dict]],
) -> list[tuple[str, dict]]:
    """Combine unambiguous function or module advice for human display only.

    A missing optional column/language can join agreeing known values. Conflicts
    anywhere at the same location, duplicate checks, and evidence variants leave
    the entire candidate group separate. Originals remain on display metadata.
    """
    rows = list(rows)
    candidates = {}
    for index, (category, finding) in enumerate(rows):
        identity = _advice_identity(category, finding)
        if identity is not None:
            location, details = identity
            candidates.setdefault(location, []).append((index, details))

    replacements = {}
    consumed = set()
    for (family, _file, _line), candidates_at_location in candidates.items():
        indices = [index for index, _details in candidates_at_location]
        if len(indices) < 2:
            continue
        by_rule = {_rule_id(rows[index][1]): index for index in indices}
        if len(by_rule) != len(indices):
            continue
        names = [
            name
            for _index, (names, _columns, _language) in candidates_at_location
            for name in names
        ]
        columns = {
            column
            for _index, (_names, columns, _language) in candidates_at_location
            for column in columns
        }
        languages = {
            language
            for _index, (_names, _columns, language) in candidates_at_location
            if language is not None
        }
        if not _compatible_names(names) or len(columns) > 1 or len(languages) > 1:
            continue
        originals = tuple(rows[by_rule[rule]][1] for rule in family if rule in by_rule)
        metadata = ComplexityDisplay(originals)
        view = dict(originals[0])
        view["rule_id"] = metadata.rule_ids[0]
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


def standalone_function_advice(rows) -> set[int]:
    """Identify unambiguous size-only signals without dropping metric groups.

    Missing identities, conflicting measurements and duplicate variants remain
    visible. A second function metric corroborates a measurement even when it
    is not a complexity rule; existing combined entries retain every member.
    """
    locations = {}
    uncertain = set()
    for category, finding in rows:
        identity = _advice_identity(category, finding)
        if identity is not None:
            location, _details = identity
            locations.setdefault(location, []).append(finding)
        elif (
            category == "quality"
            and _rule_id(finding) in _FUNCTION_RULES
            and get_finding_type(finding, category) == "advice"
        ):
            line = finding.get("line")
            if type(line) is int and line > 0:
                for field in ("file", "file_path"):
                    file = finding.get(field)
                    if isinstance(file, str) and file:
                        uncertain.add((_FUNCTION_RULES, file, line))
    return {
        id(findings[0])
        for location, findings in locations.items()
        if location not in uncertain
        and len(findings) == 1
        and _rule_id(findings[0]) in {"SKY-C304", "SKY-Q302", "SKY-L028"}
    }


# Generic spellings for new callers; historical imports remain compatible.
AdviceDisplay = ComplexityDisplay
advice_display = complexity_display
combine_advice = combine_complexity_advice


def group_advice_for_display(result) -> list[dict]:
    """Group human entries by advice family while retaining every original."""
    rows = [
        finding
        for category, finding in combine_complexity_advice(iter_result_findings(result))
        if get_finding_type(finding, category) == "advice"
    ]
    present_rules = {
        rule
        for finding in rows
        for rule in (
            complexity_display(finding).rule_ids
            if complexity_display(finding)
            else (_rule_id(finding),)
        )
    }
    families = [
        tuple(rule for rule in family if rule in present_rules)
        for family in (_FUNCTION_RULES, _ARCHITECTURE_RULES)
    ]
    shared = {rule: family for family in families if len(family) > 1 for rule in family}
    grouped = {}
    for finding in rows:
        rule = _rule_id(finding)
        family = shared.get(rule)
        key = family[0] if family else rule
        group = grouped.setdefault(
            key,
            {
                "rule_id": " + ".join(family) if family else rule,
                "name": _family_name(family)
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
