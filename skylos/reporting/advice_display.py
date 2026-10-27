"""Human-facing advice views; canonical findings and counts remain untouched."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from skylos.reporting.finding_types import (
    get_finding_type,
    iter_result_findings,
    summarize_finding_types,
)
from skylos.rules.catalog import get_rule_name


_COMPLEXITY_RULES = ("SKY-Q301", "SKY-Q306")
_FUNCTION_RULES = (*_COMPLEXITY_RULES, "SKY-C304", "SKY-Q302", "SKY-L028")
_ARCHITECTURE_RULES = ("SKY-Q802", "SKY-Q803")
_TYPING_RULES = ("SKY-T101", "SKY-T102")
_METRIC_NAMES = {
    "SKY-Q301": "Cyclomatic complexity",
    "SKY-Q306": "Cognitive complexity",
    "SKY-C304": "Code lines",
    "SKY-Q302": "Maximum nesting",
    "SKY-L028": "Return statements",
    "SKY-Q802": "Distance from main sequence",
    "SKY-Q803": "Architecture zone",
}
SEVERITY_RANK = {
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
    primary_line: int | None = None

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(_rule_id(finding) for finding in self.findings))

    @property
    def rule_label(self) -> str:
        return " + ".join(self.rule_ids)

    @property
    def name(self) -> str:
        if self.primary_line is not None:
            return "Function maintainability including nested scopes"
        return _family_name(self.rule_ids)

    @property
    def metric_lines(self) -> tuple[str, ...]:
        return tuple(
            (
                f"Nested {finding.get('simple_name') or finding.get('name')} "
                f"at line {finding['line']}: {_metric_line(finding)}"
                if self.primary_line is not None
                and finding.get("line") != self.primary_line
                else _metric_line(finding)
            )
            for finding in self.findings
        )

    @property
    def message(self) -> str:
        lines = []
        for finding, metric_line in zip(self.findings, self.metric_lines):
            lines.append(metric_line)
            original = finding.get("message")
            if original:
                lines.append(str(original))
        return "\n".join(lines)


@dataclass(frozen=True)
class FileAnnotationDisplay(ComplexityDisplay):
    """Missing-annotation advice for one file: one entry, every line kept."""

    @property
    def name(self) -> str:
        return "Missing type annotations"

    @property
    def metric_lines(self) -> tuple[str, ...]:
        return tuple(
            f"Line {finding.get('line')}: {finding.get('message') or _rule_id(finding)}"
            for finding in self.findings
        )

    @property
    def message(self) -> str:
        count = len({finding.get("line") for finding in self.findings})
        noun = "function" if count == 1 else "functions"
        return "\n".join(
            (f"{count} {noun} in this file miss annotations.", *self.metric_lines)
        )


def _rule_id(finding: Mapping) -> str:
    return str(finding.get("rule_id") or finding.get("id") or "").upper()


def _family_name(rule_ids) -> str:
    if set(rule_ids).issubset(_TYPING_RULES):
        return "Function annotations"
    if set(rule_ids).issubset(_ARCHITECTURE_RULES):
        return "Module architecture"
    if tuple(rule_ids) == _COMPLEXITY_RULES:
        return "Function complexity"
    return "Function maintainability"


def _metric_line(finding: dict) -> str:
    rule_id = _rule_id(finding)
    if rule_id == "SKY-T101":
        return f"{rule_id}: Untyped parameters: {finding.get('value', '')}"
    if rule_id == "SKY-T102":
        return f"{rule_id}: Missing return annotation"
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


def default_display_severity(section) -> str:
    """Severity reports show for a record of this result section without one."""
    if section in {
        "analysis_errors",
        "danger",
        "secrets",
        "dependency_vulnerabilities",
    }:
        return "HIGH"
    if str(section or "").startswith("unused_"):
        return "LOW"
    return "MEDIUM"


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
        else _TYPING_RULES
        if rule_id in _TYPING_RULES
        else None
    )
    if (
        category != "quality"
        or family is None
        or get_finding_type(finding, category) != "advice"
        or complexity_display(finding) is not None
        or finding.get("type")
        not in (None, "module" if family == _ARCHITECTURE_RULES else "function")
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


def same_location_advice_groups(rows) -> list[list[int]]:
    """Indices of advice signals one entry can stand for, each group in
    rule-family order: two or more different checks at the same function or
    module location, with agreeing names, column and language. Duplicate
    checks and conflicting details at a location leave it ungrouped."""
    candidates = {}
    for index, (category, finding) in enumerate(rows):
        identity = _advice_identity(category, finding)
        if identity is not None:
            location, details = identity
            candidates.setdefault(location, []).append((index, details))

    groups = []
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
        group = []
        for rule in family:
            if rule in by_rule:
                group.append(by_rule[rule])
        groups.append(group)
    return groups


def combine_complexity_advice(
    rows: Iterable[tuple[str, dict]],
) -> list[tuple[str, dict]]:
    """Combine unambiguous function or module advice for human display only.

    A missing optional column/language can join agreeing known values. Conflicts
    anywhere at the same location, duplicate checks, and evidence variants leave
    the entire candidate group separate. Originals remain on display metadata.
    """
    rows = list(rows)
    replacements = {}
    consumed = set()
    for indices in same_location_advice_groups(rows):
        originals = tuple(rows[index][1] for index in indices)
        metadata = ComplexityDisplay(originals)
        view = dict(originals[0])
        view["rule_id"] = metadata.rule_ids[0]
        view["_complexity_display"] = metadata
        view["message"] = metadata.message
        view["severity"] = min(
            (str(finding.get("severity") or "MEDIUM").upper() for finding in originals),
            key=lambda severity: SEVERITY_RANK.get(severity, 99),
        )
        replacements[min(indices)] = ("quality", view)
        consumed.update(indices)

    grouped = [
        replacements[index] if index in replacements else row
        for index, row in enumerate(rows)
        if index in replacements or index not in consumed
    ]
    return _combine_file_annotations(_combine_included_cognitive_scopes(grouped))


def _annotation_file(category, finding) -> str | None:
    if (
        category != "quality"
        or not isinstance(finding, Mapping)
    ):
        return None
    display = complexity_display(finding)
    members = display.findings if display is not None else (finding,)
    if not members:
        return None
    member_files = set()
    for member in members:
        if (
            not isinstance(member, Mapping)
            or _rule_id(member) not in _TYPING_RULES
            or get_finding_type(member, category) != "advice"
            or complexity_display(member) is not None
        ):
            return None
        files = [member[field] for field in ("file", "file_path") if member.get(field)]
        line = member.get("line")
        if (
            not files
            or any(not isinstance(file, str) or not file.strip() for file in files)
            or len(set(files)) != 1
            or type(line) is not int
            or line <= 0
        ):
            return None
        member_files.add(files[0])
    return next(iter(member_files)) if len(member_files) == 1 else None


def _combine_file_annotations(rows):
    """One missing-annotation entry per file; each function stays a member.

    Annotation advice is per function but read per file: fixing it means
    working through one module. Unknown files or lines stay separate.
    """
    by_file = {}
    for index, (category, finding) in enumerate(rows):
        file = _annotation_file(category, finding)
        if file is not None:
            by_file.setdefault(file, []).append(index)
    replacements = {}
    consumed = set()
    for file, indices in by_file.items():
        if len(indices) < 2:
            continue
        members = tuple(
            sorted(
                (
                    member
                    for index in indices
                    for member in (
                        complexity_display(rows[index][1]).findings
                        if complexity_display(rows[index][1]) is not None
                        else (rows[index][1],)
                    )
                ),
                key=lambda finding: (finding["line"], _rule_id(finding)),
            )
        )
        display = FileAnnotationDisplay(members)
        view = dict(members[0])
        view["_complexity_display"] = display
        view["message"] = display.message
        view["name"] = view["simple_name"] = Path(file).name
        view["severity"] = min(
            (str(finding.get("severity") or "LOW").upper() for finding in members),
            key=lambda severity: SEVERITY_RANK.get(severity, 99),
        )
        replacements[min(indices)] = ("quality", view)
        consumed.update(indices)
    if not replacements:
        return rows
    return [
        replacements[index] if index in replacements else row
        for index, row in enumerate(rows)
        if index in replacements or index not in consumed
    ]


def _cognitive_scope(finding):
    """Validate the analyzer's additive, source-owned score decomposition."""
    scope = finding.get("cognitive_scope")
    line = finding.get("line")
    value = finding.get("value")
    if (
        not isinstance(scope, Mapping)
        or type(scope.get("version")) is not int
        or scope["version"] != 1
        or type(line) is not int
        or line < 1
        or type(value) is not int
        or value < 1
        or type(scope.get("end_line")) is not int
        or scope["end_line"] < line
        or type(scope.get("own_score")) is not int
        or scope["own_score"] < 0
        or not isinstance(scope.get("nested_contributions"), list)
    ):
        return None
    owners = {}
    for owner in scope["nested_contributions"]:
        if (
            not isinstance(owner, Mapping)
            or any(type(owner.get(key)) is not int for key in ("line", "end_line", "score"))
            or not line <= owner["line"] <= owner["end_line"] <= scope["end_line"]
            or owner["score"] < 0
            or not isinstance(owner.get("name"), str)
            or not owner["name"]
            or not isinstance(owner.get("kind"), str)
            or owner.get("kind") not in {"FunctionDef", "AsyncFunctionDef", "ClassDef", "Lambda"}
        ):
            return None
        key = (owner["line"], owner["end_line"], owner["name"], owner["kind"])
        if key in owners:
            return None
        owners[key] = owner["score"]
    if scope["own_score"] + sum(owners.values()) != value:
        return None
    return scope, owners


def _includes_cognitive_scope(parent, child):
    parent_proof = _cognitive_scope(parent)
    child_proof = _cognitive_scope(child)
    if parent_proof is None or child_proof is None:
        return False
    parent_scope, parent_owners = parent_proof
    child_scope, child_owners = child_proof
    containing = child_scope.get("containing_function")
    parent_name = parent.get("simple_name") or str(parent.get("name", "")).rsplit(".", 1)[-1]
    child_name = child.get("simple_name") or str(child.get("name", "")).rsplit(".", 1)[-1]
    if (
        not isinstance(containing, Mapping)
        or (
            parent.get("language") is not None
            and child.get("language") is not None
            and parent["language"] != child["language"]
        )
        or containing.get("name") != parent_name
        or type(containing.get("line")) is not int
        or containing["line"] != parent["line"]
        or not parent["line"] < child["line"] <= child_scope["end_line"] <= parent_scope["end_line"]
    ):
        return False
    # Parent and child scores use different nesting contexts. Check each
    # source owner, rather than assuming that two similar totals overlap.
    for key, score in child_owners.items():
        if parent_owners.get(key, -1) < score:
            return False
    if child_scope["own_score"]:
        matches = [
            score for (line, end, name, kind), score in parent_owners.items()
            if (line, end, name) == (child["line"], child_scope["end_line"], child_name)
            and kind in {"FunctionDef", "AsyncFunctionDef"}
        ]
        if len(matches) != 1 or matches[0] < child_scope["own_score"]:
            return False
    return True


def _combine_included_cognitive_scopes(rows):
    """Present nested checks together only when their scores really overlap.

    Cognitive complexity includes nested bodies. Separate findings on those
    same bodies are related evidence, not independent corroboration. Keep all
    child measurements and locations under the enclosing entry. An absent,
    suppressed, conflicting or unproven parent leaves the child independent.
    """
    originals = []
    candidates = {}
    uncertain = set()
    for index, (category, finding) in enumerate(rows):
        display = complexity_display(finding)
        members = display.findings if display else (finding,)
        originals.append(members)
        if category != "quality":
            continue
        for member in members:
            if _rule_id(member) != "SKY-Q306":
                continue
            if _advice_identity(category, member) is None:
                line = member.get("line")
                if get_finding_type(member, category) == "advice" and type(line) is int and line > 0:
                    for field in ("file", "file_path"):
                        file = member.get(field)
                        if isinstance(file, str) and file:
                            uncertain.add((file, line))
                continue
            key = (member.get("file") or member.get("file_path"), member["line"])
            candidates.setdefault(key, []).append((index, member))
    unique = {
        key: values[0] for key, values in candidates.items()
        if len(values) == 1 and key not in uncertain
    }
    parents = {}
    for (file, _line), (index, child) in unique.items():
        scope = child.get("cognitive_scope")
        containing = scope.get("containing_function") if isinstance(scope, Mapping) else None
        if not isinstance(containing, Mapping) or type(containing.get("line")) is not int:
            continue
        parent = unique.get((file, containing["line"]))
        if parent is None or parent[0] == index or not _includes_cognitive_scope(parent[1], child):
            continue
        # A previously grouped component can carry several cognitive records;
        # contradictory ownership for one entry must not combine components.
        if index in parents and parents[index] != parent[0]:
            parents[index] = None
        else:
            parents[index] = parent[0]
    parents = {child: parent for child, parent in parents.items() if parent is not None}
    components = {}
    for index in range(len(rows)):
        root = index
        seen = set()
        while root in parents and root not in seen:
            seen.add(root)
            root = parents[root]
        if root in seen:  # Defensive: valid lexical source spans cannot cycle.
            return rows
        components.setdefault(root, []).append(index)
    if all(len(indices) == 1 for indices in components.values()):
        return rows
    replacements = {}
    consumed = set()
    for root, indices in components.items():
        if len(indices) == 1:
            continue
        members = tuple(
            member for index in (root, *(i for i in indices if i != root))
            for member in originals[index]
        )
        view = dict(rows[root][1])
        display = ComplexityDisplay(members, primary_line=view["line"])
        view["_complexity_display"] = display
        view["message"] = display.message
        replacements[root] = ("quality", view)
        consumed.update(indices)
    return [
        replacements[index] if index in replacements else row
        for index, row in enumerate(rows)
        if index in replacements or index not in consumed
    ]


def standalone_function_advice(rows) -> dict[tuple, dict]:
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
        location: findings[0]
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
        for family in (_FUNCTION_RULES, _ARCHITECTURE_RULES, _TYPING_RULES)
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
