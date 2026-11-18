"""Display related checks for one filesystem operation together.

Raw JSON, SARIF, listing and gate inputs retain every original finding.
"""

from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

from skylos.cicd.evidence import sanitize_untrusted_text

_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}
_SEVERITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_REVIEW_STATUSES = {"unknown", "incomplete"}
_MAX_REVIEW_EXAMPLES = 3


def _review_text(value, *, limit=300):
    return sanitize_untrusted_text(value, max_length=limit, neutralize_mentions=False)


def path_review_summary(findings):
    """Describe unresolved reported paths without changing any finding or gate.

    This receipt covers only findings present in the report. A zero count does
    not establish complete caller coverage or prove all filesystem paths safe.
    Full recorded chains remain on each finding's ``metadata.path_provenance``.
    """
    statuses = {"unknown": 0, "incomplete": 0}
    by_rule = defaultdict(int)
    examples = []
    for row in findings or ():
        if not isinstance(row, Mapping):
            continue
        rule_id = row.get("rule_id")
        if not isinstance(rule_id, str) or rule_id not in _RULES:
            continue
        metadata = row.get("metadata")
        provenance = (
            metadata.get("path_provenance") if isinstance(metadata, Mapping) else None
        )
        if not isinstance(provenance, Mapping):
            continue
        status = provenance.get("status")
        if not isinstance(status, str) or status not in _REVIEW_STATUSES:
            continue
        statuses[status] += 1
        by_rule[rule_id] += 1
        if len(examples) >= _MAX_REVIEW_EXAMPLES:
            continue
        reason = "The caller or input source could not be established."
        chains = provenance.get(status)
        if isinstance(chains, list):
            for chain in chains[:4]:
                if isinstance(chain, list) and chain and isinstance(chain[0], str):
                    reason = chain[0]
                    break
        if status == "incomplete" and reason.startswith("The caller"):
            reason = "Analysis stopped before every caller chain could be followed."
        example = {
            "rule_id": rule_id,
            "file": _review_text(row.get("file") or row.get("file_path") or "?"),
            "status": status,
            "reason": _review_text(reason),
        }
        line = row.get("line")
        if isinstance(line, int) and not isinstance(line, bool) and line > 0:
            example["line"] = line
        examples.append(example)
    return {
        "version": 1,
        "unresolved_count": sum(statuses.values()),
        "by_status": statuses,
        "by_rule": dict(sorted(by_rule.items())),
        "examples": examples,
        "scope": "Reported path findings only; unresolved evidence is not proof of safety.",
    }


def path_review_lines(result, *, root_path=None):
    """A small review summary, followed by bounded locations and trace gaps."""
    findings = result.get("danger") if isinstance(result, Mapping) else None
    summary = path_review_summary(findings)
    count = summary["unresolved_count"]
    if not count:
        return []
    noun = "finding needs" if count == 1 else "findings need"
    statuses = summary["by_status"]
    lines = [
        f"{count} path {noun} review: caller/source unresolved; safety is not established.",
        (
            f"Unknown sources or callers ({statuses['unknown']}) · "
            f"Incomplete traces ({statuses['incomplete']}). Exploitability remains unconfirmed."
        ),
    ]
    for example in summary["examples"]:
        file = example["file"]
        if root_path is not None:
            try:
                file = str(Path(file).relative_to(Path(root_path)))
            except (TypeError, ValueError):
                pass
        location = file
        if example.get("line"):
            location += f":{example['line']}"
        lines.append(f"{example['rule_id']} {location}: {example['reason']}")
    lines.append(
        "These findings remain reported. Full caller/source evidence is in "
        "metadata.path_provenance with --format json."
    )
    return lines


def group_path_checks(rows):
    rows = list(rows)
    groups = defaultdict(list)
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("rule_id") not in _RULES:
            continue
        file = row.get("file") or row.get("file_path")
        line, col = row.get("line"), row.get("col")
        if not file or type(line) is not int or type(col) is not int:
            continue
        metadata = row.get("metadata") or {}
        operand = metadata.get("path_operand") if isinstance(metadata, dict) else None
        groups[(str(file), line, col, row.get("symbol"), repr(operand))].append(index)

    replacements, combined = {}, set()
    for indices in groups.values():
        rules = {rows[i]["rule_id"] for i in indices}
        # Same-rule variants may have different evidence; do not merge them.
        if len(rules) < 2 or len(rules) != len(indices):
            continue
        lead = min(
            indices,
            key=lambda i: (
                _SEVERITY.get(str(rows[i].get("severity")).upper(), 99),
                rows[i]["rule_id"],
            ),
        )
        replacements[indices[0]] = {
            **rows[lead],
            "_path_checks": [rows[i] for i in indices],
        }
        combined.update(indices[1:])
    return [replacements.get(i, row) for i, row in enumerate(rows) if i not in combined]


def path_rule_label(row):
    checks = row.get("_path_checks")
    if not checks:
        return None
    return ", ".join(check["rule_id"] for check in checks)


def path_check_details(row):
    return [
        f"{check['rule_id']}: {check.get('message', '')}"
        for check in row.get("_path_checks", ())
        if check["rule_id"] != row["rule_id"]
    ]
