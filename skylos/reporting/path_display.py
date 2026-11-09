"""Display related checks for one filesystem operation together.

Raw JSON, SARIF, listing and gate inputs retain every original finding.
"""

from collections import defaultdict

_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}
_SEVERITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


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
