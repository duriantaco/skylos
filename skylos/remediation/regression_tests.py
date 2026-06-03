from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SQL_INJECTION_RULE_ID = "SKY-D211"
SQL_INJECTION_FAMILY = "sql_injection"


@dataclass(frozen=True)
class RegressionTestCandidate:
    rule_id: str
    family: str
    source_file: str
    test_file: str
    description: str
    content: str

    def to_summary(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "family": self.family,
            "source_file": self.source_file,
            "test_file": self.test_file,
            "description": self.description,
        }


def generate_regression_test_candidate(
    finding: Any,
    project_root: str | Path,
) -> RegressionTestCandidate | None:
    rule_id = _finding_rule_id(finding)
    if rule_id != SQL_INJECTION_RULE_ID:
        return None

    root = _resolved_root(project_root)
    if root is None:
        return None

    source_path = _source_path_for_finding(finding, root)
    if source_path is None:
        return None

    relative_source = _relative_source_path(source_path, root)
    if relative_source is None:
        return None

    test_dir = _existing_test_dir(root)
    if test_dir is None:
        return None

    test_path = _candidate_test_path(test_dir, relative_source)
    relative_test = _relative_source_path(test_path, root)
    if relative_test is None:
        return None

    description = _description_for_finding(finding, relative_source)
    content = _render_sql_injection_test(relative_source, test_path)

    return RegressionTestCandidate(
        rule_id=SQL_INJECTION_RULE_ID,
        family=SQL_INJECTION_FAMILY,
        source_file=relative_source.as_posix(),
        test_file=relative_test.as_posix(),
        description=description,
        content=content,
    )


def _resolved_root(project_root: str | Path) -> Path | None:
    try:
        root = Path(project_root).resolve(strict=True)
    except OSError:
        return None
    if not root.is_dir():
        return None
    return root


def _finding_value(finding: Any, key: str) -> Any:
    if isinstance(finding, dict):
        return finding.get(key)
    return getattr(finding, key, None)


def _finding_rule_id(finding: Any) -> str:
    value = _finding_value(finding, "rule_id")
    if not isinstance(value, str):
        return ""
    return value


def _finding_line(finding: Any) -> int:
    value = _finding_value(finding, "line")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _source_path_for_finding(finding: Any, root: Path) -> Path | None:
    value = _finding_value(finding, "file")
    if not isinstance(value, str):
        return None
    if not value.strip():
        return None

    raw = Path(value)
    if raw.is_absolute():
        candidate = raw
    else:
        candidate = root / raw

    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None

    if resolved.suffix != ".py":
        return None

    try:
        resolved.relative_to(root)
    except ValueError:
        return None

    if not resolved.is_file():
        return None

    return resolved


def _relative_source_path(path: Path, root: Path) -> Path | None:
    try:
        return path.relative_to(root)
    except ValueError:
        return None


def _existing_test_dir(root: Path) -> Path | None:
    for name in ("tests", "test"):
        candidate = root / name
        if candidate.is_symlink():
            continue
        if candidate.is_dir():
            return candidate
    return None


def _candidate_test_path(test_dir: Path, relative_source: Path) -> Path:
    source_name = relative_source.as_posix()
    digest = hashlib.sha256(source_name.encode("utf-8")).hexdigest()[:10]
    slug = _slug_source_name(source_name)
    filename = f"test_skylos_sqli_{slug}_{digest}.py"
    return test_dir / filename


def _slug_source_name(source_name: str) -> str:
    parts: list[str] = []
    previous_underscore = False
    for char in source_name:
        if char.isalnum():
            parts.append(char.lower())
            previous_underscore = False
            continue
        if previous_underscore:
            continue
        parts.append("_")
        previous_underscore = True

    slug = "".join(parts).strip("_")
    if not slug:
        slug = "target"
    if len(slug) > 48:
        slug = slug[:48].rstrip("_")
    if not slug:
        slug = "target"
    return slug


def _description_for_finding(finding: Any, relative_source: Path) -> str:
    line = _finding_line(finding)
    source_name = relative_source.as_posix()
    if line > 0:
        return (
            f"Regression proof that {SQL_INJECTION_RULE_ID} stays closed in "
            f"{source_name} after line {line} remediation."
        )
    return (
        f"Regression proof that {SQL_INJECTION_RULE_ID} stays closed in "
        f"{source_name}."
    )


def _render_sql_injection_test(relative_source: Path, test_path: Path) -> str:
    source_literal = json.dumps(relative_source.as_posix())
    suffix = _test_function_suffix(test_path)
    return f'''from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze


def test_sky_d211_sql_injection_regression_{suffix}():
    root = Path(__file__).resolve().parents[1]
    target = root / {source_literal}
    raw = analyze(
        str(target),
        conf=0,
        enable_danger=True,
        enable_quality=False,
        enable_secrets=False,
    )
    if isinstance(raw, str):
        result = json.loads(raw)
    else:
        result = raw

    danger = result.get("danger")
    if not isinstance(danger, list):
        danger = []

    remaining = []
    for finding in danger:
        if not isinstance(finding, dict):
            continue
        rule_id = finding.get("rule_id")
        if rule_id == "SKY-D211":
            remaining.append(finding)

    assert not remaining, "SKY-D211 SQL injection regression still present"
'''


def _test_function_suffix(test_path: Path) -> str:
    stem = test_path.stem
    if stem.startswith("test_"):
        stem = stem[5:]
    suffix = _slug_source_name(stem)
    if suffix[0].isdigit():
        suffix = f"case_{suffix}"
    return suffix
