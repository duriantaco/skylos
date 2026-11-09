"""What a scan reports, after analysis: generated files, test code, severity.

These adjustments run before the grade and directory rollups are computed, so
counts, grades and gates describe exactly what is reported:

* findings located in files the scan treats as generated (Django migrations)
  are not reported, except security, reliability, secret and custom-rule
  findings (see ``skylos.core.generated_files``);
* performance advice is not reported in test code: the cost it describes is
  paid in production. Test code is judged by its path, which is enough for
  advice but never proves code is not shipped (production can import a module
  under ``tests/``), so every security rule still applies in test code;
* CRITICAL is reserved for issues in shipped code: a CRITICAL finding in a
  test file is reported as HIGH, except secrets, which leak wherever they are
  committed;
* ``exec``/``eval`` (reported for every call, with no source evidence) is
  MEDIUM in a module proved to be test-only: pytest or unittest would collect
  it and no non-test module imports it. It stays reported and listed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from skylos.constants import get_non_library_dir_kind
from skylos.core.generated_files import (
    REPORT_ONLY_DROPPED_SECTIONS,
    finding_in_files,
)
from skylos.core.test_paths import is_test_code_path

_SUMMARY_COUNT_KEYS = {
    "quality": "quality_count",
    "ai_defects": "ai_defects_count",
    "danger": "danger_count",
    "reliability": "reliability_count",
    "custom_rules": "custom_rules_count",
    "unused_files": "unused_files_count",
    "unused_exports": "unused_exports_count",
}
TEST_FILE_CAPPED_SECTIONS = (
    "danger",
    "reliability",
    "quality",
    "ai_defects",
    "custom_rules",
)
TEST_FILE_SEVERITY_CAP = "HIGH"
TEST_ONLY_CODE_EXECUTION_RULES = frozenset({"SKY-D201", "SKY-D202"})
TEST_ONLY_CODE_EXECUTION_SEVERITY = "MEDIUM"
TEST_CODE_NOT_APPLICABLE_RULES = frozenset(
    {"SKY-P401", "SKY-P402", "SKY-P403", "SKY-P404", "SKY-Q402"}
)
_TEST_CODE_RULE_SECTIONS = ("quality",)


def report_only_file_keys(analyzer) -> frozenset[str]:
    scope = getattr(analyzer, "_generated_file_scope", None)
    if scope is None:
        return frozenset()
    return scope.report_only_keys()


def without_report_only_files(items, file_keys: frozenset[str]) -> list:
    if not file_keys:
        return list(items or [])
    return [item for item in items or [] if not finding_in_files(item, file_keys)]


def apply_report_scope(
    result: dict, analyzer, *, modmap=None, raw_imports=None
) -> None:
    summary = result.setdefault("analysis_summary", {})
    changed_sections: set[str] = set()

    scope = getattr(analyzer, "_generated_file_scope", None)
    if scope is not None:
        file_keys = scope.report_only_keys()
        not_reported = 0
        for section in REPORT_ONLY_DROPPED_SECTIONS:
            items = result.get(section)
            if not isinstance(items, list) or not items:
                continue
            kept = without_report_only_files(items, file_keys)
            if len(kept) != len(items):
                not_reported += len(items) - len(kept)
                result[section] = kept
                changed_sections.add(section)
        generated_summary = scope.summary()
        generated_summary["findings_not_reported"] = not_reported
        summary["generated_files"] = generated_summary

    project_root = getattr(analyzer, "_project_root", None)
    not_applicable = drop_test_code_not_applicable(result, project_root)
    if not_applicable:
        summary["test_code_not_applicable"] = sum(not_applicable.values())
        changed_sections.update(not_applicable)

    capped = cap_test_file_severity(result, project_root)
    if capped:
        summary["test_file_severity_capped"] = capped
    lowered = cap_test_only_code_execution(
        result,
        project_root,
        modmap=modmap,
        raw_imports=raw_imports,
        analyzer=analyzer,
    )
    if lowered:
        summary["test_only_code_execution_lowered"] = lowered

    bare_noqa = count_bare_noqa_security_findings(result)
    if bare_noqa:
        summary["bare_noqa_security_findings"] = bare_noqa

    for section in changed_sections:
        count_key = _SUMMARY_COUNT_KEYS.get(section)
        if count_key and (count_key in summary or result.get(section)):
            summary[count_key] = len(result.get(section) or [])


_BARE_NOQA_SECTIONS = ("danger", "secrets", "ai_defects", "quality")


def count_bare_noqa_security_findings(result: dict) -> int:
    """HIGH/CRITICAL security findings that sit on a bare ``# noqa``, which
    no longer hides them (``skylos.analysis.finding_filter``)."""
    return sum(
        1
        for section in _BARE_NOQA_SECTIONS
        for finding in result.get(section) or []
        if isinstance(finding, dict) and finding.get("bare_noqa_ignored")
    )


def drop_test_code_not_applicable(result: dict, project_root=None) -> dict[str, int]:
    """Remove TEST_CODE_NOT_APPLICABLE_RULES findings located in test code;
    return how many per section.

    Test code is judged relative to the project root by language convention
    (``is_test_code_path``); repository config cannot relabel shipped code.
    Without a root, an absolute path is never treated as test code.
    """
    dropped: dict[str, int] = {}
    for section in _TEST_CODE_RULE_SECTIONS:
        items = result.get(section)
        if not isinstance(items, list) or not items:
            continue
        kept = []
        for finding in items:
            if (
                isinstance(finding, dict)
                and finding.get("rule_id") in TEST_CODE_NOT_APPLICABLE_RULES
                and is_test_code_path(
                    finding.get("file") or finding.get("file_path"), project_root
                )
            ):
                continue
            kept.append(finding)
        if len(kept) != len(items):
            dropped[section] = len(items) - len(kept)
            result[section] = kept
    return dropped


def cap_test_file_severity(result: dict, project_root=None) -> int:
    """Report CRITICAL findings in test files as HIGH; return how many."""
    root = Path(project_root) if project_root is not None else None
    capped = 0
    for section in TEST_FILE_CAPPED_SECTIONS:
        for finding in result.get(section) or []:
            if not isinstance(finding, dict):
                continue
            if str(finding.get("severity", "")).upper() != "CRITICAL":
                continue
            file_value = finding.get("file") or finding.get("file_path")
            if not file_value or not _is_test_file(file_value, root):
                continue
            finding["original_severity"] = finding.get("severity")
            finding["severity"] = TEST_FILE_SEVERITY_CAP
            finding["severity_reason"] = "test_file"
            capped += 1
    return capped


_TEST_SUITE_DIRECTORIES = frozenset({"tests", "test"})
_MAX_IMPORTER_SOURCE_BYTES = 2_000_000


def _whole_repository_scan(analyzer) -> bool:
    scope = getattr(analyzer, "_analysis_scope", None)
    if not isinstance(scope, dict) or scope.get("changed_files_only"):
        return False
    try:
        return (
            Path(str(scope.get("scan_path"))).resolve()
            == Path(str(scope.get("repository_root"))).resolve()
        )
    except (OSError, RuntimeError, TypeError):
        return False


def _suite_relative(path: Path, root: Path) -> Path | None:
    """The path inside a top-level test suite directory, or None."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    if (
        len(relative.parts) < 2
        or relative.parts[0].lower() not in _TEST_SUITE_DIRECTORIES
    ):
        return None
    return relative


def _production_mentions(root: Path, modmap, is_test) -> tuple[str, ...] | None:
    """Source text of every non-test Python module, or None if any is
    unreadable. Mentions catch imports at any depth and dynamic loaders."""
    from skylos.core.safe_cache_io import read_project_text_no_symlink

    texts = []
    for file in modmap:
        path = Path(str(file))
        if path.suffix != ".py" or is_test(str(path)):
            continue
        try:
            text = read_project_text_no_symlink(
                root,
                path,
                max_bytes=_MAX_IMPORTER_SOURCE_BYTES,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, ValueError, RuntimeError):
            return None
        if text is None:
            return None
        texts.append(text)
    return tuple(texts)


def _mentioned(texts, relative: Path) -> bool:
    stem = relative.with_suffix("").name
    suite = relative.parts[0]
    pattern = re.compile(rf"(?<!\w){re.escape(stem)}(?!\w)|['\"]{re.escape(suite)}[./]")
    return any(pattern.search(text) for text in texts)


_EXTERNAL_INPUT_PREFIXES = (
    "urllib.request.",
    "requests.",
    "httpx.",
    "aiohttp.",
    "http.client.",
    "socket.",
    "sys.stdin",
)
_EXTERNAL_INPUT_CALLS = frozenset({"urlopen", "input", "recv", "recvfrom"})


def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _reads_external_input(node) -> bool:
    for part in ast.walk(node):
        name = ""
        if isinstance(part, ast.Call):
            name = _dotted(part.func)
        elif isinstance(part, ast.Attribute):
            name = _dotted(part)
        if not name:
            continue
        if name.startswith(_EXTERNAL_INPUT_PREFIXES):
            return True
        if name.rsplit(".", 1)[-1] in _EXTERNAL_INPUT_CALLS:
            return True
    return False


def _executes_external_input(root: Path, path: Path, line) -> bool | None:
    """Whether the exec/eval at ``line`` runs network or stdin input, directly
    or through a local assigned from it; None when the file cannot be read."""
    from skylos.core.safe_cache_io import read_project_text_no_symlink

    try:
        text = read_project_text_no_symlink(
            root,
            path,
            max_bytes=_MAX_IMPORTER_SOURCE_BYTES,
            encoding="utf-8",
            errors="replace",
        )
        tree = ast.parse(text or "")
    except (OSError, ValueError, RuntimeError, SyntaxError):
        return None
    scopes = [tree]
    scopes.extend(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
    )
    for scope in scopes:
        for call in ast.walk(scope):
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id in {"exec", "eval"}
                and call.lineno == line
            ):
                continue
            if any(_reads_external_input(argument) for argument in call.args):
                return True
            names = {
                part.id
                for argument in call.args
                for part in ast.walk(argument)
                if isinstance(part, ast.Name)
            }
            for statement in ast.walk(scope):
                if (
                    isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign))
                    and statement.value is not None
                    and _reads_external_input(statement.value)
                ):
                    targets = [getattr(statement, "target", None)]
                    targets.extend(getattr(statement, "targets", []))
                    for target in targets:
                        if target is None:
                            continue
                        if any(
                            isinstance(part, ast.Name) and part.id in names
                            for part in ast.walk(target)
                        ):
                            return True
    return False


def cap_test_only_code_execution(
    result: dict, project_root=None, *, modmap=None, raw_imports=None, analyzer=None
) -> int:
    """Report HIGH ``exec``/``eval`` in proved test-only modules as MEDIUM.

    Proof: a whole-repository scan; the module sits in a top-level ``tests``
    or ``test`` directory and is a test module (name/folder plus a test or
    framework import); no non-test module imports it at module level, and no
    non-test module mentions its name or builds a path into the suite (which
    covers function-level, ``try`` and dynamic imports)."""
    if project_root is None or modmap is None or raw_imports is None:
        return 0
    if not _whole_repository_scan(analyzer):
        return 0
    candidates = [
        finding
        for finding in result.get("danger") or []
        if isinstance(finding, dict)
        and finding.get("rule_id") in TEST_ONLY_CODE_EXECUTION_RULES
        and str(finding.get("severity", "")).upper() == "HIGH"
        and "original_severity" not in finding
    ]
    if not candidates:
        return 0
    from skylos.rules.quality._test_code import is_python_test_file
    from skylos.rules.quality.clones import (
        imported_outside_tests,
        python_imports_outside_tests,
    )

    root = Path(project_root).resolve()
    imported = python_imports_outside_tests(raw_imports, root)
    modules = {}
    for file, module in modmap.items():
        try:
            modules[str(Path(file).resolve())] = module
        except (OSError, RuntimeError):
            continue
    test_files = {}

    def is_test(file_value):
        if file_value not in test_files:
            test_files[file_value] = is_python_test_file(file_value, root)
        return test_files[file_value]

    texts = None
    verdicts = {}
    lowered = 0
    for finding in candidates:
        file_value = finding.get("file") or finding.get("file_path")
        if not file_value:
            continue
        path = Path(str(file_value))
        if not path.is_absolute():
            path = root / path
        try:
            key = str(path.resolve())
        except (OSError, RuntimeError):
            continue
        if key not in verdicts:
            relative = _suite_relative(Path(key), root)
            verdict = (
                relative is not None
                and is_test(key)
                and not imported_outside_tests(modules.get(key), imported)
            )
            if verdict:
                if texts is None:
                    texts = _production_mentions(root, modmap, is_test)
                verdict = texts is not None and not _mentioned(texts, relative)
            verdicts[key] = verdict
        if not verdicts[key]:
            continue
        if _executes_external_input(root, Path(key), finding.get("line")) is not False:
            continue
        finding["original_severity"] = finding.get("severity")
        finding["severity"] = TEST_ONLY_CODE_EXECUTION_SEVERITY
        finding["severity_reason"] = "test_only_module"
        lowered += 1
    return lowered


def _is_test_file(file_value, root: Path | None) -> bool:
    return get_non_library_dir_kind(str(file_value), root) == "test"
