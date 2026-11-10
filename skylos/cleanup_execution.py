"""Reviewable cleanup edits with guarded writes and explicit verification receipts.

No target code runs unless the caller supplies a test command. A successful
static rescan alone does not establish preserved runtime behavior.
"""

from __future__ import annotations

import ast
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
import difflib
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Callable
from uuid import uuid4

from skylos.analysis.errors import analysis_result_incomplete
from skylos.cleanup_identity import source_anchor_digest, source_anchor_from_text
from skylos.reporting.finding_types import get_finding_type, iter_result_findings
from skylos.reporting.rollups import FINDING_SECTIONS

MAX_SOURCE_BYTES = 5_000_000
SUPPORTED_RULES = frozenset({"SKY-U001", "SKY-U002", "SKY-L038"})


def _hash(value: bytes) -> str:
    return sha256(value).hexdigest()


def _root_path(root: str | Path) -> Path:
    root = Path(root)
    if root.is_symlink():
        raise ValueError("cleanup root must not be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("cleanup root must be a directory")
    return root


def _relative(root: Path, file: str) -> Path:
    candidate = Path(file)
    if candidate.is_absolute():
        candidate = candidate.relative_to(root)
    if not candidate.parts or any(part in {"..", "."} for part in candidate.parts):
        raise ValueError("cleanup file must remain inside the project")
    return candidate


@contextmanager
def _source_file(root: Path, relative: Path):
    """Open every path component without following project symlinks."""
    # Keep containment at the file boundary: O_NOFOLLOW alone does not reject
    # parent components or an absolute path that resets descriptor traversal.
    root = _root_path(root)
    relative = _relative(root, str(relative))
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("safe cleanup writes are unavailable on this platform")
    # The canonical user-selected project directory defines the authorized base.
    directory = os.open(  # skylos: ignore[SKY-D215] authorized project root
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    source_fd = None
    try:
        for part in relative.parts[:-1]:
            next_directory = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = next_directory
        # _relative rejects absolute escapes and parent components; each child
        # is opened without following links under the held directory descriptor.
        source_fd = (
            os.open(  # skylos: ignore[SKY-D215] checked descriptor-relative path
                relative.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
        )
        metadata = os.fstat(source_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("cleanup source must be a regular file with one link")
        if metadata.st_size > MAX_SOURCE_BYTES:
            raise ValueError("cleanup source exceeds the size limit")
        content = bytearray()
        while len(content) <= MAX_SOURCE_BYTES:
            part = os.read(source_fd, min(65536, MAX_SOURCE_BYTES + 1 - len(content)))
            if not part:
                break
            content.extend(part)
        if len(content) > MAX_SOURCE_BYTES:
            raise ValueError("cleanup source exceeds the size limit")
        yield directory, bytes(content), metadata
    finally:
        if source_fd is not None:
            os.close(source_fd)
        os.close(directory)


def _read_source(root: Path, relative: Path) -> bytes:
    with _source_file(root, relative) as (_, content, _metadata):
        return content


def _replace_unchanged(root: Path, relative: Path, expected: bytes, replacement: bytes):
    """Optimistically compare source and atomically publish one complete file."""
    temporary = f".skylos-cleanup-{uuid4().hex}.tmp"
    with _source_file(root, relative) as (directory, content, metadata):
        if content != expected:
            raise ValueError("source changed; preserving the current file")
        temporary_fd = None
        try:
            temporary_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                stat.S_IMODE(metadata.st_mode),
                dir_fd=directory,
            )
            with os.fdopen(temporary_fd, "wb") as handle:
                temporary_fd = None
                handle.write(replacement)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), stat.S_IMODE(metadata.st_mode))
            # Reopen the named file rather than trusting a descriptor that an
            # editor may have replaced while the patch was being prepared.
            with _source_file(root, relative) as (_parent, current, current_stat):
                parent_stat = os.fstat(directory)
                current_parent = os.fstat(_parent)
                if (parent_stat.st_dev, parent_stat.st_ino) != (
                    current_parent.st_dev,
                    current_parent.st_ino,
                ):
                    raise ValueError(
                        "source directory changed; preserving the current file"
                    )
                if current != expected or (
                    current_stat.st_dev,
                    current_stat.st_ino,
                ) != (metadata.st_dev, metadata.st_ino):
                    raise ValueError("source changed; preserving the current file")
            os.replace(
                temporary, relative.name, src_dir_fd=directory, dst_dir_fd=directory
            )
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def _rule(task: dict) -> str:
    return str(task.get("rule_id") or "").upper()


def _finding(task: dict) -> dict:
    value = task.get("finding", task)
    if not isinstance(value, dict):
        raise ValueError("cleanup task has invalid finding evidence")
    return value


def _target_node(tree: ast.Module, task: dict) -> ast.AST:
    finding = _finding(task)
    rule = _rule(task)
    line = int(finding.get("line") or task.get("line") or 0)
    column = finding.get("col")
    if rule == "SKY-U001":
        kinds = (ast.FunctionDef, ast.AsyncFunctionDef)
    elif rule == "SKY-U002":
        kinds = (ast.Import, ast.ImportFrom)
    else:
        kinds = (ast.Call,)
    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, kinds)
        and node.lineno == line
        and (column is None or node.col_offset == column)
    ]
    if rule == "SKY-U001":
        name = str(task.get("name") or finding.get("name") or "").split(".")[-1]
        candidates = [node for node in candidates if node.name == name]
    if len(candidates) != 1:
        raise ValueError("cleanup task does not identify one source node")
    return candidates[0]


def _anchor(tree: ast.Module, target: ast.AST) -> str:
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    owners = []
    node = target
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            owners.append((type(node).__name__, node.name))
    return json.dumps(
        [list(reversed(owners)), ast.dump(target, include_attributes=False)]
    )


def _unique_anchor(tree: ast.Module, target: ast.AST) -> str:
    anchor = _anchor(tree, target)
    if (
        sum(
            _anchor(tree, node) == anchor
            for node in ast.walk(tree)
            if isinstance(node, type(target))
        )
        != 1
    ):
        raise ValueError("cleanup source anchor is ambiguous")
    return anchor


def _l038_edit(
    source: str, task: dict, root: Path, relative: Path, target: ast.AST
) -> str:
    import libcst as cst
    from libcst.metadata import PositionProvider
    from skylos.rules.quality.slop import FormattedConversionCallRule

    findings = (
        FormattedConversionCallRule().visit_node(
            ast.parse(source),
            {"source": source, "filename": str(root / relative), "project_root": root},
        )
        or []
    )
    matches = [
        row
        for row in findings
        if row["line"] == target.lineno and row["col"] == target.col_offset
    ]
    if len(matches) != 1:
        raise ValueError("the simplification detector no longer proves this rewrite")
    conversion = matches[0]["value"][-1]
    # Python AST offsets count UTF-8 bytes; LibCST positions count characters.
    source_line = source.splitlines(keepends=True)[target.lineno - 1]
    target_column = len(
        source_line.encode("utf-8")[: target.col_offset].decode("utf-8")
    )
    target_identity = ast.dump(target, include_attributes=False)

    class Rewrite(cst.CSTTransformer):
        METADATA_DEPENDENCIES = (PositionProvider,)

        def leave_FormattedStringExpression(self, original, updated):
            call = original.expression
            position = self.get_metadata(PositionProvider, call)
            if (
                position.start.line != target.lineno
                or position.start.column != target_column
            ):
                return updated
            if not isinstance(call, cst.Call) or len(call.args) != 1:
                return updated
            try:
                expression = ast.parse(cst.Module([]).code_for_node(call), mode="eval")
            except (SyntaxError, ValueError, RecursionError) as exc:
                raise ValueError(
                    "CST conversion call identity could not be checked"
                ) from exc
            if ast.dump(expression.body, include_attributes=False) != target_identity:
                raise ValueError(
                    "CST expression differs from the selected conversion call"
                )
            if getattr(original, "equal", None) is not None:
                raise ValueError("debug f-string labels require manual review")
            return updated.with_changes(
                expression=updated.expression.args[0].value, conversion=conversion
            )

    return cst.MetadataWrapper(cst.parse_module(source)).visit(Rewrite()).code


def plan_cleanup_edit(task: dict[str, Any], root: str | Path) -> dict[str, Any]:
    """Prepare one reviewable patch; refuse stale or unsupported source evidence."""
    root = _root_path(root)
    rule = _rule(task)
    if rule not in SUPPORTED_RULES:
        raise ValueError(
            f"no deterministic cleanup edit supports {rule or 'this task'}"
        )
    if rule in {"SKY-U001", "SKY-U002"} and task.get("category") != "dead_code":
        raise ValueError("unused-code edits require native dead-code evidence")
    relative = _relative(
        root, str(task.get("file") or _finding(task).get("file") or "")
    )
    original = _read_source(root, relative)
    if task.get("source_sha256") != _hash(original):
        raise ValueError("cleanup task is stale or has no source hash; scan again")
    source = original.decode("utf-8")
    baseline = task.get("_baseline_report", task.get("baseline_report"))
    if not isinstance(baseline, dict):
        raise ValueError("cleanup edits require their originating analyzer report")
    if rule in {"SKY-U001", "SKY-U002"}:
        family = "unused_functions" if rule == "SKY-U001" else "unused_imports"
        candidates = baseline.get(family, [])
    else:
        candidates = [
            row
            for category, row in iter_result_findings(baseline)
            if category == task.get("category")
        ]
    matched = [
        row
        for row in candidates
        if isinstance(row, dict) and _same_location(row, task, root)
    ]
    if len(matched) != 1:
        raise ValueError(
            "task finding is absent or ambiguous in the originating report"
        )
    typescript_proof = None
    if relative.suffix in {".ts", ".tsx"}:
        if rule != "SKY-U002":
            raise ValueError(
                "TypeScript cleanup currently supports only unused type imports"
            )
        from skylos.cleanup_typescript import plan_typescript_unused_import

        typescript_proof = plan_typescript_unused_import(task, root, original)
        changed = typescript_proof["replacement"]
        anchor = typescript_proof["target_anchor"]
    elif relative.suffix == ".py":
        tree = ast.parse(source)
        expected_anchor = task.get("source_anchor")
        if (
            not expected_anchor
            or source_anchor_digest(_finding(task), root) != expected_anchor
        ):
            raise ValueError("cleanup source anchor is stale or unavailable")
        target = _target_node(tree, task)
        anchor = _unique_anchor(tree, target)
        if rule == "SKY-L038":
            changed = _l038_edit(source, task, root, relative, target)
        else:
            from skylos.remediation.codemods import (
                remove_unused_function_cst,
                remove_unused_import_cst,
            )

            if rule == "SKY-U001":
                # Definition-time decorators/default expressions can perform work
                # even when no caller exists. Keep those cases for manual review.
                if (
                    target.decorator_list
                    or target.args.defaults
                    or any(value is not None for value in target.args.kw_defaults)
                ):
                    raise ValueError(
                        "function has definition-time behavior; review manually"
                    )
                arguments = [
                    *target.args.posonlyargs,
                    *target.args.args,
                    *target.args.kwonlyargs,
                ]
                arguments.extend(
                    arg
                    for arg in (target.args.vararg, target.args.kwarg)
                    if arg is not None
                )
                if (
                    target.returns
                    or getattr(target, "type_params", ())
                    or any(arg.annotation for arg in arguments)
                ):
                    raise ValueError(
                        "function annotations require manual review before deletion"
                    )
                transform = remove_unused_function_cst
            else:
                allowed_modules = {
                    "typing",
                    "math",
                    "collections",
                    "itertools",
                    "functools",
                    "operator",
                    "re",
                    "sys",
                    "os",
                    "json",
                    "pathlib",
                }
                if not isinstance(target, ast.Import) or any(
                    alias.name.split(".")[0] not in allowed_modules
                    for alias in target.names
                ):
                    raise ValueError(
                        "import side effects require manual review; only standard-library import statements are supported"
                    )
                imported_roots = {alias.name.split(".")[0] for alias in target.names}
                if any(
                    path.name in imported_roots
                    or path.name.removesuffix(".py") in imported_roots
                    for path in root.rglob("*")
                ):
                    raise ValueError(
                        "a project module may shadow this standard-library import"
                    )
                transform = remove_unused_import_cst
            name = str(task.get("name") or _finding(task).get("name") or "")
            changed, did_change = transform(source, name, target.lineno)
            if not did_change:
                raise ValueError("the existing codemod could not locate the finding")
    else:
        raise ValueError(
            "Deterministic cleanup edits support Python and bounded TypeScript type imports"
        )
    if changed == source:
        raise ValueError("cleanup edit would not change this source")
    if relative.suffix == ".py":
        ast.parse(changed)
    replacement = changed.encode("utf-8")
    return {
        "version": 1,
        "status": "planned",
        "task_id": task.get("id"),
        "rule_id": rule,
        "file": relative.as_posix(),
        "source_sha256": _hash(original),
        "applied_sha256": _hash(replacement),
        "patch": "".join(
            difflib.unified_diff(
                source.splitlines(True),
                changed.splitlines(True),
                fromfile=f"a/{relative.as_posix()}",
                tofile=f"b/{relative.as_posix()}",
            )
        ),
        "scope": deepcopy(task.get("scope")),
        "_task": {
            key: deepcopy(value)
            for key, value in task.items()
            if key not in {"_baseline_report", "baseline_report"}
        },
        "_source": source,
        "_replacement": changed,
        "_target_anchor": anchor,
        "_typescript_proof": typescript_proof,
        "limitations": typescript_proof["limitations"] if typescript_proof else [],
        "_baseline_report": deepcopy(baseline),
    }


def _same_location(row: dict, task: dict, root: Path) -> bool:
    finding = _finding(task)
    try:
        file = _relative(
            root, str(row.get("file") or row.get("file_path") or "")
        ).as_posix()
        target_file = _relative(
            root, str(task.get("file") or finding.get("file") or "")
        ).as_posix()
    except ValueError:
        return False
    row_name = row.get("name") or row.get("simple_name")
    target_name = finding.get("name") or task.get("name")
    if row_name and target_name and row_name != target_name:
        return False
    return (
        str(
            row.get("rule_id")
            or (_rule(task) if task.get("category") == "dead_code" else "")
        ).upper()
        == _rule(task)
        and file == target_file
        and row.get("line", row.get("lineno")) == finding.get("line", task.get("line"))
        and (finding.get("col") is None or row.get("col") == finding["col"])
    )


def _coverage(report: dict) -> list[str]:
    reasons = []
    if not isinstance(report, dict) or not isinstance(
        report.get("analysis_summary"), dict
    ):
        return ["Analyzer result has no valid summary."]
    summary = report["analysis_summary"]
    if type(summary.get("total_files")) is not int or summary["total_files"] < 1:
        reasons.append("No supported source files were analyzed.")
    if not isinstance(
        report.get("analysis_errors"), list
    ) or analysis_result_incomplete(report):
        reasons.append("Source analysis was incomplete.")
    for section in (
        *dict(FINDING_SECTIONS),
        "code_health",
        "circular_dependencies",
        "publisher_change_findings",
    ):
        if section in report and (
            not isinstance(report[section], list)
            or any(not isinstance(row, dict) for row in report[section])
        ):
            reasons.append(f"Malformed findings in {section}.")
    metrics = report.get("architecture_metrics")
    if metrics is not None:
        groups = metrics.get("advisories", []) if isinstance(metrics, dict) else None
        if not isinstance(groups, list) or any(
            not isinstance(group, dict)
            or not isinstance(group.get("signals"), list)
            or any(not isinstance(row, dict) for row in group["signals"])
            for group in groups
        ):
            reasons.append("Malformed architecture advisory findings.")
    categories = summary.get("grade_categories")
    if (
        not isinstance(categories, list)
        or not categories
        or any(not isinstance(category, str) for category in categories)
    ):
        reasons.append("Enabled analyzer checks are not recorded.")
    scope = summary.get("comparison_scope")
    if (
        not isinstance(scope, dict)
        or not isinstance(scope.get("scan_path"), str)
        or not scope["scan_path"]
    ):
        reasons.append("The originating scan target is not recorded.")
    if isinstance(categories, list) and "ai_defects" in categories:
        ai = summary.get("ai_verification")
        if (
            not isinstance(ai, dict)
            or ai.get("state") != "complete"
            or ai.get("missing_checks")
        ):
            reasons.append("AI verification coverage is incomplete or unavailable.")
    return reasons


def _risk_key(
    category: str, finding: dict, root: Path, sources: dict[str, str] | None = None
) -> str:
    try:
        file = _relative(
            root, str(finding.get("file") or finding.get("file_path") or "")
        ).as_posix()
    except ValueError:
        file = str(finding.get("file") or "")

    # Location-independent identity avoids treating shifted existing findings
    # as new regressions. Evidence text remains available in the full receipt.
    def evidence(value):
        if isinstance(value, dict):
            return {
                key: evidence(item)
                for key, item in value.items()
                if key
                not in {"line", "lineno", "col", "column", "start_line", "end_line"}
            }
        if isinstance(value, list):
            return [evidence(item) for item in value]
        return value

    identity = {
        key: finding.get(key)
        for key in ("rule_id", "name", "simple_name", "message", "value")
    }
    identity["evidence"] = evidence(finding.get("evidence"))
    if sources is not None and file in sources:
        identity["source_anchor"] = source_anchor_from_text(finding, sources[file])
    return json.dumps([category, file, identity], sort_keys=True, default=str)


def compare_cleanup_reports(
    before: dict,
    after: dict,
    *,
    project_root: str | Path,
    task: dict | None = None,
    required_categories: tuple[str, ...] | None = None,
    before_sources: dict[str, str] | None = None,
    after_sources: dict[str, str] | None = None,
) -> dict:
    """Compare raw finding identities and comparable scan receipts, never totals."""
    root = _root_path(project_root)
    limitations = _coverage(before) + _coverage(after)
    before_summary = (
        before.get("analysis_summary", {}) if isinstance(before, dict) else {}
    )
    after_summary = after.get("analysis_summary", {}) if isinstance(after, dict) else {}
    if required_categories:
        for summary in (before_summary, after_summary):
            categories = summary.get("grade_categories")
            if not isinstance(categories, list) or any(
                category not in categories for category in required_categories
            ):
                limitations.append("Required analyzer checks were not enabled.")
    for field in ("grade_categories", "comparison_scope"):
        if not before_summary.get(field) or before_summary.get(
            field
        ) != after_summary.get(field):
            limitations.append(f"Comparable {field} was not established.")

    def risky(report):
        for category, row in iter_result_findings(report):
            purpose = get_finding_type(row, category)
            if purpose == "defect" or (
                purpose == "review"
                and str(row.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
            ):
                yield category, row

    baseline = Counter(
        _risk_key(category, row, root, before_sources)
        for category, row in risky(before)
    )
    new = []
    for category, row in risky(after):
        key = _risk_key(category, row, root, after_sources)
        if baseline[key]:
            baseline[key] -= 1
        else:
            new.append(deepcopy(row))
    original_present = None
    if task is not None:
        target_file = _relative(root, str(task["file"]))
        source = _read_source(root, target_file).decode("utf-8")
        anchor = task.get("_target_anchor")
        if not anchor:
            limitations.append("Original source anchor is unavailable.")
        elif target_file.suffix in {".ts", ".tsx"}:
            from skylos.cleanup_typescript import typescript_import_anchor_present

            original_present = typescript_import_anchor_present(
                source, anchor, file_path=target_file.as_posix()
            )
        else:
            tree = ast.parse(source)
            original_present = any(
                _anchor(tree, node) == anchor for node in ast.walk(tree)
            )
    return {
        "status": "failed"
        if new or original_present
        else "incomplete"
        if limitations
        else "passed",
        "limitations": list(dict.fromkeys(limitations)),
        "new_findings": new,
        "original_present": original_present,
    }


def apply_cleanup_edit(
    edit: dict[str, Any],
    root: str | Path,
    *,
    test_cmd: str | None = None,
    rescan: Callable[[], dict] | None = None,
    test_timeout: int = 300,
    junit_xml: str | None = None,
) -> dict[str, Any]:
    """Apply only the reviewed deterministic edit and verify explicitly requested checks."""
    root = _root_path(root)
    task = edit.get("_task")
    if not isinstance(task, dict):
        raise ValueError("cleanup edit has no original task")
    task = {**task, "_baseline_report": edit.get("_baseline_report")}
    fresh = plan_cleanup_edit(task, root)
    if fresh["source_sha256"] != edit.get("source_sha256") or fresh[
        "applied_sha256"
    ] != edit.get("applied_sha256"):
        raise ValueError("cleanup patch changed; preview it again")
    if fresh.get("_typescript_proof") != edit.get("_typescript_proof"):
        raise ValueError("TypeScript cleanup proof changed; preview it again")
    relative = _relative(root, fresh["file"])
    original, replacement = (
        fresh["_source"].encode("utf-8"),
        fresh["_replacement"].encode("utf-8"),
    )
    argv = None
    if test_cmd is not None:
        from skylos.cleanup_checks import validate_junit_path
        from skylos.llm.executor import RemediationExecutor

        validate_junit_path(junit_xml)
        argv = RemediationExecutor(project_root=root)._safe_test_argv(test_cmd)
        if not argv:
            raise ValueError(
                "test command contains unsupported shell syntax or is empty"
            )
    if fresh.get("_typescript_proof"):
        from skylos.cleanup_typescript import revalidate_typescript_dependencies

        revalidate_typescript_dependencies(root, fresh["_typescript_proof"])
    _replace_unchanged(root, relative, original, replacement)
    result = {
        "version": 1,
        "task_id": edit.get("task_id"),
        "rule_id": _rule(task),
        "file": fresh["file"],
        "source_sha256": fresh["source_sha256"],
        "applied_sha256": fresh["applied_sha256"],
        "status": "applied_unverified",
        "applied": True,
        "rolled_back": False,
        "tests": {
            "status": "skipped",
            "command": None,
            "evidence": "none",
            "count": None,
            "observed": False,
            "exercised_change": None,
        },
        "rescan": {"status": "skipped"},
        "rollback": {"status": "skipped"},
        "limitations": list(fresh.get("limitations", [])),
    }
    from skylos.cleanup_checks import (
        changed_lines,
        compare_cleanup_behavior,
        run_cleanup_tests,
    )

    result["behavior"] = compare_cleanup_behavior(
        fresh["file"], fresh["_source"], fresh["_replacement"]
    )
    failed = result["behavior"]["status"] == "failed"
    if argv is not None and not failed:
        try:
            result["tests"] = run_cleanup_tests(
                root,
                argv,
                file=fresh["file"],
                before=fresh["_source"],
                after=fresh["_replacement"],
                timeout=test_timeout,
                junit_xml=junit_xml,
            )
            failed = result["tests"]["status"] == "failed"
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["tests"] = {
                "status": "incomplete",
                "command": argv,
                "error": str(exc),
            }
            result["limitations"].append("Authorized tests could not complete.")
    if rescan is not None:
        try:
            after = rescan()
            if isinstance(after, str):
                after = json.loads(after)
            comparison_task = {**task, "_target_anchor": fresh["_target_anchor"]}
            categories = {"quality", "ai_defects", "dead_code"}
            baseline_categories = (
                fresh["_baseline_report"]
                .get("analysis_summary", {})
                .get("grade_categories", [])
            )
            categories.update(
                category
                for category in ("security", "secrets")
                if category in baseline_categories
            )
            result["rescan"] = compare_cleanup_reports(
                fresh["_baseline_report"],
                after,
                project_root=root,
                task=comparison_task,
                required_categories=tuple(sorted(categories)),
                before_sources={fresh["file"]: fresh["_source"]},
                after_sources={
                    fresh["file"]: _read_source(root, relative).decode("utf-8")
                },
            )
            result["rescan"]["checked_categories"] = sorted(categories)
            failed = failed or result["rescan"]["status"] == "failed"
        except (Exception, SystemExit) as exc:
            result["rescan"] = {"status": "incomplete", "error": str(exc)}
            result["limitations"].append("The comparable rescan could not complete.")
    proof_incomplete = False
    if fresh.get("_typescript_proof"):
        try:
            revalidate_typescript_dependencies(root, fresh["_typescript_proof"])
        except (OSError, ValueError) as exc:
            proof_incomplete = True
            result["limitations"].append(str(exc))
    if failed:
        result["status"] = "failed"
        try:
            _replace_unchanged(root, relative, replacement, original)
            result["rolled_back"] = True
            result["applied"] = False
            result["rollback"] = {"status": "passed"}
        except (OSError, ValueError) as exc:
            result["rollback"] = {"status": "failed"}
            result["limitations"].append(f"Rollback was not applied: {exc}")
    elif proof_incomplete:
        result["status"] = "incomplete"
    elif (
        result["tests"]["status"] == "passed"
        and result["tests"].get("observed") is True
        and result["rescan"]["status"] == "passed"
    ):
        try:
            unchanged = _read_source(root, relative) == replacement
        except (OSError, ValueError, UnicodeError):
            unchanged = False
        if not unchanged:
            result["status"] = "incomplete"
            result["limitations"].append("The source changed during verification.")
        else:
            python_replacement = relative.suffix == ".py" and bool(
                changed_lines(fresh["_source"], fresh["_replacement"])
            )
            exercised = result["tests"].get("exercised_change")
            behavior = result["behavior"]
            modeled = (
                behavior.get("status") == "passed"
                and behavior.get("model") == "python-source-effects-v1"
                and behavior.get("functions")
                and all(
                    check.get("status") == "equivalent"
                    for check in behavior["functions"]
                )
                and not behavior.get("limitations")
            )
            if python_replacement and (
                exercised is False or (exercised is not True and not modeled)
            ):
                result["status"] = "applied_unverified"
                result["limitations"].append(
                    "Observed tests did not exercise the changed lines."
                    if exercised is False
                    else "Changed-line exercise is unknown and no bounded behavior proof was established."
                )
            else:
                result["status"] = "verified"
                if relative.suffix == ".py" and not python_replacement:
                    result["limitations"].append(
                        "Deletion-only edits have no replacement lines to trace; verification is limited to observed tests and the comparable static rescan."
                    )
    elif (
        result["tests"]["status"] == "incomplete"
        or result["rescan"]["status"] == "incomplete"
    ):
        result["status"] = "incomplete"
    else:
        result["limitations"].append(
            "Verification requires observed passing tests (JUnit), not only a zero-exit command, and a complete comparable rescan."
        )
    return result
