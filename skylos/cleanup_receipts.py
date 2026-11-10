"""Bounded cleanup observations for explicit uploads, never issue resolution.

Only allowlisted scalar evidence leaves local history. A working-tree attempt
keeps its original revisions; loading or uploading never rebinds it to HEAD.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
from uuid import uuid4

from skylos.cleanup_state import load_cleanup_state, mutate_cleanup_workspace
from skylos.core.git_context import GitContext

MAX_CLEANUP_RECEIPTS = 20
CHECK_CATEGORIES = ("quality", "ai_defects", "dead_code", "security", "secrets")
LIMITATIONS = (
    "unbound_outcome",
    "tests_not_observed",
    "change_not_exercised",
    "security_not_checked",
    "stale_source",
    "incomplete_scan",
    "rollback_failed",
)
CHECK_STATUSES = {"passed", "failed", "skipped", "incomplete"}
RECEIPT_STATUSES = {"verified", "applied_unverified", "failed", "incomplete"}
TEST_EVIDENCE = {"none", "exit_code", "junit", "pytest_junit", "done"}
_HASH = re.compile(r"[0-9a-f]{64}")
_SHA = re.compile(r"[0-9a-f]{40}")
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_RULE = re.compile(r"SKY-[A-Z0-9-]{1,112}")
_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,40}")
_TIMESTAMP = re.compile(
    r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)"
)


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _choice(value, choices):
    return isinstance(value, str) and value in choices


def _path(value, *, allow_root=False):
    if allow_root and value == ".":
        return True
    return (
        isinstance(value, str)
        and 0 < len(value) <= 500
        and not value.startswith("/")
        and not any(
            char in "\\:" or ord(char) < 32 or ord(char) == 127 for char in value
        )
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _count(value):
    return value is None or type(value) is int and 0 <= value <= 2_147_483_647


def _boolean(value):
    return value is None or type(value) is bool


def _revision(value):
    if not isinstance(value, dict) or "head" not in value or "dirty" not in value:
        return None
    if not (value["head"] is None or _matches(_SHA, value["head"])) or not _boolean(
        value["dirty"]
    ):
        return None
    return {"head": value["head"], "dirty": value["dirty"]}


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 40 or not _matches(_TIMESTAMP, value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_cleanup_receipt(value):
    """Reconstruct the public schema; unknown fields and private prose are dropped."""
    if not isinstance(value, dict):
        return None
    scope, checks = value.get("scope"), value.get("checks")
    if not isinstance(scope, dict) or not isinstance(checks, dict):
        return None
    tests, rescan = checks.get("tests"), checks.get("rescan")
    if not isinstance(tests, dict) or not isinstance(rescan, dict):
        return None
    source_revision = _revision(value.get("source_revision"))
    outcome_revision = _revision(value.get("outcome_revision"))
    returncode = tests.get("returncode")
    digest = scope.get("config_digest")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or not _matches(_UUID, value.get("attempt_id"))
        or not _matches(_HASH, value.get("task_id"))
        or not _matches(_RULE, value.get("rule_id"))
        or not _path(value.get("file"))
        or _timestamp(value.get("recorded_at")) is None
        or not _matches(_HASH, value.get("source_sha256"))
        or not _matches(_HASH, value.get("applied_sha256"))
        or not _path(scope.get("target"), allow_root=True)
        or not _matches(_VERSION, scope.get("scanner_version"))
        or not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or not _matches(_HASH, digest[7:])
        or not _choice(value.get("status"), RECEIPT_STATUSES)
        or type(value.get("applied")) is not bool
        or type(value.get("rolled_back")) is not bool
        or source_revision is None
        or outcome_revision is None
        or not _choice(tests.get("status"), CHECK_STATUSES)
        or "returncode" not in tests
        or not (
            returncode is None
            or type(returncode) is int
            and abs(returncode) <= 2_147_483_647
        )
        or not _choice(tests.get("evidence"), TEST_EVIDENCE)
        or "count" not in tests
        or not _count(tests["count"])
        or "exercised_change" not in tests
        or not _boolean(tests["exercised_change"])
        or not _choice(rescan.get("status"), CHECK_STATUSES)
        or "new_findings_count" not in rescan
        or not _count(rescan["new_findings_count"])
        or "original_present" not in rescan
        or not _boolean(rescan["original_present"])
    ):
        return None
    categories = rescan.get("checked_categories", [])
    if (
        not isinstance(categories, list)
        or len(categories) > len(CHECK_CATEGORIES)
        or any(category not in CHECK_CATEGORIES for category in categories)
    ):
        return None
    if value["rolled_back"] and value["applied"]:
        return None
    if value["status"] == "verified" and (
        not value["applied"]
        or value["rolled_back"]
        or tests["status"] != "passed"
        or returncode != 0
        or tests["count"] is None
        or tests["count"] < 1
        or tests["evidence"] not in {"junit", "pytest_junit", "done"}
        or rescan["status"] != "passed"
        or rescan["new_findings_count"] != 0
        or rescan["original_present"] is not False
    ):
        return None
    public_checks = {
        "tests": {
            key: tests[key]
            for key in ("status", "returncode", "evidence", "count", "exercised_change")
        },
        "rescan": {
            **{
                key: rescan[key]
                for key in ("status", "new_findings_count", "original_present")
            },
            "checked_categories": [
                category for category in CHECK_CATEGORIES if category in categories
            ],
        },
    }
    for name in ("rollback", "behavior"):
        if name not in checks:
            continue
        check = checks[name]
        if not isinstance(check, dict) or not _choice(
            check.get("status"), CHECK_STATUSES
        ):
            return None
        if value["status"] == "verified" and check["status"] == "failed":
            return None
        public_checks[name] = {"status": check["status"]}
        if name == "behavior":
            if check.get("model") != "python-source-effects-v1":
                return None
            public_checks[name]["model"] = check["model"]
    optional = {}
    for name in ("source_scan_id", "source_finding_id"):
        if value.get(name) is not None:
            if not _matches(_UUID, value[name]):
                return None
            optional[name] = value[name]
    if "limitations" in value:
        limits = value["limitations"]
        if (
            not isinstance(limits, list)
            or len(limits) > len(LIMITATIONS)
            or any(limit not in LIMITATIONS for limit in limits)
        ):
            return None
        optional["limitations"] = list(dict.fromkeys(limits))
    return {
        "schema_version": 1,
        **{
            key: value[key]
            for key in (
                "attempt_id",
                "task_id",
                "rule_id",
                "file",
                "recorded_at",
                "source_sha256",
                "applied_sha256",
                "status",
                "applied",
                "rolled_back",
            )
        },
        "scope": {
            "target": scope["target"],
            "scanner_version": scope["scanner_version"],
            "config_digest": digest,
        },
        "source_revision": source_revision,
        "outcome_revision": outcome_revision,
        "checks": public_checks,
        **optional,
    }


def cleanup_receipt_batch(values):
    """Keep the latest 20 valid attempts; conflicting duplicate identities are omitted."""
    if not isinstance(values, list):
        return []
    attempts, conflicts = {}, set()
    for index, value in enumerate(values):
        receipt = parse_cleanup_receipt(value)
        if receipt is None:
            continue
        attempt = receipt["attempt_id"]
        if attempt in attempts and attempts[attempt][1] != receipt:
            conflicts.add(attempt)
        else:
            attempts[attempt] = (index, receipt)
    ordered = sorted(
        (entry for attempt, entry in attempts.items() if attempt not in conflicts),
        key=lambda entry: (_timestamp(entry[1]["recorded_at"]), entry[0]),
        reverse=True,
    )
    return [receipt for _index, receipt in ordered[:MAX_CLEANUP_RECEIPTS]]


def capture_cleanup_revision(root):
    """Capture this before applying. Git reads disable repository helpers and filters."""
    unknown = {"head": None, "dirty": None}
    try:
        context = GitContext.from_path(root)
        head = context.run("rev-parse", "--verify", "HEAD^{commit}")
        if head.returncode or not _matches(_SHA, head.stdout.strip()):
            return unknown
        status = context.run("status", "--porcelain=v1", "-z", "--untracked-files=all")
        return {
            "head": head.stdout.strip(),
            "dirty": bool(status.stdout) if status.returncode == 0 else None,
        }
    except (OSError, ValueError, subprocess.SubprocessError):
        return unknown


def _relative_path(value, project_root, repository_root, *, allow_root=False):
    if not isinstance(value, (str, Path)):
        raise ValueError("Cleanup receipt requires a source path")
    path = Path(value)
    if ".." in path.parts:
        raise ValueError("Cleanup receipt paths must stay inside the project")
    if not path.is_absolute():
        if not _path(str(value), allow_root=allow_root):
            raise ValueError("Cleanup receipt requires a safe POSIX path")
        path = project_root / path
    else:
        from skylos.security.regression_diff import _lexical_repository_path

        # Canonicalize only an alias of the project root (e.g. /var on macOS),
        # without following links in the project-relative source path.
        path = _lexical_repository_path(project_root, path)
    try:
        path.relative_to(project_root)
        relative = path.relative_to(repository_root).as_posix()
    except ValueError as exc:
        raise ValueError("Cleanup receipt paths must stay inside the project") from exc
    if not _path(relative, allow_root=allow_root):
        raise ValueError("Cleanup receipt requires a safe POSIX path")
    return relative


def _public_scope(scope, root, repository):
    if not isinstance(scope, dict):
        raise ValueError("Cleanup receipt scope is missing")
    if (
        scope.get("project_root") is not None
        and Path(scope["project_root"]).resolve() != root
    ):
        raise ValueError("Cleanup receipt scope does not match its project root")
    digest = scope.get("config_digest")
    if _matches(_HASH, digest):
        digest = "sha256:" + digest
    return {
        "target": _relative_path(
            scope.get("target"), root, repository, allow_root=True
        ),
        "scanner_version": scope.get("scanner_version"),
        "config_digest": digest,
    }


def make_cleanup_receipt(
    task,
    scope,
    execution,
    *,
    project_root,
    source_revision,
    edit=None,
    limitation_codes=(),
):
    """Create a minimal attempt envelope; immediate working-tree results stay unbound."""
    root = Path(project_root)
    if root.is_symlink():
        raise ValueError("Cleanup receipt root must not be a symlink")
    root = root.resolve(strict=True)
    repository = GitContext.from_path(root).root.resolve()
    if not isinstance(task, dict) or not isinstance(execution, dict):
        raise ValueError("Cleanup receipt requires its original task and execution")
    edit = edit if isinstance(edit, dict) else {}
    tests, rescan = execution.get("tests", {}), execution.get("rescan", {})
    if not isinstance(tests, dict) or not isinstance(rescan, dict):
        raise ValueError("Cleanup receipt check results are malformed")
    if execution.get("status") == "verified" and tests.get("observed") is not True:
        raise ValueError("Verified cleanup receipts require observed test evidence")
    for evidence in (execution, edit):
        if evidence.get("task_id") is not None and evidence["task_id"] != task.get(
            "id"
        ):
            raise ValueError("Cleanup receipt task does not match its execution")
    if execution.get("rule_id") is not None and execution["rule_id"] != task.get(
        "rule_id"
    ):
        raise ValueError("Cleanup receipt rule does not match its execution")
    file = _relative_path(task.get("file"), root, repository)
    if (
        execution.get("file") is not None
        and _relative_path(execution["file"], root, repository) != file
    ):
        raise ValueError("Cleanup receipt file does not match its execution")
    for key in ("source_sha256", "applied_sha256"):
        if (
            execution.get(key) is not None
            and edit.get(key) is not None
            and execution[key] != edit[key]
        ):
            raise ValueError("Cleanup receipt hashes do not match the reviewed edit")
    categories = rescan.get("checked_categories", [])
    limits = set(limitation_codes)
    if not limits.issubset(LIMITATIONS):
        raise ValueError("Cleanup receipt limitation codes are invalid")
    limits.add("unbound_outcome")
    if tests.get("observed") is not True:
        limits.add("tests_not_observed")
    if tests.get("exercised_change") is False:
        limits.add("change_not_exercised")
    if not isinstance(categories, list) or "security" not in categories:
        limits.add("security_not_checked")
    if rescan.get("status") in {"skipped", "incomplete"}:
        limits.add("incomplete_scan")
    checks = {
        "tests": {
            "status": tests.get("status", "skipped"),
            "returncode": tests.get("returncode"),
            "evidence": tests.get("evidence", "none"),
            "count": tests.get("count"),
            "exercised_change": tests.get("exercised_change"),
        },
        "rescan": {
            "status": rescan.get("status", "skipped"),
            "new_findings_count": len(rescan["new_findings"])
            if isinstance(rescan.get("new_findings"), list)
            else rescan.get("new_findings_count"),
            "original_present": rescan.get("original_present"),
            "checked_categories": categories,
        },
    }
    for name in ("rollback", "behavior"):
        if isinstance(execution.get(name), dict):
            checks[name] = execution[name]
    if checks.get("rollback", {}).get("status") == "failed":
        limits.add("rollback_failed")
    receipt = {
        "schema_version": 1,
        "attempt_id": str(uuid4()),
        "task_id": task.get("id"),
        "rule_id": task.get("rule_id"),
        "file": file,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_sha256": execution.get("source_sha256", edit.get("source_sha256")),
        "applied_sha256": execution.get("applied_sha256", edit.get("applied_sha256")),
        "scope": _public_scope(scope, root, repository),
        "source_revision": source_revision,
        "outcome_revision": {"head": None, "dirty": True},
        "status": execution.get("status"),
        "applied": execution.get("applied"),
        "rolled_back": execution.get("rolled_back"),
        "checks": checks,
        "limitations": [code for code in LIMITATIONS if code in limits],
        **{
            name: task[name]
            for name in ("source_scan_id", "source_finding_id")
            if name in task
        },
    }
    result = parse_cleanup_receipt(receipt)
    if result is None:
        raise ValueError("Cleanup execution cannot form a valid bounded receipt")
    return result


def store_cleanup_receipt(root, scope, receipt):
    """Persist one sanitized envelope; a saved attempt cannot acquire a new revision."""
    receipt = parse_cleanup_receipt(receipt)
    if receipt is None:
        raise ValueError("Cleanup receipt is malformed")
    project = Path(root).resolve(strict=True)
    if receipt["scope"] != _public_scope(
        scope, project, GitContext.from_path(project).root.resolve()
    ):
        raise ValueError("Cleanup receipt scope does not match its workspace")

    def save(bucket):
        previous = bucket.get("cleanup_receipts", [])
        previous = previous if isinstance(previous, list) else []
        for value in previous:
            existing = parse_cleanup_receipt(value)
            if (
                existing is not None
                and existing["attempt_id"] == receipt["attempt_id"]
                and existing != receipt
            ):
                raise ValueError(
                    "A stored cleanup attempt cannot be changed or rebound"
                )
        bucket["cleanup_receipts"] = cleanup_receipt_batch([*previous, receipt])
        return receipt

    return mutate_cleanup_workspace(root, scope, save)


def load_cleanup_receipts(root):
    """Read only persisted envelopes across scopes; never inspect current HEAD."""
    state = load_cleanup_state(Path(root))
    values = []
    for bucket in state["scopes"].values():
        if isinstance(bucket, dict) and isinstance(
            bucket.get("cleanup_receipts"), list
        ):
            values.extend(bucket["cleanup_receipts"])
    return cleanup_receipt_batch(values)
