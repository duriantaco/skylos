"""Source-bound cleanup plans. Planning and completion never authorize edits."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
import re

from skylos.cleanup_state import load_cleanup_state, scope_identity
from skylos.core.safe_cache_io import read_project_text_no_symlink

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _scope(root, scope):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Cleanup workspace root is unsafe or unavailable")
    root = root.resolve()
    if not isinstance(scope, dict) or scope.get("project_root") != str(root):
        raise ValueError("Cleanup workspace scope does not match its project root")
    if not all(
        isinstance(scope.get(key), str) and scope[key]
        for key in ("target", "scanner_version", "config_digest")
    ):
        raise ValueError("Cleanup workspace requires a comparable scan scope")
    try:
        Path(scope["target"]).resolve().relative_to(root)
    except (ValueError, OSError) as exc:
        raise ValueError(
            "Cleanup workspace target is outside its project root"
        ) from exc
    return root


def _name(name):
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError(
            "Plan names need 1-80 letters, digits, dots, underscores or hyphens"
        )
    return name


def _text_list(values, label):
    if not isinstance(values, (list, tuple)) or len(values) > 50:
        raise ValueError(f"Invalid cleanup {label}")
    if any(
        not isinstance(item, str) or not item.strip() or len(item) > 1000
        for item in values
    ):
        raise ValueError(f"Invalid cleanup {label}")
    return list(values)


def _relative_file(file):
    if (
        not isinstance(file, str)
        or not file
        or "\\" in file
        or "\x00" in file
        or PurePosixPath(file).is_absolute()
        or ".." in PurePosixPath(file).parts
    ):
        raise ValueError("Cleanup evidence must name a project-relative file")
    return file


def _source_hash(root, file):
    source = read_project_text_no_symlink(
        root, _relative_file(file), max_bytes=2_000_000, newline=""
    )
    return sha256(source.encode("utf-8")).hexdigest() if source is not None else None


def _context_is_current(root, hashes, *, max_files=64):
    if (
        not isinstance(hashes, dict)
        or not hashes
        or len(hashes) > max_files
        or any(
            not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
            for digest in hashes.values()
        )
    ):
        raise ValueError("Cleanup review source provenance is malformed")
    return all(_source_hash(root, file) == digest for file, digest in hashes.items())


def _match(items, prefix, label="task"):
    if not isinstance(prefix, str) or not prefix:
        raise ValueError(f"Cleanup {label} ID is empty")
    matches = [item for item in items if item.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError(f"Cleanup {label} ID is unknown or ambiguous")
    return matches[0]


def _tasks(queue, *, scope=None):
    if not isinstance(queue, dict) or queue.get("status") not in {"ready", "clear"}:
        raise ValueError("Cleanup plans require a complete current queue")
    if (
        scope is not None
        and queue.get("project_root", scope["project_root"]) != scope["project_root"]
    ):
        raise ValueError("Cleanup queue belongs to a different project root")
    tasks = {}
    for section in ("tasks", "advisories"):
        rows = queue.get(section, [])
        if not isinstance(rows, list):
            raise ValueError("Cleanup queue tasks are malformed")
        for task in rows:
            if not isinstance(task, dict):
                raise ValueError("Cleanup queue task is malformed")
            if scope is not None and task.get("scope") != scope:
                raise ValueError("Cleanup queue task belongs to a different scan scope")
            identity = task.get("id")
            if (
                not isinstance(identity, str)
                or not _DIGEST.fullmatch(identity)
                or identity in tasks
            ):
                raise ValueError("Cleanup task identity is invalid or duplicated")
            tasks[identity] = task
    return tasks


def _task_step(root, scope, task):
    if task.get("scope") != scope:
        raise ValueError("Cleanup task belongs to a different scan scope")
    file = _relative_file(task.get("file"))
    digest = task.get("source_sha256")
    if (
        not isinstance(digest, str)
        or not _DIGEST.fullmatch(digest)
        or _source_hash(root, file) != digest
    ):
        raise ValueError("Cleanup task source is unavailable or stale; rescan first")
    anchor = task.get("source_anchor")
    if not isinstance(anchor, str) or not anchor:
        raise ValueError("Cleanup task has no source anchor")
    return {
        "id": task["id"],
        "kind": "scanner_task",
        "task_id": task["id"],
        "rule_id": task.get("rule_id"),
        "file": file,
        "source_anchor": anchor,
        "source_sha256": digest,
        "completion": "open",
        "verification_status": "unverified",
    }


def _bucket(root, scope):
    state = load_cleanup_state(root)
    bucket = state["scopes"].get(scope_identity(scope), {})
    if not isinstance(bucket, dict) or (bucket and bucket.get("scope") != scope):
        raise ValueError("Cleanup workspace scope is malformed")
    return bucket


def _plans(bucket):
    plans = bucket.setdefault("plans", {})
    if not isinstance(plans, dict) or any(
        not isinstance(name, str) or not _NAME.fullmatch(name) for name in plans
    ):
        raise ValueError("Cleanup plans are malformed")
    return plans


def _plan(bucket, name, scope):
    plan = _plans(bucket).get(_name(name))
    if plan is None:
        raise ValueError("Cleanup plan is unknown in this scan scope")
    if (
        not isinstance(plan, dict)
        or plan.get("version") != 1
        or plan.get("name") != name
        or plan.get("execution_authorized") is not False
        or plan.get("scope") != scope
        or not isinstance(plan.get("steps"), list)
        or any(
            not isinstance(step, dict) or not isinstance(step.get("id"), str)
            for step in plan["steps"]
        )
        or len({step["id"] for step in plan["steps"]}) != len(plan["steps"])
    ):
        raise ValueError("Cleanup plan is malformed or has an incompatible scope")
    for step in plan["steps"]:
        if (
            not _DIGEST.fullmatch(step["id"])
            or step.get("kind") not in {"scanner_task", "review_advice"}
            or not isinstance(step.get("source_sha256"), str)
            or not _DIGEST.fullmatch(step["source_sha256"])
            or step.get("completion") not in {"open", "completed"}
            or (
                step.get("kind") == "scanner_task"
                and (
                    step.get("task_id") != step["id"]
                    or not isinstance(step.get("source_anchor"), str)
                    or not step["source_anchor"]
                )
            )
        ):
            raise ValueError("Cleanup plan step is malformed")
        _relative_file(step.get("file"))
    return plan


def _mutate(root, scope, callback):
    from skylos.cleanup_state import mutate_cleanup_workspace

    return mutate_cleanup_workspace(root, scope, callback)


def create_cleanup_plan(
    root, scope, queue, name, task_ids, *, prerequisites=(), acceptance_checks=()
):
    """Save explicitly selected scanner tasks; checks/prerequisites are prose only."""
    root = _scope(root, scope)
    name = _name(name)
    tasks = _tasks(queue, scope=scope)
    if not isinstance(task_ids, (list, tuple)) or not task_ids or len(task_ids) > 500:
        raise ValueError("Select between 1 and 500 cleanup tasks")
    identities = [_match(tasks, prefix) for prefix in task_ids]
    if len(set(identities)) != len(identities):
        raise ValueError("Cleanup plan contains duplicate tasks")
    steps = [_task_step(root, scope, tasks[identity]) for identity in identities]
    prerequisites = _text_list(prerequisites, "prerequisites")
    acceptance_checks = _text_list(acceptance_checks, "acceptance checks")

    def save(bucket):
        plans = _plans(bucket)
        if name in plans:
            raise ValueError("Cleanup plan already exists")
        if any(
            _source_hash(root, step["file"]) != step["source_sha256"] for step in steps
        ):
            raise ValueError("Cleanup task source changed before its plan was saved")
        now = _now()
        plans[name] = {
            "version": 1,
            "name": name,
            "scope": deepcopy(scope),
            "created_at": now,
            "updated_at": now,
            "steps": steps,
            "prerequisites": prerequisites,
            "acceptance_checks": acceptance_checks,
            "execution_authorized": False,
        }
        return plans[name]

    return _mutate(root, scope, save)


def _step_status(root, scope, step, tasks):
    if _source_hash(root, step.get("file")) != step.get("source_sha256"):
        return "stale"
    if step.get("kind") == "review_advice":
        hashes = step.get("context_source_hashes", {})
        if not _context_is_current(root, hashes):
            return "stale"
        if "context_dependency_hashes" in step and not _context_is_current(
            root, step["context_dependency_hashes"], max_files=512
        ):
            return "stale"
        return "current"
    task = tasks.get(step.get("task_id"))
    if task is None:
        return "not_reported_in_view"
    if (
        task.get("scope") != scope
        or task.get("source_anchor") != step.get("source_anchor")
        or task.get("source_sha256") != step.get("source_sha256")
    ):
        return "stale"
    return "current"


def view_cleanup_plans(root, scope, queue, name=None):
    """Project freshness without inferring completion from scanner disappearance."""
    root = _scope(root, scope)
    tasks = _tasks(queue, scope=scope)
    bucket = _bucket(root, scope)
    names = [_name(name)] if name is not None else sorted(_plans(bucket))
    result = []
    for plan_name in names:
        result.append(
            _project_plan(root, scope, _plan(bucket, plan_name, scope), tasks)
        )
    return result[0] if name is not None else result


def _project_plan(root, scope, plan, tasks):
    plan = deepcopy(plan)
    for step in plan["steps"]:
        step["refresh_status"] = _step_status(root, scope, step, tasks)
        step["verification_status"] = "unverified"
    plan["status"] = (
        "needs_refresh"
        if any(step["refresh_status"] != "current" for step in plan["steps"])
        else "current"
    )
    plan["completed_steps"] = sum(
        step.get("completion") == "completed" for step in plan["steps"]
    )
    return plan


def _find_step(plan, prefix):
    identity = _match([step["id"] for step in plan["steps"]], prefix, "plan step")
    step = next(step for step in plan["steps"] if step["id"] == identity)
    return step


def move_cleanup_plan_task(root, scope, queue, name, task_id, *, before):
    root = _scope(root, scope)
    tasks = _tasks(queue, scope=scope)

    def move(bucket):
        plan = _plan(bucket, name, scope)
        step = _find_step(plan, task_id)
        target = _find_step(plan, before)
        if step is target:
            raise ValueError("A cleanup step cannot move before itself")
        plan["steps"].remove(step)
        plan["steps"].insert(plan["steps"].index(target), step)
        plan["updated_at"] = _now()
        return _project_plan(root, scope, plan, tasks)

    return _mutate(root, scope, move)


def complete_cleanup_plan_task(root, scope, queue, name, task_id, *, note=""):
    """Record human completion independently of tests, scanner findings and gates."""
    root = _scope(root, scope)
    tasks = _tasks(queue, scope=scope)
    if not isinstance(note, str) or len(note) > 4000:
        raise ValueError("Cleanup completion note is invalid")

    def complete(bucket):
        plan = _plan(bucket, name, scope)
        step = _find_step(plan, task_id)
        freshness = _step_status(root, scope, step, tasks)
        if freshness != "current" and not note.strip():
            raise ValueError("Completing stale or absent cleanup work requires a note")
        step.update(
            completion="completed",
            completed_at=_now(),
            completion_note=note,
            verification_status="unverified",
            completed_with_evidence_status=freshness,
        )
        plan["updated_at"] = _now()
        return _project_plan(root, scope, plan, tasks)

    return _mutate(root, scope, complete)


def _append_review_step(bucket, scope, name, review):
    plan = _plan(bucket, name, scope)
    if len(plan["steps"]) >= 500:
        raise ValueError("Cleanup plan has reached its task limit")
    if any(step["id"] == review["id"] for step in plan["steps"]):
        raise ValueError("Review advice is already in this cleanup plan")
    plan["steps"].append(
        {
            "id": review["id"],
            "kind": "review_advice",
            "review_id": review["id"],
            "file": review["file"],
            "line": review["line"],
            "source_sha256": review["source_sha256"],
            "context_source_hashes": deepcopy(review["context_source_hashes"]),
            "summary": review["summary"],
            "evidence": review["evidence"],
            "suggestion": review["suggestion"],
            "completion": "open",
            "verification_status": "unverified",
            "finding_type": "advice",
        }
    )
    if "context_dependency_hashes" in review:
        plan["steps"][-1]["context_dependency_hashes"] = deepcopy(
            review["context_dependency_hashes"]
        )
    plan["updated_at"] = _now()
    return plan
