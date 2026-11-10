"""Durable subjective cleanup advice, separate from scanner findings and gates."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

from skylos.cleanup_plans import (
    _append_review_step,
    _bucket,
    _context_is_current,
    _DIGEST,
    _match,
    _mutate,
    _now,
    _relative_file,
    _scope,
    _tasks,
)
from skylos.core.safe_cache_io import read_project_text_no_symlink


def _reviews(bucket):
    reviews = bucket.setdefault("reviews", {})
    if not isinstance(reviews, dict) or any(
        not isinstance(identity, str) or not _DIGEST.fullmatch(identity)
        for identity in reviews
    ):
        raise ValueError("Stored cleanup reviews are malformed")
    return reviews


def _provenance(model, provider, revision):
    for value in (model, provider):
        if not isinstance(value, str) or not value.strip() or len(value) > 200:
            raise ValueError("Cleanup review requires a model and provider")
    if revision is not None and (
        not isinstance(revision, str) or not revision.strip() or len(revision) > 200
    ):
        raise ValueError("Cleanup review revision is invalid")
    return {
        "kind": "model_context_review",
        "model": model,
        "provider": provider,
        "revision": revision,
        "revision_known": revision is not None,
    }


def _context_sources(root, context):
    if not isinstance(context, dict) or not isinstance(context.get("files"), list):
        raise ValueError("Cleanup review source context is malformed")
    files = context["files"]
    if not files or len(files) > 64:
        raise ValueError("Cleanup review needs bounded source context")
    excerpts, hashes = {}, {}
    used = 0
    for file in files:
        if not isinstance(file, dict):
            raise ValueError("Cleanup review source excerpt is malformed")
        path = _relative_file(file.get("file"))
        start, excerpt = file.get("start_line"), file.get("source")
        if (
            path in excerpts
            or type(start) is not int
            or start < 1
            or not isinstance(excerpt, str)
            or not excerpt
        ):
            raise ValueError("Cleanup review source excerpt is invalid or duplicated")
        used += len(excerpt)
        if used > 128_000:
            raise ValueError("Cleanup review source context exceeds its budget")
        source = read_project_text_no_symlink(
            root, path, max_bytes=2_000_000, newline=""
        )
        if source is None:
            raise ValueError("Cleanup review source is unavailable")
        lines = source.splitlines()
        excerpt_lines = excerpt.splitlines()
        observed = "\n".join(lines[start - 1 : start - 1 + len(excerpt_lines)])
        if not observed.startswith(excerpt):
            raise ValueError("Cleanup review context changed before it could be stored")
        excerpts[path] = {"start_line": start, "lines": excerpt_lines}
        hashes[path] = sha256(source.encode("utf-8")).hexdigest()
    limitations = context.get("limitations", [])
    if (
        not isinstance(limitations, list)
        or len(limitations) > 100
        or any(not isinstance(value, str) or len(value) > 4000 for value in limitations)
    ):
        raise ValueError("Cleanup review context limitations are malformed")
    return excerpts, hashes, list(limitations)


def store_cleanup_review(
    root, scope, review, context, *, model, provider, revision=None
):
    """Persist validated, cited advice; never import it into raw detector output."""
    root = _scope(root, scope)
    provenance = _provenance(model, provider, revision)
    if (
        not isinstance(review, dict)
        or review.get("status") != "reviewed"
        or review.get("kind") != "subjective_advice"
    ):
        raise ValueError("Only a completed advisory cleanup review can be stored")
    advice = review.get("advice")
    if not isinstance(advice, list) or len(advice) > 10:
        raise ValueError("Cleanup review advice is malformed or oversized")
    excerpts, hashes, limitations = _context_sources(root, context)
    has_dependencies = "context_dependency_hashes" in context
    dependencies = deepcopy(context.get("context_dependency_hashes"))
    if has_dependencies and not _context_is_current(root, dependencies, max_files=512):
        raise ValueError(
            "Cleanup review graph or caller evidence changed before storage"
        )
    records = []
    for row in advice:
        if not isinstance(row, dict) or row.get("finding_type", "advice") != "advice":
            raise ValueError("Subjective cleanup review cannot create scanner defects")
        if any(
            not isinstance(row.get(key), str)
            or not row[key].strip()
            or len(row[key]) > 4000
            for key in ("summary", "evidence", "suggestion")
        ):
            raise ValueError("Cleanup review needs concrete advisory evidence")
        path, line = _relative_file(row.get("file")), row.get("line")
        excerpt = excerpts.get(path)
        if (
            excerpt is None
            or type(line) is not int
            or not excerpt["start_line"]
            <= line
            < excerpt["start_line"] + len(excerpt["lines"])
        ):
            raise ValueError("Cleanup review cites unavailable source context")
        if row.get("confidence") not in {"low", "medium", "high"}:
            raise ValueError("Cleanup review confidence is invalid")
        record = {
            "scope": deepcopy(scope),
            "file": path,
            "line": line,
            "summary": row["summary"],
            "evidence": row["evidence"],
            "suggestion": row["suggestion"],
            "confidence": row["confidence"],
            "finding_type": "advice",
            "source_sha256": hashes[path],
            "context_source_hashes": deepcopy(hashes),
            "provenance": provenance,
            "citations": [
                {
                    "file": path,
                    "line": line,
                    "text": excerpt["lines"][line - excerpt["start_line"]],
                }
            ],
            "context_limitations": limitations,
            "coverage": "bounded",
        }
        if has_dependencies:
            record["context_dependency_hashes"] = deepcopy(dependencies)
        record["id"] = sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
        records.append(record)

    def save(bucket):
        if not _context_is_current(root, hashes):
            raise ValueError("Cleanup review source changed before it could be stored")
        if has_dependencies and not _context_is_current(
            root, dependencies, max_files=512
        ):
            raise ValueError(
                "Cleanup review graph or caller evidence changed before storage"
            )
        stored = _reviews(bucket)
        now = _now()
        result = []
        for record in records:
            previous = stored.get(record["id"], {})
            if not isinstance(previous, dict):
                raise ValueError("Stored cleanup review is malformed")
            stored[record["id"]] = {
                **record,
                "created_at": previous.get("created_at", now),
                "reviewed_at": now,
                "refresh_status": "current",
                "promoted_plans": deepcopy(previous.get("promoted_plans", [])),
            }
            result.append(stored[record["id"]])
        return result

    return _mutate(root, scope, save)


def _freshness(root, scope, record, *, revision=None):
    if not isinstance(record, dict) or record.get("scope") != scope:
        raise ValueError("Stored cleanup review has an incompatible scope")
    if (
        not isinstance(record.get("id"), str)
        or not _DIGEST.fullmatch(record["id"])
        or type(record.get("line")) is not int
        or record["line"] < 1
        or any(
            not isinstance(record.get(key), str) or not record[key].strip()
            for key in ("summary", "evidence", "suggestion")
        )
    ):
        raise ValueError("Stored cleanup review evidence is malformed")
    hashes = record.get("context_source_hashes")
    if (
        not isinstance(hashes, dict)
        or not hashes
        or any(
            not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
            for digest in hashes.values()
        )
        or record.get("source_sha256") != hashes.get(record.get("file"))
        or record.get("finding_type") != "advice"
    ):
        raise ValueError("Stored cleanup review has no source provenance")
    if not _context_is_current(root, hashes):
        return "stale"
    if "context_dependency_hashes" in record and not _context_is_current(
        root, record["context_dependency_hashes"], max_files=512
    ):
        return "stale"
    provenance = record.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("Stored cleanup review provenance is malformed")
    if revision is not None and provenance.get("revision") != revision:
        return "stale"
    return "current"


def view_cleanup_reviews(root, scope, *, revision=None):
    root = _scope(root, scope)
    result = []
    for identity, record in sorted(_reviews(_bucket(root, scope)).items()):
        if not isinstance(record, dict) or record.get("id") != identity:
            raise ValueError("Stored cleanup review identity is malformed")
        current = deepcopy(record)
        current["refresh_status"] = _freshness(root, scope, record, revision=revision)
        result.append(current)
    return result


def promote_cleanup_review(root, scope, queue, review_id, plan_name, *, revision=None):
    """Explicitly add current advice to a plan; it remains unverified advice."""
    root = _scope(root, scope)
    _tasks(queue, scope=scope)

    def promote(bucket):
        reviews = _reviews(bucket)
        identity = _match(reviews, review_id, "review")
        review = reviews[identity]
        if _freshness(root, scope, review, revision=revision) != "current":
            raise ValueError("Cleanup review is stale; review current source first")
        plan = _append_review_step(bucket, scope, plan_name, review)
        promoted = review.setdefault("promoted_plans", [])
        if not isinstance(promoted, list):
            raise ValueError("Stored cleanup review promotion history is malformed")
        promoted.append(plan_name)
        return plan

    return _mutate(root, scope, promote)
