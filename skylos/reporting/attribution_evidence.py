"""Bounded readers for recorded attribution, never an AI-content classifier.

Git AI authorship/3.0.0: git-ai-project/git-ai/specs/git_ai_standard_v3.0.0.md
Agent Trace 0.1.0: https://agent-trace.dev/ (storage is implementation-defined).
Records are local assertions, not authenticated proof of who operated a tool.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import subprocess
import time
from datetime import datetime
from pathlib import Path, PurePosixPath
from uuid import UUID

from skylos.constants import SUBPROCESS_TIMEOUT
from skylos.core.git_safety import read_only_git_command, read_only_git_environment
from skylos.core.safe_cache_io import read_project_text_no_symlink

MAX_RECORD_BYTES = 2_000_000
MAX_FILE_BYTES = 2_000_000
MAX_RECORDS = 200
MAX_FILES = 1000
MAX_RANGES = 10_000
MAX_TOTAL_BYTES = 16_000_000
MAX_READ_SECONDS = 5.0
TRACE_DIRS = (".skylos/agent-traces", ".agent-trace")
_SHA_RE = re.compile(r"[a-fA-F0-9]{40}(?:[a-fA-F0-9]{24})?\Z")
_HASH_RE = re.compile(r"sha256:[a-f0-9]{64}\Z")
_SESSION_RE = re.compile(r"s_[a-f0-9]{14}::t_[a-f0-9]{14}\Z")
_HUMAN_RE = re.compile(r"h_[a-f0-9]{14}\Z")
_LEGACY_RE = re.compile(r"(?:[a-f0-9]{16}|[a-f0-9]{7})\Z")


def canonical_agent_name(value):
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()[:128]
    aliases = {
        "claude-code": "claude",
        "claude_code": "claude",
        "Claude Code": "claude",
        "codex-cli": "codex",
        "codex_cli": "codex",
        "github-copilot": "copilot",
        "cursor-agent": "cursor",
        "aider-chat": "aider",
    }
    lowered = value.lower()
    return aliases.get(
        value,
        aliases.get(
            lowered,
            lowered
            if lowered
            in {
                "claude",
                "codex",
                "cursor",
                "copilot",
                "aider",
                "devin",
                "jules",
                "amazon-q",
            }
            else value,
        ),
    )


def content_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_relative_path(value) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    if "\\" in value or any(ord(c) < 32 for c in value):
        return None
    path = PurePosixPath(value)
    if (
        not path.parts
        or path.is_absolute()
        or ":" in path.parts[0]
        or any(part in {"", ".", "..", ".git"} for part in value.split("/"))
    ):
        return None
    return path.as_posix()


def read_source(root: Path, path: str) -> str | None:
    if safe_relative_path(path) is None:
        return None
    return read_project_text_no_symlink(
        root, path, max_bytes=MAX_FILE_BYTES, newline=""
    )


def _read_current(root, path, status):
    if time.monotonic() >= status.get("_deadline", float("inf")):
        status["limited"] = True
        return None
    cache = status.setdefault("_source_cache", {})
    if path in cache:
        return cache[path]
    if len(cache) >= MAX_FILES or status.get("_source_bytes", 0) >= MAX_TOTAL_BYTES:
        status["limited"] = True
        return None
    text = read_source(root, path)
    size = len(text.encode("utf-8")) if text is not None else 0
    if status.get("_source_bytes", 0) + size > MAX_TOTAL_BYTES:
        status["limited"] = True
        return None
    status["_source_bytes"] = status.get("_source_bytes", 0) + size
    cache[path] = text
    return text


def _read_revision(root, revision, path, status):
    if time.monotonic() >= status.get("_deadline", float("inf")):
        status["limited"] = True
        return None
    if not _valid_revision(revision):
        return None
    cache = status.setdefault("_revision_cache", {})
    key = (revision, path)
    if key not in cache:
        if (
            len(cache) >= MAX_FILES
            or status.get("_revision_bytes", 0) >= MAX_TOTAL_BYTES
        ):
            status["limited"] = True
            return None
        text = revision_source(root, revision, path)
        size = len(text.encode()) if text is not None else 0
        if status.get("_revision_bytes", 0) + size > MAX_TOTAL_BYTES:
            status["limited"] = True
            return None
        status["_revision_bytes"] = status.get("_revision_bytes", 0) + size
        cache[key] = text
    return cache[key]


def _git(root, args, *, limit=MAX_RECORD_BYTES) -> str | None:
    # cat-file size is checked before reading blobs; subprocess output has a
    # ceiling even for corrupted/untrusted notes. No hooks, filters or fetches.
    try:
        with subprocess.Popen(
            read_only_git_command(args),
            cwd=root,
            env=read_only_git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as proc:
            timeout = min(SUBPROCESS_TIMEOUT, MAX_READ_SECONDS)
            chunks, total, deadline = [], 0, time.monotonic() + timeout
            if os.name == "nt":
                # Git blob sizes are checked separately. Windows cannot select
                # anonymous pipe handles; communicate still bounds its time.
                try:
                    output, _ = proc.communicate(timeout=timeout)
                except subprocess.SubprocessError:
                    proc.kill()
                    return None
                return (
                    output.decode("utf-8")
                    if proc.returncode == 0 and len(output) <= limit
                    else None
                )
            os.set_blocking(proc.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        proc.kill()
                        return None
                    ready = selector.select(remaining)
                    if not ready:
                        proc.kill()
                        return None
                    chunk = os.read(proc.stdout.fileno(), min(65536, limit + 1 - total))
                    if not chunk:
                        selector.unregister(proc.stdout)
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > limit:
                        proc.kill()
                        return None
            try:
                proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.SubprocessError:
                proc.kill()
                return None
            if proc.returncode:
                return None
        return b"".join(chunks).decode("utf-8")
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return None


def current_revision(root) -> str | None:
    value = (_git(root, ["rev-parse", "HEAD"], limit=128) or "").strip()
    return value if _SHA_RE.fullmatch(value) else None


def _valid_revision(value):
    return isinstance(value, str) and bool(_SHA_RE.fullmatch(value))


def revision_source(root, revision, path) -> str | None:
    if not _valid_revision(revision) or safe_relative_path(path) is None:
        return None
    spec = f"{revision}:{path}"
    size = _git(root, ["cat-file", "-s", spec], limit=32)
    if size is None or not size.strip().isdigit() or int(size) > MAX_FILE_BYTES:
        return None
    # A Git symlink blob must not become evidence for the referenced target.
    entry = _git(root, ["ls-tree", revision, "--", path], limit=8192)
    if not entry or not entry.startswith(("100644 blob ", "100755 blob ")):
        return None
    return _git(root, ["cat-file", "blob", spec], limit=MAX_FILE_BYTES)


def valid_ranges(ranges, line_count) -> list[tuple[int, int]] | None:
    if not isinstance(ranges, list) or len(ranges) > MAX_RANGES:
        return None
    result = []
    for item in ranges:
        if isinstance(item, dict):
            start, end = item.get("start_line"), item.get("end_line")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            start, end = item
        else:
            return None
        if (
            type(start) is not int
            or type(end) is not int
            or not 1 <= start <= end <= line_count
        ):
            return None
        result.append((start, end))
    return result


def _short(value) -> str | None:
    return value[:128] if isinstance(value, str) and value.strip() else None


def parse_git_ai_note(text: str) -> dict[str, list[dict]]:
    """Read the published two-section format, including known-human entries."""
    if len(text.encode("utf-8")) > MAX_RECORD_BYTES or "\n---\n" not in text:
        return {}
    attestations, raw_metadata = text.split("\n---\n", 1)
    try:
        metadata = json.loads(raw_metadata)
    except (ValueError, RecursionError):
        return {}
    if (
        not isinstance(metadata, dict)
        or metadata.get("schema_version") != "authorship/3.0.0"
    ):
        return {}
    if not _valid_revision(metadata.get("base_commit_sha")):
        return {}
    maps = {name: metadata.get(name, {}) for name in ("prompts", "sessions", "humans")}
    if any(not isinstance(value, dict) for value in maps.values()):
        return {}
    files, path, count = {}, None, 0
    for line in attestations.splitlines():
        if not line:
            continue
        if not line.startswith(" "):
            try:
                candidate = json.loads(line) if line.startswith('"') else line
            except (ValueError, RecursionError):
                return {}
            path = safe_relative_path(candidate)
            if path is None or len(files) >= MAX_FILES:
                return {}
            files.setdefault(path, [])
            continue
        if path is None or not line.startswith("  ") or line.startswith("   "):
            return {}
        pieces = line[2:].split(" ")
        if len(pieces) != 2:
            return {}
        key, spec = pieces
        if _SESSION_RE.fullmatch(key):
            record = maps["sessions"].get(key.split("::", 1)[0])
            category = "ai"
        elif _HUMAN_RE.fullmatch(key):
            record = maps["humans"].get(key)
            category = "human"
        elif _LEGACY_RE.fullmatch(key):
            record = maps["prompts"].get(key)
            category = "ai"
        else:
            return {}
        if not isinstance(record, dict):
            return {}
        ranges, previous = [], 0
        for token in spec.split(","):
            if not re.fullmatch(r"[1-9][0-9]*(?:-[1-9][0-9]*)?", token):
                return {}
            bounds = token.split("-")
            if any(len(bound) > 7 for bound in bounds):
                return {}
            start, end = int(bounds[0]), int(bounds[-1])
            if start <= previous or end < start or end > MAX_FILE_BYTES:
                return {}
            ranges.append((start, end))
            previous = end
            count += 1
            if count > MAX_RANGES:
                return {}
        agent = record.get("agent_id", {})
        if category == "ai" and (
            not isinstance(agent, dict) or not _short(agent.get("tool"))
        ):
            return {}
        if category == "human" and not _short(record.get("author")):
            return {}
        files[path].append(
            {
                "type": category,
                "agent_name": canonical_agent_name(agent.get("tool")),
                "agent_lines": ranges,
                "model_id": _short(agent.get("model")),
                "session_id": _short(agent.get("id")),
                "evidence_source": "git_ai",
            }
        )
    return files


def _read_git_ai(root, status) -> dict[str, list[dict]]:
    revision = current_revision(root)
    status["_head"] = revision
    if not revision:
        return {}
    # Resolve the note first so its blob size is bounded before allocation.
    note_id = (
        _git(root, ["notes", "--ref=refs/notes/ai", "list", revision], limit=128) or ""
    ).strip()
    if not _SHA_RE.fullmatch(note_id):
        return {}
    size = _git(root, ["cat-file", "-s", note_id], limit=32)
    if size is None or not size.strip().isdigit() or int(size) > MAX_RECORD_BYTES:
        status["rejected_records"] += 1
        return {}
    note = _git(root, ["cat-file", "blob", note_id])
    if note is None:
        return {}
    parsed = parse_git_ai_note(note)
    status["git_ai_note_present"] = True
    if not parsed:
        status["rejected_records"] += 1
    result = {}
    for path, contributors in parsed.items():
        current = _read_current(root, path, status)
        committed = _read_revision(root, revision, path, status)
        if current is None or committed != current:
            status["stale_files"] += 1
            continue
        line_count = len(current.splitlines())
        if any(
            valid_ranges(c["agent_lines"], line_count) is None for c in contributors
        ):
            status["rejected_records"] += 1
            continue
        result[path] = [
            {**c, "content_hash": content_hash(current), "revision": revision}
            for c in contributors
        ]
    return result


def _trace_contributors(record, root, status):
    if not isinstance(record, dict) or record.get("version") != "0.1.0":
        return {}
    if not _short(record.get("id")) or not _short(record.get("timestamp")):
        return {}
    try:
        UUID(record["id"])
        timestamp = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return {}
    except (ValueError, AttributeError, TypeError):
        return {}
    files = record.get("files")
    if not isinstance(files, list) or len(files) > MAX_FILES:
        return {}
    metadata = record.get("metadata") or {}
    vendor = metadata.get("dev.skylos", {}) if isinstance(metadata, dict) else {}
    hashes = vendor.get("files", {}) if isinstance(vendor, dict) else {}
    vcs = record.get("vcs") or {}
    revision = (
        vcs.get("revision")
        if isinstance(vcs, dict) and vcs.get("type") == "git"
        else None
    )
    tool = record.get("tool") or {}
    agent_name = _short(tool.get("name")) if isinstance(tool, dict) else None
    details = vendor.get("contributors", {}) if isinstance(vendor, dict) else {}
    head = status.get("_head")
    result, range_count = {}, 0
    for file in files:
        if not isinstance(file, dict):
            return {}
        path = safe_relative_path(file.get("path"))
        current = _read_current(root, path, status) if path else None
        if current is None:
            status["stale_files"] += 1
            continue
        entry = hashes.get(path, {}) if isinstance(hashes, dict) else {}
        bound_hash = entry.get("content_hash") if isinstance(entry, dict) else None
        if isinstance(bound_hash, str) and _HASH_RE.fullmatch(bound_hash):
            bound = bound_hash == content_hash(current)
        else:
            bound = _read_revision(root, revision, path, status) == current
        if not bound:
            status["stale_files"] += 1
            continue
        conversations = file.get("conversations")
        if not isinstance(conversations, list) or len(conversations) > MAX_RANGES:
            return {}
        committed_revision = (
            head
            if head and _read_revision(root, head, path, status) == current
            else None
        )
        for index, conversation in enumerate(conversations):
            if not isinstance(conversation, dict):
                return {}
            contributor = conversation.get("contributor") or {}
            if not isinstance(contributor, dict):
                return {}
            default_type = contributor.get("type")
            if default_type not in {"ai", "human", "mixed", "unknown"}:
                return {}
            ranges = conversation.get("ranges")
            valid = valid_ranges(ranges, len(current.splitlines()))
            if valid is None:
                return {}
            identities = details.get(path, []) if isinstance(details, dict) else []
            identity = (
                identities[index]
                if isinstance(identities, list) and index < len(identities)
                else {}
            )
            if not isinstance(identity, dict):
                identity = {}
            for item, bounds in zip(ranges, valid):
                override = (
                    item.get("contributor", contributor)
                    if isinstance(item, dict)
                    else contributor
                )
                if not isinstance(override, dict) or override.get("type") not in {
                    "ai",
                    "human",
                    "mixed",
                    "unknown",
                }:
                    return {}
                # A range hash is an extra check, never a relocation heuristic.
                expected = item.get("content_hash") if isinstance(item, dict) else None
                if expected is not None and not isinstance(expected, str):
                    return {}
                if expected and expected.startswith("sha256:"):
                    lines = current.splitlines(keepends=True)
                    if expected != content_hash(
                        "".join(lines[bounds[0] - 1 : bounds[1]])
                    ):
                        return {}
                result.setdefault(path, []).append(
                    {
                        "type": override["type"],
                        "agent_name": canonical_agent_name(identity.get("agent_name"))
                        or canonical_agent_name(agent_name),
                        "agent_lines": [bounds],
                        "model_id": _short(override.get("model_id")),
                        "session_id": _short(identity.get("session_id"))
                        or _short(vendor.get("session_id")),
                        "evidence_source": "agent_trace",
                        "content_hash": content_hash(current),
                        "revision": committed_revision,
                    }
                )
                range_count += 1
                if range_count > MAX_RANGES:
                    return {}
    return result


def read_attribution_evidence(root) -> tuple[dict[str, list[dict]], dict]:
    root = Path(root).resolve()
    status = {
        "recorded_files": 0,
        "rejected_records": 0,
        "stale_files": 0,
        "capture_gaps": 0,
        "limited": False,
        "coverage": "partial",
        "git_ai_note_present": False,
        "_deadline": time.monotonic() + MAX_READ_SECONDS,
    }
    result = _read_git_ai(root, status)
    range_budget = MAX_RANGES - sum(
        len(c["agent_lines"]) for cs in result.values() for c in cs
    )
    candidates = []
    for relative in TRACE_DIRS:
        directory = root / relative
        # Reject parent links too; project-relative reads guard each component.
        if any(
            (root / Path(*Path(relative).parts[:n])).is_symlink()
            for n in range(1, len(Path(relative).parts) + 1)
        ):
            continue
        try:
            if directory.is_dir():
                for path in directory.iterdir():
                    if path.name.endswith(".json"):
                        candidates.append(path)
                        if len(candidates) > MAX_RECORDS:
                            status["limited"] = True
                            break
        except OSError:
            status["rejected_records"] += 1
        if len(candidates) > MAX_RECORDS:
            break
    if len(candidates) >= MAX_RECORDS:
        status["limited"] = True
    total_bytes = 0
    for path in sorted(candidates)[:MAX_RECORDS]:
        if time.monotonic() >= status["_deadline"]:
            status["limited"] = True
            break
        raw = read_project_text_no_symlink(
            root, path, max_bytes=MAX_RECORD_BYTES, newline=""
        )
        if raw is None:
            status["rejected_records"] += 1
            continue
        total_bytes += len(raw.encode("utf-8"))
        if total_bytes > MAX_TOTAL_BYTES:
            status["limited"] = True
            break
        try:
            record = json.loads(raw)
            metadata = record.get("metadata") if isinstance(record, dict) else None
            vendor = (
                metadata.get("dev.skylos", {}) if isinstance(metadata, dict) else {}
            )
            if isinstance(vendor, dict) and vendor.get("capture") in {
                "missing_checkpoint",
                "shell_diff_unknown",
                "incomplete_diff_unknown",
            }:
                status["capture_gaps"] += 1
            parsed = _trace_contributors(record, root, status)
        except (ValueError, RecursionError, TypeError, AttributeError):
            parsed = {}
        if not parsed:
            status["rejected_records"] += 1
        range_count = sum(len(c["agent_lines"]) for cs in parsed.values() for c in cs)
        if range_count > range_budget:
            status["limited"] = True
            continue
        range_budget -= range_count
        for file_path, contributors in parsed.items():
            result.setdefault(file_path, []).extend(contributors)
    status["recorded_files"] = len(result)
    for private in (
        "_source_cache",
        "_source_bytes",
        "_revision_cache",
        "_revision_bytes",
        "_deadline",
        "_head",
    ):
        status.pop(private, None)
    return result, status
