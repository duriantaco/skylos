"""Record actual before/after tool changes using Agent Trace 0.1.0.

Capture is best effort and local. Shell execution and missing/overlapping
checkpoints remain unknown. No source contents or prompts are in durable traces.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from skylos.core.safe_cache_io import (
    project_cache_lock,
    read_project_text_no_symlink,
    save_project_json_cache,
)
from skylos.reporting.attribution_evidence import (
    MAX_RECORD_BYTES,
    MAX_RECORDS,
    _git,
    content_hash,
    read_attribution_evidence,
    read_source,
    safe_relative_path,
)

MAX_CAPTURE_FILES = 100
MAX_CAPTURE_BYTES = 8_000_000
CHECKPOINT_TTL = 300
STATE_PATH = ".skylos/cache/attribution-checkpoints.json"
LOCK_PATH = ".skylos/cache/attribution-checkpoints.lock"
MAX_PENDING = 20


def _id(value):
    return hashlib.sha256(str(value or "default").encode()).hexdigest()[:32]


def _key(payload):
    # A per-tool id disambiguates parallel calls. Older clients are supported
    # sequentially; overlapping calls invalidate the checkpoint.
    session = payload.get("session_id") or payload.get("conversation_id")
    tool_id = payload.get("tool_use_id") or payload.get("tool_call_id")
    return _id(f"{session}:{tool_id or payload.get('tool_name', 'cursor-edit')}")


def _state(root):
    raw = read_project_text_no_symlink(
        root, STATE_PATH, max_bytes=MAX_CAPTURE_BYTES * 2
    )
    try:
        result = json.loads(raw) if raw else {}
    except (ValueError, RecursionError):
        return {}
    return result if isinstance(result, dict) else {}


def _save(root, state):
    serialized = json.dumps(state)
    if len(serialized.encode()) > MAX_CAPTURE_BYTES * 2:
        return False
    return save_project_json_cache(root, STATE_PATH, state)


def _relative(raw, root, base):
    if not isinstance(raw, str):
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = base / path
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        return None
    return safe_relative_path(relative)


def _paths(payload, root, *, shell=False):
    if shell:
        listed = _git(
            root,
            ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            limit=100_000,
        )
        if listed is None:
            return [], True
        paths = [
            p
            for p in listed.split("\0")
            if p and not p.startswith((".skylos/", ".git/"))
        ]
        return paths[:MAX_CAPTURE_FILES], len(paths) > MAX_CAPTURE_FILES
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return [], True
    base = Path(payload.get("cwd") or root)
    if not base.is_absolute():
        base = root / base
    raw_paths = [tool_input.get("file_path") or payload.get("file_path")]
    command = tool_input.get("command")
    if isinstance(command, str) and "*** Begin Patch" in command:
        raw_paths = []
        for line in command.splitlines():
            for prefix in (
                "*** Update File: ",
                "*** Add File: ",
                "*** Delete File: ",
                "*** Move to: ",
            ):
                if line.startswith(prefix):
                    raw_paths.append(line[len(prefix) :])
    paths = list(
        dict.fromkeys(p for raw in raw_paths if (p := _relative(raw, root, base)))
    )
    return paths[:MAX_CAPTURE_FILES], len(paths) > MAX_CAPTURE_FILES or not paths


def capture_before(root, client, payload, *, shell=False):
    root = Path(root).resolve()
    paths, limited = _paths(payload, root, shell=shell)
    evidence, _ = read_attribution_evidence(root)
    files, total = {}, 0
    for path in paths:
        text = read_source(root, path)
        # Distinguish a genuinely missing file from unreadable/symlink/oversize.
        if text is None and (root / path).exists():
            limited = True
            continue
        total += len((text or "").encode())
        if total > MAX_CAPTURE_BYTES:
            limited = True
            break
        files[path] = {"text": text, "contributors": evidence.get(path, [])}
    with project_cache_lock(root, LOCK_PATH) as locked:
        if not locked:
            return False
        state = _state(root)
        now = time.time()
        state = {
            k: v
            for k, v in state.items()
            if isinstance(v, dict) and now - v.get("at", 0) < CHECKPOINT_TTL
        }
        key = _key(payload)
        overlap = key in state
        for pending in state.values():
            if set(files) & set(pending.get("files", {})):
                pending["overlap"] = True
                overlap = True
        if len(state) >= MAX_PENDING and key not in state:
            return False
        state[key] = {
            "at": now,
            "files": files,
            "shell": shell,
            "limited": limited,
            "overlap": overlap,
            "client": client,
            "tool_name": payload.get("tool_name"),
        }
        return _save(root, state)


def _ranges(lines):
    result = []
    for line in sorted(set(lines)):
        if result and line == result[-1][1] + 1:
            result[-1][1] = line
        else:
            result.append([line, line])
    return result


def _expected_edit(before, after, payload, path, root):
    """Check direct-tool output against its input; never use text-search ranges."""
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return False
    tool = payload.get("tool_name")
    if tool == "Write":
        return (
            isinstance(tool_input.get("content"), str)
            and tool_input["content"] == after
        )
    if tool in {"Edit", "MultiEdit"}:
        expected = before or ""
        edits = tool_input.get("edits") if tool == "MultiEdit" else [tool_input]
        if not isinstance(edits, list):
            return False
        for edit in edits:
            if not isinstance(edit, dict):
                return False
            old, new = edit.get("old_string"), edit.get("new_string")
            if not isinstance(old, str) or not old or not isinstance(new, str):
                return False
            if edit.get("replace_all"):
                expected = expected.replace(old, new)
            elif expected.count(old) == 1:
                expected = expected.replace(old, new, 1)
            else:
                return False
        return expected == after
    # Patch tools require exact pre/post snapshots. Its recorded positions are
    # calculated from the actual diff; no approximate tool-returned ranges.
    if tool == "apply_patch":
        return _expected_patch(
            before,
            after,
            tool_input.get("command"),
            path,
            root,
            Path(payload.get("cwd") or root),
        )
    return False


def _expected_patch(before, after, patch, path, root, base):
    if (
        not isinstance(patch, str)
        or "*** Begin Patch" not in patch
        or "*** Move to:" in patch
    ):
        return False
    selected, operation, chunks, old, new = False, None, [], [], []

    def flush():
        if old or new:
            chunks.append(("".join(old), "".join(new)))
        old.clear()
        new.clear()

    for line in patch.splitlines():
        if line.startswith(
            ("*** Update File: ", "*** Add File: ", "*** Delete File: ")
        ):
            flush()
            if selected:
                break
            prefix, raw = line.split(": ", 1)
            selected = _relative(raw, root, base) == path
            operation = prefix
        elif selected and (line.startswith("@@") or line.startswith("*** ")):
            flush()
        elif selected:
            if not line or line[0] not in {" ", "+", "-"}:
                return False
            text = line[1:] + "\n"
            if line[0] in {" ", "-"}:
                old.append(text)
            if line[0] in {" ", "+"}:
                new.append(text)
    flush()
    if operation == "*** Add File" and before is None:
        return "".join(n for _, n in chunks) == after
    if operation != "*** Update File" or before is None:
        return False
    expected = before
    for old_text, new_text in chunks:
        if not old_text or expected.count(old_text) != 1:
            return False
        expected = expected.replace(old_text, new_text, 1)
    return bool(chunks) and expected == after


def _contributions(before, after, previous, *, client, model_id, known):
    old, new = (before or "").splitlines(keepends=True), after.splitlines(keepends=True)
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    changed, mapping = [], {}
    old_counts, new_counts = Counter(old), Counter(new)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                # Repeated equal lines cannot establish which occurrence kept
                # its historical writer. Drop their ownership conservatively.
                if old_counts[old[i1 + offset]] == new_counts[new[j1 + offset]] == 1:
                    mapping[i1 + offset + 1] = j1 + offset + 1
        elif tag in {"insert", "replace"}:
            changed.extend(range(j1 + 1, j2 + 1))
    result = []
    for contributor in previous:
        retained = [
            new_line
            for old_line, new_line in mapping.items()
            if any(
                start <= old_line <= end
                for start, end in contributor.get("agent_lines", [])
            )
        ]
        if retained:
            result.append({**contributor, "agent_lines": _ranges(retained)})
    # Duplicate content can make a canonical diff pick another occurrence.
    # Its writer stays unknown, even when the tool's resulting bytes validate.
    certain = [n for n in changed if known and new_counts[new[n - 1]] == 1]
    certain_set = set(certain)
    uncertain = [n for n in changed if n not in certain_set]
    for category, owned in (("ai", certain), ("unknown", uncertain)):
        if owned:
            result.append(
                {
                    "type": category,
                    "agent_name": client,
                    "agent_lines": _ranges(owned),
                    "model_id": model_id,
                }
            )
    return result


def capture_after(root, client, payload, *, shell=False):
    root = Path(root).resolve()
    with project_cache_lock(root, LOCK_PATH) as locked:
        if not locked:
            return False
        state = _state(root)
        checkpoint = state.pop(_key(payload), None)
        _save(root, state)
    now = time.time()
    if (
        not isinstance(checkpoint, dict)
        or now - checkpoint.get("at", 0) >= CHECKPOINT_TTL
    ):
        return _write_trace(root, client, payload, [], {}, {}, "missing_checkpoint")
    shell = shell or checkpoint.get("shell", False)
    files = checkpoint.get("files", {})
    if shell:
        # Newly created shell files were not in the before listing.
        for path in _paths(payload, root, shell=True)[0]:
            files.setdefault(path, {"text": None, "contributors": []})
    trace_files, hashes, details = [], {}, {}
    model_id = payload.get("model_id") or payload.get("model")
    if not isinstance(model_id, str) or len(model_id) > 128:
        model_id = None
    for path, entry in files.items():
        after = read_source(root, path)
        before = entry.get("text")
        if after is None or before == after:
            continue
        failed = payload.get("hook_event_name") == "PostToolUseFailure"
        known = not (
            shell or failed or checkpoint.get("overlap") or checkpoint.get("limited")
        )
        known = known and _expected_edit(before, after, payload, path, root)
        contributors = _contributions(
            before,
            after,
            entry.get("contributors", []),
            client=client,
            model_id=model_id,
            known=known,
        )
        if not contributors:
            continue
        conversations = []
        details[path] = []
        for contributor in contributors:
            ranges = []
            lines = after.splitlines(keepends=True)
            for start, end in contributor["agent_lines"]:
                ranges.append(
                    {
                        "start_line": start,
                        "end_line": end,
                        "content_hash": content_hash("".join(lines[start - 1 : end])),
                    }
                )
            identity = {"type": contributor.get("type", "unknown")}
            if contributor.get("model_id"):
                identity["model_id"] = contributor["model_id"]
            conversations.append({"contributor": identity, "ranges": ranges})
            details[path].append(
                {
                    "agent_name": contributor.get("agent_name"),
                    "session_id": contributor.get("session_id"),
                }
            )
        trace_files.append({"path": path, "conversations": conversations})
        hashes[path] = {
            "content_hash": content_hash(after),
            "before_hash": content_hash(before or ""),
        }
    capture = "shell_diff_unknown" if shell else "tool_diff"
    if checkpoint.get("limited") or checkpoint.get("overlap"):
        capture = "incomplete_diff_unknown"
    return _write_trace(root, client, payload, trace_files, hashes, details, capture)


def _write_trace(root, client, payload, files, hashes, details, capture):
    directory = root / ".skylos/agent-traces"
    # write_text_no_symlink guards every parent. Refuse unreadable/link dirs.
    if directory.is_symlink() or (root / ".skylos").is_symlink():
        return False
    record = {
        "version": "0.1.0",
        "id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": {"name": client},
        "files": files,
        "metadata": {
            "dev.skylos": {
                "session_id": _id(
                    payload.get("session_id") or payload.get("conversation_id")
                ),
                "tool_use_id": _id(
                    payload.get("tool_use_id") or payload.get("tool_call_id")
                ),
                "capture": capture,
                "coverage": "partial",
                "files": hashes,
                "contributors": details,
            }
        },
    }
    serialized = json.dumps(record, indent=2)
    if len(serialized.encode()) > MAX_RECORD_BYTES:
        return False
    # Keep the current per-file state useful after the bounded audit history
    # fills up. This is also a valid Agent Trace record, with vendor metadata
    # preserving the actual tool for each contributor.
    with project_cache_lock(root, ".skylos/cache/attribution-index.lock") as locked:
        if not locked:
            return False
        index_path = directory / "current.json"
        raw = read_project_text_no_symlink(root, index_path, max_bytes=MAX_RECORD_BYTES)
        try:
            previous = json.loads(raw) if raw else {}
        except (ValueError, RecursionError):
            return False
        if not isinstance(previous, dict):
            return False
        old_files = previous.get("files", [])
        old_metadata = previous.get("metadata") or {}
        if not isinstance(old_metadata, dict):
            return False
        old_vendor = old_metadata.get("dev.skylos", {})
        if not isinstance(old_files, list) or not isinstance(old_vendor, dict):
            return False
        indexed = {
            f["path"]: f
            for f in old_files
            if isinstance(f, dict) and safe_relative_path(f.get("path"))
        }
        for item in files:
            indexed[item["path"]] = item
        previous_hashes = old_vendor.get("files", {})
        previous_details = old_vendor.get("contributors", {})
        if not isinstance(previous_hashes, dict) or not isinstance(
            previous_details, dict
        ):
            return False
        current = {
            **record,
            "tool": {"name": "skylos"},
            "files": list(indexed.values()),
            "metadata": {
                "dev.skylos": {
                    **record["metadata"]["dev.skylos"],
                    "capture": "current_index",
                    "files": {**previous_hashes, **hashes},
                    "contributors": {**previous_details, **details},
                }
            },
        }
        if (
            len(current["files"]) > 1000
            or len(json.dumps(current).encode()) > MAX_RECORD_BYTES
        ):
            return False
        if not save_project_json_cache(root, index_path, current):
            return False
        # The immutable history has a ceiling. Current state still advances;
        # the coverage receipt explicitly stays partial.
        if directory.is_dir() and sum(1 for _ in directory.iterdir()) >= MAX_RECORDS:
            return True
    name = f"{time.time_ns():020d}-{record['id']}.json"
    return save_project_json_cache(root, directory / name, record)
