"""Check changed PostgreSQL migrations against policy committed at a trusted base."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

import tomllib

from skylos.analysis.sql_files import POSTGRES_DUMP_BYTE_LIMIT
from skylos.core.git_safety import read_only_git_command, read_only_git_environment

_REGULAR_MODES = {"100644", "100755"}
_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_CONFIG = "pyproject.toml"


class EvidenceError(ValueError):
    pass


def _git(root, *args):
    result = subprocess.run(
        read_only_git_command(args, literal_pathspecs=True),
        cwd=root,
        env=read_only_git_environment(),
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise EvidenceError(f"Git could not read the requested {args[0]} evidence.")
    return result.stdout


@dataclass(frozen=True)
class Entry:
    mode: str
    oid: str
    size: int

    def text(self, root, limit):
        if self.mode not in _REGULAR_MODES:
            raise EvidenceError("Expected a regular Git blob.")
        if self.size < 0:
            raise EvidenceError("Git could not verify this blob's size.")
        if self.size > limit:
            raise EvidenceError(f"File exceeds the {limit:,}-byte input limit.")
        data = _git(root, "cat-file", "blob", self.oid)
        if len(data) != self.size:
            raise EvidenceError("Git blob size did not match its tree entry.")
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise EvidenceError("File is not UTF-8.") from exc


def _entries(root, revision, paths, recursive=False):
    flags = "-rlz" if recursive else "-lz"
    raw = _git(root, "ls-tree", "--full-tree", flags, revision, "--", *paths)
    result = {}
    for record in raw.split(b"\0"):
        if record:
            metadata, path = record.split(b"\t", 1)
            mode, _, oid, size = metadata.decode("ascii").split()
            result[os.fsdecode(path)] = Entry(
                mode, oid, int(size) if size.isdecimal() else -1
            )
    return result


def _valid_path(value):
    return (
        isinstance(value, str)
        and all(part not in ("", ".", "..") for part in value.split("/"))
        and not any(char in value for char in "\\*?[]\0")
    )


@dataclass
class Policy:
    directories: tuple[str, ...] = ()
    forbid: bool = False
    exceptions: set[tuple[str, str]] = field(default_factory=set)

    def protects(self, path):
        return any(d == "." or path.startswith(d + "/") for d in self.directories)


def _policy(root, base):
    entry = _entries(root, base, [_CONFIG]).get(_CONFIG)
    if entry is None:
        return Policy()
    try:
        config = tomllib.loads(entry.text(root, 2_000_000))
    except tomllib.TOMLDecodeError as exc:
        raise EvidenceError("Trusted pyproject.toml contains invalid TOML.") from exc
    for key in ("tool", "skylos", "sql", "production"):
        if not isinstance(config, dict):
            raise EvidenceError("Expected a TOML table for the trusted SQL policy.")
        if key not in config:
            return Policy()
        config = config[key]
    keys = {"directories", "forbid_public_writes", "allow_public_writes"}
    if not isinstance(config, dict) or config.keys() - keys:
        raise EvidenceError(
            "Invalid or unknown setting in trusted SQL production policy."
        )
    directories = config.get("directories")
    forbid = config.get("forbid_public_writes", False)
    allowed = config.get("allow_public_writes", [])
    if (
        not isinstance(directories, list)
        or not directories
        or not all(d == "." or _valid_path(d) for d in directories)
        or not isinstance(forbid, bool)
        or not isinstance(allowed, list)
    ):
        raise EvidenceError(
            "Invalid production directories, prohibition or exceptions."
        )
    policy = Policy(tuple(directories), forbid)
    for item in allowed:
        if not isinstance(item, dict) or set(item) != {"path", "fingerprint"}:
            raise EvidenceError(
                "Each grant exception needs an exact path and fingerprint."
            )
        path, digest = item["path"], item["fingerprint"]
        if (
            not _valid_path(path)
            or not path.lower().endswith(".sql")
            or not policy.protects(path)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise EvidenceError("Invalid grant exception path or SHA-256 fingerprint.")
        policy.exceptions.add((path, digest))
    return policy


def _grants(source, collect):
    try:
        from skylos.visitors.languages.postgresql_grant_policy import migration_grants
    except ImportError as exc:
        raise EvidenceError(
            "PostgreSQL parser unavailable. Install skylos[postgres]."
        ) from exc
    try:
        return migration_grants(source, collect)
    except (ValueError, RuntimeError) as exc:
        raise EvidenceError(f"Could not analyze PostgreSQL source: {exc}") from exc


def _assign_grant(index, grants, capacities, by_target, assigned):
    # Find an available grant. An earlier narrowing may have two eligible
    # grants, so move its credit if this grant needs the one it consumed.
    queue = deque([index])
    previous = {index: None}
    reached = {}
    while queue:
        current = queue.popleft()
        grant = grants[current]
        for slot in by_target[next(iter(grant.targets), None)]:
            if slot in reached or not grant.covered_by(slot):
                continue
            reached[slot] = current
            if capacities[slot]:
                capacities[slot] -= 1
                while slot is not None:
                    current = reached[slot]
                    assigned[slot].add(current)
                    slot = previous[current]
                    if slot is not None:
                        assigned[slot].remove(current)
                return True
            for earlier in assigned[slot]:
                if earlier not in previous:
                    previous[earlier] = slot
                    queue.append(earlier)
    return False


# A single GRANT can represent a product of many tables and columns. When
# expanding that product is expensive, retain the whole-statement comparison.
_MAX_GRANT_CELLS = 65_536


def _grant_cells(grant):
    for target in grant.targets or (None,):
        for action, column in grant.rights:
            yield (grant.scope, target, action), column


def _match_regrouped(grants, baseline, matched, approved):
    if not baseline or len(grants) == len(matched):
        return
    size = sum(
        max(1, len(grant.targets)) * len(grant.rights)
        for rows in (grants, baseline)
        for grant in rows
    )
    if size > _MAX_GRANT_CELLS:
        return

    available = defaultdict(Counter)
    used = defaultdict(Counter)
    reserved = Counter()
    for grant in baseline:
        for key, column in _grant_cells(grant):
            available[key][column] += 1

    def consume(grant):
        for key, col in _grant_cells(grant):
            used[key][col] += 1
            if col is not None:
                # One table-wide right covers each distinct column, including
                # several columns that are now granted by separate statements.
                reserved[key] = max(reserved[key], used[key][col] - available[key][col])

    def covers(grant):
        for key, col in _grant_cells(grant):
            whole = (
                available[key][None]
                - used[key][None]
                - ((key[2], None) in grant.rights)
            )
            if whole < reserved[key]:
                return False
            if col is not None and used[key][col] + 1 > available[key][col] + whole:
                return False
        return True

    for i in matched - approved:
        consume(grants[i])
    for i, grant in enumerate(grants):
        if i not in matched and covers(grant):
            consume(grant)
            matched.add(i)


def _unmatched(grants, baseline, path, exceptions):
    # Match identical permissions first. A later narrowing can spend a broader
    # historical grant once, even when the order of the statements changed.
    capacities = defaultdict(Counter)
    allowed = {digest for filename, digest in exceptions if filename == path}
    for grant in baseline:
        # A base grant with the exact approved fingerprint already accounts
        # for the one approved occurrence.
        allowed.discard(grant.fingerprint)
        capacities[grant.scope][grant.targets, grant.rights] += 1
    pending = defaultdict(list)
    matched = set()
    approved = set()
    approved_occurrences = set()
    for i, grant in enumerate(grants):
        if grant.occurrence is not None and grant.occurrence in approved_occurrences:
            matched.add(i)
            approved.add(i)
            continue
        if grant.fingerprint in allowed:
            allowed.remove(grant.fingerprint)
            approved_occurrences.add(grant.occurrence)
            matched.add(i)
            approved.add(i)
            continue
        available = capacities[grant.scope]
        access = grant.targets, grant.rights
        if available[access]:
            available[access] -= 1
            matched.add(i)
        else:
            pending[grant.scope].append(i)
    for scope, indices in pending.items():
        available = capacities[scope]
        remaining = sum(available.values())
        by_target = defaultdict(list)
        for slot, count in available.items():
            if count:
                for target in slot[0] or (None,):
                    by_target[target].append(slot)
        assigned = defaultdict(set)
        for i in indices:
            if not remaining:
                break
            if _assign_grant(i, grants, available, by_target, assigned):
                matched.add(i)
                remaining -= 1

    _match_regrouped(grants, baseline, matched, approved)
    for i, grant in enumerate(grants):
        if i not in matched:
            yield i, grant


def _introduced(grants, baseline, path, exceptions):
    # Report once per original statement. A revoke in a later transaction
    # cannot undo the earlier exposure, and removing the revoke can still
    # introduce a surviving right.
    comparisons = [(grants, baseline)]
    if hasattr(grants, "exposed"):
        comparisons.append((grants.exposed, getattr(baseline, "exposed", baseline)))
    emitted = set()
    for current, previous in comparisons:
        for index, grant in _unmatched(current, previous, path, exceptions):
            occurrence = grant.occurrence if grant.occurrence is not None else index
            if occurrence not in emitted:
                emitted.add(occurrence)
                yield {
                    "file": path,
                    "line": grant.line,
                    "rule_id": "SKY-D420",
                    "fingerprint": grant.fingerprint,
                }


def check_postgres(root, base, head):
    result = {
        "status": "pass",
        "checked_files": 0,
        "violations": [],
        "unchecked_files": [],
    }
    subject = "Git revisions"
    try:
        for sha in (base, head):
            if (
                not _SHA.fullmatch(sha)
                or _git(root, "cat-file", "-t", sha) != b"commit\n"
            ):
                raise EvidenceError("Expected full Git commit IDs for base and head.")
        subject = _CONFIG
        policy = _policy(root, base)
        if not policy.directories:
            return result
        # Include ancestors so a changed symlink or submodule cannot hide
        # protected descendants. ls-tree never follows or executes either.
        tops = sorted({d.split("/")[0] for d in policy.directories})
        paths = [] if "." in tops else tops
        subject = "Git trees"
        before = _entries(root, base, paths, recursive=True)
        after = _entries(root, head, paths, recursive=True)
        for path, entry in after.items():
            if before.get(path) == entry:
                continue
            protected = policy.protects(path)
            ancestor = any(
                d == path or d.startswith(path + "/") for d in policy.directories
            )
            if entry.mode not in _REGULAR_MODES and (protected or ancestor):
                result["unchecked_files"].append(
                    {
                        "file": path,
                        "reason": "Symlink or submodule in a protected migration path.",
                    }
                )
                continue
            if not protected or not path.lower().endswith(".sql"):
                continue
            try:
                grants = _grants(
                    entry.text(root, POSTGRES_DUMP_BYTE_LIMIT), policy.forbid
                )
                result["checked_files"] += 1
                if not grants.exposed:
                    continue
                old = before.get(path)
                baseline = (
                    _grants(old.text(root, POSTGRES_DUMP_BYTE_LIMIT), True)
                    if old and old.mode in _REGULAR_MODES
                    else []
                )
                result["violations"].extend(
                    _introduced(grants, baseline, path, policy.exceptions)
                )
            except EvidenceError as exc:
                result["unchecked_files"].append({"file": path, "reason": str(exc)})
    except (EvidenceError, OSError, subprocess.SubprocessError) as exc:
        result["unchecked_files"].append({"file": subject, "reason": str(exc)})
    if result["violations"] or result["unchecked_files"]:
        result["status"] = "fail"
    return result


def run_postgres_check(args):
    result = check_postgres(Path.cwd(), args.base, args.head)
    if args.format == "json":
        print(json.dumps(result))
    else:
        print(
            f"PostgreSQL migration check: {result['status']} ({result['checked_files']} files checked)"
        )
        for item in result["violations"]:
            print(
                f"{item['file']!a}:{item['line']} New PUBLIC write grant (SKY-D420). Fingerprint {item['fingerprint']}"
            )
        for item in result["unchecked_files"]:
            print(f"{item['file']!a}: {item['reason']!a}")
    return int(result["status"] == "fail")
