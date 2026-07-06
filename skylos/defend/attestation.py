from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

ATTESTATION_SCHEMA = "1"
MAX_ATTESTED_FILE_BYTES = 10_000_000


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hash_file(path: Path, *, root: Path | None = None) -> str | None:
    resolved = _resolve_hashable_path(path, root=root)
    if resolved is None:
        return None
    return _sha256_regular_file(resolved)


def _resolve_hashable_path(path: Path, *, root: Path | None = None) -> Path | None:
    raw_path = Path(path)
    try:
        mode = raw_path.lstat().st_mode
    except OSError:
        return None
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        return None

    try:
        resolved = raw_path.resolve(strict=True)
    except OSError:
        return None

    if root is not None:
        try:
            resolved.relative_to(root.resolve(strict=True))
        except (OSError, ValueError):
            return None

    return resolved


def _sha256_regular_file(path: Path) -> str | None:
    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow

    fd: int | None = None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] path resolved, regular, bounded, and opened no-follow
            path, flags
        )
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            return None
        if stat_result.st_size > MAX_ATTESTED_FILE_BYTES:
            return None

        digest = hashlib.sha256()
        remaining = MAX_ATTESTED_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
            remaining -= len(chunk)
        return None
    except OSError:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _relative_posix(path: Path, target: Path) -> str:
    try:
        return Path(path).relative_to(target).as_posix()
    except ValueError:
        return Path(path).as_posix()


def _jsonable(value: Any) -> Any:
    to_dict = getattr(type(value), "to_dict", None)
    if callable(to_dict):
        return _jsonable(to_dict(value))
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, dict):
        return {str(key): _jsonable(val) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, set):
        return sorted(_jsonable(item) for item in value)
    return value


def _canonical_sort_key(value: Any) -> str:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _normalize_sequence(values: Sequence[Any] | None) -> list[Any]:
    normalized = [_jsonable(value) for value in (values or [])]
    normalized.sort(key=_canonical_sort_key)
    return normalized


def _normalize_results(results: Sequence[Any]) -> list[dict[str, Any]]:
    normalized = []
    for result in results:
        to_dict = getattr(type(result), "to_dict", None)
        if callable(to_dict):
            normalized.append(_jsonable(to_dict(result)))
            continue

        normalized.append(
            {
                "plugin_id": str(getattr(result, "plugin_id", "")),
                "passed": bool(getattr(result, "passed", False)),
                "integration_location": str(
                    getattr(result, "integration_location", "")
                ),
                "location": str(getattr(result, "location", "")),
                "message": str(getattr(result, "message", "")),
                "severity": str(getattr(result, "severity", "")),
                "weight": int(getattr(result, "weight", 0) or 0),
                "category": str(getattr(result, "category", "")),
                "owasp_llm": getattr(result, "owasp_llm", None),
                "remediation": str(getattr(result, "remediation", "")),
            }
        )
    normalized.sort(key=_canonical_sort_key)
    return normalized


def build_attestation(
    *,
    target: Path,
    files: Sequence[Path],
    results: Sequence[Any],
    plugin_ids: Sequence[str],
    policy_path: str | None = None,
    owasp_framework: str,
    owasp_version: str | int,
    min_severity: str | None = None,
    owasp_filter: Sequence[str] | None = None,
    integrations: Sequence[Any] | None = None,
    score: Any | None = None,
    ops_score: Any | None = None,
    owasp_coverage: Any | None = None,
    framework_evidence: Any | None = None,
) -> dict:
    """
    Build a reproducible attestation block for a defend run.

    The digest covers only stable inputs (file contents, policy, plugin set,
    filters, and run evidence) — never timestamps — so re-running an
    identical tree with the same Skylos version must reproduce the digest.

    Calls: skylos/defend/attestation.py _sha256_json, _hash_file.

    Called from: skylos/commands/defend_cmd.py _format_defend_output;
        skylos_mcp/server.py _verify_agent_impl.
    """
    from skylos import __version__ as skylos_version

    target = Path(target)
    resolved_target = target.resolve()
    file_entries = []
    for path in files:
        file_entries.append(
            {
                "path": _relative_posix(path, target),
                "sha256": _hash_file(path, root=resolved_target),
            }
        )
    file_entries.sort(key=lambda entry: entry["path"])

    policy_hash = None
    if policy_path:
        policy_hash = _hash_file(Path(policy_path))

    run_evidence = {
        "results": _normalize_results(results),
        "integrations": _normalize_sequence(integrations),
        "score": _jsonable(score) if score is not None else None,
        "ops_score": _jsonable(ops_score) if ops_score is not None else None,
        "owasp_coverage": _jsonable(owasp_coverage),
        "framework_evidence": _jsonable(framework_evidence),
    }

    digest_input = {
        "attestation_schema": ATTESTATION_SCHEMA,
        "skylos_version": skylos_version,
        "files": file_entries,
        "policy_sha256": policy_hash,
        "plugin_set": sorted(str(pid) for pid in plugin_ids),
        "owasp": {
            "framework": str(owasp_framework),
            "version": str(owasp_version),
        },
        "filters": {
            "min_severity": min_severity,
            "owasp_filter": sorted(owasp_filter) if owasp_filter else None,
        },
        "run_evidence": run_evidence,
    }

    return {
        "algorithm": "sha256",
        "digest": _sha256_json(digest_input),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "files_hashed": len(file_entries),
            "files_digest": _sha256_json(file_entries),
            "policy_hash": policy_hash,
            "plugin_set": digest_input["plugin_set"],
            "owasp_framework": str(owasp_framework),
            "owasp_version": str(owasp_version),
            "skylos_version": skylos_version,
            "results_digest": _sha256_json(run_evidence["results"]),
            "integrations_digest": _sha256_json(run_evidence["integrations"]),
            "run_evidence_digest": _sha256_json(run_evidence),
        },
    }
