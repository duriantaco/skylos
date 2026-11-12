"""Prove public npm identities for explicitly configured mirror lock entries.

Only the fixed public npm metadata endpoint is contacted. A proof describes
the artifact recorded by a lockfile, without fetching or installing it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import threading
import time
from urllib.parse import quote

from skylos.commands.hook_parallel import PENDING, run_parallel
from skylos.core.safe_cache_io import (
    load_project_json_cache,
    project_cache_lock,
    save_project_json_cache,
)
from skylos.rules.sca.npm_mirror_policy import canonical_integrity, mirror_url_matches
from skylos.rules.sca.osv_client import OsvResponseError, read_json_response

NPM_METADATA_ORIGIN = "https://registry.npmjs.org"
MAX_METADATA_BYTES = 1024 * 1024
MAX_TOTAL_METADATA_BYTES = 32 * 1024 * 1024
MAX_IDENTITIES = 5000
METADATA_DEADLINE_SECONDS = 120.0
METADATA_REQUEST_SECONDS = 6.0
METADATA_WORKERS = 8
CACHE_FILE = "npm-mirror-identities.json"
MAX_CACHE_BYTES = 4 * 1024 * 1024
MAX_CACHE_AGE_SECONDS = 7 * 24 * 3600


@dataclass(frozen=True)
class PublicNpmIdentity:
    name: str
    version: str
    integrity: str
    verified_at: int


@dataclass(frozen=True)
class NpmMirrorVerification:
    proofs: dict[str, PublicNpmIdentity]
    receipt: dict


def _identity(name, version) -> tuple[str, str] | None:
    from skylos.rules.sca.npm_lockfile import _exact_version, _name

    if (
        _name(name) is None
        or not isinstance(version, str)
        or _exact_version(version) != version
    ):
        return None
    return name, version


def _cache_directory(root: Path) -> Path | None:
    try:
        base = os.environ.get("XDG_CACHE_HOME")
        path = Path(base) if base else Path.home() / ".cache"
        if not path.is_absolute():
            return None
        directory = (path / "skylos").resolve()
        scan_root = root.resolve()
        if directory.is_relative_to(scan_root):
            return None
        # A subdirectory scan must not accept proofs from a tracked sibling.
        # Inspect every ancestor to handle nested checkouts without trusting
        # repository configuration or invoking repository Git helpers.
        for ancestor in (scan_root, *scan_root.parents):
            if (ancestor / ".git").exists() and directory.is_relative_to(ancestor):
                return None
        return directory
    except (OSError, RuntimeError, ValueError):
        return None


def _cache_entries(payload, now: int) -> dict[tuple[str, str], PublicNpmIdentity]:
    if not isinstance(payload, dict) or type(payload.get("schema_version")) is not int:
        return {}
    entries = payload.get("entries")
    if (
        payload["schema_version"] != 1
        or payload.get("provider") != "registry.npmjs.org"
        or not isinstance(entries, list)
    ):
        return {}
    if len(entries) > MAX_IDENTITIES:
        return {}
    result = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = _identity(entry.get("name"), entry.get("version"))
        timestamp = entry.get("verified_at")
        integrity = canonical_integrity(entry.get("integrity"))
        if (
            key is None
            or integrity is None
            or type(timestamp) is not int
            or not -300 <= now - timestamp <= MAX_CACHE_AGE_SECONDS
        ):
            continue
        result[key] = PublicNpmIdentity(*key, integrity, timestamp)
    return result


def _load_cache(directory: Path | None, now: int):
    if directory is None:
        return {}
    return _cache_entries(
        load_project_json_cache(directory, CACHE_FILE, max_bytes=MAX_CACHE_BYTES), now
    )


def _save_cache(directory: Path | None, values):
    if directory is None or not values:
        return
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with project_cache_lock(
            directory, CACHE_FILE + ".lock", timeout_seconds=0.25
        ) as owned:
            if not owned:
                return
            entries = _load_cache(directory, int(time.time()))
            entries.update({(value.name, value.version): value for value in values})
            newest = sorted(
                entries.values(), key=lambda value: value.verified_at, reverse=True
            )[:MAX_IDENTITIES]
            save_project_json_cache(
                directory,
                CACHE_FILE,
                {
                    "schema_version": 1,
                    "provider": "registry.npmjs.org",
                    "entries": [
                        {
                            "name": value.name,
                            "version": value.version,
                            "integrity": value.integrity,
                            "verified_at": value.verified_at,
                        }
                        for value in newest
                    ],
                },
                indent=None,
            )
    except (OSError, ValueError):
        return


class _ByteBudget:
    def __init__(self):
        self.used = 0
        self.exhausted = False
        self.lock = threading.Lock()

    def consume(self, count: int):
        with self.lock:
            if self.used + count > MAX_TOTAL_METADATA_BYTES:
                self.exhausted = True
                raise OsvResponseError("mirror_metadata_byte_limit")
            self.used += count


def _anonymous_request(request):
    # A truthy auth callable prevents requests from loading .netrc credentials.
    request.headers.pop("Authorization", None)
    return request


def _fetch_public_identity(key, transport, deadline, budget):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    name, version = key
    url = f"{NPM_METADATA_ORIGIN}/{quote(name, safe='@')}/{quote(version, safe='')}"
    timeout = min(METADATA_REQUEST_SECONDS, remaining)
    try:
        response = transport.get(
            url,
            stream=True,
            allow_redirects=False,
            timeout=(timeout, timeout),
            auth=_anonymous_request,
            headers={"User-Agent": "skylos/npm-mirrors", "Accept": "application/json"},
        )
        data = read_json_response(
            response,
            max_bytes=MAX_METADATA_BYTES,
            deadline=deadline,
            consume_bytes=budget.consume,
        )
    except (OSError, ValueError, OsvResponseError):
        return None
    except Exception:  # noqa: BLE001 - provider failure leaves the entry unchecked
        return None
    if (
        not isinstance(data, dict)
        or data.get("name") != name
        or data.get("version") != version
        or not isinstance(data.get("dist"), dict)
    ):
        return None
    integrity = canonical_integrity(data["dist"].get("integrity"))
    if integrity is None:
        return None
    return PublicNpmIdentity(name, version, integrity, int(time.time()))


def _internal_candidate(candidate, policy) -> bool:
    from skylos.commands.hook_locked_packages import is_internal

    dependency = candidate.dependency
    names = [dependency.get("name"), candidate.not_checked.get("installed_name")]
    aliases = dependency.get("installed_names")
    if isinstance(aliases, list):
        names.extend(aliases)
    return any(
        is_internal("npm", name, policy.internal_packages)
        for name in names
        if isinstance(name, str)
    )


def verify_npm_mirrors(root, inventory, policy, transport) -> NpmMirrorVerification:
    """Network-only scan stage; callers reparse inputs before applying proofs."""
    reasons = Counter()
    eligible = []
    identities = {}
    for candidate in getattr(inventory, "_npm_mirror_candidates", ()):
        dependency = candidate.dependency
        classic = (
            Path(str(dependency.get("file", ""))).name == "yarn.lock"
            and dependency.get("lockfile_version") == 1
        )
        if not mirror_url_matches(
            candidate.source_url,
            policy.npm_registry_mirrors,
            allow_legacy_hash_fragment=classic,
        ):
            reasons["source_not_configured"] += 1
            continue
        if _internal_candidate(candidate, policy):
            reasons["internal_package"] += 1
            continue
        key = _identity(dependency.get("name"), dependency.get("version"))
        integrity = canonical_integrity(dependency.get("integrity"))
        if key is None or integrity is None:
            reasons["missing_strong_integrity_or_identity"] += 1
            continue
        if key not in identities and len(identities) >= MAX_IDENTITIES:
            reasons["identity_limit"] += 1
            continue
        eligible.append((candidate, key, integrity))
        identities[key] = None

    now = int(time.time())
    directory = _cache_directory(Path(root))
    cached = _load_cache(directory, now)
    answers = {key: cached[key] for key in identities if key in cached}
    pending = [key for key in identities if key not in answers]
    deadline = time.monotonic() + METADATA_DEADLINE_SECONDS
    budget = _ByteBudget()
    results = run_parallel(
        [
            lambda key=key: _fetch_public_identity(key, transport, deadline, budget)
            for key in pending
        ],
        deadline,
        workers=METADATA_WORKERS,
    )
    fetched = []
    for key, result in zip(pending, results):
        if isinstance(result, PublicNpmIdentity):
            answers[key] = result
            fetched.append(result)
        else:
            reasons[
                "metadata_deadline" if result is PENDING else "metadata_unavailable"
            ] += 1
    _save_cache(directory, fetched)
    proofs = {}
    for candidate, key, integrity in eligible:
        answer = answers.get(key)
        if answer is None:
            continue
        if integrity != answer.integrity:
            reasons["integrity_mismatch"] += 1
            continue
        proofs[candidate.proof_key] = answer
    if getattr(inventory, "_npm_mirror_candidate_limit_reached", False):
        reasons["candidate_limit"] += 1
    if budget.exhausted:
        reasons["metadata_byte_limit"] += 1
    incomplete = any(
        reasons[reason]
        for reason in (
            "metadata_unavailable",
            "metadata_deadline",
            "metadata_byte_limit",
            "identity_limit",
            "candidate_limit",
        )
    )
    return NpmMirrorVerification(
        proofs=proofs,
        receipt={
            "schema_version": 1,
            "status": "partial" if incomplete else "complete",
            "candidate_count": len(getattr(inventory, "_npm_mirror_candidates", ())),
            "eligible_occurrences": len(eligible),
            "verified_occurrences": len(proofs),
            "metadata_requests": len(pending),
            "cache_hits": len(identities) - len(pending),
            "metadata_bytes": budget.used,
            "reasons": dict(reasons),
            "provider": "registry.npmjs.org",
            "limits": {
                "identities": MAX_IDENTITIES,
                "metadata_bytes": MAX_TOTAL_METADATA_BYTES,
                "metadata_seconds": METADATA_DEADLINE_SECONDS,
            },
        },
    )


def apply_verified_npm_mirrors(inventory, proofs) -> int:
    """Promote exact, freshly parsed occurrences while retaining raw source records."""
    if not proofs:
        return 0
    promoted = 0
    removed = set()
    for candidate in getattr(inventory, "npm_mirror_candidates", ()):
        proof = proofs.get(candidate.proof_key)
        dependency = candidate.dependency
        if (
            not isinstance(proof, PublicNpmIdentity)
            or (proof.name, proof.version)
            != (dependency.get("name"), dependency.get("version"))
            or proof.integrity != canonical_integrity(dependency.get("integrity"))
            or not any(
                entry is candidate.not_checked for entry in inventory.not_checked
            )
        ):
            continue
        row = _promoted_dependency(dependency)
        row.update(
            source_type="npm_registry_mirror",
            registry="registry.npmjs.org",
            registry_mirror={
                "schema_version": 1,
                "provider": "registry.npmjs.org",
                "package_name": proof.name,
                "package_version": proof.version,
                "integrity": proof.integrity,
                "verified_at": proof.verified_at,
                "lockfile_sha256": candidate.file_sha256,
                "occurrence_sha256": candidate.proof_key,
            },
        )
        inventory.dependencies.append(row)
        removed.add(id(candidate.not_checked))
        promoted += 1
    inventory.not_checked[:] = [
        entry for entry in inventory.not_checked if id(entry) not in removed
    ]
    return promoted


_OPAQUE_PACKAGE_PATH = re.compile(r"yarn:[0-9a-f]{64}")
_SAFE_RANGE = re.compile(r"[A-Za-z0-9.*+^~<>=| -]+")
_SAFE_ALIAS = re.compile(
    r"npm:(?:@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+|[A-Za-z0-9._-]+)"
    r"(?:@[A-Za-z0-9.*+^~<>=| -]+)?"
)


def _source_bearing_context(value: str) -> bool:
    return any(char in value for char in (":", "?", "#", "%", "\\")) or (
        "//" in value or any(ord(char) <= 31 or ord(char) == 127 for char in value)
    )


def _opaque_context(value: str) -> str:
    return "context:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _public_specifier(value: str) -> str:
    if value.startswith(("file:", "link:", "workspace:", "portal:", "./", "../", "/")):
        return "<local>"
    if _SAFE_RANGE.fullmatch(value) or _SAFE_ALIAS.fullmatch(value):
        return value
    return "<non-registry>"


def _safe_npm_descriptor(value: str) -> bool:
    if _SAFE_ALIAS.fullmatch(value):
        return True
    if "@npm:" not in value:
        return False
    from skylos.rules.sca.npm_lockfile import _name

    alias, _, reference = value.partition("@npm:")
    return _name(alias) is not None and bool(_SAFE_ALIAS.fullmatch("npm:" + reference))


def _public_context(value, *, field=""):
    """Project lockfile context without publishing private source references."""
    if isinstance(value, dict):
        return {
            (_opaque_context(key) if _source_bearing_context(key) else key)
            if isinstance(key, str)
            else "<invalid>": _public_context(child, field=key)
            for key, child in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_public_context(child, field=field) for child in value]
    if not isinstance(value, str):
        return value
    if field in {"version_spec", "specifier"}:
        return _public_specifier(value)
    if field == "package_path":
        if _OPAQUE_PACKAGE_PATH.fullmatch(value):
            return value
        return _opaque_context(value) if _source_bearing_context(value) else value
    if value.startswith(("file:", "link:", "workspace:", "portal:")):
        return "<local>"
    if _safe_npm_descriptor(value):
        return value
    return "<non-registry>" if _source_bearing_context(value) else value


def _promoted_dependency(dependency: dict) -> dict:
    row = {
        key: _public_context(value, field=key)
        for key, value in dependency.items()
        if key not in {"installed_names", "file", "snippet", "integrity"}
    }
    row["file"] = dependency["file"]
    row["integrity"] = dependency["integrity"]
    row["snippet"] = f"{dependency['name']}@{dependency['version']}"
    return row


def verified_mirror_dependency(dependency) -> bool:
    """Validate the public identity context attached by the scan proof stage."""
    if not isinstance(dependency, dict):
        return False
    proof = dependency.get("registry_mirror")
    if (
        dependency.get("ecosystem") != "npm"
        or dependency.get("source_type") != "npm_registry_mirror"
        or dependency.get("registry") != "registry.npmjs.org"
        or not isinstance(proof, dict)
        or type(proof.get("schema_version")) is not int
        or proof["schema_version"] != 1
        or proof.get("provider") != "registry.npmjs.org"
        or _identity(proof.get("package_name"), proof.get("package_version"))
        != _identity(dependency.get("name"), dependency.get("version"))
        or _identity(dependency.get("name"), dependency.get("version")) is None
        or canonical_integrity(proof.get("integrity")) is None
        or proof["integrity"] != dependency.get("integrity")
        or type(proof.get("verified_at")) is not int
        or not 0 < proof["verified_at"] <= int(time.time()) + 300
    ):
        return False
    return all(
        isinstance(proof.get(field), str)
        and re.fullmatch(r"[0-9a-f]{64}", proof[field]) is not None
        for field in ("lockfile_sha256", "occurrence_sha256")
    )
