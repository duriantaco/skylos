"""Private, data-only identity candidates for explicitly configured npm mirrors."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

MAX_MIRROR_CANDIDATES = 5000
MAX_MIRROR_CANDIDATE_BYTES = 16 * 1024 * 1024
MAX_MIRROR_ENTRY_BYTES = 1024 * 1024


@dataclass(frozen=True)
class NpmMirrorCandidate:
    """A possible public copy whose raw source remains local until proved."""

    dependency: dict = field(repr=False)
    source_url: str = field(repr=False)
    occurrence_id: str = field(repr=False)
    not_checked: dict = field(repr=False)
    file_sha256: str
    proof_key: str


def _possible_mirror_url(value: object, *, allow_legacy_hash_fragment=False) -> bool:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= 8192
        or value != value.strip()
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.port != 0
            and not parsed.query
            and (
                not parsed.fragment
                or allow_legacy_hash_fragment
                and re.fullmatch(r"[0-9a-fA-F]{40}", parsed.fragment) is not None
            )
        )
    except ValueError:
        return False


def add_npm_mirror_candidate(
    inventory,
    *,
    path: Path,
    text: str,
    occurrence_id,
    dependency: dict,
    source_url: object,
    not_checked: dict,
    allow_legacy_hash_fragment: bool = False,
) -> None:
    """Retain an exact occurrence without changing any public parser output.

    The caller has already parsed the package identity. Raw URLs and this
    candidate list are internal scan inputs, never a finding or upload field.
    Only a separate scan-time verifier may promote a candidate.
    """
    if not _possible_mirror_url(
        source_url, allow_legacy_hash_fragment=allow_legacy_hash_fragment
    ):
        return
    if len(inventory.npm_mirror_candidates) >= MAX_MIRROR_CANDIDATES:
        inventory.npm_mirror_candidate_limit_reached = True
        return
    absolute_path = os.path.abspath(path)
    cached = getattr(inventory, "_npm_mirror_source_digest", None)
    if cached is None or cached[0] != absolute_path or cached[1] is not text:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        cached = (absolute_path, text, digest)
        inventory._npm_mirror_source_digest = cached
    digest = cached[2]
    try:
        structural_id = json.dumps(
            occurrence_id, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        )
        key_material = json.dumps(
            [
                "skylos.npm-mirror-candidate.v1",
                absolute_path,
                digest,
                structural_id,
                dependency,
                source_url,
                dependency.get("integrity"),
            ],
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return
    total = getattr(inventory, "_npm_mirror_candidate_bytes", 0) + len(key_material)
    if len(key_material) > MAX_MIRROR_ENTRY_BYTES or total > MAX_MIRROR_CANDIDATE_BYTES:
        inventory.npm_mirror_candidate_limit_reached = True
        return
    inventory._npm_mirror_candidate_bytes = total
    inventory.npm_mirror_candidates.append(
        NpmMirrorCandidate(
            dependency=deepcopy(dependency),
            source_url=source_url,
            occurrence_id=structural_id,
            not_checked=not_checked,
            file_sha256=digest,
            proof_key=hashlib.sha256(key_material).hexdigest(),
        )
    )
