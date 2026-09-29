"""Offline verification of Skylos Cloud signed check verdicts.

Skylos Cloud signs what it decided for one commit: an in-toto Statement v1
with a SLSA Verification Summary predicate, in a DSSE envelope, signed with
Ed25519. The predicate commits to a check summary by SHA-256, so the summary
travels next to the envelope and anyone with the published public keys can
verify both offline.

This module is a port of ``verifyVerdictBundle`` in Skylos Cloud's
``src/lib/check-verdict.ts``: the same checks, in the same order, with the
same failure reasons. Keep the two in step.

A verdict proves this check ran under this policy with this result. It does
not prove the code is safe, and for uploads that are not GitHub OIDC it
cannot prove the uploaded results came from that commit's code.

Ed25519 needs the optional ``cryptography`` package; it is imported lazily
so the rest of Skylos does not depend on it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Iterable, Mapping, NamedTuple

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERDICT_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
VSA_PREDICATE_TYPE = "https://slsa.dev/verification_summary/v1"
CHECK_SUMMARY_SCHEMA = "skylos.check-summary/v1"
VERDICT_BUNDLE_SCHEMA = "skylos.verdict-bundle/v1"
VERDICT_VERIFIER_ID = "https://skylos.dev/verifiers/pr-check"
VERDICT_KEY_ID_PREFIX = "skylos-verdict-"
VERDICT_RESULTS = ("PASSED", "FAILED")
# Custom VSA levels (the spec allows values that don't start with SLSA_).
VERDICT_PASSED_LEVEL = "SKYLOS_POLICY_PASSED"
# Passed only because an admin chose "merge anyway".
VERDICT_OVERRIDDEN_LEVEL = "SKYLOS_GATE_OVERRIDDEN"
# Passed only because the workspace gate is turned off.
VERDICT_GATE_DISABLED_LEVEL = "SKYLOS_GATE_DISABLED"
# Passed, but the scan recorded no gate settings, so it isn't a policy pass.
VERDICT_GATE_UNKNOWN_LEVEL = "SKYLOS_GATE_UNKNOWN"
# How far in the future a signing time may be before --max-age rejects it.
MAX_CLOCK_SKEW = timedelta(minutes=5)

CRYPTOGRAPHY_INSTALL_HINT = (
    'Install it with: pip install cryptography (or pip install "skylos[verdict]")'
)

# The TS reference anchors these with ^...$ and no multiline flag; fullmatch
# gives the same meaning (Python's $ would also accept a trailing newline).
_SHA = re.compile(r"[0-9a-f]{40}")
_KEY_ID = re.compile(r"skylos-verdict-[0-9a-f]{16}")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
_UTF8 = "utf-8"

NOT_AN_OBJECT = "The bundle is not a JSON object."
UNKNOWN_SCHEMA = "Unknown bundle schema."
NOT_DSSE = "The envelope is not a DSSE in-toto envelope."
NO_SUMMARY = "The bundle has no summary."
NO_VALID_SIGNATURE = "No valid signature from a trusted Skylos key."
PAYLOAD_NOT_JSON = "The signed payload is not JSON."
NOT_A_SUMMARY_STATEMENT = "The signed statement is not a Skylos verification summary."
NO_COMMIT = "The signed statement has no commit."
NO_RESULT = "The signed statement has no result."
DIGEST_MISMATCH = "The summary does not match the signed digest."
SUMMARY_NOT_JSON = "The summary is not JSON."
SUMMARY_DISAGREES = "The summary and the signed statement disagree."
OTHER_WORKSPACE = "The verdict belongs to a different workspace."
NOT_REPOSITORY_VERIFIED = "The verdict is not bound to a verified repository upload."
INVALID_SIGNING_TIME = "The verdict has an invalid signing time."
TOO_OLD = "The verdict is older than the allowed age."


class VerdictCryptoUnavailable(RuntimeError):
    """Raised when the optional ``cryptography`` package is not installed."""


class _Rejected(Exception):
    """A failed check; its message is the public failure reason."""


class _Crypto(NamedTuple):
    invalid_signature: type[Exception]
    unsupported_algorithm: type[Exception]
    serialization: Any
    ed25519: Any


@dataclass(frozen=True)
class VerdictExpectations:
    """What the verdict must also say, beyond being validly signed.

    Mirrors ``VerdictExpectations`` in check-verdict.ts. ``now`` must be
    timezone-aware; it defaults to the current UTC time.
    """

    commit: str | None = None
    project: str | None = None
    workspace: str | None = None
    # "host/owner/repo", compared case-insensitively.
    repository: str | None = None
    # Require an OIDC upload bound to the repository and a verified binding.
    require_repository_verified: bool = False
    # Reject verdicts signed longer ago than this.
    max_age: timedelta | None = None
    now: datetime | None = None


@dataclass(frozen=True)
class VerdictVerification:
    ok: bool
    reason: str | None = None
    statement: dict | None = None
    summary: dict | None = None
    key_id: str | None = None


def load_crypto() -> _Crypto:
    """Import the Ed25519 primitives, or raise VerdictCryptoUnavailable."""
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise VerdictCryptoUnavailable(
            "Verifying a signed verdict needs the 'cryptography' package. "
            + CRYPTOGRAPHY_INSTALL_HINT
        ) from exc
    return _Crypto(InvalidSignature, UnsupportedAlgorithm, serialization, ed25519)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding (lengths are byte counts)."""
    type_bytes = payload_type.encode(_UTF8)
    return b"".join(
        [
            f"DSSEv1 {len(type_bytes)} ".encode("ascii"),
            type_bytes,
            f" {len(payload)} ".encode("ascii"),
            payload,
        ]
    )


def verdict_key_id(spki_der: bytes) -> str:
    """Stable id for a public key: the first 16 hex of SHA-256 over its SPKI DER."""
    return VERDICT_KEY_ID_PREFIX + sha256_hex(spki_der)[:16]


def verdict_resource_name(summary: Mapping[str, Any]) -> str | None:
    """The subject name Skylos Cloud derives from a summary (None if it can't)."""
    repository = summary.get("repository")
    commit = summary.get("commit")
    if isinstance(repository, str) and repository:
        return f"git+https://{repository}@{commit}"
    project_id = get_path(summary, "project", "id")
    # JS truthiness: only a falsy repository falls back to the project id.
    if repository not in (None, "", False, 0) or not isinstance(project_id, str):
        return None
    return f"skylos-project:{project_id}@{commit}"


def repository_verified(summary: Mapping[str, Any]) -> bool:
    """A GitHub OIDC upload bound to the repository, for a verified binding."""
    return (
        summary.get("repository_binding") == "verified"
        and get_path(summary, "upload_identity", "repository_verified") is True
    )


def verified_levels(statement: Mapping[str, Any]) -> list[str]:
    """The signed ``verifiedLevels`` (strings only)."""
    levels = get_path(statement, "predicate", "verifiedLevels")
    if not isinstance(levels, list):
        return []
    return [level for level in levels if isinstance(level, str)]


def parse_json_strict(text: str) -> Any:
    """``json.loads`` that, like JSON.parse, rejects NaN and Infinity."""
    return json.loads(text, parse_constant=_reject_constant)


def get_path(value: Any, *keys: str) -> Any:
    """Optional chaining: ``value?.a?.b``, None when any step is not an object."""
    for key in keys:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def verify_verdict_bundle(
    bundle: Any,
    trusted_keys: Iterable[Mapping[str, Any]],
    expectations: VerdictExpectations | None = None,
) -> VerdictVerification:
    """Verify a bundle against trusted public keys.

    Checks the DSSE signature, the statement shape, the summary digest, and
    that the summary and statement describe the same commit and result.
    ``expectations`` also bind it to the commit, project, workspace, and
    repository being deployed, and can require a verified repository upload
    and a recent signing time.

    Raises VerdictCryptoUnavailable when ``cryptography`` is missing.
    """
    expect = expectations or VerdictExpectations()
    crypto = load_crypto()
    keys = [key for key in trusted_keys if isinstance(key, Mapping)]
    try:
        _check_bundle_shape(bundle)
        envelope = bundle["envelope"]
        payload = base64.b64decode(envelope["payload"])
        pae = dsse_pae(envelope["payloadType"], payload)
        key_id = _find_trusted_signature(envelope["signatures"], pae, keys, crypto)
        statement = _read_statement(payload)
        commit = statement["subject"][0]["digest"]["gitCommit"]
        summary = _read_summary(bundle["summary_json"], statement, commit)
        _check_subject_expectations(summary, commit, expect)
        _check_trust_expectations(statement, summary, expect)
    except _Rejected as exc:
        return VerdictVerification(ok=False, reason=str(exc))
    return VerdictVerification(
        ok=True, statement=statement, summary=summary, key_id=key_id
    )


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _is_base64(value: Any) -> bool:
    return isinstance(value, str) and _BASE64.fullmatch(value) is not None


def _is_key_id(value: Any) -> bool:
    return isinstance(value, str) and _KEY_ID.fullmatch(value) is not None


def _js_utf8(text: str) -> bytes:
    """UTF-8 bytes as Node's Buffer.from(text, "utf8") produces them.

    Node encodes a lone surrogate as U+FFFD; Python would raise instead.
    json.loads already joins escaped surrogate pairs, so any surrogate left
    in a str is lone.
    """
    return _LONE_SURROGATE.sub("�", text).encode(_UTF8)


def _check_bundle_shape(bundle: Any) -> None:
    if not isinstance(bundle, dict):
        raise _Rejected(NOT_AN_OBJECT)
    if bundle.get("schema") != VERDICT_BUNDLE_SCHEMA:
        raise _Rejected(UNKNOWN_SCHEMA)
    envelope = bundle.get("envelope")
    if (
        get_path(envelope, "payloadType") != VERDICT_PAYLOAD_TYPE
        or not _is_base64(get_path(envelope, "payload"))
        or not isinstance(get_path(envelope, "signatures"), list)
    ):
        raise _Rejected(NOT_DSSE)
    if not isinstance(bundle.get("summary_json"), str):
        raise _Rejected(NO_SUMMARY)


def _find_trusted_signature(
    signatures: list,
    pae: bytes,
    keys: list[Mapping[str, Any]],
    crypto: _Crypto,
) -> str:
    """The key id of the first signature a trusted key verifies."""
    for signature in signatures:
        keyid = get_path(signature, "keyid")
        sig = get_path(signature, "sig")
        if not _is_key_id(keyid) or not _is_base64(sig):
            continue
        trusted = next((key for key in keys if key.get("key_id") == keyid), None)
        public_key = _load_published_key(trusted, crypto) if trusted else None
        if public_key is not None and _signature_valid(public_key, sig, pae, crypto):
            return keyid
    raise _Rejected(NO_VALID_SIGNATURE)


def _load_published_key(
    trusted: Mapping[str, Any], crypto: _Crypto
) -> Ed25519PublicKey | None:
    """The Ed25519 key of a published entry, or None if unusable.

    A published id must really belong to its key, so an entry whose key_id is
    not derived from its own public key is rejected.
    """
    pem = trusted.get("public_key_pem")
    if not isinstance(pem, str):
        return None
    try:
        public_key = crypto.serialization.load_pem_public_key(pem.encode(_UTF8))
    except (ValueError, TypeError, UnicodeError, crypto.unsupported_algorithm):
        return None
    if not isinstance(public_key, crypto.ed25519.Ed25519PublicKey):
        return None
    der = public_key.public_bytes(
        crypto.serialization.Encoding.DER,
        crypto.serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key if verdict_key_id(der) == trusted.get("key_id") else None


def _signature_valid(
    public_key: Ed25519PublicKey, sig: str, pae: bytes, crypto: _Crypto
) -> bool:
    try:
        public_key.verify(base64.b64decode(sig), pae)
    except crypto.invalid_signature:
        return False
    return True


def _read_statement(payload: bytes) -> dict:
    try:
        statement = parse_json_strict(payload.decode(_UTF8, errors="replace"))
    except (ValueError, RecursionError) as exc:
        raise _Rejected(PAYLOAD_NOT_JSON) from exc
    predicate = get_path(statement, "predicate")
    subject = get_path(statement, "subject")
    attestations = get_path(predicate, "inputAttestations")
    if (
        get_path(statement, "_type") != IN_TOTO_STATEMENT_TYPE
        or get_path(statement, "predicateType") != VSA_PREDICATE_TYPE
        or get_path(predicate, "verifier", "id") != VERDICT_VERIFIER_ID
        or not _is_single_item_list(subject)
        or not _is_single_item_list(attestations)
    ):
        raise _Rejected(NOT_A_SUMMARY_STATEMENT)
    commit = get_path(subject[0], "digest", "gitCommit")
    if not isinstance(commit, str) or _SHA.fullmatch(commit) is None:
        raise _Rejected(NO_COMMIT)
    if predicate.get("verificationResult") not in VERDICT_RESULTS:
        raise _Rejected(NO_RESULT)
    return statement


def _is_single_item_list(value: Any) -> bool:
    return isinstance(value, list) and len(value) == 1


def _read_summary(summary_json: str, statement: dict, commit: str) -> dict:
    predicate = statement["predicate"]
    signed_digest = get_path(predicate["inputAttestations"][0], "digest", "sha256")
    if sha256_hex(_js_utf8(summary_json)) != signed_digest:
        raise _Rejected(DIGEST_MISMATCH)
    try:
        summary = parse_json_strict(summary_json)
    except (ValueError, RecursionError) as exc:
        raise _Rejected(SUMMARY_NOT_JSON) from exc
    subject_name = statement["subject"][0].get("name")
    if (
        get_path(summary, "schema") != CHECK_SUMMARY_SCHEMA
        or summary.get("commit") != commit
        or summary.get("verdict") != predicate["verificationResult"]
        or not isinstance(subject_name, str)
        or verdict_resource_name(summary) != subject_name
    ):
        raise _Rejected(SUMMARY_DISAGREES)
    return summary


def _check_subject_expectations(
    summary: dict, commit: str, expect: VerdictExpectations
) -> None:
    if expect.commit is not None and expect.commit.lower() != commit:
        raise _Rejected(f"The verdict is for commit {commit}, not {expect.commit}.")
    project_id = get_path(summary, "project", "id")
    if expect.project is not None and project_id != expect.project:
        shown = _js_string(project_id, "unknown")
        raise _Rejected(f"The verdict is for project {shown}, not {expect.project}.")
    workspace_id = get_path(summary, "workspace", "id")
    if expect.workspace is not None and workspace_id != expect.workspace:
        raise _Rejected(OTHER_WORKSPACE)
    repository = summary.get("repository")
    if (
        expect.repository is not None
        and _js_string(repository, "").lower() != expect.repository.lower()
    ):
        shown = _js_string(repository, "none")
        raise _Rejected(
            f"The verdict is for repository {shown}, not {expect.repository}."
        )


def _check_trust_expectations(
    statement: dict, summary: dict, expect: VerdictExpectations
) -> None:
    if expect.require_repository_verified and not repository_verified(summary):
        raise _Rejected(NOT_REPOSITORY_VERIFIED)
    if expect.max_age is None:
        return
    signed_at = _parse_signing_time(get_path(statement, "predicate", "timeVerified"))
    now = expect.now or datetime.now(timezone.utc)
    if signed_at is None or signed_at > now + MAX_CLOCK_SKEW:
        raise _Rejected(INVALID_SIGNING_TIME)
    if now - signed_at > expect.max_age:
        raise _Rejected(TOO_OLD)


def _parse_signing_time(value: Any) -> datetime | None:
    """An ISO 8601 time with a zone (as toISOString writes it), or None."""
    if not isinstance(value, str):
        return None
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # A time without a zone is ambiguous; fail closed rather than guess.
    return parsed if parsed.tzinfo is not None else None


def _js_string(value: Any, default: str) -> str:
    """``String(value ?? default)`` for the JSON values a summary can hold."""
    if value is None:
        return default
    if isinstance(value, bool):
        return "true" if value else "false"
    return value if isinstance(value, str) else json.dumps(value)
