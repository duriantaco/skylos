"""``skylos verify-verdict``: check a signed Skylos Cloud check verdict.

The verification itself lives in :mod:`skylos.verdict`; this module reads
the bundle and the trusted keys, runs it, and reports the result.

Exit codes: 0 verified (and PASSED under --require-passed); 1 verified but
FAILED under --require-passed; 2 not verified, invalid input, keys
unavailable, or the optional ``cryptography`` package is missing.
"""

from __future__ import annotations

import argparse
import dataclasses
import http.client
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from skylos.verdict import (
    VERDICT_GATE_DISABLED_LEVEL,
    VERDICT_GATE_UNKNOWN_LEVEL,
    VERDICT_OVERRIDDEN_LEVEL,
    VERDICT_PASSED_LEVEL,
    VerdictCryptoUnavailable,
    VerdictExpectations,
    VerdictVerification,
    get_path,
    load_crypto,
    parse_json_strict,
    repository_verified,
    verified_levels,
    verify_verdict_bundle,
)

DEFAULT_KEYS_URL = "https://skylos.dev/.well-known/skylos-verdict-keys.json"
KEYS_TIMEOUT_SECONDS = 10
MAX_KEYS_BYTES = 1_000_000
MAX_BUNDLE_BYTES = 10_000_000

EXIT_VERIFIED = 0
EXIT_NOT_PASSING = 1
EXIT_NOT_VERIFIED = 2

_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_DURATION = re.compile(r"([1-9][0-9]*)([smhdw])")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_UNKNOWN = "unknown"
_BUNDLE = "bundle"
_CANT_PROVE = "so Skylos can't prove {what} came from this commit's code."

_UPLOAD_IDENTITY_WORDS = {
    "github_oidc": "GitHub OIDC without a verified repository id",
    "gitlab_oidc": "GitLab OIDC",
    "project_api_key": "a project API key",
    "legacy_project_key": "a legacy project key",
    "session": "a signed-in session",
}
_LEVEL_NOTES = {
    VERDICT_OVERRIDDEN_LEVEL: "An admin overrode the gate for this commit (merge anyway).",
    VERDICT_GATE_DISABLED_LEVEL: (
        "The workspace gate is off, so this PASSED is not a policy decision."
    ),
    VERDICT_GATE_UNKNOWN_LEVEL: (
        "The scan recorded no gate settings, so this PASSED is not a policy decision."
    ),
}
_REQUIRE_PASSED = "--require-passed: "
_LEVEL_REFUSALS = {
    VERDICT_GATE_DISABLED_LEVEL: (
        f"the workspace gate is off ({VERDICT_GATE_DISABLED_LEVEL}); "
        "only a policy pass is accepted."
    ),
    VERDICT_OVERRIDDEN_LEVEL: (
        f"an admin overrode the gate ({VERDICT_OVERRIDDEN_LEVEL}); "
        "add --allow-override to accept overrides."
    ),
    VERDICT_GATE_UNKNOWN_LEVEL: (
        f"the scan recorded no gate settings ({VERDICT_GATE_UNKNOWN_LEVEL}); "
        "upload a fresh scan to get a policy decision."
    ),
}

_DESCRIPTION = (
    "Verify a signed Skylos Cloud check verdict: the Ed25519 DSSE signature,\n"
    "the in-toto / SLSA verification summary, and the check summary it\n"
    "commits to."
)
_EPILOG = (
    "A verdict proves this Skylos check ran under this policy with this\n"
    "result for the results uploaded for this commit. It does not prove the\n"
    "code is safe, and unless the upload is repository-verified it cannot\n"
    "prove the results came from this commit's code.\n\n"
    f"Default keys: {DEFAULT_KEYS_URL}\n\n"
    "Recommended deploy gate (fetch the verdict fresh from the API):\n"
    '  skylos verify-verdict verdict.json --commit "$SHA" \\\n'
    "    --repository github.com/org/repo --require-repository-verified \\\n"
    "    --require-trusted-upload --max-age 7d --require-passed\n\n"
    "Exit codes: 0 verified (and passing, with --require-passed); 1 verified\n"
    "but not passing, only with --require-passed; 2 not verified, a --commit/\n"
    "--repository/--project/--workspace/--max-age/--require-repository-verified/\n"
    "--require-trusted-upload mismatch, invalid input, keys unavailable, or\n"
    "cryptography missing."
)


class NotVerified(Exception):
    """A problem that stops verification before or instead of a result."""


def run_verify_verdict_command(argv: Sequence[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv))
    if args.allow_override and not args.require_passed:
        parser.error("--allow-override only applies with --require-passed")
    try:
        result = _verify(args)
    except NotVerified as exc:
        return _report_not_verified(str(exc), as_json=args.json)
    if not result.ok:
        reason = result.reason or "Unknown failure."
        return _report_not_verified(reason, as_json=args.json)
    return _report_verified(result, args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos verify-verdict",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "bundle",
        metavar="BUNDLE",
        help='Verdict bundle JSON file; "-" reads it from stdin.',
    )
    parser.add_argument(
        "--keys",
        metavar="PATH_OR_URL",
        default=DEFAULT_KEYS_URL,
        help=(
            "Trusted public keys: a local JSON file (offline) or an https:// URL "
            "(default: the Skylos published key set below)."
        ),
    )
    _add_expectation_args(parser)
    _add_gate_args(parser)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print one JSON object instead of text.",
    )
    return parser


def _add_expectation_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--commit",
        metavar="SHA",
        help="Require the verdict to be for this full commit SHA (case-insensitive).",
    )
    parser.add_argument(
        "--repository",
        metavar="HOST/OWNER/REPO",
        help="Require this repository, e.g. github.com/acme/api (case-insensitive).",
    )
    parser.add_argument(
        "--project",
        metavar="PROJECT_ID",
        help="Require the verdict to be for this Skylos project id.",
    )
    parser.add_argument(
        "--workspace",
        metavar="ORG_ID",
        help="Require the verdict to belong to this Skylos workspace id.",
    )
    parser.add_argument(
        "--require-repository-verified",
        action="store_true",
        help=(
            "Require a GitHub OIDC upload bound to the repository and a project "
            "bound to it by repository id."
        ),
    )
    parser.add_argument(
        "--require-trusted-upload",
        action="store_true",
        help=(
            "Require an upload Skylos Cloud trusted: CI with GitHub or GitLab "
            "OIDC, or a CI key the project trusts. Rejects skylos login uploads "
            "and verdicts signed before trust was recorded."
        ),
    )
    parser.add_argument(
        "--max-age",
        metavar="DURATION",
        type=_parse_duration,
        help="Reject verdicts signed longer ago than this, e.g. 90m, 24h, 7d.",
    )


def _add_gate_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--require-passed",
        action="store_true",
        help=(
            f"Exit 1 unless the result is PASSED at level {VERDICT_PASSED_LEVEL}. "
            "FAILED, an overridden gate, and a disabled gate do not pass."
        ),
    )
    parser.add_argument(
        "--allow-override",
        action="store_true",
        help=(
            f"With --require-passed, also accept {VERDICT_OVERRIDDEN_LEVEL} (an "
            f"admin chose merge anyway). {VERDICT_GATE_DISABLED_LEVEL} never passes."
        ),
    )


def _parse_duration(text: str) -> timedelta:
    match = _DURATION.fullmatch(text.strip().lower())
    if match is None:
        raise argparse.ArgumentTypeError(
            f"invalid duration {text!r}; use a number and s, m, h, d, or w, e.g. 7d"
        )
    count, unit = match.groups()
    try:
        return timedelta(seconds=int(count) * _DURATION_UNITS[unit])
    except OverflowError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid duration {text!r}; too long"
        ) from exc


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _flag_value(value: str | None, flag: str) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        raise NotVerified(f"{flag} is empty.")
    return value


def _expectations(args: argparse.Namespace) -> VerdictExpectations:
    return VerdictExpectations(
        commit=_flag_value(args.commit, "--commit"),
        project=_flag_value(args.project, "--project"),
        workspace=_flag_value(args.workspace, "--workspace"),
        repository=_flag_value(args.repository, "--repository"),
        require_repository_verified=args.require_repository_verified,
        require_trusted_upload=args.require_trusted_upload,
        max_age=args.max_age,
    )


def _verify(args: argparse.Namespace) -> VerdictVerification:
    expectations = _expectations(args)
    # Check the optional dependency before reading input or fetching keys.
    try:
        load_crypto()
    except VerdictCryptoUnavailable as exc:
        raise NotVerified(str(exc)) from exc
    bundle = _load_bundle(args.bundle)
    keys = _load_keys(args.keys)
    # Read the clock after any key fetch, so --max-age is measured at the check.
    expectations = dataclasses.replace(expectations, now=_utc_now())
    return verify_verdict_bundle(bundle, keys, expectations)


# ---------------------------------------------------------------------- input


def _load_bundle(source: str) -> Any:
    if source == "-":
        raw = _read_stdin(MAX_BUNDLE_BYTES)
    else:
        raw = _read_file(Path(source), MAX_BUNDLE_BYTES, _BUNDLE)
    try:
        return parse_json_strict(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise NotVerified("The bundle is not JSON.") from exc


def _load_keys(source: str) -> list[dict]:
    if _URL_SCHEME.match(source):
        raw = _fetch_keys(source)
    else:
        raw = _read_file(Path(source), MAX_KEYS_BYTES, "key set")
    try:
        document = parse_json_strict(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise NotVerified("The key set is not JSON.") from exc
    keys = get_path(document, "keys")
    if not isinstance(keys, list):
        raise NotVerified('The key set has no "keys" list.')
    return [key for key in keys if isinstance(key, dict)]


def _too_large(what: str, limit: int) -> NotVerified:
    return NotVerified(f"The {what} is larger than {limit:,} bytes.")


def _read_file(path: Path, limit: int, what: str) -> bytes:
    try:
        with path.open("rb") as handle:  # skylos: ignore[SKY-D325] operator CLI path
            data = handle.read(limit + 1)
    except OSError as exc:
        detail = exc.strerror or exc.__class__.__name__
        raise NotVerified(f"Could not read the {what} {path}: {detail}.") from exc
    if len(data) > limit:
        raise _too_large(what, limit)
    return data


def _read_stdin(limit: int) -> bytes:
    stream = getattr(sys.stdin, "buffer", None)
    if stream is not None:
        data = stream.read(limit + 1)
    else:
        data = sys.stdin.read(limit + 1).encode("utf-8")
    if len(data) > limit:
        raise _too_large(_BUNDLE, limit)
    return data


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to other https:// URLs."""

    def redirect_request(self, req, *args):
        # urllib passes (fp, code, msg, headers, newurl) after the request.
        newurl = args[-1]
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise NotVerified("The key set URL redirected away from https://.")
        return super().redirect_request(req, *args)


def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_HttpsOnlyRedirects)


def _fetch_keys(url: str) -> bytes:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise NotVerified(f"The key set URL is not valid: {exc}.") from exc
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise NotVerified(
            "The key set URL must use https:// (or pass a local key file)."
        )
    from skylos import __version__

    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": f"skylos/{__version__}"},
    )
    # The URL is the operator's chosen trust root: https only, https-only
    # redirects, a timeout, and a bounded read.
    opener = _build_opener()
    try:
        with opener.open(request, timeout=KEYS_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_KEYS_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise NotVerified(
            f"Could not fetch the key set from {url}: HTTP {exc.code}."
        ) from exc
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        OSError,
        ValueError,
    ) as exc:
        detail = getattr(exc, "reason", None) or exc
        raise NotVerified(f"Could not fetch the key set from {url}: {detail}.") from exc
    if len(body) > MAX_KEYS_BYTES:
        raise _too_large("key set", MAX_KEYS_BYTES)
    return body


# --------------------------------------------------------------------- output


def _report_not_verified(reason: str, *, as_json: bool) -> int:
    if as_json:
        print(json.dumps(_failure_payload(reason), indent=2))
    else:
        print(f"Not verified: {_clean(reason)}", file=sys.stderr)
    return EXIT_NOT_VERIFIED


def _report_verified(result: VerdictVerification, args: argparse.Namespace) -> int:
    levels = verified_levels(result.statement or {})
    payload = _success_payload(result, levels)
    problem = None
    if args.require_passed:
        problem = _require_passed_problem(
            payload["verdict"], levels, allow_override=args.allow_override
        )
    payload["reason"] = problem
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        lines = _human_lines(result.summary or {}, payload, levels)
        if problem:
            lines.append(_clean(problem))
        for line in lines:
            print(line)
    return EXIT_NOT_PASSING if problem else EXIT_VERIFIED


def _require_passed_problem(
    verdict: str | None, levels: list[str], *, allow_override: bool
) -> str | None:
    """Why --require-passed refuses this verified verdict, or None."""
    if verdict != "PASSED":
        return _REQUIRE_PASSED + "the verified result is FAILED."
    accepted = {VERDICT_PASSED_LEVEL}
    if allow_override:
        accepted.add(VERDICT_OVERRIDDEN_LEVEL)
    # A disabled gate never passes, whatever else the levels say.
    if VERDICT_GATE_DISABLED_LEVEL not in levels and accepted.intersection(levels):
        return None
    for level in (
        VERDICT_GATE_DISABLED_LEVEL,
        VERDICT_GATE_UNKNOWN_LEVEL,
        VERDICT_OVERRIDDEN_LEVEL,
    ):
        if level in levels:
            return _REQUIRE_PASSED + _LEVEL_REFUSALS[level]
    return _REQUIRE_PASSED + f"the verdict has no {VERDICT_PASSED_LEVEL} level."


def _failure_payload(reason: str) -> dict:
    return {
        "verified": False,
        "verdict": None,
        "verified_level": None,
        "commit": None,
        "repository": None,
        "repository_binding": None,
        "project_id": None,
        "workspace_id": None,
        "scan_id": None,
        "policy_hash": None,
        "key_id": None,
        "time_verified": None,
        "repository_verified": None,
        "reason": reason,
    }


def _success_payload(result: VerdictVerification, levels: list[str]) -> dict:
    statement = result.statement or {}
    summary = result.summary or {}
    binding = summary.get("repository_binding")
    return {
        "verified": True,
        "verdict": get_path(statement, "predicate", "verificationResult"),
        "verified_level": ", ".join(levels) or None,
        "commit": statement["subject"][0]["digest"]["gitCommit"],
        "repository": _text(summary.get("repository")),
        "repository_binding": "verified" if binding == "verified" else "unverified",
        "project_id": _text(get_path(summary, "project", "id")),
        "workspace_id": _text(get_path(summary, "workspace", "id")),
        "scan_id": _text(get_path(summary, "scan", "id")),
        "policy_hash": _text(get_path(summary, "policy", "hash")),
        "key_id": result.key_id,
        "time_verified": _text(get_path(statement, "predicate", "timeVerified")),
        "repository_verified": repository_verified(summary),
        "reason": None,
    }


def _human_lines(summary: dict, payload: dict, levels: list[str]) -> list[str]:
    policy_hash = payload["policy_hash"]
    details = ", ".join(
        [
            f"level {payload['verified_level'] or 'none'}",
            f"scan {payload['scan_id'] or _UNKNOWN}",
            f"policy {policy_hash[:12]}" if policy_hash else "no recorded policy",
            f"key {payload['key_id']}",
            f"verified {payload['time_verified'] or _UNKNOWN}",
        ]
    )
    target = _target(summary, payload["commit"])
    lines = [f"Verified: {payload['verdict']} for {target} ({details})"]
    lines.extend(_LEVEL_NOTES[level] for level in levels if level in _LEVEL_NOTES)
    if not payload["repository_verified"]:
        lines.append(_unverified_repository_line(summary))
    return [_clean(line) for line in lines]


def _unverified_repository_line(summary: dict) -> str:
    if get_path(summary, "upload_identity", "repository_verified") is not True:
        identity = _upload_identity(summary)
        return f"The results were uploaded with {identity}, " + _CANT_PROVE.format(
            what="they"
        )
    return (
        "The project is not bound to its repository by GitHub repository id, "
        + _CANT_PROVE.format(what="the results")
    )


def _target(summary: dict, commit: str) -> str:
    repository = _text(summary.get("repository"))
    if repository:
        return f"{repository}@{commit}"
    project = _text(get_path(summary, "project", "name")) or _text(
        get_path(summary, "project", "id")
    )
    return f"Skylos project {project or _UNKNOWN}@{commit}"


def _upload_identity(summary: dict) -> str:
    identity = get_path(summary, "upload_identity")
    upload_type = _text(get_path(identity, "type"))
    if upload_type is None:
        words = "an unrecorded upload identity"
    else:
        words = _UPLOAD_IDENTITY_WORDS.get(upload_type, f'upload type "{upload_type}"')
    label = _text(get_path(identity, "api_key_label"))
    return f'{words} "{label}"' if label else words


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _clean(text: str) -> str:
    """Drop terminal control characters from text that came from a bundle."""
    return _CONTROL_CHARS.sub("?", text)
