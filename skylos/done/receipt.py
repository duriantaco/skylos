"""The done receipt (``skylos.done-receipt/v1``): JSON, text and markdown.

The JSON is what Skylos Cloud accepts as ``done_receipt`` in a report
upload (contracts/upload/v1.json). ``validate_receipt`` applies the same
limits Cloud does, so a receipt Skylos writes is never stored as unreadable.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import (
    _close_file_descriptor,
    _directory_open_flags,
    _open_output_parent,
    read_text_no_symlink,
    save_project_json_cache,
    write_text_no_symlink,
)
from skylos.done.engine import DoneResult

SCHEMA = "skylos.done-receipt/v1"
RECEIPTS_DIR = Path(".skylos") / "receipts"
LATEST_NAME = "latest.json"

MAX_CHECKS = 20
MAX_FINDINGS = 500
MAX_EVIDENCE_KEYS = 12
MAX_MESSAGE = 300
MAX_EVIDENCE_TEXT = 120
MAX_PATH = 512
MAX_UNVERIFIED = 5000
MAX_RECEIPT_BYTES = 8 * 1024 * 1024

_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
_CHECK_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_RULE_RE = re.compile(r"^[A-Z][A-Z0-9-]{1,40}$")
_CLIENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,63}$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,32}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

LABELS = {
    "agent_edits": "Recorded session edits pass the existing guards",
    "tests_pass": "Tests pass when Skylos runs them",
    "test_tampering": "No tests deleted, skipped or weakened",
    "gate_tampering": "Skylos settings and hooks left alone",
    "secrets": "No secrets added",
    "unknown_imports": "Every package and import is real",
}
FIXES = {
    "agent_edits": "Fix the remaining edit findings and run skylos hook recheck --session.",
    "tests_pass": "Fix the failing tests, or the code they test.",
    "test_tampering": "Put back the removed or skipped tests and the original assertions and settings.",
    "gate_tampering": "Undo the changes to those files. A person should make changes there.",
    "secrets": "Remove the secret, rotate it, and load it from the environment or a secret store.",
    "unknown_imports": "Remove the made-up import, or declare the real package that provides it.",
}


# ---------------------------------------------------------------------------
# Building and validating
# ---------------------------------------------------------------------------


def build_receipt(
    result: DoneResult,
    *,
    agent_client: str = "unknown",
    agent_model: str | None = None,
    session_id: str | None = None,
    stop_blocks: int | None = None,
) -> dict[str, Any]:
    comparison = result.comparison
    checks = []
    for outcome in result.checks[:MAX_CHECKS]:
        check = outcome.result
        findings = sorted(check.findings, key=lambda f: not f.blocking)
        checks.append(
            {
                "id": check.id,
                "rule": check.rule
                if check.rule and _RULE_RE.match(check.rule)
                else None,
                "mode": outcome.mode,
                "status": check.status,
                "evidence": _clean_evidence(check.evidence),
                "findings": [
                    {
                        "rule": f.rule if f.rule and _RULE_RE.match(f.rule) else None,
                        "file": _clean_path(f.file),
                        "line": f.line
                        if isinstance(f.line, int) and f.line >= 1
                        else None,
                        "message": _clean_text(f.message, MAX_MESSAGE) or "finding",
                    }
                    for f in findings[:MAX_FINDINGS]
                ],
            }
        )
    return {
        "schema": SCHEMA,
        "skylos_version": _version(),
        "base": {"sha": comparison.base_sha, "source": comparison.base_source},
        "head": {"sha": comparison.head_sha, "dirty": comparison.head_dirty},
        "agent": {
            "client": agent_client
            if _CLIENT_RE.match(agent_client or "")
            else "unknown",
            "model": agent_model
            if agent_model and _MODEL_RE.match(agent_model)
            else None,
            "session_id": session_id
            if session_id and _SESSION_RE.match(session_id)
            else None,
        },
        "config_digest": result.config.digest(),
        "verdict": result.verdict,
        "stop_blocks": stop_blocks,
        "checks": checks,
        "unverified": [],
    }


def validate_receipt(receipt: Any) -> list[str]:
    """Problems that would make Skylos Cloud store the receipt as unreadable."""
    problems: list[str] = []
    if not isinstance(receipt, dict) or receipt.get("schema") != SCHEMA:
        return [f"schema is not {SCHEMA}"]
    version = receipt.get("skylos_version")
    if version is not None and not (
        isinstance(version, str) and _VERSION_RE.match(version)
    ):
        problems.append("skylos_version is malformed")
    digest = receipt.get("config_digest")
    if digest is not None and not (
        isinstance(digest, str) and _DIGEST_RE.match(digest)
    ):
        problems.append("config_digest is malformed")
    if not isinstance(receipt.get("verdict"), str) or receipt["verdict"] not in {
        "pass",
        "fail",
        "incomplete",
    }:
        problems.append("verdict must be pass, fail or incomplete")
    base, head, agent = receipt.get("base"), receipt.get("head"), receipt.get("agent")
    if not (
        isinstance(base, dict)
        and isinstance(base.get("sha"), str)
        and _SHA_RE.match(base["sha"])
        and isinstance(base.get("source"), str)
        and base["source"] in {"session", "merge_base", "head"}
    ):
        problems.append("base is malformed")
    if not (
        isinstance(head, dict)
        and isinstance(head.get("sha"), str)
        and _SHA_RE.match(head["sha"])
        and isinstance(head.get("dirty"), bool)
    ):
        problems.append("head is malformed")
    if not (
        isinstance(agent, dict)
        and isinstance(agent.get("client"), str)
        and _CLIENT_RE.match(agent["client"])
        and _optional(agent.get("model"), _MODEL_RE)
        and _optional(agent.get("session_id"), _SESSION_RE)
    ):
        problems.append("agent is malformed")
    stop_blocks = receipt.get("stop_blocks")
    if stop_blocks is not None and not (
        isinstance(stop_blocks, int)
        and not isinstance(stop_blocks, bool)
        and 0 <= stop_blocks <= 1000
    ):
        problems.append("stop_blocks is malformed")
    checks = receipt.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS:
        problems.append(f"checks must hold 1 to {MAX_CHECKS} entries")
        checks = []
    seen = set()
    for check in checks:
        problems += [f"check {_label(check)}: {p}" for p in _check_problems(check)]
        if isinstance(check, dict) and isinstance(check.get("id"), str):
            if check.get("id") in seen:
                problems.append(f"check {check.get('id')} appears twice")
            seen.add(check.get("id"))
    unverified = receipt.get("unverified", [])
    if not isinstance(unverified, list) or len(unverified) > MAX_UNVERIFIED:
        problems.append("unverified is malformed")
    else:
        for item in unverified:
            if not (
                isinstance(item, dict)
                and _clean_path(item.get("file")) == item.get("file")
                and isinstance(item.get("line"), int)
                and not isinstance(item["line"], bool)
                and item["line"] >= 1
            ):
                problems.append("unverified entry is malformed")
                break
    return problems


def _check_problems(check: Any) -> list[str]:
    if not isinstance(check, dict):
        return ["not an object"]
    problems = []
    if not (isinstance(check.get("id"), str) and _CHECK_ID_RE.match(check["id"])):
        problems.append("id is malformed")
    if not _optional(check.get("rule"), _RULE_RE):
        problems.append("rule is malformed")
    if not isinstance(check.get("mode"), str) or check["mode"] not in {
        "block",
        "advise",
        "shadow",
        "off",
    }:
        problems.append("mode is malformed")
    if not isinstance(check.get("status"), str) or check["status"] not in {
        "pass",
        "fail",
        "incomplete",
        "skipped",
    }:
        problems.append("status is malformed")
    evidence = check.get("evidence", {})
    if evidence is not None and (
        not isinstance(evidence, dict)
        or len(evidence) > MAX_EVIDENCE_KEYS
        or _clean_evidence(evidence) != evidence
    ):
        problems.append("evidence is malformed")
    findings = check.get("findings", [])
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        problems.append("findings are malformed")
        return problems
    for finding in findings:
        if not (
            isinstance(finding, dict)
            and _optional(finding.get("rule"), _RULE_RE)
            and (
                finding.get("file") is None
                or _clean_path(finding.get("file")) == finding.get("file")
            )
            and (
                finding.get("line") is None
                or (
                    isinstance(finding.get("line"), int)
                    and not isinstance(finding["line"], bool)
                    and finding["line"] >= 1
                )
            )
            and isinstance(finding.get("message"), str)
            and finding["message"].strip()
            and len(finding["message"]) <= MAX_MESSAGE
            and not _CONTROL_RE.search(finding["message"])
        ):
            problems.append("a finding is malformed")
            break
    return problems


def _label(check: Any) -> str:
    return str(check.get("id")) if isinstance(check, dict) else "?"


def _optional(value: Any, pattern: re.Pattern[str]) -> bool:
    return value is None or (isinstance(value, str) and bool(pattern.match(value)))


def _clean_text(value: Any, limit: int) -> str:
    text = _CONTROL_RE.sub(" ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def _clean_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAX_PATH:
        return None
    if value.startswith(("/", "~")) or "\\" in value or re.match(r"^[A-Za-z]:", value):
        return None
    if _CONTROL_RE.search(value):
        return None
    if any(segment in {"", ".."} for segment in value.split("/")):
        return None
    return value


def _clean_evidence(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        return {}
    cleaned: dict[str, Any] = {}
    # "summary" first: it is the line people read.
    keys = sorted(evidence, key=lambda k: (k != "summary", list(evidence).index(k)))
    for key in keys:
        if len(cleaned) >= MAX_EVIDENCE_KEYS:
            break
        value = evidence[key]
        if not isinstance(key, str) or not _EVIDENCE_KEY_RE.match(key):
            continue
        if isinstance(value, bool) or (
            isinstance(value, int) and not isinstance(value, bool)
        ):
            cleaned[key] = value
        elif isinstance(value, float) and math.isfinite(value):
            cleaned[key] = value
        elif isinstance(value, str):
            text = _clean_text(value, MAX_EVIDENCE_TEXT)
            if text == value:
                cleaned[key] = value
            elif text:
                cleaned[key] = text
    return cleaned


def _version() -> str | None:
    try:
        from skylos import __version__

        return __version__ if _VERSION_RE.match(__version__) else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Writing and reading
# ---------------------------------------------------------------------------


def _prepare_receipts_directory(root: Path) -> Path | None:
    """Create fixed receipt directories without following replaced parents."""
    try:
        root = root.resolve(strict=True)
        if not root.is_dir():
            return None
    except (OSError, ValueError, RuntimeError):
        return None
    directory = root / RECEIPTS_DIR
    if (
        os.name != "nt"
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    ):
        directory_fd = _open_output_parent(root / ".skylos")
        if directory_fd is None:
            return None
        try:
            for component in (".skylos", "receipts"):
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(
                    component, _directory_open_flags(), dir_fd=directory_fd
                )
                _close_file_descriptor(directory_fd)
                directory_fd = next_fd
                if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
                    return None
        except OSError:
            return None
        finally:
            _close_file_descriptor(directory_fd)
        return directory

    # Platforms without descriptor-relative opens use the same checked-path
    # fallback as the file writer. Recheck each directory after creation.
    try:
        for candidate in (root / ".skylos", directory):
            if candidate.is_symlink():
                return None
            candidate.resolve().relative_to(root)
            candidate.mkdir(mode=0o700, exist_ok=True)
            if candidate.is_symlink() or not candidate.is_dir():
                return None
            candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError, RuntimeError):
        return None
    return directory


def write_receipt(root: Path, receipt: dict[str, Any]) -> Path | None:
    """Write the receipt under .skylos/receipts/ and as latest.json."""
    if validate_receipt(receipt):
        return None
    try:
        text = json.dumps(receipt, indent=2, sort_keys=False, allow_nan=False) + "\n"
    except (TypeError, ValueError, OverflowError):
        return None
    if len(text.encode("utf-8")) > MAX_RECEIPT_BYTES:
        return None
    directory = _prepare_receipts_directory(root)
    if directory is None:
        return None
    # Receipts are local records, never part of a commit. Ignoring them from
    # inside their own directory leaves the repository's .gitignore alone.
    ignore = directory / ".gitignore"
    if not ignore.exists() and not ignore.is_symlink():
        write_text_no_symlink(ignore, "*\n")
    name = f"{receipt['head']['sha'][:12]}-{receipt['base']['sha'][:12]}.json"
    path = directory / name
    if not write_text_no_symlink(path, text):
        return None
    if not save_project_json_cache(root, RECEIPTS_DIR / LATEST_NAME, json.loads(text)):
        return None
    return path


def read_receipt(path: Path) -> dict[str, Any] | None:
    text = read_text_no_symlink(path, max_bytes=MAX_RECEIPT_BYTES)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("schema") == SCHEMA else None


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _status_word(check: dict[str, Any]) -> str:
    status, mode = check.get("status"), check.get("mode")
    if status == "pass":
        return "PASS"
    if status == "skipped":
        return "OFF" if mode == "off" else "SKIP"
    if mode != "block":
        return "WARN"
    return "FAIL" if status == "fail" else "UNFINISHED"


def _headline(receipt: dict[str, Any]) -> str:
    base, head = receipt["base"], receipt["head"]
    source = {
        "merge_base": "merge base",
        "session": "session start",
        "head": "HEAD",
    }.get(base["source"], base["source"])
    dirty = " + uncommitted changes" if head.get("dirty") else ""
    return f"Skylos done · base {base['sha'][:7]} ({source}) · head {head['sha'][:7]}{dirty}"


def _verdict_line(receipt: dict[str, Any]) -> str:
    blocking = [
        c
        for c in receipt["checks"]
        if c.get("mode") == "block" and c.get("status") in {"fail", "incomplete"}
    ]
    verdict = receipt["verdict"]
    if verdict == "pass":
        return "Verdict: PASS"
    word = "FAIL" if verdict == "fail" else "UNFINISHED"
    names = ", ".join(LABELS.get(c["id"], c["id"]) for c in blocking)
    return f"Verdict: {word} ({names})"


def _visible(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    # Shadow checks are measured, never shown.
    return [c for c in receipt["checks"] if c.get("mode") != "shadow"]


def render_text(receipt: dict[str, Any], *, max_findings: int = 10) -> str:
    lines = [_headline(receipt)]
    for check in _visible(receipt):
        summary = check.get("evidence", {}).get("summary", "")
        lines.append(
            f"{_status_word(check):<11}{LABELS.get(check['id'], check['id'])}: {summary}"
        )
        if check.get("status") in {"fail", "incomplete"} or check.get("findings"):
            for finding in check.get("findings", [])[:max_findings]:
                where = finding.get("file") or ""
                if where and finding.get("line"):
                    where += f":{finding['line']}"
                rule = f"{finding['rule']} " if finding.get("rule") else ""
                lines.append(f"           {where}  {rule}{finding['message']}".rstrip())
            hidden = len(check.get("findings", [])) - max_findings
            if hidden > 0:
                lines.append(f"           … and {hidden} more")
            if check.get("status") == "fail" and check["id"] in FIXES:
                lines.append(f"           Fix: {FIXES[check['id']]}")
    shadow = len(receipt["checks"]) - len(_visible(receipt))
    if shadow:
        lines.append(f"{shadow} check(s) measured silently (shadow mode)")
    lines.append(_verdict_line(receipt))
    return "\n".join(lines)


def render_markdown(receipt: dict[str, Any], *, max_findings: int = 10) -> str:
    out = [f"## {_md(_headline(receipt))}", ""]
    out.append("| Result | Check | Details |")
    out.append("|:--|:--|:--|")
    for check in _visible(receipt):
        summary = check.get("evidence", {}).get("summary", "")
        out.append(
            f"| {_status_word(check)} | {_md(LABELS.get(check['id'], check['id']))} | {_md(summary)} |"
        )
    for check in _visible(receipt):
        findings = check.get("findings", [])
        if not findings:
            continue
        out += ["", f"**{_md(LABELS.get(check['id'], check['id']))}**", ""]
        for finding in findings[:max_findings]:
            where = finding.get("file") or ""
            if where and finding.get("line"):
                where += f":{finding['line']}"
            rule = f"`{finding['rule']}` " if finding.get("rule") else ""
            location = f"`{_md(where)}` " if where else ""
            out.append(f"- {location}{rule}{_md(finding['message'])}")
        hidden = len(findings) - max_findings
        if hidden > 0:
            out.append(f"- … and {hidden} more")
    out += ["", f"**{_verdict_line(receipt)}**", ""]
    return "\n".join(out)


def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------


def load_receipt_for_upload(
    receipt_path: str | Path, repo_path: str | Path
) -> tuple[dict[str, Any] | None, str | None]:
    """A receipt that may ride on this upload, or the reason it may not.

    Both the saved receipt and the current checkout must describe a clean
    HEAD: a receipt for other code would vouch for the wrong commit.
    """
    receipt = read_receipt(Path(receipt_path))
    if receipt is None:
        return None, f"cannot read the done receipt {receipt_path}"
    error = receipt_upload_error(receipt, repo_path)
    return (None, error) if error else (receipt, None)


def receipt_upload_error(
    receipt: Any, repo_path: str | Path, *, commit_hash: str | None = None
) -> str | None:
    """Bind an upload receipt to the current clean checkout and upload commit.

    This is checked again when the upload is prepared, after analysis, so
    an edit or checkout made after CLI argument parsing cannot reuse it.
    """
    from skylos.done.base import DoneError, open_comparison

    problems = validate_receipt(receipt)
    if problems:
        return f"the done receipt is malformed: {problems[0]}"
    try:
        comparison = open_comparison(repo_path)
    except DoneError as exc:
        return f"cannot check the done receipt: {exc}"
    if receipt["head"]["sha"] != comparison.head_sha:
        return (
            f"the done receipt is for commit {receipt['head']['sha'][:12]}, "
            f"not HEAD ({comparison.head_sha[:12]}); run skylos done again"
        )
    if commit_hash is not None and receipt["head"]["sha"] != commit_hash:
        return (
            "the done receipt does not match the upload commit; run skylos done again"
        )
    if receipt["head"]["dirty"]:
        return (
            "the done receipt includes uncommitted changes; "
            "commit them and run skylos done again"
        )
    if comparison.head_dirty:
        return (
            "the current checkout has uncommitted changes; "
            "commit them and run skylos done again before uploading the receipt"
        )
    return None
