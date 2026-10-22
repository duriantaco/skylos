"""Run an explicitly approved Cloud review without executing PR source."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

MAX_FILES = 30
MAX_FILE_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_FINDINGS = 200
SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".go",
        ".php",
        ".rs",
        ".dart",
    }
)
_REVIEW_ID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
_SHA = re.compile(r"[a-f0-9]{40}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class AgentReviewError(ValueError):
    """A review cannot complete safely; messages never contain credentials."""


def _cloud_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as exc:
        raise AgentReviewError("Cloud URL must be an HTTPS origin") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise AgentReviewError("Cloud URL must be an HTTPS origin")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _request_json(session, method: str, url: str, token: str, *, payload=None):
    try:
        with session.request(
            method,
            url,
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
            timeout=(10, 180),
            allow_redirects=False,
            stream=True,
        ) as response:
            if response.status_code < 200 or response.status_code >= 300:
                raise AgentReviewError("Review service rejected the request")
            chunks = []
            size = 0
            for chunk in response.iter_content(chunk_size=65536):
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise AgentReviewError("Review service response is too large")
                chunks.append(chunk)
            data = json.loads(b"".join(chunks))
    except (requests.RequestException, UnicodeError, json.JSONDecodeError) as exc:
        raise AgentReviewError("Review service request failed") from exc
    if not isinstance(data, dict):
        raise AgentReviewError("Review service returned invalid data")
    return data


def _oidc_token(session, environ: Mapping[str, str]) -> str:
    from skylos.api._urls import _validate_github_oidc_request_url

    request_token = environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not request_token or environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise AgentReviewError("Agent review requires a GitHub workflow_dispatch job")
    try:
        url = _validate_github_oidc_request_url(
            environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
        )
    except ValueError as exc:
        raise AgentReviewError("GitHub OIDC request URL is invalid") from exc
    parsed = urlsplit(url)
    query = [
        (key, value) for key, value in parse_qsl(parsed.query) if key != "audience"
    ]
    query.append(("audience", "skylos"))
    url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
    data = _request_json(session, "GET", url, request_token)
    token = data.get("value")
    if not isinstance(token, str) or not token or len(token) > 32768:
        raise AgentReviewError("GitHub did not issue an OIDC token")
    return token


def _validated_bundle(data: dict, origin: str, review_id: str, repository: str):
    token = data.get("token")
    if not isinstance(token, str) or not token or len(token) > 8192:
        raise AgentReviewError("Review service returned an invalid runner token")
    if (
        not _REPOSITORY.fullmatch(str(data.get("repository", "")))
        or data["repository"].lower() != repository.lower()
        or type(data.get("prNumber")) is not int
        or data["prNumber"] < 1
        or not _SHA.fullmatch(str(data.get("baseSha", "")))
        or not _SHA.fullmatch(str(data.get("headSha", "")))
    ):
        raise AgentReviewError("Review service returned an invalid PR identity")
    expected_proxy = f"{origin}/api/pr-reviews/{review_id}/v1"
    if data.get("proxyBaseUrl") != expected_proxy:
        raise AgentReviewError("Review proxy must belong to this Cloud review")
    model = data.get("model")
    if not isinstance(model, str) or not re.fullmatch(
        r"[A-Za-z0-9_.:/-]{1,100}", model
    ):
        raise AgentReviewError("Review service returned an invalid model")
    files = data.get("files")
    if not isinstance(files, list) or len(files) > MAX_FILES:
        raise AgentReviewError("Review source file count exceeds the limit")
    seen = set()
    total = 0
    for source in files:
        if not isinstance(source, dict):
            raise AgentReviewError("Review source is malformed")
        path = source.get("path")
        content = source.get("content")
        if not isinstance(path, str) or not isinstance(content, str):
            raise AgentReviewError("Review source is malformed")
        parsed_path = PurePosixPath(path)
        if (
            not path
            or len(path) > 1024
            or "\\" in path
            or ":" in path
            or any(ord(character) < 32 for character in path)
            or parsed_path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or parsed_path.suffix.lower() not in SOURCE_SUFFIXES
            or path in seen
            or "\x00" in content
        ):
            raise AgentReviewError("Review source path or content is unsafe")
        seen.add(path)
        size = len(content.encode("utf-8"))
        total += size
        if size > MAX_FILE_BYTES or total > MAX_SOURCE_BYTES:
            raise AgentReviewError("Review source size exceeds the limit")
    return data


def _validate_model_findings(payload: object, line_count: int) -> list[dict]:
    from skylos.llm.schemas import FINDING_SCHEMA, SECURITY_DETAILS_SCHEMA

    if not isinstance(payload, dict) or set(payload) != {"findings"}:
        raise AgentReviewError("Model review returned malformed findings")
    findings = payload["findings"]
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise AgentReviewError("Model review returned malformed findings")
    fields = FINDING_SCHEMA["properties"]
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != set(
            FINDING_SCHEMA["required"]
        ):
            raise AgentReviewError("Model review returned malformed findings")
        for name in ("rule_id", "issue_type", "severity", "message", "confidence"):
            if not isinstance(finding[name], str):
                raise AgentReviewError("Model review returned malformed findings")
            choices = fields[name].get("enum")
            if choices is not None and finding[name] not in choices:
                raise AgentReviewError("Model review returned malformed findings")
        if not re.fullmatch(r"SKY-[A-Z][0-9]{3}", finding["rule_id"]):
            raise AgentReviewError("Model review returned an invalid rule ID")
        if not finding["message"].strip() or len(finding["message"]) > 500:
            raise AgentReviewError("Model review returned an invalid message")
        for name in ("explanation", "suggestion", "symbol"):
            if finding[name] is not None and not isinstance(finding[name], str):
                raise AgentReviewError("Model review returned malformed findings")
        line = finding["line"]
        end = finding["end_line"]
        if end is None:
            end = line
        if (
            type(line) is not int
            or type(end) is not int
            or not 1 <= line <= end <= line_count
        ):
            raise AgentReviewError("Model finding is outside the reviewed source")
        details = finding["security_details"]
        if details is not None:
            if not isinstance(details, dict) or set(details) != set(
                SECURITY_DETAILS_SCHEMA["required"]
            ):
                raise AgentReviewError(
                    "Model review returned malformed security evidence"
                )
            if any(
                not isinstance(details[name], str)
                for name in ("attack_path", "impact", "fix", "unsafe_if")
            ):
                raise AgentReviewError(
                    "Model review returned malformed security evidence"
                )
            evidence = details["evidence_lines"]
            if not isinstance(evidence, list) or any(
                type(line) is not int or not 1 <= line <= line_count
                for line in evidence
            ):
                raise AgentReviewError("Model evidence is outside the reviewed source")
    return findings


def _review_sources(session, bundle: dict) -> list[dict]:
    from skylos.llm.agents import FINDINGS_RESPONSE_FORMAT
    from skylos.llm.context import ContextBuilder
    from skylos.llm.prompts import build_review_prompt
    from skylos.llm.schemas import normalize_json_response_text, parse_llm_response
    from skylos.llm.validator import ResultValidator, deduplicate_findings

    builder = ContextBuilder(max_context_tokens=32768)
    validator = ResultValidator()
    findings = []
    for source in bundle["files"]:
        path = source["path"]
        content = source["content"]
        context = builder.build_analysis_context(
            content, file_path=path, include_review_hints=True
        )
        system, user = build_review_prompt(context, include_examples=False)
        result = _request_json(
            session,
            "POST",
            bundle["proxyBaseUrl"] + "/chat/completions",
            bundle["token"],
            payload={
                "model": bundle["model"],
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": 4096,
                "temperature": 0,
                "stream": False,
                "response_format": FINDINGS_RESPONSE_FORMAT,
            },
        )
        try:
            choice = result["choices"][0]
            if choice.get("finish_reason") != "stop":
                raise AgentReviewError("Model review did not finish")
            raw = normalize_json_response_text(choice["message"]["content"])
            payload = json.loads(raw)
            line_count = max(1, len(content.splitlines()))
            raw_findings = _validate_model_findings(payload, line_count)
            parsed = parse_llm_response(raw, path)
            if len(parsed) != len(raw_findings):
                raise AgentReviewError("Model review returned malformed findings")
            for finding in parsed:
                line = finding.location.line
                end_line = finding.location.end_line or line
                if (
                    finding.location.file != path
                    or type(line) is not int
                    or type(end_line) is not int
                    or not 1 <= line <= end_line <= line_count
                ):
                    raise AgentReviewError(
                        "Model finding is outside the reviewed source"
                    )
            validated, _ = validator.validate(parsed, content, path)
            for finding in deduplicate_findings(validated):
                serialized = finding.to_dict()
                findings.append(
                    {
                        "file": serialized["location"]["file"],
                        "line": serialized["location"]["line"],
                        "rule_id": serialized["rule_id"],
                        "message": serialized["message"],
                        "severity": serialized["severity"].upper(),
                        "category": serialized["issue_type"],
                        "explanation": serialized.get("explanation"),
                        "suggestion": serialized.get("suggestion"),
                        "confidence": serialized.get("confidence"),
                        "security_details": serialized.get("security_details"),
                    }
                )
            if len(findings) > MAX_FINDINGS:
                raise AgentReviewError("Model review returned too many findings")
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            if isinstance(exc, AgentReviewError):
                raise
            raise AgentReviewError("Model review returned malformed findings") from exc
    return findings


def run_agent_review(
    review_id: str, cloud_url: str, *, environ=None, session=None
) -> int:
    """Review only the approved source bundle; never discover or execute a repo."""
    if not _REVIEW_ID.fullmatch(review_id):
        raise AgentReviewError("Review ID must be a lowercase UUID")
    origin = _cloud_origin(cloud_url)
    if environ is None:
        environment = os.environ
    else:
        environment = environ
    own_session = session is None
    if own_session:
        session = requests.Session()
        session.trust_env = False
    runner_token = None
    complete_url = f"{origin}/api/pr-reviews/{review_id}/complete"
    try:
        identity = _oidc_token(session, environment)
        data = _request_json(
            session,
            "POST",
            f"{origin}/api/pr-reviews/{review_id}/runner",
            identity,
            payload={},
        )
        candidate_token = data.get("token")
        if isinstance(candidate_token, str) and 0 < len(candidate_token) <= 8192:
            runner_token = candidate_token
        bundle = _validated_bundle(
            data, origin, review_id, environment.get("GITHUB_REPOSITORY", "")
        )
        runner_token = bundle["token"]
        findings = _review_sources(session, bundle)
        _request_json(
            session,
            "POST",
            complete_url,
            runner_token,
            payload={
                "status": "completed",
                "findings": findings,
                "summary": {
                    "filesReviewed": len(bundle["files"]),
                    "findingsCount": len(findings),
                    "baseSha": bundle["baseSha"],
                    "headSha": bundle["headSha"],
                },
            },
        )
        return 0
    except Exception as exc:
        if runner_token:
            try:
                _request_json(
                    session,
                    "POST",
                    complete_url,
                    runner_token,
                    payload={
                        "status": "failed",
                        "findings": [],
                        "error": "Agent review could not complete safely",
                    },
                )
            except (AgentReviewError, requests.RequestException):
                pass
        if isinstance(exc, AgentReviewError):
            raise
        raise AgentReviewError("Agent review could not complete safely") from exc
    finally:
        if own_session:
            session.close()


def add_agent_review_parser(subcommands):
    parser = subcommands.add_parser(
        "agent-review", help="Run a Cloud-approved paid PR review in GitHub Actions"
    )
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--cloud-url", default="https://skylos.dev")


def run_agent_review_command(args, *, console) -> int:
    try:
        result = run_agent_review(args.review_id, args.cloud_url)
    except AgentReviewError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    console.print("Skylos agent review completed")
    return result
