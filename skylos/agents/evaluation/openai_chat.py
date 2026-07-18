from __future__ import annotations

import ipaddress
import hashlib
import math
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import requests

from ._openai_transport import (
    AgentEndpointError,
    new_agent_session as _new_agent_session,
    post_owned_session_with_deadline as _post_owned_session_with_deadline,
    send_agent_request as _send_agent_request,
)
from ._openai_response import (
    decode_openai_response as _decode_openai_response,
    normalize_openai_chat_response,  # noqa: F401
    redact_json as _redact_json,
    redact_observation as _redact_observation,
    redact_text as _redact_text,
)
from .schema import (
    AgentBehaviorError,
    AgentObservation,
    AgentScenario,
    AgentTarget,
)


MAX_ENDPOINT_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_ENDPOINT_RESPONSE_TOKENS = 32_768
MAX_AUTH_TOKEN_CHARS = 8_192
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class AgentAuthContext:
    _token: str = field(repr=False)

    @property
    def authorization_header(self) -> str:
        return f"Bearer {self._token}"

    def redact_observation(self, observation: AgentObservation) -> AgentObservation:
        return _redact_observation(observation, self._token)

    def redact_value(self, value: Any) -> Any:
        return _redact_json(value, self._token)

    def redact_text(self, value: str) -> str:
        return _redact_text(value, self._token)


@dataclass(frozen=True)
class LiveAgentObservation:
    evaluation: AgentObservation
    persisted: AgentObservation


@dataclass(frozen=True)
class _OpenAIRequest:
    endpoint: str
    headers: dict[str, str]
    payload: dict[str, Any]
    timeout: float


def load_agent_auth_context(auth_env: str | None) -> AgentAuthContext | None:
    if auth_env is None:
        return None
    return AgentAuthContext(_auth_token(auth_env))


def observe_openai_chat(
    target: AgentTarget,
    scenario: AgentScenario,
    *,
    endpoint_override: str | None = None,
    auth_env: str | None = None,
    allow_remote: bool = False,
    allow_contract_endpoint: bool = False,
    session: Any = None,
    request_timeout: float | None = None,
    max_tokens: int = 1024,
) -> AgentObservation:
    evidence = observe_openai_chat_evidence(
        target,
        scenario,
        endpoint_override=endpoint_override,
        auth_context=load_agent_auth_context(auth_env),
        allow_remote=allow_remote,
        allow_contract_endpoint=allow_contract_endpoint,
        session=session,
        request_timeout=request_timeout,
        max_tokens=max_tokens,
    )
    return evidence.persisted


def observe_openai_chat_evidence(
    target: AgentTarget,
    scenario: AgentScenario,
    *,
    endpoint_override: str | None = None,
    auth_context: AgentAuthContext | None = None,
    allow_remote: bool = False,
    allow_contract_endpoint: bool = False,
    session: Any = None,
    request_timeout: float | None = None,
    max_tokens: int = 1024,
) -> LiveAgentObservation:
    request = _prepare_openai_request(
        target,
        scenario,
        endpoint_override=endpoint_override,
        auth_context=auth_context,
        allow_remote=allow_remote,
        allow_contract_endpoint=allow_contract_endpoint,
        request_timeout=request_timeout,
        max_tokens=max_tokens,
    )
    body = _request_response_body(request, session=session)
    observation = _decode_openai_response(body, scenario_id=scenario.scenario_id)
    persisted = (
        observation
        if auth_context is None
        else auth_context.redact_observation(observation)
    )
    return LiveAgentObservation(evaluation=observation, persisted=persisted)


def _prepare_openai_request(
    target: AgentTarget,
    scenario: AgentScenario,
    *,
    endpoint_override: str | None,
    auth_context: AgentAuthContext | None,
    allow_remote: bool,
    allow_contract_endpoint: bool,
    request_timeout: float | None,
    max_tokens: int,
) -> _OpenAIRequest:
    endpoint_override = _validate_endpoint_override(endpoint_override)
    effective_timeout = (
        target.timeout_seconds if request_timeout is None else request_timeout
    )
    _validate_request_limits(
        request_timeout=effective_timeout,
        max_tokens=max_tokens,
    )
    endpoint = endpoint_override if endpoint_override is not None else target.endpoint
    if endpoint is None:
        raise AgentBehaviorError(
            "agent.endpoint is required for live tests; use --observations for offline mode"
        )
    if target.model is None:
        raise AgentBehaviorError(
            "agent.model is required for live tests; use --observations for offline mode"
        )
    endpoint_is_override = endpoint_override is not None
    if auth_context is not None and not endpoint_is_override:
        raise AgentBehaviorError(
            "--auth-env requires a trusted --endpoint override; contract YAML cannot select an authenticated endpoint"
        )
    safe_endpoint = validate_agent_endpoint(
        endpoint,
        allow_remote=allow_remote,
        endpoint_is_override=endpoint_is_override,
        authenticated=auth_context is not None,
        allow_contract_endpoint=allow_contract_endpoint,
    )
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if auth_context is not None:
        headers["Authorization"] = auth_context.authorization_header
    return _OpenAIRequest(
        endpoint=safe_endpoint,
        headers=headers,
        payload=build_openai_chat_request(target, scenario, max_tokens=max_tokens),
        timeout=effective_timeout,
    )


def _request_response_body(request: _OpenAIRequest, *, session: Any) -> bytes:
    owns_session = session is None
    client = _new_agent_session() if session is None else session
    response = None
    deadline = time.monotonic() + request.timeout
    try:
        response = _dispatch_agent_request(client, request, owns_session, deadline)
        _enforce_request_deadline(deadline)
        return _read_success_response(response, deadline)
    except AgentEndpointError:
        raise
    except requests.RequestException as exc:
        raise _request_exception(exc, deadline) from exc
    except (OSError, UnicodeError) as exc:
        raise _response_exception(exc, deadline) from exc
    finally:
        _close_request_resources(response, client, owns_session)


def _dispatch_agent_request(
    client: Any,
    request: _OpenAIRequest,
    owns_session: bool,
    deadline: float,
) -> Any:
    sender = _post_owned_session_with_deadline if owns_session else _send_agent_request
    return sender(
        client,
        request.endpoint,
        payload=request.payload,
        headers=request.headers,
        timeout=request.timeout,
        deadline=deadline,
    )


def _read_success_response(response: Any, deadline: float) -> bytes:
    status_code = getattr(response, "status_code", None)
    if not isinstance(status_code, int):
        raise AgentEndpointError("agent endpoint returned no HTTP status")
    if 300 <= status_code < 400:
        raise AgentEndpointError("agent endpoint redirects are not allowed")
    if status_code < 200 or status_code >= 300:
        raise AgentEndpointError(f"agent endpoint returned HTTP {status_code}")
    return _read_bounded_response(response, deadline=deadline)


def _request_exception(exc: Exception, deadline: float) -> AgentEndpointError:
    if time.monotonic() >= deadline:
        return AgentEndpointError("agent endpoint exceeded request deadline")
    return AgentEndpointError(f"agent endpoint request failed: {type(exc).__name__}")


def _response_exception(exc: Exception, deadline: float) -> AgentEndpointError:
    if time.monotonic() >= deadline:
        return AgentEndpointError("agent endpoint exceeded request deadline")
    return AgentEndpointError(f"agent endpoint response failed: {type(exc).__name__}")


def _close_request_resources(response: Any, client: Any, owns_session: bool) -> None:
    if response is not None:
        try:
            response.close()
        except Exception:
            pass
    if owns_session:
        try:
            client.close()
        except Exception:
            pass


def validate_agent_endpoint(
    endpoint: str,
    *,
    allow_remote: bool,
    endpoint_is_override: bool = False,
    authenticated: bool = False,
    allow_contract_endpoint: bool = False,
) -> str:
    endpoint = _validated_endpoint_text(endpoint)
    parsed = _split_agent_endpoint(endpoint)
    _validate_endpoint_components(parsed)
    loopback = _is_loopback_host(parsed.hostname)
    _validate_endpoint_policy(
        parsed.scheme,
        loopback=loopback,
        allow_remote=allow_remote,
        endpoint_is_override=endpoint_is_override,
        authenticated=authenticated,
        allow_contract_endpoint=allow_contract_endpoint,
    )
    return endpoint


def _validated_endpoint_text(endpoint: str) -> str:
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise AgentBehaviorError("agent endpoint must be a non-empty URL")
    if endpoint != endpoint.strip():
        raise AgentBehaviorError(
            "agent endpoint must not contain surrounding whitespace"
        )
    return endpoint


def _split_agent_endpoint(endpoint: str) -> Any:
    try:
        parsed = urlsplit(endpoint)
    except ValueError as exc:
        raise AgentBehaviorError(f"Invalid agent endpoint: {exc}") from exc
    if parsed.scheme not in {"http", "https"}:
        raise AgentBehaviorError("agent endpoint must use http or https")
    if not parsed.hostname:
        raise AgentBehaviorError("agent endpoint must include a hostname")
    return parsed


def _validate_endpoint_components(parsed: Any) -> None:
    if parsed.username is not None or parsed.password is not None:
        raise AgentBehaviorError("agent endpoint must not contain credentials")
    if parsed.fragment:
        raise AgentBehaviorError("agent endpoint must not contain a fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise AgentBehaviorError("agent endpoint contains an invalid port") from exc
    if port is not None and not 1 <= port <= 65_535:
        raise AgentBehaviorError("agent endpoint contains an invalid port")


def _validate_endpoint_policy(
    scheme: str,
    *,
    loopback: bool,
    allow_remote: bool,
    endpoint_is_override: bool,
    authenticated: bool,
    allow_contract_endpoint: bool,
) -> None:
    if not loopback and not endpoint_is_override:
        raise AgentBehaviorError(
            "remote agent endpoints must be supplied with trusted --endpoint, not contract YAML"
        )
    if loopback and not endpoint_is_override and not allow_contract_endpoint:
        raise AgentBehaviorError(
            "contract-provided agent endpoints require --allow-contract-endpoint or a trusted --endpoint override"
        )
    if not loopback and not allow_remote:
        raise AgentBehaviorError(
            "remote agent endpoints require --allow-remote; loopback endpoints are allowed by default"
        )
    if not loopback and scheme != "https":
        raise AgentBehaviorError("remote agent endpoints must use https")
    if authenticated and not endpoint_is_override:
        raise AgentBehaviorError(
            "authenticated agent endpoints require a trusted --endpoint override"
        )


def agent_endpoint_fingerprint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    hostname = parsed.hostname or ""
    host = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    port = parsed.port
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    netloc = host if port in {None, default_port} else f"{host}:{port}"
    canonical = f"{parsed.scheme.lower()}://{netloc}{parsed.path or '/'}"
    if parsed.query:
        canonical = f"{canonical}?{parsed.query}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_openai_chat_request(
    target: AgentTarget,
    scenario: AgentScenario,
    *,
    max_tokens: int = 1024,
) -> dict[str, Any]:
    _validate_request_limits(request_timeout=None, max_tokens=max_tokens)
    messages: list[dict[str, str]] = []
    if scenario.system_prompt:
        messages.append({"role": "system", "content": scenario.system_prompt})
    messages.append({"role": "user", "content": scenario.prompt})
    payload: dict[str, Any] = {
        "model": target.model,
        "messages": messages,
        "stream": False,
        "max_tokens": max_tokens,
    }

    tool_map = target.tool_map()
    tool_names = (
        scenario.available_tools
        if scenario.available_tools is not None
        else tuple(tool_map)
    )
    tools = [tool_map[name].openai_dict() for name in tool_names]
    if tools:
        payload["tools"] = tools
    return payload


def _read_bounded_response(response: Any, *, deadline: float) -> bytes:
    _enforce_request_deadline(deadline)
    content_length = getattr(response, "headers", {}).get("Content-Length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_ENDPOINT_RESPONSE_BYTES:
                raise AgentEndpointError("agent endpoint response is too large")
        except ValueError:
            pass

    body = bytearray()
    iterator = iter(response.iter_content(chunk_size=64 * 1024))
    timer = threading.Timer(
        max(0.0, deadline - time.monotonic()),
        _shutdown_response,
        args=(response,),
    )
    timer.daemon = True
    timer.start()
    try:
        while True:
            _enforce_request_deadline(deadline)
            try:
                chunk = next(iterator)
            except StopIteration:
                break
            _enforce_request_deadline(deadline)
            if not chunk:
                continue
            body.extend(chunk)
            if len(body) > MAX_ENDPOINT_RESPONSE_BYTES:
                raise AgentEndpointError("agent endpoint response is too large")
    except Exception as exc:
        if time.monotonic() >= deadline:
            raise AgentEndpointError(
                "agent endpoint exceeded request deadline"
            ) from exc
        raise
    finally:
        timer.cancel()
    _enforce_request_deadline(deadline)
    return bytes(body)


def _auth_token(auth_env: str) -> str:
    if not _ENV_NAME_RE.fullmatch(auth_env):
        raise AgentBehaviorError("--auth-env must be a valid environment variable name")
    token = os.environ.get(auth_env)
    if not token:
        raise AgentBehaviorError(f"environment variable {auth_env} is not set")
    if len(token) > MAX_AUTH_TOKEN_CHARS:
        raise AgentBehaviorError(
            f"environment variable {auth_env} exceeds {MAX_AUTH_TOKEN_CHARS} characters"
        )
    if "\r" in token or "\n" in token:
        raise AgentBehaviorError(
            f"environment variable {auth_env} contains invalid header characters"
        )
    return token


def _validate_request_limits(
    *,
    request_timeout: float | None,
    max_tokens: int,
) -> None:
    if request_timeout is not None:
        if isinstance(request_timeout, bool) or not isinstance(
            request_timeout, int | float
        ):
            raise AgentBehaviorError("request timeout must be a number")
        if not math.isfinite(request_timeout):
            raise AgentBehaviorError("request timeout must be finite")
        if request_timeout <= 0 or request_timeout > 300:
            raise AgentBehaviorError("request timeout must be between 0 and 300")
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
        raise AgentBehaviorError("max_tokens must be an integer")
    if max_tokens <= 0 or max_tokens > MAX_ENDPOINT_RESPONSE_TOKENS:
        raise AgentBehaviorError(
            f"max_tokens must be between 1 and {MAX_ENDPOINT_RESPONSE_TOKENS}"
        )


def _validate_endpoint_override(endpoint_override: str | None) -> str | None:
    if endpoint_override is None:
        return None
    if not isinstance(endpoint_override, str) or not endpoint_override.strip():
        raise AgentBehaviorError("--endpoint must be a non-empty URL")
    if endpoint_override != endpoint_override.strip():
        raise AgentBehaviorError(
            "--endpoint must be a non-empty URL without surrounding whitespace"
        )
    return endpoint_override


def _enforce_request_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise AgentEndpointError("agent endpoint exceeded request deadline")


def _shutdown_response(response: Any) -> None:
    raw_response = getattr(response, "raw", None)
    if raw_response is None:
        return
    shutdown = getattr(raw_response, "shutdown", None)
    if callable(shutdown):
        try:
            shutdown()
        except (OSError, RuntimeError, ValueError):
            pass
    close = getattr(raw_response, "close", None)
    if callable(close):
        try:
            close()
        except (OSError, RuntimeError, ValueError):
            pass


def _is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
