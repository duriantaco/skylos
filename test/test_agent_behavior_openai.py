from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from dataclasses import replace

import pytest

from skylos.agents.evaluation.openai_chat import (
    MAX_ENDPOINT_RESPONSE_BYTES,
    AgentEndpointError,
    build_openai_chat_request,
    normalize_openai_chat_response,
    observe_openai_chat,
    validate_agent_endpoint,
)
from skylos.agents.evaluation.schema import (
    AgentBehaviorError,
    AgentScenario,
    AgentTarget,
    AgentToolDefinition,
    ResponseExpectation,
    ScenarioExpectation,
)


class FakeResponse:
    def __init__(
        self,
        payload=None,
        *,
        status_code=200,
        body: bytes | None = None,
        headers=None,
    ):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.body = body if body is not None else json.dumps(payload).encode("utf-8")
        self.closed = False

    def iter_content(self, chunk_size):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start : start + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []
        self.closed = False

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response

    def close(self):
        self.closed = True


@contextmanager
def _slow_http_endpoint(phase):
    class SlowResponseHandler(socketserver.BaseRequestHandler):
        def handle(self):
            request = bytearray()
            while b"\r\n\r\n" not in request and len(request) <= 256 * 1024:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                request.extend(chunk)

            body = json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": "done", "tool_calls": []},
                        }
                    ]
                }
            ).encode("utf-8")
            headers = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"X-Padding: "
                + b"a" * 128
                + b"\r\nConnection: close\r\n\r\n"
            )
            try:
                if phase == "headers":
                    chunks = (bytes([value]) for value in headers)
                else:
                    self.request.sendall(headers)
                    chunks = (bytes([value]) for value in body)
                for chunk in chunks:
                    self.request.sendall(chunk)
                    time.sleep(0.01)
            except OSError:
                return

    class SlowResponseServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = SlowResponseServer(("127.0.0.1", 0), SlowResponseHandler)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


@contextmanager
def _recording_http_endpoint():
    request_received = threading.Event()

    class RecordingHandler(socketserver.BaseRequestHandler):
        def handle(self):
            request = bytearray()
            while b"\r\n\r\n" not in request and len(request) <= 256 * 1024:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                request.extend(chunk)
            request_received.set()
            body = json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": "done", "tool_calls": []},
                        }
                    ]
                }
            ).encode("utf-8")
            response = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + body
            )
            try:
                self.request.sendall(response)
            except OSError:
                return

    class RecordingServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = RecordingServer(("127.0.0.1", 0), RecordingHandler)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        yield (
            f"http://localhost:{server.server_address[1]}/v1/chat/completions",
            request_received,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def _target() -> AgentTarget:
    return AgentTarget(
        endpoint="http://127.0.0.1:8000/v1/chat/completions",
        model="agent-under-test",
        timeout_seconds=12,
        tools=(
            AgentToolDefinition(
                name="lookup_policy",
                description="Look up a policy",
                parameters={"type": "object"},
            ),
            AgentToolDefinition(
                name="delete_database",
                description="Delete a database",
                parameters={"type": "object"},
            ),
        ),
    )


def _scenario() -> AgentScenario:
    return AgentScenario(
        scenario_id="refund",
        prompt="What is the refund window?",
        system_prompt="Use policy evidence.",
        available_tools=("lookup_policy",),
        expectation=ScenarioExpectation(
            response=ResponseExpectation(contains=("30 days",))
        ),
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://127.0.0.1:8000/v1/chat/completions",
        "http://[::1]:8000/v1/chat/completions",
        "http://localhost:8000/v1/chat/completions",
    ],
)
def test_loopback_contract_endpoints_require_explicit_consent(endpoint):
    with pytest.raises(AgentBehaviorError, match="--allow-contract-endpoint"):
        validate_agent_endpoint(endpoint, allow_remote=False)
    assert (
        validate_agent_endpoint(
            endpoint,
            allow_remote=False,
            allow_contract_endpoint=True,
        )
        == endpoint
    )


def test_remote_endpoint_requires_explicit_opt_in():
    endpoint = "https://agent.example.com/v1/chat/completions"
    with pytest.raises(AgentBehaviorError, match="trusted --endpoint"):
        validate_agent_endpoint(
            endpoint,
            allow_remote=False,
        )

    with pytest.raises(AgentBehaviorError, match="--allow-remote"):
        validate_agent_endpoint(
            endpoint,
            allow_remote=False,
            endpoint_is_override=True,
        )
    assert (
        validate_agent_endpoint(
            endpoint,
            allow_remote=True,
            endpoint_is_override=True,
        )
        == endpoint
    )


def test_remote_endpoint_override_requires_https():
    with pytest.raises(AgentBehaviorError, match="must use https"):
        validate_agent_endpoint(
            "http://agent.example.com/v1/chat/completions",
            allow_remote=True,
            endpoint_is_override=True,
        )


@pytest.mark.parametrize(
    "endpoint, message",
    [
        ("file:///tmp/agent", "http or https"),
        ("http://user:password@127.0.0.1:8000/v1", "credentials"),
        ("http://127.0.0.1:8000/v1#fragment", "fragment"),
    ],
)
def test_endpoint_rejects_unsafe_url_shapes(endpoint, message):
    with pytest.raises(AgentBehaviorError, match=message):
        validate_agent_endpoint(endpoint, allow_remote=True)


def test_request_uses_only_scenario_available_tools():
    payload = build_openai_chat_request(_target(), _scenario())

    assert payload == {
        "model": "agent-under-test",
        "messages": [
            {"role": "system", "content": "Use policy evidence."},
            {"role": "user", "content": "What is the refund window?"},
        ],
        "stream": False,
        "max_tokens": 1024,
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "lookup_policy",
                    "description": "Look up a policy",
                    "parameters": {"type": "object"},
                },
            }
        ],
    }


def test_request_applies_explicit_response_token_budget():
    payload = build_openai_chat_request(_target(), _scenario(), max_tokens=77)

    assert payload["max_tokens"] == 77


@pytest.mark.parametrize("max_tokens", [0, 32769, True])
def test_request_rejects_invalid_response_token_budget(max_tokens):
    with pytest.raises(AgentBehaviorError, match="max_tokens"):
        build_openai_chat_request(_target(), _scenario(), max_tokens=max_tokens)


def test_live_observer_rejects_non_finite_request_timeout():
    with pytest.raises(AgentBehaviorError, match="request timeout must be finite"):
        observe_openai_chat(
            _target(),
            _scenario(),
            allow_contract_endpoint=True,
            request_timeout=float("nan"),
            session=FakeSession(FakeResponse({})),
        )


def test_normalizes_text_tools_refusal_and_sources():
    observation = normalize_openai_chat_response(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": [{"type": "text", "text": "30 days"}],
                        "tool_calls": [
                            {
                                "type": "function",
                                "function": {
                                    "name": "lookup_policy",
                                    "arguments": '{"id": "refund-v3"}',
                                },
                            }
                        ],
                        "refusal": None,
                        "sources": [
                            "refund-v3",
                            {"id": "faq-v2"},
                            {"source": "legal-v1"},
                        ],
                    },
                }
            ]
        },
        scenario_id="refund",
    )

    assert observation.response == "30 days"
    assert observation.response_complete is True
    assert observation.tool_calls_complete is True
    assert observation.finish_reason == "stop"
    assert observation.tool_calls is not None
    assert observation.tool_calls[0].name == "lookup_policy"
    assert observation.tool_calls[0].arguments == {"id": "refund-v3"}
    assert observation.refusal is False
    assert observation.sources == ("refund-v3", "faq-v2", "legal-v1")


def test_unknown_content_part_marks_final_response_incomplete():
    observation = normalize_openai_chat_response(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": [
                            {"type": "text", "text": "visible"},
                            {"type": "future_content", "value": "hidden"},
                        ],
                        "tool_calls": [],
                    },
                }
            ]
        },
        scenario_id="unknown-content",
    )

    assert observation.response == "visible"
    assert observation.response_complete is False
    assert observation.tool_calls_complete is True


def test_absent_tool_calls_are_incomplete_evidence():
    observation = normalize_openai_chat_response(
        {"choices": [{"message": {"content": "No tools needed."}}]},
        scenario_id="chat",
    )

    assert observation.tool_calls is None
    assert observation.refusal is None
    assert observation.sources is None
    assert observation.response_complete is None
    assert observation.tool_calls_complete is None


def test_omitted_tool_calls_remain_incomplete_with_stop_finish_reason():
    observation = normalize_openai_chat_response(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": "No tools needed."},
                }
            ]
        },
        scenario_id="chat",
    )

    assert observation.tool_calls is None
    assert observation.tool_calls_complete is False


@pytest.mark.parametrize(
    "finish_reason, expected_complete",
    [("stop", True), ("length", False), ("tool_calls", False)],
)
def test_normalizes_finish_reason(finish_reason, expected_complete):
    observation = normalize_openai_chat_response(
        {
            "choices": [
                {
                    "finish_reason": finish_reason,
                    "message": {"content": "result", "tool_calls": []},
                }
            ]
        },
        scenario_id="chat",
    )

    assert observation.finish_reason == finish_reason
    assert observation.response_complete is expected_complete
    assert observation.tool_calls_complete is (finish_reason in {"stop", "tool_calls"})


def test_explicit_null_tool_calls_mean_no_returned_calls():
    observation = normalize_openai_chat_response(
        {"choices": [{"message": {"content": "No tools.", "tool_calls": None}}]},
        scenario_id="chat",
    )

    assert observation.tool_calls == ()


def test_malformed_tool_arguments_remain_incomplete_evidence():
    observation = normalize_openai_chat_response(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "lookup_policy",
                                    "arguments": "not-json",
                                }
                            }
                        ]
                    },
                }
            ]
        },
        scenario_id="refund",
    )

    assert observation.tool_calls is not None
    assert observation.tool_calls[0].arguments is None


def test_invalid_returned_tool_name_is_incomplete_evidence():
    observation = normalize_openai_chat_response(
        {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "../../unsafe",
                                    "arguments": "{}",
                                }
                            }
                        ]
                    },
                }
            ]
        },
        scenario_id="refund",
    )

    assert observation.tool_calls is None


def test_excessive_returned_tool_calls_are_incomplete_evidence():
    observation = normalize_openai_chat_response(
        {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "lookup_policy",
                                    "arguments": "{}",
                                }
                            }
                            for _ in range(251)
                        ]
                    },
                }
            ]
        },
        scenario_id="refund",
    )

    assert observation.tool_calls is None
    assert observation.tool_calls_complete is False


def test_live_observer_sends_cli_selected_auth_without_persisting_it(monkeypatch):
    response = FakeResponse(
        {
            "choices": [
                {
                    "message": {
                        "content": "30 days",
                        "tool_calls": [],
                        "refusal": False,
                        "sources": ["refund-v3"],
                    }
                }
            ]
        }
    )
    session = FakeSession(response)
    monkeypatch.setenv("TEST_AGENT_TOKEN", "super-secret-token")

    observation = observe_openai_chat(
        _target(),
        _scenario(),
        endpoint_override=_target().endpoint,
        auth_env="TEST_AGENT_TOKEN",
        session=session,
    )

    assert observation.response == "30 days"
    assert "super-secret-token" not in json.dumps(observation.to_dict())
    assert len(session.calls) == 1
    url, kwargs = session.calls[0]
    assert url == _target().endpoint
    assert kwargs["headers"]["Authorization"] == "Bearer super-secret-token"
    assert kwargs["allow_redirects"] is False
    assert kwargs["stream"] is True
    assert kwargs["timeout"] == 12
    assert response.closed
    assert not session.closed


def test_live_observer_rejects_missing_auth_environment():
    with pytest.raises(AgentBehaviorError, match="is not set"):
        observe_openai_chat(
            _target(),
            _scenario(),
            endpoint_override=_target().endpoint,
            auth_env="DEFINITELY_MISSING_AGENT_TOKEN",
            session=FakeSession(FakeResponse({})),
        )


def test_live_observer_rejects_auth_without_trusted_endpoint_override(monkeypatch):
    monkeypatch.setenv("TEST_AGENT_TOKEN", "secret")

    with pytest.raises(AgentBehaviorError, match="trusted --endpoint"):
        observe_openai_chat(
            _target(),
            _scenario(),
            auth_env="TEST_AGENT_TOKEN",
            session=FakeSession(FakeResponse({})),
        )


@pytest.mark.parametrize("endpoint_override", ["", "   "])
def test_live_observer_rejects_empty_trusted_endpoint_override(
    monkeypatch,
    endpoint_override,
):
    monkeypatch.setenv("TEST_AGENT_TOKEN", "secret")
    session = FakeSession(FakeResponse({}))

    with pytest.raises(AgentBehaviorError, match="--endpoint must be a non-empty URL"):
        observe_openai_chat(
            _target(),
            _scenario(),
            endpoint_override=endpoint_override,
            auth_env="TEST_AGENT_TOKEN",
            session=session,
        )

    assert session.calls == []


def test_live_observer_rejects_auth_header_control_characters(monkeypatch):
    monkeypatch.setenv("TEST_AGENT_TOKEN", "secret\r\nInjected: value")

    with pytest.raises(AgentBehaviorError, match="invalid header characters"):
        observe_openai_chat(
            _target(),
            _scenario(),
            endpoint_override=_target().endpoint,
            auth_env="TEST_AGENT_TOKEN",
            session=FakeSession(FakeResponse({})),
        )


def test_reflected_auth_token_is_redacted_from_normalized_evidence(monkeypatch):
    secret = "super-secret-token"
    monkeypatch.setenv("TEST_AGENT_TOKEN", secret)
    session = FakeSession(
        FakeResponse(
            {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": f"reflected {secret}",
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "lookup_policy",
                                        "arguments": json.dumps(
                                            {"nested": [secret, {secret: secret}]}
                                        ),
                                    }
                                }
                            ],
                            "sources": [secret],
                        },
                    }
                ]
            }
        )
    )

    observation = observe_openai_chat(
        _target(),
        _scenario(),
        endpoint_override=_target().endpoint,
        auth_env="TEST_AGENT_TOKEN",
        session=session,
    )

    serialized = json.dumps(observation.to_dict())
    assert secret not in serialized
    assert serialized.count("[REDACTED]") >= 4
    assert observation.response_complete is True


def test_reflected_auth_token_is_redacted_from_finish_reason(monkeypatch):
    secret = "secret-finish-reason"
    monkeypatch.setenv("TEST_AGENT_TOKEN", secret)
    session = FakeSession(
        FakeResponse(
            {
                "choices": [
                    {
                        "finish_reason": secret,
                        "message": {"content": "result", "tool_calls": []},
                    }
                ]
            }
        )
    )

    observation = observe_openai_chat(
        _target(),
        _scenario(),
        endpoint_override=_target().endpoint,
        auth_env="TEST_AGENT_TOKEN",
        session=session,
    )

    assert secret not in json.dumps(observation.to_dict())
    assert observation.finish_reason == "[REDACTED]"


def test_short_auth_token_redaction_does_not_amplify_evidence(monkeypatch):
    monkeypatch.setenv("TEST_AGENT_TOKEN", "x")
    observation = observe_openai_chat(
        _target(),
        _scenario(),
        endpoint_override=_target().endpoint,
        auth_env="TEST_AGENT_TOKEN",
        session=FakeSession(
            FakeResponse(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": "x" * 10_000, "tool_calls": []},
                        }
                    ]
                }
            )
        ),
    )

    assert observation.response == "*" * 10_000


def test_live_observer_rejects_redirect_and_oversized_response():
    redirect = FakeSession(FakeResponse({}, status_code=302))
    with pytest.raises(AgentEndpointError, match="redirects"):
        observe_openai_chat(
            _target(),
            _scenario(),
            allow_contract_endpoint=True,
            session=redirect,
        )

    oversized = FakeSession(
        FakeResponse(
            body=b"{}",
            headers={"Content-Length": str(MAX_ENDPOINT_RESPONSE_BYTES + 1)},
        )
    )
    with pytest.raises(AgentEndpointError, match="too large"):
        observe_openai_chat(
            _target(),
            _scenario(),
            allow_contract_endpoint=True,
            session=oversized,
        )


def test_live_observer_rejects_invalid_protocol_shape():
    session = FakeSession(FakeResponse({"choices": []}))

    with pytest.raises(AgentEndpointError, match=r"choices\[0\]"):
        observe_openai_chat(
            _target(),
            _scenario(),
            allow_contract_endpoint=True,
            session=session,
        )


def test_live_observer_rejects_duplicate_response_keys():
    session = FakeSession(
        FakeResponse(
            body=(
                b'{"choices":[{"finish_reason":"stop","finish_reason":"length",'
                b'"message":{"content":"hello"}}]}'
            )
        )
    )

    with pytest.raises(AgentEndpointError, match="duplicate key"):
        observe_openai_chat(
            _target(),
            _scenario(),
            allow_contract_endpoint=True,
            session=session,
        )


def test_live_observer_rejects_excessive_json_nesting_without_crashing():
    session = FakeSession(FakeResponse(body=b"[" * 10_000 + b"0" + b"]" * 10_000))

    with pytest.raises(AgentEndpointError, match="invalid JSON"):
        observe_openai_chat(
            _target(),
            _scenario(),
            allow_contract_endpoint=True,
            session=session,
        )


def test_live_observer_rejects_deep_response_values_before_normalization():
    nested: object = "value"
    for _ in range(100):
        nested = {"nested": nested}
    session = FakeSession(
        FakeResponse(
            {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": "done",
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "lookup_policy",
                                        "arguments": nested,
                                    }
                                }
                            ],
                        },
                    }
                ]
            }
        )
    )

    with pytest.raises(AgentEndpointError, match="nesting exceeds"):
        observe_openai_chat(
            _target(),
            _scenario(),
            allow_contract_endpoint=True,
            session=session,
        )


def test_live_observer_enforces_total_streaming_deadline():
    class SlowDripResponse(FakeResponse):
        def __init__(self, payload):
            super().__init__(payload)
            self.chunks_yielded = 0

        def iter_content(self, chunk_size):
            for _ in range(100):
                time.sleep(0.002)
                self.chunks_yielded += 1
                yield b" "
            yield self.body

    response = SlowDripResponse(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": "done", "tool_calls": []},
                }
            ]
        }
    )

    with pytest.raises(AgentEndpointError, match="request deadline"):
        observe_openai_chat(
            _target(),
            _scenario(),
            allow_contract_endpoint=True,
            request_timeout=0.01,
            session=FakeSession(response),
        )

    assert response.chunks_yielded < 100


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_builtin_transport_enforces_absolute_http_deadline(phase):
    with _slow_http_endpoint(phase) as endpoint:
        started = time.monotonic()
        with pytest.raises(AgentEndpointError, match="request deadline"):
            observe_openai_chat(
                replace(_target(), endpoint=endpoint),
                _scenario(),
                allow_contract_endpoint=True,
                request_timeout=0.05,
            )
        elapsed = time.monotonic() - started

    assert elapsed < 0.5


def test_builtin_transport_cancels_request_after_dns_deadline(monkeypatch):
    real_getaddrinfo = socket.getaddrinfo

    def delayed_getaddrinfo(*args, **kwargs):
        time.sleep(0.3)
        return real_getaddrinfo(*args, **kwargs)

    with _recording_http_endpoint() as (endpoint, request_received):
        monkeypatch.setattr(socket, "getaddrinfo", delayed_getaddrinfo)
        started = time.monotonic()
        with pytest.raises(AgentEndpointError, match="request deadline"):
            observe_openai_chat(
                replace(_target(), endpoint=endpoint),
                _scenario(),
                allow_contract_endpoint=True,
                request_timeout=0.05,
            )
        elapsed = time.monotonic() - started
        time.sleep(0.4)

        assert not request_received.is_set()
        assert not any(
            thread.name == "skylos-agent-http" and thread.is_alive()
            for thread in threading.enumerate()
        )

    assert elapsed < 0.2


def test_builtin_transport_accepts_normal_http_response():
    with _recording_http_endpoint() as (endpoint, request_received):
        observation = observe_openai_chat(
            replace(_target(), endpoint=endpoint),
            _scenario(),
            allow_contract_endpoint=True,
            request_timeout=1,
        )

    assert request_received.is_set()
    assert observation.response == "done"
    assert observation.response_complete is True
