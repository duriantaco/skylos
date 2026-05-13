from __future__ import annotations

import contextlib
import http.client
import json
import threading

from skylos.agents.center import rebuild_agent_state_from_existing, save_agent_state
from skylos.agents.service import (
    AgentServiceController,
    _default_allowed_origins,
    create_agent_service,
)


@contextlib.contextmanager
def running_agent_service(
    project_root,
    *,
    token: str | None = None,
    default_limit: int = 10,
    allowed_origins: list[str] | None = None,
):
    server = create_agent_service(
        str(project_root),
        host="127.0.0.1",
        port=0,
        token=token,
        default_limit=default_limit,
        allowed_origins=allowed_origins,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request_http(
    server,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: dict | None = None,
    raw_body: str | None = None,
    origin: str | None = None,
    headers: dict[str, str] | None = None,
):
    host, port = server.server_address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    request_headers = {"Content-Type": "application/json"}
    if origin is not None:
        request_headers["Origin"] = origin
    if token is not None:
        request_headers["X-Skylos-Agent-Token"] = token
    if headers:
        request_headers.update(headers)
    payload = (
        raw_body
        if raw_body is not None
        else (None if body is None else json.dumps(body))
    )
    try:
        conn.request(method, path, body=payload, headers=request_headers)
        response = conn.getresponse()
        response_headers = {k.lower(): v for k, v in response.getheaders()}
        raw = response.read().decode("utf-8")
        return response.status, response_headers, raw
    finally:
        conn.close()


def request_json(
    server,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: dict | None = None,
    raw_body: str | None = None,
    origin: str | None = None,
    headers: dict[str, str] | None = None,
):
    status, _headers, raw = request_http(
        server,
        method,
        path,
        token=token,
        body=body,
        raw_body=raw_body,
        origin=origin,
        headers=headers,
    )
    return status, json.loads(raw)


def service_origin(server, host: str = "127.0.0.1") -> str:
    return f"http://{host}:{server.server_address[1]}"


def build_service_state(project_root, findings):
    state = rebuild_agent_state_from_existing(
        {
            "project_root": str(project_root),
            "file_signatures": {"src/auth.py": {"mtime_ns": 1, "size": 10}},
            "changed_files": ["src/auth.py"],
            "baseline_present": False,
            "findings": findings,
        }
    )
    save_agent_state(project_root, state)
    return state


def test_agent_service_controller_serves_command_center_and_triage_updates(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    state = rebuild_agent_state_from_existing(
        {
            "project_root": str(project_root),
            "file_signatures": {"src/auth.py": {"mtime_ns": 1, "size": 10}},
            "changed_files": ["src/auth.py"],
            "baseline_present": False,
            "findings": [
                {
                    "fingerprint": "security:1",
                    "rule_id": "SKY-D999",
                    "category": "security",
                    "severity": "HIGH",
                    "message": "Shell injection path",
                    "file": "src/auth.py",
                    "absolute_file": str(project_root / "src" / "auth.py"),
                    "line": 9,
                    "confidence": 91,
                    "is_new_vs_baseline": True,
                    "is_new_since_last_scan": True,
                    "is_in_changed_file": True,
                },
            ],
        }
    )
    save_agent_state(project_root, state)

    controller = AgentServiceController(str(project_root))

    health = controller.health()
    assert health["ok"] is True
    assert health["has_state"] is True

    payload = controller.get_command_center()
    assert payload["items"][0]["id"] == "security:1"
    assert payload["triaged_count"] == 0

    dismissed = controller.dismiss("security:1")
    assert dismissed["triage"]["security:1"]["status"] == "dismissed"
    assert dismissed["actions"] == []

    restored = controller.restore("security:1")
    assert restored["triage"] == {}
    assert restored["actions"][0]["id"] == "security:1"


def test_agent_service_controller_tracks_snoozed_actions(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    state = rebuild_agent_state_from_existing(
        {
            "project_root": str(project_root),
            "file_signatures": {"src/helpers.py": {"mtime_ns": 1, "size": 10}},
            "changed_files": [],
            "baseline_present": False,
            "findings": [
                {
                    "fingerprint": "dead:1",
                    "rule_id": "SKY-U002",
                    "category": "dead_code",
                    "severity": "INFO",
                    "message": "Unused import: os",
                    "file": "src/helpers.py",
                    "absolute_file": str(project_root / "src" / "helpers.py"),
                    "line": 2,
                    "confidence": 40,
                    "is_new_vs_baseline": False,
                    "is_new_since_last_scan": False,
                    "is_in_changed_file": False,
                },
            ],
        }
    )
    save_agent_state(project_root, state)

    controller = AgentServiceController(str(project_root))
    snoozed = controller.snooze("dead:1", hours=4)

    assert snoozed["triage"]["dead:1"]["status"] == "snoozed"
    assert snoozed["actions"] == []

    payload = controller.get_command_center()
    assert payload["triaged_count"] == 1
    assert payload["items"] == []


def test_create_agent_service_http_routes_and_auth(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    build_service_state(
        project_root,
        [
            {
                "fingerprint": "security:1",
                "rule_id": "SKY-D999",
                "category": "security",
                "severity": "HIGH",
                "message": "Shell injection path",
                "file": "src/auth.py",
                "absolute_file": str(project_root / "src" / "auth.py"),
                "line": 9,
                "confidence": 91,
                "is_new_vs_baseline": True,
                "is_new_since_last_scan": True,
                "is_in_changed_file": True,
            },
        ],
    )

    with running_agent_service(project_root, token="secret", default_limit=2) as server:
        status, payload = request_json(server, "GET", "/health", token="wrong")
        assert status == 401
        assert payload == {"error": "Unauthorized"}

        status, payload = request_json(server, "GET", "/health", token="secret")
        assert status == 200
        assert payload["ok"] is True
        assert payload["has_state"] is True

        status, payload = request_json(
            server,
            "GET",
            "/command-center?limit=1",
            token="secret",
        )
        assert status == 200
        assert payload["triaged_count"] == 0
        assert len(payload["items"]) == 1
        assert payload["items"][0]["id"] == "security:1"

        status, payload = request_json(server, "GET", "/nope", token="secret")
        assert status == 404
        assert payload == {"error": "Not found"}


def test_create_agent_service_post_parsing_happens_before_route_dispatch(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    build_service_state(
        project_root,
        [
            {
                "fingerprint": "security:1",
                "rule_id": "SKY-D999",
                "category": "security",
                "severity": "HIGH",
                "message": "Shell injection path",
                "file": "src/auth.py",
                "absolute_file": str(project_root / "src" / "auth.py"),
                "line": 9,
                "confidence": 91,
                "is_new_vs_baseline": True,
                "is_new_since_last_scan": True,
                "is_in_changed_file": True,
            },
        ],
    )

    with running_agent_service(project_root, token="secret") as server:
        status, payload = request_json(
            server,
            "POST",
            "/refresh",
            token="secret",
            raw_body='{"bad"',
        )
        assert status == 400
        assert payload == {"error": "Invalid JSON body"}

        status, payload = request_json(
            server,
            "POST",
            "/nope",
            token="secret",
            raw_body='{"bad"',
        )
        assert status == 400
        assert payload == {"error": "Invalid JSON body"}

        status, payload = request_json(
            server,
            "POST",
            "/nope",
            token="secret",
            body={},
        )
        assert status == 404
        assert payload == {"error": "Not found"}


def test_create_agent_service_auth_short_circuits_before_body_parsing(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    build_service_state(
        project_root,
        [
            {
                "fingerprint": "security:1",
                "rule_id": "SKY-D999",
                "category": "security",
                "severity": "HIGH",
                "message": "Shell injection path",
                "file": "src/auth.py",
                "absolute_file": str(project_root / "src" / "auth.py"),
                "line": 9,
                "confidence": 91,
                "is_new_vs_baseline": True,
                "is_new_since_last_scan": True,
                "is_in_changed_file": True,
            },
        ],
    )

    with running_agent_service(project_root, token="secret") as server:
        status, payload = request_json(
            server,
            "POST",
            "/triage/dismiss",
            token="wrong",
            raw_body='{"bad"',
        )
        assert status == 401
        assert payload == {"error": "Unauthorized"}


def test_create_agent_service_validates_action_id_and_hours(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    build_service_state(
        project_root,
        [
            {
                "fingerprint": "security:1",
                "rule_id": "SKY-D999",
                "category": "security",
                "severity": "HIGH",
                "message": "Shell injection path",
                "file": "src/auth.py",
                "absolute_file": str(project_root / "src" / "auth.py"),
                "line": 9,
                "confidence": 91,
                "is_new_vs_baseline": True,
                "is_new_since_last_scan": True,
                "is_in_changed_file": True,
            },
        ],
    )

    with running_agent_service(project_root, token="secret") as server:
        status, payload = request_json(
            server,
            "POST",
            "/triage/dismiss",
            token="secret",
            body={},
        )
        assert status == 400
        assert payload == {"error": "action_id is required"}

        status, payload = request_json(
            server,
            "POST",
            "/triage/snooze",
            token="secret",
            body={"action_id": "security:1", "hours": "nope"},
        )
        assert status == 400
        assert "could not convert string to float" in payload["error"]


def test_create_agent_service_limit_fallback_and_clamp(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    findings = [
        {
            "fingerprint": f"security:{idx}",
            "rule_id": "SKY-D999",
            "category": "security",
            "severity": "HIGH",
            "message": f"Shell injection path {idx}",
            "file": "src/auth.py",
            "absolute_file": str(project_root / "src" / "auth.py"),
            "line": idx,
            "confidence": 91,
            "is_new_vs_baseline": True,
            "is_new_since_last_scan": True,
            "is_in_changed_file": True,
        }
        for idx in range(1, 121)
    ]
    build_service_state(project_root, findings)

    with running_agent_service(project_root, default_limit=2) as server:
        status, payload = request_json(
            server,
            "GET",
            "/command-center?limit=abc",
        )
        assert status == 200
        assert len(payload["items"]) == 2

        status, payload = request_json(
            server,
            "GET",
            "/command-center?limit=999",
        )
        assert status == 200
        assert len(payload["items"]) == 10


def test_agent_service_cors_rejects_disallowed_origin_before_mutation(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    build_service_state(
        project_root,
        [
            {
                "fingerprint": "security:1",
                "rule_id": "SKY-D999",
                "category": "security",
                "severity": "HIGH",
                "message": "Shell injection path",
                "file": "src/auth.py",
                "absolute_file": str(project_root / "src" / "auth.py"),
                "line": 9,
                "confidence": 91,
                "is_new_vs_baseline": True,
                "is_new_since_last_scan": True,
                "is_in_changed_file": True,
            },
        ],
    )

    with running_agent_service(project_root) as server:
        status, headers, raw = request_http(
            server,
            "POST",
            "/triage/dismiss",
            origin="https://evil.example.com",
            body={"action_id": "security:1"},
        )
        assert status == 403
        assert json.loads(raw) == {"error": "Origin is not allowed"}
        assert "access-control-allow-origin" not in headers
        assert headers["vary"] == "Origin"

        status, headers, raw = request_http(
            server,
            "POST",
            "/triage/dismiss",
            origin="null",
            body={"action_id": "security:1"},
        )
        assert status == 403
        assert json.loads(raw) == {"error": "Origin is not allowed"}
        assert "access-control-allow-origin" not in headers
        assert headers["vary"] == "Origin"

        status, payload = request_json(server, "GET", "/state")
        assert status == 200
        assert payload.get("triage", {}) == {}


def test_agent_service_cors_allows_default_local_origin_to_mutate(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    build_service_state(
        project_root,
        [
            {
                "fingerprint": "security:1",
                "rule_id": "SKY-D999",
                "category": "security",
                "severity": "HIGH",
                "message": "Shell injection path",
                "file": "src/auth.py",
                "absolute_file": str(project_root / "src" / "auth.py"),
                "line": 9,
                "confidence": 91,
                "is_new_vs_baseline": True,
                "is_new_since_last_scan": True,
                "is_in_changed_file": True,
            },
        ],
    )

    with running_agent_service(project_root) as server:
        origin = service_origin(server)
        status, headers, raw = request_http(
            server,
            "POST",
            "/triage/dismiss",
            origin=origin,
            body={"action_id": "security:1"},
        )
        payload = json.loads(raw)

        assert status == 200
        assert headers["access-control-allow-origin"] == origin
        assert headers["vary"] == "Origin"
        assert payload["triage"]["security:1"]["status"] == "dismissed"


def test_agent_service_cors_preflight_origin_policy(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    build_service_state(project_root, [])

    with running_agent_service(project_root) as server:
        status, headers, _raw = request_http(
            server,
            "OPTIONS",
            "/triage/dismiss",
            origin="https://evil.example.com",
            headers={"Access-Control-Request-Method": "POST"},
        )
        assert status == 403
        assert "access-control-allow-origin" not in headers

        origin = service_origin(server)
        status, headers, raw = request_http(
            server,
            "OPTIONS",
            "/triage/dismiss",
            origin=origin,
            headers={"Access-Control-Request-Method": "POST"},
        )
        assert status == 204
        assert raw == ""
        assert headers["access-control-allow-origin"] == origin
        assert "X-Skylos-Agent-Token" in headers["access-control-allow-headers"]
        assert "POST" in headers["access-control-allow-methods"]


def test_agent_service_cors_custom_allowed_origins_override_defaults(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    build_service_state(project_root, [])

    with running_agent_service(
        project_root,
        allowed_origins=["https://dashboard.example.com/"],
    ) as server:
        status, headers, raw = request_http(
            server,
            "GET",
            "/health",
            origin="https://dashboard.example.com",
        )
        assert status == 200
        assert json.loads(raw)["ok"] is True
        assert (
            headers["access-control-allow-origin"]
            == "https://dashboard.example.com"
        )

        status, headers, _raw = request_http(
            server,
            "GET",
            "/health",
            origin=service_origin(server),
        )
        assert status == 403
        assert "access-control-allow-origin" not in headers


def test_agent_service_no_origin_header_still_works_without_cors_grant(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    build_service_state(project_root, [])

    with running_agent_service(project_root) as server:
        status, headers, raw = request_http(server, "GET", "/health")
        assert status == 200
        assert json.loads(raw)["ok"] is True
        assert "access-control-allow-origin" not in headers


def test_default_allowed_origins_include_ipv6_loopback():
    wildcard_origins = _default_allowed_origins("0.0.0.0", 5089)
    ipv6_origins = _default_allowed_origins("::1", 5089)

    assert "http://127.0.0.1:5089" in wildcard_origins
    assert "http://localhost:5089" in wildcard_origins
    assert "http://[::1]:5089" in wildcard_origins
    assert "http://[::1]:5089" in ipv6_origins
