from __future__ import annotations

import contextlib
import http.client
import json
import threading

from skylos.agent_center import rebuild_agent_state_from_existing, save_agent_state
from skylos.agent_service import AgentServiceController, create_agent_service


@contextlib.contextmanager
def running_agent_service(
    project_root, *, token: str | None = None, default_limit: int = 10
):
    server = create_agent_service(
        str(project_root),
        host="127.0.0.1",
        port=0,
        token=token,
        default_limit=default_limit,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request_json(
    server,
    method: str,
    path: str,
    *,
    token: str | None = None,
    body: dict | None = None,
    raw_body: str | None = None,
):
    host, port = server.server_address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Skylos-Agent-Token"] = token
    payload = (
        raw_body
        if raw_body is not None
        else (None if body is None else json.dumps(body))
    )
    try:
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        return response.status, json.loads(raw)
    finally:
        conn.close()


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
