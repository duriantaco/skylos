"""PoC test: CORS wildcard in AgentServiceHandler allows any origin.

The agent service sets Access-Control-Allow-Origin: * on all responses,
allowing any website to make cross-origin requests.  This test verifies
that after the fix the server only reflects explicitly allowed origins.
"""
from __future__ import annotations

import contextlib
import http.client
import json
import threading

from skylos.agent_center import rebuild_agent_state_from_existing, save_agent_state
from skylos.agent_service import create_agent_service


@contextlib.contextmanager
def _running_service(project_root, **kwargs):
    server = create_agent_service(str(project_root), host="127.0.0.1", port=0, **kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(server, method, path, *, origin=None, headers=None):
    host, port = server.server_address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    hdrs = {"Content-Type": "application/json"}
    if origin:
        hdrs["Origin"] = origin
    if headers:
        hdrs.update(headers)
    conn.request(method, path, headers=hdrs)
    resp = conn.getresponse()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    body = resp.read().decode("utf-8")
    conn.close()
    return resp.status, resp_headers, body


def _seed_state(project_root):
    state = rebuild_agent_state_from_existing(
        {
            "project_root": str(project_root),
            "file_signatures": {"a.py": {"mtime_ns": 1, "size": 1}},
            "changed_files": [],
            "baseline_present": False,
            "findings": [],
        }
    )
    save_agent_state(project_root, state)


# ---------- Tests ----------


def test_cors_rejects_unknown_origin(tmp_path):
    """A request from an untrusted origin must NOT get Access-Control-Allow-Origin: *."""
    root = tmp_path / "repo"
    root.mkdir()
    _seed_state(root)

    with _running_service(root) as server:
        status, headers, _ = _request(server, "GET", "/health", origin="https://evil.example.com")
        acao = headers.get("access-control-allow-origin", "")
        # Must NOT be wildcard and must NOT echo back the evil origin
        assert acao != "*", "CORS wildcard still present — any origin can access the API"
        assert "evil.example.com" not in acao, "Untrusted origin was reflected"


def test_cors_allows_localhost_origin(tmp_path):
    """Requests from localhost should be allowed by default."""
    root = tmp_path / "repo"
    root.mkdir()
    _seed_state(root)

    with _running_service(root) as server:
        host, port = server.server_address
        local_origin = f"http://{host}:{port}"
        status, headers, _ = _request(server, "GET", "/health", origin=local_origin)
        acao = headers.get("access-control-allow-origin", "")
        assert acao == local_origin, f"Expected localhost origin reflected, got: {acao!r}"


def test_cors_preflight_rejects_unknown_origin(tmp_path):
    """OPTIONS preflight from untrusted origin must not echo wildcard."""
    root = tmp_path / "repo"
    root.mkdir()
    _seed_state(root)

    with _running_service(root) as server:
        status, headers, _ = _request(
            server,
            "OPTIONS",
            "/triage/dismiss",
            origin="https://evil.example.com",
            headers={"Access-Control-Request-Method": "POST"},
        )
        acao = headers.get("access-control-allow-origin", "")
        assert acao != "*", "OPTIONS preflight returns wildcard CORS"
        assert "evil.example.com" not in acao


def test_cors_custom_allowed_origins(tmp_path):
    """When allowed_origins is given, only those origins are accepted."""
    root = tmp_path / "repo"
    root.mkdir()
    _seed_state(root)

    with _running_service(root, allowed_origins=["https://my-dashboard.example.com"]) as server:
        # allowed origin
        status, headers, _ = _request(
            server, "GET", "/health", origin="https://my-dashboard.example.com"
        )
        acao = headers.get("access-control-allow-origin", "")
        assert acao == "https://my-dashboard.example.com"

        # disallowed origin
        status, headers, _ = _request(
            server, "GET", "/health", origin="https://evil.example.com"
        )
        acao = headers.get("access-control-allow-origin", "")
        assert acao != "*"
        assert "evil.example.com" not in acao


def test_cors_no_origin_header_still_works(tmp_path):
    """Same-origin / non-browser clients with no Origin header still get a response."""
    root = tmp_path / "repo"
    root.mkdir()
    _seed_state(root)

    with _running_service(root) as server:
        status, headers, body = _request(server, "GET", "/health")
        assert status == 200
        payload = json.loads(body)
        assert payload["ok"] is True
