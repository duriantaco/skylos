import http.client
import json
import subprocess
import sys
import threading
import time

import pytest

from skylos.graph import build_graph, check
from skylos.graph.check import CheckRunner
from skylos.graph.server import GraphServer


def _wait(runner, seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        status = runner.status()
        if status["state"] != "running":
            return status
        time.sleep(0.05)
    raise AssertionError("check did not finish")


def _fake_done(monkeypatch, code, seconds=0.0):
    script = f"import time; print('PASS tests'); print('\\x1b[31mFAIL shortcut\\x1b[0m'); time.sleep({seconds}); raise SystemExit({code})"
    monkeypatch.setattr(check, "done_command", lambda base: [sys.executable, "-c", script])


@pytest.mark.parametrize(
    ("code", "state", "message"),
    [(0, "passed", "Passed"), (1, "blocked", "Blocked"), (2, "error", "exit 2")],
)
def test_runner_maps_done_exit_codes_and_keeps_the_output(tmp_path, monkeypatch, code, state, message):
    _fake_done(monkeypatch, code)
    rebuilt = []
    runner = CheckRunner(tmp_path, "origin/main", lambda: rebuilt.append(True))

    assert runner.status()["state"] == "idle"
    assert runner.start() is True
    status = _wait(runner)

    assert status["state"] == state
    assert message in status["message"]
    assert status["exit_code"] == code
    assert status["log"] == ["PASS tests", "FAIL shortcut"]
    assert status["command"] == "skylos done --base origin/main"
    assert rebuilt == [True]


def test_runner_allows_one_run_at_a_time(tmp_path, monkeypatch):
    _fake_done(monkeypatch, 0, seconds=1.0)
    runner = CheckRunner(tmp_path, "HEAD")

    assert runner.start() is True
    assert runner.start() is False
    assert _wait(runner)["state"] == "passed"
    assert runner.start() is True
    _wait(runner)


def _request(port, method, path, headers=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, json.loads(data or b"{}")


def _serve(root, runner):
    server = GraphServer(root, 0, check=runner)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_check_endpoint_needs_token_local_host_and_json(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("def run():\n    return 1\n")
    build_graph(tmp_path)
    _fake_done(monkeypatch, 1, seconds=1.0)
    runner = CheckRunner(tmp_path, "origin/main")
    server = _serve(tmp_path, runner)
    port = server.server_address[1]
    token = {"X-Skylos-Token": server.token}
    json_type = {"Content-Type": "application/json"}
    try:
        assert _request(port, "POST", "/api/check", json_type, "{}")[0] == 403
        assert _request(port, "POST", "/api/check", {**token, **json_type, "Host": f"evil.example:{port}"}, "{}")[0] == 403
        assert _request(port, "POST", "/api/check", {**token, "Content-Type": "text/plain"}, "{}")[0] == 415
        assert runner.status()["state"] == "idle"

        status, body = _request(port, "POST", "/api/check", {**token, **json_type}, "{}")
        assert status == 202
        assert body["state"] == "running" and body["available"] is True
        assert _request(port, "POST", "/api/check", {**token, **json_type}, "{}")[0] == 409
        assert _request(port, "GET", "/api/check")[0] == 403

        _wait(runner)
        status, body = _request(port, "GET", "/api/check", token)
        assert status == 200
        assert body["state"] == "blocked"
        assert body["log"][-1] == "FAIL shortcut"
    finally:
        server.shutdown()
        server.server_close()


def test_viewer_without_a_runner_offers_no_check(tmp_path):
    (tmp_path / "app.py").write_text("def run():\n    return 1\n")
    build_graph(tmp_path)
    server = _serve(tmp_path, None)
    port = server.server_address[1]
    token = {"X-Skylos-Token": server.token}
    try:
        assert _request(port, "GET", "/api/check", token) == (200, {"available": False})
        assert _request(port, "POST", "/api/check", {**token, "Content-Type": "application/json"}, "{}")[0] == 404
    finally:
        server.shutdown()
        server.server_close()


def test_real_done_run_writes_a_receipt(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (root / "test_calc.py").write_text("from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n")
    (root / "pyproject.toml").write_text("[project]\nname = \"calc\"\nversion = \"0\"\n\n[tool.pytest.ini_options]\ntestpaths = [\".\"]\n")
    for args in (["init", "-q", "-b", "main"], ["add", "-A"], ["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "start"]):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (root / "calc.py").write_text("def add(a, b):\n    total = a + b\n    return total\n")
    runner = CheckRunner(root, "HEAD")

    runner.start()
    status = _wait(runner, 180)

    assert status["state"] == "passed", status["log"]
    assert any(line.startswith("Verdict: PASS") for line in status["log"])
    assert json.loads((root / ".skylos" / "receipts" / "latest.json").read_text())["agent"]["client"] == "check-button"
