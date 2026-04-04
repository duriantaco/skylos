import json
import sys
import os
import unittest
from pathlib import Path

import pytest

pytest.importorskip("flask", reason="Flask not installed — skip server tests")
pytest.importorskip("flask_cors", reason="flask-cors not installed — skip server tests")

from unittest.mock import patch, MagicMock

_original_constants = sys.modules.get("skylos.constants")
mock_constants = MagicMock()
mock_constants.DEFAULT_EXCLUDE_FOLDERS = [".git", "__pycache__"]
sys.modules["skylos.constants"] = mock_constants

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from skylos.server import app, start_server, _get_server_port, _get_default_cors_origins

if _original_constants is not None:
    sys.modules["skylos.constants"] = _original_constants
else:
    del sys.modules["skylos.constants"]


class TestSkylosWebApp(unittest.TestCase):
    def setUp(self):
        self.token = "test-token-for-tests"
        app.config["WEB_API_TOKEN"] = self.token
        app.config["ALLOWED_SCAN_ROOTS"] = [Path("/")]
        self.app = app.test_client()
        self.app.testing = True
        self.auth_headers = {
            "Content-Type": "application/json",
            "X-Skylos-Web-Token": self.token,
        }

    def test_serve_frontend(self):
        response = self.app.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<!DOCTYPE html>", response.data)
        self.assertIn(b"Skylos Dead Code Analyzer", response.data)
        self.assertIn(b'id="analyzeBtn"', response.data)
        self.assertIn(b"wrapper.textContent = message", response.data)
        self.assertIn(b"name.textContent = item.name", response.data)

    def test_serve_frontend_embeds_token_as_json_literal(self):
        app.config["WEB_API_TOKEN"] = 'tok-"</script>-x'

        response = self.app.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'const SKYLOS_WEB_TOKEN = "tok-\\"<\\/script>-x";', response.data
        )
        self.assertNotIn(b"</script>-x", response.data)

    def test_analyze_missing_path(self):
        response = self.app.post(
            "/api/analyze",
            data=json.dumps({"confidence": 50}),
            headers=self.auth_headers,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Path is required", response.data)

    @patch("os.path.exists")
    def test_analyze_invalid_path(self, mock_exists):
        mock_exists.return_value = False

        payload = {"path": "/non/existent/path"}
        response = self.app.post(
            "/api/analyze",
            data=json.dumps(payload),
            headers=self.auth_headers,
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Path does not exist", response.data)

    @patch("skylos.analyze")
    @patch("os.path.exists")
    def test_analyze_success(self, mock_exists, mock_skylos_analyze):
        mock_exists.return_value = True

        mock_result = {
            "unused_functions": [{"name": "dead_func", "line": 10}],
            "unused_imports": [],
        }
        mock_skylos_analyze.return_value = json.dumps(mock_result)

        payload = {"path": "/real/path", "confidence": 80}
        response = self.app.post(
            "/api/analyze",
            data=json.dumps(payload),
            headers=self.auth_headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, mock_result)

        args, kwargs = mock_skylos_analyze.call_args
        self.assertEqual(args[0], "/real/path")
        self.assertEqual(kwargs["conf"], 80)

    @patch("skylos.analyze")
    @patch("os.path.exists")
    def test_analyze_internal_error(self, mock_exists, mock_skylos_analyze):
        mock_exists.return_value = True
        mock_skylos_analyze.side_effect = Exception("Parsing error")

        payload = {"path": "/real/path"}
        response = self.app.post(
            "/api/analyze",
            data=json.dumps(payload),
            headers=self.auth_headers,
        )

        self.assertEqual(response.status_code, 500)
        self.assertIn(b"Parsing error", response.data)

    @patch("skylos.server.webbrowser.open")
    @patch("skylos.server.Timer")
    @patch("skylos.server.app.run")
    def test_start_server(self, mock_run, mock_timer, mock_browser):
        start_server(exclude_folders=["custom_folder"])

        if mock_run.called:
            mock_run.assert_called_with(
                debug=False, host="127.0.0.1", port=5090, use_reloader=False
            )
            mock_timer.assert_called()

    @patch.dict(os.environ, {"SKYLOS_PORT": "5111"}, clear=False)
    @patch("skylos.server.webbrowser.open")
    @patch("skylos.server.Timer")
    @patch("skylos.server.app.run")
    def test_start_server_uses_env_port(self, mock_run, mock_timer, mock_browser):
        start_server(exclude_folders=["custom_folder"])

        mock_run.assert_called_with(
            debug=False, host="127.0.0.1", port=5111, use_reloader=False
        )
        open_browser = mock_timer.call_args.args[1]
        open_browser()
        mock_browser.assert_called_with("http://localhost:5111")

    @patch.dict(os.environ, {"SKYLOS_PORT": "5111"}, clear=False)
    def test_default_cors_origins_use_env_port(self):
        self.assertEqual(
            _get_default_cors_origins(),
            ["http://localhost:5111", "http://127.0.0.1:5111"],
        )

    @patch.dict(os.environ, {"SKYLOS_PORT": "not-a-port"}, clear=False)
    def test_get_server_port_rejects_invalid_env_value(self):
        with self.assertRaisesRegex(ValueError, "Invalid SKYLOS_PORT"):
            _get_server_port()


if __name__ == "__main__":
    unittest.main()
