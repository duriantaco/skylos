import unittest
import json
import sys
import os
from unittest.mock import patch, MagicMock

mock_constants = MagicMock()
mock_constants.DEFAULT_EXCLUDE_FOLDERS = [".git", "__pycache__"]
sys.modules["skylos.constants"] = mock_constants

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from skylos.server import app, start_server


class TestSkylosWebApp(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_serve_frontend(self):
        response = self.app.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<!DOCTYPE html>", response.data)
        self.assertIn(b"Skylos Dead Code Analyzer", response.data)
        self.assertIn(b'id="analyzeBtn"', response.data)

    def test_analyze_missing_path(self):
        response = self.app.post(
            "/api/analyze",
            data=json.dumps({"confidence": 50}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Path is required", response.data)

    @patch("os.path.exists")
    def test_analyze_invalid_path(self, mock_exists):
        mock_exists.return_value = False

        payload = {"path": "/non/existent/path"}
        response = self.app.post(
            "/api/analyze", data=json.dumps(payload), content_type="application/json"
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
            "/api/analyze", data=json.dumps(payload), content_type="application/json"
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
            "/api/analyze", data=json.dumps(payload), content_type="application/json"
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
                debug=False, host="0.0.0.0", port=5090, use_reloader=False
            )
            mock_timer.assert_called()


if __name__ == "__main__":
    unittest.main()
