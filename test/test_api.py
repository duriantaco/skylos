import os
import importlib
import unittest
from unittest.mock import patch, MagicMock, mock_open

import skylos.api as api
from skylos.api import upload_report, extract_snippet


class TestSkylosApi(unittest.TestCase):
    @patch("subprocess.check_output")
    @patch("skylos.api.get_project_token")
    @patch("requests.post")
    def test_upload_report_success(self, mock_post, mock_token, mock_git):
        mock_token.return_value = "test_token_123"
        mock_git.side_effect = [b"mock_commit_hash\n", b"main\n", b"/mock/git/root\n"]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"scanId": "scan_abc_789"}
        mock_post.return_value = mock_response

        dummy_results = {
            "danger": [
                {
                    "file": "app.py",
                    "line": 10,
                    "message": "High risk",
                    "rule_id": "SKY-D001",
                }
            ],
            "quality": [],
        }

        result = upload_report(dummy_results, is_forced=True)

        self.assertTrue(result["success"])
        self.assertEqual(result["scan_id"], "scan_abc_789")

        args, kwargs = mock_post.call_args
        payload = kwargs["json"]
        self.assertEqual(payload["commit_hash"], "mock_commit_hash")
        self.assertTrue(payload["is_forced"])
        self.assertEqual(payload["version"], "2.1.0")

    @patch("skylos.api.get_project_token")
    def test_upload_report_no_token(self, mock_token):
        mock_token.return_value = None
        result = upload_report({})
        self.assertFalse(result["success"])
        self.assertEqual(
            result["error"],
            "No token found. Run 'skylos sync connect' or set SKYLOS_TOKEN.",
        )

    @patch("subprocess.check_output")
    @patch("skylos.api.get_project_token")
    @patch("requests.post")
    def test_upload_report_retry_logic(self, mock_post, mock_token, mock_git):
        mock_token.return_value = "token"
        mock_git.return_value = b"test\n"

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        result = upload_report({"danger": []})

        self.assertFalse(result["success"])
        self.assertEqual(mock_post.call_count, 3)
        self.assertIn("Server Error 500", result["error"])

    def test_extract_snippet_valid(self):
        content = "line1\nline2\nline3\nline4\nline5\n"
        with patch("builtins.open", mock_open(read_data=content)):
            snippet = extract_snippet("fake.py", 3, context=1)
            self.assertEqual(snippet, "line2\nline3\nline4")

    def test_extract_snippet_context_zero(self):
        content = "a\nb\nc\nd\n"
        with patch("builtins.open", mock_open(read_data=content)):
            snippet = extract_snippet("fake.py", 3, context=0)
            self.assertEqual(snippet, "c")

    def test_extract_snippet_missing_file_returns_none(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            snippet = extract_snippet("missing.py", 1, context=2)
            self.assertIsNone(snippet)

    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor"))
    @patch("skylos.api.get_git_root", return_value=None)
    @patch("skylos.api.get_project_info")
    @patch("requests.post")
    def test_upload_report_whoami_failure_still_uploads(
        self, mock_post, mock_info, _, _mock_git_info, mock_token
    ):
        mock_token.return_value = "token"
        mock_info.return_value = None

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"scanId": "scan_ok"}
        mock_post.return_value = mock_response

        result = upload_report({"danger": []}, quiet=False)
        self.assertTrue(result["success"])
        self.assertEqual(result["scan_id"], "scan_ok")
        self.assertEqual(mock_post.call_count, 1)

    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor"))
    @patch("skylos.api.get_git_root", return_value=None)
    @patch("requests.post")
    def test_upload_report_401_returns_invalid_token_error(
        self, mock_post, _, _mock_git_info, mock_token
    ):
        mock_token.return_value = "token"
        resp = MagicMock()
        resp.status_code = 401
        resp.text = "Unauthorized"
        mock_post.return_value = resp

        result = upload_report({"danger": []})
        self.assertFalse(result["success"])
        self.assertEqual(
            result["error"],
            "Invalid API token. Run 'skylos sync connect' to reconnect.",
        )
        self.assertEqual(mock_post.call_count, 1)

    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor"))
    @patch("skylos.api.get_git_root", return_value=None)
    @patch("requests.post")
    def test_retry_returns_last_error_text(
        self, mock_post, _, _mock_git_info, mock_token
    ):
        mock_token.return_value = "token"

        r1 = MagicMock(status_code=500, text="E1")
        r2 = MagicMock(status_code=502, text="E2")
        r3 = MagicMock(status_code=503, text="E3")
        mock_post.side_effect = [r1, r2, r3]

        result = upload_report({"danger": []})
        self.assertFalse(result["success"])
        self.assertEqual(mock_post.call_count, 3)
        self.assertIn("Server Error 503", result["error"])
        self.assertIn("E3", result["error"])

    def test_base_url_api_suffix_endpoints(self):
        old = os.environ.get("SKYLOS_API_URL")
        try:
            os.environ["SKYLOS_API_URL"] = "https://example.com/api"
            importlib.reload(api)
            self.assertEqual(api.REPORT_URL, "https://example.com/api/report")
            self.assertEqual(api.WHOAMI_URL, "https://example.com/api/sync/whoami")
        finally:
            if old is None:
                os.environ.pop("SKYLOS_API_URL", None)
            else:
                os.environ["SKYLOS_API_URL"] = old
            importlib.reload(api)

    @patch("skylos.api.SarifExporter")
    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor"))
    @patch("skylos.api.get_git_root", return_value=None)
    @patch("requests.post")
    def test_prepare_for_sarif_normalizes_missing_fields(
        self, mock_post, _root, _git, mock_token, mock_exporter
    ):
        mock_token.return_value = "token"

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"scanId": "scan_norm"}
        mock_post.return_value = resp

        mock_exporter.return_value.generate.return_value = {"version": "2.1.0"}

        result = upload_report({"danger": [{"message": "oops"}]}, quiet=True)
        self.assertTrue(result["success"])

        all_findings = mock_exporter.call_args[0][0]
        self.assertEqual(len(all_findings), 1)
        f = all_findings[0]
        self.assertEqual(f["rule_id"], "SKY-D000")
        self.assertEqual(f["line_number"], 1)
        self.assertEqual(f["file_path"], "unknown")
        self.assertEqual(f["category"], "SECURITY")
        self.assertEqual(f["message"], "oops")

    @patch("skylos.api.SarifExporter")
    @patch("skylos.api.get_project_token")
    @patch("skylos.api.get_git_info", return_value=("c", "b", "actor"))
    @patch("skylos.api.get_git_root", return_value="/mock/git/root")
    @patch("requests.post")
    def test_prepare_for_sarif_relpaths_when_git_root_present(
        self, mock_post, _root, _git, mock_token, mock_exporter
    ):
        mock_token.return_value = "token"

        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"scanId": "scan_path"}
        mock_post.return_value = resp

        mock_exporter.return_value.generate.return_value = {"version": "2.1.0"}

        result = upload_report(
            {"danger": [{"file": "/mock/git/root/app.py", "line": 5, "message": "m"}]},
            quiet=True,
        )
        self.assertTrue(result["success"])

        all_findings = mock_exporter.call_args[0][0]
        f = all_findings[0]
        self.assertEqual(f["file_path"], "app.py")
        self.assertEqual(f["line_number"], 5)


if __name__ == "__main__":
    unittest.main()
