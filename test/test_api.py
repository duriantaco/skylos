import unittest
from unittest.mock import patch, MagicMock, mock_open

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
        self.assertEqual(result["error"], "No token found")

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
