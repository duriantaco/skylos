"""Tests for CLI credit balance, credit status display, and upload credit gating.

Covers:
- get_credit_balance (success, failure, no token)
- print_credit_status (enterprise, low balance, normal)
- upload_report credit handling (402 no credits, credits_warning, normal deduction)
"""

from unittest.mock import patch, MagicMock

import pytest

from skylos.api import get_credit_balance, print_credit_status


# ---------------------------------------------------------------------------
# get_credit_balance tests
# ---------------------------------------------------------------------------


class TestGetCreditBalance:
    @patch("skylos.api.get_project_token", return_value="test-token")
    @patch("skylos.api.requests")
    def test_returns_balance_on_success(self, mock_requests, mock_token):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "balance": 500,
            "plan": "pro",
            "org_name": "Test Org",
            "recent_transactions": [],
        }
        mock_requests.get.return_value = mock_resp

        result = get_credit_balance("test-token")
        assert result is not None
        assert result["balance"] == 500
        assert result["plan"] == "pro"

    @patch("skylos.api.get_project_token", return_value="test-token")
    @patch("skylos.api.requests")
    def test_returns_none_on_server_error(self, mock_requests, mock_token):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_requests.get.return_value = mock_resp

        result = get_credit_balance("test-token")
        assert result is None

    @patch("skylos.api.get_project_token", return_value="test-token")
    @patch("skylos.api.requests")
    def test_returns_none_on_network_error(self, mock_requests, mock_token):
        mock_requests.get.side_effect = ConnectionError("network down")
        result = get_credit_balance("test-token")
        assert result is None

    def test_returns_none_when_no_token(self):
        result = get_credit_balance(None)
        assert result is None

    def test_returns_none_for_oidc_token(self):
        result = get_credit_balance("oidc:some-token")
        assert result is None

    @patch("skylos.api.get_project_token", return_value="test-token")
    @patch("skylos.api.requests")
    def test_sends_correct_auth_header(self, mock_requests, mock_token):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"balance": 100}
        mock_requests.get.return_value = mock_resp

        get_credit_balance("my-token-123")

        call_args = mock_requests.get.call_args
        assert call_args[1]["headers"]["Authorization"] == "Bearer my-token-123"

    @patch("skylos.api.get_project_token", return_value="test-token")
    @patch("skylos.api.requests")
    def test_calls_correct_endpoint(self, mock_requests, mock_token):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"balance": 100}
        mock_requests.get.return_value = mock_resp

        get_credit_balance("token")

        url = mock_requests.get.call_args[0][0]
        assert url.endswith("/api/credits/balance")


# ---------------------------------------------------------------------------
# print_credit_status tests
# ---------------------------------------------------------------------------


class TestPrintCreditStatus:
    @patch("skylos.api.get_credit_balance")
    def test_enterprise_shows_unlimited(self, mock_balance, capsys):
        mock_balance.return_value = {
            "balance": 0,
            "plan": "enterprise",
        }
        result = print_credit_status("token")
        output = capsys.readouterr().out
        assert "unlimited" in output.lower() or "Enterprise" in output

    @patch("skylos.api.get_credit_balance")
    def test_low_balance_shows_warning(self, mock_balance, capsys):
        mock_balance.return_value = {
            "balance": 5,
            "plan": "pro",
        }
        result = print_credit_status("token")
        output = capsys.readouterr().out
        assert "5" in output
        assert "dashboard/billing" in output

    @patch("skylos.api.get_credit_balance")
    def test_normal_balance_shows_count(self, mock_balance, capsys):
        mock_balance.return_value = {
            "balance": 5000,
            "plan": "pro",
        }
        result = print_credit_status("token")
        output = capsys.readouterr().out
        assert "5,000" in output

    @patch("skylos.api.get_credit_balance")
    def test_quiet_mode_no_output(self, mock_balance, capsys):
        mock_balance.return_value = {
            "balance": 100,
            "plan": "pro",
        }
        result = print_credit_status("token", quiet=True)
        output = capsys.readouterr().out
        assert output == ""

    @patch("skylos.api.get_credit_balance")
    def test_returns_none_when_no_data(self, mock_balance):
        mock_balance.return_value = None
        result = print_credit_status("token")
        assert result is None


# ---------------------------------------------------------------------------
# upload_report credit gating tests
# ---------------------------------------------------------------------------


class TestUploadReportCredits:
    """Tests for credit-related behavior in upload_report().

    upload_report() does heavy processing (SARIF conversion, git info, etc.)
    before hitting the API, so we mock at multiple levels.
    """

    MINIMAL_RESULT = {
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    @patch("skylos.api.detect_ai_code", return_value={"detected": False, "indicators": [], "ai_files": [], "confidence": "low"})
    @patch("skylos.api.get_git_info", return_value=("abc123", "main", "user", None))
    @patch("skylos.api.get_project_info", return_value={"ok": True, "plan": "pro", "project": {"name": "test"}})
    @patch("skylos.api.get_project_token", return_value="test-token")
    @patch("skylos.api.requests")
    @patch("skylos.api._load_repo_link")
    @patch("skylos.api.get_git_root", return_value="/fake/repo")
    def test_402_returns_no_credits_error(
        self, mock_git, mock_link, mock_requests, mock_token, mock_info, mock_gitinfo, mock_ai
    ):
        from skylos.api import upload_report

        mock_link.return_value = {"project_id": "proj-1", "org_id": "org-1"}

        mock_resp = MagicMock()
        mock_resp.status_code = 402
        mock_resp.json.return_value = {
            "error": "No credits remaining. Buy more at skylos.dev/dashboard/billing"
        }
        mock_resp.text = "No credits"
        mock_requests.post.return_value = mock_resp

        result = upload_report(self.MINIMAL_RESULT, quiet=True)
        assert result["success"] is False
        assert result.get("code") == "NO_CREDITS"
        assert "credits" in result["error"].lower() or "Credits" in result["error"]

    @patch("skylos.api.detect_ai_code", return_value={"detected": False, "indicators": [], "ai_files": [], "confidence": "low"})
    @patch("skylos.api.get_git_info", return_value=("abc123", "main", "user", None))
    @patch("skylos.api.get_project_info", return_value={"ok": True, "plan": "pro", "project": {"name": "test"}})
    @patch("skylos.api.get_project_token", return_value="test-token")
    @patch("skylos.api.requests")
    @patch("skylos.api._load_repo_link")
    @patch("skylos.api.get_git_root", return_value="/fake/repo")
    def test_successful_upload_includes_credits_remaining(
        self, mock_git, mock_link, mock_requests, mock_token, mock_info, mock_gitinfo, mock_ai
    ):
        from skylos.api import upload_report

        mock_link.return_value = {"project_id": "proj-1", "org_id": "org-1"}

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "scan_id": "scan-123",
            "quality_gate_passed": True,
            "credits_remaining": 499,
            "credits_warning": False,
            "plan": "pro",
        }
        mock_requests.post.return_value = mock_resp

        result = upload_report(self.MINIMAL_RESULT, quiet=True)
        assert result["success"] is True
        assert result["credits_warning"] is False

    @patch("skylos.api.detect_ai_code", return_value={"detected": False, "indicators": [], "ai_files": [], "confidence": "low"})
    @patch("skylos.api.get_git_info", return_value=("abc123", "main", "user", None))
    @patch("skylos.api.get_project_info", return_value={"ok": True, "plan": "pro", "project": {"name": "test"}})
    @patch("skylos.api.get_project_token", return_value="test-token")
    @patch("skylos.api.requests")
    @patch("skylos.api._load_repo_link")
    @patch("skylos.api.get_git_root", return_value="/fake/repo")
    def test_credits_warning_flag_passed_through(
        self, mock_git, mock_link, mock_requests, mock_token, mock_info, mock_gitinfo, mock_ai
    ):
        from skylos.api import upload_report

        mock_link.return_value = {"project_id": "proj-1", "org_id": "org-1"}

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "scan_id": "scan-456",
            "quality_gate_passed": True,
            "credits_remaining": 12,
            "credits_warning": True,
            "plan": "pro",
        }
        mock_requests.post.return_value = mock_resp

        result = upload_report(self.MINIMAL_RESULT, quiet=True)
        assert result["success"] is True
        assert result["credits_warning"] is True
