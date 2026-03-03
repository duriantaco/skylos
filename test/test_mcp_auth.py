"""Tests for MCP server auth gating and credit deduction.

Covers:
- AuthSession state management (rate limits, unauth limits, expiry)
- check_tool_access (unauthenticated vs authenticated, tool restrictions)
- deduct_credits (success, insufficient credits, enterprise bypass, network failure)
- initialize_auth (no key, invalid key, valid key with plan tiers)
- _gate integration (auth + credits combined)
"""

import json
import time
from unittest.mock import patch, MagicMock

import pytest

mcp = pytest.importorskip("mcp", reason="mcp not installed")

from skylos_mcp.auth import (
    AuthSession,
    TOOL_CREDIT_MAP,
    UNAUTHENTICATED_TOOLS,
    UNAUTH_DAILY_LIMIT,
    check_tool_access,
    deduct_credits,
    initialize_auth,
    get_session,
)


# ---------------------------------------------------------------------------
# AuthSession unit tests
# ---------------------------------------------------------------------------


class TestAuthSession:
    def test_default_session_is_unauthenticated(self):
        s = AuthSession()
        assert s.authenticated is False
        assert s.plan == "free"
        assert s.credits == 0

    def test_is_valid_requires_authentication(self):
        s = AuthSession(authenticated=False, validated_at=time.time())
        assert s.is_valid() is False

    def test_is_valid_within_15_minutes(self):
        s = AuthSession(authenticated=True, validated_at=time.time())
        assert s.is_valid() is True

    def test_is_valid_expires_after_15_minutes(self):
        s = AuthSession(authenticated=True, validated_at=time.time() - 901)
        assert s.is_valid() is False

    def test_check_rate_limit_under_limit(self):
        s = AuthSession(rate_limit_per_hour=50)
        assert s.check_rate_limit() is True

    def test_check_rate_limit_at_limit(self):
        s = AuthSession(rate_limit_per_hour=3)
        now = time.time()
        s._call_counts["_all"] = [now - 10, now - 5, now - 1]
        assert s.check_rate_limit() is False

    def test_check_rate_limit_old_calls_expire(self):
        s = AuthSession(rate_limit_per_hour=3)
        old = time.time() - 3700  # > 1 hour ago
        s._call_counts["_all"] = [old, old, old]
        assert s.check_rate_limit() is True

    def test_record_call_tracks_tool_and_all(self):
        s = AuthSession()
        s.record_call("analyze")
        s.record_call("analyze")
        s.record_call("security_scan")
        assert len(s._call_counts["_all"]) == 3
        assert len(s._call_counts["analyze"]) == 2
        assert len(s._call_counts["security_scan"]) == 1

    def test_check_unauth_limit_under_limit(self):
        s = AuthSession()
        assert s.check_unauth_limit() is True

    def test_check_unauth_limit_at_limit(self):
        s = AuthSession()
        now = time.time()
        s._unauth_calls = [now - i for i in range(UNAUTH_DAILY_LIMIT)]
        assert s.check_unauth_limit() is False

    def test_check_unauth_limit_old_calls_expire(self):
        s = AuthSession()
        old = time.time() - 90000  # > 24 hours ago
        s._unauth_calls = [old] * 10
        assert s.check_unauth_limit() is True

    def test_record_unauth_call(self):
        s = AuthSession()
        s.record_unauth_call()
        assert len(s._unauth_calls) == 1


# ---------------------------------------------------------------------------
# check_tool_access tests
# ---------------------------------------------------------------------------


class TestCheckToolAccess:
    def _set_session(self, **kwargs):
        """Replace global session for testing."""
        import skylos_mcp.auth as auth_mod

        auth_mod._session = AuthSession(**kwargs)

    def test_unauthenticated_analyze_allowed(self):
        self._set_session(authenticated=False)
        allowed, err = check_tool_access("analyze")
        assert allowed is True
        assert err == ""

    def test_unauthenticated_security_scan_blocked(self):
        self._set_session(authenticated=False)
        allowed, err = check_tool_access("security_scan")
        assert allowed is False
        assert "requires authentication" in err
        assert "SKYLOS_API_KEY" in err

    def test_unauthenticated_quality_check_blocked(self):
        self._set_session(authenticated=False)
        allowed, err = check_tool_access("quality_check")
        assert allowed is False
        assert "requires authentication" in err

    def test_unauthenticated_secrets_scan_blocked(self):
        self._set_session(authenticated=False)
        allowed, err = check_tool_access("secrets_scan")
        assert allowed is False
        assert "requires authentication" in err

    def test_unauthenticated_remediate_blocked(self):
        self._set_session(authenticated=False)
        allowed, err = check_tool_access("remediate")
        assert allowed is False
        assert "requires authentication" in err

    def test_unauthenticated_daily_limit_enforced(self):
        self._set_session(authenticated=False)
        session = get_session()
        session._unauth_calls = [time.time() - i for i in range(UNAUTH_DAILY_LIMIT)]

        allowed, err = check_tool_access("analyze")
        assert allowed is False
        assert "Daily limit reached" in err

    def test_authenticated_all_tools_allowed(self):
        self._set_session(
            authenticated=True,
            plan="pro",
            rate_limit_per_hour=500,
            validated_at=time.time(),
        )
        for tool in TOOL_CREDIT_MAP:
            allowed, err = check_tool_access(tool)
            assert allowed is True, f"{tool} should be allowed for authenticated user"

    def test_authenticated_rate_limit_enforced(self):
        self._set_session(
            authenticated=True,
            plan="free",
            rate_limit_per_hour=3,
            validated_at=time.time(),
        )
        session = get_session()
        now = time.time()
        session._call_counts["_all"] = [now - 1, now - 2, now - 3]

        allowed, err = check_tool_access("analyze")
        assert allowed is False
        assert "Rate limit exceeded" in err


# ---------------------------------------------------------------------------
# deduct_credits tests
# ---------------------------------------------------------------------------


class TestDeductCredits:
    def _set_session(self, **kwargs):
        import skylos_mcp.auth as auth_mod

        auth_mod._session = AuthSession(**kwargs)

    def test_unauthenticated_no_deduction(self):
        self._set_session(authenticated=False)
        ok, err = deduct_credits("analyze")
        assert ok is True
        # Should record the unauth call
        assert len(get_session()._unauth_calls) == 1

    def test_enterprise_no_deduction(self):
        self._set_session(
            authenticated=True,
            plan="enterprise",
            api_key="test-key",
            validated_at=time.time(),
        )
        ok, err = deduct_credits("security_scan")
        assert ok is True
        # Should record the call but no HTTP request
        assert len(get_session()._call_counts.get("_all", [])) == 1

    def test_unknown_tool_no_deduction(self):
        self._set_session(
            authenticated=True,
            plan="pro",
            api_key="test-key",
            validated_at=time.time(),
        )
        ok, err = deduct_credits("unknown_tool")
        assert ok is True

    def test_successful_deduction(self):
        self._set_session(
            authenticated=True,
            plan="pro",
            api_key="test-key",
            credits=100,
            validated_at=time.time(),
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"balance_after": 99, "success": True}

        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp
        with patch.dict("sys.modules", {"requests": mock_req}):
            ok, err = deduct_credits("analyze")

        assert ok is True
        assert get_session().credits == 99

        mock_req.post.assert_called_once()
        call_args = mock_req.post.call_args
        assert "credits/deduct" in call_args[0][0]
        assert call_args[1]["json"]["feature_key"] == "mcp_analyze"

    def test_insufficient_credits_402(self):
        self._set_session(
            authenticated=True,
            plan="pro",
            api_key="test-key",
            credits=0,
            validated_at=time.time(),
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 402
        mock_resp.json.return_value = {
            "required": 2,
            "available": 0,
            "shortfall": 2,
        }

        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp
        with patch.dict("sys.modules", {"requests": mock_req}):
            ok, err = deduct_credits("security_scan")

        assert ok is False
        assert "Insufficient credits" in err
        assert "Required: 2" in err
        assert "available: 0" in err
        assert "dashboard/billing" in err

    def test_network_failure_allows_call(self):
        """Graceful degradation: network errors should not block the tool."""
        self._set_session(
            authenticated=True,
            plan="pro",
            api_key="test-key",
            credits=100,
            validated_at=time.time(),
        )

        mock_req = MagicMock()
        mock_req.post.side_effect = ConnectionError("network down")
        with patch.dict("sys.modules", {"requests": mock_req}):
            ok, err = deduct_credits("analyze")

        assert ok is True
        assert len(get_session()._call_counts.get("_all", [])) == 1

    def test_unexpected_status_code_allows_call(self):
        self._set_session(
            authenticated=True,
            plan="pro",
            api_key="test-key",
            validated_at=time.time(),
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp
        with patch.dict("sys.modules", {"requests": mock_req}):
            ok, err = deduct_credits("analyze")

        assert ok is True

    def test_correct_feature_keys_sent(self):
        """Each tool maps to the correct feature_key in the API call."""
        expected = {
            "analyze": "mcp_analyze",
            "security_scan": "mcp_security_scan",
            "quality_check": "mcp_quality_check",
            "secrets_scan": "mcp_secrets_scan",
            "remediate": "mcp_remediate",
        }
        for tool, feature_key in expected.items():
            self._set_session(
                authenticated=True,
                plan="pro",
                api_key="test-key",
                validated_at=time.time(),
            )

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"balance_after": 90}

            mock_req = MagicMock()
            mock_req.post.return_value = mock_resp
            with patch.dict("sys.modules", {"requests": mock_req}):
                deduct_credits(tool)

            sent_key = mock_req.post.call_args[1]["json"]["feature_key"]
            assert sent_key == feature_key, (
                f"{tool} should send {feature_key}, got {sent_key}"
            )


# ---------------------------------------------------------------------------
# initialize_auth tests
# ---------------------------------------------------------------------------


class TestInitializeAuth:
    @patch.dict("os.environ", {}, clear=False)
    def test_no_api_key_returns_unauthenticated(self):
        with patch.dict("os.environ", {"SKYLOS_API_KEY": ""}):
            session = initialize_auth()
            assert session.authenticated is False

    @patch("skylos_mcp.auth._validate_with_cloud")
    def test_invalid_key_returns_unauthenticated(self, mock_validate):
        mock_validate.return_value = None
        with patch.dict("os.environ", {"SKYLOS_API_KEY": "bad-key"}):
            session = initialize_auth()
            assert session.authenticated is False

    @patch("skylos_mcp.auth._validate_with_cloud")
    def test_valid_free_key(self, mock_validate):
        mock_validate.return_value = {
            "plan": "free",
            "credits": 50,
            "org_id": "org-123",
        }
        with patch.dict("os.environ", {"SKYLOS_API_KEY": "valid-key"}):
            session = initialize_auth()
            assert session.authenticated is True
            assert session.plan == "free"
            assert session.credits == 50
            assert session.rate_limit_per_hour == 50

    @patch("skylos_mcp.auth._validate_with_cloud")
    def test_valid_pro_key(self, mock_validate):
        mock_validate.return_value = {
            "plan": "pro",
            "credits": 5000,
            "org_id": "org-456",
        }
        with patch.dict("os.environ", {"SKYLOS_API_KEY": "pro-key"}):
            session = initialize_auth()
            assert session.authenticated is True
            assert session.plan == "pro"
            assert session.rate_limit_per_hour == 500

    @patch("skylos_mcp.auth._validate_with_cloud")
    def test_valid_enterprise_key(self, mock_validate):
        mock_validate.return_value = {
            "plan": "enterprise",
            "credits": 0,
            "org_id": "org-789",
        }
        with patch.dict("os.environ", {"SKYLOS_API_KEY": "ent-key"}):
            session = initialize_auth()
            assert session.authenticated is True
            assert session.plan == "enterprise"
            assert session.rate_limit_per_hour == 5000


# ---------------------------------------------------------------------------
# _gate integration tests (auth + credits combined)
# ---------------------------------------------------------------------------


class TestGateIntegration:
    """Tests for the _gate() function in server.py that combines auth + credits."""

    def _set_session(self, **kwargs):
        import skylos_mcp.auth as auth_mod

        auth_mod._session = AuthSession(**kwargs)

    def test_gate_unauthenticated_analyze_passes(self):
        from skylos_mcp.server import _gate

        self._set_session(authenticated=False)
        result = _gate("analyze")
        assert result is None  # None = no error, proceed

    def test_gate_unauthenticated_security_scan_blocked(self):
        from skylos_mcp.server import _gate

        self._set_session(authenticated=False)
        result = _gate("security_scan")
        assert result is not None
        error = json.loads(result)
        assert "error" in error
        assert "requires authentication" in error["error"]

    def test_gate_authenticated_with_credits_passes(self):
        from skylos_mcp.server import _gate

        self._set_session(
            authenticated=True,
            plan="pro",
            api_key="test-key",
            credits=100,
            rate_limit_per_hour=500,
            validated_at=time.time(),
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"balance_after": 98}

        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp
        with patch.dict("sys.modules", {"requests": mock_req}):
            result = _gate("security_scan")
        assert result is None

    def test_gate_authenticated_no_credits_blocked(self):
        from skylos_mcp.server import _gate

        self._set_session(
            authenticated=True,
            plan="pro",
            api_key="test-key",
            credits=0,
            rate_limit_per_hour=500,
            validated_at=time.time(),
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 402
        mock_resp.json.return_value = {"required": 10, "available": 0}

        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp
        with patch.dict("sys.modules", {"requests": mock_req}):
            result = _gate("remediate")
        assert result is not None
        error = json.loads(result)
        assert "Insufficient credits" in error["error"]

    def test_gate_enterprise_always_passes(self):
        from skylos_mcp.server import _gate

        self._set_session(
            authenticated=True,
            plan="enterprise",
            api_key="ent-key",
            credits=0,  # doesn't matter for enterprise
            rate_limit_per_hour=5000,
            validated_at=time.time(),
        )
        for tool in TOOL_CREDIT_MAP:
            result = _gate(tool)
            assert result is None, f"Enterprise should pass gate for {tool}"

    def test_gate_rate_limited_blocked(self):
        from skylos_mcp.server import _gate

        self._set_session(
            authenticated=True,
            plan="free",
            api_key="test-key",
            rate_limit_per_hour=2,
            validated_at=time.time(),
        )
        session = get_session()
        now = time.time()
        session._call_counts["_all"] = [now - 1, now - 2]

        result = _gate("analyze")
        assert result is not None
        error = json.loads(result)
        assert "Rate limit exceeded" in error["error"]
