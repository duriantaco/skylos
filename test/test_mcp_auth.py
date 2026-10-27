import json
import asyncio
import time
from unittest.mock import patch, MagicMock

import pytest

mcp = pytest.importorskip("mcp", reason="mcp not installed")

from skylos_mcp.auth import (  # noqa: E402
    AuthSession,
    MCP_AUTH_SCOPE,
    TOOL_CREDIT_MAP,
    UNAUTH_DAILY_LIMIT,
    build_mcp_network_auth,
    check_mcp_client_context,
    check_tool_access,
    deduct_credits,
    initialize_auth,
    get_session,
)


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


class TestCheckToolAccess:
    def _set_session(self, **kwargs):
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

    def test_unauthenticated_focused_quality_tools_blocked(self):
        self._set_session(authenticated=False)
        for tool in ("architecture_check", "health_score"):
            allowed, err = check_tool_access(tool)
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

    @patch("skylos_mcp.auth._validate_with_cloud")
    def test_stale_authenticated_session_revalidates(self, mock_validate):
        self._set_session(
            authenticated=True,
            plan="free",
            api_key="test-key",
            credits=1,
            rate_limit_per_hour=50,
            validated_at=time.time() - 901,
        )
        mock_validate.return_value = {
            "plan": "pro",
            "credits": 100,
            "org_id": "org-1",
        }

        allowed, err = check_tool_access("security_scan")

        assert allowed is True
        assert err == ""
        mock_validate.assert_called_once_with("test-key")
        session = get_session()
        assert session.authenticated is True
        assert session.plan == "pro"
        assert session.credits == 100
        assert session.rate_limit_per_hour == 500

    @patch("skylos_mcp.auth._validate_with_cloud")
    def test_stale_authenticated_session_blocks_paid_tool_when_revalidation_fails(
        self, mock_validate
    ):
        self._set_session(
            authenticated=True,
            plan="pro",
            api_key="revoked-key",
            credits=100,
            rate_limit_per_hour=500,
            validated_at=time.time() - 901,
        )
        mock_validate.return_value = None

        allowed, err = check_tool_access("security_scan")

        assert allowed is False
        assert "requires authentication" in err
        assert get_session().authenticated is False


class TestDeductCredits:
    def _set_session(self, **kwargs):
        import skylos_mcp.auth as auth_mod

        auth_mod._session = AuthSession(**kwargs)

    def test_unauthenticated_no_deduction(self):
        self._set_session(authenticated=False)
        ok, err = deduct_credits("analyze")
        assert ok is True
        assert len(get_session()._unauth_calls) == 1

    # Enterprise spends credits like every plan (founder decision, 14 Oct 2026).
    def _enterprise_post(self, status_code, payload, credits=5000):
        self._set_session(
            authenticated=True,
            plan="enterprise",
            api_key="ent-key",
            credits=credits,
            validated_at=time.time(),
        )
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.json.return_value = payload
        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp
        return mock_req

    def test_enterprise_is_charged(self):
        mock_req = self._enterprise_post(200, {"balance_after": 4990, "success": True})
        with patch.dict("sys.modules", {"requests": mock_req}):
            ok, err = deduct_credits("remediate")

        assert (ok, err) == (True, "")
        assert get_session().credits == 4990
        mock_req.post.assert_called_once()
        call_args = mock_req.post.call_args
        assert "credits/deduct" in call_args[0][0]
        assert call_args[1]["json"]["feature_key"] == "mcp_remediate"
        assert call_args[1]["headers"]["Authorization"] == "Bearer ent-key"

    def test_enterprise_insufficient_credits_matches_pro(self):
        answers = {}
        for plan in ("enterprise", "pro"):
            mock_req = self._enterprise_post(
                402, {"required": 10, "available": 3}, credits=3
            )
            get_session().plan = plan
            with patch.dict("sys.modules", {"requests": mock_req}):
                answers[plan] = deduct_credits("remediate")

        assert answers["enterprise"] == answers["pro"]
        ok, err = answers["enterprise"]
        assert ok is False
        assert "Insufficient credits. Required: 10, available: 3." in err
        assert "dashboard/billing" in err

    def test_enterprise_free_scan_tool_still_runs(self):
        mock_req = self._enterprise_post(200, {"balance_after": 5000, "success": True})
        with patch.dict("sys.modules", {"requests": mock_req}):
            ok, err = deduct_credits("security_scan")

        assert ok is True
        mock_req.post.assert_called_once()
        assert mock_req.post.call_args[1]["json"]["feature_key"] == "mcp_security_scan"

    def test_enterprise_network_failure_blocks_like_pro(self):
        mock_req = self._enterprise_post(200, {})
        mock_req.post.side_effect = ConnectionError("network down")
        with patch.dict("sys.modules", {"requests": mock_req}):
            ok, err = deduct_credits("remediate")

        assert ok is False
        assert "Could not verify credit deduction" in err

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

    def test_network_failure_blocks_call(self):
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

        assert ok is False
        assert "Could not verify credit deduction" in err
        assert get_session()._call_counts.get("_all", []) == []

    def test_unexpected_status_code_blocks_call(self):
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

        assert ok is False
        assert "Could not verify credit deduction" in err

    def test_correct_feature_keys_sent(self):
        expected = {
            "analyze": "mcp_analyze",
            "security_scan": "mcp_security_scan",
            "quality_check": "mcp_quality_check",
            "architecture_check": "mcp_quality_check",
            "health_score": "mcp_quality_check",
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


class TestMCPNetworkClientAuth:
    def test_client_context_not_required_for_stdio(self):
        allowed, err = check_mcp_client_context(required=False)

        assert allowed is True
        assert err == ""

    def test_client_context_required_blocks_without_authenticated_request(self):
        allowed, err = check_mcp_client_context(required=True)

        assert allowed is False
        assert "MCP client authentication is required" in err

    def test_stdio_transport_does_not_require_client_token(self):
        with patch.dict("os.environ", {"SKYLOS_MCP_TOKEN": ""}):
            auth_config = build_mcp_network_auth("stdio", host="127.0.0.1", port=8080)

        assert auth_config is None

    def test_network_transport_requires_client_token_even_with_server_key(self):
        with patch.dict(
            "os.environ",
            {
                "SKYLOS_API_KEY": "server-cloud-key",
                "SKYLOS_MCP_TOKEN": "",
            },
        ):
            with pytest.raises(RuntimeError, match="requires SKYLOS_MCP_TOKEN"):
                build_mcp_network_auth("sse", host="0.0.0.0", port=8080)

    def test_network_transport_rejects_weak_client_token(self):
        with patch.dict("os.environ", {"SKYLOS_MCP_TOKEN": "short"}):
            with pytest.raises(RuntimeError, match="at least 16 characters"):
                build_mcp_network_auth("streamable-http", host="127.0.0.1", port=8080)

    def test_network_verifier_accepts_client_token_not_server_key(self):
        with patch.dict(
            "os.environ",
            {
                "SKYLOS_API_KEY": "server-cloud-key",
                "SKYLOS_MCP_TOKEN": "client-token-123456",
            },
        ):
            auth_config = build_mcp_network_auth(
                "streamable-http",
                host="127.0.0.1",
                port=8080,
            )

        assert auth_config is not None
        assert auth_config.auth.required_scopes == [MCP_AUTH_SCOPE]

        accepted = asyncio.run(
            auth_config.token_verifier.verify_token("client-token-123456")
        )
        rejected = asyncio.run(
            auth_config.token_verifier.verify_token("server-cloud-key")
        )

        assert accepted is not None
        assert accepted.client_id == "skylos-mcp-client"
        assert accepted.scopes == [MCP_AUTH_SCOPE]
        assert rejected is None

    def test_streamable_http_rejects_missing_or_server_key_bearer(self):
        from mcp.server.fastmcp import FastMCP
        from starlette.testclient import TestClient

        with patch.dict(
            "os.environ",
            {
                "SKYLOS_API_KEY": "server-cloud-key",
                "SKYLOS_MCP_TOKEN": "client-token-123456",
            },
        ):
            auth_config = build_mcp_network_auth(
                "streamable-http",
                host="127.0.0.1",
                port=8080,
            )

        assert auth_config is not None
        app = FastMCP(
            name="skylos",
            host="127.0.0.1",
            port=8080,
            auth=auth_config.auth,
            token_verifier=auth_config.token_verifier,
        ).streamable_http_app()
        client = TestClient(app)

        assert client.get("/mcp").status_code == 401
        assert (
            client.get(
                "/mcp",
                headers={"Authorization": "Bearer server-cloud-key"},
            ).status_code
            == 401
        )


class TestGateIntegration:
    def _set_session(self, **kwargs):
        import skylos_mcp.auth as auth_mod

        auth_mod._session = AuthSession(**kwargs)

    def test_gate_unauthenticated_analyze_passes(self):
        from skylos_mcp.server import _gate

        self._set_session(authenticated=False)
        result = _gate("analyze")
        assert result is None

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

    def test_gate_network_context_blocks_server_key_without_client_context(self):
        import skylos_mcp.server as server_mod
        from skylos_mcp.server import _gate

        self._set_session(
            authenticated=True,
            plan="enterprise",
            api_key="server-cloud-key",
            credits=0,
            rate_limit_per_hour=5000,
            validated_at=time.time(),
        )

        previous = server_mod._REQUIRE_MCP_CLIENT_AUTH_CONTEXT
        server_mod._REQUIRE_MCP_CLIENT_AUTH_CONTEXT = True
        try:
            result = _gate("secrets_scan")
        finally:
            server_mod._REQUIRE_MCP_CLIENT_AUTH_CONTEXT = previous

        assert result is not None
        error = json.loads(result)
        assert "MCP client authentication is required" in error["error"]

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

    def test_gate_credit_deduction_failure_blocked(self):
        from skylos_mcp.server import _gate

        self._set_session(
            authenticated=True,
            plan="pro",
            api_key="test-key",
            credits=100,
            rate_limit_per_hour=500,
            validated_at=time.time(),
        )

        mock_req = MagicMock()
        mock_req.post.side_effect = ConnectionError("network down")
        with patch.dict("sys.modules", {"requests": mock_req}):
            result = _gate("remediate")

        assert result is not None
        error = json.loads(result)
        assert "Could not verify credit deduction" in error["error"]

    def test_gate_enterprise_without_credits_is_blocked(self):
        # Enterprise no longer skips the credit check (14 Oct 2026).
        from skylos_mcp.server import _gate

        self._set_session(
            authenticated=True,
            plan="enterprise",
            api_key="ent-key",
            credits=0,
            rate_limit_per_hour=5000,
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
        mock_req.post.assert_called_once()

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


class _ToolRegistry:
    def __init__(self):
        self.tools = {}

    def tool(self, *args, **kwargs):
        def register(fn):
            self.tools[fn.__name__] = fn
            return fn

        return register

    def resource(self, *args, **kwargs):
        def register(fn):
            return fn

        return register


class TestRemediateCredits:
    def _remediate(self):
        from skylos_mcp.server import _register_tools

        registry = _ToolRegistry()
        _register_tools(registry)
        return registry.tools["remediate"]

    def _paid_session(self, monkeypatch):
        import skylos_mcp.auth as auth_mod

        session = AuthSession(
            authenticated=True,
            plan="pro",
            api_key="test-key",
            credits=100,
            rate_limit_per_hour=500,
            validated_at=time.time(),
        )
        monkeypatch.setattr(auth_mod, "_session", session)
        return session

    def _deduct_ok(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"balance_after": 90}
        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp
        return mock_req

    def _agent(self):
        agent_cls = MagicMock()
        agent_cls.return_value.run.return_value = {"planned": 1}
        return agent_cls

    def test_dry_run_is_not_charged_but_counts_toward_the_rate_limit(
        self, tmp_path, monkeypatch
    ):
        session = self._paid_session(monkeypatch)
        mock_req = self._deduct_ok()
        agent_cls = self._agent()

        with (
            patch.dict("sys.modules", {"requests": mock_req}),
            patch("skylos.llm.orchestrator.RemediationAgent", agent_cls),
        ):
            reply = json.loads(self._remediate()(str(tmp_path), dry_run=True))

        assert reply == {"planned": 1}
        mock_req.post.assert_not_called()
        assert agent_cls.return_value.run.call_args.kwargs["dry_run"] is True
        assert len(session._call_counts["remediate"]) == 1

    def test_default_call_is_a_free_dry_run(self, tmp_path, monkeypatch):
        self._paid_session(monkeypatch)
        mock_req = self._deduct_ok()
        agent_cls = self._agent()

        with (
            patch.dict("sys.modules", {"requests": mock_req}),
            patch("skylos.llm.orchestrator.RemediationAgent", agent_cls),
        ):
            self._remediate()(str(tmp_path))

        mock_req.post.assert_not_called()
        assert agent_cls.return_value.run.call_args.kwargs["dry_run"] is True

    def test_generating_fixes_is_charged(self, tmp_path, monkeypatch):
        self._paid_session(monkeypatch)
        mock_req = self._deduct_ok()
        agent_cls = self._agent()

        with (
            patch.dict("sys.modules", {"requests": mock_req}),
            patch("skylos.llm.orchestrator.RemediationAgent", agent_cls),
            patch("skylos.llm.runtime.llm_extra_installed", return_value=True),
        ):
            self._remediate()(str(tmp_path), dry_run=False)

        mock_req.post.assert_called_once()
        assert mock_req.post.call_args.kwargs["json"] == {
            "feature_key": "mcp_remediate"
        }
        assert agent_cls.return_value.run.call_args.kwargs["dry_run"] is False

    def test_generating_fixes_without_credits_does_not_run(self, tmp_path, monkeypatch):
        self._paid_session(monkeypatch)
        mock_resp = MagicMock()
        mock_resp.status_code = 402
        mock_resp.json.return_value = {"required": 10, "available": 0}
        mock_req = MagicMock()
        mock_req.post.return_value = mock_resp
        agent_cls = self._agent()

        with (
            patch.dict("sys.modules", {"requests": mock_req}),
            patch("skylos.llm.orchestrator.RemediationAgent", agent_cls),
            patch("skylos.llm.runtime.llm_extra_installed", return_value=True),
        ):
            reply = json.loads(self._remediate()(str(tmp_path), dry_run=False))

        assert "Insufficient credits" in reply["error"]
        agent_cls.assert_not_called()

    def test_generating_fixes_without_the_llm_extra_is_refused_before_charging(
        self, tmp_path, monkeypatch
    ):
        session = self._paid_session(monkeypatch)
        mock_req = self._deduct_ok()
        agent_cls = self._agent()

        with (
            patch.dict("sys.modules", {"requests": mock_req}),
            patch("skylos.llm.orchestrator.RemediationAgent", agent_cls),
            patch("skylos.llm.runtime.llm_extra_installed", return_value=False),
        ):
            reply = json.loads(self._remediate()(str(tmp_path), dry_run=False))

        assert 'pip install "skylos[llm]"' in reply["error"]
        mock_req.post.assert_not_called()
        agent_cls.assert_not_called()
        assert "remediate" not in session._call_counts

    def test_rejected_test_cmd_is_not_charged(self, tmp_path, monkeypatch):
        self._paid_session(monkeypatch)
        mock_req = self._deduct_ok()

        with patch.dict("sys.modules", {"requests": mock_req}):
            reply = json.loads(
                self._remediate()(str(tmp_path), dry_run=False, test_cmd="pytest")
            )

        assert "does not accept test_cmd" in reply["error"]
        mock_req.post.assert_not_called()

    def test_unauthenticated_dry_run_still_needs_a_key(self, tmp_path, monkeypatch):
        import skylos_mcp.auth as auth_mod

        monkeypatch.setattr(auth_mod, "_session", AuthSession(authenticated=False))
        agent_cls = self._agent()

        with patch("skylos.llm.orchestrator.RemediationAgent", agent_cls):
            reply = json.loads(self._remediate()(str(tmp_path), dry_run=True))

        assert "requires authentication" in reply["error"]
        agent_cls.assert_not_called()

    def test_rate_limited_dry_run_is_blocked(self, tmp_path, monkeypatch):
        session = self._paid_session(monkeypatch)
        now = time.time()
        session.rate_limit_per_hour = 1
        session._call_counts["_all"] = [now - 1]
        agent_cls = self._agent()

        with patch("skylos.llm.orchestrator.RemediationAgent", agent_cls):
            reply = json.loads(self._remediate()(str(tmp_path), dry_run=True))

        assert "Rate limit exceeded" in reply["error"]
        agent_cls.assert_not_called()


class TestVerifyDeadCodeNeedsTheLlmExtra:
    def test_missing_llm_extra_is_reported_before_analysis(self, tmp_path, monkeypatch):
        import skylos_mcp.auth as auth_mod
        import skylos_mcp.server as server_mod

        monkeypatch.setattr(
            auth_mod,
            "_session",
            AuthSession(
                authenticated=True,
                plan="pro",
                api_key="test-key",
                rate_limit_per_hour=500,
                validated_at=time.time(),
            ),
        )
        registry = _ToolRegistry()
        server_mod._register_tools(registry)
        analyze = MagicMock()

        with (
            patch.object(server_mod, "_lazy_analyze", return_value=analyze),
            patch("skylos.llm.runtime.llm_extra_installed", return_value=False),
        ):
            reply = json.loads(registry.tools["verify_dead_code"](str(tmp_path)))

        assert 'pip install "skylos[llm]"' in reply["error"]
        analyze.assert_not_called()
