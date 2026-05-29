from __future__ import annotations

import logging
import hmac
import os
import time
from dataclasses import dataclass, field
from typing import Any

from skylos.constants import NETWORK_TIMEOUT_SHORT

logger = logging.getLogger("skylos-mcp-auth")

CLOUD_BASE_URL = os.getenv("SKYLOS_CLOUD_URL", "https://skylos.dev")

TOOL_CREDIT_MAP: dict[str, str] = {
    "analyze": "mcp_analyze",
    "security_scan": "mcp_security_scan",
    "quality_check": "mcp_quality_check",
    "architecture_check": "mcp_quality_check",
    "health_score": "mcp_quality_check",
    "secrets_scan": "mcp_secrets_scan",
    "remediate": "mcp_remediate",
    "provenance_scan": "mcp_provenance_scan",
}

UNAUTHENTICATED_TOOLS = {"analyze"}

UNAUTH_DAILY_LIMIT = 5
UNAUTH_WINDOW_SECONDS = 86400
MCP_CLIENT_TOKEN_ENV = "SKYLOS_MCP_TOKEN"
MCP_AUTH_SCOPE = "skylos:mcp"
MCP_NETWORK_TRANSPORTS = {"sse", "streamable-http"}
MCP_CLIENT_TOKEN_MIN_LENGTH = 16
RATE_LIMITS_BY_PLAN = {"free": 50, "pro": 500, "enterprise": 5000}


@dataclass
class AuthSession:
    authenticated: bool = False
    api_key: str = ""
    plan: str = "free"
    credits: int = 0
    org_id: str = ""
    rate_limit_per_hour: int = 50
    validated_at: float = 0.0
    _call_counts: dict[str, list[float]] = field(default_factory=dict)
    _unauth_calls: list[float] = field(default_factory=list)

    def is_valid(self) -> bool:
        if not self.authenticated:
            return False
        return (time.time() - self.validated_at) < 900  # 15 minutes

    def check_rate_limit(self) -> bool:
        now = time.time()
        hour_ago = now - 3600

        all_calls = self._call_counts.get("_all", [])
        all_calls = [t for t in all_calls if t > hour_ago]
        self._call_counts["_all"] = all_calls

        return len(all_calls) < self.rate_limit_per_hour

    def record_call(self, tool_name: str) -> None:
        now = time.time()
        if "_all" not in self._call_counts:
            self._call_counts["_all"] = []
        self._call_counts["_all"].append(now)

        if tool_name not in self._call_counts:
            self._call_counts[tool_name] = []
        self._call_counts[tool_name].append(now)

    def check_unauth_limit(self) -> bool:
        now = time.time()
        cutoff = now - UNAUTH_WINDOW_SECONDS
        self._unauth_calls = [t for t in self._unauth_calls if t > cutoff]
        return len(self._unauth_calls) < UNAUTH_DAILY_LIMIT

    def record_unauth_call(self) -> None:
        self._unauth_calls.append(time.time())


@dataclass(frozen=True)
class MCPNetworkAuth:
    auth: Any
    token_verifier: Any


class StaticMCPTokenVerifier:
    def __init__(self, expected_token: str):
        self._expected_token = expected_token

    async def verify_token(self, token: str) -> Any | None:
        if not hmac.compare_digest(token, self._expected_token):
            return None

        from mcp.server.auth.provider import AccessToken

        return AccessToken(
            token=token,
            client_id="skylos-mcp-client",
            scopes=[MCP_AUTH_SCOPE],
        )


_session = AuthSession()


def get_session() -> AuthSession:
    return _session


def _network_auth_base_url(host: str, port: int) -> str:
    public_url = os.getenv("SKYLOS_MCP_PUBLIC_URL", "").strip().rstrip("/")
    if public_url:
        return public_url

    normalized_host = host.strip() or "127.0.0.1"
    if normalized_host in {"0.0.0.0", "::"}:
        normalized_host = "127.0.0.1"
    elif ":" in normalized_host and not normalized_host.startswith("["):
        normalized_host = f"[{normalized_host}]"

    return f"http://{normalized_host}:{port}"


def build_mcp_network_auth(transport: str, *, host: str, port: int) -> MCPNetworkAuth | None:
    if transport not in MCP_NETWORK_TRANSPORTS:
        return None

    token = os.getenv(MCP_CLIENT_TOKEN_ENV, "").strip()
    if not token:
        raise RuntimeError(
            f"{transport} MCP transport requires {MCP_CLIENT_TOKEN_ENV}. "
            "SKYLOS_API_KEY only authenticates this server to Skylos Cloud; "
            "clients must send their own bearer token."
        )
    if len(token) < MCP_CLIENT_TOKEN_MIN_LENGTH:
        raise RuntimeError(
            f"{MCP_CLIENT_TOKEN_ENV} must be at least "
            f"{MCP_CLIENT_TOKEN_MIN_LENGTH} characters."
        )

    from mcp.server.auth.settings import AuthSettings

    base_url = _network_auth_base_url(host, port)
    return MCPNetworkAuth(
        auth=AuthSettings(
            issuer_url=base_url,
            resource_server_url=base_url,
            required_scopes=[MCP_AUTH_SCOPE],
        ),
        token_verifier=StaticMCPTokenVerifier(token),
    )


def check_mcp_client_context(required: bool) -> tuple[bool, str]:
    if not required:
        return (True, "")

    try:
        from mcp.server.auth.middleware.auth_context import get_access_token
    except Exception:
        return (False, "MCP client authentication is required for network transports.")

    access_token = get_access_token()
    if access_token is None or MCP_AUTH_SCOPE not in access_token.scopes:
        return (False, "MCP client authentication is required for network transports.")

    return (True, "")


def _validate_with_cloud(api_key: str) -> dict[str, Any] | None:
    try:
        import requests

        resp = requests.get(
            f"{CLOUD_BASE_URL}/api/sync/whoami",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=NETWORK_TIMEOUT_SHORT,
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception as e:
        logger.warning("Cloud validation failed: %s", e)
        return None


def initialize_auth() -> AuthSession:
    global _session

    api_key = os.getenv("SKYLOS_API_KEY", "").strip()
    if not api_key:
        logger.info("No SKYLOS_API_KEY set — running in local-only mode (limited)")
        _session = AuthSession(authenticated=False)
        return _session

    data = _validate_with_cloud(api_key)
    if data is None:
        logger.warning("API key validation failed — running in local-only mode")
        _session = AuthSession(authenticated=False)
        return _session

    plan = data.get("plan", "free")
    _session = AuthSession(
        authenticated=True,
        api_key=api_key,
        plan=plan,
        credits=data.get("credits", 0),
        org_id=data.get("org_id", ""),
        rate_limit_per_hour=RATE_LIMITS_BY_PLAN.get(plan, 50),
        validated_at=time.time(),
    )

    logger.info(
        "Authenticated: plan=%s, credits=%d, org=%s",
        plan,
        _session.credits,
        _session.org_id,
    )
    return _session


def _refresh_authenticated_session(session: AuthSession) -> bool:
    if not session.authenticated:
        return False

    data = _validate_with_cloud(session.api_key)
    if data is None:
        session.authenticated = False
        session.plan = "free"
        session.credits = 0
        session.org_id = ""
        session.rate_limit_per_hour = RATE_LIMITS_BY_PLAN["free"]
        session.validated_at = 0.0
        return False

    plan = data.get("plan", "free")
    session.plan = plan
    session.credits = data.get("credits", 0)
    session.org_id = data.get("org_id", "")
    session.rate_limit_per_hour = RATE_LIMITS_BY_PLAN.get(plan, 50)
    session.validated_at = time.time()
    return True


def check_tool_access(tool_name: str) -> tuple[bool, str]:
    session = get_session()

    if session.authenticated and not session.is_valid():
        _refresh_authenticated_session(session)

    if not session.authenticated:
        if tool_name not in UNAUTHENTICATED_TOOLS:
            return (
                False,
                f"Tool '{tool_name}' requires authentication. "
                f"Set SKYLOS_API_KEY environment variable. "
                f"Get your key at {CLOUD_BASE_URL}/dashboard/settings",
            )
        if not session.check_unauth_limit():
            return (
                False,
                f"Daily limit reached ({UNAUTH_DAILY_LIMIT} calls/day). "
                f"Set SKYLOS_API_KEY for higher limits.",
            )
        return (True, "")

    if not session.check_rate_limit():
        return (
            False,
            f"Rate limit exceeded ({session.rate_limit_per_hour}/hour). "
            f"Upgrade your plan for higher limits.",
        )

    return (True, "")


def deduct_credits(tool_name: str) -> tuple[bool, str]:
    session = get_session()

    if not session.authenticated:
        session.record_unauth_call()
        return (True, "")

    feature_key = TOOL_CREDIT_MAP.get(tool_name)
    if not feature_key:
        session.record_call(tool_name)
        return (True, "")

    if session.plan == "enterprise":
        session.record_call(tool_name)
        return (True, "")

    try:
        import requests

        resp = requests.post(
            f"{CLOUD_BASE_URL}/api/credits/deduct",
            json={"feature_key": feature_key},
            headers={"Authorization": f"Bearer {session.api_key}"},
            timeout=NETWORK_TIMEOUT_SHORT,
        )

        if resp.status_code == 402:
            data = resp.json()
            return (
                False,
                f"Insufficient credits. Required: {data.get('required', '?')}, "
                f"available: {data.get('available', '?')}. "
                f"Buy credits at {CLOUD_BASE_URL}/dashboard/billing",
            )

        if resp.status_code == 200:
            data = resp.json()
            session.credits = data.get("balance_after", session.credits)
            session.record_call(tool_name)
            return (True, "")

        logger.warning("Credit deduction returned %d — blocking call", resp.status_code)
        return (
            False,
            "Could not verify credit deduction with Skylos Cloud. "
            "Try again or check your connection.",
        )

    except Exception as e:
        logger.warning("Credit deduction failed: %s — blocking call", e)
        return (
            False,
            "Could not verify credit deduction with Skylos Cloud. "
            "Try again or check your connection.",
        )
