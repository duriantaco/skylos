from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("skylos-mcp-auth")

CLOUD_BASE_URL = os.getenv("SKYLOS_CLOUD_URL", "https://skylos.dev")

TOOL_CREDIT_MAP: dict[str, str] = {
    "analyze": "mcp_analyze",
    "security_scan": "mcp_security_scan",
    "quality_check": "mcp_quality_check",
    "secrets_scan": "mcp_secrets_scan",
    "remediate": "mcp_remediate",
}

UNAUTHENTICATED_TOOLS = {"analyze"}

UNAUTH_DAILY_LIMIT = 5
UNAUTH_WINDOW_SECONDS = 86400


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


_session = AuthSession()


def get_session() -> AuthSession:
    return _session


def _validate_with_cloud(api_key: str) -> dict[str, Any] | None:
    try:
        import requests

        resp = requests.get(
            f"{CLOUD_BASE_URL}/api/sync/whoami",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5,
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

    rate_limits = {"free": 50, "pro": 500, "enterprise": 5000}

    _session = AuthSession(
        authenticated=True,
        api_key=api_key,
        plan=plan,
        credits=data.get("credits", 0),
        org_id=data.get("org_id", ""),
        rate_limit_per_hour=rate_limits.get(plan, 50),
        validated_at=time.time(),
    )

    logger.info(
        "Authenticated: plan=%s, credits=%d, org=%s",
        plan,
        _session.credits,
        _session.org_id,
    )
    return _session


def check_tool_access(tool_name: str) -> tuple[bool, str]:
    session = get_session()

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
            timeout=5,
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

        logger.warning("Credit deduction returned %d", resp.status_code)
        session.record_call(tool_name)
        return (True, "")

    except Exception as e:
        logger.warning("Credit deduction failed: %s — allowing call", e)
        session.record_call(tool_name)
        return (True, "")
