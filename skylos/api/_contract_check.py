"""Tell the user when Skylos Cloud speaks a newer upload contract.

``GET /api/report/contract`` returns ``{"version": N, "sha256": "..."}``. The
check runs in a background thread while the upload is in progress, uses a
short timeout, runs at most once per process and stays silent on any error.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Callable

from skylos.api._upload_contract import contract_version

logger = logging.getLogger(__name__)

__all__ = [
    "contract_check_url",
    "newer_contract_notice",
    "reset_contract_check",
    "start_contract_version_check",
]

CHECK_ENV = "SKYLOS_UPLOAD_CONTRACT_CHECK"
REQUEST_TIMEOUT = (1.5, 2.0)
JOIN_TIMEOUT_SECONDS = 0.5

_lock = threading.Lock()
_state: dict[str, Any] = {"thread": None, "remote_version": None, "reported": False}


def reset_contract_check() -> None:
    with _lock:
        _state.update(thread=None, remote_version=None, reported=False)


def contract_check_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/api"):
        return f"{base}/report/contract"
    return f"{base}/api/report/contract"


def _enabled() -> bool:
    return os.getenv(CHECK_ENV, "1").strip().lower() not in {"0", "false", "no", "off"}


def _fetch(url: str, http_get: Callable[..., Any]) -> None:
    try:
        response = http_get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        if getattr(response, "status_code", None) != 200:
            return
        data = response.json()
        version = data.get("version") if isinstance(data, dict) else None
        if isinstance(version, int) and not isinstance(version, bool):
            with _lock:
                _state["remote_version"] = version
    except Exception as exc:  # never let the check affect an upload
        logger.debug("Upload contract check failed: %s", exc)


def start_contract_version_check(
    url: str, http_get: Callable[..., Any], *, validate: Callable[[str], str]
) -> None:
    if not _enabled():
        return
    with _lock:
        if _state["thread"] is not None:
            return
        try:
            safe_url = validate(url)
        except ValueError:
            _state["thread"] = False
            return
        thread = threading.Thread(
            target=_fetch,
            args=(safe_url, http_get),
            name="skylos-contract-check",
            daemon=True,
        )
        _state["thread"] = thread
    thread.start()


def newer_contract_notice(join_timeout: float = JOIN_TIMEOUT_SECONDS) -> str | None:
    """One line to print if the server's contract is newer; at most once."""
    thread = _state.get("thread")
    if not thread:
        return None
    thread.join(timeout=max(join_timeout, 0))
    with _lock:
        remote = _state.get("remote_version")
        if _state["reported"] or not isinstance(remote, int):
            return None
        local = contract_version()
        if remote <= local:
            return None
        _state["reported"] = True
    return (
        f"Skylos Cloud uses upload format v{remote}; this CLI sends v{local}. "
        "Run 'pip install -U skylos' to update."
    )
