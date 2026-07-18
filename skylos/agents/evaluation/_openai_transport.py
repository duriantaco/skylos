from __future__ import annotations

import socket
import threading
import time
from contextvars import ContextVar
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3 import HTTPConnectionPool, HTTPSConnectionPool, PoolManager
from urllib3.connection import HTTPConnection, HTTPSConnection


_REQUEST_DEADLINE: ContextVar[float | None] = ContextVar(
    "agent_request_deadline",
    default=None,
)


class AgentEndpointError(RuntimeError):
    """Raised when live agent evidence cannot be obtained safely."""


class _AbsoluteDeadlineExpired(TimeoutError):
    pass


class _AbsoluteDeadlineConnectionMixin:
    def connect(self) -> None:
        parent_connect = super().connect
        parent_connect()
        deadline = _REQUEST_DEADLINE.get()
        if deadline is not None and time.monotonic() >= deadline:
            _shutdown_connection_socket(self)
            raise _AbsoluteDeadlineExpired("agent request deadline expired")

    def request(self, *args: Any, **kwargs: Any) -> None:
        parent_request = super().request
        self._run_with_absolute_deadline(lambda: parent_request(*args, **kwargs))

    def getresponse(self) -> Any:
        parent_getresponse = super().getresponse
        return self._run_with_absolute_deadline(parent_getresponse)

    def _run_with_absolute_deadline(self, operation: Any) -> Any:
        deadline = _REQUEST_DEADLINE.get()
        if deadline is None:
            return operation()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _shutdown_connection_socket(self)
            raise _AbsoluteDeadlineExpired("agent request deadline expired")

        expired = threading.Event()
        timer = threading.Timer(
            remaining,
            _expire_connection,
            args=(self, expired),
        )
        timer.daemon = True
        timer.start()
        try:
            result = operation()
        except Exception as exc:
            if expired.is_set() or time.monotonic() >= deadline:
                raise _AbsoluteDeadlineExpired(
                    "agent request deadline expired"
                ) from exc
            raise
        finally:
            timer.cancel()

        if expired.is_set() or time.monotonic() >= deadline:
            close = getattr(result, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
            _shutdown_connection_socket(self)
            raise _AbsoluteDeadlineExpired("agent request deadline expired")
        return result


class _DeadlineHTTPConnection(_AbsoluteDeadlineConnectionMixin, HTTPConnection):
    pass


class _DeadlineHTTPSConnection(_AbsoluteDeadlineConnectionMixin, HTTPSConnection):
    pass


class _DeadlineHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _DeadlineHTTPConnection


class _DeadlineHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _DeadlineHTTPSConnection


class _DeadlinePoolManager(PoolManager):
    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = {
            "http": _DeadlineHTTPConnectionPool,
            "https": _DeadlineHTTPSConnectionPool,
        }


class _DeadlineHTTPAdapter(HTTPAdapter):
    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs: Any,
    ) -> None:
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = _DeadlinePoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


def new_agent_session() -> requests.Session:
    client = requests.Session()
    client.trust_env = False
    client.mount("http://", _DeadlineHTTPAdapter())
    client.mount("https://", _DeadlineHTTPAdapter())
    return client


def post_owned_session_with_deadline(
    client: requests.Session,
    endpoint: str,
    *,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: float,
    deadline: float,
) -> Any:
    completed = threading.Event()
    cancelled = threading.Event()
    outcome_lock = threading.Lock()
    outcome: dict[str, Any] = {}

    def dispatch() -> None:
        if cancelled.is_set() or time.monotonic() >= deadline:
            with outcome_lock:
                outcome["error"] = _AbsoluteDeadlineExpired(
                    "agent request deadline expired"
                )
            completed.set()
            return
        try:
            candidate = send_agent_request(
                client,
                endpoint,
                payload=payload,
                headers=headers,
                timeout=timeout,
                deadline=deadline,
            )
            with outcome_lock:
                request_cancelled = cancelled.is_set() or time.monotonic() >= deadline
                if request_cancelled:
                    outcome["error"] = _AbsoluteDeadlineExpired(
                        "agent request deadline expired"
                    )
                else:
                    outcome["response"] = candidate
            if request_cancelled:
                try:
                    candidate.close()
                except Exception:
                    pass
        except Exception as exc:
            with outcome_lock:
                outcome["error"] = exc
        finally:
            completed.set()

    worker = threading.Thread(
        target=dispatch,
        name="skylos-agent-http",
        daemon=True,
    )
    worker.start()
    remaining = max(0.0, deadline - time.monotonic())
    if not completed.wait(remaining):
        with outcome_lock:
            cancelled.set()
            late_response = outcome.pop("response", None)
        if late_response is not None:
            try:
                late_response.close()
            except Exception:
                pass
        client.close()
        raise AgentEndpointError("agent endpoint exceeded request deadline")
    error = outcome.get("error")
    if error is not None:
        raise error
    response = outcome.get("response")
    if response is None:
        raise AgentEndpointError("agent endpoint request produced no response")
    return response


def send_agent_request(
    client: Any,
    endpoint: str,
    *,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: float,
    deadline: float,
) -> Any:
    deadline_token = _REQUEST_DEADLINE.set(deadline)
    try:
        return client.post(  # skylos: ignore[SKY-D216] caller validates endpoint scheme, credentials, redirects, and remote opt-in
            endpoint,
            json=payload,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
    finally:
        _REQUEST_DEADLINE.reset(deadline_token)


def _expire_connection(connection: Any, expired: threading.Event) -> None:
    expired.set()
    _shutdown_connection_socket(connection)


def _shutdown_connection_socket(connection: Any) -> None:
    active_socket = getattr(connection, "sock", None)
    if active_socket is None:
        return
    try:
        active_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        active_socket.close()
    except OSError:
        pass
