from __future__ import annotations

import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit, urlparse

from skylos.agents.center import (
    clear_action_triage,
    command_center_payload,
    load_agent_state,
    refresh_agent_state,
    resolve_project_root,
    resolve_state_path,
    update_action_triage,
)


def _error_payload(message: str) -> dict[str, str]:
    return {"error": message}


def _format_origin_host(host: str) -> str:
    host = str(host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        return host
    if ":" in host:
        return f"[{host}]"
    return host


def _origin_for_host(host: str, port: int) -> str | None:
    formatted = _format_origin_host(host)
    if not formatted:
        return None
    return f"http://{formatted}:{port}"


def _normalize_origin(origin: str) -> str | None:
    origin = str(origin or "").strip()
    if not origin:
        return None

    parsed = urlsplit(origin)
    if not parsed.scheme or not parsed.netloc or parsed.username or parsed.password:
        return None
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return None

    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _default_allowed_origins(host: str, port: int) -> frozenset[str]:
    host = str(host or "").strip()
    if host in {"", "0.0.0.0", "::", "::0"}:
        origin_hosts = ("127.0.0.1", "localhost", "::1")
    elif host in {"127.0.0.1", "localhost"}:
        origin_hosts = ("127.0.0.1", "localhost")
    elif host in {"::1", "[::1]"}:
        origin_hosts = ("::1", "localhost")
    else:
        origin_hosts = (host,)

    origins = {
        normalized
        for origin_host in origin_hosts
        if (origin := _origin_for_host(origin_host, port))
        if (normalized := _normalize_origin(origin))
    }
    return frozenset(origins)


def _normalize_allowed_origins(origins: list[str]) -> frozenset[str]:
    return frozenset(
        normalized
        for origin in origins
        if (normalized := _normalize_origin(origin)) is not None
    )


class AgentServiceController:
    def __init__(
        self,
        path: str,
        *,
        state_file: str | None = None,
        conf: int = 80,
        use_baseline: bool = True,
        default_limit: int = 10,
        refresh_on_start: bool = False,
    ) -> None:
        self.project_root = resolve_project_root(path)
        self.state_file = state_file
        self.conf = conf
        self.use_baseline = use_baseline
        self.default_limit = default_limit
        self._lock = threading.RLock()

        if refresh_on_start:
            self.refresh(force=True)

    @property
    def state_path(self) -> str:
        return str(resolve_state_path(self.project_root, self.state_file))

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "project_root": str(self.project_root),
            "state_file": self.state_path,
            "has_state": self.load_state() is not None,
        }

    def load_state(self) -> dict[str, Any] | None:
        with self._lock:
            return load_agent_state(self.project_root, state_file=self.state_file)

    def refresh(self, *, force: bool) -> dict[str, Any]:
        with self._lock:
            state, _updated = refresh_agent_state(
                self.project_root,
                conf=self.conf,
                use_baseline=self.use_baseline,
                state_file=self.state_file,
                force=force,
            )
        return state

    def get_state(self, *, refresh: bool = False) -> dict[str, Any]:
        if refresh:
            return self.refresh(force=True)

        state = self.load_state()
        if state is not None:
            return state
        return self.refresh(force=True)

    def get_command_center(
        self,
        *,
        refresh: bool = False,
        limit: int | None = None,
    ) -> dict[str, Any]:
        state = self.get_state(refresh=refresh)
        payload = command_center_payload(
            state,
            limit=limit if limit is not None else self.default_limit,
        )
        payload["project_root"] = str(self.project_root)
        payload["state_file"] = self.state_path
        payload["triaged_count"] = len(state.get("triage") or {})
        return payload

    def dismiss(self, action_id: str) -> dict[str, Any]:
        with self._lock:
            return update_action_triage(
                self.project_root,
                action_id,
                status="dismissed",
                state_file=self.state_file,
            )

    def snooze(self, action_id: str, *, hours: float) -> dict[str, Any]:
        with self._lock:
            return update_action_triage(
                self.project_root,
                action_id,
                status="snoozed",
                state_file=self.state_file,
                snooze_hours=hours,
            )

    def restore(self, action_id: str) -> dict[str, Any]:
        with self._lock:
            return clear_action_triage(
                self.project_root,
                action_id,
                state_file=self.state_file,
            )

    def learn_triage(self, action_id: str, action: str) -> dict[str, Any]:
        from skylos.agents.triage_learner import TriageLearner

        state = self.get_state()
        findings = state.get("findings", [])
        finding = next(
            (f for f in findings if f.get("fingerprint") == action_id),
            None,
        )
        if finding is None:
            return _error_payload(f"Finding not found: {action_id}")

        learner = TriageLearner()
        learner.load(str(self.project_root))
        updated = learner.learn_from_triage(finding, action)
        learner.save(str(self.project_root))

        return {
            "ok": True,
            "patterns_updated": len(updated),
            "total_patterns": learner.pattern_count,
        }

    def get_suggestions(self) -> dict[str, Any]:
        """Get auto-triage candidates from learned patterns."""
        from skylos.agents.triage_learner import TriageLearner

        state = self.get_state()
        findings = state.get("findings", [])

        learner = TriageLearner()
        learner.load(str(self.project_root))
        candidates = learner.get_auto_triage_candidates(findings)

        return {
            "candidates": [
                {
                    "fingerprint": f.get("fingerprint", ""),
                    "message": f.get("message", ""),
                    "file": f.get("file", ""),
                    "line": f.get("line", 0),
                    "action": action,
                    "confidence": confidence,
                }
                for f, action, confidence in candidates
            ],
            "total_patterns": learner.pattern_count,
        }


def _resolve_refresh_query(query: str) -> bool:
    params = parse_qs(query or "", keep_blank_values=False)
    return params.get("refresh", ["0"])[0] in {"1", "true", "yes"}


def _resolve_limit_query(query: str, default: int) -> int:
    params = parse_qs(query or "", keep_blank_values=False)
    raw = params.get("limit", [str(default)])[0]
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(1, min(value, 100))


def _dispatch_get_request(
    *,
    controller: AgentServiceController,
    path: str,
    query: str,
    default_limit: int,
) -> tuple[HTTPStatus, dict[str, Any]]:
    if path == "/health":
        return HTTPStatus.OK, controller.health()
    if path == "/state":
        return HTTPStatus.OK, controller.get_state(
            refresh=_resolve_refresh_query(query)
        )
    if path == "/command-center":
        payload = controller.get_command_center(
            refresh=_resolve_refresh_query(query),
            limit=_resolve_limit_query(query, default_limit),
        )
        return HTTPStatus.OK, payload
    if path == "/suggestions":
        return HTTPStatus.OK, controller.get_suggestions()
    return HTTPStatus.NOT_FOUND, _error_payload("Not found")


def _dispatch_post_request(
    *,
    controller: AgentServiceController,
    path: str,
    body: dict[str, Any],
    require_action_id: Callable[[dict[str, Any]], str],
) -> tuple[HTTPStatus, dict[str, Any]]:
    if path == "/refresh":
        return HTTPStatus.OK, controller.refresh(force=True)
    if path == "/triage/dismiss":
        return HTTPStatus.OK, controller.dismiss(require_action_id(body))
    if path == "/triage/snooze":
        action_id = require_action_id(body)
        hours = float(body.get("hours", 24))
        return HTTPStatus.OK, controller.snooze(action_id, hours=hours)
    if path == "/triage/restore":
        return HTTPStatus.OK, controller.restore(require_action_id(body))
    if path == "/learn":
        action_id = require_action_id(body)
        action = str(body.get("action", "dismiss"))
        return HTTPStatus.OK, controller.learn_triage(action_id, action)
    return HTTPStatus.NOT_FOUND, _error_payload("Not found")


class AgentServiceHandler(BaseHTTPRequestHandler):
    server_version = "SkylosAgentService/0.1"
    controller: AgentServiceController
    token: str | None = None
    default_limit: int = 10
    allowed_origins: frozenset[str] = frozenset()

    def do_OPTIONS(self) -> None:
        if not self._origin_is_allowed():
            self._send_json(
                HTTPStatus.FORBIDDEN,
                _error_payload("Origin is not allowed"),
            )
            return

        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        if not self._origin_is_allowed():
            self._send_json(
                HTTPStatus.FORBIDDEN,
                _error_payload("Origin is not allowed"),
            )
            return

        if not self._is_authorized():
            return

        parsed = urlparse(self.path)
        status, payload = _dispatch_get_request(
            controller=self.controller,
            path=parsed.path,
            query=parsed.query,
            default_limit=self.default_limit,
        )
        self._send_json(status, payload)

    def do_POST(self) -> None:
        if not self._origin_is_allowed():
            self._send_json(
                HTTPStatus.FORBIDDEN,
                _error_payload("Origin is not allowed"),
            )
            return

        if not self._is_authorized():
            return

        parsed = urlparse(self.path)
        body = self._read_json_body()
        status, payload = _dispatch_post_request(
            controller=self.controller,
            path=parsed.path,
            body=body,
            require_action_id=self._require_action_id,
        )
        self._send_json(status, payload)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _is_authorized(self) -> bool:
        if not self.token:
            return True
        header = self.headers.get("X-Skylos-Agent-Token", "")
        if header == self.token:
            return True
        self._send_json(HTTPStatus.UNAUTHORIZED, _error_payload("Unauthorized"))
        return False

    def _origin_is_allowed(self) -> bool:
        raw_origin = self.headers.get("Origin", "")
        if not raw_origin:
            return True
        origin = _normalize_origin(raw_origin)
        if origin is None:
            return False
        return origin in self.allowed_origins

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(HTTPStatus.BAD_REQUEST, _error_payload("Invalid JSON body"))
            raise _HandledRequestError()
        if not isinstance(payload, dict):
            self._send_json(
                HTTPStatus.BAD_REQUEST, _error_payload("JSON body must be an object")
            )
            raise _HandledRequestError()
        return payload

    def _require_action_id(self, body: dict[str, Any]) -> str:
        action_id = str(body.get("action_id") or "").strip()
        if action_id:
            return action_id
        self._send_json(HTTPStatus.BAD_REQUEST, _error_payload("action_id is required"))
        raise _HandledRequestError()

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_cors_headers(self) -> None:
        raw_origin = self.headers.get("Origin", "")
        if not raw_origin:
            return

        self.send_header("Vary", "Origin")
        origin = _normalize_origin(raw_origin)
        if origin in self.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header(
                "Access-Control-Allow-Headers",
                "Content-Type, X-Skylos-Agent-Token",
            )
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")


class SafeAgentServiceHandler(AgentServiceHandler):
    def do_GET(self) -> None:
        try:
            super().do_GET()
        except _HandledRequestError:
            return
        except Exception as exc:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, _error_payload(str(exc)))

    def do_POST(self) -> None:
        try:
            super().do_POST()
        except _HandledRequestError:
            return
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, _error_payload(str(exc)))
        except Exception as exc:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, _error_payload(str(exc)))


def _bind_agent_service_handler(
    controller: AgentServiceController,
    *,
    token: str | None,
    default_limit: int,
    allowed_origins: frozenset[str],
) -> type[SafeAgentServiceHandler]:
    return type(
        "BoundAgentServiceHandler",
        (SafeAgentServiceHandler,),
        {
            "controller": controller,
            "token": token,
            "default_limit": default_limit,
            "allowed_origins": allowed_origins,
        },
    )


def create_agent_service(
    path: str,
    *,
    host: str = "127.0.0.1",
    port: int = 5089,
    token: str | None = None,
    state_file: str | None = None,
    conf: int = 80,
    use_baseline: bool = True,
    default_limit: int = 10,
    refresh_on_start: bool = False,
    allowed_origins: list[str] | None = None,
) -> ThreadingHTTPServer:
    controller = AgentServiceController(
        path,
        state_file=state_file,
        conf=conf,
        use_baseline=use_baseline,
        default_limit=default_limit,
        refresh_on_start=refresh_on_start,
    )
    server = ThreadingHTTPServer((host, port), SafeAgentServiceHandler)
    actual_host = str(server.server_address[0])
    actual_port = int(server.server_address[1])
    if allowed_origins is not None:
        normalized_allowed_origins = _normalize_allowed_origins(allowed_origins)
    else:
        default_origins = set(_default_allowed_origins(host, actual_port))
        default_origins.update(_default_allowed_origins(actual_host, actual_port))
        normalized_allowed_origins = frozenset(default_origins)
    handler_class = _bind_agent_service_handler(
        controller,
        token=token,
        default_limit=default_limit,
        allowed_origins=normalized_allowed_origins,
    )
    server.RequestHandlerClass = handler_class
    server.controller = controller  # type: ignore[attr-defined]
    return server


def serve_agent_service(
    path: str,
    *,
    host: str = "127.0.0.1",
    port: int = 5089,
    token: str | None = None,
    state_file: str | None = None,
    conf: int = 80,
    use_baseline: bool = True,
    default_limit: int = 10,
    refresh_on_start: bool = False,
    allowed_origins: list[str] | None = None,
) -> ThreadingHTTPServer:
    server = create_agent_service(
        path,
        host=host,
        port=port,
        token=token,
        state_file=state_file,
        conf=conf,
        use_baseline=use_baseline,
        default_limit=default_limit,
        refresh_on_start=refresh_on_start,
        allowed_origins=allowed_origins,
    )
    server.serve_forever()
    return server


class _HandledRequestError(Exception):
    pass
