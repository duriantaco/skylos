from __future__ import annotations

import json
import secrets
import threading
import time
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from skylos.graph.describe import apply_summaries
from skylos.graph.query import MATCH_NAME, GraphIndex
from skylos.graph.store import CHANGES_FILE, GRAPH_FILE, NOTES_FILE, graph_dir

ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
}
LENS_LIMIT = 40
SECOND_STEP_LIMIT = 24
NOTE_LIMIT = 600
IMPORTANT_LIMIT = 15
AREA_PREVIEW = 12


def _asset(name: str) -> bytes:
    return resources.files("skylos.graph.viewer").joinpath(name).read_bytes()


class GraphState:
    def __init__(self, root: Path):
        self.root = root
        self.lock = threading.Lock()
        self.stamp: tuple = ()
        self.index: GraphIndex | None = None
        self.refresh()

    def _current_stamp(self) -> tuple:
        directory = graph_dir(self.root)
        stamp = []
        for name in (GRAPH_FILE, NOTES_FILE, CHANGES_FILE):
            try:
                stamp.append((directory / name).stat().st_mtime_ns)
            except OSError:
                stamp.append(0)
        return tuple(stamp)

    def refresh(self) -> bool:
        stamp = self._current_stamp()
        with self.lock:
            if stamp == self.stamp and self.index is not None:
                return False
            index = GraphIndex.load(self.root)
            if index is not None:
                self.index = index
            self.stamp = stamp
            return True

    def get(self) -> GraphIndex | None:
        self.refresh()
        return self.index


def _change_rows(index: GraphIndex) -> list[dict]:
    if not index.changes:
        return []
    flagged = set(index.changes.get("flagged") or ())
    rows = []
    for entry in index.changes.get("symbols", ()):
        if entry.get("is_test"):
            continue
        rows.append({
            "node_id": entry.get("node_id"),
            "id": entry["id"],
            "name": entry["name"],
            "file": entry["file"],
            "verdict": entry["verdict"],
            "verdict_text": entry["verdict_text"],
            "same_logic": entry["same_logic"],
            "flagged": entry["id"] in flagged,
            "risk": entry.get("risk", 0),
            "review": entry.get("review") or "read",
            "review_why": entry.get("review_why") or entry["verdict_text"],
            "lines_changed": entry.get("lines_changed", 0),
            "reasons": entry.get("reasons", [])[:3],
            "evidence": entry.get("evidence", [])[:2],
        })
    rows.sort(key=lambda r: (_BUCKET_ORDER.get(r["review"], 1), -r["risk"], r["file"], r["name"]))
    return rows


_BUCKET_ORDER = {"read_first": 0, "read": 1, "skim": 2, "skip": 3}


def _verdicts(index: GraphIndex) -> dict[str, str]:
    found = {}
    for node_id, entry in index.change_by_id.items():
        found[node_id] = entry["verdict"]
    return found


def _neighbours(index: GraphIndex, node_id: str, upward: bool) -> list[tuple[str, str, str]]:
    resolved = index.callees.get(node_id, ())
    named = index.name_callees.get(node_id, ())
    if upward:
        resolved = index.callers.get(node_id, ())
        named = index.name_callers.get(node_id, ())
    found = [(other, kind, "") for other, kind in resolved]
    seen = {other for other, _kind in resolved}
    for other, kind in named:
        if other not in seen:
            seen.add(other)
            found.append((other, kind, MATCH_NAME))
    return found


def _lens(index: GraphIndex, node_id: str, depth: int) -> dict:
    verdicts = _verdicts(index)

    def label(item_id: str, edge: str, match: str = "") -> dict:
        result = dict(index.label(item_id), edge=edge)
        result["verdict"] = verdicts.get(item_id)
        if match:
            result["match"] = match
        return result

    callers = sorted(_neighbours(index, node_id, True), key=lambda c: (index.nodes[c[0]]["is_test"], bool(c[2]), c[0]))
    callees = sorted(_neighbours(index, node_id, False), key=lambda c: (bool(c[2]), c[0]))
    lens = {
        "center": label(node_id, ""),
        "callers": [label(c, k, m) for c, k, m in callers[:LENS_LIMIT]],
        "callers_total": len(callers),
        "callers_tests": sum(1 for c, _k, _m in callers if index.nodes[c]["is_test"]),
        "callers_name": sum(1 for _c, _k, m in callers if m),
        "callees": [label(c, k, m) for c, k, m in callees[:LENS_LIMIT]],
        "callees_total": len(callees),
        "callees_name": sum(1 for _c, _k, m in callees if m),
        "callers2": [],
        "callees2": [],
    }
    if depth > 1:
        shown = {node_id} | {c for c, _k, _m in callers[:LENS_LIMIT]} | {c for c, _k, _m in callees[:LENS_LIMIT]}
        for first, _kind, _match in callers[:LENS_LIMIT]:
            for second, kind, match in _neighbours(index, first, True):
                if second not in shown and len(lens["callers2"]) < SECOND_STEP_LIMIT:
                    shown.add(second)
                    lens["callers2"].append(dict(label(second, kind, match), via=first))
        for first, _kind, _match in callees[:LENS_LIMIT]:
            for second, kind, match in _neighbours(index, first, False):
                if second not in shown and len(lens["callees2"]) < SECOND_STEP_LIMIT:
                    shown.add(second)
                    lens["callees2"].append(dict(label(second, kind, match), via=first))
    return lens


class Handler(BaseHTTPRequestHandler):
    server_version = "SkylosGraph"
    sys_version = ""

    def log_message(self, format, *args):
        return

    @property
    def state(self) -> GraphState:
        return self.server.state

    def _allowed_host(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        port = self.server.server_address[1]
        return host in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _cookie_token(self) -> str:
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie") or "")
        except CookieError:
            return ""
        morsel = jar.get(self.server.cookie_name)
        if morsel is None:
            return ""
        return morsel.value

    def _token_ok(self, query: dict) -> bool:
        expected = self.server.token
        for supplied in (self.headers.get("X-Skylos-Token"), (query.get("token") or [""])[0], self._cookie_token()):
            if supplied and secrets.compare_digest(supplied, expected):
                return True
        return False

    def _send(self, status: int, body: bytes, content_type: str, cookie: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", f"{self.server.cookie_name}={self.server.token}; HttpOnly; SameSite=Strict; Path=/")
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status: int = 200) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message}, status)

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if not self._allowed_host():
            self._error(HTTPStatus.FORBIDDEN, "wrong host")
            return
        if url.path in ASSETS and url.path != "/":
            name, content_type = ASSETS[url.path]
            self._send(200, _asset(name), content_type)
            return
        if not self._token_ok(query):
            self._error(HTTPStatus.FORBIDDEN, "missing or wrong token: open the link printed by skylos open")
            return
        if url.path == "/":
            name, content_type = ASSETS["/"]
            self._send(200, _asset(name), content_type, cookie=True)
            return
        if url.path == "/api/events":
            self._events()
            return
        if url.path == "/api/check":
            self._check_status()
            return
        index = self.state.get()
        if index is None:
            self._error(HTTPStatus.NOT_FOUND, "no graph yet: run skylos graph")
            return
        routes = {
            "/api/overview": self._overview,
            "/api/tree": self._tree,
            "/api/file": self._file,
            "/api/search": self._search,
            "/api/node": self._node,
            "/api/change": self._change,
            "/api/areas": self._areas,
            "/api/area": self._area,
            "/api/pipeline": self._pipeline,
            "/api/diagram": self._diagram,
        }
        handler = routes.get(url.path)
        if handler is None:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        handler(index, query)

    def do_POST(self):
        url = urlparse(self.path)
        if not self._allowed_host() or not self._token_ok({}):
            self._error(HTTPStatus.FORBIDDEN, "forbidden")
            return
        if url.path not in ("/api/note", "/api/check"):
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
            self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "send JSON")
            return
        if url.path == "/api/check":
            self._check_start()
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 8192:
            self._error(HTTPStatus.BAD_REQUEST, "bad body")
            return
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "bad JSON")
            return
        index = self.state.get()
        if not isinstance(body, dict):
            body = {}
        node_id = body.get("id")
        text = body.get("text")
        if index is None or node_id not in index.nodes or not isinstance(text, str):
            self._error(HTTPStatus.BAD_REQUEST, "unknown id or missing text")
            return
        text = text.strip()[:NOTE_LIMIT]
        if len(text) < 3:
            self._error(HTTPStatus.BAD_REQUEST, "write at least a few words")
            return
        apply_summaries(self.state.root, index, {node_id: text}, "human")
        self.state.refresh()
        self._json({"ok": True})

    def _check_status(self):
        runner = self.server.check
        if runner is None:
            self._json({"available": False})
            return
        self._json(dict(runner.status(), available=True))

    def _check_start(self):
        runner = self.server.check
        if runner is None:
            self._error(HTTPStatus.NOT_FOUND, "checks run only from skylos open")
            return
        if not runner.start():
            self._error(HTTPStatus.CONFLICT, "a check is already running")
            return
        self._json(dict(runner.status(), available=True), HTTPStatus.ACCEPTED)

    def _events(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        stamp = self.state.stamp
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while not self.server.stopping.is_set():
                time.sleep(1.0)
                self.state.refresh()
                if self.state.stamp != stamp:
                    stamp = self.state.stamp
                    self.wfile.write(b"event: reload\ndata: {}\n\n")
                else:
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def _overview(self, index: GraphIndex, query: dict):
        changes = None
        if index.changes:
            changes = {
                "base": index.changes.get("base"),
                "base_commit": index.changes.get("base_commit"),
                "counts": index.changes.get("counts", {}),
                "review": index.changes.get("review"),
                "rows": _change_rows(index),
            }
        important = []
        for item in index.ranked(IMPORTANT_LIMIT):
            area = index.area_of(item["id"])
            if area:
                item["area"] = {"id": area["id"], "name": area["name"]}
            important.append(item)
        self._json({
            "overview": index.overview(),
            "entry_points": index.entry_points(),
            "hubs": index.hubs(),
            "important": important,
            "areas": index.areas()[:AREA_PREVIEW],
            "changes": changes,
        })

    def _pipeline(self, index: GraphIndex, query: dict):
        from skylos.graph.pipeline import pipeline

        self._json(pipeline(index.root))

    def _diagram(self, index: GraphIndex, query: dict):
        from skylos.graph.diagram import MEMBER_LIMIT, area_diagram, codebase_diagram

        impact = (query.get("impact") or [""])[0] == "1"
        text = (query.get("area") or [""])[0]
        if not text:
            self._json(codebase_diagram(index, impact=impact))
            return
        limit_text = (query.get("limit") or [""])[0]
        limit = MEMBER_LIMIT
        if limit_text.isdigit():
            limit = int(limit_text)
        found = None
        if text.isdigit():
            found = area_diagram(index, int(text), impact=impact, limit=limit)
        if found is None:
            self._error(HTTPStatus.NOT_FOUND, "unknown area")
            return
        self._json(found)

    def _areas(self, index: GraphIndex, query: dict):
        self._json({"areas": index.areas()})

    def _area(self, index: GraphIndex, query: dict):
        text = (query.get("id") or [""])[0]
        if not text.isdigit():
            self._error(HTTPStatus.NOT_FOUND, "unknown area")
            return
        found = index.area(int(text))
        if found is None:
            self._error(HTTPStatus.NOT_FOUND, "unknown area")
            return
        self._json(found)

    def _tree(self, index: GraphIndex, query: dict):
        changed: dict[str, int] = {}
        for node_id in index.change_by_id:
            node = index.nodes.get(node_id)
            if node:
                changed[node["file"]] = changed.get(node["file"], 0) + 1
        files = []
        for item in index.graph["files"]:
            files.append(dict(item, changed=changed.get(item["file"], 0)))
        self._json({"files": files})

    def _file(self, index: GraphIndex, query: dict):
        path = (query.get("path") or [""])[0]
        verdicts = _verdicts(index)
        symbols = []
        for node in index.graph["nodes"]:
            if node["file"] == path:
                symbols.append({
                    "id": node["id"],
                    "name": node["name"],
                    "kind": node["kind"],
                    "line": node["start"],
                    "described": bool(index.note(node["id"])),
                    "verdict": verdicts.get(node["id"]),
                    "area": index.node_area.get(node["id"]),
                })
        self._json({"file": path, "symbols": symbols})

    def _search(self, index: GraphIndex, query: dict):
        text = (query.get("q") or [""])[0][:200]
        self._json({"results": index.find(text, limit=30, include_tests=True)})

    def _change(self, index: GraphIndex, query: dict):
        change_id = (query.get("id") or [""])[0]
        for entry in (index.changes or {}).get("symbols", ()):
            if entry["id"] == change_id:
                note = index.notes.get("changes", {}).get(entry.get("change_key"))
                self._json({"change": entry, "change_note": note})
                return
        self._error(HTTPStatus.NOT_FOUND, "unknown change")

    def _node(self, index: GraphIndex, query: dict):
        node_id = (query.get("id") or [""])[0]
        if node_id not in index.nodes:
            self._error(HTTPStatus.NOT_FOUND, "unknown id")
            return
        depth = 1
        if (query.get("depth") or ["1"])[0] == "2":
            depth = 2
        card = index.card(node_id)
        card["lens"] = _lens(index, node_id, depth)
        self._json(card)


class GraphServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, root: Path, port: int = 0, check=None):
        super().__init__(("127.0.0.1", port), Handler)
        self.check = check
        self.state = GraphState(root)
        self.token = secrets.token_urlsafe(18)
        self.cookie_name = f"skylos_graph_{self.server_address[1]}"
        self.stopping = threading.Event()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/?token={self.token}"

    def shutdown(self):
        self.stopping.set()
        if self.check is not None:
            self.check.stop()
        super().shutdown()
