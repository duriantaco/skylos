try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
except ImportError:
    raise ImportError(
        "Flask is required for the web server. Install it with: pip install skylos[web]"
    )
import skylos
import json
import os
import webbrowser
import hmac
import ipaddress
import secrets
from pathlib import Path
from threading import Timer
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.server_frontend import render_frontend_html

app = Flask(__name__)


def _get_server_port():
    raw = os.getenv("SKYLOS_PORT", "5090")
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid SKYLOS_PORT: {raw!r}") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid SKYLOS_PORT: {raw!r}")
    return port


def _get_default_cors_origins():
    port = _get_server_port()
    return [f"http://localhost:{port}", f"http://127.0.0.1:{port}"]


_cors_origins = os.getenv("SKYLOS_CORS_ORIGINS")
if _cors_origins:
    origins = [o.strip() for o in _cors_origins.split(",") if o.strip()]
else:
    origins = _get_default_cors_origins()

CORS(
    app,
    origins=origins,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Skylos-Web-Token"],
)


def _is_loopback_addr(addr):
    if not addr:
        return False
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _get_allowed_scan_roots():
    raw = os.getenv("SKYLOS_ALLOWED_ROOTS", "").strip()
    roots = []

    if raw:
        for p in raw.split(","):
            value = p.strip()
            if value:
                roots.append(Path(value).expanduser().resolve())
    else:
        roots.append(Path.cwd().resolve())

    uniq = []
    seen = set()
    for root in roots:
        key = str(root)
        if key not in seen:
            uniq.append(root)
            seen.add(key)
    return uniq


def _is_allowed_scan_path(path_str):
    allowed_roots = app.config.get("ALLOWED_SCAN_ROOTS") or []
    try:
        resolved = Path(path_str).expanduser().resolve()
    except Exception:
        return False, None, allowed_roots

    for root in allowed_roots:
        if resolved == root or root in resolved.parents:
            return True, resolved, allowed_roots
    return False, resolved, allowed_roots


@app.route("/")
def serve_frontend():
    return render_frontend_html(app.config.get("WEB_API_TOKEN", ""))


@app.route("/api/analyze", methods=["POST"])
def analyze_project():
    try:
        if not _is_loopback_addr(request.remote_addr):
            return jsonify({"error": "Local requests only"}), 403

        expected_token = app.config.get("WEB_API_TOKEN", "")
        provided_token = request.headers.get("X-Skylos-Web-Token", "")
        if not expected_token or not hmac.compare_digest(
            provided_token, expected_token
        ):
            return jsonify({"error": "Unauthorized request"}), 401

        data = request.get_json(silent=True) or {}
        path = str(data.get("path", "")).strip()
        try:
            confidence = int(data.get("confidence", 60))
        except (TypeError, ValueError):
            confidence = 60
        confidence = max(0, min(confidence, 100))

        if not path:
            return jsonify({"error": "Path is required"}), 400

        if not os.path.exists(path):
            return jsonify({"error": f"Path does not exist: {path}"}), 400

        allowed, _resolved, roots = _is_allowed_scan_path(path)
        if not allowed:
            roots_hint = ", ".join(str(r) for r in roots)
            return (
                jsonify(
                    {
                        "error": "Path is outside allowed scan roots. "
                        f"Allowed: {roots_hint}. "
                        "Set SKYLOS_ALLOWED_ROOTS to override."
                    }
                ),
                403,
            )

        exclude_folders = app.config.get("EXCLUDE_FOLDERS", DEFAULT_EXCLUDE_FOLDERS)

        result_json = skylos.analyze(
            path, conf=confidence, exclude_folders=exclude_folders
        )
        result = json.loads(result_json)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def start_server(exclude_folders=None):
    if exclude_folders is None:
        exclude_folders = DEFAULT_EXCLUDE_FOLDERS
    port = _get_server_port()
    local_url = f"http://localhost:{port}"
    app.config["EXCLUDE_FOLDERS"] = exclude_folders
    app.config["ALLOWED_SCAN_ROOTS"] = _get_allowed_scan_roots()
    app.config["WEB_API_TOKEN"] = os.getenv("SKYLOS_WEB_TOKEN") or secrets.token_hex(24)

    def open_browser():
        webbrowser.open(local_url)

    print(" Starting Skylos Web Interface...")
    print(f"Opening browser at: {local_url}")

    Timer(1.5, open_browser).start()

    bind_host = os.getenv("SKYLOS_BIND", "127.0.0.1")
    app.run(debug=False, host=bind_host, port=port, use_reloader=False)


if __name__ == "__main__":
    start_server()
