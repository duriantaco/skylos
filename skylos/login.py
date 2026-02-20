import http.server
import os
import socket
import subprocess
import time
import webbrowser
from urllib.parse import parse_qs, urlparse

DEFAULT_BASE_URL = "https://skylos.dev"
CALLBACK_PATH = "/callback"
TIMEOUT_SECONDS = 300


class LoginResult:
    def __init__(self, token, project_id, project_name, org_name, plan):
        self.token = token
        self.project_id = project_id
        self.project_name = project_name
        self.org_name = org_name
        self.plan = plan


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get_repo_name():
    try:
        url = (
            subprocess.check_output(
                ["git", "remote", "get-url", "origin"],
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
        name = url.rstrip("/").split("/")[-1]
        if name.endswith(".git"):
            name = name[:-4]
        return name
    except Exception:
        return None


def _get_repo_url():
    try:
        url = (
            subprocess.check_output(
                ["git", "remote", "get-url", "origin"],
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
        if url.startswith("git@github.com:"):
            url = url.replace("git@github.com:", "https://github.com/")
        if url.endswith(".git"):
            url = url[:-4]
        return url
    except Exception:
        return None


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    result = None

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != CALLBACK_PATH:
            self.send_response(404)
            self.end_headers()
            return

        params = parse_qs(parsed.query)
        token = params.get("token", [None])[0]
        project_id = params.get("project_id", [None])[0]
        project_name = params.get("project_name", [None])[0]
        org_name = params.get("org_name", [None])[0]
        plan = params.get("plan", ["free"])[0]
        error = params.get("error", [None])[0]

        if error:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"<html><body><h2>Login failed: {error}</h2>"
                f"<p>You can close this tab.</p></body></html>".encode()
            )
            _CallbackHandler.result = "error"
            return

        if token and project_id:
            _CallbackHandler.result = LoginResult(
                token=token,
                project_id=project_id,
                project_name=project_name or "Unknown",
                org_name=org_name or "My Workspace",
                plan=plan or "free",
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body style='font-family:system-ui;text-align:center;padding:60px'>"
                b"<h2 style='color:#16a34a'>Connected to Skylos Cloud!</h2>"
                b"<p style='color:#64748b'>You can close this tab and return to your terminal.</p>"
                b"<script>setTimeout(function(){window.close()},2000)</script>"
                b"</body></html>"
            )
        else:
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h2>Missing parameters</h2></body></html>")

    def log_message(self, format, *args):
        pass


def browser_login(console=None, base_url=None):
    base_url = base_url or os.getenv("SKYLOS_API_URL", DEFAULT_BASE_URL).rstrip("/")

    port = _find_free_port()
    repo_name = _get_repo_name() or ""
    repo_url = _get_repo_url() or ""

    _CallbackHandler.result = None

    server = http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
    server.timeout = 5

    connect_url = (
        f"{base_url}/cli/connect?port={port}&repo={repo_name}&repo_url={repo_url}"
    )

    if console:
        console.print("\n[bold]Opening browser to connect to Skylos Cloud...[/bold]")
        console.print(f"[dim]If the browser doesn't open, visit:[/dim]")
        console.print(f"  {connect_url}\n")
    else:
        print("\nOpening browser to connect to Skylos Cloud...")
        print(f"If the browser doesn't open, visit:\n  {connect_url}\n")

    try:
        webbrowser.open(connect_url)
    except Exception:
        if console:
            console.print(
                "[warn]Could not open browser. Visit the URL above manually.[/warn]"
            )
        else:
            print("Could not open browser. Visit the URL above manually.")

    if console:
        console.print(
            "[dim]Waiting for authentication (press Ctrl+C to cancel)...[/dim]"
        )
    else:
        print("Waiting for authentication (press Ctrl+C to cancel)...")

    start_time = time.time()
    try:
        while _CallbackHandler.result is None:
            server.handle_request()
            if time.time() - start_time > TIMEOUT_SECONDS:
                if console:
                    console.print("[warn]Login timed out after 5 minutes.[/warn]")
                else:
                    print("Login timed out after 5 minutes.")
                break
    except KeyboardInterrupt:
        if console:
            console.print("\n[dim]Login cancelled.[/dim]")
        else:
            print("\nLogin cancelled.")
    finally:
        server.server_close()

    result = _CallbackHandler.result
    if result == "error":
        return None
    return result


def manual_token_fallback(console=None):
    if console:
        console.print("\n[bold]Manual connection[/bold]")
        console.print(
            "Get your API key at: [bold]https://skylos.dev/dashboard/settings[/bold]\n"
        )
    else:
        print("\nManual connection")
        print("Get your API key at: https://skylos.dev/dashboard/settings\n")

    try:
        token = input("Paste your API token: ").strip()
    except (KeyboardInterrupt, EOFError):
        if console:
            console.print("\n[dim]Cancelled.[/dim]")
        else:
            print("\nCancelled.")
        return None

    if not token:
        return None

    from skylos.sync import api_get, AuthError

    try:
        info = api_get("/api/sync/whoami", token)
    except AuthError as e:
        if console:
            console.print(f"[bad]Invalid token: {e}[/bad]")
        else:
            print(f"Invalid token: {e}")
        return None

    project = info.get("project", {})
    org = info.get("organization", {})

    return LoginResult(
        token=token,
        project_id=project.get("id", ""),
        project_name=project.get("name", "Unknown"),
        org_name=org.get("name", "My Workspace"),
        plan=info.get("plan", "free"),
    )


def _save_login_result(result, base_url=None):
    from skylos.sync import save_token, _write_link, _find_repo_root

    repo_root = _find_repo_root()

    save_token(
        result.token,
        project_id=result.project_id,
        project_name=result.project_name,
        org_name=result.org_name,
        plan=result.plan,
    )

    _write_link(
        repo_root,
        result.project_id,
        project_name=result.project_name,
        org_name=result.org_name,
        plan=result.plan,
        base_url=base_url or DEFAULT_BASE_URL,
    )


def run_login(console=None, base_url=None):
    from skylos.sync import get_token, api_get, AuthError

    existing = get_token()
    if existing:
        try:
            info = api_get("/api/sync/whoami", existing)
            project = info.get("project", {})
            name = project.get("name", "Unknown")
            if console:
                console.print(f"\n[good]Already connected to: {name}[/good]")
                console.print(
                    "[dim]Run 'skylos sync disconnect' to disconnect first.[/dim]"
                )
            else:
                print(f"\nAlready connected to: {name}")
                print("Run 'skylos sync disconnect' to disconnect first.")
            return LoginResult(
                token=existing,
                project_id=project.get("id", ""),
                project_name=name,
                org_name=info.get("organization", {}).get("name", "My Workspace"),
                plan=info.get("plan", "free"),
            )
        except AuthError:
            pass

    result = None
    try:
        result = browser_login(console=console, base_url=base_url)
    except (OSError, Exception) as e:
        if console:
            console.print(f"[warn]Browser auth unavailable: {e}[/warn]")
        else:
            print(f"Browser auth unavailable: {e}")

    if result is None:
        result = manual_token_fallback(console=console)

    if result is None:
        return None

    _save_login_result(result, base_url=base_url)

    if console:
        console.print(f"\n[good]Connected to Skylos Cloud![/good]")
        console.print(f"  Project:      {result.project_name}")
        console.print(f"  Organization: {result.org_name}")
        console.print(f"  Plan:         {result.plan.capitalize()}")
        console.print(
            f"\n  Run: [bold cyan]skylos . --upload[/bold cyan] to scan and upload"
        )
    else:
        print(f"\nConnected to Skylos Cloud!")
        print(f"  Project:      {result.project_name}")
        print(f"  Organization: {result.org_name}")
        print(f"  Plan:         {result.plan.capitalize()}")
        print(f"\n  Run: skylos . --upload  to scan and upload")

    return result
