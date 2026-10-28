import os
import sys
import json
import argparse
import stat
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import subprocess
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlparse
from skylos.ui.paths import shown_path
from skylos.cloud.plan_names import (
    PAID_PLAN_NAME,
    PRICING_URL,
    plan_display_name,
)
from skylos.cloud.sync_setup import (
    build_pre_push_hook as _sync_setup_build_pre_push_hook,
    collect_setup_choices as _collect_setup_choices,
    create_precommit_config as create_precommit_config,
    install_pre_push_hook as _install_pre_push_hook,
    install_selected_setup_features as _install_selected_setup_features,
    print_free_plan_setup_summary as _print_free_plan_setup_summary,
    print_setup_next_steps as _print_setup_next_steps,
    write_cloud_workflow as _write_cloud_workflow,
)

try:
    import requests
    import yaml
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install requests pyyaml")
    sys.exit(1)


SKYLOS_DIR = ".skylos"
CONFIG_FILE = "config.yaml"
SUPPRESSIONS_FILE = "suppressions.json"
NO_REMOTE_MESSAGE = (
    "skylos sync pull needs a git repository with a remote, because reviewed "
    "findings are tied to the repository's remote URL. Add one with: "
    "git remote add origin <url>"
)
DEFAULT_API_URL = "https://skylos.dev"
WHOAMI_ENDPOINT = "/api/sync/whoami"
UNKNOWN_LABEL = "Unknown"
CANCELLED_MESSAGE = "\nCancelled."
PRO_PLANS = {"pro", "enterprise", "beta"}

GLOBAL_CREDS_DIR = Path.home() / ".skylos"
GLOBAL_CREDS_FILE = GLOBAL_CREDS_DIR / "credentials.json"


LINK_FILE = "link.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_creds() -> dict[str, Any]:
    if not GLOBAL_CREDS_FILE.exists():
        return {}
    try:
        return json.loads(GLOBAL_CREDS_FILE.read_text() or "{}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _write_creds(data: dict[str, Any]) -> None:
    GLOBAL_CREDS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(GLOBAL_CREDS_DIR, 0o700)
    except OSError:
        pass

    payload = json.dumps(data, indent=2)
    fd = os.open(
        GLOBAL_CREDS_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
    finally:
        try:
            os.chmod(GLOBAL_CREDS_FILE, 0o600)
        except OSError:
            pass


def _find_repo_root() -> Path:
    from skylos.core.git_safety import (
        read_only_git_command,
        read_only_git_environment,
    )

    try:
        out = (
            subprocess.check_output(
                read_only_git_command(["rev-parse", "--show-toplevel"]),
                stderr=subprocess.DEVNULL,
                env=read_only_git_environment(),
            )
            .decode()
            .strip()
        )
        if out:
            return Path(out)
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
        pass
    return Path.cwd()


def _linked_project_id(repo_root: Path) -> str | None:
    data = _read_link(repo_root)
    if not data:
        return None
    repo_subpath = _current_repo_subpath(repo_root)
    subpath_entry = _project_entry_for_subpath(data, repo_subpath)
    project_id = subpath_entry.get("project_id") or data.get("project_id")
    if project_id:
        return str(project_id).strip()
    return None


def _read_link(repo_root: Path) -> dict[str, Any]:
    try:
        p = _ensure_safe_link_path(repo_root, create_dir=False)
    except AuthError:
        return {}
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text() or "{}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _normalize_repo_subpath_value(value: Any) -> str:
    try:
        from skylos.cloud.project_context import normalize_repo_subpath

        normalized = normalize_repo_subpath(value)
        return normalized or ""
    except (ImportError, OSError, ValueError):
        return str(value or "").strip("/")


def _current_repo_subpath(repo_root: Path) -> str:
    try:
        from skylos.cloud.project_context import repo_subpath_for_project

        return repo_subpath_for_project(Path.cwd(), repo_root)
    except (ImportError, OSError, ValueError):
        return ""


def _project_entry_for_subpath(link: dict[str, Any], repo_subpath: str) -> dict:
    projects = link.get("projects")
    if isinstance(projects, dict):
        entry = projects.get(repo_subpath)
        if isinstance(entry, dict):
            return entry
    return {}


def _ensure_safe_link_path(repo_root: Path, *, create_dir: bool = False) -> Path:
    repo_root = Path(repo_root)
    try:
        resolved_repo = repo_root.resolve(strict=True)
    except OSError as exc:
        raise AuthError(f"Repository root is not accessible: {repo_root}") from exc

    skylos_dir = resolved_repo / SKYLOS_DIR
    try:
        dir_stat = skylos_dir.lstat()
    except FileNotFoundError:
        if not create_dir:
            return skylos_dir / LINK_FILE
        skylos_dir.mkdir(  # skylos: ignore[SKY-D215] fixed child under resolved repo root
            parents=True,
            exist_ok=False,
        )
        dir_stat = skylos_dir.lstat()

    if stat.S_ISLNK(dir_stat.st_mode):
        raise AuthError(f"Refusing to use symlinked Skylos directory: {skylos_dir}")
    if not stat.S_ISDIR(dir_stat.st_mode):
        raise AuthError(f"Skylos path is not a directory: {skylos_dir}")

    try:
        resolved_skylos_dir = skylos_dir.resolve(strict=True)
        resolved_skylos_dir.relative_to(resolved_repo)
    except (OSError, ValueError) as exc:
        raise AuthError(
            f"Skylos directory must stay inside the repository: {skylos_dir}"
        ) from exc

    link_path = skylos_dir / LINK_FILE
    try:
        link_stat = link_path.lstat()
    except FileNotFoundError:
        return link_path

    if stat.S_ISLNK(link_stat.st_mode):
        raise AuthError(f"Refusing to use symlinked Skylos link file: {link_path}")
    if not stat.S_ISREG(link_stat.st_mode):
        raise AuthError(f"Skylos link path is not a regular file: {link_path}")

    try:
        link_path.resolve(strict=True).relative_to(resolved_skylos_dir)
    except (OSError, ValueError) as exc:
        raise AuthError(f"Skylos link file must stay inside {skylos_dir}") from exc

    return link_path


def _atomic_write_text(path: Path, content: str) -> None:
    tmp_path = None
    fd = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{LINK_FILE}.",
            suffix=".tmp",
            dir=str(path.parent),
            text=True,
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass


def _write_link(
    repo_root: Path,
    project_id,
    project_name=None,
    org_name=None,
    plan=None,
    repo_subpath=None,
    *,
    base_url=None,
):
    link_path = _ensure_safe_link_path(repo_root, create_dir=True)
    existing = _read_link(repo_root)
    normalized_subpath = _normalize_repo_subpath_value(repo_subpath)
    payload = {
        "project_id": str(project_id),
        "linked_at": _utc_now_iso(),
        "repo_subpath": normalized_subpath,
    }
    if base_url:
        payload["base_url"] = str(base_url).rstrip("/")
    if project_name:
        payload["project_name"] = project_name
    if org_name:
        payload["org_name"] = org_name
    if plan:
        payload["plan"] = str(plan).lower()
    if isinstance(existing, dict):
        projects = existing.get("projects")
    else:
        projects = {}
    if not isinstance(projects, dict):
        projects = {}
    project_plan = None
    if plan:
        project_plan = str(plan).lower()
    projects[normalized_subpath] = {
        "project_id": str(project_id),
        "project_name": project_name,
        "org_name": org_name,
        "plan": project_plan,
        "repo_subpath": normalized_subpath,
        "linked_at": payload["linked_at"],
    }
    payload["projects"] = projects
    _atomic_write_text(link_path, json.dumps(payload, indent=2))
    return str(link_path)


def _delete_link(repo_root: Path) -> str | None:
    try:
        p = _ensure_safe_link_path(repo_root, create_dir=False)
    except AuthError:
        return None
    if not p.exists():
        return None
    p.unlink()
    return str(p)


def get_api_url() -> str:
    return _normalize_api_base_url(os.environ.get("SKYLOS_API_URL", DEFAULT_API_URL))


def _normalize_api_base_url(base_url: str) -> str:
    normalized = (base_url or DEFAULT_API_URL).strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"}:
        raise AuthError("SKYLOS_API_URL must use HTTP or HTTPS")
    if not parsed.netloc:
        raise AuthError("SKYLOS_API_URL must include a host")
    if parsed.username or parsed.password:
        raise AuthError("SKYLOS_API_URL must not include credentials")
    if parsed.fragment:
        raise AuthError("SKYLOS_API_URL must not include a fragment")
    return normalized


def _normalize_api_endpoint(endpoint: str) -> str:
    if not isinstance(endpoint, str):
        raise AuthError("API endpoint must be a string")
    parsed = urlparse(endpoint)
    if parsed.scheme or parsed.netloc:
        raise AuthError("API endpoint must be relative")
    if not endpoint.startswith("/") or endpoint.startswith("//"):
        raise AuthError("API endpoint must start with a single slash")
    if "\\" in endpoint or any(part == ".." for part in parsed.path.split("/")):
        raise AuthError("API endpoint contains an unsafe path segment")
    return endpoint


def _safe_sync_url(endpoint: str) -> str:
    return f"{get_api_url()}{_normalize_api_endpoint(endpoint)}"


def _try_ci_oidc_token() -> str | None:
    try:
        from skylos.api import _try_github_oidc_token, _try_gitlab_oidc_token
    except ImportError:
        return None

    try:
        token = _try_github_oidc_token() or _try_gitlab_oidc_token()
    except (OSError, RuntimeError, ValueError):
        return None
    if isinstance(token, str):
        return token
    return None


def get_token() -> str | None:
    env_token = os.environ.get("SKYLOS_TOKEN", "").strip()
    if env_token:
        return env_token

    oidc_token = _try_ci_oidc_token()
    if oidc_token:
        return oidc_token

    repo_root = _find_repo_root()
    linked_pid = _linked_project_id(repo_root)

    data = _load_creds()

    tokens = data.get("tokens") or {}
    if linked_pid and linked_pid in tokens:
        t = (tokens.get(linked_pid) or {}).get("token")
        if t:
            return t

    t = data.get("token")
    if t:
        return t

    return None


def save_token(
    token: str,
    project_id: str | None = None,
    project_name: str | None = None,
    org_name: str | None = None,
    plan: str | None = None,
    repo_subpath: str | None = None,
) -> str:
    data = _load_creds()
    now = _utc_now_iso()

    data["token"] = token
    data["saved_at"] = now
    data["plan"] = (plan or data.get("plan") or "free").lower()
    for key, value in (
        ("project_id", project_id),
        ("project_name", project_name),
        ("org_name", org_name),
    ):
        if value:
            data[key] = str(value)
        else:
            data.pop(key, None)

    if project_id:
        tokens = data.get("tokens") or {}
        pid = str(project_id)

        tokens[pid] = {
            "token": token,
            "saved_at": now,
            "plan": (plan or "free").lower(),
        }
        if project_name:
            tokens[pid]["project_name"] = project_name
        if org_name:
            tokens[pid]["org_name"] = org_name
        if repo_subpath is not None:
            tokens[pid]["repo_subpath"] = _normalize_repo_subpath_value(repo_subpath)

        data["tokens"] = tokens

    _write_creds(data)
    return str(GLOBAL_CREDS_FILE)


def clear_token() -> bool:
    if GLOBAL_CREDS_FILE.exists():
        GLOBAL_CREDS_FILE.unlink()
        return True
    return False


def mask_token(token: str | None) -> str:
    if isinstance(token, str) and token.startswith("gitlab_oidc:"):
        return "<GitLab job ID token>"
    if not token or len(token) <= 12:
        return "****"
    return token[:8] + "..." + token[-4:]


class AuthError(Exception):
    pass


def _cloud_reason(resp) -> str:
    """Cloud's own explanation for a refused request, or "" if it gave none.

    Only the structured ``error``/``hint``/``code`` fields are used, never the
    raw body, and control characters are dropped: this text can end up in a
    public CI log.
    """
    try:
        body = resp.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    parts = [
        body[key].strip()
        for key in ("error", "hint")
        if isinstance(body.get(key), str) and body[key].strip()
    ]
    code = body.get("code")
    if parts and isinstance(code, str) and code.strip():
        parts.append(f"({code.strip()})")
    text = "".join(ch for ch in " ".join(parts) if ch.isprintable())
    return text[:500]


def _auth_headers(token: str | None) -> dict[str, str]:
    if token and str(token).startswith("gitlab_oidc:"):
        from skylos.api import _build_auth_headers

        return _build_auth_headers(token)
    if token and str(token).startswith("oidc:"):
        return {
            "Authorization": f"Bearer {token[5:]}",
            "X-Skylos-Auth": "oidc",
        }
    return {"Authorization": f"Bearer {token}"}


def api_get(
    endpoint: str,
    token: str | None,
    *,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    url = _safe_sync_url(endpoint)
    headers = {**(extra_headers or {}), **_auth_headers(token)}

    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=30,
        )
    except requests.exceptions.ConnectionError:
        raise AuthError(f"Cannot connect to {get_api_url()}")
    except requests.exceptions.Timeout:
        raise AuthError("Request timed out")

    if resp.status_code == 401:
        reason = _cloud_reason(resp)
        if token and str(token).startswith(("oidc:", "gitlab_oidc:")):
            raise AuthError(
                reason
                or "Skylos Cloud rejected this GitHub Actions or GitLab CI identity"
            )
        raise AuthError(reason or "Invalid Skylos token")

    if resp.status_code >= 400:
        raise AuthError(
            _cloud_reason(resp)
            or f"Skylos Cloud refused {endpoint} (HTTP {resp.status_code})"
        )

    resp.raise_for_status()
    return resp.json()


def _extract_project_context(info: dict[str, Any]) -> dict[str, Any]:
    project = info.get("project", {})
    org = info.get("organization", {})
    plan = info.get("plan", "free")
    project_id = project.get("id") or project.get("project_id")
    return {
        "project": project,
        "org": org,
        "plan": plan,
        "project_id": project_id,
    }


def _verify_project_context(token: str) -> dict[str, Any]:
    info = api_get(WHOAMI_ENDPOINT, token)
    return _extract_project_context(info)


def _save_repo_link_and_token(
    repo_root: Path,
    token: str,
    context: dict[str, Any],
) -> tuple[str, str]:
    link_path = _write_link(
        repo_root,
        context["project_id"],
        project_name=context["project"].get("name"),
        org_name=context["org"].get("name"),
        plan=context["plan"],
        base_url=get_api_url(),
    )

    creds_path = save_token(
        token,
        project_id=context["project_id"],
        project_name=context["project"].get("name"),
        org_name=context["org"].get("name"),
        plan=context["plan"],
    )
    return link_path, creds_path


def cmd_connect(token_arg: str | None = None) -> None:
    print("\n Connect to Skylos Cloud\n")

    env_token = os.environ.get("SKYLOS_TOKEN", "").strip()
    if env_token and not token_arg:
        print("⚠️  Warning: SKYLOS_TOKEN environment variable is set!")
        print(f"   Current value: {mask_token(env_token)}")
        print("   To use a different token, either:")
        print("   1. Run: unset SKYLOS_TOKEN")
        print("   2. Pass token as argument: skylos sync connect <token>")
        print()
        response = input("Use existing env var token? (y/n): ").strip().lower()
        if response != "y":
            token = None
        else:
            token = env_token
    else:
        token = token_arg or env_token

    if not token:
        print("Project token required. To get one:")
        print("  1. Get one at: https://skylos.dev/settings/api-keys")
        print("  2. Create a project and copy its project token")
        print()
        print("Enter your project token:")
        try:
            token = input("> ").strip()
        except (KeyboardInterrupt, EOFError):
            print(CANCELLED_MESSAGE)
            sys.exit(1)

    if not token:
        print("Error: No token provided.")
        sys.exit(1)

    print(f"Verifying token {mask_token(token)}...")

    try:
        context = _verify_project_context(token)
    except AuthError as e:
        print(f"\n✗ {e}")
        sys.exit(1)

    project = context["project"]
    org = context["org"]
    plan = context["plan"]

    print("\n✓ Connected!\n")
    print(f"  Project:      {project.get('name', UNKNOWN_LABEL)}")
    print(f"  Organization: {org.get('name', UNKNOWN_LABEL)}")
    print(f"  Plan:         {plan_display_name(plan)}")

    project_id = context["project_id"]
    if not project_id:
        print("\n✗ Server did not return project id (expected project.id).")
        sys.exit(1)

    repo_root = _find_repo_root()

    try:
        link_path, creds_path = _save_repo_link_and_token(repo_root, token, context)
    except AuthError as e:
        print(f"\n✗ {e}")
        sys.exit(1)

    print(f"\nLinked repo: {shown_path(repo_root)}")
    print(f"Link file:   {shown_path(link_path)}")
    print(f"\nToken saved to {shown_path(creds_path)}")
    print("\nYou can now run:")
    print("  skylos .      # Scan locally; findings stay on your machine")
    print("  skylos cloud  # Scan with every check and upload to Skylos Cloud")


def cmd_status() -> None:
    token = get_token()

    if not token:
        print("\nNot connected to Skylos Cloud.")
        print("Run 'skylos login' or 'skylos sync connect' to connect.\n")
        return

    print("\nChecking connection...")

    try:
        info = api_get(WHOAMI_ENDPOINT, token)
    except AuthError as e:
        print(f"\n✗ {e}")
        print(
            "Run 'skylos login' to reconnect, or 'skylos sync connect' to set a token manually.\n"
        )
        return

    project = info.get("project", {})
    org = info.get("organization", {})
    plan = info.get("plan", "free")

    print("\n✓ Connected\n")
    print(f"  Project:      {project.get('name', UNKNOWN_LABEL)}")
    print(f"  Organization: {org.get('name', UNKNOWN_LABEL)}")
    print(f"  Plan:         {plan_display_name(plan)}")


def cmd_disconnect() -> None:
    if clear_token():
        print("✓ Disconnected.")
    else:
        print("No saved credentials found.")


def _iter_saved_projects() -> list[dict[str, str]]:
    data = _load_creds()
    tokens = data.get("tokens") or {}
    items = []
    for project_id, entry in tokens.items():
        if not isinstance(entry, dict):
            continue
        items.append(
            {
                "project_id": str(project_id),
                "project_name": entry.get("project_name") or UNKNOWN_LABEL,
                "org_name": entry.get("org_name") or UNKNOWN_LABEL,
                "plan": entry.get("plan") or data.get("plan") or "free",
                "saved_at": entry.get("saved_at") or "",
            }
        )
    items.sort(key=lambda item: item["saved_at"], reverse=True)
    return items


def cmd_project_status() -> None:
    repo_root = _find_repo_root()
    link = _read_link(repo_root)
    linked_project_id = link.get("project_id")
    active = None
    token = get_token()

    if token:
        try:
            active = api_get(WHOAMI_ENDPOINT, token)
        except AuthError:
            active = None

    print("\nSkylos Project Status\n")
    print(f"  Repo:         {shown_path(repo_root)}")

    if linked_project_id:
        print(f"  Linked ID:    {linked_project_id}")
        if link.get("project_name"):
            print(f"  Linked Name:  {link.get('project_name')}")
        if link.get("org_name"):
            print(f"  Linked Org:   {link.get('org_name')}")
    else:
        print("  Linked ID:    none")

    if os.environ.get("SKYLOS_TOKEN"):
        print("  Token Source: SKYLOS_TOKEN")
    elif linked_project_id:
        print("  Token Source: linked project")
    elif token:
        print("  Token Source: saved default token")
    else:
        print("  Token Source: none")

    if active:
        project = active.get("project", {})
        org = active.get("organization", {})
        print(f"  Active Name:  {project.get('name', UNKNOWN_LABEL)}")
        print(f"  Active Org:   {org.get('name', 'My Workspace')}")
        print(f"  Plan:         {plan_display_name(active.get('plan'))}")
    else:
        print("  Active Name:  not connected")

    if not linked_project_id:
        print("\nUse 'skylos project use' to select or create a project for this repo.")


def cmd_project_list() -> None:
    repo_root = _find_repo_root()
    linked_project_id = _linked_project_id(repo_root)
    items = _iter_saved_projects()

    if not items:
        print("\nNo saved Skylos projects found.")
        print("Run 'skylos login' or 'skylos project use' first.\n")
        return

    print("\nKnown Skylos Projects\n")
    for item in items:
        marker = " "
        if item["project_id"] == linked_project_id:
            marker = "*"
        print(f"{marker} {item['project_name']}  [{item['project_id']}]")
        print(f"    Org: {item['org_name']}   Plan: {plan_display_name(item['plan'])}")

    if linked_project_id:
        print("\n* active for this repo")
    else:
        print("\nNo active repo link. Use 'skylos project use' to select one.")


def cmd_project_use() -> None:
    from skylos.cloud.login import run_login

    result = run_login()
    if result is None:
        print("Project selection cancelled.")


def cmd_project_create() -> None:
    print("\nOpening the Skylos project chooser.")
    print("Create a new project in the browser and it will be linked to this repo.\n")
    cmd_project_use()


def cmd_project_unlink() -> None:
    repo_root = _find_repo_root()
    repo_subpath = _current_repo_subpath(repo_root)
    project_root = repo_root / repo_subpath if repo_subpath else repo_root
    from skylos.core.review_decisions import invalidate_trusted_bundle

    invalidate_trusted_bundle(
        project_root,
        cache_root=GLOBAL_CREDS_DIR / "reviewed-findings",
    )
    link_path = _delete_link(repo_root)
    if link_path:
        print(f"✓ Removed repo link: {link_path}")
    else:
        print("No repo link found.")


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def cmd_pull(*, dry_run: bool = False, output_format: str = "text") -> None:
    from skylos.cloud.sync_state import (
        SYNC_RECORD_DIR,
        activate_sync_files,
        validate_sync_paths,
    )
    from skylos.core.review_decisions import (
        invalidate_trusted_bundle,
        repository_scope,
        write_trusted_bundle,
    )

    def progress(message: str) -> None:
        if output_format != "json":
            print(message)

    cache_root = GLOBAL_CREDS_DIR / "reviewed-findings"
    sync_project_root = None
    trust_invalidated = False
    try:
        token = get_token()
        if not token:
            raise AuthError(
                "Not connected. Run 'skylos login' or 'skylos sync connect' first."
            )
        repo_root = _find_repo_root()
        sync_subpath = _current_repo_subpath(repo_root)
        sync_project_root = repo_root / sync_subpath if sync_subpath else repo_root
        if repository_scope(sync_project_root) is None:
            raise AuthError(NO_REMOTE_MESSAGE)
        if not dry_run:
            trust_invalidated = invalidate_trusted_bundle(
                sync_project_root, cache_root=cache_root
            )
        skylos_dir = _ensure_safe_link_path(repo_root, create_dir=False).parent
        validate_sync_paths(repo_root, (CONFIG_FILE, SUPPRESSIONS_FILE))

        info = api_get(WHOAMI_ENDPOINT, token)
        if not isinstance(info, dict):
            raise AuthError("Invalid project response")
        project = info.get("project")
        if not isinstance(project, dict):
            raise AuthError("Invalid project response")
        progress(f"Connected to: {project.get('name', UNKNOWN_LABEL)}\n")
        progress("Pulling configuration...")
        config_data = api_get("/api/sync/config", token)
        config_payload = _sync_config_payload(config_data)
        progress("Pulling suppressions...")
        supp_data = api_get("/api/sync/suppressions", token)
        _validate_sync_suppressions(supp_data)
        whoami_project = info.get("project") if isinstance(info, dict) else None
        whoami_project_id = (
            str(whoami_project.get("id") or "").strip()
            if isinstance(whoami_project, dict)
            else ""
        )
        suppression_project_id = str(supp_data.get("project_id") or "").strip()
        if (
            whoami_project_id
            and suppression_project_id
            and whoami_project_id != suppression_project_id
        ):
            raise AuthError("Suppression response belongs to a different project")
        if not suppression_project_id and whoami_project_id:
            supp_data = {**supp_data, "project_id": whoami_project_id}
        config_project_id = str(config_data.get("project_id") or "").strip()
        if (
            whoami_project_id
            and config_project_id
            and whoami_project_id != config_project_id
        ):
            raise AuthError("Configuration response belongs to a different project")
        files = {
            CONFIG_FILE: yaml.safe_dump(config_payload, default_flow_style=False),
            SUPPRESSIONS_FILE: json.dumps(supp_data, indent=2, allow_nan=False) + "\n",
        }
        changes = {
            filename: {"path": str(skylos_dir / filename)} for filename in files
        }
        if not dry_run:
            with activate_sync_files(
                repo_root, files, record_root=GLOBAL_CREDS_DIR / SYNC_RECORD_DIR
            ):
                trusted_path = write_trusted_bundle(
                    sync_project_root,
                    supp_data,
                    cache_root=cache_root,
                    service_origin=get_api_url(),
                )
                if trusted_path is None:
                    raise AuthError("Could not store trusted suppression state")
        count = len(supp_data.get("decisions", supp_data.get("suppressions", [])))
        if output_format == "json":
            print(json.dumps(
                {
                    "status": "validated" if dry_run else "synced",
                    "dry_run": dry_run,
                    "project_id": whoami_project_id or suppression_project_id or None,
                    "files": changes,
                    "suppression_count": count,
                    "trusted_suppressions": "unchanged" if dry_run else "refreshed",
                },
                sort_keys=True,
            ))
        else:
            for filename in files:
                progress(f"  {'Would write' if dry_run else '✓'} {_display_path(skylos_dir / filename)}")
            progress(
                "\n✓ Dry run complete; no files or trust state changed."
                if dry_run else "\n✓ Sync complete!"
            )
    except Exception as error:
        if not dry_run and sync_project_root is not None:
            trust_invalidated = invalidate_trusted_bundle(
                sync_project_root, cache_root=cache_root
            ) or trust_invalidated
        if output_format == "json":
            print(json.dumps(
                {
                    "status": "failed", "dry_run": dry_run, "error": str(error),
                    "trusted_suppressions": "invalidated" if trust_invalidated else "unchanged",
                },
                sort_keys=True,
            ))
        else:
            print(f"Error: {error}")
        sys.exit(1)


def _sync_config_payload(config_data):
    if not isinstance(config_data, dict):
        raise AuthError("Invalid configuration response")
    config_payload = config_data.get("config", config_data)
    if not isinstance(config_payload, dict):
        raise AuthError("Invalid configuration response")
    return config_payload


def _validate_sync_suppressions(supp_data) -> None:
    from skylos.core.review_decisions import (
        MAX_BUNDLE_BYTES, REVIEW_SCHEMA, REVIEW_SCHEMA_VERSION,
    )

    if not isinstance(supp_data, dict):
        raise AuthError("Invalid suppression response")
    if supp_data.get("schema") not in (None, REVIEW_SCHEMA):
        raise AuthError("Unsupported suppression schema")
    if supp_data.get("version") not in (None, 1, REVIEW_SCHEMA_VERSION):
        raise AuthError("Unsupported suppression version")
    records = supp_data.get("decisions", supp_data.get("suppressions"))
    if not isinstance(records, list) or any(
        not isinstance(record, dict) for record in records
    ):
        raise AuthError("Invalid suppression records")
    for key in ("decisions", "suppressions"):
        if key in supp_data and (
            not isinstance(supp_data[key], list)
            or any(not isinstance(record, dict) for record in supp_data[key])
        ):
            raise AuthError("Invalid suppression records")
    try:
        serialized = json.dumps(supp_data, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise AuthError("Invalid suppression response") from error
    if len(serialized) > MAX_BUNDLE_BYTES:
        raise AuthError("Suppression response exceeds size limit")


def _write_sync_config(skylos_dir: Path, config_data):
    from skylos.cloud.sync_state import SYNC_RECORD_DIR, activate_sync_files

    config_payload = _sync_config_payload(config_data)
    config_path = skylos_dir / CONFIG_FILE
    files = {CONFIG_FILE: yaml.safe_dump(config_payload, default_flow_style=False)}
    with activate_sync_files(
        skylos_dir.parent, files, record_root=GLOBAL_CREDS_DIR / SYNC_RECORD_DIR
    ):
        pass
    print(f"  ✓ {config_path}")


def _write_sync_suppressions(skylos_dir: Path, supp_data):
    from skylos.cloud.sync_state import SYNC_RECORD_DIR, activate_sync_files

    _validate_sync_suppressions(supp_data)
    supp_path = skylos_dir / SUPPRESSIONS_FILE
    files = {SUPPRESSIONS_FILE: json.dumps(supp_data, indent=2, allow_nan=False) + "\n"}
    with activate_sync_files(
        skylos_dir.parent, files, record_root=GLOBAL_CREDS_DIR / SYNC_RECORD_DIR
    ):
        pass
    print(f"  ✓ {supp_path} ({supp_data.get('count', 0)} suppressions)")


def _build_pre_push_hook() -> str:
    return _sync_setup_build_pre_push_hook()


def _optional_arg(args: Sequence[str], index: int) -> str | None:
    if len(args) > index:
        return args[index]
    return None


def cmd_setup(token_arg: str | None = None) -> None:
    print("\n🐕 Skylos Setup\n")

    token = token_arg
    if not token:
        print("Get your token from: https://skylos.dev/dashboard/settings\n")
        try:
            token = input("Paste token: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(CANCELLED_MESSAGE)
            return

    if not token:
        print("Error: No token provided.")
        return

    print("\nConnecting...")
    try:
        context = _verify_project_context(token)
    except AuthError as e:
        print(f"\n✗ {e}")
        return

    project = context["project"]
    plan = context["plan"]

    project_id = context["project_id"]
    if not project_id:
        print("\n✗ Server did not return project id (expected project.id).")
        return

    repo_root = _find_repo_root()

    try:
        _save_repo_link_and_token(repo_root, token, context)
    except AuthError as e:
        print(f"\n✗ {e}")
        return

    print("✓ Connected!\n")
    print(f"  Project: {project.get('name', UNKNOWN_LABEL)}")
    print(f"  Plan: {plan_display_name(plan)}\n")

    is_pro = plan in PRO_PLANS

    git_dir = Path(".git")
    has_git = git_dir.exists()
    has_precommit_file = Path(".pre-commit-config.yaml").exists()
    has_workflow = Path(".github/workflows/skylos.yml").exists()

    if not is_pro:
        _print_free_plan_setup_summary(has_git=has_git)
        return

    print(f"{plan_display_name(plan)} plan detected.\n")
    print("Let's set up your blocking features:\n")

    if not has_git:
        print("  ⚠️  Not a git repository")
        print("     Run: git init\n")
        return

    print("  ✓ Git repository detected\n")

    setup_choices = _collect_setup_choices(
        has_precommit_file=has_precommit_file,
        has_workflow=has_workflow,
    )
    if setup_choices is None:
        return

    setup_hooks, setup_precommit, setup_ci = setup_choices

    print("\n" + "=" * 60)
    print("\nInstalling selected features...\n")

    _install_selected_setup_features(
        git_dir=git_dir,
        setup_hooks=setup_hooks,
        setup_precommit=setup_precommit,
        setup_ci=setup_ci,
        has_precommit_file=has_precommit_file,
    )

    print("\n" + "=" * 60)
    _print_setup_next_steps(setup_precommit=setup_precommit, setup_ci=setup_ci)
    print("=" * 60 + "\n")


def cmd_upgrade() -> None:
    print("\n🐕 Skylos Upgrade\n")

    token = get_token()
    if not token:
        print("✗ Not connected.")
        print("Run: skylos login")
        print("Or:  skylos sync connect <token>\n")
        return

    print("Checking plan...")
    try:
        plan = _verify_project_context(token)["plan"]
    except AuthError as e:
        print(f"✗ {e}")
        return

    if plan not in PRO_PLANS:
        print(f"\nCurrent plan: {plan_display_name(plan)}")
        print(
            f"This needs the {PAID_PLAN_NAME} plan. Buying any credit pack turns it on."
        )
        print(f"See: {PRICING_URL}\n")
        return

    print(f"✓ {plan_display_name(plan)} plan detected.\n")
    print("Installing blocking features...\n")

    git_dir = Path(".git")
    if git_dir.exists():
        _install_pre_push_hook(git_dir)
        print(" ✓ Installed git hooks")

    workflow_path = Path(".github/workflows/skylos.yml")

    if not workflow_path.exists():
        _write_cloud_workflow()
        print("  ✓ Created workflow\n")

    print("=" * 60)
    print("\n FINAL STEP: Bind GitHub repo to Skylos Cloud\n")
    print("1. Confirm this repo is linked to the Skylos Cloud project")
    print("2. Commit the generated workflow")
    print(
        "3. GitHub OIDC will authenticate workflow runs without a SKYLOS_TOKEN secret\n"
    )
    print("=" * 60 + "\n")
    print("✅ Upgrade complete!")


HELP_FLAGS = frozenset({"-h", "--help"})


def _print_sync_usage() -> None:
    print("Usage: skylos sync <command>")
    print("")
    print("Commands:")
    print("  connect [token]  Connect to Skylos Cloud")
    print("  status           Show connection status")
    print("  disconnect       Remove saved credentials")
    print("  pull             Pull config and suppressions (skylos sync pull --help)")
    print("  setup [token]    One-command setup")
    print(f"  upgrade          Add {PAID_PLAN_NAME} plan features after upgrading")


def main(args: Sequence[str] | None = None) -> None:
    if args is None:
        args = sys.argv[1:]

    if not args or args[0] in HELP_FLAGS:
        _print_sync_usage()
        return

    cmd = args[0].lower()
    if cmd == "pull":
        parser = argparse.ArgumentParser(
            prog="skylos sync pull",
            description="Fetch and validate Cloud configuration and suppressions.",
            allow_abbrev=False,
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Validate without writing files or changing trust state",
        )
        parser.add_argument("--format", choices=("text", "json"), default="text")
        options = parser.parse_args(list(args[1:]))
        cmd_pull(dry_run=options.dry_run, output_format=options.format)
        return
    if HELP_FLAGS.intersection(args[1:]):
        _print_sync_usage()
        return
    handlers = {
        "connect": lambda: cmd_connect(_optional_arg(args, 1)),
        "status": cmd_status,
        "disconnect": cmd_disconnect,
        "setup": lambda: cmd_setup(_optional_arg(args, 1)),
        "upgrade": cmd_upgrade,
    }
    handler = handlers.get(cmd)
    if handler is None:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
    handler()


def _print_project_usage() -> None:
    print("Usage: skylos project <command>")
    print("")
    print("Commands:")
    print("  status    Show the active project for this repo")
    print("  list      Show locally known projects")
    print("  use       Select or create a project for this repo")
    print("  create    Open the browser flow and create a new project")
    print("  unlink    Remove the local repo-to-project link")


def project_main(args: Sequence[str] | None = None) -> None:
    if args is None:
        args = sys.argv[1:]

    if not args or HELP_FLAGS.intersection(args):
        _print_project_usage()
        return

    cmd = args[0].lower()
    handlers = {
        "status": cmd_project_status,
        "list": cmd_project_list,
        "use": cmd_project_use,
        "create": cmd_project_create,
        "unlink": cmd_project_unlink,
    }
    handler = handlers.get(cmd)
    if handler is None:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
    handler()


def load_custom_rules() -> dict[str, Any]:
    """Report rule loading coverage separately from an empty ruleset."""
    # Explicit operator environment also transports trusted CI policy
    # artifacts into credential-free scan jobs. It is the same source used by
    # the analyzer, so its receipt must describe the rules actually scanned.
    environment_rules = os.environ.get("SKYLOS_CUSTOM_RULES")
    if environment_rules is not None:
        try:
            rules = json.loads(environment_rules)
            if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
                raise ValueError("Invalid custom rule environment")
            return {"rules": rules, "status": "complete", "source": "environment"}
        except (ValueError, RecursionError):
            return {"rules": [], "status": "unavailable", "reason": "invalid_custom_rule_environment"}
    token = get_token()
    if not token:
        return {"rules": [], "status": "not_connected"}

    try:
        data = api_get("/api/sync/rules", token)
        if not isinstance(data, dict):
            raise ValueError("Invalid custom rule response")
        rules = data.get("rules")
        if not isinstance(rules, list) or any(
            not isinstance(rule, dict) for rule in rules
        ):
            raise ValueError("Invalid custom rule response")
        return {"rules": rules, "status": "complete"}
    except (AuthError, OSError, ValueError) as error:
        return {
            "rules": [], "status": "unavailable",
            "reason": "custom_rule_fetch_failed", "error_type": type(error).__name__,
        }


def get_custom_rules() -> list[dict[str, Any]]:
    return load_custom_rules()["rules"]


if __name__ == "__main__":
    main()
