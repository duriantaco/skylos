import os
import sys
import json
import stat
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import subprocess
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlparse
from skylos.cloud.sync_setup import (
    build_pre_push_hook as _sync_setup_build_pre_push_hook,
    collect_setup_choices as _collect_setup_choices,
    create_precommit_config,
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
    try:
        out = (
            subprocess.check_output(
                ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
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
        from skylos.api import _try_github_oidc_token
    except ImportError:
        return None

    try:
        token = _try_github_oidc_token()
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
    if not token or len(token) <= 12:
        return "****"
    return token[:8] + "..." + token[-4:]


class AuthError(Exception):
    pass


def _auth_headers(token: str | None) -> dict[str, str]:
    if token and str(token).startswith("oidc:"):
        return {
            "Authorization": f"Bearer {token[5:]}",
            "X-Skylos-Auth": "oidc",
        }
    return {"Authorization": f"Bearer {token}"}


def api_get(endpoint: str, token: str | None) -> dict[str, Any]:
    url = _safe_sync_url(endpoint)

    try:
        resp = requests.get(
            url,
            headers=_auth_headers(token),
            timeout=30,
        )
    except requests.exceptions.ConnectionError:
        raise AuthError(f"Cannot connect to {get_api_url()}")
    except requests.exceptions.Timeout:
        raise AuthError("Request timed out")

    if resp.status_code == 401:
        raise AuthError("Invalid API token")

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
        print("API token required. To get one:")
        print("  1. Get one at: https://skylos.dev/settings/api-keys")
        print("  2. Create a project and copy the API key")
        print()
        print("Enter your API token:")
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
    print(f"  Plan:         {plan.capitalize()}")

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

    print(f"\nLinked repo: {repo_root}")
    print(f"Link file:   {link_path}")
    print(f"\nToken saved to {creds_path}")
    print("\nYou can now run:")
    print("  skylos .           # Scan locally")
    print("  skylos . --upload  # Scan and upload")


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
    print(f"  Plan:         {plan.capitalize()}")


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
    print(f"  Repo:         {repo_root}")

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
        print(f"  Plan:         {active.get('plan', 'free').capitalize()}")
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
        print(f"    Org: {item['org_name']}   Plan: {str(item['plan']).capitalize()}")

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
    link_path = _delete_link(repo_root)
    if link_path:
        print(f"✓ Removed repo link: {link_path}")
    else:
        print("No repo link found.")


def cmd_pull() -> None:
    token = get_token()

    if not token:
        print("Error: Not connected.")
        print("Run 'skylos login' or 'skylos sync connect' first.")
        sys.exit(1)

    repo_root = _find_repo_root()
    skylos_dir = repo_root / SKYLOS_DIR
    skylos_dir.mkdir(parents=True, exist_ok=True)

    try:
        info = api_get(WHOAMI_ENDPOINT, token)
        print(f"Connected to: {info.get('project', {}).get('name', UNKNOWN_LABEL)}\n")
    except AuthError as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        print("Pulling configuration...")
        config_data = api_get("/api/sync/config", token)
        _write_sync_config(skylos_dir, config_data)

        print("Pulling suppressions...")
        supp_data = api_get("/api/sync/suppressions", token)
        _write_sync_suppressions(skylos_dir, supp_data)

        print("\n✓ Sync complete!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _write_sync_config(skylos_dir: Path, config_data):
    config_payload = config_data.get("config")
    if not isinstance(config_payload, dict):
        if isinstance(config_data, dict):
            config_payload = config_data
        else:
            config_payload = {}

    config_path = skylos_dir / CONFIG_FILE
    with config_path.open("w") as f:
        yaml.dump(config_payload, f, default_flow_style=False)
    print(f"  ✓ {config_path}")


def _write_sync_suppressions(skylos_dir: Path, supp_data):
    supp_path = skylos_dir / SUPPRESSIONS_FILE
    with supp_path.open("w") as f:
        json.dump(supp_data.get("suppressions", []), f, indent=2)
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
    print(f"  Plan: {plan.capitalize()}\n")

    is_pro = plan in PRO_PLANS

    git_dir = Path(".git")
    has_git = git_dir.exists()
    has_precommit_file = Path(".pre-commit-config.yaml").exists()
    has_workflow = Path(".github/workflows/skylos.yml").exists()

    if not is_pro:
        _print_free_plan_setup_summary(has_git=has_git)
        return

    print("🎉 Pro plan detected!\n")
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
        print(f"\nCurrent plan: {plan.capitalize()}")
        print("Upgrade to Pro first!")
        print("Visit: https://skylos.dev/pricing\n")
        return

    print("✓ Pro plan detected!\n")
    print("Installing Pro features...\n")

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


def main(args: Sequence[str] | None = None) -> None:
    if args is None:
        args = sys.argv[1:]

    if not args:
        print("Usage: skylos sync <command>")
        print("")
        print("Commands:")
        print("  connect [token]  Connect to Skylos Cloud")
        print("  status           Show connection status")
        print("  disconnect       Remove saved credentials")
        print("  pull             Pull config and suppressions")
        print("  setup [token]    One-command setup")
        print("  upgrade          Add Pro features after upgrading")
        return

    cmd = args[0].lower()
    handlers = {
        "connect": lambda: cmd_connect(_optional_arg(args, 1)),
        "status": cmd_status,
        "disconnect": cmd_disconnect,
        "pull": cmd_pull,
        "setup": lambda: cmd_setup(_optional_arg(args, 1)),
        "upgrade": cmd_upgrade,
    }
    handler = handlers.get(cmd)
    if handler is None:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
    handler()


def project_main(args: Sequence[str] | None = None) -> None:
    if args is None:
        args = sys.argv[1:]

    if not args:
        print("Usage: skylos project <command>")
        print("")
        print("Commands:")
        print("  status    Show the active project for this repo")
        print("  list      Show locally known projects")
        print("  use       Select or create a project for this repo")
        print("  create    Open the browser flow and create a new project")
        print("  unlink    Remove the local repo-to-project link")
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


def get_custom_rules() -> list[dict[str, Any]]:
    token = get_token()
    if not token:
        return []

    try:
        data = api_get("/api/sync/rules", token)
        rules = data.get("rules", [])
        if isinstance(rules, list):
            return rules
        return []
    except (AuthError, OSError, ValueError):
        return []


if __name__ == "__main__":
    main()
