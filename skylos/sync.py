import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone
import subprocess

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
LOCAL_API_URL = "http://localhost:3000"

GLOBAL_CREDS_DIR = Path.home() / ".skylos"
GLOBAL_CREDS_FILE = GLOBAL_CREDS_DIR / "credentials.json"


LINK_FILE = "link.json"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_creds():
    if not GLOBAL_CREDS_FILE.exists():
        return {}
    try:
        return json.loads(GLOBAL_CREDS_FILE.read_text() or "{}")
    except Exception:
        return {}


def _write_creds(data):
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


def _find_repo_root():
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
    except Exception:
        pass
    return Path.cwd()


def _linked_project_id(repo_root: Path):
    p = repo_root / SKYLOS_DIR / LINK_FILE
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text() or "{}")
    except Exception:
        return None
    repo_subpath = _current_repo_subpath(repo_root)
    subpath_entry = _project_entry_for_subpath(data, repo_subpath)
    project_id = subpath_entry.get("project_id") or data.get("project_id")
    return str(project_id).strip() if project_id else None


def _read_link(repo_root: Path):
    p = repo_root / SKYLOS_DIR / LINK_FILE
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text() or "{}")
    except Exception:
        return {}


def _normalize_repo_subpath_value(value) -> str:
    try:
        from skylos.project_context import normalize_repo_subpath

        normalized = normalize_repo_subpath(value)
        return normalized or ""
    except Exception:
        return str(value or "").strip("/")


def _current_repo_subpath(repo_root: Path) -> str:
    try:
        from skylos.project_context import repo_subpath_for_project

        return repo_subpath_for_project(Path.cwd(), repo_root)
    except Exception:
        return ""


def _project_entry_for_subpath(link: dict, repo_subpath: str) -> dict:
    projects = link.get("projects")
    if isinstance(projects, dict):
        entry = projects.get(repo_subpath)
        if isinstance(entry, dict):
            return entry
    return {}


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
    skylos_dir = repo_root / SKYLOS_DIR
    skylos_dir.mkdir(parents=True, exist_ok=True)

    link_path = skylos_dir / LINK_FILE
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
    projects = existing.get("projects") if isinstance(existing, dict) else {}
    if not isinstance(projects, dict):
        projects = {}
    projects[normalized_subpath] = {
        "project_id": str(project_id),
        "project_name": project_name,
        "org_name": org_name,
        "plan": str(plan).lower() if plan else None,
        "repo_subpath": normalized_subpath,
        "linked_at": payload["linked_at"],
    }
    payload["projects"] = projects
    # if folder_id:
    #     payload["folder_id"] = str(folder_id)
    # if folder_name:
    #     payload["folder_name"] = str(folder_name)

    link_path.write_text(json.dumps(payload, indent=2))
    return str(link_path)


def _delete_link(repo_root: Path):
    p = repo_root / SKYLOS_DIR / LINK_FILE
    if not p.exists():
        return None
    p.unlink()
    return str(p)


def get_api_url():
    return os.environ.get("SKYLOS_API_URL", DEFAULT_API_URL)
    # return os.environ.get("SKYLOS_API_URL", LOCAL_API_URL)


def _try_ci_oidc_token():
    try:
        from skylos.api import _try_github_oidc_token
    except Exception:
        return None

    try:
        return _try_github_oidc_token()
    except Exception:
        return None


def get_token():
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
    token, project_id=None, project_name=None, org_name=None, plan=None, repo_subpath=None
):
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


def clear_token():
    if GLOBAL_CREDS_FILE.exists():
        GLOBAL_CREDS_FILE.unlink()
        return True
    return False


def mask_token(token):
    if not token or len(token) <= 12:
        return "****"
    return token[:8] + "..." + token[-4:]


class AuthError(Exception):
    pass


def _auth_headers(token):
    if token and str(token).startswith("oidc:"):
        return {
            "Authorization": f"Bearer {token[5:]}",
            "X-Skylos-Auth": "oidc",
        }
    return {"Authorization": f"Bearer {token}"}


def api_get(endpoint, token):
    url = f"{get_api_url()}{endpoint}"

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


def _extract_project_context(info):
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


def _verify_project_context(token):
    info = api_get("/api/sync/whoami", token)
    return _extract_project_context(info)


def _save_repo_link_and_token(repo_root, token, context):
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


def cmd_connect(token_arg=None):
    print("\n Connect to Skylos Cloud\n")

    env_token = os.environ.get("SKYLOS_TOKEN", "").strip()
    if env_token and not token_arg:
        print(f"⚠️  Warning: SKYLOS_TOKEN environment variable is set!")
        print(f"   Current value: {mask_token(env_token)}")
        print(f"   To use a different token, either:")
        print(f"   1. Run: unset SKYLOS_TOKEN")
        print(f"   2. Pass token as argument: skylos sync connect <token>")
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
            print("\nCancelled.")
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

    print(f"\n✓ Connected!\n")
    print(f"  Project:      {project.get('name', 'Unknown')}")
    print(f"  Organization: {org.get('name', 'Unknown')}")
    print(f"  Plan:         {plan.capitalize()}")

    project_id = context["project_id"]
    if not project_id:
        print("\n✗ Server did not return project id (expected project.id).")
        sys.exit(1)

    repo_root = _find_repo_root()

    link_path, creds_path = _save_repo_link_and_token(repo_root, token, context)

    print(f"\nLinked repo: {repo_root}")
    print(f"Link file:   {link_path}")
    print(f"\nToken saved to {creds_path}")
    print("\nYou can now run:")
    print("  skylos .           # Scan locally")
    print("  skylos . --upload  # Scan and upload")


def cmd_status():
    token = get_token()

    if not token:
        print("\nNot connected to Skylos Cloud.")
        print("Run 'skylos login' or 'skylos sync connect' to connect.\n")
        return

    print(f"\nChecking connection...")

    try:
        info = api_get("/api/sync/whoami", token)
    except AuthError as e:
        print(f"\n✗ {e}")
        print(
            "Run 'skylos login' to reconnect, or 'skylos sync connect' to set a token manually.\n"
        )
        return

    project = info.get("project", {})
    org = info.get("organization", {})
    plan = info.get("plan", "free")

    print(f"\n✓ Connected\n")
    print(f"  Project:      {project.get('name', 'Unknown')}")
    print(f"  Organization: {org.get('name', 'Unknown')}")
    print(f"  Plan:         {plan.capitalize()}")


def cmd_disconnect():
    if clear_token():
        print("✓ Disconnected.")
    else:
        print("No saved credentials found.")


def _iter_saved_projects():
    data = _load_creds()
    tokens = data.get("tokens") or {}
    items = []
    for project_id, entry in tokens.items():
        if not isinstance(entry, dict):
            continue
        items.append(
            {
                "project_id": str(project_id),
                "project_name": entry.get("project_name") or "Unknown",
                "org_name": entry.get("org_name") or "Unknown",
                "plan": entry.get("plan") or data.get("plan") or "free",
                "saved_at": entry.get("saved_at") or "",
            }
        )
    items.sort(key=lambda item: item["saved_at"], reverse=True)
    return items


def cmd_project_status():
    repo_root = _find_repo_root()
    link = _read_link(repo_root)
    linked_project_id = link.get("project_id")
    active = None
    token = get_token()

    if token:
        try:
            active = api_get("/api/sync/whoami", token)
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
        print(f"  Active Name:  {project.get('name', 'Unknown')}")
        print(f"  Active Org:   {org.get('name', 'My Workspace')}")
        print(f"  Plan:         {active.get('plan', 'free').capitalize()}")
    else:
        print("  Active Name:  not connected")

    if not linked_project_id:
        print("\nUse 'skylos project use' to select or create a project for this repo.")


def cmd_project_list():
    repo_root = _find_repo_root()
    linked_project_id = _linked_project_id(repo_root)
    items = _iter_saved_projects()

    if not items:
        print("\nNo saved Skylos projects found.")
        print("Run 'skylos login' or 'skylos project use' first.\n")
        return

    print("\nKnown Skylos Projects\n")
    for item in items:
        marker = "*" if item["project_id"] == linked_project_id else " "
        print(f"{marker} {item['project_name']}  [{item['project_id']}]")
        print(f"    Org: {item['org_name']}   Plan: {str(item['plan']).capitalize()}")

    if linked_project_id:
        print("\n* active for this repo")
    else:
        print("\nNo active repo link. Use 'skylos project use' to select one.")


def cmd_project_use():
    from skylos.login import run_login

    result = run_login()
    if result is None:
        print("Project selection cancelled.")


def cmd_project_create():
    print("\nOpening the Skylos project chooser.")
    print("Create a new project in the browser and it will be linked to this repo.\n")
    cmd_project_use()


def cmd_project_unlink():
    repo_root = _find_repo_root()
    link_path = _delete_link(repo_root)
    if link_path:
        print(f"✓ Removed repo link: {link_path}")
    else:
        print("No repo link found.")


def cmd_pull():
    token = get_token()

    if not token:
        print("Error: Not connected.")
        print("Run 'skylos login' or 'skylos sync connect' first.")
        sys.exit(1)

    repo_root = _find_repo_root()
    skylos_dir = repo_root / SKYLOS_DIR
    skylos_dir.mkdir(parents=True, exist_ok=True)

    try:
        info = api_get("/api/sync/whoami", token)
        print(f"Connected to: {info.get('project', {}).get('name', 'Unknown')}\n")
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


PRECOMMIT_HOOK_DEPENDENCIES = [
    "inquirer>=3.0.3",
    "libcst>=1.8.2",
    "rich>=14.0.0",
    "textual>=1.0.0",
    "keyring>=25.6.0,!=3.4.2",
    "requests",
    "tree-sitter>=0.25.2",
    "tree-sitter-typescript>=0.23.2",
    "tree-sitter-go>=0.23.0",
    "tree-sitter-java>=0.23.0",
    "pyyaml",
    "networkx",
    "pyperclip",
    "ca9>=0.1.0",
    "mcp>=1.0.0",
]


def create_precommit_config():
    precommit_path = Path(".pre-commit-config.yaml")

    if precommit_path.exists():
        print("  ⚠️  .pre-commit-config.yaml already exists (skipping)")
        return False

    dependency_lines = "\n".join(
        f'          - "{dependency}"' for dependency in PRECOMMIT_HOOK_DEPENDENCIES
    )

    config_content = f"""# Skylos pre-commit configuration
# Fast staged-only local hook.
# Checks security, secrets, and quality in staged source/config files.
# Full repo and diff-aware enforcement runs in CI.

repos:
  - repo: local
    hooks:
      - id: skylos-gate
        name: Skylos Staged Gate
        entry: python -m skylos.cli
        language: python
        additional_dependencies:
{dependency_lines}
        pass_filenames: false
        require_serial: true
        args: ["agent", "pre-commit", "."]
        stages: [pre-commit]
"""

    precommit_path.write_text(config_content)
    print("  ✓ Created .pre-commit-config.yaml")
    return True


def _write_sync_config(skylos_dir: Path, config_data):
    config_payload = config_data.get("config")
    if not isinstance(config_payload, dict):
        # Backward-compat: older/newer cloud deployments may return the
        # sync config directly at the top level instead of wrapping it.
        config_payload = config_data if isinstance(config_data, dict) else {}

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
    return """#!/bin/bash
# Fast local parity guard only. Full Skylos scans should run manually or in CI.
if python3 -c "import skylos_fast" 2>/dev/null; then
    echo "Running Rust/Python parity check..."
    python3 -m pytest test/test_fast_parity.py -k "synthetic or exact_match or same_cycles_found or python_files_match" -q --no-header --tb=line 2>&1
    PARITY_EXIT=$?
    if [ $PARITY_EXIT -ne 0 ]; then
        echo ""
        echo "BLOCKED: Rust/Python parity drift detected."
        echo "Run 'pytest test/test_fast_parity.py -v' for details."
        exit 1
    fi
fi

exit 0
"""


def cmd_setup(token_arg=None):
    print("\n🐕 Skylos Setup\n")

    token = token_arg
    if not token:
        print("Get your token from: https://skylos.dev/dashboard/settings\n")
        try:
            token = input("Paste token: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return

    if not token:
        print("Error: No token provided.")
        return

    print(f"\nConnecting...")
    try:
        context = _verify_project_context(token)
    except AuthError as e:
        print(f"\n✗ {e}")
        return

    project = context["project"]
    org = context["org"]
    plan = context["plan"]

    project_id = context["project_id"]
    if not project_id:
        print("\n✗ Server did not return project id (expected project.id).")
        return

    repo_root = _find_repo_root()

    _save_repo_link_and_token(repo_root, token, context)

    print(f"✓ Connected!\n")
    print(f"  Project: {project.get('name', 'Unknown')}")
    print(f"  Plan: {plan.capitalize()}\n")

    is_pro = plan in ["pro", "enterprise", "beta"]

    git_dir = Path(".git")
    has_git = git_dir.exists()
    has_precommit_file = Path(".pre-commit-config.yaml").exists()
    has_workflow = Path(".github/workflows/skylos.yml").exists()

    if not is_pro:
        print("=" * 60)
        print("\n Pro Features Available (Upgrade to enable):\n")

        if has_git:
            print("  🔒 Git hooks - Block bad code on push")
            print("  🔒 Pre-commit - Block bad code on commit")
            print("  🔒 GitHub Actions - Block PRs automatically")
        else:
            print("  ⚠️  Initialize git first: git init")

        print("\n" + "=" * 60)
        print("\n✓ Setup complete!\n")
        print(" What you can do now:\n")
        print("  • Run local scans:")
        print("    $ skylos .\n")
        print("  • View results in dashboard:")
        print("    https://skylos.dev/dashboard\n")
        print("=" * 60 + "\n")
        return

    print("🎉 Pro plan detected!\n")
    print("Let's set up your blocking features:\n")

    if not has_git:
        print("  ⚠️  Not a git repository")
        print("     Run: git init\n")
        return

    print("  ✓ Git repository detected\n")

    setup_hooks = False
    setup_precommit = False
    setup_ci = False

    try:
        response = (
            input("  Install optional pre-push parity hook? (fast push safeguard) [Y/n]: ")
            .strip()
            .lower()
        )
        setup_hooks = response in ["", "y", "yes"]
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return

    if not has_precommit_file:
        try:
            response = (
                input(
                    "  Create staged pre-commit config? (fast local check before commit) [y/N]: "
                )
                .strip()
                .lower()
            )
            setup_precommit = response in ["y", "yes"]
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return
    else:
        print(" * .pre-commit-config.yaml exists (skipping)")

    if not has_workflow:
        try:
            response = (
                input("  Create GitHub Actions? (blocks PR merges) [Y/n]: ")
                .strip()
                .lower()
            )
            setup_ci = response in ["", "y", "yes"]
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return
    else:
        print("  *  .github/workflows/skylos.yml exists (skipping)")

    print("\n" + "=" * 60)
    print("\nInstalling selected features...\n")

    if setup_hooks:
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        hook_path = hooks_dir / "pre-push"
        hook_content = _build_pre_push_hook()
        hook_path.write_text(hook_content)
        hook_path.chmod(0o755)
        print("  ✓ Installed git hooks (.git/hooks/pre-push)")
    else:
        print(" ✗ Skipped git hooks")

    if setup_precommit:
        created = create_precommit_config()
        if created:
            print("  ✓ Created pre-commit config (.pre-commit-config.yaml)")
    elif not has_precommit_file:
        print("  ✗ Skipped pre-commit config")

    if setup_ci:
        workflow_dir = Path(".github/workflows")
        workflow_dir.mkdir(parents=True, exist_ok=True)
        workflow_path = workflow_dir / "skylos.yml"

        workflow_content = """name: Skylos Quality Gate

on:
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write
  checks: write
  id-token: write

jobs:
  skylos:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Skylos
        run: python -m pip install skylos

      - name: Pull Skylos Cloud Policy
        run: |
          skylos sync pull || echo "No Skylos Cloud policy available through GitHub OIDC; continuing with local config."
      
      - name: Run Skylos Scan & Upload
        run: |
          skylos . --danger --secrets --quality --upload
        env:
          SKYLOS_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}
          SKYLOS_BRANCH: ${{ github.event.pull_request.head.ref || github.ref_name }}
"""
        workflow_path.write_text(workflow_content)
        print("  ✓ Created GitHub Actions (.github/workflows/skylos.yml)")
    else:
        print("  ✗ Skipped GitHub Actions")

    print("\n" + "=" * 60)

    if setup_precommit or setup_ci:
        print("\n Next Steps:\n")

        if setup_precommit:
            print("1. Install pre-commit:")
            print("   $ pip install pre-commit")
            print("   $ pre-commit install\n")

        if setup_ci:
            if setup_precommit:
                step_num = "2"
            else:
                step_num = "1"
            print(f"{step_num}. Bind this GitHub repo to the Skylos Cloud project.")
            print("   The workflow uses GitHub OIDC by default; no SKYLOS_TOKEN secret is required.")
            print("   Keep SKYLOS_TOKEN only as a legacy fallback for non-GitHub CI.\n")

        final_step = (
            "3"
            if (setup_precommit and setup_ci)
            else ("2" if (setup_precommit or setup_ci) else "1")
        )
        print(f"{final_step}. Commit and push:")
        print("   $ git add .")
        print("   $ git commit -m 'Add Skylos'")
        print("   $ git push\n")

        print("🎯 Your code is now protected!")
    else:
        print("\n✓ Setup complete!")
        print("\nRun: skylos . to scan your code\n")

    print("=" * 60 + "\n")


def cmd_upgrade():
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

    if plan not in ["pro", "enterprise", "beta"]:
        print(f"\nCurrent plan: {plan.capitalize()}")
        print("Upgrade to Pro first!")
        print("Visit: https://skylos.dev/pricing\n")
        return

    print(f"✓ Pro plan detected!\n")
    print("Installing Pro features...\n")

    git_dir = Path(".git")
    if git_dir.exists():
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        hook_path = hooks_dir / "pre-push"
        hook_content = _build_pre_push_hook()
        hook_path.write_text(hook_content)
        hook_path.chmod(0o755)
        print(" ✓ Installed git hooks")

    workflow_dir = Path(".github/workflows")
    workflow_dir.mkdir(parents=True, exist_ok=True)
    workflow_path = workflow_dir / "skylos.yml"

    if not workflow_path.exists():
        workflow_content = """name: Skylos Quality Gate

on:
  pull_request:
    branches: [main, master]

jobs:
  skylos:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Skylos
        run: python -m pip install skylos

      - name: Pull Skylos Cloud Policy
        run: |
          skylos sync pull || echo "No Skylos Cloud policy available through GitHub OIDC; continuing with local config."
      
      - name: Run Skylos Scan & Upload
        run: skylos . --danger --secrets --quality --upload
        env:
          SKYLOS_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}
          SKYLOS_BRANCH: ${{ github.event.pull_request.head.ref || github.ref_name }}
"""
        workflow_path.write_text(workflow_content)
        print("  ✓ Created workflow\n")

    print("=" * 60)
    print("\n FINAL STEP: Bind GitHub repo to Skylos Cloud\n")
    print("1. Confirm this repo is linked to the Skylos Cloud project")
    print("2. Commit the generated workflow")
    print("3. GitHub OIDC will authenticate workflow runs without a SKYLOS_TOKEN secret\n")
    print("=" * 60 + "\n")
    print("✅ Upgrade complete!")


def main(args=None):
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
        "connect": lambda: cmd_connect(args[1] if len(args) > 1 else None),
        "status": cmd_status,
        "disconnect": cmd_disconnect,
        "pull": cmd_pull,
        "setup": lambda: cmd_setup(args[1] if len(args) > 1 else None),
        "upgrade": cmd_upgrade,
    }
    handler = handlers.get(cmd)
    if handler is None:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
    handler()


def project_main(args=None):
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


def get_custom_rules():
    token = get_token()
    if not token:
        return []

    try:
        data = api_get("/api/sync/rules", token)
        return data.get("rules", [])
    except Exception:
        return []


if __name__ == "__main__":
    main()
