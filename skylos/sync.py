import os
import sys
import json
from pathlib import Path
from datetime import datetime

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
META_FILE = ".sync-meta.json"
DEFAULT_API_URL = "https://skylos.dev"
LOCAL_API_URL = "http://localhost:3000"

GLOBAL_CREDS_DIR = Path.home() / ".skylos"
GLOBAL_CREDS_FILE = GLOBAL_CREDS_DIR / "credentials.json"


def get_api_url():
    return os.environ.get("SKYLOS_API_URL", DEFAULT_API_URL)
    # return os.environ.get("SKYLOS_API_URL", LOCAL_API_URL)


def get_token():
    env_token = os.environ.get("SKYLOS_TOKEN", "").strip()
    if env_token:
        return env_token

    if GLOBAL_CREDS_FILE.exists():
        try:
            data = json.loads(GLOBAL_CREDS_FILE.read_text())
            return data.get("token")
        except:
            pass

    return None


def save_token(token, project_name=None, org_name=None, plan=None):
    GLOBAL_CREDS_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "token": token,
        "saved_at": datetime.utcnow().isoformat() + "Z",
        "plan": (plan or "free").lower(),
    }
    if project_name:
        data["project_name"] = project_name
    if org_name:
        data["org_name"] = org_name

    GLOBAL_CREDS_FILE.write_text(json.dumps(data, indent=2))
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


def api_get(endpoint, token):
    url = f"{get_api_url()}{endpoint}"

    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
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
        print("Enter your API token (from Dashboard → Settings):")
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
        info = api_get("/api/sync/whoami", token)
    except AuthError as e:
        print(f"\n✗ {e}")
        sys.exit(1)

    project = info.get("project", {})
    org = info.get("organization", {})
    plan = info.get("plan", "free")

    print(f"\n✓ Connected!\n")
    print(f"  Project:      {project.get('name', 'Unknown')}")
    print(f"  Organization: {org.get('name', 'Unknown')}")
    print(f"  Plan:         {plan.capitalize()}")

    creds_path = save_token(
        token, project_name=project.get("name"), org_name=org.get("name"), plan=plan
    )

    print(f"\nToken saved to {creds_path}")
    print("\nYou can now run:")
    print("  skylos .           # Scan locally")
    print("  skylos . --upload  # Scan and upload")


def cmd_status():
    token = get_token()

    if not token:
        print("\nNot connected to Skylos Cloud.")
        print("Run 'skylos sync connect' to connect.\n")
        return

    print(f"\nChecking connection...")

    try:
        info = api_get("/api/sync/whoami", token)
    except AuthError as e:
        print(f"\n✗ {e}")
        print("Run 'skylos sync connect' to reconnect.\n")
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


def cmd_pull():
    token = get_token()

    if not token:
        print("Error: Not connected.")
        print("Run 'skylos sync connect' first.")
        sys.exit(1)

    skylos_dir = Path(SKYLOS_DIR)
    skylos_dir.mkdir(exist_ok=True)

    try:
        info = api_get("/api/sync/whoami", token)
        print(f"Connected to: {info.get('project', {}).get('name', 'Unknown')}\n")
    except AuthError as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        print("Pulling configuration...")
        config_data = api_get("/api/sync/config", token)

        config_path = skylos_dir / CONFIG_FILE
        with config_path.open("w") as f:
            yaml.dump(config_data.get("config", {}), f, default_flow_style=False)
        print(f"  ✓ {config_path}")

        print("Pulling suppressions...")
        supp_data = api_get("/api/sync/suppressions", token)

        supp_path = skylos_dir / SUPPRESSIONS_FILE
        with supp_path.open("w") as f:
            json.dump(supp_data.get("suppressions", []), f, indent=2)
        print(f"  ✓ {supp_path} ({supp_data.get('count', 0)} suppressions)")

        print("\n✓ Sync complete!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def create_precommit_config():
    precommit_path = Path(".pre-commit-config.yaml")

    if precommit_path.exists():
        print("  ⚠️  .pre-commit-config.yaml already exists (skipping)")
        return False

    config_content = """# Skylos pre-commit configuration

repos:
  - repo: local
    hooks:
      - id: skylos-gate
        name: Skylos Quality Gate
        entry: python -m skylos.cli
        language: system
        pass_filenames: false
        require_serial: true
        args: [".", "--gate", "--danger"]
"""

    precommit_path.write_text(config_content)
    print("  ✓ Created .pre-commit-config.yaml")
    return True


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
        info = api_get("/api/sync/whoami", token)
    except AuthError as e:
        print(f"\n✗ {e}")
        return

    project = info.get("project", {})
    org = info.get("organization", {})
    plan = info.get("plan", "free")

    save_token(
        token, project_name=project.get("name"), org_name=org.get("name"), plan=plan
    )

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
            input("  Install git hooks? (blocks 'git push') [Y/n]: ").strip().lower()
        )
        setup_hooks = response in ["", "y", "yes"]
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return

    if not has_precommit_file:
        try:
            response = (
                input("  Create pre-commit config? (blocks 'git commit') [y/N]: ")
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
        hook_content = r"""#!/bin/bash
echo "Running Skylos quality gate..."
skylos .
exit $?
"""
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
        run: pip install skylos
      
      - name: Run Skylos Scan
        env:
          SKYLOS_TOKEN: ${{ secrets.SKYLOS_TOKEN }}
        run: |
          skylos . --danger --upload --sha ${{ github.event.pull_request.head.sha }}
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
            print(f"{step_num}. Add SKYLOS_TOKEN to GitHub:")
            print("   Settings -> Secrets -> Actions -> New secret")
            print("   Name: SKYLOS_TOKEN")
            print(f"   Value: {mask_token(token)}\n")

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
        print("Run: skylos sync connect <token>\n")
        return

    print("Checking plan...")
    try:
        info = api_get("/api/sync/whoami", token)
        plan = info.get("plan", "free")
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
        hook_content = """#!/bin/bash
echo "Running Skylos quality gate..."
skylos . --gate
exit $?
"""
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
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Skylos
        run: pip install skylos
      
      - name: Run Skylos Scan
        env:
          SKYLOS_TOKEN: ${{ secrets.SKYLOS_TOKEN }}
        run: skylos . --danger --gate
"""
        workflow_path.write_text(workflow_content)
        print("  ✓ Created workflow\n")

    print("=" * 60)
    print("\n FINAL STEP: Add token to GitHub\n")
    print("1. Repo -> Settings -> Secrets -> Actions")
    print("2. Add: SKYLOS_TOKEN")
    print(f"3. Value: {mask_token(token)}\n")
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

    if cmd == "connect":
        cmd_connect(args[1] if len(args) > 1 else None)
    elif cmd == "status":
        cmd_status()
    elif cmd == "disconnect":
        cmd_disconnect()
    elif cmd == "pull":
        cmd_pull()
    elif cmd == "setup":
        cmd_setup(args[1] if len(args) > 1 else None)
    elif cmd == "upgrade":
        cmd_upgrade()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


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
