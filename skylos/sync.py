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

GLOBAL_CREDS_DIR = Path.home() / ".skylos"
GLOBAL_CREDS_FILE = GLOBAL_CREDS_DIR / "credentials.json"


def get_api_url():
    return os.environ.get("SKYLOS_API_URL", DEFAULT_API_URL)


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
    GLOBAL_CREDS_DIR.mkdir(exist_ok=True)

    data = {
        "token": token,
        "saved_at": datetime.utcnow().isoformat() + "Z",
    }
    if project_name:
        data["project_name"] = project_name
    if org_name:
        data["org_name"] = org_name
    if plan:
        data["plan"] = plan

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

    token = token_arg or os.environ.get("SKYLOS_TOKEN", "").strip()

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
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
