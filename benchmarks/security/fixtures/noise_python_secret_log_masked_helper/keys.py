import getpass
from pathlib import Path

KEY_FILE = Path.home() / ".config" / "tool" / "key"


def mask(key):
    if len(key) <= 14:
        return "..."
    return key[:6] + "..." + key[-4:]


def write_key_file(value):
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(KEY_FILE, "w") as handle:
        handle.write(value + "\n")
    return KEY_FILE


def store():
    value = getpass.getpass("API key (hidden): ").strip()
    print(f"stored in {write_key_file(value)} as {mask(value)}")
