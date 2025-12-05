import os

try:
    import keyring

    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

SERVICE_NAME = "skylos"


def save_key(provider, key):
    if not KEYRING_AVAILABLE:
        print("[warn] 'keyring' library not found. Cannot save credentials securely.")
        return

    try:
        keyring.set_password(SERVICE_NAME, provider, key)
    except Exception as e:
        print(f"[warn] Failed to save to system keyring: {e}")


def get_key(provider):
    env_var = f"{provider.upper()}_API_KEY"
    key = os.getenv(env_var)
    if key:
        return key

    if KEYRING_AVAILABLE:
        try:
            return keyring.get_password(SERVICE_NAME, provider)
        except Exception:
            return None

    return None
