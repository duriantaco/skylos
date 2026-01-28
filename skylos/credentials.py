import os

try:
    import keyring

    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

SERVICE_NAME = "skylos"

PROVIDERS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GEMINI_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "groq": "GROQ_API_KEY",
    "xai": "XAI_API_KEY",
    "together": "TOGETHER_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
}


def save_key(provider, key):
    if not KEYRING_AVAILABLE:
        print("[warn] 'keyring' not found. Cannot save credentials securely.")
        return False

    try:
        keyring.set_password(SERVICE_NAME, provider, key)
        return True
    except Exception as e:
        print(f"[warn] Failed to save to keyring: {e}")
        return False


def get_key(provider):
    env_var = PROVIDERS.get(provider)
    if env_var:
        key = os.getenv(env_var)
        if key:
            return key

    if KEYRING_AVAILABLE:
        try:
            return keyring.get_password(SERVICE_NAME, provider)
        except Exception:
            pass

    return None


def delete_key(provider):
    try:
        import keyring
    except Exception:
        return False

    service = "skylos"
    username = str(provider)

    try:
        keyring.delete_password(service, username)
        return True
    except Exception:
        return False


def list_providers():
    return list(PROVIDERS.keys())
