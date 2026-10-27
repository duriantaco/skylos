import importlib.util
import os
from urllib.parse import urlparse

from skylos.cloud.credentials import get_key, save_key, PROVIDERS


LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}
LLM_EXTRA_INSTALL_COMMAND = 'pip install "skylos[llm]"'
LLM_EXTRA_MISSING_MESSAGE = (
    "This command needs the optional LLM extra (LiteLLM), which is not "
    f"installed. Install it with: {LLM_EXTRA_INSTALL_COMMAND}"
)


def llm_extra_installed() -> bool:
    return importlib.util.find_spec("litellm") is not None


def load_litellm():
    os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "true")
    import litellm

    return litellm


def llm_extra_importable() -> bool:
    if not llm_extra_installed():
        return False
    try:
        load_litellm()
    except Exception:
        return False
    return True


def provider_key_env_var(model, provider=None):
    resolved = (provider or "").strip().lower() or detect_provider(model)
    if resolved == "ollama":
        return None
    return PROVIDERS.get(resolved)


def detect_provider(model):
    m = (model or "").strip().lower()

    if m.startswith("gemini/"):
        return "google"

    for prefix in [
        "ollama/",
        "groq/",
        "mistral/",
        "together/",
        "deepseek/",
        "xai/",
    ]:
        if m.startswith(prefix):
            return prefix[:-1]

    if "claude" in m:
        return "anthropic"

    return "openai"


def is_local_llm(model, base_url: None):
    m = (model or "").strip().lower()
    if m.startswith("ollama/"):
        return True

    url = (base_url or "").strip()
    if not url:
        return False

    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""

    host = host.lower()
    return host in LOCAL_HOSTS


def resolve_llm_runtime(
    *,
    model,
    provider_override: None,
    base_url_override: None,
    console=None,
    allow_prompt=True,
):
    provider = (
        (provider_override or "").strip().lower()
        or (os.getenv("SKYLOS_LLM_PROVIDER") or "").strip().lower()
        or detect_provider(model)
    )

    base_url = (
        (base_url_override or "").strip()
        or (os.getenv("SKYLOS_LLM_BASE_URL") or "").strip()
        or (os.getenv("OPENAI_BASE_URL") or "").strip()
        or None
    )

    local = is_local_llm(model, base_url)

    if local or provider == "ollama":
        return provider, "", base_url, True

    api_key = get_key(provider)

    if api_key:
        env_var = PROVIDERS.get(provider)
        if env_var:
            os.environ.setdefault(env_var, api_key)

    if (not api_key) and allow_prompt and console is not None:
        env_var = PROVIDERS.get(provider)
        label = env_var or f"{provider.upper()}_API_KEY"
        console.print(f"[warn]No {label} found.[/warn]")
        try:
            api_key = console.input(
                f"[bold yellow]Paste {provider.title()} API Key:[/bold yellow] ",
                password=True,
            )
            if api_key:
                save_key(provider, api_key)
        except (KeyboardInterrupt, EOFError):
            return provider, None, base_url, False

    return provider, api_key, base_url, False
