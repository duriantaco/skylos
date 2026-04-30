from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any


DISABLED_SECURITY_PATTERNS = {
    "verify": "Requests TLS verification disabled (verify=False).",
    "check_hostname": "TLS hostname verification disabled (check_hostname=False).",
}

DANGEROUS_CALLS = {
    "_create_unverified_context": "ssl._create_unverified_context() disables certificate verification.",
    "_create_default_https_context": None,
}

DANGEROUS_DECORATORS = {
    "csrf_exempt": "CSRF protection disabled via @csrf_exempt.",
    "login_not_required": "Authentication bypassed via @login_not_required.",
}

DANGEROUS_ASSIGNMENTS = {
    "DEBUG": (True, "DEBUG = True left in code. Disable in production."),
    "ALLOWED_HOSTS": (
        None,
        'ALLOWED_HOSTS contains wildcard "*". Restrict in production.',
    ),
    "SECRET_KEY": (None, None),
    "SESSION_COOKIE_SECURE": (
        False,
        "SESSION_COOKIE_SECURE = False leaves session cookies usable over plaintext HTTP.",
    ),
    "CSRF_COOKIE_SECURE": (
        False,
        "CSRF_COOKIE_SECURE = False leaves CSRF cookies usable over plaintext HTTP.",
    ),
    "SESSION_COOKIE_HTTPONLY": (
        False,
        "SESSION_COOKIE_HTTPONLY = False allows JavaScript to read session cookies.",
    ),
    "CSRF_COOKIE_HTTPONLY": (
        False,
        "CSRF_COOKIE_HTTPONLY = False allows JavaScript to read CSRF cookies.",
    ),
    "WTF_CSRF_ENABLED": (
        False,
        "WTF_CSRF_ENABLED = False disables Flask-WTF CSRF protection.",
    ),
    "JWT_VERIFY": (False, "JWT_VERIFY = False disables JWT verification."),
    "JWT_VERIFY_EXPIRATION": (
        False,
        "JWT_VERIFY_EXPIRATION = False accepts expired JWTs.",
    ),
}

PHANTOM_SECURITY_NAMES = {
    "sanitize_input",
    "sanitize_html",
    "sanitize_sql",
    "sanitize_query",
    "sanitize_string",
    "sanitize_data",
    "sanitize_url",
    "sanitize_path",
    "sanitize_file_path",
    "sanitize_filename",
    "sanitize_output",
    "sanitize_request",
    "sanitize_params",
    "sanitize_user_input",
    "validate_token",
    "validate_jwt",
    "validate_session",
    "validate_auth",
    "validate_credentials",
    "validate_api_key",
    "validate_permissions",
    "validate_file_upload",
    "validate_redirect_url",
    "validate_origin",
    "escape_html",
    "escape_sql",
    "escape_input",
    "escape_output",
    "escape_string",
    "escape_query",
    "check_permission",
    "check_permissions",
    "check_auth",
    "check_authorization",
    "check_access",
    "check_role",
    "check_csrf",
    "verify_token",
    "verify_jwt",
    "verify_signature",
    "verify_auth",
    "verify_api_key",
    "verify_csrf",
    "require_auth",
    "require_login",
    "require_admin",
    "require_permission",
    "ensure_authenticated",
    "ensure_authorized",
    "enforce_rbac",
    "encrypt_password",
    "hash_password",
    "secure_random",
    "safe_join",
    "safe_eval",
    "safe_deserialize",
    "clean_input",
    "clean_html",
    "clean_data",
    "filter_xss",
    "prevent_injection",
    "prevent_xss",
    "mask_pii",
    "redact_secrets",
    "rate_limit",
    "throttle_request",
}

PHANTOM_SECURITY_DECORATORS = {
    "requires_auth",
    "requires_admin",
    "requires_permission",
    "requires_role",
    "require_auth",
    "require_login",
    "login_required",
    "require_permission",
    "require_permissions",
    "require_admin",
    "require_role",
    "admin_required",
    "permission_required",
    "check_auth",
    "check_access",
    "check_permission",
    "check_permissions",
    "authenticate",
    "authorize",
    "authorized",
    "validate_jwt",
    "validate_origin",
    "verify_token",
    "verify_jwt",
    "verify_csrf",
    "jwt_required",
    "rate_limit",
    "rate_limiter",
    "throttle",
    "throttle_request",
    "sanitize_input",
    "csrf_protect",
    "csrf_required",
    "cors_protect",
    "secure",
    "secured",
    "secure_endpoint",
    "permissions_required",
    "roles_required",
    "roles_accepted",
    "auth_required",
    "token_required",
    "api_key_required",
    "enforce_rbac",
}

WELL_KNOWN_ENV_VARS = {
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "LANG",
    "TERM",
    "PWD",
    "EDITOR",
    "VIRTUAL_ENV",
    "PYTHONPATH",
    "PYTHONDONTWRITEBYTECODE",
    "CI",
    "DEBUG",
    "LOG_LEVEL",
    "TESTING",
    "ENV",
    "ENVIRONMENT",
    "APP_ENV",
    "NODE_ENV",
    "FLASK_ENV",
    "DJANGO_SETTINGS_MODULE",
    "DATABASE_URL",
    "REDIS_URL",
    "SECRET_KEY",
    "PORT",
    "HOST",
    "BIND",
}

SECURITY_VAR_KEYWORDS = {
    "token",
    "secret",
    "key",
    "password",
    "nonce",
    "session",
    "cookie",
    "otp",
    "totp",
    "mfa",
    "sso",
    "salt",
    "csrf",
    "auth",
    "jwt",
    "hmac",
    "signature",
    "code",
    "pin",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "reset_token",
    "verification",
    "confirm",
}

INSECURE_RANDOM_FUNCS = {
    "randint",
    "choice",
    "choices",
    "random",
    "randrange",
    "sample",
    "shuffle",
    "randbytes",
    "getrandbits",
    "uniform",
}

CREDENTIAL_VAR_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "auth_token",
    "access_token",
    "refresh_token",
    "db_password",
    "database_url",
    "connection_string",
    "db_url",
    "dsn",
    "private_key",
    "secret_key",
    "encryption_key",
    "signing_key",
    "session_secret",
    "jwt_secret",
    "oauth_client_secret",
    "client_secret",
    "app_secret",
    "webhook_secret",
    "slack_signing_secret",
    "stripe_secret_key",
    "openai_api_key",
    "anthropic_api_key",
}

CREDENTIAL_VAR_SUFFIXES = {
    "_password",
    "_passwd",
    "_secret",
    "_token",
    "_key",
    "_api_key",
    "_apikey",
    "_private_key",
    "_signing_secret",
    "_webhook_secret",
}

PLACEHOLDER_VALUES = {
    "changeme",
    "change_me",
    "your_api_key_here",
    "replace_me",
    "todo",
    "xxx",
    "yyy",
    "zzz",
    "placeholder",
    "example",
    "test",
    "dummy",
    "fake",
    "sample",
    "password",
    "secret",
    "admin",
    "letmein",
    "your_password_here",
    "insert_key_here",
    "your_secret_here",
}

SENSITIVE_FILE_KEYWORDS = {
    ".env",
    ".pem",
    ".key",
    ".cert",
    ".crt",
    ".p12",
    ".pfx",
    "credentials",
    "secrets",
    "private",
    "id_rsa",
    "id_ed25519",
    "service_account",
    "kubeconfig",
    "keyfile",
    "keystore",
}

NETWORK_TIMEOUT_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.options",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.head",
    "httpx.options",
    "urllib.request.urlopen",
    "urlopen",
}


@dataclass(frozen=True)
class VibeDictionary:
    disabled_security_patterns: dict[str, str]
    dangerous_calls: dict[str, str | None]
    dangerous_decorators: dict[str, str]
    dangerous_assignments: dict[str, tuple[Any, str | None]]
    phantom_security_names: frozenset[str]
    phantom_security_decorators: frozenset[str]
    well_known_env_vars: frozenset[str]
    security_var_keywords: frozenset[str]
    insecure_random_funcs: frozenset[str]
    credential_var_names: frozenset[str]
    credential_var_suffixes: frozenset[str]
    placeholder_values: frozenset[str]
    sensitive_file_keywords: frozenset[str]
    network_timeout_calls: frozenset[str]


DEFAULT_VIBE_DICTIONARY = VibeDictionary(
    disabled_security_patterns=dict(DISABLED_SECURITY_PATTERNS),
    dangerous_calls=dict(DANGEROUS_CALLS),
    dangerous_decorators=dict(DANGEROUS_DECORATORS),
    dangerous_assignments=dict(DANGEROUS_ASSIGNMENTS),
    phantom_security_names=frozenset(PHANTOM_SECURITY_NAMES),
    phantom_security_decorators=frozenset(PHANTOM_SECURITY_DECORATORS),
    well_known_env_vars=frozenset(WELL_KNOWN_ENV_VARS),
    security_var_keywords=frozenset(SECURITY_VAR_KEYWORDS),
    insecure_random_funcs=frozenset(INSECURE_RANDOM_FUNCS),
    credential_var_names=frozenset(CREDENTIAL_VAR_NAMES),
    credential_var_suffixes=frozenset(CREDENTIAL_VAR_SUFFIXES),
    placeholder_values=frozenset(PLACEHOLDER_VALUES),
    sensitive_file_keywords=frozenset(SENSITIVE_FILE_KEYWORDS),
    network_timeout_calls=frozenset(NETWORK_TIMEOUT_CALLS),
)


_SET_OVERLAYS = {
    "extra_phantom_names": "phantom_security_names",
    "extra_phantom_decorators": "phantom_security_decorators",
    "extra_well_known_env_vars": "well_known_env_vars",
    "extra_security_var_keywords": "security_var_keywords",
    "extra_insecure_random_funcs": "insecure_random_funcs",
    "extra_credential_names": "credential_var_names",
    "extra_secret_names": "credential_var_names",
    "extra_credential_suffixes": "credential_var_suffixes",
    "extra_placeholder_values": "placeholder_values",
    "extra_sensitive_file_keywords": "sensitive_file_keywords",
    "extra_network_timeout_calls": "network_timeout_calls",
}


def build_vibe_dictionary(config: dict[str, Any] | None = None) -> VibeDictionary:
    """Return the default vibe dictionary plus user-configured extensions."""
    if not isinstance(config, dict):
        return DEFAULT_VIBE_DICTIONARY

    values: dict[str, Any] = {}
    for config_key, field_name in _SET_OVERLAYS.items():
        extras = _string_list(config.get(config_key))
        if not extras:
            continue
        current = set(getattr(DEFAULT_VIBE_DICTIONARY, field_name))
        current.update(extras)
        values[field_name] = frozenset(current)

    return replace(DEFAULT_VIBE_DICTIONARY, **values)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, (list, tuple, set)):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]
