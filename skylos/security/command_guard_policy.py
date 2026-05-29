from __future__ import annotations

import re
from collections.abc import Iterator

from skylos.security.command_guard_exfil import SENSITIVE_READERS
from skylos.security.command_guard_parse import command_name, tokens_start_with
from skylos.security.command_guard_paths import is_sensitive_path
from skylos.security.command_guard_types import (
    PACKAGE_REGISTRY_RULE,
    PERSISTENT_MUTATION_RULE,
    PUBLISH_RULE,
    SCOPE_VIOLATION_RULE,
    UNTRUSTED_TOOL_RULE,
    CommandRisk,
)


PROFILE_WRITE_RE = re.compile(
    r"(?:>>?|tee\s+-a)\s+(?:~|\$HOME|\$\{HOME\})/"
    r"\.(?:bashrc|bash_profile|zshrc|zprofile|profile|config/fish/config\.fish)\b",
    re.I,
)
PACKAGE_SETUP_SCRIPT_NAMES = {"bootstrap", "install", "postinstall", "prepare", "setup"}
PUBLISH_COMMAND_PREFIXES = (
    ("cargo", "publish"),
    ("docker", "push"),
    ("gem", "push"),
    ("helm", "push"),
    ("maturin", "publish"),
    ("npm", "publish"),
    ("pnpm", "publish"),
    ("twine", "upload"),
)


def token_policy_risks(tokens: list[str]) -> Iterator[CommandRisk]:
    if _is_package_registry_override(tokens):
        yield PACKAGE_REGISTRY_RULE
    if _is_sensitive_scope_access(tokens):
        yield SCOPE_VIOLATION_RULE
    if _is_persistent_mutation(tokens):
        yield PERSISTENT_MUTATION_RULE
    if _is_publish_command(tokens):
        yield PUBLISH_RULE
    if _is_untrusted_package_tool_execution(tokens):
        yield UNTRUSTED_TOOL_RULE


def command_policy_risks(command: str) -> Iterator[CommandRisk]:
    if PROFILE_WRITE_RE.search(command):
        yield PERSISTENT_MUTATION_RULE


def _is_package_registry_override(tokens: list[str]) -> bool:
    name = command_name(tokens)
    if name in {"pip", "pip3"}:
        return _tokens_include_registry(tokens[1:])
    if _is_python_pip_command(tokens):
        return _tokens_include_registry(tokens[3:])
    if name in {"npm", "pnpm", "yarn"}:
        lowered = [token.lower() for token in tokens[1:]]
        return "registry" in lowered or any(token.startswith("--registry") for token in tokens[1:])
    return name == "gem" and any(token.startswith("--source") for token in tokens[1:])


def _is_sensitive_scope_access(tokens: list[str]) -> bool:
    name = command_name(tokens)
    if name in SENSITIVE_READERS and any(is_sensitive_path(token) for token in tokens[1:]):
        return True
    return (
        name == "docker"
        and len(tokens) > 1
        and tokens[1] == "run"
        and _docker_run_mounts_host_root(tokens)
    )


def _is_persistent_mutation(tokens: list[str]) -> bool:
    name = command_name(tokens)
    if name == "crontab":
        return True
    if _is_service_persistence_command(name, tokens):
        return True
    if _is_package_config_set(name, tokens):
        return True
    return name == "git" and len(tokens) >= 4 and tokens[1] == "config" and "--global" in tokens[2:]


def _is_publish_command(tokens: list[str]) -> bool:
    if any(tokens_start_with(tokens, prefix) for prefix in PUBLISH_COMMAND_PREFIXES):
        return True
    return tokens_start_with(tokens, ("yarn", "npm", "publish"))


def _is_untrusted_package_tool_execution(tokens: list[str]) -> bool:
    name = command_name(tokens)
    if name == "npx":
        return "-y" in tokens[1:] or "--yes" in tokens[1:] or _uses_latest_tag(tokens)
    if name == "npm":
        return _is_npm_tool_execution(tokens)
    if name == "pnpm":
        return _is_pnpm_tool_execution(tokens)
    return name == "yarn" and _is_yarn_tool_execution(tokens)


def _docker_run_mounts_host_root(tokens: list[str]) -> bool:
    return any(_mount_value_exposes_root(value) for value in _iter_docker_mount_values(tokens))


def _iter_docker_mount_values(tokens: list[str]) -> Iterator[str]:
    for idx, token in enumerate(tokens):
        if token in {"-v", "--volume", "--mount"} and idx + 1 < len(tokens):
            yield tokens[idx + 1]
        elif token.startswith("-v") and len(token) > 2:
            yield token[2:]
        elif token.startswith("--volume=") or token.startswith("--mount="):
            yield token.split("=", 1)[1]


def _mount_value_exposes_root(value: str) -> bool:
    lowered = value.lower()
    if lowered.startswith("/:") or lowered.startswith("/:/"):
        return True
    return any(part in {"source=/", "src=/", "from=/"} for part in lowered.split(","))


def _tokens_include_registry(tokens: list[str]) -> bool:
    return any(token.startswith(("--extra-index-url", "--index-url")) for token in tokens)


def _is_python_pip_command(tokens: list[str]) -> bool:
    return tokens_start_with(tokens, ("python", "-m", "pip")) or tokens_start_with(
        tokens, ("python3", "-m", "pip")
    )


def _is_service_persistence_command(name: str, tokens: list[str]) -> bool:
    return name in {"launchctl", "systemctl"} and any(
        token in {"enable", "load", "bootstrap"} for token in tokens[1:]
    )


def _is_package_config_set(name: str, tokens: list[str]) -> bool:
    if name in {"npm", "pnpm", "yarn", "pip", "pip3"} and len(tokens) >= 4:
        return tokens[1:3] == ["config", "set"]
    return tokens_start_with(tokens, ("python", "-m", "pip", "config", "set")) or (
        tokens_start_with(tokens, ("python3", "-m", "pip", "config", "set"))
    )


def _is_npm_tool_execution(tokens: list[str]) -> bool:
    if len(tokens) < 2:
        return False
    if tokens[1] == "exec" and ("-y" in tokens[2:] or "--yes" in tokens[2:]):
        return True
    return len(tokens) >= 3 and tokens[1] == "run" and _is_setup_script(tokens[2])


def _is_pnpm_tool_execution(tokens: list[str]) -> bool:
    if len(tokens) < 2:
        return False
    return tokens[1] == "dlx" or (
        len(tokens) >= 3 and tokens[1] == "run" and _is_setup_script(tokens[2])
    )


def _is_yarn_tool_execution(tokens: list[str]) -> bool:
    return bool(tokens[1:]) and (tokens[1] == "dlx" or _is_setup_script(tokens[1]))


def _is_setup_script(value: str) -> bool:
    return value.lower() in PACKAGE_SETUP_SCRIPT_NAMES


def _uses_latest_tag(tokens: list[str]) -> bool:
    return any(token.endswith("@latest") for token in tokens[1:])
