from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from fnmatch import fnmatchcase

from skylos.security.command_guard_exfil import SENSITIVE_READERS
from skylos.security.command_guard_parse import (
    command_name,
    split_redirects,
    tokens_start_with,
)
from skylos.security.command_guard_paths import (
    glob_could_match,
    has_glob,
    is_sensitive_path,
)
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
# Redirect targets that make a write persist as a backdoor (SKY-D339): remote
# login keys and login hooks, shell startup files, schedulers, services, sudo
# rules, preloaded libraries. A glob that could name one of them counts too.
PERSISTENCE_FILE_NAMES = {
    ".bash_login",
    ".bash_profile",
    ".bashrc",
    ".profile",
    ".zlogin",
    ".zprofile",
    ".zshenv",
    ".zshrc",
    "authorized_keys",
    "authorized_keys2",
}
# sshd runs ~/.ssh/rc and loads ~/.ssh/environment at every login.
SSH_LOGIN_FILE_NAMES = {"environment", "rc"}
PERSISTENCE_PATHS = (
    "/etc/bash.bashrc",
    "/etc/crontab",
    "/etc/environment",
    "/etc/ld.so.preload",
    "/etc/profile",
    "/etc/rc.local",
    "/etc/sudoers",
    "/etc/zsh/",
    "/etc/zshrc",
)
PERSISTENCE_DIRS = (
    "/etc/cron",
    "/etc/init.d/",
    "/etc/profile.d/",
    "/etc/sudoers.d/",
    "/etc/systemd/",
    "/lib/systemd/",
    "/usr/lib/systemd/",
    "/var/spool/cron/",
    "/.config/autostart/",
    "/.config/fish/",
    "/.config/systemd/",
)
# The only sensitive paths (is_sensitive_path) a redirect may write without a
# SKY-D338 report: routine CI and Docker credential setup. Default-deny: every
# other sensitive target stays reported, including files that run code or
# steer authentication or installs (~/.ssh/config, ~/.aws/config,
# ~/.kube/config, ~/.npmrc, ~/.claude/settings.json, ~/.docker/config.json,
# /run/secrets/...) and certificates, which can land in a trust store. A
# target holding "..", a glob, a variable other than a leading $HOME, or a
# command substitution never matches. Scopes (scan_shell_command decides
# which apply to a script): "home" is a path under the home directory (~,
# $HOME, /root, /home/<user>) unless HOME is reassigned; "project" is a
# relative path (no leading "/", "~" or "$") in a script the caller knows
# starts in the project and that cannot change directory.
ROUTINE_CREDENTIAL_WRITES = (
    ("home", ".ssh/known_hosts"),
    ("home", ".ssh/id_*"),
    ("home", ".netrc"),
    ("home", ".pypirc"),
    ("project", ".env"),
)
# Case-sensitive: "$home" and "${Home}" are other variables.
HOME_VARIABLE_PREFIXES = ("$HOME/", "${HOME}/")
# Reserved words and grouping that can precede a command ("then cat ~/.netrc").
SHELL_KEYWORDS = {"!", "{", "do", "elif", "else", "if", "then", "until", "while"}
SYSTEM_HOME_RE = re.compile(r"(?:/root|/home/(?!\.{1,2}/)[^/$`]+)/")
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


def token_policy_risks(
    tokens: list[str],
    command: str | None = None,
    *,
    routine_scopes: frozenset[str] = frozenset(),
) -> Iterator[CommandRisk]:
    words, writes = split_redirects(command) if command is not None else ([], [])
    if _is_package_registry_override(tokens):
        yield PACKAGE_REGISTRY_RULE
    if _is_sensitive_scope_access(
        _command_words(words or tokens), writes, routine_scopes
    ):
        yield SCOPE_VIOLATION_RULE
    if _is_persistent_mutation(tokens) or any(
        _is_persistence_target(target) for target in writes
    ):
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


def _command_words(words: list[str]) -> list[str]:
    # Skip reserved words and a function header: "f() { cat ~/.netrc".
    idx = 0
    while idx < len(words):
        if words[idx] in SHELL_KEYWORDS or words[idx].endswith("()"):
            idx += 1
        elif words[idx] == "function":
            idx += 2
        else:
            break
    return words[idx:]


def _home_path(path: str, *, system_homes: bool = False) -> str:
    for home in HOME_VARIABLE_PREFIXES:
        if path.startswith(home):
            return "~/" + path[len(home) :]
    match = SYSTEM_HOME_RE.match(path) if system_homes else None
    return "~/" + path[match.end() :] if match else path


def _is_persistence_target(target: str) -> bool:
    lowered = _home_path(target.strip().replace("\\", "/")).lower()
    # "/etc//cron.d", "/etc/./sudoers" and "/tmp/../etc/sudoers" name the same
    # files, so the lexically normalised path is checked as well.
    collapsed = re.sub(r"/{2,}", "/", lowered)
    normalised = posixpath.normpath(collapsed) if collapsed else collapsed
    return any(_is_persistence_path(path) for path in (lowered, normalised))


def _is_persistence_path(lowered: str) -> bool:
    parts = [part for part in lowered.split("/") if part]
    if not parts:
        return False
    if any(glob_could_match(parts[-1], name) for name in PERSISTENCE_FILE_NAMES):
        return True
    if (
        len(parts) > 1
        and glob_could_match(parts[-2], ".ssh")
        and any(glob_could_match(parts[-1], name) for name in SSH_LOGIN_FILE_NAMES)
    ):
        return True
    absolute = "/" + lowered.lstrip("~/") if lowered.startswith("~") else lowered
    if any(
        glob_could_match(absolute, path, starts=True) for path in PERSISTENCE_PATHS
    ) or any(
        glob_could_match(absolute, marker, contains=True) for marker in PERSISTENCE_DIRS
    ):
        return True
    return _is_global_git_hook(lowered, parts)


def _is_global_git_hook(lowered: str, parts: list[str]) -> bool:
    # Git hooks outside the project (global templates) run for every
    # repository on the host; a project's own .git/hooks are its setup.
    outside_project = lowered.startswith(("/", "~", "$")) or any(
        glob_could_match(part, "..") for part in parts
    )
    return outside_project and any(
        glob_could_match(part, "hooks")
        and any(
            glob_could_match(parent, "git", contains=True)
            for parent in parts[max(0, i - 2) : i]
        )
        for i, part in enumerate(parts[:-1])
    )


def _is_routine_credential_write(target: str, scopes: frozenset[str]) -> bool:
    # No .strip(): an escaped trailing space is part of the file name, and a
    # backslash (an escape the parser could not resolve) never matches.
    if not scopes or "\\" in target:
        return False
    # ".." can leave the home directory or the project; it is checked before
    # /home/<user>/ is rewritten to "~/" so "/home/../etc" cannot pass as home.
    if ".." in target.split("/"):
        return False
    path = _home_path(target, system_homes=True).lower()
    if has_glob(path) or "$" in path or "`" in path:
        return False
    parts = [part for part in path.split("/") if part not in {"", "."}]
    return bool(parts) and any(
        _matches_routine_write(scope, pattern, path, parts)
        for scope, pattern in ROUTINE_CREDENTIAL_WRITES
        if scope in scopes
    )


def _matches_routine_write(
    scope: str, pattern: str, path: str, parts: list[str]
) -> bool:
    if scope == "home":
        wanted = pattern.split("/")
        return (
            path.startswith("~/")
            and len(parts) == len(wanted) + 1
            and all(fnmatchcase(part, want) for part, want in zip(parts[1:], wanted))
        )
    return not path.startswith(("/", "~")) and fnmatchcase(parts[-1], pattern)


def _writes_sensitive_target(target: str, scopes: frozenset[str]) -> bool:
    # A persistence target that is also sensitive (~/.ssh/authorized_keys)
    # keeps this CRITICAL report beside SKY-D339.
    return is_sensitive_path(target) and not _is_routine_credential_write(
        target, scopes
    )


def _is_sensitive_scope_access(
    tokens: list[str], writes: list[str], scopes: frozenset[str]
) -> bool:
    name = command_name(tokens)
    if name in SENSITIVE_READERS and (
        any(is_sensitive_path(token) for token in tokens[1:])
        or any(_writes_sensitive_target(target, scopes) for target in writes)
    ):
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
    publishes = any(
        tokens_start_with(tokens, prefix) for prefix in PUBLISH_COMMAND_PREFIXES
    ) or tokens_start_with(tokens, ("yarn", "npm", "publish"))
    return publishes and not _requests_dry_run(tokens)


def _requests_dry_run(tokens: list[str]) -> bool:
    """The last dry-run setting before ``--`` wins, as in npm, pnpm and cargo.

    ``--dry-run`` followed by ``false`` (npm's boolean value form),
    ``--dry-run=<anything but true>`` and ``--no-dry-run`` still publish.
    A tool without the flag rejects it instead of uploading.
    """
    options = tokens
    if "--" in tokens:
        options = tokens[: tokens.index("--")]
    dry_run = False
    for index, token in enumerate(options):
        if token == "--dry-run":
            following = ""
            if index + 1 < len(options):
                following = options[index + 1].lower()
            dry_run = following != "false"
        elif token.startswith("--dry-run="):
            dry_run = token == "--dry-run=true"
        elif token == "--no-dry-run":
            dry_run = False
    return dry_run


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
