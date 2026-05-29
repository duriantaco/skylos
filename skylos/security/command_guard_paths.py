from __future__ import annotations

import re


LOCAL_HOST_RE = re.compile(
    r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:/|$)",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s'\"`)$]+", re.I)


def is_sensitive_path(value: str) -> bool:
    text = strip_shell_file_marker(value).strip().strip("'\"")
    if not text:
        return False

    lowered = text.lower().replace("\\", "/")
    basename = lowered.rsplit("/", 1)[-1]
    return (
        _is_sensitive_basename(basename)
        or basename.endswith((".key", ".pem", ".p12", ".pfx"))
        or _contains_sensitive_path_marker(lowered)
    )


def is_external_url(value: str) -> bool:
    match = URL_RE.search(value)
    if not match:
        return False
    return LOCAL_HOST_RE.match(match.group(0)) is None


def looks_like_remote_host(token: str) -> bool:
    if token.startswith(("-", "@")):
        return False
    if "@" in token and ":" in token:
        return True
    return ":" in token and not token.startswith(("./", "/", "~"))


def has_external_destination(tokens: list[str]) -> bool:
    for token in tokens[1:]:
        if URL_RE.search(token):
            if is_external_url(token):
                return True
            continue
        if looks_like_remote_host(token):
            return True
    return False


def strip_shell_file_marker(value: str) -> str:
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if value.startswith("@"):
        value = value[1:]
    return value


def _is_sensitive_basename(basename: str) -> bool:
    if basename == ".env" or basename.startswith(".env."):
        return True
    if basename.endswith(".env"):
        return True
    return basename in {
        ".envrc",
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "auth.json",
        "config.json",
        "credentials",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
    }


def _contains_sensitive_path_marker(lowered: str) -> bool:
    return any(
        marker in lowered
        for marker in (
            "/.aws/",
            "/.azure/",
            "/.claude/",
            "/.codex/",
            "/.config/gh/",
            "/.docker/config.json",
            "/.kube/",
            "/.ssh/",
            "/run/secrets/",
            "~/.aws/",
            "~/.azure/",
            "~/.claude/",
            "~/.codex/",
            "~/.config/gh/",
            "~/.docker/config.json",
            "~/.kube/",
            "~/.ssh/",
        )
    )
