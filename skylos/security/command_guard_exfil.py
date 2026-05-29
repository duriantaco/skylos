from __future__ import annotations

import re
from collections.abc import Iterator

from skylos.security.command_guard_parse import (
    command_name,
    split_option,
    tokens_start_with,
)
from skylos.security.command_guard_paths import (
    has_external_destination,
    is_external_url,
    is_sensitive_path,
    looks_like_remote_host,
)
from skylos.security.command_guard_types import (
    DATA_EXFIL_RULE,
    DESTRUCTIVE_RULE,
    REMOTE_SCRIPT_RULE,
    CommandRisk,
)


ENV_DUMP_COMMANDS = {"printenv", "set", "declare", "typeset"}
TOKEN_COMMAND_PREFIXES = (
    ("gh", "auth", "token"),
    ("gcloud", "auth", "print-access-token"),
    ("op", "item", "get"),
    ("npm", "token"),
)
SENSITIVE_READERS = {
    "awk",
    "base64",
    "cat",
    "grep",
    "head",
    "less",
    "more",
    "rg",
    "sed",
    "tail",
    "tar",
    "zip",
}
NETWORK_COMMANDS = {
    "curl",
    "ftp",
    "nc",
    "ncat",
    "netcat",
    "rsync",
    "scp",
    "sftp",
    "socat",
    "ssh",
    "wget",
}
SHELL_INTERPRETERS = {
    "bash",
    "dash",
    "ksh",
    "node",
    "perl",
    "python",
    "python3",
    "ruby",
    "sh",
    "zsh",
}
CURL_UPLOAD_FLAGS = {
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--form",
    "--form-string",
    "--upload-file",
    "-d",
    "-F",
    "-T",
}
WGET_UPLOAD_FLAGS = {
    "--body-data",
    "--body-file",
    "--post-data",
    "--post-file",
}
SECRET_ENV_RE = re.compile(
    r"\$(?:\{)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:SECRET|TOKEN|PASSWORD|PASS|API_KEY|PRIVATE_KEY|ACCESS_KEY|"
    r"CREDENTIAL|CREDENTIALS|OAUTH)"
    r"[A-Za-z0-9_]*(?:\})?",
    re.I,
)
REMOTE_EXEC_RE = re.compile(
    r"\b(?:bash|dash|ksh|sh|zsh|python3?|node|ruby|perl)\b"
    r"[^;&|]*\$\(\s*(?:curl|wget)\b[^)]*https?://",
    re.I,
)
REVERSE_SHELL_PATTERNS = (
    re.compile(r"/dev/tcp/[^/\s]+/\d+", re.I),
    re.compile(r"\b(?:nc|ncat|netcat)\b[^;&|]*\s-e\s+(?:/bin/)?(?:ba)?sh\b", re.I),
    re.compile(r"\bsocat\b[^;&|]*\bexec:(?:/bin/)?(?:ba)?sh\b", re.I),
)
DESTRUCTIVE_PATTERNS = (
    re.compile(
        r"\brm\s+"
        r"(?:-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*)"
        r"\s+(?:/|~(?:/|\s|$)|\$HOME(?:/|\s|$)|\.git(?:/|\s|$))",
        re.I,
    ),
    re.compile(r"\bgit\s+clean\s+-(?=[A-Za-z]*f)(?=[A-Za-z]*d)(?=[A-Za-z]*x)[A-Za-z]+\b", re.I),
    re.compile(r"\bgit\s+reset\s+--hard\b", re.I),
)


def command_risks(command: str) -> Iterator[CommandRisk]:
    if REMOTE_EXEC_RE.search(command):
        yield REMOTE_SCRIPT_RULE
    if any(pattern.search(command) for pattern in REVERSE_SHELL_PATTERNS):
        yield DATA_EXFIL_RULE
    if any(pattern.search(command) for pattern in DESTRUCTIVE_PATTERNS):
        yield DESTRUCTIVE_RULE


def pipeline_risks(pipeline: list[list[str]]) -> Iterator[CommandRisk]:
    if _pipeline_has_data_exfil(pipeline):
        yield DATA_EXFIL_RULE
    if _pipeline_has_remote_script_execution(pipeline):
        yield REMOTE_SCRIPT_RULE
    if any(_network_sink_reads_sensitive_file(tokens) for tokens in pipeline):
        yield DATA_EXFIL_RULE
    if any(_network_sink_sends_secret_env(tokens) for tokens in pipeline):
        yield DATA_EXFIL_RULE


def _pipeline_has_data_exfil(pipeline: list[list[str]]) -> bool:
    seen_sensitive = False
    for tokens in pipeline:
        if _is_sensitive_source(tokens):
            seen_sensitive = True
            continue
        if seen_sensitive and _is_network_upload_sink(tokens):
            return True
    return False


def _pipeline_has_remote_script_execution(pipeline: list[list[str]]) -> bool:
    seen_remote_fetch = False
    for tokens in pipeline:
        if _is_remote_fetch(tokens):
            seen_remote_fetch = True
            continue
        if seen_remote_fetch and command_name(tokens) in SHELL_INTERPRETERS:
            return True
    return False


def _is_sensitive_source(tokens: list[str]) -> bool:
    name = command_name(tokens)
    return (
        _is_env_dump_source(name, tokens)
        or _is_token_source(tokens)
        or _reads_sensitive_path(name, tokens)
    )


def _is_network_upload_sink(tokens: list[str]) -> bool:
    name = command_name(tokens)
    if name not in NETWORK_COMMANDS or not has_external_destination(tokens):
        return False
    if name in {"nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "ftp", "rsync"}:
        return True
    return (name == "curl" and _curl_uploads_data(tokens)) or (
        name == "wget" and _wget_uploads_data(tokens)
    )


def _network_sink_reads_sensitive_file(tokens: list[str]) -> bool:
    name = command_name(tokens)
    if not has_external_destination(tokens):
        return False
    if name == "curl":
        return _curl_reads_sensitive_file(tokens)
    if name == "wget":
        return _wget_reads_sensitive_file(tokens)
    if name in {"scp", "sftp", "rsync"}:
        return _copy_reads_sensitive_file(tokens)
    return False


def _network_sink_sends_secret_env(tokens: list[str]) -> bool:
    name = command_name(tokens)
    if name not in NETWORK_COMMANDS or not has_external_destination(tokens):
        return False
    return any(_contains_secret_env_ref(token) for token in tokens[1:])


def _is_remote_fetch(tokens: list[str]) -> bool:
    name = command_name(tokens)
    if name not in {"curl", "wget"}:
        return False
    return any(is_external_url(token) for token in tokens[1:])


def _curl_uploads_data(tokens: list[str]) -> bool:
    return any(
        _curl_upload_value_reads_stdin(flag, value or _next_token(tokens, idx))
        for idx, token in enumerate(tokens)
        for flag, value in [split_option(token)]
        if flag in CURL_UPLOAD_FLAGS
    )


def _wget_uploads_data(tokens: list[str]) -> bool:
    return any(
        _wget_value_reads_stdin(value or _next_token(tokens, idx))
        for idx, token in enumerate(tokens)
        for flag, value in [split_option(token)]
        if flag in WGET_UPLOAD_FLAGS
    )


def _curl_upload_value_reads_stdin(flag: str, value: str) -> bool:
    if flag in {"-T", "--upload-file"}:
        return value in {"-", "@-"}
    if flag in {"-F", "--form", "--form-string"}:
        return value == "@-" or "=@-" in value
    return value == "@-"


def _env_command_dumps_environment(tokens: list[str]) -> bool:
    idx = 1
    while idx < len(tokens):
        token = tokens[idx]
        if "=" in token and not token.startswith(("/", "./", "$")):
            idx += 1
        elif token in {"-0", "-i"} or token.startswith("-"):
            idx += 1
        elif token in {"-C", "-S", "-u"}:
            idx += 2
        else:
            return False
    return True


def _is_env_dump_source(name: str, tokens: list[str]) -> bool:
    if not name:
        return False
    if name in ENV_DUMP_COMMANDS:
        return True
    if name == "export" and len(tokens) == 1:
        return True
    return name == "env" and _env_command_dumps_environment(tokens)


def _is_token_source(tokens: list[str]) -> bool:
    if tokens_start_with(tokens, ("aws", "configure", "get")):
        return any("secret" in token.lower() or "token" in token.lower() for token in tokens[3:])
    return any(tokens_start_with(tokens, prefix) for prefix in TOKEN_COMMAND_PREFIXES)


def _reads_sensitive_path(name: str, tokens: list[str]) -> bool:
    return name in SENSITIVE_READERS and any(is_sensitive_path(token) for token in tokens[1:])


def _curl_reads_sensitive_file(tokens: list[str]) -> bool:
    return any(
        is_sensitive_path(value or _next_token(tokens, idx))
        for idx, token in enumerate(tokens)
        for flag, value in [split_option(token)]
        if flag in CURL_UPLOAD_FLAGS
    )


def _wget_reads_sensitive_file(tokens: list[str]) -> bool:
    return any(
        is_sensitive_path(value or _next_token(tokens, idx))
        for idx, token in enumerate(tokens)
        for flag, value in [split_option(token)]
        if flag in WGET_UPLOAD_FLAGS
    )


def _copy_reads_sensitive_file(tokens: list[str]) -> bool:
    return any(is_sensitive_path(token) for token in tokens[1:]) and any(
        looks_like_remote_host(token) or is_external_url(token) for token in tokens[1:]
    )


def _contains_secret_env_ref(value: str) -> bool:
    return bool(SECRET_ENV_RE.search(value))


def _wget_value_reads_stdin(value: str) -> bool:
    return value in {"-", "@-"} or value.endswith("=-")


def _next_token(tokens: list[str], idx: int) -> str:
    return tokens[idx + 1] if idx + 1 < len(tokens) else ""
