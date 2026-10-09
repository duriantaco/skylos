from __future__ import annotations

import re
import shlex
from collections.abc import Iterator

from skylos.security.command_guard_parse import (
    _split_shell_on,
    command_name,
    shell_tokens,
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
        r"\bgit\s+clean\s+-(?=[A-Za-z]*f)(?=[A-Za-z]*d)(?=[A-Za-z]*x)[A-Za-z]+\b", re.I
    ),
    re.compile(r"\bgit\s+reset\s+--hard\b", re.I),
)
REDIRECT_RE = re.compile(r"\d*(?:>>?|<)")
# Wiping the working directory: ``rm -rf .``, ``rm -rf *``, ``rm -rf ./*``.
CWD_WIPE_TARGETS = {".", "./", "..", "../", "*", ".*", "./*", "../*"}
# ``$DIR/`` or ``${DIR}/*``: an empty variable turns it into ``/`` or ``/*``.
EMPTY_VAR_ROOT_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/\**$")
HOME_PREFIXES = ("/root/", "~/", "$HOME/", "${HOME}/")
# Package-manager caches and scratch space that builds remove to slim an
# image (``pip install ... && rm -rf /root/.cache/pip``).
CACHE_DIRS_UNDER_HOME = (".cache", ".npm")
DISPOSABLE_ROOTS = (
    "/tmp/",
    "/var/tmp/",
    "/var/cache/",
    "/var/lib/apt/lists/",
    "/usr/local/share/.cache/",
)


def command_risks(command: str) -> Iterator[CommandRisk]:
    if REMOTE_EXEC_RE.search(command):
        yield REMOTE_SCRIPT_RULE
    if any(pattern.search(command) for pattern in REVERSE_SHELL_PATTERNS):
        yield DATA_EXFIL_RULE
    if _has_broad_rm(command) or any(
        pattern.search(command) for pattern in DESTRUCTIVE_PATTERNS
    ):
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


def _has_broad_rm(command: str, *, _depth: int = 0) -> bool:
    # Keep quoted/escaped separators inside their operand, and join shell
    # continuations before deciding whether a cache path is bounded.
    command = _rm_without_comments(command).replace("\\\n", "")
    if any(
        _rm_nested_risk(script, _depth) for script in _rm_substituted_scripts(command)
    ):
        return True
    for statement in _split_shell_on(
        command, {";", "&&", "&", "||", "|", "\n", "(", ")"}
    ):
        try:
            tokens = shlex.split(statement, comments=False, posix=True)
        except ValueError:
            tokens = shell_tokens(statement)
        tokens = _rm_executable_tokens(tokens)
        if not tokens:
            continue
        name = _rm_known_command_name(tokens[0])
        if tokens[0].rsplit("/", 1)[-1] == "rm":
            name = "rm"
        if name == "rm":
            recursive = forced = False
            options_done = False
            for option in tokens[1:]:
                if options_done:
                    continue
                if option == "--":
                    options_done = True
                elif option == "--recursive":
                    recursive = True
                elif option == "--force":
                    forced = True
                elif option.startswith("-") and not option.startswith("--"):
                    recursive |= "r" in option or "R" in option
                    forced |= "f" in option
            if (
                recursive
                and forced
                and any(
                    _is_broad_rm_target(target) for target in _rm_targets(tokens[1:])
                )
            ):
                return True
        elif name == "find":
            for offset, token in enumerate(tokens):
                if token not in {"-exec", "-execdir"}:
                    continue
                end = offset + 1
                while end < len(tokens) and tokens[end] not in {";", "+"}:
                    end += 1
                if _rm_nested_risk(shlex.join(tokens[offset + 1 : end]), _depth):
                    return True
        elif name in {"bash", "dash", "ksh", "sh", "zsh", "eval"}:
            # A quoted script has its own shell parse. Its operands must
            # receive the same cache-boundary checks as a direct command.
            script = None
            if name == "eval" and len(tokens) > 1:
                script = " ".join(tokens[1:])
            else:
                offset = 1
                while offset < len(tokens) - 1:
                    option = tokens[offset]
                    if option == "--":
                        break
                    if option in {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}:
                        offset += 2
                    elif (
                        option.startswith("-")
                        and not option.startswith("--")
                        and "c" in option
                    ):
                        script = tokens[offset + 1]
                        break
                    elif option.startswith(("-", "+")):
                        offset += 1
                    else:
                        break
            if script is not None and (_rm_nested_risk(script, _depth)):
                return True
        elif name not in {"echo", "printf"}:
            # Unknown executables may run their arguments. Preserve embedded
            # command evidence unless this is a positively identified printer.
            for offset, token in enumerate(tokens[1:], 1):
                if token.rsplit("/", 1)[-1] in {
                    "rm",
                    "bash",
                    "dash",
                    "ksh",
                    "sh",
                    "zsh",
                    "eval",
                    "find",
                }:
                    script = shlex.join(tokens[offset:])
                elif re.search(r"\brm\s+", token):
                    script = token
                else:
                    continue
                if _rm_nested_risk(script, _depth):
                    return True
    return False


def _rm_nested_risk(script: str, depth: int) -> bool:
    if depth < 8:
        return _has_broad_rm(script, _depth=depth + 1)
    # At the inspection bound, retain actual rm evidence. Deeply nested
    # harmless scripts alone do not justify a destructive-command finding.
    return bool(re.search(r"\brm\b", script))


def _rm_substituted_scripts(command: str) -> Iterator[str]:
    """Inspect executed substitutions; single-quoted text remains literal."""
    quote = None
    index = 0
    while index < len(command):
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if command.startswith("$(", index) or char == "`":
            backtick = char == "`"
            start = index + (1 if backtick else 2)
            end = start
            depth = 1
            inner_quote = None
            while end < len(command):
                current = command[end]
                if inner_quote == "'":
                    if current == "'":
                        inner_quote = None
                elif current == "\\":
                    end += 2
                    continue
                elif backtick and current == "`":
                    break
                elif inner_quote:
                    if current == inner_quote:
                        inner_quote = None
                elif current in {"'", '"'}:
                    inner_quote = current
                elif not backtick and current == "(":
                    depth += 1
                elif not backtick and current == ")":
                    depth -= 1
                    if depth == 0:
                        break
                end += 1
            yield command[start:end]
            index = end + 1
            continue
        if quote:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        index += 1


def _rm_without_comments(command: str) -> str:
    kept: list[str] = []
    quote = None
    escaped = False
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "#" and (index == 0 or command[index - 1] in " \t\r\n;|&()<>"):
            end = command.find("\n", index)
            if end == -1:
                break
            index = end
            continue
        kept.append(char)
        index += 1
    return "".join(kept)


_RM_COMMAND_PREFIXES = {"command", "env", "exec", "nohup", "sudo", "time", "xargs"}
_RM_PREFIX_VALUE_OPTIONS = {
    "exec": {"-a"},
    "env": {"-C", "--chdir", "-u", "--unset"},
    "sudo": {"-C", "-g", "-h", "-p", "-T", "-u", "--user", "--group"},
    "time": {"-o", "--output", "-f", "--format"},
    "xargs": {
        "-a",
        "--arg-file",
        "-d",
        "--delimiter",
        "-E",
        "--eof",
        "-I",
        "--replace",
        "-L",
        "--max-lines",
        "-n",
        "--max-args",
        "-P",
        "--max-procs",
        "-s",
        "--max-chars",
    },
}


def _rm_known_command_name(token: str) -> str:
    if token.startswith(("/bin/", "/usr/bin/")):
        name = token.rsplit("/", 1)[-1]
        if token in {f"/bin/{name}", f"/usr/bin/{name}"}:
            return name
    return token


def _rm_executable_tokens(tokens: list[str]) -> list[str]:
    """Resolve common execution prefixes without treating printed argv as code."""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        name = _rm_known_command_name(token)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token) or token in {
            "!",
            "if",
            "then",
            "elif",
            "else",
            "do",
            "while",
            "until",
            "{",
        }:
            index += 1
        elif name in _RM_COMMAND_PREFIXES:
            index += 1
            while index < len(tokens):
                option = tokens[index]
                if option in {"--help", "--version"}:
                    return []
                if name == "env" and option.startswith("--split-string="):
                    return _rm_executable_tokens(
                        shell_tokens(option.split("=", 1)[1]) + tokens[index + 1 :]
                    )
                if (
                    name == "env"
                    and option in {"-S", "--split-string"}
                    and index + 1 < len(tokens)
                ):
                    return _rm_executable_tokens(
                        shell_tokens(tokens[index + 1]) + tokens[index + 2 :]
                    )
                if option == "--":
                    index += 1
                    break
                if option.startswith("-") and not option.startswith("--"):
                    value_flags = {
                        flag[1]
                        for flag in _RM_PREFIX_VALUE_OPTIONS.get(name, set())
                        if len(flag) == 2
                    }
                    flags = set()
                    takes_next = False
                    for offset, flag in enumerate(option[1:], 1):
                        flags.add(flag)
                        if flag in value_flags:
                            takes_next = offset == len(option) - 1
                            break
                    if (name == "command" and flags.intersection("vV")) or (
                        name == "sudo" and flags.intersection("lvV")
                    ):
                        return []
                    index += 2 if takes_next else 1
                    continue
                if option in _RM_PREFIX_VALUE_OPTIONS.get(name, set()):
                    index += 2
                elif option.startswith("-"):
                    index += 1
                else:
                    break
        else:
            return tokens[index:]
    return []


def _rm_targets(tokens: list[str]) -> list[str]:
    targets: list[str] = []
    options_done = False
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        redirect = REDIRECT_RE.match(token)
        if redirect:
            # ``> /dev/null`` names the redirect target in the next token.
            skip_next = redirect.end() == len(token)
            continue
        token = token.strip("'\"`()")
        if not token:
            continue
        if not options_done and token == "--":
            options_done = True
            continue
        if not options_done and token.startswith("-"):
            continue
        targets.append(token)
    return targets


def _is_broad_rm_target(target: str) -> bool:
    if target in CWD_WIPE_TARGETS or EMPTY_VAR_ROOT_RE.match(target):
        return True
    if _is_disposable_path(target):
        return False
    return (
        target.startswith("/")
        or target in {"~", "$HOME", "${HOME}", ".git"}
        or target.startswith(("~/", "$HOME/", "${HOME}/", ".git/"))
    )


def _is_disposable_path(target: str) -> bool:
    # An expansion can introduce parent traversal even below a literal cache
    # prefix (e.g. TARGET=../.. in /tmp/$TARGET). Only HOME itself is allowed
    # to expand in the explicitly supported home-cache roots.
    literal = target
    for home in ("$HOME/", "${HOME}/"):
        if literal.startswith(home):
            literal = literal[len(home) :]
            break
    if any(marker in literal for marker in ("$", "`", "{")):
        return False
    if ".." in target.split("/"):
        return False
    if any(
        target.startswith(root) and len(target) > len(root) for root in DISPOSABLE_ROOTS
    ):
        return True
    for home in HOME_PREFIXES:
        if target.startswith(home):
            return target[len(home) :].split("/", 1)[0] in CACHE_DIRS_UNDER_HOME
    return False


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
        return any(
            "secret" in token.lower() or "token" in token.lower()
            for token in tokens[3:]
        )
    return any(tokens_start_with(tokens, prefix) for prefix in TOKEN_COMMAND_PREFIXES)


def _reads_sensitive_path(name: str, tokens: list[str]) -> bool:
    return name in SENSITIVE_READERS and any(
        is_sensitive_path(token) for token in tokens[1:]
    )


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
