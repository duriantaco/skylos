"""Static reading of shell commands in package scripts and CI/container files.

Package scripts, GitHub Actions ``run:`` steps, Dockerfile ``RUN``/``CMD``/
``ENTRYPOINT`` lines, Makefile recipes, Procfiles and GitLab CI scripts are
parsed into the commands they run. Nothing here executes a command: words are
tokenized with :mod:`shlex` and every construct the parser does not model is
reported as unknown instead of guessed.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import NamedTuple

from skylos.core.safe_cache_io import read_project_text_no_symlink

MAX_WRAPPER_DEPTH = 3
MAX_COMMAND_FILE_BYTES = 2_000_000
_PACKAGE = re.compile(r"^(?:@[a-zA-Z0-9._~-]+/)?[a-zA-Z0-9._~-]+$")
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")

SYSTEM_COMMANDS = {
    # Runtimes, shells and package managers.
    "node", "nodejs", "bun", "deno", "npm", "pnpm", "yarn", "corepack", "sh", "bash", "zsh", "dash",
    "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "python", "python3", "pip",
    "pip3", "uv", "poetry", "ruby", "gem", "bundle", "rails", "php", "composer", "java", "javac",
    "mvn", "gradle", "go", "cargo", "rustc", "rustup", "dotnet", "swift", "xcodebuild", "xcrun",
    "pod", "fastlane", "flutter", "dart", "adb", "emulator", "perl", "lua", "R", "Rscript",
    # POSIX utilities and shell builtins.
    "echo", "printf", "true", "false", "test", "[", "mkdir", "rm", "rmdir", "cp", "mv", "cat",
    "ls", "pwd", "cd", "touch", "exit", "sleep", "which", "command", "export", "unset", "set",
    "source", ".", "eval", "exec", "env", "printenv", "wait", "kill", "pkill", "trap", "type",
    "ulimit", "umask", "read", "shift", "chmod", "chown", "ln", "find", "grep", "egrep", "sed",
    "awk", "xargs", "tee", "wc", "sort", "uniq", "head", "tail", "cut", "tr", "diff", "patch",
    "date", "basename", "dirname", "realpath", "readlink", "stat", "du", "df", "tar", "zip",
    "unzip", "gzip", "gunzip", "base64", "md5sum", "shasum", "sha256sum", "openssl", "gpg",
    "curl", "wget", "ssh", "scp", "rsync", "nc", "lsof", "ps", "nohup", "nice", "time",
    "timeout", "watch", "yes", "seq", "jq", "yq", "open", "xdg-open", "start", "explorer",
    "osascript", "pbcopy", "pbpaste", "say", "sudo", "id", "whoami", "hostname", "uname",
    "clear", "file", "install", "envsubst", "column", "paste", "comm", "join", "split", "less",
    "more", "tput", "stty", "sync", "systemctl", "launchctl", "defaults", "security", "codesign",
    "del", "copy", "xcopy", "rd", "md", "move", "ren", "robocopy", "where",
    # Build, container, cloud and database tooling installed outside npm.
    "git", "gh", "hg", "svn", "make", "cmake", "ninja", "gcc", "g++", "cc", "clang", "clang++",
    "emcc", "wasm-opt", "wat2wasm", "protoc", "docker", "docker-compose", "podman", "kubectl",
    "helm", "kind", "minikube", "skaffold", "tilt", "terraform", "tofu", "packer", "vagrant",
    "ansible", "ansible-playbook", "aws", "sam", "gcloud", "gsutil", "az", "doctl", "flyctl",
    "fly", "heroku", "pulumi", "railway", "doppler", "op", "vault", "sops", "psql", "pg_dump",
    "pg_restore", "pg_ctl", "createdb", "dropdb", "mysql", "mysqldump", "sqlite3", "redis-cli",
    "redis-server", "mongod", "mongo", "mongosh", "mongodump", "mongorestore", "ffmpeg",
    "ffprobe", "convert", "magick", "identify", "pngquant", "optipng", "cwebp", "inkscape",
    "pandoc", "hugo", "jekyll", "mkdocs", "sphinx-build", "ruff", "black", "mypy", "pytest",
    "tox", "pre-commit", "shellcheck", "shfmt", "hadolint", "actionlint", "yamllint", "codespell",
    "typos", "lychee", "just", "task", "mise", "asdf", "nvm", "volta", "fnm", "brew", "apt",
    "apt-get", "yum", "dnf", "apk", "choco", "winget", "scoop", "ngrok", "mkcert", "caddy",
    "nginx", "code", "code-insiders", "cursor", "claude", "supabase", "stripe", "act",
    # Shell builtins.
    "readarray", "mapfile", "declare", "local", "let", "shopt", "pushd", "popd", "return", "break",
    "continue", "getopts", "alias", "unalias", "hash", "typeset", "readonly", "jobs", "bg", "fg",
    "builtin", "caller", "complete", "compgen", "disown", "history", "logout", "suspend", "times", ":",
}


SHELL_KEYWORDS = {"if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "function", "select", "{", "}", "!", "[[", "]]", "coproc"}


# Package-manager subcommands that neither run a project binary nor a script.
PM_BUILTINS = {
    "install", "i", "add", "remove", "rm", "uninstall", "un", "update", "up", "upgrade",
    "upgrade-interactive", "publish", "pack", "version", "audit", "ci", "prune", "dedupe",
    "outdated", "link", "ln", "unlink", "rebuild", "rb", "cache", "config", "c", "set", "get",
    "info", "view", "why", "explain", "list", "ls", "ll", "la", "login", "logout", "whoami",
    "init", "create", "import", "fetch", "patch", "patch-commit", "patch-remove", "store",
    "licenses", "bin", "root", "prefix", "doctor", "deploy", "approve-builds", "ignored-builds",
    "setup", "env", "help", "tag", "dist-tag", "owner", "policies", "plugin", "constraints",
    "npm", "node", "sbom", "server", "unplug", "stage", "global", "autoclean", "check",
    "generate-lock-entry", "team", "search", "ping", "pkg", "query", "shrinkwrap", "star",
    "stars", "token", "profile", "hook", "access", "adduser", "bugs", "docs", "edit", "explore",
    "fund", "repo", "completion", "self-update", "cat-file", "cat-index", "find-hash", "dlx",
}


PM_SCOPED = {"workspace", "workspaces", "recursive", "multi", "m"}


PM_SCRIPT_COMMANDS = {"run", "run-script", "rum", "urn", "test", "t", "tst", "start", "stop", "restart"}


NPX_COMMANDS = {"npx", "pnpx", "bunx"}


NPX_FLAGS = {"--yes", "-y", "--no-install", "--no", "-q", "--quiet", "--prefer-offline", "--bun", "--silent"}


OPAQUE_WRAPPERS = {"cross-env-shell", "sh", "bash", "zsh", "cmd", "powershell", "pwsh", "dotenv", "dotenvx", "env-cmd", "op", "retry-cli"}


SCRIPT_RUNNERS = {"npm-run-all", "run-s", "run-p", "npm-run-all2"}


CONCURRENTLY_BOOLEAN_FLAGS = {
    "-r", "--raw", "--no-color", "-g", "--group", "--timings", "-P", "--passthrough-arguments",
    "--pad-prefix", "-k", "--kill-others", "--kill-others-on-fail", "-i", "--handle-input",
    "-h", "--help", "-v", "-V", "--version",
}


CONCURRENTLY_VALUE_FLAGS = {
    "-n", "--names", "--name-separator", "-s", "--success", "--hide", "-p", "--prefix", "-c",
    "--prefix-colors", "-l", "--prefix-length", "-t", "--timestamp-format", "--restart-tries",
    "--restart-after", "--default-input-target", "-m", "--max-processes", "--cwd", "-ks",
    "--kill-signal", "--teardown",
}


# Package-manager options that select the directory or workspace a command
# runs in, options that take a value, and boolean options.
PM_TARGET_FLAGS = {"--cwd": "cwd", "--prefix": "cwd", "-C": "cwd", "--dir": "cwd", "--filter": "workspace", "-F": "workspace", "--workspace": "workspace"}


PM_VALUE_FLAGS = {"--network-timeout", "--registry", "--cache-folder", "--modules-folder", "--mutex", "--loglevel", "--reporter", "--network-concurrency", "--child-concurrency", "--workspace-concurrency", "--reporter-hide-prefix"}


PM_BOOLEAN_FLAGS = {
    "-s", "--silent", "--frozen-lockfile", "--immutable", "--pure-lockfile", "--offline", "--prefer-offline",
    "--if-present", "--ignore-scripts", "--verbose", "--non-interactive", "--check-files", "--production",
    "--prod", "--dev", "-D", "-P", "--no-optional", "--no-bail", "--stream", "--parallel", "--sequential",
    "--include-workspace-root", "--workspace-root", "--color", "--no-color", "--aggregate-output", "-q", "--quiet",
}


PM_RECURSIVE_FLAGS = {"-r", "--recursive", "--workspaces", "-ws"}


# Runtimes whose first positional argument is a script file to load.
SCRIPT_RUNTIMES = {"node", "nodejs", "bun", "deno", "tsx", "ts-node", "ts-node-esm", "ts-node-script", "vite-node", "babel-node", "esno", "esr", "jiti", "sucrase-node"}


RUNTIME_VALUE_FLAGS = {"-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--input-type", "--title", "--env-file", "--tsconfig", "--project", "-P", "-O", "--compiler-options", "--cwd", "--config", "-c", "--inspect-port", "--stack-size", "--max-old-space-size"}


RUNTIME_EVAL_FLAGS = {"-e", "--eval", "-p", "--print"}


# Bun and Deno subcommands are not script files.
RUNTIME_SUBCOMMANDS = {"build", "install", "add", "remove", "test", "x", "run", "create", "upgrade", "pm", "link", "unlink", "init", "outdated", "publish", "update", "repl", "fmt", "lint", "check", "compile", "task", "bundle", "info", "cache", "doc", "serve", "bench", "coverage", "eval", "types", "vendor", "jupyter", "lsp"}


SHELL_SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh"}


SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash"}


# Compound shell syntax: lead keywords before a command, closing words, and
# headers that are not commands themselves.
SHELL_LEAD_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "time"}


SHELL_CLOSE_KEYWORDS = {"fi", "done", "esac", "}", "]]"}


_SEGMENT_SEPARATORS = {";", "&&", "||", "|", "&", "|&", "(", ")", ";;", ";&", ";;&", "<(", ">(", "$("}


_REDIRECTIONS = {">", ">>", "<", "<<<", ">&", "&>", "&>>", ">|", "<>", "<&"}


_SUBSTITUTION = "__skylos_substitution__"


_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")


_BIN_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._+-]*")


class _Command(NamedTuple):
    """One command a script runs.

    ``origin`` is ``direct`` for a plain command, ``package_manager`` for a
    ``pnpm <bin>``/``yarn <bin>`` shorthand and ``npx`` for a runner that can
    fetch a package that is not installed locally. ``target`` names the
    directory (``("cwd", path)``) or workspace (``("workspace", name)``) a
    package-manager command runs in; its name is then a script of that
    package or a binary resolved there. ``script`` is a file a runtime or
    shell loads (``node scripts/build.js``); ``name`` is None for a shell
    script run by path. ``args`` are the words after the binary (after the
    runtime for a script), read by per-binary argument specs.
    """

    name: str | None
    origin: str = "direct"
    target: tuple | None = None
    script: str | None = None
    args: tuple = ()


def _tokens(script, punctuation=";&|", comments=False):
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars=punctuation)
        lexer.whitespace_split = True
        lexer.commenters = "#" if comments else ""
        return list(lexer)
    except ValueError:
        return None


def _segments(tokens):
    segments, segment = [], []
    for token in tokens:
        if token in {";", "&&", "||", "|", "&"}:
            if segment:
                segments.append(segment)
            segment = []
        else:
            segment.append(token)
    if segment:
        segments.append(segment)
    return segments


def _split_substitutions(script):
    """Replace ``$(...)`` and backtick substitutions with a placeholder word.

    Returns ``(text, inner_scripts)`` or None when a substitution is not
    closed. Single-quoted text is literal; ``$((`` arithmetic is kept.
    """
    out, inner, index, quote = [], [], 0, None
    while index < len(script):
        char = script[index]
        if quote == "'":
            quote = None if char == "'" else quote
            out.append(char)
            index += 1
            continue
        if char == "\\" and index + 1 < len(script):
            out.append(script[index:index + 2])
            index += 2
            continue
        if char in "'\"":
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            out.append(char)
            index += 1
            continue
        if char == "`":
            end = script.find("`", index + 1)
            if end < 0:
                return None
            inner.append(script[index + 1:end])
            out.append(_SUBSTITUTION)
            index = end + 1
            continue
        if script.startswith("$(", index) and not script.startswith("$((", index):
            depth, cursor = 1, index + 2
            while cursor < len(script) and depth:
                depth += {"(": 1, ")": -1}.get(script[cursor], 0)
                cursor += 1
            if depth:
                return None
            inner.append(script[index + 2:cursor - 1])
            out.append(_SUBSTITUTION)
            index = cursor
            continue
        out.append(char)
        index += 1
    return "".join(out), inner


def _shell_segments(script, lenient):
    """Command token lists split at ``; && || | &`` with redirections removed.

    Strict mode (package.json scripts) declines subshell grouping. Returns
    ``(segments, unknown)``.
    """
    tokens = _tokens(script, ";&|()<>", comments=lenient)
    if tokens is None:
        return [], True
    segments, segment, unknown, index = [], [], False, 0

    def flush():
        nonlocal segment
        if segment:
            segments.append(segment)
        segment = []

    while index < len(tokens):
        token = tokens[index]
        index += 1
        if lenient and token == "()":
            segment = []  # ``name() {``: a function definition, not a command.
            continue
        if lenient and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\+?=", token) and index < len(tokens) and tokens[index] == "(":
            # ``name=(a b c)`` assigns an array; its words are not commands.
            while index < len(tokens) and tokens[index] != ")":
                index += 1
            index += 1
            continue
        if token in _SEGMENT_SEPARATORS:
            if token in {"(", ")", "<(", ">(", "$("} and not lenient:
                return [], True
            flush()
            continue
        if token in _REDIRECTIONS:
            if index < len(tokens) and tokens[index] not in _SEGMENT_SEPARATORS | _REDIRECTIONS:
                index += 1  # The redirection target is a file, not a command.
            continue
        if set(token) <= set(";&|()<>"):
            # Here-documents and other operators are not modelled.
            unknown = True
            segment = []
            while index < len(tokens) and tokens[index] not in _SEGMENT_SEPARATORS:
                index += 1
            continue
        segment.append(token)
    flush()
    return segments, unknown


def _script_commands(script, script_names=(), depth=0, *, lenient=False):
    """Return ``(commands, unknown)`` for a shell command line.

    Every ``;``/``&&``/``||``/``|`` segment is read on its own, so one opaque
    segment does not hide the commands of the others. ``$VAR`` expansions are
    allowed in arguments and assignments; an expanded command name, eval-style
    code and opaque wrappers make the result ``unknown``. ``lenient`` (CI and
    container command files) also reads commands inside ``if``/``while``
    bodies and subshells; package scripts decline that compound syntax.
    """
    if not isinstance(script, str):
        return [], True
    split = _split_substitutions(script.replace("\r", ""))
    if split is None:
        return [], True
    text, inner = split
    commands, unknown = [], False
    for nested in inner:
        if depth >= MAX_WRAPPER_DEPTH:
            unknown = True
            continue
        found, nested_unknown = _script_commands(nested, script_names, depth + 1, lenient=lenient)
        commands.extend(found)
        unknown |= nested_unknown
    for line in text.split("\n"):
        segments, segments_unknown = _shell_segments(line, lenient)
        unknown |= segments_unknown
        for segment in segments:
            found, segment_unknown = _segment_commands(segment, script_names, depth, lenient=lenient)
            commands.extend(found)
            unknown |= segment_unknown
    return commands, unknown


def _expanded(token):
    return "$" in token or "`" in token or _SUBSTITUTION in token


def _package_manager_commands(command, rest, script_names, depth, lenient):
    """``npm``/``pnpm``/``yarn`` invocations: scripts, binaries and targets."""
    target, recursive, rest = None, False, list(rest)
    while rest and rest[0].startswith("-") and rest[0] != "--":
        flag, has_value, value = rest[0].partition("=")
        kind = PM_TARGET_FLAGS.get(flag)
        if command == "pnpm" and flag == "-w":
            kind = None  # pnpm -w is --workspace-root
        elif command == "npm" and flag == "-w":
            kind = "workspace"
        if kind is not None:
            if not has_value:
                if len(rest) < 2:
                    return [], True
                value, rest = rest[1], rest[2:]
            else:
                rest = rest[1:]
            if _expanded(value):
                return [], True
            target = (kind, value)
            continue
        if flag in PM_VALUE_FLAGS:
            rest = rest[1:] if has_value else rest[2:]
            continue
        if flag in PM_RECURSIVE_FLAGS or (command == "pnpm" and flag == "-w"):
            recursive |= flag in PM_RECURSIVE_FLAGS
            rest = rest[1:]
            continue
        if flag in PM_BOOLEAN_FLAGS:
            rest = rest[1:]
            continue
        return [], True
    if not rest:
        return [], False
    head = rest[0]
    if _expanded(head):
        return [], True
    if command == "yarn" and head == "workspace":
        if len(rest) < 3 or _expanded(rest[1]):
            return ([], False) if len(rest) == 2 else ([], True)
        return _package_manager_commands(command, ["--filter", rest[1], *rest[2:]], script_names, depth, lenient)
    if command == "yarn" and head == "workspaces":
        # ``yarn workspaces run|foreach`` runs package scripts, which are
        # inspected in their own packages; ``exec`` names an unknown binary.
        return [], "exec" in rest
    if recursive:
        return [], head in {"exec", "x", "dlx"}
    if head in {"run", "run-script"} or (command == "npm" and head in PM_SCRIPT_COMMANDS):
        script = rest[1] if len(rest) > 1 and head in {"run", "run-script"} else (head if head not in {"run", "run-script"} else None)
        if script is None:
            return [], False
        if target is not None:
            return ([_Command(script, "package_manager", target)], False)
        if script in script_names or head not in {"run", "run-script"}:
            return [], False  # Every declared script is inspected independently.
        if command == "npm":
            return [], True
        return ([_Command(script, "package_manager")], False) if _BIN_NAME.fullmatch(script) else ([], True)
    if command == "npm" or head in PM_SCRIPT_COMMANDS:
        if head in PM_SCRIPT_COMMANDS or head in PM_BUILTINS:
            return [], False
        if head in {"exec", "x"}:
            rest = [token for token in rest[1:] if token != "--"]
            if rest and not rest[0].startswith("-") and not _expanded(rest[0]):
                return [_Command(rest[0], "npx", target, args=tuple(rest[1:]))], False
        return [], True
    if head == "exec":
        rest = [token for token in rest[1:] if token != "--"]
        if rest and not rest[0].startswith("-") and _BIN_NAME.fullmatch(rest[0]):
            return [_Command(rest[0], "package_manager", target, args=tuple(rest[1:]))], False
        return [], True
    if head in PM_SCOPED:
        return [], True
    if head in PM_BUILTINS:
        return [], False
    if target is not None:
        # A script of the target package (checked by the caller) or a binary.
        return [_Command(head, "package_manager", target, args=tuple(rest[1:]))], False
    if head in script_names:
        return [], False
    return ([_Command(head, "package_manager", args=tuple(rest[1:]))], False) if _BIN_NAME.fullmatch(head) else ([], True)


def _runtime_script(command, rest):
    """``(script, unknown)``: the file a runtime loads, if any."""
    index = 0
    if command in {"bun", "deno"} and rest[:1] == ["run"]:
        index = 1
    while index < len(rest):
        token = rest[index]
        flag = token.split("=", 1)[0]
        if flag in RUNTIME_EVAL_FLAGS:
            return None, True
        if token == "--":
            index += 1
            break
        if token.startswith("-"):
            index += 2 if flag in RUNTIME_VALUE_FLAGS and "=" not in token else 1
            continue
        break
    if index >= len(rest):
        return None, False
    script = rest[index]
    if _expanded(script):
        return None, True
    if command in {"bun", "deno"} and script in RUNTIME_SUBCOMMANDS:
        return None, False
    if command in {"bun", "deno"} and "." not in script and "/" not in script:
        return None, False  # A package script or binary name, handled elsewhere.
    if _URL.match(script) and not script.startswith("file:"):
        return None, False
    return script, False


def _segment_commands(tokens, script_names, depth, *, lenient=False):
    tokens = list(tokens)
    while tokens and lenient and tokens[0] in SHELL_LEAD_KEYWORDS:
        tokens = tokens[1:]
    while tokens and _ASSIGNMENT.fullmatch(tokens[0]):
        tokens = tokens[1:]
    if not tokens:
        return [], False
    command, rest = tokens[0], tokens[1:]
    if lenient and command in SHELL_CLOSE_KEYWORDS | {"[[", "for", "select"}:
        return [], False  # Conditions and loop headers run no package binary.
    if command.startswith(("node_modules/.bin/", "./node_modules/.bin/")):
        command = command.rsplit("/", 1)[-1]
    if _expanded(command):
        return [], True
    if lenient and ("/" in command or command.endswith(tuple(SHELL_SCRIPT_SUFFIXES))) and Path(command).suffix in SHELL_SCRIPT_SUFFIXES | {""}:
        return [_Command(None, "direct", None, command)], False
    if command in SHELL_KEYWORDS or (command not in SYSTEM_COMMANDS and not _BIN_NAME.fullmatch(command)):
        return [], True  # Paths, expansions and compound shell syntax are not modelled.
    if command in {"npm", "pnpm", "yarn"}:
        return _package_manager_commands(command, rest, script_names, depth, lenient)
    if command in NPX_COMMANDS or (command == "bun" and rest[:1] == ["x"]):
        rest = rest[1:] if command == "bun" else rest
        while rest and rest[0] in NPX_FLAGS | {"--"}:
            rest = rest[1:]
        if not rest or rest[0].startswith("-") or _expanded(rest[0]):
            return [], True  # --package/--call select providers indirectly.
        spec = rest[0]
        name = "@" + spec[1:].split("@", 1)[0] if spec.startswith("@") else spec.split("@", 1)[0]
        return ([_Command(name, "npx", args=tuple(rest[1:]))], False) if _PACKAGE.fullmatch(name) else ([], True)
    if command == "bun" and rest[:1] == ["run"] and len(rest) > 1:
        target = rest[1]
        if target in script_names:
            return [], False
        if "." not in target and "/" not in target:
            return ([_Command(target, "npx", args=tuple(rest[2:]))], False) if _BIN_NAME.fullmatch(target) else ([], True)
    if command in {"cross-env", "env"}:
        rest = list(rest)
        while rest and _ASSIGNMENT.fullmatch(rest[0]):
            rest = rest[1:]
        if command == "env" and rest and rest[0].startswith("-"):
            return [], True
        prefix = [_Command(command)] if command == "cross-env" else []
        if not rest or depth >= MAX_WRAPPER_DEPTH:
            return prefix, bool(rest)
        found, inner_unknown = _segment_commands(rest, script_names, depth + 1, lenient=lenient)
        return prefix + found, inner_unknown
    if lenient and command in SHELL_INTERPRETERS:
        if rest[:1] == ["-c"] and len(rest) > 1 and depth < MAX_WRAPPER_DEPTH:
            found, inner_unknown = _script_commands(rest[1], script_names, depth + 1, lenient=True)
            return found, inner_unknown
        if rest and not rest[0].startswith("-") and not _expanded(rest[0]):
            return [_Command(None, "direct", None, rest[0])], False
        return [], True
    if command in OPAQUE_WRAPPERS:
        if "--" in rest and depth < MAX_WRAPPER_DEPTH and command in {"dotenv", "dotenvx", "env-cmd", "op"}:
            inner = rest[rest.index("--") + 1:]
            found, inner_unknown = _segment_commands(inner, script_names, depth + 1, lenient=lenient)
            return [_Command(command), *found], inner_unknown
        return [_Command(command)], True
    if command in SCRIPT_RUNNERS:
        # Arguments name package scripts, which are inspected independently.
        return [_Command(command)], False
    if command == "concurrently":
        commands, unknown, index = [_Command(command)], False, 0
        while index < len(rest):
            token = rest[index]
            index += 1
            if token.startswith("-"):
                flag = token.split("=", 1)[0]
                if flag in CONCURRENTLY_VALUE_FLAGS:
                    index += 0 if "=" in token else 1
                elif flag not in CONCURRENTLY_BOOLEAN_FLAGS:
                    unknown = True
                continue
            if re.match(r"(?:npm|pnpm|yarn|bun):", token):
                continue  # Script shorthand; scripts are inspected independently.
            if depth >= MAX_WRAPPER_DEPTH:
                unknown = True
                continue
            found, inner_unknown = _script_commands(token, script_names, depth + 1, lenient=lenient)
            commands.extend(found)
            unknown |= inner_unknown
        return commands, unknown
    if command in SCRIPT_RUNTIMES:
        script, dynamic = _runtime_script(command, rest)
        return [_Command(command, "direct", None, script, tuple(rest))], dynamic
    return [_Command(command, args=tuple(rest))], False


_GHA_EXPRESSION = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)


_MAKE_VARIABLE = re.compile(r"\$[({][A-Za-z_][A-Za-z0-9_.]*[)}]")


_HEREDOC = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")


MAX_COMMAND_FILE_DEPTH = 2


def _yaml_documents(text):
    """Load YAML as data; custom tags (GitLab ``!reference``) become None."""
    import yaml

    class _DataLoader(yaml.SafeLoader):
        """SafeLoader that also accepts application tags, as plain None."""

    _DataLoader.add_multi_constructor("!", lambda loader, suffix, node: None)
    loader = _DataLoader(text)
    documents = []
    try:
        while loader.check_data():
            documents.append(loader.get_data())
    except (yaml.YAMLError, RecursionError, ValueError):
        return None
    finally:
        loader.dispose()
    return documents


def _workflow_commands(data, base):
    """``[(run, cwd)]`` from a GitHub Actions workflow or composite action."""
    if not isinstance(data, dict):
        return None
    commands = []

    def run_directory(defaults, fallback):
        run = defaults.get("run") if isinstance(defaults, dict) else None
        directory = run.get("working-directory") if isinstance(run, dict) else None
        return directory if isinstance(directory, str) else fallback

    def add_steps(steps, directory, shell):
        for step in steps if isinstance(steps, list) else []:
            if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                continue
            step_shell = step.get("shell", shell)
            if isinstance(step_shell, str) and step_shell.split()[0] not in {"bash", "sh"}:
                continue  # pwsh, python and cmd steps are not POSIX shell.
            step_directory = step.get("working-directory", directory)
            cwd = base
            if isinstance(step_directory, str) and "${{" not in step_directory:
                cwd = (base / step_directory).resolve()
            commands.append((step["run"], cwd))

    default_directory = run_directory(data.get("defaults"), None)
    jobs = data.get("jobs")
    for job in jobs.values() if isinstance(jobs, dict) else []:
        if isinstance(job, dict):
            add_steps(job.get("steps"), run_directory(job.get("defaults"), default_directory), None)
    runs = data.get("runs")
    if isinstance(runs, dict):
        add_steps(runs.get("steps"), default_directory, None)
    return commands


def _gitlab_commands(data, base):
    if not isinstance(data, dict):
        return None
    commands = []
    for job in data.values():
        if not isinstance(job, dict):
            continue
        for key in ("before_script", "script", "after_script"):
            value = job.get(key)
            for item in [value] if isinstance(value, str) else value if isinstance(value, list) else []:
                if isinstance(item, str):
                    commands.append((item, base))
                elif isinstance(item, list):
                    commands.extend((nested, base) for nested in item if isinstance(nested, str))
    return commands


def _dockerfile_commands(text, base):
    commands = []
    for line in re.sub(r"\\\r?\n", " ", text).splitlines():
        match = re.match(r"\s*(?:RUN|CMD|ENTRYPOINT|HEALTHCHECK(?:\s+--\S+)*\s+CMD)\s+(.*)", line, re.IGNORECASE)
        if not match:
            continue
        body = match.group(1).strip()
        while body.startswith("--"):
            body = body.split(None, 1)[1] if " " in body else ""
        if body.startswith("["):
            try:
                words = json.loads(body)
            except ValueError:
                words = None
            body = shlex.join(words) if isinstance(words, list) and all(isinstance(word, str) for word in words) else None
        elif body.startswith("<<"):
            body = None  # Here-document bodies are not modelled.
        commands.append((body, base))
    return commands


def _makefile_commands(text, base):
    commands = []
    for line in re.sub(r"\\\r?\n", " ", text).splitlines():
        if not line.startswith("\t"):
            continue
        body = line.strip().lstrip("@-+").strip()
        body = _MAKE_VARIABLE.sub("$MAKEVAR", body).replace("$$", "$")
        if body:
            commands.append((body, base))
    return commands


def _procfile_commands(text, base):
    return [(match.group(1), base) for match in re.finditer(r"(?m)^[\w.-]+:\s*(.+)$", text)]


def _command_file_lines(root, path):
    """``[(command or None, cwd)]`` from a CI, container or task file, or None."""
    text = read_project_text_no_symlink(root, path, max_bytes=MAX_COMMAND_FILE_BYTES)
    if text is None:
        return None
    base = path.parent
    if path.name in {"Dockerfile", "Containerfile"}:
        return _dockerfile_commands(text, base)
    if path.name == "Makefile":
        return _makefile_commands(text, base)
    if path.name == "Procfile":
        return _procfile_commands(text, base)
    documents = _yaml_documents(text)
    if documents is None:
        return None
    if path.name == ".gitlab-ci.yml":
        commands = []
        for document in documents:
            found = _gitlab_commands(document, base)
            if found is None and document is not None:
                return None
            commands.extend(found or [])
        return commands
    # .github/workflows/*.yml: steps run from the repository root.
    repository = next((parent.parent for parent in path.parents if parent.name == ".github"), base)
    commands = []
    for document in documents:
        found = _workflow_commands(document, repository)
        if found is None and document is not None:
            return None
        commands.extend(found or [])
    return commands


def _unknown_words(line, script_names, depth=0):
    """Words of the command segments the parser declines.

    None when a declined segment's command name is itself an expansion, so
    any package could provide it.
    """
    split = _split_substitutions(line)
    if split is None:
        return None
    text, inner = split
    words = set()
    for nested in inner:
        found = _unknown_words(nested, script_names, depth + 1) if depth < MAX_WRAPPER_DEPTH else None
        if found is None:
            return None
        words |= found
    segments, operator_unknown = _shell_segments(text, True)
    if operator_unknown:
        return None
    for segment in segments:
        _commands, unknown = _segment_commands(segment, script_names, 0, lenient=True)
        if not unknown:
            continue
        tokens = list(segment)
        while tokens and (tokens[0] in SHELL_LEAD_KEYWORDS or _ASSIGNMENT.fullmatch(tokens[0])):
            tokens = tokens[1:]
        if not tokens or _expanded(tokens[0]):
            return None
        words.update(token for token in tokens if len(token) >= 3 and not token.startswith("-") and "=" not in token and "/" not in token and not _expanded(token))
    return words - SYSTEM_COMMANDS - SHELL_KEYWORDS


def _shell_script(root, path):
    """A ``.sh``-style file, or an extensionless one with a POSIX shell shebang."""
    if path.suffix in SHELL_SCRIPT_SUFFIXES:
        return True
    if path.suffix:
        return False
    text = read_project_text_no_symlink(root, path, max_bytes=MAX_COMMAND_FILE_BYTES) or ""
    first = text.split("\n", 1)[0]
    return bool(re.match(r"#!\s*\S*/(?:env\s+)?(?:ba|z|da)?sh\b", first))


def _command_lines(text):
    """Logical shell lines; here-document bodies are dropped."""
    lines, terminator = [], None
    for line in re.sub(r"\\\r?\n", " ", text).splitlines():
        if terminator is not None:
            if line.strip() == terminator:
                terminator = None
            continue
        if line.lstrip().startswith("#"):
            continue
        heredoc = _HEREDOC.search(line)
        if heredoc:
            terminator = heredoc.group(1)
            line = line[:heredoc.start()]
        lines.append(line)
    return lines
