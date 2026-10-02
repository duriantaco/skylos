"""What a change is compared with, and what it changed.

The base is a commit: the merge base of ``--base`` for a pull request, or
HEAD when no base is given. The head is the working tree, so committed,
staged, unstaged and untracked (non-ignored) edits all count.

Every Git call runs with repository-configured helpers disabled (no external
diff, textconv, filters or hooks): the repository under check is untrusted.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from skylos.core.git_context import GitContext
from skylos.core.git_safety import read_only_git_command
from skylos.core.safe_cache_io import read_project_text_no_symlink

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_DIFF_BYTES = 32 * 1024 * 1024
_GIT_TIMEOUT_SECONDS = 60

# Files Skylos itself writes while it works. They never count as part of the
# change, or the gate would trip over its own receipts and session state.
_RUNTIME_PREFIXES = (".skylos/receipts/", ".skylos/cache/")
_RUNTIME_FILES = (".skylos/agent-session.json", ".skylos/agent-session.lock")
_RUNTIME_FILE_PREFIXES = (".skylos/hook.log",)

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


class DoneError(Exception):
    """A problem the user must fix before the gate can run (said plainly)."""


def is_runtime_path(path: str) -> bool:
    return (
        path.startswith(_RUNTIME_PREFIXES)
        or path in _RUNTIME_FILES
        or path.startswith(_RUNTIME_FILE_PREFIXES)
    )


@dataclass(frozen=True)
class ChangedFile:
    """One changed path. ``base_path`` is None when the file is new."""

    path: str
    status: str  # "added", "modified", "deleted" or "renamed"
    base_path: str | None

    @property
    def head_path(self) -> str | None:
        return None if self.status == "deleted" else self.path


@dataclass
class Comparison:
    root: Path
    base_sha: str
    base_source: str  # "merge_base" or "head"
    config_sha: str  # where [tool.skylos.done] is read from
    head_sha: str
    head_dirty: bool
    changed: tuple[ChangedFile, ...]
    _context: GitContext = field(repr=False)
    _untracked: frozenset[str] = field(default_factory=frozenset, repr=False)
    _diff_cache: dict[str, str] = field(default_factory=dict, repr=False)

    # -- file contents ---------------------------------------------------

    def base_text(self, path: str | None, *, sha: str | None = None) -> str | None:
        """Text of ``path`` at the base commit (or ``sha``), None if absent."""
        if not path:
            return None
        data = _git_bytes(
            self._context, "cat-file", "blob", f"{sha or self.base_sha}:{path}"
        )
        if data is None or len(data) > MAX_FILE_BYTES:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def head_text(self, path: str | None) -> str | None:
        """Text of ``path`` in the working tree, never through a symlink."""
        if not path:
            return None
        return read_project_text_no_symlink(
            self.root, path, max_bytes=MAX_FILE_BYTES, errors="strict"
        )

    def relative_path(self, path: str) -> str | None:
        return self._context.relative_path(path)

    # -- diffs -----------------------------------------------------------

    def file_diff(self, changed: ChangedFile) -> str:
        """Unified diff of one file, base to working tree."""
        key = f"{changed.base_path}\0{changed.path}"
        if key not in self._diff_cache:
            if changed.path in self._untracked:
                self._diff_cache[key] = _new_file_diff(
                    changed.path, self.head_text(changed.path)
                )
            else:
                paths = [changed.path]
                if changed.base_path and changed.base_path != changed.path:
                    paths.insert(0, changed.base_path)
                self._diff_cache[key] = (
                    _git_text(
                        self._context,
                        "diff",
                        "-M",
                        self.base_sha,
                        "--",
                        *(f":(literal){p}" for p in paths),
                    )
                    or ""
                )
        return self._diff_cache[key]

    def diff_text(self) -> str:
        """Unified diff of the whole change, base to working tree."""
        parts = []
        total = 0
        for changed in self.changed:
            diff = self.file_diff(changed)
            total += len(diff)
            if total > MAX_DIFF_BYTES:
                raise DoneError("the change is too large to check (over 32 MB of diff)")
            parts.append(diff)
        return "".join(
            part if part.endswith("\n") else part + "\n" for part in parts if part
        )

    def added_lines(self, changed: ChangedFile) -> set[int]:
        """Line numbers at head that this change added or rewrote."""
        if changed.status == "deleted":
            return set()
        return added_lines_from_diff(self.file_diff(changed)).get(changed.path, set())


def open_comparison(path: str | Path, base_ref: str | None = None) -> Comparison:
    target = Path(path).resolve()
    if not target.exists():
        raise DoneError(f"{path} does not exist")
    context = GitContext.from_path(target)
    if context.filter_config_overrides is None:
        raise DoneError("could not safely read this repository's Git settings")
    if _git_text(context, "rev-parse", "--show-toplevel") is None:
        raise DoneError(f"{path} is not inside a Git repository")

    head = _resolve_commit(context, "HEAD")
    if head is None:
        raise DoneError("this repository has no commits yet")

    if base_ref:
        if base_ref.startswith("-"):
            raise DoneError(f"invalid base {base_ref!r}")
        tip = _resolve_commit(context, base_ref)
        if tip is None:
            raise DoneError(
                f"cannot find base {base_ref!r}; fetch it first "
                "(in GitHub Actions: actions/checkout with fetch-depth: 0)"
            )
        merge_base = (_git_text(context, "merge-base", tip, head) or "").strip()
        if not _SHA_RE.match(merge_base):
            raise DoneError(
                f"{base_ref!r} and HEAD share no history; fetch full history "
                "(in GitHub Actions: actions/checkout with fetch-depth: 0)"
            )
        base_sha, base_source, config_sha = merge_base, "merge_base", tip
    else:
        base_sha, base_source, config_sha = head, "head", head

    root = Path(context.root)
    changed, untracked = _changed_files(context, base_sha)
    return Comparison(
        root=root,
        base_sha=base_sha,
        base_source=base_source,
        config_sha=config_sha,
        head_sha=head,
        head_dirty=_is_dirty(context),
        changed=changed,
        _context=context,
        _untracked=untracked,
    )


def added_lines_from_diff(diff_text: str) -> dict[str, set[int]]:
    """Map each file in a unified diff to the head line numbers it adds."""
    added: dict[str, set[int]] = {}
    current: set[int] | None = None
    line_no = 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            target = _diff_header_path(raw[4:])
            current = added.setdefault(target, set()) if target else None
            continue
        if raw.startswith("--- ") or raw.startswith("diff --git "):
            continue
        match = _HUNK_RE.match(raw)
        if match:
            line_no = int(match.group(1))
            continue
        if current is None:
            continue
        if raw.startswith("+"):
            current.add(line_no)
            line_no += 1
        elif raw.startswith(" "):
            line_no += 1
    return added


# ---------------------------------------------------------------------------
# Git plumbing
# ---------------------------------------------------------------------------


def _resolve_commit(context: GitContext, ref: str) -> str | None:
    out = _git_text(context, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    sha = (out or "").strip()
    return sha if _SHA_RE.match(sha) else None


def _changed_files(
    context: GitContext, base_sha: str
) -> tuple[tuple[ChangedFile, ...], frozenset[str]]:
    out = _git_text(context, "diff", "--name-status", "-z", "-M", base_sha, "--")
    if out is None:
        raise DoneError("git diff failed; check that the base commit is available")
    changed: dict[str, ChangedFile] = {}
    tokens = out.split("\0")
    index = 0
    while index < len(tokens):
        status = tokens[index]
        index += 1
        if not status:
            continue
        kind = status[0]
        if kind in "RC":
            if index + 1 >= len(tokens):
                break
            old, new = tokens[index], tokens[index + 1]
            index += 2
            if kind == "R":
                changed[new] = ChangedFile(new, "renamed", old)
            else:
                changed[new] = ChangedFile(new, "added", None)
            continue
        if index >= len(tokens):
            break
        path = tokens[index]
        index += 1
        if kind == "A":
            changed[path] = ChangedFile(path, "added", None)
        elif kind == "D":
            changed[path] = ChangedFile(path, "deleted", path)
        else:  # M, T (type change), U (unmerged)
            changed[path] = ChangedFile(path, "modified", path)

    untracked_out = _git_text(
        context, "ls-files", "--others", "--exclude-standard", "-z"
    )
    untracked = set()
    for path in (untracked_out or "").split("\0"):
        if path and path not in changed:
            changed[path] = ChangedFile(path, "added", None)
            untracked.add(path)

    files = tuple(
        item
        for key, item in sorted(changed.items())
        if not is_runtime_path(key)
        and not (item.base_path and is_runtime_path(item.base_path))
    )
    return files, frozenset(untracked)


def _is_dirty(context: GitContext) -> bool:
    out = _git_text(
        context, "status", "--porcelain=v1", "-z", "--untracked-files=normal"
    )
    if out is None:
        return True
    entries = iter(out.split("\0"))
    for entry in entries:
        if len(entry) <= 3:
            continue
        if entry[0] in "RC":
            next(entries, None)  # the rename's original path
        if not is_runtime_path(entry[3:]):
            return True
    return False


def _command(context: GitContext, args: tuple[str, ...]) -> list[str]:
    safe = list(args)
    overrides = ["core.quotePath=false"]
    if safe and safe[0] == "diff":
        safe[1:1] = ["--no-ext-diff", "--no-textconv", "--no-color"]
    if safe and safe[0] in {"diff", "status"}:
        # Comparing the working tree runs clean filters; disable them all.
        overrides.extend(context.filter_config_overrides or ())
    return read_only_git_command(safe, config_overrides=overrides)


def _git_bytes(context: GitContext, *args: str) -> bytes | None:
    try:
        result = subprocess.run(
            _command(context, args),
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            cwd=str(context.root),
            env=context.env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _git_text(context: GitContext, *args: str) -> str | None:
    data = _git_bytes(context, *args)
    if data is None:
        return None
    return data.decode("utf-8", errors="replace")


def _new_file_diff(path: str, text: str | None) -> str:
    if text is None:
        return ""
    lines = text.splitlines()
    header = f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n"
    if not lines:
        return header
    body = "".join(f"+{line}\n" for line in lines)
    return f"{header}@@ -0,0 +1,{len(lines)} @@\n{body}"


def _diff_header_path(raw: str) -> str | None:
    value = raw.rstrip("\n")
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        value = _unquote_c_style(value[1:-1])
    if value == "/dev/null":
        return None
    if value.startswith("b/"):
        return value[2:]
    return value


def _unquote_c_style(value: str) -> str:
    """Undo Git's C-style path quoting (``\\t``, ``\\"``, octal bytes)."""
    out = bytearray()
    index = 0
    escapes = {
        "n": 10,
        "t": 9,
        '"': 34,
        "\\": 92,
        "a": 7,
        "b": 8,
        "f": 12,
        "r": 13,
        "v": 11,
    }
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            nxt = value[index + 1]
            if nxt in escapes:
                out.append(escapes[nxt])
                index += 2
                continue
            octal = value[index + 1 : index + 4]
            if len(octal) == 3 and all(c in "01234567" for c in octal):
                out.append(int(octal, 8))
                index += 4
                continue
        out.extend(char.encode("utf-8"))
        index += 1
    return out.decode("utf-8", errors="replace")
