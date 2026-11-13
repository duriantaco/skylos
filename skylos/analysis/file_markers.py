"""Inline ``skylos: ignore`` markers for findings that no file worker filtered.

Source files keep the source grammar: the marker is a real comment on the
reported line. Configuration and dependency files (YAML, TOML, HCL,
requirements and ``.env`` files, ``yarn.lock``) keep the configuration
grammar: a ``skylos: ignore[RULE]`` comment on the reported line, or on its
own line directly above it. Markdown, JSON and other files without comments
carry no markers.

Supply-chain trust rules and guardrail-tamper findings are honoured in
pull-request CI (``SKYLOS_POLICY_BASE``) only when the policy base already
carried the same marker, as for their baselines: a change cannot excuse
itself.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path, PurePath

from skylos.analysis.finding_filter import finding_is_inline_ignored
from skylos.core.inline_directives import (
    comment_body,
    comment_family,
    inline_ignores,
    parse_directive,
)
from skylos.core.safe_cache_io import read_text_no_symlink

MAX_MARKER_FILE_BYTES = 4_000_000
_MARKER_TEXT = re.compile(r"skylos: ignore\[(SKY-[A-Z][A-Z0-9-]*)\]")
_PYTHON_SUFFIXES = (".py", ".pyi", ".pyw")
_YAML_SUFFIXES = (".yml", ".yaml")
_TOML_SUFFIXES = (".toml",)
_TOML_NAMES = frozenset({"uv.lock", "poetry.lock", "cargo.lock", "pipfile"})
_HCL_SUFFIXES = (".tf", ".tfvars", ".hcl")
_HASH_NAMES = frozenset({"yarn.lock", ".env"})
_GUARDRAIL_KIND = "guardrail_tamper"


def _hash_comment_file(name: str) -> bool:
    if name in _HASH_NAMES or name.startswith(".env."):
        return True
    if name.endswith(".in"):
        return True
    if not name.endswith(".txt"):
        return False
    return "requirements" in name or "constraints" in name


def marker_style(path) -> str | None:
    name = PurePath(str(path)).name.lower()
    if name.endswith(_PYTHON_SUFFIXES):
        return "python"
    if comment_family(path) is not None:
        return "source"
    if name.endswith(_YAML_SUFFIXES):
        return "yaml"
    if name.endswith(_TOML_SUFFIXES) or name in _TOML_NAMES:
        return "toml"
    if name.endswith(_HCL_SUFFIXES):
        return "hcl"
    if _hash_comment_file(name):
        return "hash"
    return None


def _hash_comments(lines: list[str]) -> dict[int, str]:
    comments = {}
    for number, line in enumerate(lines, start=1):
        for index, char in enumerate(line):
            if char == "#" and (index == 0 or line[index - 1] in " \t"):
                comments[number] = line[index:]
                break
    return comments


def _stripped_comments(lines: list[str], code: list[str] | None) -> dict[int, str]:
    if code is None or len(code) != len(lines):
        return {}
    comments = {}
    for number, (line, before) in enumerate(zip(lines, code), start=1):
        rest = line[len(before.rstrip("\r\n")) :].strip()
        if rest.startswith("#"):
            comments[number] = rest
    return comments


def _yaml_comments(text: str, lines: list[str]) -> dict[int, str]:
    from skylos.security.injection_scanner import _yaml_lines_without_comments

    return _stripped_comments(lines, _yaml_lines_without_comments(text))


def _toml_comments(text: str, lines: list[str]) -> dict[int, str]:
    from skylos.security.injection_scanner import _toml_lines_without_comments

    return _stripped_comments(lines, _toml_lines_without_comments(text))


def _hcl_line_comment(line: str, state: dict) -> str | None:
    index = 0
    while index < len(line):
        if state["block"]:
            close = line.find("*/", index)
            if close < 0:
                return None
            state["block"] = False
            index = close + 2
            continue
        char = line[index]
        if char == '"':
            index += 1
            while index < len(line) and line[index] != '"':
                if line[index] == "\\":
                    index += 1
                index += 1
            index += 1
            continue
        if char == "#" or line.startswith("//", index):
            return line[index:]
        if line.startswith("/*", index):
            state["block"] = True
            index += 2
            continue
        if line.startswith("<<", index):
            label = line[index + 2 :].lstrip("-").strip()
            if label.isidentifier():
                state["heredoc"] = label
                return None
        index += 1
    return None


def _hcl_comments(lines: list[str]) -> dict[int, str]:
    comments = {}
    state = {"block": False, "heredoc": None}
    for number, line in enumerate(lines, start=1):
        if state["heredoc"] is not None:
            if line.strip() == state["heredoc"]:
                state["heredoc"] = None
            continue
        comment = _hcl_line_comment(line, state)
        if comment is not None:
            comments[number] = comment
    return comments


def _config_comments(style: str, text: str, lines: list[str]) -> dict[int, str]:
    if style == "yaml":
        return _yaml_comments(text, lines)
    if style == "toml":
        return _toml_comments(text, lines)
    if style == "hcl":
        return _hcl_comments(lines)
    return _hash_comments(lines)


def _rule_markers(comments: dict[int, str]) -> dict[int, set[str]]:
    markers = {}
    for number, comment in comments.items():
        rules = set(_MARKER_TEXT.findall(comment))
        body = comment_body(comment)
        if body is not None:
            parsed = parse_directive(body)
            if parsed is not None and parsed[0] == "rules":
                rules.update(parsed[1])
        if rules:
            markers[number] = rules
    return markers


def _standalone(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("#", "//"))


class FileMarkers:
    """Markers of one file, read once."""

    def __init__(self, path, text: str | None):
        self.path = path
        self.style = marker_style(path)
        self.lines = []
        self.ignore_lines = set()
        self.rules_by_line = {}
        self.block_headers = {}
        if text is None:
            self.style = None
            return
        self.lines = text.splitlines()
        if self.style == "python":
            from skylos.config import (
                get_skylos_ignore_lines,
                get_skylos_ignore_rules_by_line,
            )

            self.ignore_lines = get_skylos_ignore_lines(text)
            self.rules_by_line = get_skylos_ignore_rules_by_line(text)
        elif self.style == "source":
            self.ignore_lines, self.rules_by_line = inline_ignores(path, text)
        elif self.style is not None:
            self.rules_by_line = _rule_markers(
                _config_comments(self.style, text, self.lines)
            )
        if self.style == "yaml" and "skylos" in text:
            self.block_headers, header_comments = _yaml_block_headers(text)
            for line, rules in _rule_markers(header_comments).items():
                self.rules_by_line.setdefault(line, set()).update(rules)

    def _marked(self, rule_id: str, line: int) -> int | None:
        if rule_id in self.rules_by_line.get(line, ()):
            return line
        above = line - 1
        if (
            above >= 1
            and rule_id in self.rules_by_line.get(above, ())
            and _standalone(self.lines[above - 1])
        ):
            return above
        return None

    def marker_line(self, finding: dict) -> int | None:
        line = finding.get("line")
        if not isinstance(line, int) or isinstance(line, bool):
            return None
        rule_id = str(finding.get("rule_id") or "").upper()
        if self.style in ("python", "source"):
            if finding_is_inline_ignored(
                finding, self.ignore_lines, self.rules_by_line
            ):
                return line
            return None
        if self.style is None or not rule_id:
            return None
        marker = self._marked(rule_id, line)
        if marker is None and line in self.block_headers:
            marker = self._marked(rule_id, self.block_headers[line])
        return marker


def _yaml_block_headers(text: str) -> tuple[dict[int, int], dict[int, str]]:
    import yaml

    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    try:
        tokens = list(yaml.scan(text, Loader=loader))
    except (yaml.YAMLError, ValueError, RecursionError):
        return {}, {}
    lines = text.splitlines()
    headers = {}
    comments = {}
    for token in tokens:
        if not isinstance(token, yaml.ScalarToken) or token.style not in ("|", ">"):
            continue
        header = token.start_mark.line + 1
        if header <= len(lines):
            after = lines[header - 1][token.start_mark.column :]
            index = after.find("#")
            if index > 0 and after[index - 1] in " \t":
                comments[header] = after[index:]
        last = token.end_mark.line
        if token.end_mark.column > 0:
            last += 1
        for line in range(header + 1, last + 1):
            headers[line] = header
    return headers, comments


def read_file_markers(path) -> FileMarkers:
    text = None
    if marker_style(path) is not None:
        text = read_text_no_symlink(
            path, max_bytes=MAX_MARKER_FILE_BYTES, errors="replace"
        )
    return FileMarkers(path, text)


def trust_boundary_finding(finding: dict) -> bool:
    from skylos.core.sca_baseline import supply_chain_trust_rule

    return supply_chain_trust_rule(finding) or finding.get("kind") == _GUARDRAIL_KIND


def _base_lines(root: Path, path: Path, commit: str) -> list[str] | None:
    from skylos.cicd.policy import _base_text
    from skylos.config import ConfigError
    from skylos.core.git_context import GitContext

    try:
        context = GitContext.from_path(root)
        relative = path.resolve().relative_to(context.root.resolve()).as_posix()
        text = _base_text(context, commit, relative)
    except (ConfigError, OSError, ValueError, subprocess.SubprocessError):
        return None
    if text is None:
        return None
    return [line.strip() for line in text.splitlines()]


def _current_lines(path: Path) -> list[str]:
    text = read_text_no_symlink(path, max_bytes=MAX_MARKER_FILE_BYTES, errors="replace")
    if text is None:
        return []
    return text.splitlines()


def _held_on_base(current: list[str], line: int, marker: int, base) -> bool:
    if base is None or not 1 <= marker <= line <= len(current):
        return False
    wanted = [current[index - 1].strip() for index in range(marker, line + 1)]
    for start in range(len(base) - len(wanted) + 1):
        if base[start : start + len(wanted)] == wanted:
            return True
    return False


class MarkerReader:
    """Reads each file's markers once and answers per finding.

    Files a worker already parsed answer from the worker's markers; any
    other file is read here with the grammar of its kind."""

    def __init__(self, root=None, ignore_lines=None, ignore_rules=None):
        self.root = None
        if root is not None:
            self.root = Path(os.path.realpath(str(root)))
        self._worker_lines = ignore_lines or {}
        self._worker_rules = ignore_rules or {}
        self._worker = None
        self._files = {}
        self._base = {}
        self.policy_base = None
        from skylos.config import POLICY_BASE_ENV_VAR

        commit = os.environ.get(POLICY_BASE_ENV_VAR)
        if commit:
            self.policy_base = commit

    def resolve(self, file) -> Path | None:
        if not file:
            return None
        path = Path(str(file))
        if not path.is_absolute():
            if self.root is None:
                return None
            path = self.root / path
        return Path(os.path.realpath(str(path)))

    def _worker_markers(self, path: Path):
        if self._worker is None:
            self._worker = {}
            for key in set(self._worker_lines) | set(self._worker_rules):
                self._worker[os.path.realpath(str(key))] = (
                    self._worker_lines.get(key, set()),
                    self._worker_rules.get(key, {}),
                )
        return self._worker.get(str(path))

    def markers(self, path: Path) -> FileMarkers:
        key = str(path)
        if key not in self._files:
            self._files[key] = read_file_markers(path)
        return self._files[key]

    def _base_holds(self, path: Path, line: int, marker: int) -> bool:
        key = str(path)
        if key not in self._base:
            self._base[key] = _base_lines(
                self.root or path.parent, path, self.policy_base
            )
        return _held_on_base(_current_lines(path), line, marker, self._base[key])

    def marker_line(self, finding: dict) -> int | None:
        path = self.resolve(finding.get("file"))
        if path is None:
            return None
        worker = self._worker_markers(path)
        if worker is not None:
            if finding_is_inline_ignored(finding, worker[0], worker[1]):
                return finding.get("line")
            return None
        return self.markers(path).marker_line(finding)

    def ignored(self, finding: dict) -> bool:
        marker = self.marker_line(finding)
        if marker is None:
            return False
        if self.policy_base and trust_boundary_finding(finding):
            path = self.resolve(finding.get("file"))
            if not self._base_holds(path, int(finding["line"]), marker):
                finding["inline_ignore_not_honoured"] = "policy_base"
                return False
        return True
