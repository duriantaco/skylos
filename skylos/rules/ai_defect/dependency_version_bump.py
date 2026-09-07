"""SKY-A106: advisory when a dependency repeats its project's version change.

Only complete, bounded snapshots and literal Python packaging metadata are
supported. No package code is executed and no registry is contacted. Dynamic
metadata, ambiguous records, URL requirements, and unsupported syntax are
deliberately skipped rather than inferred from matching text.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import Any, Callable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib


RULE_ID = "SKY-A106"
PROJECT_MANIFEST_NAMES = ("pyproject.toml", "setup.py")
MAX_MANIFEST_BYTES = 2_000_000
_MAX_FILES = 256
_MAX_TOTAL_BYTES = 16_000_000
_MAX_TOKENS = 100_000
_MAX_DEPTH = 64
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_VERSION = re.compile(r"[0-9][A-Za-z0-9.!+_-]*\Z")
_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?\s*(.*)$")
_SPECIFIER = re.compile(r"(===|==|!=|~=|>=|<=|>|<|\^|~)\s*([0-9][A-Za-z0-9.!+_-]*)\Z")
_TOKEN = re.compile(
    r"(?P<space>[ \t\r]+)|(?P<comment>\#[^\n]*)|(?P<newline>\n)"
    r'|(?P<string>"""(?:[^"\\]|\\.|"(?!""))*"{3,5}'
    r"|'''(?:[^']|'(?!''))*'{3,5}"
    r'|"(?:[^"\\\n]|\\.)*"|\'[^\'\n]*\')'
    r'|(?P<punct>[\[\]{},=.])|(?P<bare>[^\s\[\]{},=.#"\']+)',
    re.DOTALL,
)


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    line: int


class _TomlLocations:
    """Index scalar locations from a TOML document already validated by tomllib.

    This is a location lexer, not a replacement TOML value parser. Table and
    key paths are resolved against the parsed document, so comments, repeated
    strings, arrays, inline tables, and package subtables cannot cross scopes.
    Unsupported location syntax makes the document ineligible for a signal.
    """

    def __init__(self, text: str, data: dict[str, Any]):
        self.data = data
        self.locations: dict[tuple, int] = {}
        self.tokens: list[_Token] = []
        offset = 0
        line = 1
        for match in _TOKEN.finditer(text):
            if match.start() != offset:
                raise ValueError("Unsupported TOML token")
            kind = match.lastgroup
            token_text = match.group()
            if kind not in {"space", "comment"}:
                self.tokens.append(_Token(kind, token_text, line))
            line += token_text.count("\n")
            offset = match.end()
            if len(self.tokens) > _MAX_TOKENS:
                raise ValueError("Too many TOML tokens")
        if offset != len(text):
            raise ValueError("Unsupported TOML token")
        self.index = 0
        self.array_indices: dict[tuple, int] = {}
        self._document()

    def _peek(self, text: str) -> bool:
        return self.index < len(self.tokens) and self.tokens[self.index].text == text

    def _take(self, expected: str | None = None) -> _Token:
        if self.index >= len(self.tokens):
            raise ValueError("Missing TOML token")
        token = self.tokens[self.index]
        if expected is not None and token.text != expected:
            raise ValueError("Unexpected TOML token")
        self.index += 1
        return token

    def _keys(self) -> tuple[str, ...]:
        keys = []
        while True:
            token = self._take()
            if token.kind == "string":
                key = tomllib.loads("key=" + token.text)["key"]
            elif token.kind == "bare":
                key = token.text
            else:
                raise ValueError("Unsupported TOML key")
            keys.append(key)
            if not self._peek("."):
                return tuple(keys)
            self._take(".")

    def _table_path(self, keys: tuple, array: bool) -> tuple:
        value: Any = self.data
        path: tuple = ()
        for index, key in enumerate(keys):
            value = value[key]
            path += (key,)
            if isinstance(value, list):
                if array and index == len(keys) - 1:
                    self.array_indices[path] = self.array_indices.get(path, -1) + 1
                array_index = self.array_indices[path]
                path += (array_index,)
                value = value[array_index]
        return path

    def _document(self) -> None:
        table: tuple = ()
        while self.index < len(self.tokens):
            if self._peek("\n"):
                self._take()
            elif self._peek("["):
                self._take()
                array = self._peek("[")
                if array:
                    self._take()
                keys = self._keys()
                self._take("]")
                if array:
                    self._take("]")
                table = self._table_path(keys, array)
            else:
                path = table + self._keys()
                self._take("=")
                self._value(path, 0)

    def _value(self, path: tuple, depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise ValueError("TOML nesting limit")
        token = self._take()
        self.locations[path] = token.line
        if token.text == "[":
            item = 0
            while not self._peek("]"):
                if self._peek("\n") or self._peek(","):
                    self._take()
                    continue
                self._value(path + (item,), depth + 1)
                item += 1
            self._take("]")
        elif token.text == "{":
            while not self._peek("}"):
                if self._peek(",") or self._peek("\n"):
                    self._take()
                    continue
                keys = self._keys()
                self._take("=")
                self._value(path + keys, depth + 1)
            self._take("}")
        elif token.kind != "string":
            # Numbers/datetimes may contain several lexical pieces. Their
            # values are irrelevant here; their enclosing semantic key is not.
            while self.index < len(self.tokens):
                if self.tokens[self.index].text in {"\n", ",", "]", "}"}:
                    break
                self._take()

    def line(self, path: tuple) -> int | None:
        return self.locations.get(path)


@dataclass(frozen=True)
class _Identity:
    name: str
    version: str
    path: str
    line: int


@dataclass(frozen=True)
class _Dependency:
    name: str
    version: str
    slot: tuple
    line: int
    source_span: tuple[int, int] | None = None


@dataclass
class _Document:
    identities: list[_Identity]
    dependencies: list[_Dependency]
    local_names: set[str] = field(default_factory=set)


def is_supported_path(path: str) -> bool:
    """Whether a normalized repository path is supported by this detector."""
    if not isinstance(path, str) or not path or "\\" in path:
        return False
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or any(part in {".", ".."} for part in path.split("/")):
        return False
    name = parsed.name
    return name in {*PROJECT_MANIFEST_NAMES, "uv.lock", "poetry.lock"} or (
        name.endswith(".txt")
        and (name.startswith("requirements") or "requirements" in parsed.parts[:-1])
    )


def _name(value: Any) -> str | None:
    if isinstance(value, str) and _NAME.fullmatch(value):
        return re.sub(r"[-_.]+", "-", value).lower()
    return None


def _version(value: Any) -> str | None:
    return value if isinstance(value, str) and _VERSION.fullmatch(value) else None


def _get(data: Any, path: tuple, default: Any = None) -> Any:
    try:
        for key in path:
            data = data[key]
        return data
    except (KeyError, IndexError, TypeError):
        return default


def _requirement(
    text: Any,
    scope: tuple,
    line: int | None,
    *,
    version_line: Callable[[int, str], int] | None = None,
) -> list[_Dependency]:
    if not isinstance(text, str) or line is None or "\n" in text or "\\" in text:
        return []
    leading_space = len(text) - len(text.lstrip())
    text = re.split(r"\s+#", text, maxsplit=1)[0].strip()
    spec_text, _, marker = text.partition(";")
    match = _REQUIREMENT.fullmatch(spec_text.strip())
    if not match:
        return []
    name = _name(match[1])
    if name is None:
        return []
    extras = tuple(
        sorted(
            extra.strip().lower()
            for extra in (match[2] or "").split(",")
            if extra.strip()
        )
    )
    constraint_offset = (
        leading_space + match.start(3) + len(match[3]) - len(match[3].lstrip())
    )
    constraints = match[3].strip()
    if constraints.startswith("(") and constraints.endswith(")"):
        constraints = constraints[1:-1]
        constraint_offset += 1 + len(constraints) - len(constraints.lstrip())
        constraints = constraints.strip()
    result = []
    for constraint in constraints.split(","):
        specifier = _SPECIFIER.fullmatch(constraint.strip())
        if not specifier:
            return []
        operator, version = specifier.groups()
        offset = (
            constraint_offset
            + len(constraint)
            - len(constraint.lstrip())
            + specifier.start(2)
        )
        result.append(
            _Dependency(
                name,
                version,
                scope + (name, extras, marker.strip(), operator),
                version_line(offset, version) if version_line else line,
            )
        )
        constraint_offset += len(constraint) + 1
    return result


def _toml_document(path: str, text: str) -> _Document:
    data = tomllib.loads(text)
    source = _TomlLocations(text, data)
    identities = []
    dependencies = []
    local_names = set()
    if PurePosixPath(path).name in {"uv.lock", "poetry.lock"}:
        packages = data.get("package", [])
        if not isinstance(packages, list):
            return _Document([], [])
        for index, package in enumerate(packages):
            if not isinstance(package, dict):
                continue
            name, version = _name(package.get("name")), _version(package.get("version"))
            line = source.line(("package", index, "version"))
            origin = package.get("source", {})
            if not isinstance(origin, dict):
                continue
            if PurePosixPath(path).name == "uv.lock":
                # Editable, virtual, path, Git, and URL artifacts are not
                # independent registry dependencies.
                if set(origin) != {"registry"} or not isinstance(
                    origin["registry"], str
                ):
                    if name:
                        local_names.add(name)
                    continue
                registry = origin["registry"]
            else:
                if origin and origin.get("type") not in {"legacy", "index"}:
                    if name:
                        local_names.add(name)
                    continue
                registry = origin.get("url", "")
                if not isinstance(registry, str):
                    continue
            if name and version and line:
                dependencies.append(
                    _Dependency(name, version, ("lock", name, registry, "=="), line)
                )
        return _Document([], dependencies, local_names)

    sources = _get(data, ("tool", "uv", "sources"), {})
    if isinstance(sources, dict):
        for name, configurations in sources.items():
            if not isinstance(configurations, list):
                configurations = [configurations]
            if _name(name) and any(
                isinstance(value, dict)
                and any(
                    key in value
                    for key in ("workspace", "path", "editable", "git", "url")
                )
                for value in configurations
            ):
                local_names.add(_name(name))

    for section in (("project",), ("tool", "poetry")):
        metadata = _get(data, section)
        if not isinstance(metadata, dict):
            continue
        name, version = _name(metadata.get("name")), _version(metadata.get("version"))
        dynamic = metadata.get("dynamic", [])
        line = source.line(section + ("version",))
        if (
            name
            and version
            and line
            and isinstance(dynamic, list)
            and "version" not in dynamic
        ):
            identities.append(_Identity(name, version, path, line))

    groups: list[tuple] = [("project", "dependencies"), ("build-system", "requires")]
    for section in (("project", "optional-dependencies"), ("dependency-groups",)):
        values = _get(data, section, {})
        if isinstance(values, dict):
            groups.extend(section + (key,) for key in values)
    for group in groups:
        values = _get(data, group, [])
        if isinstance(values, list):
            for index, value in enumerate(values):
                dependencies.extend(
                    _requirement(value, group, source.line(group + (index,)))
                )

    poetry_groups = [
        ("tool", "poetry", "dependencies"),
        ("tool", "poetry", "dev-dependencies"),
    ]
    groups_data = _get(data, ("tool", "poetry", "group"), {})
    if isinstance(groups_data, dict):
        poetry_groups.extend(
            ("tool", "poetry", "group", key, "dependencies") for key in groups_data
        )
    for group in poetry_groups:
        values = _get(data, group, {})
        if not isinstance(values, dict):
            continue
        for name, value in values.items():
            if name == "python" or _name(name) is None:
                continue
            value_path = group + (name,)
            marker = ""
            if isinstance(value, dict):
                if any(key in value for key in ("path", "git", "url")):
                    local_names.add(_name(name))
                    continue
                marker = str(value.get("markers", ""))
                value = value.get("version")
                value_path += ("version",)
            if not isinstance(value, str):
                continue
            if _version(value):
                value = "==" + value
            dependencies.extend(
                _requirement(
                    name + value + (";" + marker if marker else ""),
                    group,
                    source.line(value_path),
                )
            )
    return _Document(identities, dependencies, local_names)


def _setup_version_line(
    source_lines: list[str], node: ast.Constant
) -> Callable[[int, str], int]:
    """Locate a version inside static adjacent string tokens without execution.

    Python joins adjacent literals into one AST constant. Keep each token's
    decoded range so an unchanged package-name token cannot anchor a version
    that changed in a later token. Full source spans separately cover escaped
    or split versions where one exact token location would be insufficient.
    """
    # AST columns are UTF-8 byte offsets. Slice only this literal's lines;
    # rescanning the whole manifest for every dependency would be quadratic.
    lines = source_lines[node.lineno - 1 : node.end_lineno]
    lines[-1] = lines[-1].encode("utf-8")[: node.end_col_offset].decode("utf-8")
    lines[0] = lines[0].encode("utf-8")[node.col_offset :].decode("utf-8")
    segment = "".join(lines)
    pieces = []
    offset = 0
    try:
        for token in tokenize.generate_tokens(io.StringIO(segment).readline):
            if token.type != tokenize.STRING:
                continue
            value = ast.literal_eval(token.string)
            if not isinstance(value, str):
                continue
            pieces.append((offset, offset + len(value), token))
            offset += len(value)
            if len(pieces) > _MAX_TOKENS:
                pieces = []
                break
    except (SyntaxError, ValueError, tokenize.TokenError):
        pieces = []

    def locate(value_offset: int, version: str) -> int:
        for start, end, token in pieces:
            if start <= value_offset < end:
                line = node.lineno + token.start[0] - 1
                # Exact version text also gives the right physical line in a
                # multiline token. Ambiguous/escaped spellings use the token
                # start, with the complete literal span retained as evidence.
                if token.string.count(version) == 1:
                    line += token.string[: token.string.index(version)].count("\n")
                return line
        return node.lineno

    return locate


def _setup_document(path: str, text: str) -> _Document:
    tree = ast.parse(text)
    nodes = list(ast.walk(tree))
    if len(nodes) > _MAX_TOKENS:
        return _Document([], [])
    source_lines = io.StringIO(text, newline=None).readlines()
    setup_names = set()
    module_names = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module in {
            "setuptools",
            "distutils.core",
        }:
            setup_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "setup"
            )
        elif isinstance(node, ast.Import):
            module_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "setuptools"
            )
    shadowed = set()
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadowed.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            shadowed.add(node.id)
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.attr == "setup"
            and isinstance(node.value, ast.Name)
        ):
            shadowed.add(node.value.id)
        elif isinstance(node, ast.arg):
            shadowed.add(node.arg)
        elif isinstance(node, ast.ImportFrom) and node.module not in {
            "setuptools",
            "distutils.core",
        }:
            shadowed.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            shadowed.update(
                alias.asname or alias.name.split(".")[0]
                for alias in node.names
                if alias.name != "setuptools"
            )
    setup_names -= shadowed
    module_names -= shadowed
    statements = list(tree.body)
    for node in tree.body:
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "__name__"
            and len(node.test.ops) == len(node.test.comparators) == 1
            and isinstance(node.test.ops[0], ast.Eq)
            and isinstance(node.test.comparators[0], ast.Constant)
            and node.test.comparators[0].value == "__main__"
        ):
            statements.extend(node.body)
    calls = [
        statement.value
        for statement in statements
        if isinstance(statement, ast.Expr)
        and isinstance(node := statement.value, ast.Call)
        and (
            isinstance(node.func, ast.Name)
            and node.func.id in setup_names
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == "setup"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in module_names
        )
    ]
    if len(calls) != 1 or any(keyword.arg is None for keyword in calls[0].keywords):
        return _Document([], [])
    keywords = {keyword.arg: keyword.value for keyword in calls[0].keywords}
    if len(keywords) != len(calls[0].keywords):
        return _Document([], [])
    name_node, version_node = keywords.get("name"), keywords.get("version")
    name = _name(name_node.value) if isinstance(name_node, ast.Constant) else None
    version = (
        _version(version_node.value) if isinstance(version_node, ast.Constant) else None
    )
    identities = (
        [_Identity(name, version, path, version_node.lineno)]
        if name and version
        else []
    )
    dependencies = []

    def collect(node: ast.AST | None, scope: tuple) -> None:
        if isinstance(node, (ast.List, ast.Tuple)):
            for item in node.elts:
                if isinstance(item, ast.Constant):
                    span = (
                        (item.lineno, item.end_lineno)
                        if item.end_lineno and item.end_lineno > item.lineno
                        else None
                    )
                    records = _requirement(
                        item.value,
                        scope,
                        item.lineno,
                        version_line=(
                            _setup_version_line(source_lines, item) if span else None
                        ),
                    )
                    dependencies.extend(
                        replace(record, source_span=span) for record in records
                    )

    for keyword in ("install_requires", "setup_requires", "tests_require"):
        collect(keywords.get(keyword), (keyword,))
    extras = keywords.get("extras_require")
    if isinstance(extras, ast.Dict):
        for key, value in zip(extras.keys, extras.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                collect(value, ("extras_require", key.value))
    return _Document(identities, dependencies)


def _parse(path: str, text: Any) -> _Document:
    empty = _Document([], [])
    if (
        not isinstance(text, str)
        or len(text.encode("utf-8", errors="replace")) > MAX_MANIFEST_BYTES
    ):
        return empty
    try:
        if PurePosixPath(path).name == "setup.py":
            return _setup_document(path, text)
        if PurePosixPath(path).suffix == ".txt":
            dependencies = []
            for line, value in enumerate(text.splitlines(), 1):
                dependencies.extend(_requirement(value, ("requirements",), line))
            return _Document([], dependencies)
        return _toml_document(path, text)
    except (
        ValueError,
        SyntaxError,
        TypeError,
        KeyError,
        IndexError,
        RecursionError,
        OverflowError,
    ):
        return empty


def _directory(path: str) -> str:
    return str(PurePosixPath(path).parent)


def _owner(path: str, roots: set[str]) -> str | None:
    directory = PurePosixPath(path).parent
    for candidate in (directory, *directory.parents):
        if str(candidate) in roots:
            return str(candidate)
    return None


def _identities(documents: dict[str, _Document]) -> dict[str, _Identity]:
    by_directory: dict[str, list[_Identity]] = defaultdict(list)
    for path, document in documents.items():
        if PurePosixPath(path).name in PROJECT_MANIFEST_NAMES:
            by_directory[_directory(path)].extend(document.identities)
    result = {}
    for directory, identities in by_directory.items():
        if len({(item.name, item.version) for item in identities}) == 1:
            result[directory] = sorted(identities, key=lambda item: item.path)[0]
    return result


def _changed_dependencies(before: list[_Dependency], after: list[_Dependency]):
    old_slots: dict[tuple, list[_Dependency]] = defaultdict(list)
    new_slots: dict[tuple, list[_Dependency]] = defaultdict(list)
    for dependency in before:
        old_slots[dependency.slot].append(dependency)
    for dependency in after:
        new_slots[dependency.slot].append(dependency)
    for slot in sorted(old_slots.keys() & new_slots.keys()):
        old_versions = Counter(item.version for item in old_slots[slot])
        new_versions = Counter(item.version for item in new_slots[slot])
        removed = list((old_versions - new_versions).elements())
        added = list((new_versions - old_versions).elements())
        # An unchanged duplicate record is not a second version transition.
        # Multiple changed records in one semantic slot are ambiguous.
        if len(removed) == len(added) == 1:
            matching = [item for item in new_slots[slot] if item.version == added[0]]
            if len(matching) == 1:
                yield removed[0], matching[0]


def detect_mirrored_dependency_bumps(
    before_files: dict[str, str], after_files: dict[str, str]
) -> list[dict]:
    """Compare complete snapshots, returning neutral advisory findings.

    Callers should supply changed supported files and their ancestor project
    manifests. Even malformed nested manifests establish ownership boundaries;
    an outer package's version never supplies evidence for an inner package.
    """
    if not isinstance(before_files, dict) or not isinstance(after_files, dict):
        return []
    paths = sorted(
        path
        for path in before_files.keys() | after_files.keys()
        if is_supported_path(path)
    )
    if len(paths) > _MAX_FILES:
        return []
    total = sum(
        len(value.encode("utf-8", errors="replace"))
        for files in (before_files, after_files)
        for path in paths
        if isinstance(value := files.get(path), str)
    )
    if total > _MAX_TOTAL_BYTES:
        return []
    before = {
        path: _parse(path, before_files[path]) for path in paths if path in before_files
    }
    after = {
        path: _parse(path, after_files[path]) for path in paths if path in after_files
    }
    old_identities, new_identities = _identities(before), _identities(after)
    roots = {
        _directory(path)
        for path in paths
        if PurePosixPath(path).name in PROJECT_MANIFEST_NAMES
    }
    # Known projects remain internal packages even when a workspace consumes
    # their published releases. Source overrides, however, belong only to the
    # project declaring them and must not leak into independent projects.
    project_names = {
        identity.name
        for document in (*before.values(), *after.values())
        for identity in document.identities
    }
    local_names: dict[str | None, set[str]] = defaultdict(set)
    for documents in (before, after):
        for path, document in documents.items():
            owner = _owner(path, roots)
            local_names[owner].update(document.local_names)
    findings = []
    seen = set()
    for path in paths:
        if (
            path not in before
            or path not in after
            or before_files[path] == after_files[path]
        ):
            continue
        owner = _owner(path, roots)
        old_project, new_project = old_identities.get(owner), new_identities.get(owner)
        if (
            old_project is None
            or new_project is None
            or old_project.name != new_project.name
            or old_project.version == new_project.version
        ):
            continue
        for old_version, dependency in _changed_dependencies(
            before[path].dependencies, after[path].dependencies
        ):
            if (
                dependency.name in project_names
                or dependency.name in local_names[owner]
                or old_version != old_project.version
                or dependency.version != new_project.version
            ):
                continue
            key = (
                path,
                dependency.line,
                dependency.name,
                old_version,
                dependency.version,
            )
            if key in seen:
                continue
            seen.add(key)
            metadata = {
                "signal_only": True,
                "blocking_recommended": False,
                "project": new_project.name,
                "project_old_version": old_project.version,
                "project_new_version": new_project.version,
                "project_file": new_project.path,
                "project_line": new_project.line,
                "dependency": dependency.name,
                "dependency_old_version": old_version,
                "dependency_new_version": dependency.version,
                "dependency_operator": dependency.slot[-1],
                "evidence_path": path,
            }
            finding = {
                "rule_id": RULE_ID,
                "severity": "LOW",
                "category": "ai_defect",
                "kind": "mirrored_dependency_bump",
                "defect_type": "mirrored_dependency_bump",
                "file": path,
                "basename": PurePosixPath(path).name,
                "line": dependency.line,
                "col": 0,
                "name": dependency.name,
                "message": (
                    f"Dependency '{dependency.name}' changed from {old_version} to {dependency.version}, "
                    f"matching project '{new_project.name}'. Review whether this dependency "
                    "change was intentional; matching versions alone do not prove a defect."
                ),
                "metadata": metadata,
            }
            if dependency.source_span:
                finding["related_locations"] = [
                    {
                        "file": path,
                        "start_line": dependency.source_span[0],
                        "end_line": dependency.source_span[1],
                    }
                ]
            findings.append(finding)
    return sorted(findings, key=lambda item: (item["file"], item["line"], item["name"]))
