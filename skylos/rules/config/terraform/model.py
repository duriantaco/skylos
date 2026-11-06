"""A bounded, source-only Terraform module and literal/reference model.

Input variables, external modules, data sources and unsupported expressions are
unknown. This is neither a Terraform interpreter nor a provider schema validator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from bisect import bisect_right
import json
import math
import os
from pathlib import Path
import re
from typing import Any

from skylos.core.file_discovery import should_exclude_path
from skylos.core.safe_cache_io import read_project_text_no_symlink


MAX_FILES = 256
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_DIRECTORIES = 20000
MAX_NODES = 50000
MAX_DEPTH = 64
MAX_RESOLVE_WORK = 4096
_SKIP_DIRS = {
    ".git",
    ".terraform",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "build",
    "dist",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
}
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
_LOCAL_START = re.compile(r"local\.([A-Za-z_][A-Za-z0-9_-]*)")
_SELECTOR = re.compile(r'\.([A-Za-z_][A-Za-z0-9_-]*)|\[(\d+|"(?:[^"\\]|\\.)*")\]')
_INTERPOLATION = re.compile(r"(?<!\$)\$\{|(?<!%)%\{")
_HCL_ESCAPE = re.compile(r'\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[nrt"\\])')


@dataclass(frozen=True)
class Unknown:
    reason: str

    def __bool__(self):
        raise TypeError("Unresolved Terraform values have no truth value")


@dataclass(frozen=True)
class Expression:
    text: str


def is_unknown(value: object) -> bool:
    return isinstance(value, Unknown)


@dataclass(frozen=True)
class Resource:
    resource_type: str
    name: str
    file: str
    line: int
    attributes: dict[str, Any]
    module: Path


@dataclass
class Project:
    resources: list[Resource] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    analysis_errors: list[dict[str, Any]] = field(default_factory=list)
    _locals: dict[Path, dict[str, Any]] = field(default_factory=dict, repr=False)
    _providers: dict[Path, dict[str, Any]] = field(default_factory=dict, repr=False)
    _aliases: dict[Path, set[tuple[str, str]]] = field(default_factory=dict, repr=False)
    _incomplete_modules: set[Path] = field(default_factory=set, repr=False)
    _discovery_complete: bool = field(default=True, repr=False)

    def _unknown(self, reason):
        self.coverage["unresolved_resolution_attempts"] += 1
        return Unknown(reason)

    def resolve(self, value, resource: Resource | None = None):
        self.coverage["resolution_attempts"] += 1
        module = resource.module if resource is not None else None
        if module is None and len(self._locals) == 1:
            module = next(iter(self._locals))
        if not self._discovery_complete or module in self._incomplete_modules:
            return self._unknown("incomplete_module")
        return self._resolve(value, module, set(), [MAX_RESOLVE_WORK], 0)

    def _resolve(self, value, module, active, budget, depth):
        budget[0] -= 1
        if budget[0] < 0 or depth > MAX_DEPTH:
            return self._unknown("resolution_budget")
        if isinstance(value, Unknown):
            return self._unknown(value.reason)
        if value is None:
            return self._unknown("null_or_unset")
        if isinstance(value, Expression):
            text = value.text.strip()
            match = _LOCAL_START.match(text)
            if match is None:
                return self._unknown("external_or_unsupported_expression")
            name = match.group(1)
            key = (module, name)
            if key in active:
                return self._unknown("local_cycle")
            bindings = self._locals.get(module, {})
            if name not in bindings:
                return self._unknown("unresolved_local")
            selectors = []
            position = match.end()
            while position < len(text):
                selector = _SELECTOR.match(text, position)
                if selector is None:
                    return self._unknown("unsupported_local_expression")
                selectors.append(selector.group(1) or selector.group(2))
                position = selector.end()
            resolved = self._resolve(
                bindings[name], module, active | {key}, budget, depth + 1
            )
            for selector in selectors:
                if isinstance(resolved, Unknown):
                    return resolved
                try:
                    if isinstance(resolved, dict):
                        key_value = (
                            json.loads(selector)
                            if selector.startswith('"')
                            else selector
                        )
                        resolved = resolved[key_value]
                    elif isinstance(resolved, list) and selector.isdecimal():
                        resolved = resolved[int(selector)]
                    else:
                        return self._unknown("invalid_local_selector")
                except (KeyError, IndexError, ValueError, TypeError):
                    return self._unknown("unresolved_local_selector")
            return resolved
        if isinstance(value, list):
            return [
                self._resolve(item, module, active, budget, depth + 1) for item in value
            ]
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                return self._unknown("dynamic_object_key")
            return {
                key: self._resolve(item, module, active, budget, depth + 1)
                for key, item in value.items()
            }
        if isinstance(value, float) and not math.isfinite(value):
            return self._unknown("unsupported_number")
        if type(value) in (str, int, float, bool):
            return value
        return self._unknown("unsupported_value")

    def instance_status(self, resource: Resource) -> str:
        if not self._discovery_complete or resource.module in self._incomplete_modules:
            return "unknown"
        attrs = resource.attributes
        if "count" in attrs and "for_each" in attrs:
            return "unknown"
        if "count" in attrs:
            count = self.resolve(attrs["count"], resource)
            if type(count) is not int or count < 0:
                return "unknown"
            return "absent" if count == 0 else "present"
        if "for_each" in attrs:
            items = self.resolve(attrs["for_each"], resource)
            if not isinstance(items, dict):
                return "unknown"
            return "present" if items else "absent"
        return "present"

    def aws_provider_status(self, resource: Resource) -> bool | None:
        if not self._discovery_complete or resource.module in self._incomplete_modules:
            return None
        raw = resource.attributes.get("provider")
        if raw is None:
            local_name, alias = resource.resource_type.split("_", 1)[0], None
        else:
            if isinstance(raw, Expression):
                reference = raw.text
            elif resource.file.endswith(".tf.json") and isinstance(raw, str):
                reference = raw
            else:
                return None
            parts = reference.split(".")
            if len(parts) not in (1, 2) or any(
                not _IDENTIFIER.fullmatch(p) for p in parts
            ):
                return None
            local_name, alias = parts[0], parts[1] if len(parts) == 2 else None
        providers = self._providers.get(resource.module, {})
        source = providers.get(local_name, f"hashicorp/{local_name}")
        if isinstance(source, Unknown) or not isinstance(source, str):
            return None
        source = source.lower().removeprefix("registry.terraform.io/")
        if source != "hashicorp/aws":
            return False
        if alias is not None and (local_name, alias) not in self._aliases.get(
            resource.module, set()
        ):
            return None
        return True


def _error(project, path, kind, message, line=1, error_type="ConfigError"):
    path = Path(path)
    project._incomplete_modules.add(path.parent if _is_tf(path) else path)
    project.analysis_errors.append(
        {
            "rule_id": "SKY-ANALYSIS-INCOMPLETE",
            "severity": "HIGH",
            "kind": kind,
            "file": str(path),
            "line": max(1, int(line or 1)),
            "column": 1,
            "error_type": error_type,
            "message": message,
        }
    )


def _is_tf(path):
    return path.name.endswith(".tf") or path.name.endswith(".tf.json")


def _absolute(path, base):
    candidate = Path(os.path.abspath(base / path))
    # Normalize filesystem aliases in ancestors (e.g. macOS /var) without
    # following a final symlink source or selected directory into a new scope.
    return candidate.parent.resolve() / candidate.name


def _discover(root, project, changed_files, scan_paths, exclude_folders):
    if root.is_symlink() or not root.exists():
        _error(
            project,
            root,
            "terraform_scope_error",
            "Terraform scan root is missing or is a symlink",
        )
        return []
    root = root.resolve()
    if not root.is_file() and not root.is_dir():
        _error(
            project,
            root,
            "terraform_source_read_error",
            "Terraform source root is not a regular file or directory",
        )
        return []
    base = root.parent if root.is_file() else root
    file_target = root.is_file()
    if file_target and not _is_tf(root):
        return []
    selected_modules = None
    if changed_files is not None:
        selected_modules = {
            _absolute(Path(name), base).parent
            for name in changed_files
            if _is_tf(Path(name)) or str(name).endswith((".tfvars", ".tfvars.json"))
        }
    requested_files = set()
    requested_dirs = set()
    if scan_paths is not None:
        for entry in scan_paths:
            candidate = _absolute(Path(entry), base)
            if candidate.is_dir():
                requested_dirs.add(candidate)
            elif _is_tf(candidate):
                requested_files.add(candidate.parent)
        if not requested_files and not requested_dirs:
            return []
    found = []
    visited = 0

    def walk_error(error):
        path = Path(getattr(error, "filename", None) or base)
        project._incomplete_modules.add(path)
        project.coverage["discovery_errors"].append(
            {
                "kind": "terraform_discovery_error",
                "file": str(path),
                "line": 1,
                "error_type": type(error).__name__,
                "message": "Could not enumerate potential Terraform configuration",
            }
        )

    for directory, dirs, names in os.walk(base, followlinks=False, onerror=walk_error):
        visited += 1
        parent = Path(directory)
        if visited > MAX_DIRECTORIES:
            project._discovery_complete = False
            _error(
                project,
                base,
                "terraform_budget_exceeded",
                "Terraform directory discovery budget exhausted",
            )
            break
        dirs[:] = [
            name
            for name in sorted(dirs)
            if name not in _SKIP_DIRS
            and not (parent / name).is_symlink()
            and not should_exclude_path(parent / name, base, exclude_folders)
        ]
        if file_target:
            dirs[:] = []
        if selected_modules is not None and parent not in selected_modules:
            continue
        if (
            scan_paths is not None
            and parent not in requested_files
            and not any(
                parent == directory or parent.is_relative_to(directory)
                for directory in requested_dirs
            )
        ):
            continue
        for name in sorted(names):
            path = parent / name
            if not _is_tf(path):
                continue
            if path.is_symlink() or should_exclude_path(path, base, exclude_folders):
                _error(
                    project,
                    path,
                    "terraform_module_context_excluded",
                    "A Terraform module file was excluded or is a symlink; module values are unresolved",
                )
                continue
            found.append(path)
            if len(found) > MAX_FILES:
                project._discovery_complete = False
                _error(
                    project,
                    path,
                    "terraform_budget_exceeded",
                    "Terraform file discovery budget exhausted",
                )
                return found[:MAX_FILES]
    return found


def _decode_hcl_string(value):
    text = value[1:-1]
    escapes = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}

    def replace(match):
        escaped = match.group(1)
        return (
            chr(int(escaped[1:], 16)) if escaped[0] in ("u", "U") else escapes[escaped]
        )

    return _HCL_ESCAPE.sub(replace, text)


def _template(value, *, native=False):
    if _INTERPOLATION.search(value):
        if not native and value.startswith("${") and value.endswith("}"):
            return Expression(value[2:-1].strip())
        return Unknown("string_template")
    return value.replace("$${", "${").replace("%%{", "%{")


def _normalize(value, *, native=False, depth=0):
    if depth > MAX_DEPTH:
        return Unknown("value_depth")
    if isinstance(value, str):
        if native:
            if value.startswith('"') and value.endswith('"'):
                return _template(_decode_hcl_string(value), native=True)
            if value.startswith("${") and value.endswith("}"):
                return Expression(value[2:-1].strip())
        return _template(value)
    if isinstance(value, list):
        return [_normalize(v, native=native, depth=depth + 1) for v in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if native:
                if key.startswith('"') and key.endswith('"'):
                    key = _template(_decode_hcl_string(key), native=True)
                elif not _IDENTIFIER.fullmatch(key):
                    key = Expression(key)
            result[key] = _normalize(item, native=native, depth=depth + 1)
        return result
    return value


def _native_blocks(text):
    import hcl2
    from hcl2.utils import SerializationOptions

    options = SerializationOptions(
        with_comments=False, explicit_blocks=False, preserve_heredocs=False
    )
    tree = hcl2.parses(text)
    stack = [(tree, 0)]
    node_count = 0
    while stack:
        node, depth = stack.pop()
        node_count += 1
        if node_count > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("Terraform AST budget exhausted")
        if getattr(node, "lark_name", lambda: "")() == "body":
            names = set()
            for child in node.children:
                if getattr(child, "lark_name", lambda: "")() == "attribute":
                    name = child.identifier.serialize(options)
                    if name in names:
                        raise ValueError("Duplicate Terraform body attribute")
                    names.add(name)
        stack.extend((child, depth + 1) for child in getattr(node, "children", ()))
    blocks = []
    for block in tree.children[0].children:
        kind = getattr(block, "lark_name", lambda: "")()
        if kind == "attribute":
            raise ValueError("Terraform top-level attributes are invalid")
        if kind != "block":
            continue
        labels = [label.serialize(options) for label in block.labels]
        labels = [
            _decode_hcl_string(label)
            if label.startswith('"') and label.endswith('"')
            else label
            for label in labels
        ]
        attrs = _normalize(block.body.serialize(options), native=True)
        line = getattr(getattr(block, "_meta", None), "line", 1)
        blocks.append((labels[0], labels[1:], attrs, line))
    return blocks


def _strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Terraform JSON key")
        result[key] = value
    return result


def _invalid_json_constant(value):
    raise ValueError("Nonfinite Terraform JSON value")


def _json_block_locations(text):
    """Find declaration lines in already validated JSON without source regexes."""
    decoder = json.JSONDecoder()
    newline_offsets = [
        index for index, character in enumerate(text) if character == "\n"
    ]
    locations = {}
    work = [MAX_NODES]

    def whitespace(position):
        while position < len(text) and text[position].isspace():
            position += 1
        return position

    def visit(position, path, depth):
        work[0] -= 1
        if work[0] < 0 or depth > MAX_DEPTH:
            raise ValueError("Terraform JSON structure budget exhausted")
        position = whitespace(position)
        if text[position] == "{":
            position = whitespace(position + 1)
            if text[position] == "}":
                return position + 1
            while True:
                key_position = position
                key, position = decoder.raw_decode(text, position)
                child_path = (*path, key)
                if (
                    len(child_path) == 3
                    and child_path[0] == "resource"
                    or len(child_path) == 2
                    and child_path[0] == "module"
                ):
                    locations[child_path] = (
                        bisect_right(newline_offsets, key_position) + 1
                    )
                position = visit(whitespace(position) + 1, child_path, depth + 1)
                position = whitespace(position)
                if text[position] == "}":
                    return position + 1
                position = whitespace(position + 1)
        if text[position] == "[":
            position = whitespace(position + 1)
            if text[position] == "]":
                return position + 1
            while True:
                position = whitespace(visit(position, path, depth + 1))
                if text[position] == "]":
                    return position + 1
                position = whitespace(position + 1)
        return decoder.raw_decode(text, position)[1]

    visit(0, (), 0)
    return locations


def _json_blocks(text):
    document = json.loads(
        text,
        object_pairs_hook=_strict_json_object,
        parse_constant=_invalid_json_constant,
    )
    if not isinstance(document, dict):
        raise ValueError("Terraform JSON root must be an object")
    locations = _json_block_locations(text)
    blocks = []
    for kind, values in document.items():
        if not isinstance(values, dict):
            raise ValueError("Unsupported Terraform JSON block shape")
        if kind in ("locals", "terraform"):
            blocks.append((kind, [], _normalize(values), 1))
        elif kind == "resource":
            for resource_type, resources in values.items():
                if not isinstance(resources, dict):
                    raise ValueError("Terraform JSON resources must be objects")
                for name, attrs in resources.items():
                    if not isinstance(attrs, dict):
                        raise ValueError(
                            "Terraform JSON resource body must be an object"
                        )
                    blocks.append(
                        (
                            kind,
                            [resource_type, name],
                            _normalize(attrs),
                            locations.get(("resource", resource_type, name), 1),
                        )
                    )
        else:
            for label, bodies in values.items():
                bodies = bodies if isinstance(bodies, list) else [bodies]
                if any(not isinstance(body, dict) for body in bodies):
                    raise ValueError("Unsupported Terraform JSON block body")
                blocks.extend(
                    (kind, [label], _normalize(body), locations.get((kind, label), 1))
                    for body in bodies
                )
    return blocks


def load_project(root, *, changed_files=None, scan_paths=None, exclude_folders=None):
    project = Project(
        coverage={
            "status": "not_applicable",
            "files_discovered": 0,
            "files_parsed": 0,
            "resources": 0,
            "modules": 0,
            "resolution_attempts": 0,
            "unresolved_resolution_attempts": 0,
            "scope": "terraform_modules",
            "module_calls": [],
            "discovery_errors": [],
        }
    )
    root = Path(os.path.abspath(root))
    source_root = root
    if not root.is_symlink():
        try:
            source_root = (root.parent if root.is_file() else root).resolve()
        except (OSError, RuntimeError) as exc:
            _error(
                project,
                root,
                "terraform_scope_error",
                "Could not resolve Terraform source root",
                error_type=type(exc).__name__,
            )
            project.coverage["status"] = "incomplete"
            return project
    paths = _discover(root, project, changed_files, scan_paths, exclude_folders)
    project.coverage["files_discovered"] = len(paths)
    project.coverage["modules"] = len({path.parent for path in paths})
    addresses = set()
    total_bytes = 0
    for path in paths:
        module = path.parent
        project._locals.setdefault(module, {})
        project._providers.setdefault(module, {})
        project._aliases.setdefault(module, set())
        filename = path.name.removesuffix(".json")
        if filename == "override.tf" or filename.endswith("_override.tf"):
            _error(
                project,
                path,
                "terraform_unsupported_override",
                "Terraform override files require merge semantics that are not supported",
            )
            continue
        try:
            size = path.lstat().st_size
            if size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
                raise ValueError("Terraform input size budget exhausted")
            raw = read_project_text_no_symlink(
                source_root,
                path,
                max_bytes=MAX_FILE_BYTES + 1,
                encoding="utf-8",
                errors="surrogateescape",
                newline="",
            )
            if raw is None:
                raise OSError(
                    "Terraform source is unreadable or not a scoped regular file"
                )
            # Carry undecodable bytes through the bounded reader, then retain
            # strict UTF-8-with-BOM diagnostics from the original byte parser.
            data = raw.encode("utf-8", "surrogateescape")
            total_bytes += len(data)
            if len(data) > MAX_FILE_BYTES or total_bytes > MAX_TOTAL_BYTES:
                raise ValueError("Terraform input size budget exhausted")
            text = data.decode("utf-8-sig")
        except (OSError, UnicodeError) as exc:
            _error(
                project,
                path,
                "terraform_source_read_error",
                "Could not read Terraform configuration",
                error_type=type(exc).__name__,
            )
            continue
        except ValueError as exc:
            project._discovery_complete = False
            _error(
                project,
                path,
                "terraform_budget_exceeded",
                "Terraform input size budget exhausted",
                error_type=type(exc).__name__,
            )
            break
        try:
            blocks = (
                _json_blocks(text)
                if path.name.endswith(".tf.json")
                else _native_blocks(text)
            )
        except ImportError as exc:
            _error(
                project,
                path,
                "terraform_parser_unavailable",
                "Terraform HCL parser is unavailable",
                error_type=type(exc).__name__,
            )
            continue
        except Exception as exc:
            _error(
                project,
                path,
                "terraform_parse_error",
                "Could not parse Terraform configuration",
                line=getattr(exc, "line", 1),
                error_type=type(exc).__name__,
            )
            continue
        project.coverage["files_parsed"] += 1
        for kind, labels, attrs, line in blocks:
            if kind == "module":
                source = attrs.get("source")
                source = source if isinstance(source, str) else None
                project.coverage["module_calls"].append(
                    {
                        "name": labels[0] if len(labels) == 1 else None,
                        "file": str(path),
                        "line": line,
                        "source": source,
                        "source_kind": (
                            "unknown"
                            if source is None
                            else "local"
                            if source.startswith(("./", "../"))
                            else "external"
                        ),
                        "status": "unknown",
                        "reason": "Module invocation, inputs and provider bindings are not evaluated",
                    }
                )
            elif kind == "resource":
                if len(labels) != 2 or any(
                    not _IDENTIFIER.fullmatch(label) for label in labels
                ):
                    _error(
                        project,
                        path,
                        "terraform_parse_error",
                        "Invalid Terraform resource labels",
                        line,
                    )
                    continue
                address = (module, *labels)
                if address in addresses:
                    _error(
                        project,
                        path,
                        "terraform_duplicate_resource",
                        "Duplicate Terraform resource address",
                        line,
                    )
                    continue
                addresses.add(address)
                project.resources.append(
                    Resource(labels[0], labels[1], str(path), line, attrs, module)
                )
            elif kind == "locals":
                for name, value in attrs.items():
                    if name in project._locals[module]:
                        project._locals[module][name] = Unknown("duplicate_local")
                        _error(
                            project,
                            path,
                            "terraform_duplicate_local",
                            "Duplicate Terraform local binding",
                            line,
                        )
                    else:
                        project._locals[module][name] = value
            elif kind == "terraform":
                required = attrs.get("required_providers", [])
                required = [required] if isinstance(required, dict) else required
                if not isinstance(required, list):
                    _error(
                        project,
                        path,
                        "terraform_parse_error",
                        "Invalid Terraform required provider map",
                        line,
                    )
                    continue
                for mapping in required:
                    if not isinstance(mapping, dict):
                        _error(
                            project,
                            path,
                            "terraform_parse_error",
                            "Invalid Terraform required provider map",
                            line,
                        )
                        continue
                    for name, value in mapping.items():
                        source = (
                            value.get("source", f"hashicorp/{name}")
                            if isinstance(value, dict)
                            else f"hashicorp/{name}"
                            if isinstance(value, str)
                            else Unknown("provider_source")
                        )
                        if name in project._providers[module]:
                            project._providers[module][name] = Unknown(
                                "duplicate_provider"
                            )
                            _error(
                                project,
                                path,
                                "terraform_duplicate_provider",
                                "Duplicate Terraform provider source",
                                line,
                            )
                        else:
                            project._providers[module][name] = source
            elif kind == "provider" and len(labels) == 1:
                alias = attrs.get("alias")
                if isinstance(alias, str) and _IDENTIFIER.fullmatch(alias):
                    key = (labels[0], alias)
                    if key in project._aliases[module]:
                        _error(
                            project,
                            path,
                            "terraform_duplicate_provider",
                            "Duplicate Terraform provider alias",
                            line,
                        )
                    project._aliases[module].add(key)
    project.coverage["resources"] = len(project.resources)
    project.coverage["status"] = (
        "incomplete"
        if project.analysis_errors or project.coverage["discovery_errors"]
        else "complete"
        if paths
        else "not_applicable"
    )
    return project
