from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from skylos.core.file_discovery import discover_source_files
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.visitors.languages.java.core import JavaCore

_FXML_SUFFIXES = {".fxml"}
_MAX_REFERENCE_FILE_BYTES = 512_000
_CONTROLLER_SCOPE_TYPES = {
    "compact_constructor_declaration",
    "constructor_declaration",
    "method_declaration",
}
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_CONTROLLER_RE = re.compile(
    r"""\bfx:controller\s*=\s*(?P<quote>["'])"""
    r"""(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"""
    r"""(?P=quote)"""
)
_HANDLER_RE = re.compile(
    r"""\bon[A-Za-z_$][\w$]*\s*=\s*(?P<quote>["'])"""
    r"""\s*#(?P<name>[A-Za-z_$][\w$]*)\s*(?P=quote)"""
)
_FxmlDocument = tuple[Path, str, set[str]]


def collect_java_fxml_refs(
    project_root: Path,
    source_files,
    *,
    exclude_folders=None,
) -> list[tuple[str, str]]:
    root = Path(project_root).resolve()
    java_files = _java_source_files(source_files)
    if not java_files or not root.is_dir():
        return []

    fxml_files = discover_source_files(
        root,
        _FXML_SUFFIXES,
        exclude_folders=exclude_folders,
    )
    if not fxml_files:
        return []

    documents = _read_fxml_documents(root, fxml_files)
    if not documents:
        return []

    programmatic_controllers: list[tuple[str, str]] = []
    if _needs_programmatic_controllers(documents):
        programmatic_controllers = _collect_programmatic_controllers(root, java_files)
    return _collect_fxml_document_refs(root, documents, programmatic_controllers)


def _java_source_files(source_files) -> list[Path]:
    java_files: list[Path] = []
    for file_path in source_files:
        path = Path(file_path)
        if path.suffix.lower() == ".java":
            java_files.append(path.resolve())
    return java_files


def _read_fxml_documents(
    project_root: Path,
    fxml_files,
) -> list[_FxmlDocument]:
    documents: list[_FxmlDocument] = []
    for fxml_file in fxml_files:
        path = Path(fxml_file)
        source = _read_fxml_source(project_root, path)
        if source is None:
            continue
        controllers = {
            match.group("name").rsplit(".", 1)[-1]
            for match in _CONTROLLER_RE.finditer(source)
        }
        documents.append((path, source, controllers))
    return documents


def _read_fxml_source(project_root: Path, fxml_file: Path) -> str | None:
    source = read_project_text_no_symlink(
        project_root,
        fxml_file,
        max_bytes=_MAX_REFERENCE_FILE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if source is None:
        return None
    return _XML_COMMENT_RE.sub("", source)


def _needs_programmatic_controllers(documents: list[_FxmlDocument]) -> bool:
    return any(not controllers for _, _, controllers in documents)


def _collect_fxml_document_refs(
    project_root: Path,
    documents: list[_FxmlDocument],
    programmatic_controllers: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for fxml_file, source, declared_controllers in documents:
        controllers = _controllers_for_fxml_file(
            project_root,
            fxml_file,
            declared_controllers,
            programmatic_controllers,
        )
        _append_fxml_refs(refs, seen, fxml_file, source, controllers)
    return refs


def _controllers_for_fxml_file(
    project_root: Path,
    fxml_file: Path,
    declared_controllers: set[str],
    programmatic_controllers: list[tuple[str, str]],
) -> set[str]:
    if declared_controllers:
        return declared_controllers
    return _programmatic_controllers_for_file(
        project_root,
        fxml_file,
        programmatic_controllers,
    )


def _append_fxml_refs(
    refs: list[tuple[str, str]],
    seen: set[tuple[str, str]],
    fxml_file: Path,
    source: str,
    controllers: set[str],
) -> None:
    handlers = {match.group("name") for match in _HANDLER_RE.finditer(source)}
    ref_file = str(fxml_file)
    for controller in sorted(controllers):
        _append_ref(refs, seen, controller, ref_file)
        _append_ref(refs, seen, f"{controller}.initialize", ref_file)
        for handler in sorted(handlers):
            _append_ref(refs, seen, f"{controller}.{handler}", ref_file)


def _collect_programmatic_controllers(
    project_root: Path,
    java_files: list[Path],
) -> list[tuple[str, str]]:
    bindings: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for java_file in java_files:
        candidates = _programmatic_bindings_for_java_file(project_root, java_file)
        _append_unique_bindings(bindings, seen, candidates)

    return bindings


def _programmatic_bindings_for_java_file(
    project_root: Path,
    java_file: Path,
) -> list[tuple[str, str]]:
    source = read_project_text_no_symlink(
        project_root,
        java_file,
        max_bytes=_MAX_REFERENCE_FILE_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if source is None or not _has_programmatic_fxml_markers(source):
        return []

    source_bytes = source.encode("utf-8")
    root_node = JavaCore(str(java_file), source_bytes).root_node
    if root_node is None:
        return []

    bindings: list[tuple[str, str]] = []
    for class_node in _nodes_of_type(root_node, "class_declaration"):
        bindings.extend(_programmatic_bindings_for_class(class_node, source_bytes))
    return bindings


def _has_programmatic_fxml_markers(source: str) -> bool:
    return ".fxml" in source.lower() and "setController" in source


def _programmatic_bindings_for_class(
    class_node,
    source: bytes,
) -> list[tuple[str, str]]:
    class_name_node = class_node.child_by_field_name("name")
    if class_name_node is None:
        return []

    controller = _node_text(class_name_node, source)
    bindings: list[tuple[str, str]] = []
    for scope_node in _controller_scope_nodes(class_node):
        if _node_sets_itself_as_fxml_controller(scope_node, source):
            bindings.extend(
                (resource_path, controller)
                for resource_path in _fxml_resource_paths(scope_node, source)
            )
    return bindings


def _controller_scope_nodes(class_node):
    return (
        node
        for node in _walk_class_nodes(class_node)
        if node.type in _CONTROLLER_SCOPE_TYPES
    )


def _fxml_resource_paths(scope_node, source: bytes):
    for node in _walk_class_nodes(scope_node):
        if node.type != "string_literal":
            continue
        literal = _node_text(node, source).strip('"')
        if literal.lower().endswith(".fxml"):
            yield literal.replace("\\", "/").lstrip("/")


def _nodes_of_type(root_node, node_type: str):
    return (node for node in _walk_nodes(root_node) if node.type == node_type)


def _append_unique_bindings(
    bindings: list[tuple[str, str]],
    seen: set[tuple[str, str]],
    candidates: list[tuple[str, str]],
) -> None:
    for binding in candidates:
        if binding in seen:
            continue
        seen.add(binding)
        bindings.append(binding)


def _node_sets_itself_as_fxml_controller(scope_node, source: bytes) -> bool:
    for node in _walk_class_nodes(scope_node):
        if node.type != "method_invocation":
            continue
        name_node = node.child_by_field_name("name")
        arguments = node.child_by_field_name("arguments")
        if name_node is None or arguments is None:
            continue
        if _node_text(name_node, source) != "setController":
            continue
        normalized_arguments = "".join(_node_text(arguments, source).split())
        if normalized_arguments == "(this)":
            return True
    return False


def _walk_class_nodes(class_node):
    stack = list(reversed(class_node.children))
    while stack:
        current = stack.pop()
        if current.type == "class_declaration":
            continue
        yield current
        stack.extend(reversed(current.children))


def _programmatic_controllers_for_file(
    project_root: Path,
    fxml_file: Path,
    bindings: list[tuple[str, str]],
) -> set[str]:
    try:
        relative_path = fxml_file.resolve().relative_to(project_root).as_posix()
    except (OSError, ValueError):
        relative_path = fxml_file.name

    filename = fxml_file.name
    controllers: set[str] = set()
    for resource_path, controller in bindings:
        resource_name = PurePosixPath(resource_path).name
        if relative_path.endswith(resource_path) or filename == resource_name:
            controllers.add(controller)
    return controllers


def _walk_nodes(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _node_text(node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _append_ref(
    refs: list[tuple[str, str]],
    seen: set[tuple[str, str]],
    name: str,
    ref_file: str,
) -> None:
    ref = (name, ref_file)
    if ref in seen:
        return
    seen.add(ref)
    refs.append(ref)
