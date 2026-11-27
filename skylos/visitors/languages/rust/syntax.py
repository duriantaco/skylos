"""Rust edition compatibility for the tree-sitter syntax used by the visitors."""

import re
from pathlib import Path

import tomllib

from skylos.core.safe_cache_io import read_project_text_no_symlink


def _manifest_data(root, manifest):
    text = read_project_text_no_symlink(
        root, manifest.relative_to(root), max_bytes=1_000_000
    )
    if text is None:
        return {}
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return {}


def _legacy_package(file_path, project_root):
    if file_path is None:
        return None
    path = Path(file_path).absolute()
    if path.is_symlink():
        return None
    # Without the scan boundary, look only inside a conventional Cargo target.
    root = (
        Path(project_root).absolute()
        if project_root
        else next(
            (
                parent.parent
                for parent in path.parents
                if parent.name in {"src", "examples", "tests", "benches"}
            ),
            path.parent,
        )
    )
    if root not in path.parents or root.is_symlink():
        return None
    if project_root is None and root.resolve() != root:
        return None
    # Walk down from the scan boundary. A nearer manifest must not end this
    # check before a symlink in an enclosing directory is seen.
    directory = root
    manifest = None
    for part in ("", *path.parent.relative_to(root).parts):
        directory /= part
        if directory.is_symlink():
            return None
        candidate = directory / "Cargo.toml"
        if candidate.is_symlink():
            return None
        if candidate.exists():
            manifest = candidate
    if manifest is None:
        return None
    data = _manifest_data(root, manifest)
    package = data.get("package")
    if not isinstance(package, dict) or not isinstance(package.get("name"), str):
        return None
    edition = package.get("edition", "2015")
    if edition == {"workspace": True}:
        workspace = data.get("workspace")
        if "workspace" in package:
            # An explicitly redirected workspace may lie outside the scan.
            return None
        for parent in manifest.parent.parents:
            if workspace is not None or (parent != root and root not in parent.parents):
                break
            workspace = _manifest_data(root, parent / "Cargo.toml").get("workspace")
        defaults = workspace.get("package") if isinstance(workspace, dict) else None
        edition = defaults.get("edition") if isinstance(defaults, dict) else None
    if edition != "2015":
        return None
    # Targets may override the package edition. A source module can be shared
    # by several targets, so only recover when all declared editions agree.
    targets = [data.get("lib", {})]
    for kind in ("bin", "bench", "test", "example"):
        entries = data.get(kind, [])
        if not isinstance(entries, list):
            return None
        targets.extend(entries)
    if any(
        not isinstance(target, dict)
        or target.get("edition", "2015") != "2015"
        or target.get("path") not in (None, "src/lib.rs", "src/main.rs")
        for target in targets
    ):
        return None
    return root, manifest.parent


def _may_shadow_try(root):
    # A macro with a different expansion may never evaluate its argument.
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == "macro_definition":
            name = node.child_by_field_name("name")
            if name is not None and name.text.removeprefix(b"r#") == b"try":
                return True
        elif (
            node.type == "use_declaration"
            and re.search(rb"\btry\b|\*", node.text)
            or node.type in {"attribute_item", "inner_attribute_item"}
            and re.search(rb"\b(?:macro_use|path)\b", node.text)
            or node.type == "macro_invocation"
            and (
                node.parent.type == "source_file"
                or node.parent.type == "expression_statement"
                and node.parent.parent.type == "source_file"
            )
        ):
            return True
        if node.type not in {"token_tree", "macro_rule"}:
            pending.extend(node.named_children)
    return False


def _parent_may_shadow_try(parser, path, root, package):
    """Check the conventional module owners, including lib and bin roots."""
    src = package / "src"
    if src not in path.parents:
        return True
    if path in (src / "lib.rs", src / "main.rs"):
        return False
    parts = path.relative_to(src).with_suffix("").parts
    if parts[-1] == "mod":
        parts = parts[:-1]
    if not parts or parts[0] == "bin" or len(parts) > 24:
        return True
    directory = src
    owners = [src / "lib.rs", src / "main.rs"]
    for name in parts:
        declared = False
        for owner in owners:
            if owner.is_symlink():
                return True
            if not owner.exists():
                continue
            text = read_project_text_no_symlink(
                root, owner.relative_to(root), max_bytes=2_000_000
            )
            if text is None:
                return True
            parent = parser.parse(text.encode()).root_node
            if _may_shadow_try(parent):
                return True
            declared |= any(
                item.type == "mod_item"
                and item.child_by_field_name("body") is None
                and (module_name := item.child_by_field_name("name")) is not None
                and module_name.text == name.encode()
                for item in parent.named_children
            )
        if not declared:
            return True
        directory /= name
        owners = [directory.with_suffix(".rs"), directory / "mod.rs"]
    return False


def parse_rust_source(parser, source, file_path, project_root=None):
    tree = parser.parse(source)
    if not tree.root_node.has_error or b"try!" not in source:
        return tree
    # The grammar treats the legacy spelling as an ERROR preceding an
    # otherwise parsed parenthesized expression. Keep that expression visible
    # to the visitors, including calls inside it. Strings, comments and valid
    # token trees cannot enter this recovery path.
    starts = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if (
            node.is_error
            and node.end_byte - node.start_byte == 4
            and node.text == b"try!"
        ):
            following = node.next_sibling
            while following is not None and following.type in {
                "line_comment",
                "block_comment",
            }:
                following = following.next_sibling
            if following is not None and source.startswith(b"(", following.start_byte):
                starts.append(node.start_byte)
        else:
            pending.extend(child for child in node.children if child.has_error)
    if not starts:
        return tree
    package = _legacy_package(file_path, project_root)
    if package is None or _may_shadow_try(tree.root_node):
        return tree
    if _parent_may_shadow_try(parser, Path(file_path).absolute(), *package):
        return tree
    adjusted = bytearray(source)
    for start in starts:
        adjusted[start : start + 4] = b"    "
    tree = parser.parse(adjusted)
    # Node.text keeps a view of this input; other visitors also slice the
    # original source using the tree's byte offsets.
    adjusted[:] = source
    return tree
