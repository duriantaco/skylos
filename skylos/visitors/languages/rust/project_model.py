"""Rust crates, the module tree and path resolution across a scanned project.

Cargo builds every target as its own crate: the library, each binary, each
integration test, bench and example, and the build script. rustc loads
modules only through `mod` declarations (`#[path]` included), so every item
has a crate-relative path such as `crate::flags::lowargs::Mode`.

The per-file visitor names definitions from the file layout (the path after
`src/`), which is wrong for crates without `src/` and blind to re-exports and
aliases. This model reads Cargo.toml targets and walks the `mod` tree, so the
project pass (`project_liveness.py`) can follow `use` trees leaf by leaf,
`pub(crate) use` chains, `as` aliases and `Type::item` paths to the item they
name.

The model only supplies evidence. A path it cannot resolve stays unresolved
and its callers keep their previous behaviour or abstain.
"""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None

from skylos.core.safe_cache_io import read_project_text_no_symlink

from .core import RUST_LANG, _get_parser
from .syntax import parse_rust_source

_MAX_FILES = 20_000
_MAX_FILE_BYTES = 2_000_000
_MAX_TOTAL_BYTES = 400_000_000
_MAX_MANIFEST_BYTES = 1_000_000
_MAX_DEPTH = 24

ITEM_KINDS = {
    "function_item": "fn",
    "function_signature_item": "fn",
    "struct_item": "struct",
    "enum_item": "enum",
    "union_item": "union",
    "trait_item": "trait",
    "type_item": "type",
    "const_item": "const",
    "static_item": "static",
    "macro_definition": "macro",
}
TYPE_KINDS = frozenset({"struct", "enum", "union", "trait", "type"})

# Lint names whose `allow` silences dead code or unused imports.
_DEAD_CODE_LINTS = frozenset({"dead_code", "unused", "warnings"})
_UNUSED_IMPORT_LINTS = frozenset({"unused_imports", "unused", "warnings"})
_LINT_LEVEL_RE = re.compile(r"\b(?:allow|expect)\s*\(([^()]*)\)")

UNKNOWN = ("unknown",)
EXTERNAL = ("external",)


class Package:
    __slots__ = ("crates", "directory", "edition", "lib_name", "manifest", "name")

    def __init__(self, manifest, directory, name, lib_name, edition):
        self.manifest = manifest
        self.directory = directory
        self.name = name
        self.lib_name = lib_name
        self.edition = edition
        self.crates = []


class Crate:
    __slots__ = (
        "harness",
        "kind",
        "may_use_core_prelude",
        "name",
        "package",
        "root",
        "root_file",
    )

    def __init__(self, package, kind, name, root_file, harness=True):
        self.package = package
        self.kind = kind
        self.name = name
        self.root_file = root_file
        self.root = None
        self.harness = harness
        self.may_use_core_prelude = False

    @property
    def key(self):
        package = self.package.directory if self.package is not None else None
        return (str(package), self.kind, self.name, str(self.root_file))


class Module:
    __slots__ = (
        "crate",
        "directory",
        "file",
        "globs",
        "items",
        "lints",
        "opaque",
        "parent",
        "path",
    )

    def __init__(self, crate, path, file, parent, directory, lints):
        self.crate = crate
        self.path = path
        self.file = file
        self.parent = parent
        self.items = {}
        self.globs = []
        self.lints = lints
        self.directory = directory
        # A module whose items come from an item-level macro (`cfg_if!`,
        # `lazy_static!`) can hold names the model cannot see.
        self.opaque = False


class Item:
    __slots__ = (
        "cfg",
        "file",
        "kind",
        "line",
        "lints",
        "members",
        "module",
        "name",
        "owner",
        "path",
        "public",
        "target",
        "variants",
    )

    def __init__(self, kind, name, file, line, module, *, public=False, lints=()):
        self.kind = kind
        self.name = name
        self.file = file
        self.line = line
        self.module = module
        # True for exactly `pub`; `pub(crate)` re-exports stay crate-internal.
        self.public = public
        self.lints = frozenset(lints)
        self.path = ()
        self.target = None
        self.members = frozenset()
        self.variants = frozenset()
        self.cfg = False
        self.owner = None


class Impl:
    __slots__ = ("methods", "module", "self_type", "target", "trait")

    def __init__(self, module, self_type, trait):
        self.module = module
        self.self_type = self_type
        self.trait = trait
        self.methods = []
        self.target = None


class PathRef:
    """A multi-segment path read in code: `flags::generate_bash()`,
    `Separator::new(..)`, `jsont::Message::Begin`. `local` holds the imports
    declared inside the enclosing function, which shadow module imports."""

    __slots__ = ("local", "module", "owner", "segments")

    def __init__(self, module, segments, owner, local=None):
        self.module = module
        self.segments = segments
        self.owner = owner
        self.local = local


def _may_apply_no_std(nodes):
    """Look at attribute names, including the attributes after a cfg_attr predicate."""
    tokens = [n for n in nodes if n.type not in {"line_comment", "block_comment"}]
    if len(tokens) == 1:
        return tokens[0].type == "identifier" and tokens[0].text == b"no_std"
    if (
        len(tokens) != 2
        or tokens[0].text != b"cfg_attr"
        or tokens[1].type != "token_tree"
    ):
        return False
    groups = [[]]
    for child in tokens[1].children[1:-1]:
        if child.type == ",":
            groups.append([])
        else:
            groups[-1].append(child)
    return any(_may_apply_no_std(group) for group in groups[1:])


def _allowed_lints(attribute_texts):
    lints = set()
    for text in attribute_texts:
        compact = re.sub(r"\s+", "", text)
        if not compact.startswith(("#[", "#![")):
            continue
        body = compact[compact.index("[") + 1 :]
        if not body.startswith(("allow(", "expect(", "cfg_attr(")):
            continue
        # `#[cfg_attr(test, allow(dead_code))]` silences the lint in some
        # configuration, which is enough for the item to be live in another.
        for group in _LINT_LEVEL_RE.findall(body):
            for lint in group.split(","):
                lint = lint.strip()
                if lint:
                    lints.add(lint)
    return lints


def allows_dead_code(lints) -> bool:
    return bool(_DEAD_CODE_LINTS & set(lints))


def allows_unused_imports(lints) -> bool:
    return bool(_UNUSED_IMPORT_LINTS & set(lints))


class RustProject:
    def __init__(self, root, files):
        self.root = Path(root)
        self.files = {}
        self.packages = []
        self.crates = []
        self.modules_by_file = {}
        self.all_targets_scanned = True
        self.complete_target_set = None
        self.items_by_location = {}
        self.uses = []
        self.impls = []
        self.path_refs = []
        self.edition_by_file = {}
        self.macro_names = set()
        self._sources = {}
        self._visited = set()
        self._use_cache = {}
        self._resolving = set()
        self._impls_by_type = None
        self._types_by_crate_name = None
        self._lib_roots = {}
        self._crate_keys = {}
        self._bytes = 0
        for filename in files:
            path = Path(filename)
            if path.suffix != ".rs":
                continue
            try:
                resolved = path.resolve()
            except (OSError, RuntimeError, ValueError):
                continue
            self.files[resolved] = str(filename)
        self.complete = len(self.files) <= _MAX_FILES

    # ------------------------------------------------------------------
    # Cargo packages and targets

    def build(self):
        if not self.complete or RUST_LANG is None or tomllib is None:
            return self
        for manifest in self._manifests():
            self._load_package(manifest)
        for crate in self.crates:
            root = self._load_module(
                crate,
                (),
                crate.root_file,
                None,
                crate.root_file.parent,
                frozenset(),
            )
            crate.root = root
            if crate.kind == "lib" and root is not None:
                self._lib_roots.setdefault(crate.package.lib_name, root)
        # Files no target reaches keep their own inner attributes. Crate-root
        # names go first so their `mod` declarations claim their files.
        for path in sorted(
            self.files,
            key=lambda path: (path.name not in {"lib.rs", "main.rs"}, str(path)),
        ):
            if path not in self.modules_by_file:
                orphan = Crate(None, "orphan", path.stem, path)
                orphan.root = self._load_module(
                    orphan, (), path, None, path.parent, frozenset()
                )
        for impl in self.impls:
            impl.target = self._impl_target(impl)
        return self

    def _read(self, path, max_bytes):
        try:
            return read_project_text_no_symlink(
                self.root, path, max_bytes=max_bytes, errors="replace"
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return None

    def _manifests(self):
        found = set()
        try:
            root = self.root.resolve()
        except (OSError, RuntimeError, ValueError):
            return []
        directories = {path.parent for path in self.files}
        seen = set()
        for directory in directories:
            current = directory
            while current not in seen:
                seen.add(current)
                manifest = current / "Cargo.toml"
                if manifest.is_file() and not manifest.is_symlink():
                    found.add(manifest)
                if current == root or root not in current.parents:
                    break
                current = current.parent
        # Workspace members, benches and examples can sit in directories
        # whose own files are all excluded; their manifests still declare
        # targets for the files that remain.
        return sorted(found)

    def _manifest(self, path):
        text = self._read(path, _MAX_MANIFEST_BYTES)
        if text is None:
            return None
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError, TypeError):
            return None
        return data if isinstance(data, dict) else None

    def _workspace_edition(self, directory):
        try:
            root = self.root.resolve()
        except (OSError, RuntimeError, ValueError):
            return None
        current = directory.parent
        while True:
            manifest = current / "Cargo.toml"
            if manifest.is_file() and not manifest.is_symlink():
                data = self._manifest(manifest)
                workspace = data.get("workspace") if data else None
                if isinstance(workspace, dict):
                    package = workspace.get("package")
                    if isinstance(package, dict) and isinstance(
                        package.get("edition"), str
                    ):
                        return package["edition"]
                    return None
            if current == root or root not in current.parents:
                return None
            current = current.parent

    def _load_package(self, manifest):
        data = self._manifest(manifest)
        package = data.get("package") if data else None
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            return
        directory = manifest.parent
        name = package["name"]
        edition = package.get("edition")
        if isinstance(edition, dict) and edition.get("workspace") is True:
            # Same directory first: a root package can also be the workspace.
            own = data.get("workspace")
            if isinstance(own, dict) and isinstance(own.get("package"), dict):
                edition = own["package"].get("edition")
            else:
                edition = self._workspace_edition(directory)
        if not isinstance(edition, str):
            edition = "2015"
        lib = data.get("lib") if isinstance(data.get("lib"), dict) else {}
        lib_name = lib.get("name") if isinstance(lib.get("name"), str) else name
        record = Package(manifest, directory, name, lib_name.replace("-", "_"), edition)
        self.packages.append(record)
        targets = []

        def add(kind, target_name, path, harness=True):
            try:
                resolved = (directory / path).resolve()
            except (OSError, RuntimeError, ValueError):
                self.all_targets_scanned = False
                return
            if resolved not in self.files:
                self.all_targets_scanned = False
            elif all(t[2] != resolved for t in targets):
                targets.append((kind, target_name, resolved, harness))

        lib_path = lib.get("path") if isinstance(lib.get("path"), str) else None
        if lib_path or (directory / "src" / "lib.rs").is_file():
            add("lib", lib_name, lib_path or "src/lib.rs")
        for kind, table, folder, auto_key in (
            ("bin", "bin", "src/bin", "autobins"),
            ("test", "test", "tests", "autotests"),
            ("bench", "bench", "benches", "autobenches"),
            ("example", "example", "examples", "autoexamples"),
        ):
            entries = data.get(table)
            for entry in entries if isinstance(entries, list) else ():
                if not isinstance(entry, dict):
                    continue
                target_name = entry.get("name")
                path = entry.get("path")
                if not isinstance(path, str):
                    if not isinstance(target_name, str):
                        continue
                    if kind == "bin" and target_name == name:
                        path = "src/main.rs"
                    else:
                        path = f"{folder}/{target_name}.rs"
                        if not (directory / path).is_file():
                            path = f"{folder}/{target_name}/main.rs"
                add(kind, target_name, path, entry.get("harness", True) is not False)
            if package.get(auto_key, True) is False:
                continue
            if kind == "bin" and (directory / "src" / "main.rs").is_file():
                add("bin", name, "src/main.rs")
            base = directory / folder
            if base.is_dir() and not base.is_symlink():
                for child in sorted(base.iterdir()):
                    if child.suffix == ".rs" and child.is_file():
                        add(kind, child.stem, child.relative_to(directory))
                    elif child.is_dir() and (child / "main.rs").is_file():
                        add(
                            kind, child.name, (child / "main.rs").relative_to(directory)
                        )
        build = package.get("build")
        if isinstance(build, str):
            add("build", "build-script", build)
        elif build is not False and (directory / "build.rs").is_file():
            add("build", "build-script", "build.rs")
        for kind, target_name, path, harness in targets:
            crate = Crate(record, kind, target_name, path, harness)
            record.crates.append(crate)
            self.crates.append(crate)

    # ------------------------------------------------------------------
    # Module tree and items

    def _parse(self, path):
        if path not in self._sources:
            text = self._read(path, _MAX_FILE_BYTES)
            if text is None:
                self._sources[path] = None
            else:
                data = text.encode("utf-8")
                self._bytes += len(data)
                if self._bytes > _MAX_TOTAL_BYTES:
                    self.complete = False
                    self._sources[path] = None
                else:
                    tree = parse_rust_source(
                        _get_parser(RUST_LANG), data, path, self.root
                    )
                    self._sources[path] = (data, tree.root_node)
        return self._sources[path]

    def _text(self, data, node):
        if node is None:
            return ""
        return data[node.start_byte : node.end_byte].decode("utf-8", "replace")

    def _load_module(self, crate, path, file, parent, directory, lints):
        key = (crate.key, file)
        if key in self._visited or len(path) > _MAX_DEPTH:
            return None
        parsed = self._parse(file)
        if parsed is None:
            return None
        self._visited.add(key)
        data, root = parsed
        if parent is None:
            crate.may_use_core_prelude = any(
                _may_apply_no_std(attr.children)
                for child in root.named_children
                if child.type == "inner_attribute_item"
                for attr in child.named_children
                if attr.type == "attribute"
            )
        inner = [
            self._text(data, child)
            for child in root.children
            if child.type == "inner_attribute_item"
        ]
        module_lints = frozenset(lints) | frozenset(_allowed_lints(inner))
        module = Module(crate, path, file, parent, directory, module_lints)
        self.modules_by_file.setdefault(file, []).append(module)
        if crate.package is not None:
            self.edition_by_file.setdefault(file, crate.package.edition)
        self._index_block(module, root, data)
        return module

    def _attributes(self, data, node):
        """Outer attributes of an item, across comments between them."""
        texts = []
        previous = node.prev_sibling
        while previous is not None and previous.type in {
            "attribute_item",
            "line_comment",
            "block_comment",
        }:
            if previous.type == "attribute_item":
                texts.append(self._text(data, previous))
            previous = previous.prev_sibling
        texts.reverse()
        return texts

    def _add(self, module, item):
        module.items.setdefault(item.name, []).append(item)
        self._locate(item)

    def _locate(self, item):
        self.items_by_location.setdefault((item.file, item.line, item.name), []).append(
            item
        )

    def _is_public(self, data, node):
        for child in node.children:
            if child.type == "visibility_modifier":
                return self._text(data, child).strip() == "pub"
        return False

    def _index_block(self, module, block, data):
        for child in block.named_children:
            kind = child.type
            if kind in {"attribute_item", "inner_attribute_item"} or kind.endswith(
                "comment"
            ):
                continue
            attributes = self._attributes(data, child)
            lints = module.lints | frozenset(_allowed_lints(attributes))
            cfg = any(
                re.sub(r"\s+", "", text).startswith("#[cfg(") for text in attributes
            )
            if kind == "use_declaration":
                self._index_use(module, child, data, lints, cfg)
            elif kind == "mod_item":
                self._index_mod(module, child, data, lints, attributes, cfg)
            elif kind == "impl_item":
                self._index_impl(module, child, data, lints)
            elif kind == "extern_crate_declaration":
                self._index_extern_crate(module, child, data)
            elif kind in ITEM_KINDS:
                self._index_item(module, child, data, lints, cfg)
            elif kind == "macro_invocation":
                module.opaque = True
                self._collect_paths(module, child, data, None)
            else:
                self._collect_paths(module, child, data, None)

    def _name_node(self, node):
        name = node.child_by_field_name("name")
        if name is None:
            for child in node.children:
                if child.type in {"identifier", "type_identifier"}:
                    return child
        return name

    def _index_item(self, module, node, data, lints, cfg, *, scoped=True, local=None):
        name_node = self._name_node(node)
        name = self._text(data, name_node).strip()
        if not name:
            return None
        kind = ITEM_KINDS[node.type]
        if kind == "macro":
            self.macro_names.add(name)
        item = Item(
            kind,
            name,
            module.file,
            name_node.start_point[0] + 1,
            module,
            public=self._is_public(data, node),
            lints=lints,
        )
        item.cfg = cfg
        body = node.child_by_field_name("body")
        if kind == "trait" and body is not None:
            item.members = frozenset(
                self._text(data, self._name_node(member)).strip()
                for member in body.named_children
                if member.type
                in {
                    "function_signature_item",
                    "function_item",
                    "const_item",
                    "type_item",
                    "associated_type",
                }
            )
            for member in body.named_children:
                if member.type in {"function_signature_item", "function_item"}:
                    self._index_function(module, member, data, lints, owner=item)
        elif kind == "enum" and body is not None:
            item.variants = frozenset(
                self._text(data, self._name_node(variant)).strip()
                for variant in body.named_children
                if variant.type == "enum_variant"
            )
        if scoped:
            self._add(module, item)
        else:
            self._locate(item)
        if kind == "fn":
            self._index_function_body(module, node, data, lints, item, local)
        elif kind != "trait":
            self._collect_paths(module, node, data, None)
        return item

    def _index_function(self, module, node, data, lints, owner):
        attributes = self._attributes(data, node)
        name_node = self._name_node(node)
        name = self._text(data, name_node).strip()
        if not name:
            return None
        item = Item(
            "method",
            name,
            module.file,
            name_node.start_point[0] + 1,
            module,
            public=self._is_public(data, node),
            lints=lints | frozenset(_allowed_lints(attributes)),
        )
        item.cfg = any(
            re.sub(r"\s+", "", text).startswith("#[cfg(") for text in attributes
        )
        item.owner = owner
        self._locate(item)
        self._index_function_body(module, node, data, item.lints, item)
        return item

    def _index_function_body(self, module, node, data, lints, function, local=None):
        """Paths in a function, and its nested items, owned by that function.

        Imports declared in the body are visible only to the body (and its
        nested functions); they shadow the module's imports there.
        """
        if local is None:
            local = {}
        pending = list(node.children)
        while pending:
            child = pending.pop()
            if child.type == "use_declaration":
                self._index_use(module, child, data, lints, False, scope=local)
                continue
            if child.type in ITEM_KINDS and child is not node:
                attributes = self._attributes(data, child)
                nested_lints = lints | frozenset(_allowed_lints(attributes))
                cfg = any(
                    re.sub(r"\s+", "", text).startswith("#[cfg(") for text in attributes
                )
                nested = self._index_item(
                    module, child, data, nested_lints, cfg, scoped=False, local=local
                )
                if nested is not None:
                    nested.owner = function
                continue
            if child.type in {"mod_item", "impl_item"}:
                continue
            if child.type in {"scoped_identifier", "scoped_type_identifier"}:
                self._path_ref(module, child, data, function, local)
                continue
            if child.type == "token_tree":
                self._token_paths(module, child, data, function, local)
                continue
            pending.extend(child.children)

    def _collect_paths(self, module, node, data, owner):
        pending = [node]
        while pending:
            child = pending.pop()
            if child.type in {"mod_item", "use_declaration", "attribute_item"}:
                continue
            if child.type in {"scoped_identifier", "scoped_type_identifier"}:
                self._path_ref(module, child, data, owner)
                continue
            if child.type == "token_tree":
                self._token_paths(module, child, data, owner)
                continue
            pending.extend(child.children)

    def _segments(self, data, node):
        if node is None:
            return ()
        if node.type in {"scoped_identifier", "scoped_type_identifier"}:
            path = node.child_by_field_name("path")
            name = node.child_by_field_name("name")
            if name is None:
                return ()
            prefix = self._segments(data, path) if path is not None else ()
            if path is not None and not prefix:
                return ()
            return (*prefix, self._text(data, name).strip())
        if node.type == "generic_type":
            return self._segments(data, node.child_by_field_name("type"))
        if node.type in {
            "identifier",
            "type_identifier",
            "crate",
            "self",
            "super",
            "metavariable",
        }:
            return (self._text(data, node).strip(),)
        return ()

    def _path_ref(self, module, node, data, owner, local=None):
        segments = self._segments(data, node)
        if len(segments) >= 2:
            self.path_refs.append(PathRef(module, segments, owner, local))

    def _token_paths(self, module, tree, data, owner, local=None):
        """`a::b::c` token runs inside macro arguments."""
        for nested in tree.children:
            if nested.type == "token_tree":
                self._token_paths(module, nested, data, owner, local)
        children = tree.children
        index = 0
        while index < len(children):
            child = children[index]
            if child.type not in {"identifier", "crate", "self", "super"}:
                index += 1
                continue
            segments = [self._text(data, child).strip()]
            index += 1
            while (
                index + 1 < len(children)
                and children[index].type == "::"
                and children[index + 1].type in {"identifier", "self", "super"}
            ):
                segments.append(self._text(data, children[index + 1]).strip())
                index += 2
            if len(segments) >= 2:
                self.path_refs.append(PathRef(module, tuple(segments), owner, local))

    def _use_leaves(self, data, node, prefix=()):
        """(local name, path, is_glob) for each leaf of a use tree."""
        if node is None:
            return []
        if node.type == "use_as_clause":
            path = self._segments(data, node.child_by_field_name("path"))
            alias = self._text(data, node.child_by_field_name("alias")).strip()
            full = (*prefix, *path)
            if full and full[-1] == "self":
                full = full[:-1]
            return [(alias, full, False)] if alias and full else []
        if node.type == "scoped_use_list":
            base = self._segments(data, node.child_by_field_name("path"))
            return self._use_leaves(
                data, node.child_by_field_name("list"), (*prefix, *base)
            )
        if node.type == "use_list":
            leaves = []
            for child in node.named_children:
                leaves.extend(self._use_leaves(data, child, prefix))
            return leaves
        if node.type == "use_wildcard":
            path = ()
            for child in node.named_children:
                path = self._segments(data, child)
                break
            return [("*", (*prefix, *path), True)]
        segments = self._segments(data, node)
        full = (*prefix, *segments)
        if full and full[-1] == "self":
            full = full[:-1]
        if not full or full[-1] in {"crate", "super", "self"}:
            return []
        return [(full[-1], full, False)]

    def _index_use(self, module, node, data, lints, cfg, *, scope=None):
        public = self._is_public(data, node)
        line = node.start_point[0] + 1
        for local, path, glob in self._use_leaves(
            data, node.child_by_field_name("argument")
        ):
            item = Item(
                "glob" if glob else "use",
                local.removeprefix("r#"),
                module.file,
                line,
                module,
                public=public,
                lints=lints,
            )
            item.path = tuple(segment.removeprefix("r#") for segment in path)
            item.cfg = cfg
            self.uses.append(item)
            if scope is not None:
                if not glob:
                    scope.setdefault(item.name, []).append(item)
                self._locate(item)
            elif glob:
                module.globs.append(item)
            else:
                self._add(module, item)

    def _index_extern_crate(self, module, node, data):
        name = self._text(data, node.child_by_field_name("name")).strip()
        alias = self._text(data, node.child_by_field_name("alias")).strip()
        if not name:
            return
        item = Item(
            "extern", alias or name, module.file, node.start_point[0] + 1, module
        )
        item.path = (name,)
        self._add(module, item)

    def _index_mod(self, module, node, data, lints, attributes, cfg):
        name_node = node.child_by_field_name("name")
        name = self._text(data, name_node).strip().removeprefix("r#")
        if not name:
            return
        item = Item(
            "mod",
            name,
            module.file,
            name_node.start_point[0] + 1,
            module,
            public=self._is_public(data, node),
            lints=lints,
        )
        item.cfg = cfg
        self._add(module, item)
        body = node.child_by_field_name("body")
        if body is not None:
            inner = [
                self._text(data, child)
                for child in body.children
                if child.type == "inner_attribute_item"
            ]
            child_module = Module(
                module.crate,
                (*module.path, name),
                module.file,
                module,
                module.directory / name,
                lints | frozenset(_allowed_lints(inner)),
            )
            item.target = child_module
            self._index_block(child_module, body, data)
            return
        target = None
        explicit_path = False
        for text in attributes:
            match = re.match(r'#\[\s*path\s*=\s*"([^"]+)"', text)
            if match:
                explicit_path = True
                # Relative to the source file's directory, or to the inline
                # module's directory when declared inside `mod x { ... }`.
                inline = module.parent is not None and module.parent.file == module.file
                base = module.directory if inline else module.file.parent
                try:
                    target = (base / match.group(1)).resolve()
                except (OSError, RuntimeError, ValueError):
                    target = None
                break
        else:
            for candidate in (
                module.directory / f"{name}.rs",
                module.directory / name / "mod.rs",
            ):
                try:
                    resolved = candidate.resolve()
                except (OSError, RuntimeError, ValueError):
                    continue
                if resolved in self.files:
                    target = resolved
                    break
        if target is None or target not in self.files:
            return
        # rustc searches for children alongside a file loaded by #[path].
        directory = target.parent
        if not explicit_path and target.name != "mod.rs":
            directory = target.parent / target.stem
        item.target = self._load_module(
            module.crate,
            (*module.path, name),
            target,
            module,
            directory,
            lints,
        )

    def _index_impl(self, module, node, data, lints):
        self_type = self._segments(data, node.child_by_field_name("type"))
        trait = self._segments(data, node.child_by_field_name("trait"))
        impl = Impl(module, self_type, trait or None)
        self.impls.append(impl)
        body = node.child_by_field_name("body")
        for child in node.children:
            if child is not body:
                self._collect_paths(module, child, data, None)
        if body is None:
            return
        for member in body.named_children:
            if member.type == "function_item":
                method = self._index_function(module, member, data, lints, owner=impl)
                if method is not None:
                    impl.methods.append(method)
            elif not member.type.endswith("comment"):
                self._collect_paths(module, member, data, None)

    # ------------------------------------------------------------------
    # Resolution

    def crate_keys(self, filename):
        filename = str(filename)
        keys = self._crate_keys.get(filename)
        if keys is None:
            try:
                path = Path(filename).resolve()
            except (OSError, RuntimeError, ValueError):
                path = None
            keys = frozenset(
                module.crate.key for module in self.modules_by_file.get(path, ())
            )
            self._crate_keys[filename] = keys
        return keys

    def modules_of(self, filename):
        try:
            path = Path(filename).resolve()
        except (OSError, RuntimeError, ValueError):
            return ()
        return tuple(self.modules_by_file.get(path, ()))

    def source_tree(self, path):
        parsed = self._sources.get(path)
        return parsed[1] if parsed is not None else None

    def items_at(self, filename, line, name):
        try:
            path = Path(filename).resolve()
        except (OSError, RuntimeError, ValueError):
            return ()
        return tuple(self.items_by_location.get((path, line, name), ()))

    def resolve(self, module, segments, used=None, depth=0, local=None):
        """Targets of a path: ("item", Item), ("member", Item, name),
        ("module", Module), EXTERNAL or UNKNOWN."""
        if not segments or depth > _MAX_DEPTH:
            return [UNKNOWN]
        first, rest = segments[0], tuple(segments[1:])
        if first == "crate" or first == "$crate":
            starts = [("module", module.crate.root)] if module.crate.root else []
        elif first == "self":
            starts = [("module", module)]
        elif first == "super":
            current = module
            remaining = list(segments)
            while remaining and remaining[0] == "super":
                current = current.parent if current is not None else None
                remaining.pop(0)
            if current is None:
                return [UNKNOWN]
            starts = [("module", current)]
            rest = tuple(remaining)
        elif first == "Self":
            return [UNKNOWN]
        else:
            starts = []
            for item in (local or {}).get(first, ()):
                if item in self._resolving:
                    continue
                if used is not None:
                    used.add(item)
                starts.extend(self.resolve_use(item, used, depth + 1))
            if not starts:
                starts = self._lookup(module, first, used, depth, scope=True)
            if not starts:
                return [UNKNOWN if module.opaque or first[:1].isupper() else EXTERNAL]
        if any(start[1] is None for start in starts if start[0] == "module"):
            return [UNKNOWN]
        results = []
        for start in starts:
            results.extend(self._walk(start, rest, used, depth))
        return results or [UNKNOWN]

    def _walk(self, target, rest, used, depth):
        for index, segment in enumerate(rest):
            kind = target[0]
            if kind == "module":
                found = self._lookup(target[1], segment, used, depth, scope=False)
                if not found:
                    return [UNKNOWN]
                if len(found) > 1:
                    results = []
                    for option in found:
                        results.extend(
                            self._walk(option, rest[index + 1 :], used, depth + 1)
                        )
                    return results
                target = found[0]
                continue
            if kind == "item" and target[1].kind in TYPE_KINDS:
                # `Type::member` names the type and its associated item or
                # variant; later segments (`<T as Trait>::X`) are not modelled.
                return [target, ("member", target[1], segment)]
            if kind == "external":
                return [EXTERNAL]
            return [UNKNOWN]
        return [target]

    def _lookup(self, module, name, used, depth, *, scope):
        if module is None:
            return []
        found = []
        for item in module.items.get(name, ()):
            if item.kind == "use":
                if item in self._resolving:
                    continue
                if used is not None:
                    used.add(item)
                found.extend(self.resolve_use(item, used, depth + 1))
            elif item.kind == "extern":
                root = self._lib_roots.get(item.path[0])
                found.append(("module", root) if root is not None else EXTERNAL)
            elif item.kind == "mod":
                found.append(("module", item.target) if item.target else UNKNOWN)
            else:
                found.append(("item", item))
        if found:
            return found
        for glob in module.globs:
            if glob in self._resolving:
                continue
            self._resolving.add(glob)
            try:
                bases = self.resolve(glob.module, glob.path, None, depth + 1)
            finally:
                self._resolving.discard(glob)
            for base in bases:
                if base[0] == "module":
                    inner = self._lookup(base[1], name, used, depth + 1, scope=False)
                elif base[0] == "item" and name in base[1].variants:
                    inner = [("member", base[1], name)]
                else:
                    inner = []
                if inner:
                    if used is not None:
                        used.add(glob)
                    found.extend(inner)
        if found or not scope:
            return found
        # A workspace library named as an external crate (`use grep_printer::X`,
        # or a binary naming its own package's library).
        root = self._lib_roots.get(name)
        if root is not None:
            return [("module", root)]
        return []

    def resolve_use(self, item, used=None, depth=0):
        cached = self._use_cache.get(item)
        if cached is None:
            if item in self._resolving or depth > _MAX_DEPTH:
                return [UNKNOWN]
            self._resolving.add(item)
            traversed = set()
            try:
                results = self.resolve(item.module, item.path, traversed, depth + 1)
            finally:
                self._resolving.discard(item)
            traversed.discard(item)
            cached = (results, frozenset(traversed))
            self._use_cache[item] = cached
        if used is not None:
            used.update(cached[1])
        return cached[0]

    def _impl_target(self, impl):
        if not impl.self_type:
            return None
        for target in self.resolve(impl.module, impl.self_type):
            if target[0] == "item" and target[1].kind in TYPE_KINDS:
                return target[1]
        return None

    def methods_of(self, type_item, name):
        if self._impls_by_type is None:
            index = {}
            for impl in self.impls:
                if impl.target is not None:
                    index.setdefault(id(impl.target), []).append(impl)
            self._impls_by_type = index
        return [
            method
            for impl in self._impls_by_type.get(id(type_item), ())
            for method in impl.methods
            if method.name == name
        ]

    def types_named(self, crate_keys, name):
        if self._types_by_crate_name is None:
            index = {}
            for modules in self.modules_by_file.values():
                for module in modules:
                    for items in module.items.values():
                        for item in items:
                            if item.kind in TYPE_KINDS:
                                index.setdefault(
                                    (module.crate.key, item.name), []
                                ).append(item)
            self._types_by_crate_name = index
        found = []
        for key in crate_keys:
            found.extend(self._types_by_crate_name.get((key, name), ()))
        return found


def build_project(root, files):
    try:
        return RustProject(root, files).build()
    except (OSError, RuntimeError, RecursionError, ValueError, TypeError):
        return None
