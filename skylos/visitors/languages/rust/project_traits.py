"""Bounded local trait evidence for an admitted Rust source-module closure.

Only ordinary ``mod name;`` files rooted at main.rs/lib.rs are expanded, in
memory. The existing conservative local-trait proof then sees *all* competing
implementations in that source crate. Missing/excluded, ambiguous, attributed,
macro-generated and over-budget contexts supply no additional evidence.
"""

from __future__ import annotations

from bisect import bisect_right
from hashlib import sha256
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink

from .core import RustCore


_MAX_FILE_BYTES = 1_000_000
_MAX_CRATE_BYTES = 2_000_000
_MAX_PROJECT_BYTES = 8_000_000
_MAX_CRATE_FILES = 128
_MAX_ROOTS = 64


class _Unavailable(Exception):
    pass


class _Closure:
    def __init__(self, root, admitted):
        self.root = root
        self.admitted = admitted
        self.sources = {}
        self.cores = {}
        self.parts = []
        self.segments = []
        self.length = 0
        self.visited = set()
        self.external_modules = 0

    def _source(self, path):
        if path not in self.admitted:
            raise _Unavailable
        if path not in self.sources:
            if len(self.sources) >= _MAX_CRATE_FILES:
                raise _Unavailable
            source = read_project_text_no_symlink(
                self.root, path, max_bytes=_MAX_FILE_BYTES, newline=""
            )
            if source is None:
                raise _Unavailable
            data = source.encode("utf-8")
            core = RustCore(str(path), data)
            if core.root_node is None or core.root_node.has_error:
                raise _Unavailable
            self.sources[path] = data
            self.cores[path] = core
        return self.sources[path], self.cores[path]

    def _append(self, data, path=None, original_start=0):
        if self.length + len(data) > _MAX_CRATE_BYTES:
            raise _Unavailable
        if path is not None and data:
            self.segments.append(
                (self.length, self.length + len(data), path, original_start)
            )
        self.parts.append(data)
        self.length += len(data)

    def _expand_range(self, path, block, base):
        data, core = self._source(path)
        cursor = block.start_byte
        for node in block.named_children:
            if node.type != "mod_item":
                continue
            name = core._node_name_text(node.child_by_field_name("name")).removeprefix(
                "r#"
            )
            if not name or not name.isidentifier():
                raise _Unavailable
            body = node.child_by_field_name("body")
            if body is not None:
                self._append(data[cursor : body.start_byte], path, cursor)
                self._expand_range(path, body, base / name)
            else:
                # A #[path] or cfg may change module identity. The local proof
                # declines any attributes; reject it before loading a guessed file.
                previous = node.prev_named_sibling
                while previous is not None and previous.type in {
                    "line_comment",
                    "block_comment",
                }:
                    previous = previous.prev_named_sibling
                if previous is not None and previous.type == "attribute_item":
                    raise _Unavailable
                candidates = (base / f"{name}.rs", base / name / "mod.rs")
                existing = [
                    candidate
                    for candidate in candidates
                    if candidate.exists() or candidate.is_symlink()
                ]
                if len(existing) != 1:
                    raise _Unavailable
                target = existing[0]
                if target not in self.admitted:
                    raise _Unavailable
                self._append(data[cursor : node.end_byte - 1], path, cursor)
                self._append(b"{\n")
                self.external_modules += 1
                self._expand_file(target)
                self._append(b"\n}")
            cursor = node.end_byte
        self._append(data[cursor : block.end_byte], path, cursor)

    def _expand_file(self, path):
        if path in self.visited:
            raise _Unavailable
        self.visited.add(path)
        _, core = self._source(path)
        base = (
            path.parent
            if path.name in {"main.rs", "lib.rs", "mod.rs"}
            else path.with_suffix("")
        )
        self._expand_range(path, core.root_node, base)

    def expand(self, path):
        self._expand_file(path)
        return b"".join(self.parts)

    def original(self, offset):
        index = bisect_right(self.segments, (offset, float("inf"))) - 1
        if index < 0:
            return None
        start, end, path, original = self.segments[index]
        return (path, original + offset - start) if offset < end else None

    def unchanged(self):
        for path, data in self.sources.items():
            source = read_project_text_no_symlink(
                self.root, path, max_bytes=_MAX_FILE_BYTES, newline=""
            )
            if source is None or source.encode("utf-8") != data:
                return False
        return True


def apply_project_trait_imports(
    definitions, files, *, scan_root, analysis_scope, analysis_errors
):
    """Add exact import-use evidence; never remove findings without a closed proof."""
    if (
        analysis_errors
        or not isinstance(analysis_scope, dict)
        or not analysis_scope.get("complete_repository")
    ):
        return
    try:
        root = Path(scan_root).resolve(strict=True)
        admitted = set()
        for filename in files:
            path = Path(filename)
            if path.suffix != ".rs" or path.is_symlink():
                continue
            # Keep lexical paths: safe reader also checks intermediate symlinks.
            path = Path(path.absolute())
            path.relative_to(root)
            admitted.add(path)
    except (OSError, RuntimeError, TypeError, ValueError):
        return
    by_identity = {}
    for definition in definitions.values():
        facts = getattr(definition, "rust_reference_facts", None)
        if (
            definition.type != "import"
            or not isinstance(facts, dict)
            or facts.get("kind") != "import_binding"
        ):
            continue
        identity = (
            Path(definition.filename),
            facts.get("sha256"),
            facts.get("start_byte"),
            definition.simple_name.removeprefix("r#"),
        )
        by_identity.setdefault(identity, []).append(definition)
    if not by_identity:
        return
    roots = sorted(path for path in admitted if path.name in {"main.rs", "lib.rs"})
    if len(roots) > _MAX_ROOTS:
        return
    remaining = _MAX_PROJECT_BYTES
    for crate_root in roots:
        closure = _Closure(root, admitted)
        try:
            expanded = closure.expand(crate_root)
            remaining -= len(expanded)
            if remaining < 0:
                return
            if not closure.external_modules:
                continue
            core = RustCore(str(crate_root), expanded)
            core.scan()
            local = core._local_trait_imports
            if local is None:
                continue
            used = []
            for node in core._iter_nodes(core.root_node):
                if node.type != "use_declaration":
                    continue
                original = closure.original(node.start_byte)
                if original is None:
                    continue
                path, offset = original
                digest = sha256(closure.sources[path]).hexdigest()
                source = core._node_name_text(node.child_by_field_name("argument"))
                for name, imported in core._extract_use_bindings(node):
                    qualified = core._qualify_use_import(
                        source,
                        local_name=name,
                        original_name=imported,
                        namespace=local._namespace(node),
                    )
                    if qualified and local.is_used(qualified, node.parent):
                        used.extend(
                            by_identity.get(
                                (path, digest, offset, name.removeprefix("r#")), ()
                            )
                        )
            if closure.unchanged():
                for definition in used:
                    definition.references = max(definition.references, 1)
        except (OSError, RuntimeError, TypeError, ValueError, _Unavailable):
            continue
