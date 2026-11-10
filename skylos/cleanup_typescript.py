"""Narrow TypeScript type-import edits backed by bounded local source proof.

This adapter never runs a compiler. Its structural proof is deliberately smaller
than TypeScript's module system and refuses unresolved configuration or providers.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import stat

from skylos.core.safe_cache_io import read_project_text_no_symlink

MAX_CONSUMER_BYTES = 256_000
MAX_PROOF_BYTES = 64_000
_MODULE = re.compile(r"\./([A-Za-z0-9_-]+)(?:\.ts)?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")


def _root(root):
    path = Path(root).absolute()
    if path.is_symlink() or path != path.resolve() or not path.is_dir():
        raise ValueError("TypeScript cleanup root is unsafe or unavailable")
    return path


def _relative(file):
    if (
        not isinstance(file, str)
        or not file
        or "\\" in file
        or "\x00" in file
        or PurePosixPath(file).is_absolute()
        or ".." in PurePosixPath(file).parts
        or not PurePosixPath(file).parts
    ):
        raise ValueError("TypeScript cleanup needs a project-relative source path")
    return Path(file)


def _snapshot(root, relative, *, max_bytes=MAX_PROOF_BYTES):
    relative = _relative(relative)
    current = root
    for component in relative.parts:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("TypeScript proof cannot follow project symlinks")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("TypeScript proof requires singly linked regular files")
    text = read_project_text_no_symlink(root, relative, max_bytes=max_bytes, newline="")
    if text is None:
        raise ValueError("TypeScript proof source is unreadable or exceeds its budget")
    return text


def _digest(source):
    return sha256(source.encode("utf-8")).hexdigest() if source is not None else None


def _parse(source, *, tsx=False):
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_typescript

        language = (
            tree_sitter_typescript.language_tsx
            if tsx
            else tree_sitter_typescript.language_typescript
        )
        tree = Parser(Language(language())).parse(source)
    except (ImportError, TypeError, ValueError, RuntimeError) as exc:
        raise ValueError("TypeScript parser is unavailable") from exc
    nodes = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "ERROR" or node.is_missing or node.has_error:
            raise ValueError(
                "TypeScript cleanup refuses incomplete or recovered syntax"
            )
        nodes.append(node)
        if len(nodes) > 50_000:
            raise ValueError("TypeScript syntax exceeds its proof budget")
        pending.extend(reversed(node.children))
    return tree.root_node, nodes


def _text(source, node):
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _configs(root, consumer, proof):
    from skylos.visitors.languages.typescript.workspace import (
        _strip_json_comments,
        _strip_trailing_commas,
    )

    parent = consumer.parent
    found = False
    for _ in range(32):
        for name in ("tsconfig.json", "tsconfig.base.json", "jsconfig.json"):
            relative = (parent / name).as_posix()
            source = _snapshot(root, relative)
            proof[relative] = _digest(source)
            if source is None:
                continue
            found = found or name == "tsconfig.json"
            try:
                data = json.loads(
                    _strip_trailing_commas(
                        _strip_json_comments(source.lstrip("\ufeff"))
                    ),
                    object_pairs_hook=_unique_keys,
                )
            except (ValueError, RecursionError) as exc:
                raise ValueError(
                    "TypeScript configuration cannot be resolved safely"
                ) from exc
            if (
                not isinstance(data, dict)
                or "extends" in data
                or data.get("references")
            ):
                raise ValueError(
                    "TypeScript extended or referenced configurations require manual review"
                )
            options = data.get("compilerOptions", {})
            if (
                not isinstance(options, dict)
                or options.get("noResolve")
                or any(
                    key in options
                    for key in ("moduleSuffixes", "rootDirs", "paths", "plugins")
                )
            ):
                raise ValueError(
                    "TypeScript custom module resolution requires manual review"
                )
            if any(
                str(options.get(key, "")).lower() in {"node16", "nodenext"}
                for key in ("module", "moduleResolution")
            ):
                raise ValueError(
                    "Node16/NodeNext module resolution requires manual review"
                )
        if parent == Path("."):
            break
        parent = parent.parent
    else:
        raise ValueError("TypeScript configuration search exceeds its budget")
    if not found:
        raise ValueError("TypeScript cleanup requires a local tsconfig.json")


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate TypeScript configuration keys are ambiguous")
        result[key] = value
    return result


def _provider(root, consumer, module, imported, proof):
    match = _MODULE.fullmatch(module)
    if match is None:
        raise ValueError(
            "Only same-directory local TypeScript type providers are supported"
        )
    stem = consumer.parent / match[1]
    expected = stem.with_suffix(".ts")
    candidates = [
        Path(str(stem) + suffix)
        for suffix in (
            ".ts",
            ".tsx",
            ".d.ts",
            ".js",
            ".jsx",
            ".mts",
            ".cts",
            ".d.mts",
            ".d.cts",
            "/index.ts",
            "/index.tsx",
            "/index.d.ts",
            "/index.js",
        )
    ]
    sources = {}
    for candidate in candidates:
        key = candidate.as_posix()
        source = _snapshot(root, key)
        proof[key] = _digest(source)
        if source is not None:
            sources[candidate] = source
    if set(sources) != {expected} or expected == consumer:
        raise ValueError(
            "TypeScript type provider is missing, self-referential or ambiguous"
        )
    source = sources[expected]
    encoded = source.encode("utf-8")
    tree, nodes = _parse(encoded)
    if any(
        node.type
        in {
            "comment",
            "import",
            "import_statement",
            "call_expression",
            "type_query",
            "ambient_declaration",
            "internal_module",
            "module",
            "extends_type_clause",
            "extends_clause",
        }
        for node in nodes
    ):
        raise ValueError(
            "Type provider has comments, dependencies or ambient effects requiring review"
        )
    exports = set()
    declarations = []
    for statement in tree.named_children:
        declaration = statement.child_by_field_name("declaration")
        if (
            statement.type != "export_statement"
            or declaration is None
            or declaration.type
            not in {"interface_declaration", "type_alias_declaration"}
            or any(child.type == "default" for child in statement.children)
        ):
            raise ValueError(
                "Type provider must contain only directly exported interfaces or type aliases"
            )
        name = declaration.child_by_field_name("name")
        if name is None or _text(encoded, name) in exports:
            raise ValueError("Type provider export identity is ambiguous")
        exports.add(_text(encoded, name))
        declarations.append(name)
    declaration_positions = {(node.start_byte, node.end_byte) for node in declarations}
    if (
        not declarations
        or imported not in exports
        or any(
            node.type in {"type_identifier", "identifier"}
            and (node.start_byte, node.end_byte) not in declaration_positions
            for node in nodes
        )
    ):
        raise ValueError(
            "Type provider uses external, generic or dependent named types"
        )
    return expected.as_posix(), _digest(source)


def plan_typescript_unused_import(task: dict, root: str | Path, source: bytes) -> dict:
    """Return a patch candidate with provider/configuration proof dependencies."""
    root = _root(root)
    if (
        not isinstance(task, dict)
        or task.get("rule_id") != "SKY-U002"
        or task.get("category") != "dead_code"
    ):
        raise ValueError(
            "TypeScript import edits require native SKY-U002 dead-code evidence"
        )
    relative = _relative(task.get("file"))
    if relative.suffix not in {".ts", ".tsx"} or relative.name.endswith(".d.ts"):
        raise ValueError(
            "TypeScript cleanup supports ordinary .ts and .tsx consumers only"
        )
    if not isinstance(source, bytes) or len(source) > MAX_CONSUMER_BYTES:
        raise ValueError("TypeScript consumer exceeds its proof budget")
    current = _snapshot(root, relative.as_posix(), max_bytes=MAX_CONSUMER_BYTES)
    if (
        current is None
        or current.encode("utf-8") != source
        or task.get("source_sha256") != sha256(source).hexdigest()
    ):
        raise ValueError("TypeScript cleanup task has stale source evidence")
    tree, nodes = _parse(source, tsx=relative.suffix == ".tsx")
    if any(
        node.type == "comment"
        and re.search(
            r"@ts-|@jsx|^///|eslint|biome|prettier|skylos|istanbul|\bc8\b",
            _text(source, node),
        )
        for node in nodes
    ):
        raise ValueError("TypeScript directives require manual review")
    finding = task.get("finding", task)
    if not isinstance(finding, dict):
        raise ValueError("TypeScript task finding is malformed")
    line = finding.get("line", task.get("line"))
    name = finding.get("simple_name") or finding.get("name") or task.get("name")
    if type(line) is not int or line < 1 or not isinstance(name, str) or not name:
        raise ValueError("TypeScript import binding and line are required")
    candidates = [
        node
        for node in tree.named_children
        if node.type == "import_statement"
        and node.start_point[0] + 1 <= line <= node.end_point[0] + 1
    ]
    if len(candidates) != 1:
        raise ValueError("TypeScript finding does not identify one import declaration")
    target = candidates[0]
    if not re.match(
        rb"import\s+type\s*\{", source[target.start_byte : target.end_byte]
    ):
        raise ValueError("Only explicit named import type declarations are supported")
    if sorted(node.type for node in target.named_children) != [
        "import_clause",
        "string",
    ]:
        raise ValueError(
            "TypeScript import attributes or additional syntax require review"
        )
    clause = next(
        (node for node in target.named_children if node.type == "import_clause"), None
    )
    named = clause.named_children if clause is not None else []
    specifiers = (
        named[0].named_children
        if len(named) == 1 and named[0].type == "named_imports"
        else []
    )
    if len(specifiers) != 1 or specifiers[0].type != "import_specifier":
        raise ValueError("TypeScript cleanup supports one named type binding at a time")
    specifier = specifiers[0]
    imported_node = specifier.child_by_field_name("name")
    local_node = specifier.child_by_field_name("alias") or imported_node
    if imported_node is None or local_node is None:
        raise ValueError("TypeScript import binding is unavailable")
    imported, local = _text(source, imported_node), _text(source, local_node)
    qualified = relative.with_suffix("").as_posix().replace("/", ".") + "." + local
    if (
        not _IDENTIFIER.fullmatch(imported)
        or not _IDENTIFIER.fullmatch(local)
        or local_node.start_point[0] + 1 != line
    ):
        raise ValueError(
            "TypeScript import needs an exact unescaped ASCII binding location"
        )
    if name not in {local, f"{relative.stem}.{local}", qualified} or task.get(
        "name", name
    ) not in {local, f"{relative.stem}.{local}", qualified}:
        raise ValueError("TypeScript task does not match the local imported binding")
    if any(
        node.type == "comment"
        and target.start_byte <= node.start_byte < target.end_byte
        for node in nodes
    ):
        raise ValueError("Comments within a type import require manual review")
    if any(
        ("identifier" in node.type and "\\" in _text(source, node))
        or (
            node.type == "comment"
            and re.search(
                r"(?<![A-Za-z0-9_$])" + re.escape(local) + r"(?![A-Za-z0-9_$])",
                _text(source, node),
            )
        )
        for node in nodes
    ):
        raise ValueError(
            "Escaped identifiers or comment-based type references require review"
        )
    if any(
        "identifier" in node.type
        and _text(source, node) == local
        and not target.start_byte <= node.start_byte < target.end_byte
        for node in nodes
    ):
        raise ValueError(
            "TypeScript import still has a reference or an ambiguous name occurrence"
        )
    if not any(
        node != target and node.type in {"import_statement", "export_statement"}
        for node in tree.named_children
    ):
        raise ValueError("Removing this import would remove the file's module boundary")
    string = target.child_by_field_name("source")
    if (
        string is None
        or len(string.named_children) != 1
        or string.named_children[0].type != "string_fragment"
    ):
        raise ValueError("TypeScript import source is not a simple module literal")
    module = _text(source, string.named_children[0])
    resolution = {}
    _configs(root, relative, resolution)
    provider, digest = _provider(root, relative, module, imported, resolution)
    start, end = target.start_byte, target.end_byte
    line_start = source.rfind(b"\n", 0, start) + 1
    if source[line_start:start].strip():
        raise ValueError("TypeScript import has adjacent statement text")
    newline = source.find(b"\n", end)
    line_end = len(source) if newline == -1 else newline + 1
    if not source[end:line_end].strip():
        start, end = line_start, line_end
    replacement = source[:start] + source[end:]
    _parse(replacement, tsx=relative.suffix == ".tsx")
    anchor = json.dumps(
        {
            "kind": "typescript_import_type",
            "module": module,
            "imported": imported,
            "local": local,
        },
        sort_keys=True,
    )
    result = {
        "replacement": replacement.decode("utf-8"),
        "target_anchor": anchor,
        "provider_hashes": {provider: digest},
        "resolution_hashes": resolution,
        "binding": {
            "imported": imported,
            "local": local,
            "module": module,
            "line": line,
        },
        "limitations": [
            "Bounded structural type-provider proof; no compiler or runtime behavior was executed."
        ],
    }
    revalidate_typescript_dependencies(root, result)
    return result


def revalidate_typescript_dependencies(root: str | Path, proof: dict) -> None:
    """Refuse changed providers, configuration or newly introduced alternatives."""
    root = _root(root)
    if not isinstance(proof, dict):
        raise ValueError("TypeScript proof dependencies are malformed")
    for key in ("provider_hashes", "resolution_hashes"):
        hashes = proof.get(key)
        if not isinstance(hashes, dict) or not hashes or len(hashes) > 128:
            raise ValueError("TypeScript proof dependencies are missing or oversized")
        for relative, digest in hashes.items():
            if (digest is None and key == "provider_hashes") or (
                digest is not None
                and (not isinstance(digest, str) or not _DIGEST.fullmatch(digest))
            ):
                raise ValueError("TypeScript proof source hash is malformed")
            if _digest(_snapshot(root, relative)) != digest:
                raise ValueError(
                    "TypeScript provider or module resolution changed; preview again"
                )


def typescript_import_anchor_present(
    source: bytes | str, anchor: str, *, file_path: str
) -> bool:
    """Check the original import binding without treating parse failures as absence."""
    try:
        identity = json.loads(anchor)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("TypeScript import anchor is malformed") from exc
    if (
        not isinstance(identity, dict)
        or identity.get("kind") != "typescript_import_type"
        or any(
            not isinstance(identity.get(key), str) or not identity[key]
            for key in ("module", "imported", "local")
        )
    ):
        raise ValueError("TypeScript import anchor is unavailable")
    if isinstance(source, str):
        source = source.encode("utf-8")
    if not isinstance(source, bytes) or len(source) > MAX_CONSUMER_BYTES:
        raise ValueError("TypeScript consumer exceeds its proof budget")
    tree, _nodes = _parse(source, tsx=Path(file_path).suffix == ".tsx")
    for statement in tree.named_children:
        if statement.type != "import_statement":
            continue
        module = statement.child_by_field_name("source")
        if (
            module is None
            or len(module.named_children) != 1
            or _text(source, module.named_children[0]) != identity["module"]
        ):
            continue
        pending = list(statement.named_children)
        while pending:
            node = pending.pop()
            if node.type == "import_specifier":
                imported = node.child_by_field_name("name")
                local = node.child_by_field_name("alias") or imported
                if (
                    imported is not None
                    and local is not None
                    and _text(source, imported) == identity["imported"]
                    and _text(source, local) == identity["local"]
                ):
                    return True
            pending.extend(node.named_children)
    return False
