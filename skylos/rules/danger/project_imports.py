"""Metadata-bound static import context for optional provider safety proofs."""

import ast
from pathlib import Path

from .project_source import project_source_snapshot


class ProjectImports:
    def __init__(self, tree, source, root, snapshot):
        self.snapshot = snapshot
        self.source = source
        self.root = root
        self.complete = True
        self.modules = {}
        self.names = {}
        self.trees = {}
        self.paths = {}
        self.watch = set()
        self.budget = 8192
        self.provider_results = {}
        try:
            parsed = snapshot.get(source)
            if parsed is None or ast.dump(parsed, include_attributes=False) != ast.dump(
                tree, include_attributes=False
            ):
                self.complete = False
                return
            search = {root, source.parent}
            if (root / "src").is_dir():
                search.add(root / "src")
            for path, parsed in snapshot.items():
                path = Path(path)
                parts = list(path.relative_to(root).with_suffix("").parts)
                package = parts[-1] == "__init__"
                if package:
                    parts.pop()
                names = {".".join(parts)}
                for import_root in search:
                    if path.is_relative_to(import_root):
                        relative = list(
                            path.relative_to(import_root).with_suffix("").parts
                        )
                        if package:
                            relative.pop()
                        names.add(".".join(relative))
                if root.name.isidentifier():
                    names.add(".".join([root.name, *parts]))
                if not parts:
                    names.add("")
                self.names[path] = names
                self.paths[path] = package
                self.trees[path] = tree if path == source else parsed
                for name in names:
                    self.modules.setdefault(name, set()).add(path)
            if len(search) > 256:
                self.complete = False
                return
            self.search = search
            self.watch.update(search)
            pending = [source]
            visited = set()
            self.entries = []
            while pending:
                path = pending.pop()
                if path in visited:
                    continue
                visited.add(path)
                if len(visited) > 128:
                    self.complete = False
                    return
                parsed = self.trees[path]
                self.entries.append((path, parsed))
                imports = self.import_names(path, parsed)
                for imported in imports:
                    if not self.import_metadata_is_plain(imported):
                        self.complete = False
                        return
                    parts = imported.split(".")
                    for count in range(1, len(parts) + 1):
                        name = ".".join(parts[:count])
                        pending.extend(self.modules.get(name, ()))
            self.stamp = self.directory_stamp()
        except (OSError, RuntimeError, ValueError, TypeError, RecursionError):
            self.complete = False

    def import_names(self, path, tree):
        result = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                result.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    bases = set()
                    for name in self.names[path]:
                        package = name if self.paths[path] else name.rpartition(".")[0]
                        parts = package.split(".") if package else []
                        if node.level <= len(parts) + 1:
                            bases.add(".".join(parts[: len(parts) - node.level + 1]))
                    if not bases:
                        self.complete = False
                        return set()
                else:
                    bases = {""}
                for base in bases:
                    base = ".".join(part for part in (base, node.module) if part)
                    if base:
                        result.add(base)
                    result.update(
                        ".".join(part for part in (base, alias.name) if part)
                        for alias in node.names
                        if alias.name != "*"
                    )
        return result

    def import_metadata_is_plain(self, imported):
        parts = imported.split(".")
        if not all(part.isidentifier() for part in parts):
            return False
        for directory in self.search:
            for count in range(1, len(parts) + 1):
                self.budget -= 1
                if self.budget < 0:
                    return False
                base = directory.joinpath(*parts[:count])
                self.watch.add(base.parent)
                source = []
                for candidate in base.parent.glob(base.name + ".*"):
                    if candidate.is_symlink():
                        return False
                    if candidate.suffix in {".so", ".pyd", ".pyc", ".pyo"}:
                        return False
                    if candidate.suffix in {".py", ".pyw", ".pyi"}:
                        source.append(candidate)
                if len(source) > 1:
                    # Runtime source/stub competition does not prove identity.
                    return False
                if base.is_symlink():
                    return False
                if base.is_dir():
                    self.watch.add(base)
                    initializers = list(base.glob("__init__.*"))
                    if any(
                        item.is_symlink()
                        or item.suffix in {".so", ".pyd", ".pyc", ".pyo"}
                        for item in initializers
                    ):
                        return False
                    if source and initializers:
                        return False
        return True

    def directory_stamp(self):
        result = []
        for path in sorted(self.watch):
            try:
                stat = path.stat(follow_symlinks=False)
                result.append(
                    (
                        str(path),
                        stat.st_mode,
                        stat.st_mtime_ns,
                        stat.st_ctime_ns,
                        stat.st_ino,
                    )
                )
            except FileNotFoundError:
                result.append((str(path), None))
        return tuple(result)

    def fresh(self):
        try:
            return getattr(self, "stamp", None) == self.directory_stamp()
        except (OSError, RuntimeError, ValueError):
            return False

    def qualified_names(self, qualified):
        """Equate source/package/src labels only through actual source paths."""
        result = {qualified}
        parts = qualified.split(".")
        for count in range(len(parts) - 1, 0, -1):
            module = ".".join(parts[:count])
            matches = self.modules.get(module)
            if not matches:
                continue
            suffix = ".".join(parts[count:])
            for path in matches:
                result.update(
                    ".".join(part for part in (name, suffix) if part)
                    for name in self.names[path]
                )
            break
        return frozenset(result)

    def local_symbols(self, path, qualified_names):
        result = set()
        for name in self.names[path]:
            prefix = name + "." if name else ""
            for qualified in qualified_names:
                if qualified.startswith(prefix):
                    rest = qualified[len(prefix) :]
                    if rest:
                        result.add(rest)
        return result


def project_import_context(tree, filename, project_root=None):
    try:
        source = Path(filename).resolve()
        root = Path(project_root).resolve() if project_root else source.parent
        if not source.is_relative_to(root):
            return None
        snapshot, complete = project_source_snapshot(root)
        if not complete:
            return None
        cached = getattr(tree, "_skylos_project_import_context", None)
        if (
            cached is not None
            and cached.snapshot is snapshot
            and cached.source == source
            and cached.root == root
            and cached.fresh()
        ):
            return cached if cached.complete else None
        context = ProjectImports(tree, source, root, snapshot)
        if not hasattr(context, "stamp"):
            context.stamp = context.directory_stamp()
        tree._skylos_project_import_context = context
        return context if context.complete else None
    except (OSError, RuntimeError, ValueError, TypeError, RecursionError):
        return None
