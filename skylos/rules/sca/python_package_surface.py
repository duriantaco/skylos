"""The public API of an unpacked Python distribution, read with ``ast`` only.

Nothing here imports, installs or runs package code: the new version of a
dependency is untrusted. A name is ``found``, ``missing`` or ``unknown`` with a
reason; compiled modules with no stub and anything else the source cannot show
are unknown, never missing.
"""

from __future__ import annotations

import ast
import builtins
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from skylos.rules.sca.python_class_reader import ClassBody, read_class
from skylos.rules.sca.python_module_reader import (
    Binding,
    ModuleSurface,
    call_name,
    read_module,
)
from skylos.rules.sca.python_package_keywords import (
    KeywordReader,
    Signature,
    signature_of,
)

MAX_SOURCE_FILE_BYTES = 2_000_000
MAX_SOURCE_TOTAL_BYTES = 64_000_000
MAX_MODULES = 5_000
_COMPILED_SUFFIXES = (".so", ".pyd")
_NATIVE_SOURCE_SUFFIXES = (".pyx", ".c", ".cc", ".cpp", ".rs")
_SDIST_SKIP = frozenset(
    {
        "benchmarks",
        "bench",
        "build",
        "ci",
        "conftest.py",
        "dist",
        "doc",
        "docs",
        "example",
        "examples",
        "fabfile.py",
        "noxfile.py",
        "scripts",
        "setup.py",
        "test",
        "tests",
        "tools",
        "tox.ini",
    }
)
_CLOSED_BASES = frozenset({"ABC", "Generic", "Protocol", "object"})
_FILE_KINDS = (
    (".pyi", "pyi"),
    (".py", "py"),
    (".pyx", "compiled"),
    (".pyc", "compiled"),
)


class SurfaceUnreadable(ValueError):
    """The artifact as a whole cannot be read; the message says why."""


@dataclass(frozen=True)
class Target:
    kind: str
    module: str = ""
    node: Any = None
    owner: Any = None
    instance: bool = False


@dataclass(frozen=True)
class Step:
    status: str
    targets: tuple[Target, ...] = ()
    reason: str = ""


@dataclass
class _ClassInfo:
    body: ClassBody
    bases: list[Target]
    open_reason: str


@dataclass
class _ModuleFiles:
    py: Any = None
    pyi: Any = None
    compiled: bool = False


class PackageSurface:
    """Every module of one artifact, and name lookups across them."""

    def __init__(
        self,
        modules: dict[str, ModuleSurface],
        *,
        native_sources: bool = False,
    ):
        self.modules = modules
        self.native_sources = native_sources
        self.roots = {name.split(".", 1)[0] for name in modules}
        self._classes: dict[int, _ClassInfo] = {}
        self._keywords = KeywordReader(self)

    def keyword_status(self, targets: Iterable[Target], keyword: str) -> str:
        return self._keywords.status(targets, keyword)

    def module_step(self, name: str) -> Step:
        if name in self.modules:
            return Step("found", (Target("module", name),))
        parts = name.split(".")
        for index in range(len(parts) - 1, 0, -1):
            ancestor = self.modules.get(".".join(parts[:index]))
            if ancestor is not None:
                reason = ancestor.opaque or ancestor.open_reason
                if reason:
                    return Step("unknown", reason=reason)
                break
        if self.native_sources and parts[0] in self.roots:
            return Step(
                "unknown", reason="the sdist builds native modules it does not list"
            )
        return Step("missing")

    def step(self, targets: tuple[Target, ...], token: str) -> Step:
        """One attribute access (or a call, for the token ``()``) on ``targets``."""
        found: list[Target] = []
        reason = ""
        missing = False
        for target in targets:
            result = self._target_step(target, token)
            found.extend(result.targets)
            if result.status == "unknown":
                reason = reason or result.reason
            elif result.status == "missing":
                missing = True
        if found:
            return Step("found", tuple(found))
        if reason:
            return Step("unknown", reason=reason)
        if missing:
            return Step("missing")
        return Step("stop")

    def _target_step(self, target: Target, token: str) -> Step:
        if token == "()":
            if target.kind == "class" and not target.instance:
                instance = Target("class", target.module, target.node, instance=True)
                return Step("found", (instance,))
            return Step("stop")
        if target.kind == "module":
            return self.module_member(target.module, token)
        if target.kind == "class":
            return self.class_member(target, token)
        return Step("stop")

    def module_member(
        self, module_name: str, name: str, seen: frozenset = frozenset()
    ) -> Step:
        key = (module_name, name)
        if key in seen:
            return Step("unknown", reason="the module imports the name in a cycle")
        seen = seen | {key}
        surface = self.modules.get(module_name)
        if surface is None:
            return Step("missing")
        if surface.opaque:
            return Step("unknown", reason=surface.opaque)
        if name in surface.bindings:
            targets: list[Target] = []
            for binding in surface.bindings[name]:
                targets.extend(self._binding_targets(module_name, binding, seen))
            return Step("found", tuple(targets))
        if name in surface.lazy_names:
            return Step("unknown", reason="the module provides it through __getattr__")
        child = f"{module_name}.{name}"
        if child in self.modules:
            return Step("found", (Target("module", child),))
        return self._undeclared_member(surface, name, seen)

    def _undeclared_member(
        self, surface: ModuleSurface, name: str, seen: frozenset
    ) -> Step:
        unresolved = ""
        for source in surface.star_sources:
            names = self.public_names(source)
            if names is None:
                unresolved = f"it has a star import of {source} that cannot be read"
            elif name in names:
                return self.module_member(source, name, seen)
        if surface.all_names and name in surface.all_names:
            return Step("found", (Target("value", surface.name),))
        reason = unresolved or surface.open_reason
        if reason:
            return Step("unknown", reason=reason)
        return Step("missing")

    def public_names(
        self, module_name: str, seen: frozenset = frozenset()
    ) -> set[str] | None:
        """What ``from module import *`` binds; None when that cannot be read."""
        surface = self.modules.get(module_name)
        if surface is None or surface.opaque or module_name in seen:
            return None
        seen = seen | {module_name}
        sources = surface.star_sources
        names = {name for name in surface.bindings if not name.startswith("_")}
        if surface.all_names is not None:
            sources = surface.all_sources
            names = set(surface.all_names)
        for source in sources:
            extra = self.public_names(source, seen)
            if extra is None:
                return None
            names |= extra
        return names

    def _binding_targets(
        self, module_name: str, binding: Binding, seen: frozenset
    ) -> list[Target]:
        if binding.kind in {"function", "class"}:
            return [Target(binding.kind, module_name, binding.node)]
        if binding.kind == "import":
            return self._import_targets(binding, seen)
        if binding.expression is not None:
            targets = self.expression_targets(module_name, binding.expression, seen)
            if targets:
                return targets
        return [Target("value", module_name)]

    def _import_targets(self, binding: Binding, seen: frozenset) -> list[Target]:
        module = binding.module or ""
        if module.split(".", 1)[0] not in self.roots:
            return [Target("external", module)]
        if module not in self.modules:
            return [Target("value", module)]
        if binding.member is None:
            return [Target("module", module)]
        result = self.module_member(module, binding.member, seen)
        if result.status == "found":
            return list(result.targets)
        return [Target("value", module)]

    def expression_targets(
        self, module_name: str, expression: ast.expr, seen: frozenset = frozenset()
    ) -> list[Target]:
        if isinstance(expression, ast.Name):
            return list(self.module_member(module_name, expression.id, seen).targets)
        if isinstance(expression, ast.Attribute):
            base = self.expression_targets(module_name, expression.value, seen)
            if base:
                return list(self.step(tuple(base), expression.attr).targets)
        return []

    def _class_info(self, target: Target) -> _ClassInfo:
        cached = self._classes.get(id(target.node))
        if cached is not None:
            return cached
        body = read_class(target.node)
        info = _ClassInfo(body, [], body.open_reason)
        self._classes[id(target.node)] = info
        for base in target.node.bases:
            self._read_base(target, base, info)
        return info

    def _read_base(self, target: Target, base: ast.expr, info: _ClassInfo) -> None:
        if isinstance(base, ast.Subscript):
            base = base.value
        label = call_name(base)
        surface = self.modules.get(target.module)
        bound = surface is not None and label in surface.bindings
        if isinstance(base, ast.Name) and not bound and hasattr(builtins, label):
            return
        classes = [
            item
            for item in self.expression_targets(target.module, base)
            if item.kind == "class"
        ]
        if classes:
            info.bases.extend(classes)
        elif label not in _CLOSED_BASES:
            info.open_reason = (
                info.open_reason or f"the class inherits from {label or 'an expression'}"
            )

    def mro(self, target: Target) -> list[Target]:
        ordered: list[Target] = []
        seen: set[int] = set()
        pending = [target]
        while pending:
            current = pending.pop(0)
            if id(current.node) in seen:
                continue
            seen.add(id(current.node))
            ordered.append(current)
            pending = list(self._class_info(current).bases) + pending
        return ordered

    def class_member(self, target: Target, name: str) -> Step:
        reason = ""
        for current in self.mro(target):
            info = self._class_info(current)
            if name in info.body.members:
                return Step("found", tuple(self._member_targets(current, name)))
            reason = reason or info.open_reason
        if reason:
            return Step("unknown", reason=reason)
        return Step("missing")

    def inherited_member(self, target: Target, name: str) -> list[Target]:
        for current in self.mro(target)[1:]:
            if name in self._class_info(current).body.members:
                return self._member_targets(current, name)
        return []

    def _member_targets(self, owner: Target, name: str) -> list[Target]:
        targets: list[Target] = []
        for binding in self._class_info(owner).body.members[name]:
            if binding.kind == "function":
                targets.append(
                    Target("function", owner.module, binding.node, owner=owner)
                )
            elif binding.kind == "class":
                targets.append(Target("class", owner.module, binding.node))
            else:
                targets.extend(self._member_value_targets(owner, binding))
        return targets

    def _member_value_targets(self, owner: Target, binding: Binding) -> list[Target]:
        if binding.expression is not None:
            resolved = self.expression_targets(owner.module, binding.expression)
            if resolved:
                return resolved
        return [Target("value", owner.module)]

    def signatures(self, target: Target) -> list[Signature] | None:
        if target.kind == "function":
            return [signature_of(target.node, target.module, target.owner)]
        if target.kind != "class":
            return None
        if target.instance:
            return self._named_signatures(target, "__call__")
        for name in ("__init__", "__new__"):
            if self.class_member(target, name).status == "found":
                return self._named_signatures(target, name)
        return self._implicit_signature(target)

    def _implicit_signature(self, target: Target) -> list[Signature] | None:
        infos = [self._class_info(current) for current in self.mro(target)]
        if any(info.body.is_dataclass for info in infos):
            fields: set[str] = set()
            for info in infos:
                fields |= info.body.fields
            return [Signature(frozenset(fields), None, module=target.module)]
        if any(info.open_reason for info in infos):
            return None
        return [Signature(frozenset(), None, module=target.module)]

    def _named_signatures(self, target: Target, name: str) -> list[Signature] | None:
        result = self.class_member(target, name)
        if result.status != "found":
            return None
        signatures = []
        for item in result.targets:
            if item.kind != "function":
                return None
            signatures.append(signature_of(item.node, item.module, item.owner))
        return signatures


def _sdist_rows(files: list[Any]) -> list[tuple[tuple[str, ...], Any]]:
    rows = [(PurePosixPath(item.relative_path).parts, item) for item in files]
    rows = [(parts, item) for parts, item in rows if parts]
    if len({parts[0] for parts, _item in rows}) == 1:
        rows = [(parts[1:], item) for parts, item in rows if len(parts) > 1]
    return rows


def _declared_roots(
    rows: list[tuple[tuple[str, ...], Any]],
) -> tuple[tuple[str, ...], set[str]] | None:
    for parts, item in rows:
        if (
            len(parts) >= 2
            and parts[-2].endswith(".egg-info")
            and parts[-1] == "top_level.txt"
        ):
            names = _read_text(item, 64_000).split()
            if names:
                return parts[:-2], set(names)
    return None


def _sdist_base(rows: list[tuple[tuple[str, ...], Any]]) -> tuple[str, ...]:
    def has_source(prefix: str) -> bool:
        return any(
            len(parts) >= 2 and parts[0] == prefix and parts[-1].endswith(".py")
            for parts, _item in rows
        )

    if has_source("src"):
        return ("src",)
    if any(
        len(parts) == 2 and parts[1] == "__init__.py" and parts[0] not in _SDIST_SKIP
        for parts, _item in rows
    ):
        return ()
    for candidate in ("lib", "python"):
        if has_source(candidate):
            return (candidate,)
    return ()


def _sdist_paths(files: list[Any]) -> Iterator[tuple[tuple[str, ...], Any]]:
    rows = _sdist_rows(files)
    declared = _declared_roots(rows)
    roots = None
    if declared is None:
        base = _sdist_base(rows)
    else:
        base, roots = declared
    for parts, item in rows:
        if parts[: len(base)] != base or len(parts) == len(base):
            continue
        relative = parts[len(base) :]
        if roots is None:
            wanted = relative[0] not in _SDIST_SKIP
        else:
            wanted = relative[0].split(".", 1)[0] in roots
        if wanted:
            yield relative, item


def _wheel_paths(files: list[Any]) -> Iterator[tuple[tuple[str, ...], Any]]:
    for item in files:
        parts = PurePosixPath(item.relative_path).parts
        if not parts or parts[0].endswith(".dist-info"):
            continue
        if not parts[0].endswith(".data"):
            yield parts, item
        elif len(parts) > 2 and parts[1] in {"purelib", "platlib"}:
            yield parts[2:], item


def _read_text(item: Any, limit: int) -> str:
    try:
        with open(item.path, "rb") as handle:
            raw = handle.read(limit + 1)
    except OSError:
        return ""
    if len(raw) > limit:
        return ""
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _file_kind(filename: str) -> tuple[str, str] | None:
    for suffix, kind in _FILE_KINDS:
        if filename.endswith(suffix):
            return kind, filename[: -len(suffix)]
    if filename.endswith(_COMPILED_SUFFIXES):
        return "compiled", filename.split(".", 1)[0]
    return None


def _module_slot(parts: tuple[str, ...]) -> tuple[str, str, bool] | None:
    """(dotted name, file kind, is package) for one installed path, or None."""
    directories = parts[:-1]
    found = _file_kind(parts[-1])
    if found is None or any(not part.isidentifier() for part in directories):
        return None
    kind, stem = found
    if not stem.isidentifier():
        return None
    if stem != "__init__":
        return ".".join((*directories, stem)), kind, False
    if not directories:
        return None
    return ".".join(directories), kind, True


def _collect_slots(
    paths: list[tuple[tuple[str, ...], Any]],
) -> tuple[dict[str, _ModuleFiles], set[str]]:
    slots: dict[str, _ModuleFiles] = {}
    packages: set[str] = set()
    for parts, item in paths:
        found = _module_slot(parts)
        if found is None:
            continue
        name, file_kind, is_package = found
        slot = slots.setdefault(name, _ModuleFiles())
        if file_kind == "py":
            slot.py = item
        elif file_kind == "pyi":
            slot.pyi = item
        else:
            slot.compiled = True
        if is_package:
            packages.add(name)
    for name in list(slots):
        parts = name.split(".")
        for index in range(1, len(parts)):
            parent = ".".join(parts[:index])
            slots.setdefault(parent, _ModuleFiles())
            packages.add(parent)
    return slots, packages


def _merged_with_stub(primary: ModuleSurface, stub: ModuleSurface) -> ModuleSurface:
    bindings = {key: list(value) for key, value in stub.bindings.items()}
    for key, value in primary.bindings.items():
        bindings.setdefault(key, []).extend(value)
    return ModuleSurface(
        primary.name,
        bindings=bindings,
        all_names=stub.all_names,
        all_sources=stub.all_sources,
        star_sources=[*stub.star_sources, *primary.star_sources],
        lazy_names=primary.lazy_names,
        open_reason=primary.opaque or primary.open_reason or stub.open_reason,
    )


def _read_source(
    name: str, item: Any, *, is_package: bool, is_stub: bool, budget: list[int]
) -> ModuleSurface:
    size = int(getattr(item, "size", 0) or 0)
    if size > MAX_SOURCE_FILE_BYTES:
        return ModuleSurface(
            name, opaque=f"the module is over the {MAX_SOURCE_FILE_BYTES:,} byte limit"
        )
    budget[0] -= size
    if budget[0] < 0:
        raise SurfaceUnreadable(
            f"the package source is over the {MAX_SOURCE_TOTAL_BYTES:,} byte limit"
        )
    text = _read_text(item, MAX_SOURCE_FILE_BYTES)
    return read_module(name, text, is_package=is_package, is_stub=is_stub)


def _read_module_files(
    name: str, slot: _ModuleFiles, is_package: bool, budget: list[int]
) -> ModuleSurface:
    primary = None
    if slot.py is not None:
        primary = _read_source(
            name, slot.py, is_package=is_package, is_stub=False, budget=budget
        )
    stub = None
    if slot.pyi is not None and (
        primary is None or primary.opaque or primary.open_reason
    ):
        stub = _read_source(
            name, slot.pyi, is_package=is_package, is_stub=True, budget=budget
        )
    if primary is None and stub is None:
        if slot.compiled:
            return ModuleSurface(name, opaque="it is a compiled module with no .pyi")
        return ModuleSurface(name)
    if primary is None:
        return stub
    if stub is None or stub.opaque:
        return primary
    return _merged_with_stub(primary, stub)


def build_surface(
    files: Iterable[Any], *, kind: str, deadline: float | None = None
) -> PackageSurface:
    """Surface of an artifact's ``.py`` and ``.pyi`` files (``kind``: wheel or
    sdist). ``files`` have ``relative_path``, ``path`` and ``size``."""
    rows = list(files)
    if kind == "sdist":
        paths = list(_sdist_paths(rows))
    else:
        paths = list(_wheel_paths(rows))
    native_sources = kind == "sdist" and any(
        parts[-1].endswith(_NATIVE_SOURCE_SUFFIXES) for parts, _item in paths
    )
    slots, packages = _collect_slots(paths)
    if not slots:
        raise SurfaceUnreadable("no importable Python modules were found in it")
    if len(slots) > MAX_MODULES:
        raise SurfaceUnreadable(f"it has more than {MAX_MODULES:,} modules")
    budget = [MAX_SOURCE_TOTAL_BYTES]
    modules: dict[str, ModuleSurface] = {}
    for name, slot in sorted(slots.items()):
        if deadline is not None and time.monotonic() >= deadline:
            raise SurfaceUnreadable("the time limit was reached while reading it")
        modules[name] = _read_module_files(name, slot, name in packages, budget)
    return PackageSurface(modules, native_sources=native_sources)
