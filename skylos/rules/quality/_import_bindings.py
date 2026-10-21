"""Module imports whose binding stays fixed for the whole file.

An import counts only when it is a direct statement of the module body, so it
always runs: imports under ``if TYPE_CHECKING``, ``try``/``except ImportError``
or ``if __name__ == "__main__"`` may not. A name bound more than once at module
scope, declared ``global`` in any scope, or reachable through ``globals()``,
``vars()``, ``exec`` or ``eval`` has no fixed value. For ``from m import n`` the
attribute ``m.n`` must also stay put in this file: an attribute write, a
``setattr``/``delattr``-style call naming it, or a ``reload`` of ``m`` makes a
later import read something else. Target code is never imported or read.
"""

import ast
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from skylos.rules.quality._receivers import _scope_bindings

_DYNAMIC_NAMESPACE_CALLS = frozenset({"globals", "vars", "exec", "eval"})


@dataclass(frozen=True)
class ImportBinding:
    name: str
    module: str
    member: str | None
    level: int
    alias: str | None
    line: int
    position: int

    @property
    def from_import(self) -> bool:
        return self.member is not None

    def covers(self, other: "ImportBinding") -> bool:
        """Whether running ``other`` would bind the object this binding holds."""
        if self.name != other.name or self.from_import != other.from_import:
            return False
        if self.from_import:
            return (self.level, self.module, self.member, self.alias) == (
                other.level,
                other.module,
                other.member,
                other.alias,
            )
        if self.alias is not None or other.alias is not None:
            return (self.module, self.alias) == (other.module, other.alias)
        loaded = self.module.split(".")
        wanted = other.module.split(".")
        return loaded[: len(wanted)] == wanted

    def statement_text(self) -> str:
        if not self.from_import:
            text = f"import {self.module}"
        else:
            source = "." * self.level + self.module
            text = f"from {source} import {self.member}"
        if self.alias:
            text += f" as {self.alias}"
        return text


def import_bindings(statement: ast.AST, position: int = -1) -> list[ImportBinding]:
    """Names one import statement binds; a star import binds nothing provable."""
    found = []
    if isinstance(statement, ast.Import):
        for alias in statement.names:
            found.append(
                ImportBinding(
                    name=alias.asname or alias.name.split(".", 1)[0],
                    module=alias.name,
                    member=None,
                    level=0,
                    alias=alias.asname,
                    line=statement.lineno,
                    position=position,
                )
            )
    elif isinstance(statement, ast.ImportFrom):
        for alias in statement.names:
            if alias.name == "*":
                continue
            found.append(
                ImportBinding(
                    name=alias.asname or alias.name,
                    module=statement.module or "",
                    member=alias.name,
                    level=statement.level,
                    alias=alias.asname,
                    line=statement.lineno,
                    position=position,
                )
            )
    return found


def _call_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


class _RebindingEvidence:
    """Names and module attributes this file can rebind after import time."""

    def __init__(self, module: ast.Module):
        self.dynamic = False
        self.global_names: set[str] = set()
        self.module_aliases: dict[str, set[str]] = {}
        self.attribute_writes: set[tuple[str, str]] = set()
        self.reloaded: set[str] = set()
        calls = []
        for node in ast.walk(module):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                self.global_names.update(node.names)
            elif isinstance(node, ast.ImportFrom) and any(
                alias.name == "*" for alias in node.names
            ):
                self.dynamic = True
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    target = alias.name
                    if alias.asname is None:
                        target = local
                    self.module_aliases.setdefault(local, set()).add(target)
            elif isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if isinstance(node.value, ast.Name):
                    self.attribute_writes.add((node.value.id, node.attr))
            elif isinstance(node, ast.Call):
                calls.append(node)
        for call in calls:
            self._record_call(call)

    def _record_call(self, call: ast.Call):
        name = _call_name(call.func)
        if isinstance(call.func, ast.Name) and name in _DYNAMIC_NAMESPACE_CALLS:
            self.dynamic = True
            return
        if not call.args or not isinstance(call.args[0], ast.Name):
            return
        owner = call.args[0].id
        if name == "reload":
            self.reloaded.add(owner)
            return
        if len(call.args) > 1:
            member = call.args[1]
            if isinstance(member, ast.Constant) and isinstance(member.value, str):
                self.attribute_writes.add((owner, member.value))

    def source_rebound(self, binding: ImportBinding) -> bool:
        if binding.level:
            return False
        for local, targets in self.module_aliases.items():
            if binding.module not in targets and not any(
                target == binding.module.split(".", 1)[0] for target in targets
            ):
                continue
            if (
                local in self.reloaded
                or (local, binding.member) in self.attribute_writes
            ):
                return True
        return False


def _inside(path: Path, root: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(root)
    except ValueError:
        return False
    return True


def project_submodule(binding: ImportBinding, filename, project_root) -> bool:
    """Whether ``from m import n`` names a module file of a project package.

    Python keeps one object per module in ``sys.modules``, so importing a
    submodule again returns the object the earlier import bound. A function,
    class or constant can be rebound on its module at run time (a test's
    ``mock.patch``, a lazy loader), and a later ``from m import n`` then reads
    the new value, so only submodule files count. Only file metadata under the
    project root is checked; nothing is read or imported.
    """
    if not binding.from_import or project_root is None or filename is None:
        return False
    if not binding.member.isidentifier():
        return False
    parts = [part for part in binding.module.split(".") if part]
    if not all(part.isidentifier() for part in parts):
        return False
    root = Path(os.path.realpath(project_root))
    source = Path(os.path.abspath(filename))
    if not _inside(source, root):
        return False
    if binding.level:
        base = source.parent
        for _step in range(binding.level - 1):
            base = base.parent
        packages = [base.joinpath(*parts)]
    else:
        packages = [root.joinpath(*parts), (root / "src").joinpath(*parts)]
    for package in packages:
        for candidate in (
            package / f"{binding.member}.py",
            package / binding.member / "__init__.py",
        ):
            try:
                mode = candidate.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode) and _inside(candidate, root):
                return True
    return False


def stable_module_imports(module: ast.Module) -> dict[str, ImportBinding]:
    """Unconditional top-level imports that nothing else in the file rebinds."""
    if not isinstance(module, ast.Module):
        return {}
    bindings = _scope_bindings(module)
    evidence = _RebindingEvidence(module)
    if evidence.dynamic or "*" in bindings.names:
        return {}
    stable = {}
    for position, statement in enumerate(module.body):
        for binding in import_bindings(statement, position):
            if bindings.counts[binding.name] != 1:
                continue
            if binding.name in evidence.global_names:
                continue
            if binding.from_import and binding.module == "__future__":
                continue
            if binding.from_import and evidence.source_rebound(binding):
                continue
            stable[binding.name] = binding
    return stable
