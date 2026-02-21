from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("Skylos")

CONVENTION_ENTRY_FILES = frozenset(
    {
        "__main__.py",
        "manage.py",
        "wsgi.py",
        "asgi.py",
        "conftest.py",
        "setup.py",
        "fabfile.py",
        "tasks.py",
        "app.py",
        "main.py",
        "server.py",
        "cli.py",
    }
)


class ModuleReachabilityAnalyzer:
    def __init__(self):
        self.graph: Dict[str, Set[str]] = defaultdict(set)
        self.all_modules: Set[str] = set()
        self.entry_points: Set[str] = set()
        self._getattr_packages: Set[str] = set()
        self._dynamic_import_modules: Set[str] = set()

    def build(
        self,
        modmap: Dict[Path, str],
        all_raw_imports: Dict[Path, List[Tuple]],
        pyproject_entrypoints: Optional[Set[str]] = None,
        dynamic_modules: Optional[Set[str]] = None,
        file_defs: Optional[Dict[Path, list]] = None,
    ) -> None:
        for file_path, mod_name in modmap.items():
            if not mod_name:
                continue
            self.all_modules.add(mod_name)

        if not self.all_modules:
            return

        known_roots = set()
        for m in self.all_modules:
            known_roots.add(m.split(".")[0])

        for file_path, raw_imports in all_raw_imports.items():
            from_mod = modmap.get(file_path)
            if not from_mod:
                continue

            for import_module, *_ in raw_imports:
                if not import_module:
                    continue
                root = import_module.split(".")[0]
                if root not in known_roots:
                    continue

                target = self._resolve_target(import_module)
                if target:
                    self.graph[from_mod].add(target)

        self._detect_entry_points(modmap, pyproject_entrypoints)
        self._detect_getattr_packages(modmap, file_defs)
        self._expand_getattr_packages()

        if dynamic_modules:
            self._dynamic_import_modules = set(dynamic_modules)

    def _resolve_target(self, import_path: str) -> Optional[str]:
        parts = import_path.split(".")
        for i in range(len(parts), 0, -1):
            candidate = ".".join(parts[:i])
            if candidate in self.all_modules:
                return candidate
        return None

    def _detect_entry_points(
        self,
        modmap: Dict[Path, str],
        pyproject_entrypoints: Optional[Set[str]] = None,
    ) -> None:
        for file_path, mod_name in modmap.items():
            if not mod_name:
                continue
            basename = Path(file_path).name
            if basename in CONVENTION_ENTRY_FILES:
                self.entry_points.add(mod_name)

        for file_path, mod_name in modmap.items():
            if not mod_name:
                continue
            basename = Path(file_path).name
            if basename.startswith("test_") or basename.endswith("_test.py"):
                self.entry_points.add(mod_name)

        if pyproject_entrypoints:
            for qname in pyproject_entrypoints:
                parts = qname.rsplit(".", 1)
                if len(parts) == 2:
                    mod = parts[0]
                    resolved = self._resolve_target(mod)
                    if resolved:
                        self.entry_points.add(resolved)
                resolved = self._resolve_target(qname)
                if resolved:
                    self.entry_points.add(resolved)

        for file_path, mod_name in modmap.items():
            if not mod_name:
                continue
            parts = mod_name.split(".")
            basename = Path(file_path).name
            if len(parts) == 1 and basename == "__init__.py":
                self.entry_points.add(mod_name)

    def _detect_getattr_packages(
        self,
        modmap: Dict[Path, str],
        file_defs: Optional[Dict[Path, list]] = None,
    ) -> None:
        if not file_defs:
            return

        for file_path, defs in file_defs.items():
            basename = Path(file_path).name
            if basename != "__init__.py":
                continue

            mod_name = modmap.get(file_path)
            if not mod_name:
                continue

            for defn in defs:
                simple = getattr(defn, "simple_name", None)
                def_type = getattr(defn, "type", None)
                if simple == "__getattr__" and def_type == "function":
                    self._getattr_packages.add(mod_name)
                    break

    def _expand_getattr_packages(self) -> None:
        for pkg in self._getattr_packages:
            prefix = pkg + "."
            for mod in self.all_modules:
                if mod.startswith(prefix):
                    self.graph[pkg].add(mod)

    def find_unreachable(self) -> Set[str]:
        if not self.all_modules:
            return set()

        if not self.entry_points:
            logger.debug(
                "Module reachability: no entry points detected, skipping analysis"
            )
            return set()

        reachable: Set[str] = set()
        queue = list(self.entry_points)

        while queue:
            current = queue.pop()
            if current in reachable:
                continue
            reachable.add(current)

            for target in self.graph.get(current, set()):
                if target not in reachable:
                    queue.append(target)

            current_root = current.split(".")[0]
            if current_root in (self._dynamic_import_modules or set()):
                for mod in self.all_modules:
                    if mod.split(".")[0] == current_root and mod not in reachable:
                        queue.append(mod)

            for pkg in self._getattr_packages:
                if current.startswith(pkg + ".") or current == pkg:
                    if pkg not in reachable:
                        queue.append(pkg)

        unreachable = self.all_modules - reachable
        if unreachable:
            logger.info(
                f"Module reachability: {len(unreachable)}/{len(self.all_modules)} "
                f"modules unreachable from entry points"
            )

        return unreachable


def find_unreachable_modules(
    modmap: Dict[Path, str],
    all_raw_imports: Dict[Path, List[Tuple]],
    pyproject_entrypoints: Optional[Set[str]] = None,
    dynamic_modules: Optional[Set[str]] = None,
    file_defs: Optional[Dict[Path, list]] = None,
) -> Set[str]:
    analyzer = ModuleReachabilityAnalyzer()
    analyzer.build(
        modmap=modmap,
        all_raw_imports=all_raw_imports,
        pyproject_entrypoints=pyproject_entrypoints,
        dynamic_modules=dynamic_modules,
        file_defs=file_defs,
    )
    return analyzer.find_unreachable()
