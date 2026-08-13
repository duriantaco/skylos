from __future__ import annotations

from pathlib import Path

from skylos.analysis.circular_deps import _resolve_from_import_targets


def architecture_iad_strict(architecture_cfg) -> bool:
    if not isinstance(architecture_cfg, dict):
        return False
    for key in ("enforce_iad", "strict_iad"):
        if key in architecture_cfg:
            return bool(architecture_cfg.get(key))
    return False


def expand_reexported_entrypoint_modules(
    entrypoint_qnames: set[str],
    entrypoint_modules: set[str],
    raw_imports_by_file: dict[Path, list],
    modmap: dict[Path, str],
    module_files: dict[str, str],
) -> set[str]:
    modules = set(entrypoint_modules)
    known_modules = set(module_files)

    for qname in entrypoint_qnames:
        if "." not in qname:
            continue

        entry_module, entry_symbol = qname.rsplit(".", 1)
        for file_path, raw_imports in raw_imports_by_file.items():
            if modmap.get(file_path) != entry_module:
                continue

            for import_module, _line, import_type, imported_names in raw_imports:
                if import_type != "from_import":
                    continue
                if entry_symbol not in imported_names:
                    continue
                if import_module in known_modules:
                    modules.add(import_module)

    return modules


def find_package_boundary_modules(
    raw_imports_by_file: dict[Path, list],
    modmap: dict[Path, str],
    module_files: dict[str, str],
) -> set[str]:
    modules: set[str] = set()
    known_modules = set(module_files)

    for file_path, raw_imports in raw_imports_by_file.items():
        package_module = modmap.get(file_path)
        if not package_module or Path(file_path).name != "__init__.py":
            continue

        for import_module, _line, import_type, imported_names in raw_imports:
            if import_type != "from_import":
                continue

            targets = _resolve_from_import_targets(
                import_module,
                imported_names,
                known_modules,
            )
            for target in targets:
                if target != package_module and target.startswith(package_module + "."):
                    modules.add(target)

    return modules
