"""Bounded filesystem evidence for imported external-library contracts."""

import keyword
import os
from importlib.machinery import all_suffixes
from pathlib import Path
import stat


def project_local_provider(module, filename=None, project_root=None):
    """Whether a local provider exists or cannot safely be ruled out.

    ``module`` is a top-level import identifier, never a dotted path. Only
    metadata for root, src and source-directory providers is inspected; target
    code is never imported or read. Missing root context preserves existing
    AST-only import proofs, while uncertain supplied paths retain findings.
    """
    if not isinstance(module, str) or not module.isidentifier() or keyword.iskeyword(module):
        return True
    if project_root is None:
        return False
    try:
        root = Path(os.path.abspath(project_root))
        # Check parents first so later probes never follow a symlinked
        # component of the supplied project path.
        if any(
            not stat.S_ISDIR(directory.lstat().st_mode)
            for directory in reversed((root, *root.parents))
        ):
            return True
        # A package may itself be the supplied project/scan root. Its name
        # alone is insufficient; require a loader-recognized package marker.
        if root.name == module:
            for suffix in all_suffixes():
                try:
                    (root / f"__init__{suffix}").lstat()
                except FileNotFoundError:
                    continue
                return True
        search_paths = {root}
        if filename is not None:
            source = Path(os.path.abspath(filename))
            relative = source.relative_to(root)
            directory = root
            for component in relative.parts[:-1]:
                directory /= component
                if not stat.S_ISDIR(directory.lstat().st_mode):
                    return True
            try:
                source_mode = source.lstat().st_mode
            except FileNotFoundError:
                source_mode = None
            if source_mode is not None and not stat.S_ISREG(source_mode):
                return True
            search_paths.add(directory)
        source_root = root / "src"
        try:
            source_root_mode = source_root.lstat().st_mode
        except FileNotFoundError:
            source_root_mode = None
        if source_root_mode is not None:
            if stat.S_ISLNK(source_root_mode):
                return True
            if stat.S_ISDIR(source_root_mode):
                search_paths.add(source_root)
        for directory in search_paths:
            providers = [directory / module]
            providers.extend(directory / f"{module}{suffix}" for suffix in all_suffixes())
            for provider in providers:
                try:
                    provider.lstat()
                except FileNotFoundError:
                    continue
                return True
        return False
    except (OSError, RuntimeError, TypeError, ValueError):
        return True
