"""Bindings that the classic JSX transform reads without naming them.

With ``"jsx": "react"`` TypeScript compiles ``<div />`` to
``React.createElement("div")``, so the factory's root identifier must be in
scope although the source never spells it. ``jsxFactory`` and
``jsxFragmentFactory`` rename the factory, and a ``@jsx`` / ``@jsxFrag``
pragma in the file overrides both. The automatic runtime (``react-jsx``,
``react-jsxdev``) imports ``react/jsx-runtime`` itself and reads no binding;
``preserve`` and ``react-native`` leave the transform to another tool, so
nothing is assumed for them.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

from .resolve import _resolve_extends_path
from .workspace import _load_jsonc

_PRAGMA_HEAD_BYTES = 4096
_FACTORY_PRAGMA_RE = re.compile(rb"@jsx\s+([A-Za-z_$][\w$]*)")
_FRAGMENT_PRAGMA_RE = re.compile(rb"@jsxFrag\s+([A-Za-z_$][\w$]*)")
_RUNTIME_PRAGMA_RE = re.compile(rb"@jsxRuntime\s+(classic|automatic)\b")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][\w$]*")
_MAX_EXTENDS_DEPTH = 8


@lru_cache(maxsize=4096)
def _nearest_tsconfig(directory: str) -> str | None:
    candidate = os.path.join(directory, "tsconfig.json")
    if os.path.isfile(candidate):
        return candidate
    parent = os.path.dirname(directory)
    if parent == directory:
        return None
    return _nearest_tsconfig(parent)


def _root_identifier(value) -> str | None:
    if not isinstance(value, str):
        return None
    match = _IDENTIFIER_RE.match(value.strip())
    if match is None:
        return None
    return match.group(0)


def _compiler_options(tsconfig_path: str, depth: int = 0) -> dict:
    data = _load_jsonc(Path(tsconfig_path))
    if not isinstance(data, dict):
        return {}
    merged: dict = {}
    extends = data.get("extends")
    if isinstance(extends, str):
        extends = [extends]
    if isinstance(extends, list) and depth < _MAX_EXTENDS_DEPTH:
        for parent in extends:
            if not isinstance(parent, str):
                continue
            parent_path = _resolve_extends_path(os.path.dirname(tsconfig_path), parent)
            if parent_path:
                merged.update(_compiler_options(parent_path, depth + 1))
    options = data.get("compilerOptions")
    if isinstance(options, dict):
        merged.update(options)
    return merged


@lru_cache(maxsize=1024)
def _configured_factories(tsconfig_path: str) -> tuple[str | None, str | None]:
    options = _compiler_options(tsconfig_path)
    if options.get("jsx") != "react":
        return None, None
    factory = _root_identifier(options.get("jsxFactory")) or "React"
    fragment = _root_identifier(options.get("jsxFragmentFactory")) or "React"
    return factory, fragment


def classic_jsx_bindings(
    file_path: str, source: bytes, *, has_fragment: bool
) -> tuple[str, ...]:
    """Identifiers the JSX in ``file_path`` reads under the classic transform."""
    head = source[:_PRAGMA_HEAD_BYTES]
    runtime = _RUNTIME_PRAGMA_RE.search(head)
    factory_pragma = _FACTORY_PRAGMA_RE.search(head)
    fragment_pragma = _FRAGMENT_PRAGMA_RE.search(head)
    if runtime is not None and runtime.group(1) == b"automatic":
        return ()

    factory = None
    fragment = None
    tsconfig = _nearest_tsconfig(os.path.dirname(os.path.abspath(file_path)))
    if tsconfig is not None:
        factory, fragment = _configured_factories(tsconfig)
    if factory is None and runtime is not None:
        factory, fragment = "React", "React"
    if factory_pragma is not None:
        factory = factory_pragma.group(1).decode("utf-8", "replace")
        if fragment is None:
            fragment = "React"
    if fragment_pragma is not None and factory is not None:
        fragment = fragment_pragma.group(1).decode("utf-8", "replace")
    if factory is None:
        return ()
    if has_fragment and fragment is not None and fragment != factory:
        return factory, fragment
    return (factory,)
