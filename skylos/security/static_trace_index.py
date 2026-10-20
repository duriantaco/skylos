"""Bounded source snapshots for explanatory static security traces."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys

from skylos import __version__
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.quality._provider_context import project_local_provider
from skylos.security.static_trace_bindings import SourceUnit


@dataclass(frozen=True)
class TraceLimits:
    max_discovery_entries: int = 50_000
    max_files: int = 1024
    max_file_bytes: int = 2_000_000
    max_total_bytes: int = 32_000_000
    max_ast_nodes: int = 500_000
    max_steps: int = 128
    max_depth: int = 16
    max_callers: int = 16


@dataclass
class SourceDocument:
    path: str
    digest: str


class ProjectTraceIndex:
    def __init__(self, project_root, files=None, limits=None, priority_files=None):
        self.root = Path(os.path.abspath(project_root))
        self.limits = limits or TraceLimits()
        self.units = {}
        self.documents = {}
        self.modules = {}
        self.limitations = []
        self.callers = {}
        self.function_names = set()
        self.resolvers = {}
        self.call_targets = {}
        self.receiver_proofs = {}
        self._snapshot_id = None
        self.selected_paths = []
        self._load(files, priority_files)
        for unit in self.units.values():
            for function in unit.functions.values():
                name = getattr(function.node, "name", None)
                if name:
                    self.function_names.add(name)
        self._index_calls()

    def relative_path(self, path):
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        candidate = Path(os.path.abspath(candidate))
        try:
            return candidate.relative_to(self.root).as_posix()
        except ValueError:
            return None

    def _paths(self, files):
        paths = set()
        if files is not None:
            for path in files:
                relative = self.relative_path(path)
                if relative:
                    paths.add(relative)
            return sorted(paths)
        excluded = {".git", ".venv", "venv", "node_modules", "__pycache__", ".skylos"}
        inspected = 0
        for directory, names, filenames in os.walk(self.root, followlinks=False):
            kept = []
            for name in sorted(names):
                inspected += 1
                if inspected > self.limits.max_discovery_entries:
                    self.limitations.append(
                        "Source discovery work budget reached; remaining source paths are unknown."
                    )
                    return sorted(paths)
                path = Path(directory) / name
                if name not in excluded and not path.is_symlink():
                    kept.append(name)
            names[:] = kept
            for name in sorted(filenames):
                inspected += 1
                if inspected > self.limits.max_discovery_entries:
                    self.limitations.append(
                        "Source discovery work budget reached; remaining source paths are unknown."
                    )
                    return sorted(paths)
                if name.endswith(".py"):
                    relative = self.relative_path(Path(directory) / name)
                    if relative:
                        paths.add(relative)
        return sorted(paths)

    def _load(self, files, priority_files):
        total_bytes = 0
        total_nodes = 0
        paths = self._paths(files)
        priorities = set()
        for candidate in priority_files or ():
            relative = self.relative_path(candidate)
            if relative and (files is None or relative in paths):
                priorities.add(relative)
        ordinary = []
        for path in paths:
            if path not in priorities:
                ordinary.append(path)
        paths = [*sorted(priorities), *ordinary]
        self.selected_paths = sorted(paths)
        if len(paths) > self.limits.max_files:
            self.limitations.append(
                "Project file-count budget reached; other files/callers are unknown."
            )
        for path in paths[: max(0, self.limits.max_files)]:
            text = read_project_text_no_symlink(
                self.root, path, max_bytes=self.limits.max_file_bytes, newline=""
            )
            if text is None:
                self.limitations.append(
                    "Source unavailable, non-regular, symlinked, undecodable or over byte limit: "
                    + path
                )
                continue
            size = len(text.encode("utf-8"))
            if total_bytes + size > self.limits.max_total_bytes:
                self.limitations.append(
                    "Project byte budget reached; remaining files/callers are unknown."
                )
                break
            total_bytes += size
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            self.documents[path] = SourceDocument(path, digest)
            if not path.endswith(".py"):
                continue
            try:
                tree = ast.parse(text.lstrip("\ufeff"), filename=path)
            except (SyntaxError, ValueError, RecursionError):
                self.limitations.append("Python source could not be parsed: " + path)
                continue
            count = 0
            for _node in ast.walk(tree):
                count += 1
                if count + total_nodes > self.limits.max_ast_nodes:
                    break
            if count + total_nodes > self.limits.max_ast_nodes:
                self.limitations.append(
                    "Project AST work budget reached; remaining files/callers are unknown."
                )
                break
            total_nodes += count
            parts = list(Path(path).with_suffix("").parts)
            if parts and parts[0] == "src":
                parts.pop(0)
            if parts and parts[-1] == "__init__":
                parts.pop()
            unit = SourceUnit(path, text, tree, ".".join(parts))
            self.units[path] = unit
            self.modules.setdefault(unit.module_name, []).append(unit)

    def resolve_function(self, unit, scope, expression):
        if isinstance(expression, ast.Name):
            binding = unit.strict_binding(scope, expression.id)
            if binding and binding.kind == "definition":
                target = unit.functions.get(id(binding.node))
                if target and not target.node.decorator_list:
                    return target
        qualified = unit.imported_name(scope, expression)
        if not qualified:
            return None
        parts = qualified.split(".")
        for size in range(len(parts) - 1, 0, -1):
            units = self.modules.get(".".join(parts[:size]), [])
            if len(units) != 1:
                continue
            target_unit = units[0]
            if target_unit.module.dynamic:
                return None
            remainder = parts[size:]
            if len(remainder) != 1:
                return None
            binding = target_unit.strict_binding(target_unit.module, remainder[0])
            if binding and binding.kind == "definition":
                target = target_unit.functions.get(id(binding.node))
                if target and not target.node.decorator_list:
                    return target
        return None

    def _index_calls(self):
        for path in sorted(self.units):
            unit = self.units[path]
            for node in ast.walk(unit.tree):
                if isinstance(node, ast.Call):
                    scope = unit.scope_for(node)
                    target, bound = self.resolve_call(unit, scope, node)
                    if target:
                        self.callers.setdefault(id(target.node), []).append(
                            (unit, scope, node, bound)
                        )
        for values in self.callers.values():
            values.sort(
                key=lambda item: (item[0].path, item[2].lineno, item[2].col_offset)
            )

    def resolver(self, unit):
        if unit.path not in self.resolvers:
            from skylos.security.static_trace_receivers import TraceReceiverResolver

            self.resolvers[unit.path] = TraceReceiverResolver(
                unit.tree, self.root / unit.path, self.root
            )
        return self.resolvers[unit.path]

    def resolve_call(self, unit, scope, call):
        if id(call) in self.call_targets:
            return self.call_targets[id(call)]
        target = self.resolve_function(unit, scope, call.func)
        if target:
            result = (target, False)
            self.call_targets[id(call)] = result
            return result
        if not isinstance(call.func, ast.Attribute):
            return None, False
        if call.func.attr not in self.function_names:
            return None, False
        proof = self.receiver_proof(unit, call)
        if proof.get("status") != "resolved" or proof.get("bound_method") is not True:
            return None, False
        path = self.relative_path(proof.get("file") or ".")
        target_unit = self.units.get(path)
        if target_unit is None:
            return None, False
        for candidate in target_unit.functions.values():
            if candidate.node.lineno == proof.get("line"):
                if not getattr(candidate.node, "decorator_list", []):
                    result = (candidate, True)
                    self.call_targets[id(call)] = result
                    return result
        return None, False

    def receiver_proof(self, unit, call):
        if id(call) not in self.receiver_proofs:
            self.receiver_proofs[id(call)] = self.resolver(unit).resolve_call(call)
        return self.receiver_proofs[id(call)]

    def project_provider(self, qualified, unit=None):
        root = qualified.split(".", 1)[0]
        for module_name in self.modules:
            if module_name == root or module_name.startswith(root + "."):
                return True
        filename = None
        if unit is not None:
            filename = self.root / unit.path
        return project_local_provider(root, filename, self.root)

    def snapshot_id(self):
        if self._snapshot_id is not None:
            return self._snapshot_id
        files = []
        for path in sorted(self.documents):
            files.append([path, self.documents[path].digest])
        payload = {
            "context": self.context(),
            "files": files,
            "limitations": self.limitations,
        }
        self._snapshot_id = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()
        return self._snapshot_id

    def context(self):
        selected = json.dumps(self.selected_paths, separators=(",", ":"))
        return {
            "algorithm": "security-static-trace-v1",
            "receiver_model_version": 2,
            "analyzer_version": __version__,
            "python_syntax_version": ".".join(map(str, sys.version_info[:3])),
            "limits": dict(vars(self.limits)),
            "selected_scope_sha256": hashlib.sha256(selected.encode()).hexdigest(),
            "selected_file_count": len(self.selected_paths),
        }


def build_index(project_root, files=None, *, limits=None, priority_files=None):
    return ProjectTraceIndex(project_root, files, limits, priority_files)
