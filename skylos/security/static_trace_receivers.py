"""Additional receiver contracts used only by explanatory security traces."""

from __future__ import annotations

from skylos.rules.quality._provider_context import project_local_provider
from skylos.security.receiver_bindings import _Reference
from skylos.security.receiver_resolution import ReceiverResolver

_PATH_ARGUMENTS = {
    "os.open": "path",
    "os.unlink": "path",
    "os.remove": "path",
    "os.mkdir": "path",
    "os.rmdir": "path",
    "os.makedirs": "name",
    "shutil.copy": "src",
    "shutil.copy2": "src",
    "shutil.copytree": "src",
    "shutil.move": "src",
    "shutil.rmtree": "path",
}


class TraceReceiverResolver(ReceiverResolver):
    """Identify low-level path operands without changing detector effects."""

    def _attribute(self, base, name, depth, active):
        if (
            base is not None
            and base.kind == "module"
            and base.name in {"os", "shutil"}
            and f"{base.name}.{name}" in _PATH_ARGUMENTS
            and depth <= self.MAX_DEPTH
        ):
            if base.module is not None:
                if name not in base.module.bindings(base.module.tree):
                    return None
                return super()._attribute(base, name, depth, active)
            if base.name in self._unavailable_modules:
                return None
            for module in self.modules.values():
                if project_local_provider(base.name, module.path, self.root):
                    return None
            return _Reference(
                "builtin", f"{base.name}.{name}", model="trace_path_argument"
            )
        return super()._attribute(base, name, depth, active)

    def _effects(self, ref, active=frozenset()):
        if ref.model == "trace_path_argument":
            return {"filesystem": "wrapped_path_argument", "database": "none"}, 0
        return super()._effects(ref, active)

    def resolve_call(self, node):
        proof = super().resolve_call(node)
        qualified = proof.get("qualified_name")
        if qualified in _PATH_ARGUMENTS and proof.get("file") is None:
            proof["path_argument_name"] = _PATH_ARGUMENTS[qualified]
            proof["steps"].append(
                {
                    "kind": "standard_library_contract",
                    "file": str(self.path),
                    "line": getattr(node, "lineno", None),
                    "description": f"An unshadowed import identifies {qualified}; its first argument, or {_PATH_ARGUMENTS[qualified]} keyword, is the filesystem path.",
                }
            )
        return proof
