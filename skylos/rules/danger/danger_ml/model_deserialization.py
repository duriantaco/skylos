from __future__ import annotations

import ast
import sys

from skylos.rules.danger.calls import _qualified_name_from_call
from skylos.rules.danger.taint import TaintVisitor


MODEL_ARTIFACT_SUFFIXES = (
    ".bin",
    ".ckpt",
    ".h5",
    ".joblib",
    ".keras",
    ".pkl",
    ".pickle",
    ".pt",
    ".pth",
)

REMOTE_MODEL_CALLS = {
    "hf_hub_download",
    "huggingface_hub.hf_hub_download",
    "snapshot_download",
    "huggingface_hub.snapshot_download",
    "requests.get",
    "requests.post",
    "urllib.request.urlretrieve",
    "wget.download",
}

KERAS_LOAD_MODEL_CALLS = {
    "keras.models.load_model",
    "tensorflow.keras.models.load_model",
    "tf.keras.models.load_model",
}


class _ModelDeserializationChecker(TaintVisitor):
    def __init__(self, file_path, findings):
        super().__init__(file_path, findings)
        self.aliases: dict[str, str] = {}
        self.remote_model_stack: list[set[str]] = [set()]
        self._emitted: set[tuple[int, int, str]] = set()

    def _push(self):
        super()._push()
        self.remote_model_stack.append(set())

    def _pop(self):
        if len(self.remote_model_stack) > 1:
            self.remote_model_stack.pop()
        super()._pop()

    def _mark_remote_model(self, name: str) -> None:
        self.remote_model_stack[-1].add(name)

    def _is_remote_model_name(self, name: str | None) -> bool:
        if not name:
            return False
        return any(name in scope for scope in reversed(self.remote_model_stack))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                self.aliases[local] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        is_remote = self._expr_is_remote_model(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name) and is_remote:
                self._mark_remote_model(target.id)
        super().visit_Assign(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if (
            node.value
            and isinstance(node.target, ast.Name)
            and self._expr_is_remote_model(node.value)
        ):
            self._mark_remote_model(node.target.id)
        super().visit_AnnAssign(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _qualified_name_from_call(node, self.aliases)
        if name:
            self._check_model_load_call(node, name)
        self.generic_visit(node)

    def _check_model_load_call(self, node: ast.Call, name: str) -> None:
        if name == "torch.load":
            if self._kw_is_true(node, "weights_only"):
                return
            self._append_model_load_finding(node, "torch.load")
            return

        if name == "numpy.load":
            if self._kw_is_true(node, "allow_pickle"):
                self._append_model_load_finding(node, "numpy.load allow_pickle")
            return

        if name == "joblib.load":
            self._append_model_load_finding(node, "joblib.load")
            return

        if name in KERAS_LOAD_MODEL_CALLS:
            self._append_model_load_finding(node, "Keras load_model")
            return

        if name == "pickle.load" and self._call_uses_model_path(node):
            self._append_model_load_finding(node, "pickle.load on model artifact")

    def _append_model_load_finding(self, node: ast.Call, loader: str) -> None:
        line = int(getattr(node, "lineno", 1) or 1)
        col = int(getattr(node, "col_offset", 0) or 0)
        key = (line, col, loader)
        if key in self._emitted:
            return
        self._emitted.add(key)

        severity = "HIGH"
        if self._call_uses_untrusted_source(node):
            severity = "CRITICAL"
        message = (
            f"Unsafe ML model deserialization via {loader}; only load trusted "
            "local model artifacts, prefer safetensors for weights, and avoid "
            "pickle-backed formats from remote or user-controlled paths."
        )
        self.findings.append(
            {
                "rule_id": "SKY-D265",
                "severity": severity,
                "message": message,
                "file": str(self.file_path),
                "line": line,
                "col": col,
                "symbol": self._current_symbol(),
                "metadata": {"ml_model_deserialization": True},
            }
        )

    def _call_uses_untrusted_source(self, node: ast.Call) -> bool:
        return any(self._expr_is_remote_model(arg) for arg in node.args) or any(
            self._expr_is_remote_model(keyword.value) for keyword in node.keywords
        )

    def _call_uses_model_path(self, node: ast.Call) -> bool:
        return any(self._expr_looks_like_model_path(arg) for arg in node.args)

    def _expr_is_remote_model(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if self.is_tainted(node):
            return True
        if isinstance(node, ast.Name):
            return self._is_remote_model_name(node.id)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _is_remote_path(node.value)
        if isinstance(node, ast.Call):
            name = _qualified_name_from_call(node, self.aliases)
            if name in REMOTE_MODEL_CALLS:
                return True
        return any(self._expr_is_remote_model(child) for child in ast.iter_child_nodes(node))

    def _expr_looks_like_model_path(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _looks_like_model_artifact(node.value)
        if isinstance(node, ast.Call):
            name = _qualified_name_from_call(node, self.aliases)
            if name == "open" and node.args:
                return self._expr_looks_like_model_path(node.args[0])
        return any(
            self._expr_looks_like_model_path(child) for child in ast.iter_child_nodes(node)
        )

    @staticmethod
    def _kw_is_true(node: ast.Call, keyword_name: str) -> bool:
        return any(
            keyword.arg == keyword_name
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )


def _is_remote_path(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("http://", "https://", "s3://", "gs://", "hf://"))


def _looks_like_model_artifact(value: str) -> bool:
    return value.lower().endswith(MODEL_ARTIFACT_SUFFIXES)


def scan(tree, file_path, findings):
    try:
        checker = _ModelDeserializationChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(
            f"ML model deserialization analysis failed for {file_path}: {e}",
            file=sys.stderr,
        )
