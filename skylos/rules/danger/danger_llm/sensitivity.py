from __future__ import annotations

import ast

from .utils import (
    REDACTION_CALLS,
    SENSITIVE_ENV_FRAGMENTS,
    constant_string,
    is_sensitive_name,
    qualified_name_from_call,
    subscript_key_name,
)


class SensitiveExpressionMixin:
    aliases: dict[str, str]

    def _expr_is_sensitive(self, node: ast.AST | None) -> bool:
        if node is None:
            return False

        handlers = (
            (ast.Name, self._name_is_sensitive),
            (ast.Subscript, self._subscript_is_sensitive),
            (ast.Attribute, self._attribute_is_sensitive),
            (ast.JoinedStr, self._joined_string_is_sensitive),
            (ast.FormattedValue, self._formatted_value_is_sensitive),
            (ast.BinOp, self._binop_is_sensitive),
            (ast.Dict, self._dict_is_sensitive),
            ((ast.List, ast.Tuple, ast.Set), self._sequence_is_sensitive),
            (ast.Call, self._call_is_sensitive),
        )
        for node_type, handler in handlers:
            if isinstance(node, node_type):
                return handler(node)
        return False

    def _name_is_sensitive(self, node: ast.Name) -> bool:
        return self._is_sensitive_marked_name(node.id) or is_sensitive_name(node.id)

    def _subscript_is_sensitive(self, node: ast.Subscript) -> bool:
        key = subscript_key_name(node)
        if is_sensitive_name(key):
            return True
        if self._is_os_environ_expr(node.value):
            return True
        return self._expr_is_sensitive(node.value) or self._expr_is_sensitive(
            node.slice
        )

    def _attribute_is_sensitive(self, node: ast.Attribute) -> bool:
        if is_sensitive_name(node.attr):
            return True
        return self._expr_is_sensitive(node.value)

    def _joined_string_is_sensitive(self, node: ast.JoinedStr) -> bool:
        return any(self._expr_is_sensitive(value) for value in node.values)

    def _formatted_value_is_sensitive(self, node: ast.FormattedValue) -> bool:
        return self._expr_is_sensitive(node.value)

    def _binop_is_sensitive(self, node: ast.BinOp) -> bool:
        return self._expr_is_sensitive(node.left) or self._expr_is_sensitive(
            node.right
        )

    def _dict_is_sensitive(self, node: ast.Dict) -> bool:
        for key, value in zip(node.keys, node.values):
            if is_sensitive_name(constant_string(key)):
                return True
            if self._expr_is_sensitive(value):
                return True
        return False

    def _sequence_is_sensitive(self, node: ast.List | ast.Tuple | ast.Set) -> bool:
        return any(self._expr_is_sensitive(item) for item in node.elts)

    def _call_is_sensitive(self, node: ast.Call) -> bool:
        qual_name = qualified_name_from_call(node, self.aliases)
        if qual_name and qual_name.split(".")[-1] in REDACTION_CALLS:
            return False
        if self._env_call_is_sensitive(node, qual_name):
            return True
        if self._is_os_environ_expr(node):
            return True
        return any(self._expr_is_sensitive(arg) for arg in node.args) or any(
            self._expr_is_sensitive(keyword.value) for keyword in node.keywords
        )

    def _env_call_is_sensitive(self, node: ast.Call, qual_name: str | None) -> bool:
        if qual_name not in {"os.getenv", "os.environ.get", "environ.get"}:
            return False
        key = constant_string(node.args[0]) if node.args else None
        if key is None:
            return True
        return any(fragment in key.upper() for fragment in SENSITIVE_ENV_FRAGMENTS)
