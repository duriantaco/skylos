from __future__ import annotations

import ast
import fnmatch


def _decorator_name(deco: ast.AST):
    if isinstance(deco, ast.Name):
        return deco.id

    if isinstance(deco, ast.Attribute):
        base = _decorator_name(deco.value)
        if base:
            return f"{base}.{deco.attr}"
        else:
            return deco.attr

    if isinstance(deco, ast.Call):
        return _decorator_name(deco.func)

    return None


def _base_name(base):
    if isinstance(base, ast.Name):
        return base.id

    if isinstance(base, ast.Attribute):
        parts = []
        cur = base
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        return base.attr

    return None


def _matches_any(value, globs):
    val = value.lower()
    for glob in globs:
        if fnmatch.fnmatch(val, glob.lower()):
            return True
    return False


def _keep_docstring_only(body):
    if body:
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            return [first, ast.Pass()]
    return [ast.Pass()]


class MaskSpec:
    def __init__(self, names=None, decorators=None, bases=None, keep_docstring=True):
        self.names = list(names or [])
        self.decorators = list(decorators or [])
        self.bases = list(bases or [])
        self.keep_docstring = bool(keep_docstring)


class BodyMasker(ast.NodeTransformer):
    def __init__(self, spec):
        self.spec = spec
        self.masked_count = 0

    def _should_mask_function(self, node):
        if self.spec.names and _matches_any(node.name, self.spec.names):
            return True

        if self.spec.decorators and node.decorator_list:
            for deco_node in node.decorator_list:
                deco_name = _decorator_name(deco_node)
                if deco_name and _matches_any(deco_name, self.spec.decorators):
                    return True

        return False

    def _should_mask_class(self, node):
        if self.spec.names and _matches_any(node.name, self.spec.names):
            return True

        if self.spec.decorators and node.decorator_list:
            for deco_node in node.decorator_list:
                deco_name = _decorator_name(deco_node)
                if deco_name and _matches_any(deco_name, self.spec.decorators):
                    return True

        if self.spec.bases and node.bases:
            for base_node in node.bases:
                base_name = _base_name(base_node)
                if base_name and _matches_any(base_name, self.spec.bases):
                    return True

        return False

    def visit_FunctionDef(self, node):
        if self._should_mask_function(node):
            if self.spec.keep_docstring:
                node.body = _keep_docstring_only(node.body)
            else:
                node.body = [ast.Pass()]
            self.masked_count += 1
            return node

        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        if self._should_mask_function(node):
            if self.spec.keep_docstring:
                node.body = _keep_docstring_only(node.body)
            else:
                node.body = [ast.Pass()]

            self.masked_count += 1
            return node
        return self.generic_visit(node)

    def visit_ClassDef(self, node):
        if self._should_mask_class(node):
            if self.spec.keep_docstring:
                node.body = _keep_docstring_only(node.body)
            else:
                node.body = [ast.Pass()]
            self.masked_count += 1
            return node

        self.generic_visit(node)
        return node


def apply_body_mask(tree, spec):
    if not (spec.names or spec.decorators or spec.bases):
        return tree, 0

    masker = BodyMasker(spec)
    new_tree = masker.visit(tree)
    ast.fix_missing_locations(new_tree)
    return new_tree, masker.masked_count


def default_mask_spec_from_config(cfg):
    if isinstance(cfg, dict):
        block = cfg.get("masking", {})
    else:
        block = {}

    return MaskSpec(
        names=block.get("names", []),
        decorators=block.get("decorators", []),
        bases=block.get("bases", []),
        keep_docstring=block.get("keep_docstring", True),
    )
