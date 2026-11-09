"""Recognize weak RNG flowing into slugs of privacy-bearing Django models."""

from __future__ import annotations

import ast


def private_model_slug_evidence(call):
    current = call
    function = owner = module = None
    while current is not None:
        if function is None and isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            function = current
        elif owner is None and isinstance(current, ast.ClassDef):
            owner = current
        if isinstance(current, ast.Module):
            module = current
        current = getattr(current, "parent", None)
    if function is None or owner is None or module is None:
        return None
    aliases = {}
    classes = {}
    for node in module.body:
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ClassDef):
            classes[node.name] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    aliases.pop(target.id, None)

    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{name(node.value)}.{node.attr}"
        return ""

    def model(cls, seen):
        if id(cls) in seen or len(seen) > 12:
            return False
        seen = seen | {id(cls)}
        return any(
            name(base) == "django.db.models.Model"
            or (
                isinstance(base, ast.Name)
                and base.id in classes
                and model(classes[base.id], seen)
            )
            for base in cls.bases
        )

    if not model(owner, set()):
        return None
    fields = {}
    enums = {}
    for statement in owner.body:
        if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Call):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    fields[target.id] = statement.value
        elif isinstance(statement, ast.ClassDef) and any(
            name(base) == "django.db.models.TextChoices" for base in statement.bases
        ):
            values = {
                value.value.value
                for value in statement.body
                if isinstance(value, ast.Assign)
                and isinstance(value.value, ast.Constant)
                and isinstance(value.value.value, str)
            }
            enums[statement.name] = values
    privacy = fields.get("privacy_level")
    slug = fields.get("slug")
    if (
        privacy is None
        or slug is None
        or name(privacy.func) != "django.db.models.CharField"
        or name(slug.func) != "django.db.models.CharField"
    ):
        return None
    if not any(
        kw.arg == "unique"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in slug.keywords
    ):
        return None
    if not any(
        kw.arg == "choices"
        and isinstance(kw.value, ast.Attribute)
        and isinstance(kw.value.value, ast.Name)
        and kw.value.attr == "choices"
        and {"private", "protected"} <= enums.get(kw.value.value.id, set())
        for kw in privacy.keywords
    ):
        return None
    if not function.args.args:
        return None
    receiver = function.args.args[0].arg
    work = [0]

    def flow(statements, derived):
        derived = set(derived)
        hit = False
        for statement in statements:
            work[0] += 1
            if work[0] > 1024:
                return derived, False
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if isinstance(statement, ast.If):
                left, left_hit = flow(statement.body, derived)
                right, right_hit = flow(statement.orelse, derived)
                derived = left | right
                hit |= left_hit or right_hit
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                body, body_hit = flow(statement.body, derived)
                derived |= body
                derived, other_hit = flow(statement.orelse, derived)
                hit |= body_hit or other_hit
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                derived, inner_hit = flow(statement.body, derived)
                hit |= inner_hit
                continue
            if isinstance(statement, ast.Assign):
                targets, value = statement.targets, statement.value
            elif isinstance(statement, ast.AnnAssign) and statement.value:
                targets, value = [statement.target], statement.value
            else:
                continue
            nodes = list(ast.walk(value))
            tainted = call in nodes or any(
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in derived
                for node in nodes
            )
            for target in targets:
                if isinstance(target, ast.Name):
                    derived.discard(target.id)
                    if tainted:
                        derived.add(target.id)
                elif (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == receiver
                    and target.attr == "slug"
                    and tainted
                ):
                    hit = True
        return derived, hit

    _, hit = flow(function.body, set())
    if hit and work[0] <= 1024:
        return {
            "evidence_kind": "python_weak_random_private_model_slug",
            "source": "random generator",
            "sink": f"{owner.name}.slug",
            "path": [
                "weak random result",
                "unique model slug",
                "model has private/protected visibility choices",
            ],
            "analysis_complete": False,
        }
    return None
