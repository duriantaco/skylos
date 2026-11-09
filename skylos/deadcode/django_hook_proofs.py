"""Bounded source proofs for Django class hooks and form-field dispatch.

False disproves a framework convention; None retains unresolved ancestry or
dynamic field uncertainty. Target modules are parsed, never imported.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.deadcode.framework_liveness import (
    _DefinitionIndex,
    _eager_nodes,
    _qualified,
)
from skylos.deadcode.python_ast import parse_python_files
from skylos.deadcode.signature_contracts import _merge_c3_mro
from skylos.deadcode.web_framework_liveness import _WebScanner


_BASES = {
    "model": frozenset(
        {
            "django.db.models.Model",
            "django.db.models.base.Model",
            "django.db.models.Manager",
            "django.db.models.manager.Manager",
            "django.db.models.QuerySet",
            "django.db.models.query.QuerySet",
        }
    ),
    "form": frozenset(
        {
            "django.forms.Form",
            "django.forms.forms.Form",
            "django.forms.BaseForm",
            "django.forms.forms.BaseForm",
            "django.forms.ModelForm",
            "django.forms.models.ModelForm",
            "django.forms.BaseModelForm",
            "django.forms.models.BaseModelForm",
        }
    ),
    "command": frozenset(
        {
            "django.core.management.BaseCommand",
            "django.core.management.base.BaseCommand",
            "django.core.management.base.AppCommand",
            "django.core.management.base.LabelCommand",
        }
    ),
}
_MODEL_FORMS = frozenset(name for name in _BASES["form"] if "ModelForm" in name)
_BASES.update(
    {
        "model_instance": frozenset(
            {"django.db.models.Model", "django.db.models.base.Model"}
        ),
        "manager": frozenset(
            {"django.db.models.Manager", "django.db.models.manager.Manager"}
        ),
        "queryset": frozenset(
            {"django.db.models.QuerySet", "django.db.models.query.QuerySet"}
        ),
        "model_form": _MODEL_FORMS,
    }
)
_METHOD_ROLES = {
    "save": ("model_instance", "model_form"),
    "delete": ("model_instance", "queryset"),
    "clean": ("model_instance", "form"),
    "full_clean": ("model_instance", "form"),
    "validate_unique": ("model_instance", "model_form"),
    "get_absolute_url": ("model_instance",),
    "natural_key": ("model_instance",),
    "get_queryset": ("manager",),
    "is_valid": ("form",),
    "handle": ("command",),
    "add_arguments": ("command",),
}


class _HookScanner(_WebScanner):
    def __init__(self, proof, index, module):
        super().__init__(index, module, set())
        self.proof = proof
        self.started = False
        self.bindings = {}
        self.class_bindings = {}
        self.dynamic_fields = set()

    def collect(self):
        if not self.started:
            self.started = True
            self.suite(self.tree.body, self.bindings)
            self.evidence.bindings = self.bindings.copy()
        return self.evidence

    def _scan_class(self, statement, bindings, owner):
        definition = self.evidence.at(statement, "class")
        if definition is not None and owner is None:
            self.class_bindings[definition.name] = bindings.copy()
        super()._scan_class(statement, bindings, owner)
        if definition is not None and definition.name in self.evidence.classes:
            definition, bases, members, model_bindings = self.evidence.classes[
                definition.name
            ]
            self.evidence.classes[definition.name] = (
                definition,
                tuple(self.resolve_expr(base, bindings) for base in statement.bases),
                members,
                model_bindings,
            )

    def _scan_import(self, statement, bindings, owner):
        super()._scan_import(statement, bindings, owner)
        for alias in statement.names:
            if alias.name == "*":
                continue
            if isinstance(statement, ast.Import):
                imported = self.proof.scanners.get(alias.name)
                if imported is not None:
                    imported.collect()
            else:
                local = alias.asname or alias.name
                bindings[local] = self.proof.expand(bindings.get(local))
                if bindings[local] in self.proof.provider_overrides:
                    bindings[local] = self.proof.provider_overrides[bindings[local]]

    def resolve_expr(self, expression, bindings):
        if (
            isinstance(expression, ast.Name)
            and expression.id == "object"
            and expression.id not in bindings
        ):
            return "builtins.object"
        qualified = self.proof.expand(_qualified(expression, bindings))
        if (
            isinstance(expression, ast.Attribute)
            and qualified in self.proof.provider_overrides
        ):
            return self.proof.provider_overrides[qualified]
        return qualified

    def _scan_assignment(self, statement, bindings, owner):
        value = getattr(statement, "value", None)
        resolved = self.resolve_expr(value, bindings)
        targets = []
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, ast.AnnAssign) and value is not None:
            targets = [statement.target]
        for target in targets:
            self._field_table_mutations(target, bindings)
            if isinstance(target, ast.Attribute):
                qualified = _qualified(target, bindings)
                if qualified:
                    self.proof.provider_overrides[qualified] = resolved
        super()._scan_assignment(statement, bindings, owner)
        if isinstance(value, (ast.Name, ast.Attribute)):
            for target in targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = resolved
        elif isinstance(value, ast.Call):
            constructor = self.resolve_expr(value.func, bindings)
            if constructor is not None and not self.proof.shadowed:
                for family, prefix in (
                    ("form", "django.forms."),
                    ("model", "django.db.models."),
                ):
                    if constructor.startswith(prefix) and (
                        constructor.rsplit(".", 1)[-1].endswith("Field")
                        or constructor.rsplit(".", 1)[-1] == "ForeignKey"
                    ):
                        for target in targets:
                            if isinstance(target, ast.Name):
                                bindings[target.id] = (
                                    "@django.field." + family + ":" + constructor
                                )

    def _field_table_mutations(self, expression, bindings):
        for node in _eager_nodes(expression):
            if isinstance(node, ast.Attribute) and node.attr in {
                "base_fields",
                "declared_fields",
            }:
                owner = self.resolve_expr(node.value, bindings)
                if owner is not None:
                    self.dynamic_fields.add(owner)

    def _calls(self, expression, bindings, *, routes=False):
        for node in _eager_nodes(expression):
            if isinstance(node, ast.Call):
                if not isinstance(node.func, ast.Attribute) or node.func.attr not in {
                    "get",
                    "keys",
                    "items",
                    "values",
                    "copy",
                    "__getitem__",
                    "__contains__",
                }:
                    self._field_table_mutations(node.func, bindings)
                for argument in (
                    *node.args,
                    *(keyword.value for keyword in node.keywords),
                ):
                    owner = self.resolve_expr(argument, bindings)
                    if owner is not None:
                        self.dynamic_fields.add(owner)
        super()._calls(expression, bindings, routes=routes)


class DjangoHookProof:
    def __init__(self, analyzer):
        self.defs = getattr(analyzer, "defs", {}) or {}
        self.classes = {}
        self.scanners = {}
        self.ancestry = {}
        self.fields = {}
        self.declared_fields = {}
        self.mros = {}
        self.provider_overrides = {}
        self.dynamic_fields = set()
        self.shadowed = False
        if not any(
            item.type == "import" and item.name.split(".", 1)[0] == "django"
            for item in self.defs.values()
        ):
            return
        root = Path(getattr(analyzer, "_project_root", ".")).resolve()
        if root.is_file():
            root = root.parent
        paths = set()
        for filename in {str(item.filename) for item in self.defs.values()}:
            path = Path(filename).resolve()
            if path.suffix in {".py", ".pyi"} and path.is_relative_to(root):
                paths.add(path)
        parsed = parse_python_files(sorted(paths))
        index = _DefinitionIndex(self.defs, parsed, root)
        self.shadowed = "django" in index.shadowed
        for module in parsed:
            scanner = _HookScanner(self, index, module)
            self.scanners[scanner.evidence.module] = scanner
        for scanner in self.scanners.values():
            scanner.collect()
        for scanner in self.scanners.values():
            self.dynamic_fields.update(scanner.dynamic_fields)
            for name, info in scanner.evidence.classes.items():
                self.classes[name] = (*info, scanner)

    def expand(self, qualified, seen=()):
        if qualified is None or qualified in seen or len(seen) > 24:
            return qualified
        module, _, member = qualified.rpartition(".")
        scanner = self.scanners.get(module)
        if scanner is None:
            return qualified
        scanner.collect()
        if member not in scanner.bindings:
            return qualified
        value = scanner.bindings[member]
        if value == qualified:
            return qualified
        return self.expand(value, (*seen, qualified))

    def owner(self, definition):
        if definition.type == "class":
            return definition.name
        name = definition.name
        while "." in name:
            name = name.rpartition(".")[0]
            if name in self.classes:
                return name
        return None

    def status(self, name, family, active=()):
        key = name, family
        if key in self.ancestry:
            return self.ancestry[key]
        if name is None or name in active or len(active) > 32:
            return None
        if name in _BASES[family]:
            if self.shadowed:
                return False
            return True
        if name == "builtins.object":
            return False
        info = self.classes.get(name)
        if info is None:
            if any(name in bases for bases in _BASES.values()):
                return False
            return None
        definition, bases, _members, _bindings, _scanner = info
        node = definition.node
        if node.decorator_list or node.keywords:
            return None
        states = [self.status(base, family, (*active, name)) for base in bases]
        value = False
        if True in states:
            value = True
        elif None in states:
            value = None
        self.ancestry[key] = value
        return value

    def _model_form(self, name, active=()):
        if name in _MODEL_FORMS:
            return True
        if name in active or name not in self.classes:
            return False
        return any(
            self._model_form(base, (*active, name)) for base in self.classes[name][1]
        )

    def _literal_names(self, node):
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            if all(
                isinstance(item, ast.Constant) and isinstance(item.value, str)
                for item in node.elts
            ):
                return {item.value for item in node.elts}
        return None

    def _mro(self, name, active=()):
        if name in self.mros:
            return self.mros[name]
        if name is None or name in active or len(active) > 32:
            return None
        if name not in self.classes:
            return [name]
        bases = self.classes[name][1]
        sequences = []
        for base in bases:
            result = self._mro(base, (*active, name))
            if result is None:
                return None
            sequences.append(list(result))
        sequences.append(list(bases))
        merged = _merge_c3_mro(sequences)
        if merged is None:
            return None
        result = [name, *merged]
        self.mros[name] = result
        return result

    def _meta(self, name):
        lineage = self._mro(name)
        if lineage is None:
            return {}, False
        meta = None
        for owner in lineage:
            if owner in self.classes and "Meta" in self.classes[owner][2]:
                name = owner
                meta = self.classes[owner][2]["Meta"]
                break
        if not isinstance(meta, ast.ClassDef):
            return {}, False
        values = {}
        for statement in meta.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        values[target.id] = statement.value
        if "model" in values:
            scanner = self.classes[name][4]
            bindings = scanner.class_bindings.get(name, {})
            values["__model_reference__"] = scanner.resolve_expr(
                values["model"], bindings
            )
        return values, not (meta.bases or meta.decorator_list or meta.keywords)

    def _field_provider(self, name, family, active=()):
        if name is None or name in active or len(active) > 32:
            return None
        if name in self.classes:
            values = [
                self._field_provider(base, family, (*active, name))
                for base in self.classes[name][1]
            ]
            if True in values:
                return True
            if None in values:
                return None
            return False
        if name.startswith(("django.forms.", "django.db.models.")) and (
            name.rsplit(".", 1)[-1].endswith("Field")
            or name.rsplit(".", 1)[-1] == "ForeignKey"
        ):
            prefix = "django.forms."
            if family == "model":
                prefix = "django.db.models."
            return name.startswith(prefix) and not self.shadowed
        if name == "builtins.object":
            return False
        if any(name in bases for bases in _BASES.values()):
            return False
        return None

    def _declared_fields(self, name):
        definition, _bases, _members, _model_bindings, scanner = self.classes[name]
        fields = set()
        removed = set()
        known = not (definition.node.decorator_list or definition.node.keywords)
        if name in self.dynamic_fields:
            known = False
        bindings = scanner.class_bindings.get(name, {}).copy()
        family = "form"
        if self.status(name, "model") is True:
            family = "model"
        for statement in definition.node.body:
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                if statement.name == "__init__":
                    known = False
                fields.discard(statement.name)
                removed.discard(statement.name)
                bindings[statement.name] = None
                continue
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                scanner._imports(statement, bindings)
                for alias in statement.names:
                    bound = alias.asname or alias.name.split(".", 1)[0]
                    fields.discard(bound)
                    removed.discard(bound)
                continue
            targets = []
            value = None
            if isinstance(statement, ast.Assign):
                targets = statement.targets
                value = statement.value
            elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                targets = [statement.target]
                value = statement.value
            elif isinstance(statement, (ast.If, ast.Try, ast.For, ast.While, ast.With)):
                known = False
            for target in targets:
                if not isinstance(target, ast.Name):
                    known = False
                    continue
                if target.id in {"base_fields", "declared_fields"}:
                    known = False
                fields.discard(target.id)
                removed.discard(target.id)
                resolved = scanner.resolve_expr(value, bindings)
                if isinstance(value, ast.Constant) and value.value is None:
                    removed.add(target.id)
                elif isinstance(value, ast.Call):
                    provider = scanner.resolve_expr(value.func, bindings)
                    status = self._field_provider(provider, family)
                    if status is True:
                        resolved = "@django.field." + family + ":" + provider
                        editable = True
                        if family == "model":
                            if provider.rsplit(".", 1)[-1] in {
                                "AutoField",
                                "BigAutoField",
                                "SmallAutoField",
                            }:
                                editable = False
                            for keyword in value.keywords:
                                if keyword.arg == "editable":
                                    if isinstance(keyword.value, ast.Constant):
                                        editable = bool(keyword.value.value)
                                    else:
                                        known = False
                        if editable:
                            fields.add(target.id)
                    elif status is None:
                        known = False
                elif isinstance(value, (ast.Name, ast.Attribute)):
                    if resolved and resolved.startswith(
                        "@django.field." + family + ":"
                    ):
                        fields.add(target.id)
                    elif not resolved or not resolved.startswith("@django.field."):
                        known = False
                bindings[target.id] = resolved
        return fields, removed, known

    def _form_declarations(self, name, active=()):
        if name in self.declared_fields:
            return self.declared_fields[name]
        if name in active or len(active) > 32:
            return set(), False
        lineage = self._mro(name)
        if lineage is None:
            return set(), False
        fields = set()
        known = True
        for owner in reversed(lineage):
            if owner not in self.classes:
                if owner not in _BASES["form"] | {"builtins.object"}:
                    known = False
                continue
            declared, removed, complete = self._declared_fields(owner)
            known = known and complete
            if owner == name:
                fields.update(declared)
            elif self.status(owner, "form") is True:
                inherited, inherited_complete = self._form_declarations(
                    owner, (*active, name)
                )
                fields.update(inherited)
                known = known and inherited_complete
            fields.difference_update(removed)
        self.declared_fields[name] = fields, known
        return fields, known

    def field_set(self, name, active=()):
        if name in self.fields:
            return self.fields[name]
        if name in active or len(active) > 32:
            return set(), False
        info = self.classes.get(name)
        if info is None:
            if name in _BASES["form"] | _BASES["model"] or name == "builtins.object":
                return set(), True
            return set(), False
        lineage = self._mro(name)
        if lineage is None:
            return set(), False
        fields = set()
        known = True
        if self.status(name, "form") is True:
            fields, known = self._form_declarations(name)
            fields = set(fields)
        else:
            for owner in reversed(lineage):
                if owner not in self.classes:
                    if owner not in _BASES["model"] | {"builtins.object"}:
                        known = False
                    continue
                declared, removed, complete = self._declared_fields(owner)
                fields.update(declared)
                fields.difference_update(removed)
                known = known and complete
        if self._model_form(name):
            meta, complete = self._meta(name)
            selected = meta.get("fields")
            excluded = self._literal_names(meta.get("exclude"))
            selected_names = self._literal_names(selected)
            generated = set()
            if selected_names is not None:
                generated.update(selected_names)
                # A literal selection bounds generated fields even when the
                # model itself lives outside the scanned project.
                known = known and complete
            elif isinstance(selected, ast.Constant) and selected.value == "__all__":
                model_fields, model_complete = self.field_set(
                    meta.get("__model_reference__"), (*active, name)
                )
                generated = set(model_fields)
                known = known and complete and model_complete
            else:
                known = False
            if excluded:
                generated.difference_update(excluded)
            fields.update(generated)
        self.fields[name] = fields, known
        return fields, known


def _proof(analyzer):
    if analyzer is None:
        return None
    definitions = getattr(analyzer, "defs", {}) or {}
    proof = getattr(analyzer, "_django_hook_proof", None)
    if proof is None or proof.defs is not definitions:
        proof = DjangoHookProof(analyzer)
        analyzer._django_hook_proof = proof
    return proof


def django_hook_ancestry(definition, analyzer, family):
    proof = _proof(analyzer)
    if proof is None:
        return None
    return proof.status(proof.owner(definition), family)


def django_method_hook(definition, analyzer):
    """A shared family name does not make every method a Django protocol."""
    proof = _proof(analyzer)
    if proof is None:
        return None
    owner = proof.owner(definition)
    states = [
        proof.status(owner, family)
        for family in _METHOD_ROLES.get(definition.simple_name, ())
    ]
    if True in states:
        return True
    if None in states:
        return None
    return False


def django_clean_field(definition, analyzer):
    proof = _proof(analyzer)
    if proof is None:
        return None
    name = proof.owner(definition)
    if proof.status(name, "form") is not True:
        return None
    fields, complete = proof.field_set(name)
    field = definition.simple_name.removeprefix("clean_")
    if field in fields:
        return True
    if complete:
        return False
    return None
