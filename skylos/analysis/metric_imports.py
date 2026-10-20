"""Conservative, lexical import identities for source metric evidence.

This proves unchanged module imports, including equivalent compatibility
branches. Rebinding and mixed providers remain unknown; spelling is not proof.
"""

import ast
from collections import Counter, defaultdict

from skylos.rules.quality._receivers import _parameters, _scope_bindings
from skylos.rules.quality._provider_context import project_local_provider


class MetricImports:
    def __init__(self, module, providers, *, filename=None, project_root=None):
        self.module = module
        self.parents = {
            child: parent
            for parent in ast.walk(module)
            for child in ast.iter_child_nodes(parent)
        }
        providers = {
            provider: symbols
            for provider, symbols in providers.items()
            if not project_local_provider(
                provider, filename=filename, project_root=project_root
            )
        }
        self.candidates = {}
        self.bound = {}
        self.outside = {}
        self.nonlocals = {}
        module_bindings = _scope_bindings(module)
        owned = []
        pending = list(module.body)
        while pending:
            node = pending.pop()
            owned.append(node)
            if not isinstance(
                node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                pending.extend(ast.iter_child_nodes(node))
        wildcard = any(
            isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names)
            for node in owned
        )
        identities = defaultdict(set)
        import_counts = Counter()

        def add_import(local, provider):
            # typing_extensions supplies these same typing contracts on older
            # Python versions; either compatibility branch proves their role.
            if provider.startswith("typing_extensions."):
                provider = "typing." + provider.partition(".")[2]
            identities[local].add(provider)
            import_counts[local] += 1

        if not wildcard:
            for statement in owned:
                if isinstance(statement, ast.ImportFrom) and not statement.level:
                    for alias in statement.names:
                        if alias.name in providers.get(statement.module, ()):
                            local = alias.asname or alias.name
                            add_import(local, f"{statement.module}.{alias.name}")
                elif isinstance(statement, ast.Import):
                    for alias in statement.names:
                        if alias.name in providers:
                            local = alias.asname or alias.name
                            add_import(local, alias.name)
        self.candidates = {
            local: next(iter(providers))
            for local, providers in identities.items()
            if len(providers) == 1
            and module_bindings.counts[local] == import_counts[local]
        }

        function_scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
        comprehension_scopes = (
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
            ast.GeneratorExp,
        )
        self.function_scopes = function_scopes + comprehension_scopes
        for node in ast.walk(module):
            if isinstance(node, (ast.Module, ast.ClassDef, *function_scopes)):
                if isinstance(node, ast.Lambda):
                    names = _parameters(node)
                    nonlocals = set()
                else:
                    bindings = _scope_bindings(node)
                    names = set(bindings.names)
                    nonlocals = bindings.nonlocals
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        names.update(_parameters(node))
                        # An explicitly writable module import is not stable.
                        for child in ast.walk(node):
                            if isinstance(child, ast.Global):
                                for name in child.names:
                                    if bindings.counts[name]:
                                        self.candidates.pop(name, None)
                self.bound[node] = names
                self.nonlocals[node] = nonlocals
                header = []
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                ):
                    header.extend(node.args.defaults)
                    header.extend(
                        value for value in node.args.kw_defaults if value is not None
                    )
                    if not isinstance(node, ast.Lambda):
                        header.extend(node.decorator_list)
                        header.extend(
                            a.annotation
                            for a in [
                                *node.args.posonlyargs,
                                *node.args.args,
                                *node.args.kwonlyargs,
                            ]
                            if a.annotation is not None
                        )
                        if node.returns is not None:
                            header.append(node.returns)
                elif isinstance(node, ast.ClassDef):
                    header.extend([*node.bases, *node.decorator_list])
                    header.extend(keyword.value for keyword in node.keywords)
                self.outside[node] = {
                    child for value in header for child in ast.walk(value)
                }
            elif isinstance(node, comprehension_scopes):
                self.bound[node] = {
                    child.id
                    for generator in node.generators
                    for child in ast.walk(generator.target)
                    if isinstance(child, ast.Name)
                }
                self.outside[node] = set(ast.walk(node.generators[0].iter))

        # An explicit write to a provider object destroys its imported identity.
        for node in ast.walk(module):
            target = None
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                target = node.value
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and node.args
            ):
                target = node.args[0]
            while isinstance(target, ast.Attribute):
                target = target.value
            if isinstance(target, ast.Name):
                self.candidates.pop(target.id, None)

    def resolve(self, expression):
        while isinstance(expression, ast.Subscript):
            expression = expression.value
        parts = []
        root = expression
        while isinstance(root, ast.Attribute):
            parts.append(root.attr)
            root = root.value
        if not isinstance(root, ast.Name) or root.id not in self.candidates:
            return None
        scope = self.parents.get(root)
        in_function = False
        while scope is not None:
            if scope in self.bound:
                if root in self.outside.get(scope, ()):
                    scope = self.parents.get(scope)
                    continue
                if scope is self.module:
                    provider = self.candidates[root.id]
                    return ".".join([provider, *reversed(parts)])
                if isinstance(scope, self.function_scopes):
                    in_function = True
                if not (in_function and isinstance(scope, ast.ClassDef)):
                    if root.id in self.bound[
                        scope
                    ] and root.id not in self.nonlocals.get(scope, ()):
                        return None
            scope = self.parents.get(scope)
        return None
