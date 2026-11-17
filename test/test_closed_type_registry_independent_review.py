"""Semantic falsifiers for source-only negative registry proofs.

Fixtures are parsed into ASTs and interpreted as bounded abstract data. None of
this target source is imported or executed.
"""

import ast
from types import SimpleNamespace

from skylos.deadcode.closed_type_registries import closed_type_registry_unused
from test.fixture_paths import write_fixture

ROUTER = """class Router:
    def __init__(self):
        self.handlers = {}

    def register(self, kind):
        def attach(callback):
            self.handlers[kind] = callback
            return callback
        return attach

    def deliver(self, value):
        for kind in type(value).__mro__:
            callback = self.handlers.get(kind)
            if callback is not None:
                return callback(value)
        return None
"""


def negative_names(root, body, *, routes_extra="", imports=""):
    imports = ("from routes import " + imports + "\n") if imports else ""
    app = (
        """from routes import Router

def run():
    router = Router()

    @router.register(int)
    def number_handler(value):
        return 1

    @router.register(str)
    def text_handler(value):
        return 2

"""
        + "\n".join("    " + line for line in body.splitlines())
        + "\n\nrun()\n"
    )
    write_fixture(
        root,
        (root / "routes.py").relative_to(root),
        ROUTER + routes_extra,
        overwrite=True,
    )
    write_fixture(
        root, (root / "app.py").relative_to(root), imports + app, overwrite=True
    )
    definitions = {}
    for path in (root / "routes.py", root / "app.py"):
        tree = ast.parse(path.read_text())
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                continue
            kind = (
                "class"
                if isinstance(node, ast.ClassDef)
                else (
                    "method"
                    if isinstance(parents.get(node), ast.ClassDef)
                    else "function"
                )
            )
            key = f"{path}:{node.lineno}"
            definitions[key] = SimpleNamespace(
                filename=path,
                line=node.lineno,
                node=node,
                type=kind,
                name=f"{path.stem}.{node.name}",
                simple_name=node.name,
                heuristic_refs={},
                is_exported=False,
            )
    unused = closed_type_registry_unused(definitions, list(root.glob("*.py")), root)
    return {definitions[key].simple_name for key in unused}


def test_bool_dispatch_reaches_integer_base_handler_and_retains_dead_control(tmp_path):
    unused = negative_names(tmp_path, "print(router.deliver(True))")
    assert "number_handler" not in unused  # bool.__mro__ includes int
    assert "text_handler" in unused


def test_custom_hash_lookup_can_invoke_handler_and_requires_abstention(tmp_path):
    unused = negative_names(
        tmp_path,
        """class HashKey:
    def __hash__(self):
        number_handler(1)
        return 17
router.handlers.get(HashKey())
print(router.deliver("text"))""",
    )
    assert unused == set()


def test_output_container_can_execute_custom_repr_and_requires_abstention(tmp_path):
    unused = negative_names(
        tmp_path,
        """class Display:
    def __repr__(self):
        number_handler(1)
        return "shown"
print([Display()])
print(router.deliver("text"))""",
    )
    assert unused == set()


def test_class_decorator_calls_are_not_silently_ignored(tmp_path):
    unused = negative_names(
        tmp_path,
        """def activate(cls):
    number_handler(1)
    return cls
@activate
class Marker:
    pass
print(router.deliver("text"))""",
    )
    assert unused == set()


def test_class_keyword_body_is_not_silently_ignored(tmp_path):
    unused = negative_names(
        tmp_path,
        """class Marker(metaclass=type):
    number_handler(1)
print(router.deliver("text"))""",
    )
    assert unused == set()


def test_implicit_subclass_hook_calls_are_not_silently_ignored(tmp_path):
    unused = negative_names(
        tmp_path,
        """class Parent:
    def __init_subclass__(cls):
        number_handler(1)
class Child(Parent):
    pass
print(router.deliver("text"))""",
    )
    assert unused == set()


def test_discarded_user_operator_effect_is_not_silently_ignored(tmp_path):
    unused = negative_names(
        tmp_path,
        """class Effect:
    def __neg__(self):
        number_handler(1)
        return 0
-Effect()
print(router.deliver("text"))""",
    )
    assert unused == set()


def test_discarded_comprehension_calls_are_not_silently_ignored(tmp_path):
    unused = negative_names(
        tmp_path,
        """[number_handler(value) for value in (1,)]
print(router.deliver("text"))""",
    )
    assert unused == set()


def test_effectful_function_annotation_is_not_silently_ignored(tmp_path):
    unused = negative_names(
        tmp_path,
        """def annotated(value: number_handler(1)):
    return None
print(router.deliver("text"))""",
    )
    assert unused == set()


def test_implicit_destructor_calls_are_not_silently_ignored(tmp_path):
    unused = negative_names(
        tmp_path,
        """class Effect:
    def __del__(self):
        number_handler(1)
Effect()
print(router.deliver("text"))""",
    )
    assert unused == set()


def test_runtime_base_mutation_cannot_reuse_source_declared_mro(tmp_path):
    unused = negative_names(
        tmp_path,
        """@router.register(Other)
def selected_after_rebase(value):
    return 3
Child.__bases__ = (Other,)
print(router.deliver(Child()))""",
        routes_extra="""
class Parent:
    pass
class Other:
    pass
class Child(Parent):
    pass
""",
        imports="Parent, Other, Child",
    )
    assert unused == set()


def test_later_trace_evidence_revokes_cached_negative_registry_proof(tmp_path):
    import json

    from skylos.analyzer import Skylos

    negative_names(tmp_path, 'print(router.deliver("text"))')
    scanner = Skylos()
    initial = json.loads(scanner.analyze(str(tmp_path), thr=60, grep_verify=False))
    assert any(
        item["simple_name"] == "number_handler"
        for item in initial.get("unused_functions", [])
    )
    target_key, target = next(
        (key, definition)
        for key, definition in scanner.defs.items()
        if definition.simple_name == "number_handler"
    )
    reachability = scanner._python_reachability_report
    assert target_key in reachability.unreachable_keys
    target.heuristic_refs["trace_hit"] = 1.0
    reachability.refresh(scanner.defs)
    assert target_key not in reachability.unreachable_keys
    assert target.references > 0


def test_class_base_identity_survives_later_name_rebinding(tmp_path):
    unused = negative_names(
        tmp_path,
        """@router.register(OldParent)
def selected_original_base(value):
    return 3
print(router.deliver(Child()))""",
        routes_extra="""\nclass Parent:
    pass
OldParent = Parent
class Other:
    pass
class Child(Parent):
    pass
Parent = Other
""",
        imports="OldParent, Child",
    )
    assert "selected_original_base" not in unused
    assert "text_handler" in unused


def test_literal_identity_does_not_assume_ast_and_compiler_share_constants(tmp_path):
    unused = negative_names(
        tmp_path,
        """if 1000 is 1000:
    number_handler(1)
print(router.deliver("text"))""",
    )
    assert unused == set()
