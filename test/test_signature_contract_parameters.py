import json

from skylos.analyzer import analyze


def _analyze_sources(tmp_path, sources):
    for filename, source in sources.items():
        (tmp_path / filename).write_text(  # skylos: ignore[SKY-D324] pytest tmp_path with literal filenames
            source,
            encoding="utf-8",
        )

    return json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))


def _unused_parameters(tmp_path, sources):
    result = _analyze_sources(tmp_path, sources)
    return {finding["full_name"] for finding in result["unused_parameters"]}


def test_issue_723_signature_contract_shapes_keep_only_controls(tmp_path):
    unused = _unused_parameters(
        tmp_path,
        {
            "contracts.py": '''
from abc import ABC, abstractmethod
import typing


def pytest_addhooks(pluginmanager):
    """Called to register additional hook specifications."""


class ParamType:
    def get_metavar(self, param, ctx):
        """Return the metavar for this parameter."""


class ChoiceType(ParamType):
    def get_metavar(self, param, ctx):
        return f"{param}:{ctx}"


class BaseType(ABC):
    @abstractmethod
    def completion(self, manager, prefix):
        """Return completion candidates."""


class BoolType(BaseType):
    def completion(self, manager, prefix):
        return ["false", "true"]


class MarkdownElement:
    @classmethod
    def create(cls, markdown, token):
        return cls()


class Heading(MarkdownElement):
    @classmethod
    def create(cls, markdown, token):
        return cls(markdown, token)


class RootVisitor:
    def visit(self, node, **kwargs):
        getattr(self, f"visit_{type(node).__name__}")(node, **kwargs)

    def visit_AssignBlock(self, node, **kwargs):
        for child in node.body:
            self.visit(child)

    def visit_CallBlock(self, node, **kwargs):
        for child in node.body:
            self.visit(child, depth=kwargs.get("depth", 0) + 1)


class BaseModel:
    def model_dump(self, **kwargs):
        return dict(kwargs)


class RootModel(BaseModel):
    if typing.TYPE_CHECKING:
        def model_dump(self, *, mode="python", include=None):
            """Sharpen the inherited return type for static type checkers."""


def render(text, unused_width):
    return text.upper()


class Formatter:
    def format_value(self, value, unused_precision):
        return value.strip()
''',
        },
    )

    assert unused == {
        "contracts.render.unused_width",
        "contracts.Formatter.format_value.unused_precision",
    }


def test_signature_stub_detection_is_narrow(tmp_path):
    result = _analyze_sources(
        tmp_path,
        {
            "stubs.py": '''
def docstring_only(contract_arg):
    """Interface declaration."""


def bare_pass(contract_arg):
    pass


def docstring_and_pass(contract_arg):
    """Interface declaration."""
    pass


def docstring_and_ellipsis(contract_arg):
    """Interface declaration."""
    ...


def bare_ellipsis(contract_arg):
    ...


def bare_not_implemented(contract_arg):
    raise NotImplementedError


def raises_not_implemented(contract_arg):
    """Interface declaration."""
    raise NotImplementedError("implemented by adapters")


def raises_qualified_not_implemented(contract_arg):
    """Interface declaration."""
    raise errors.NotImplementedError


def concrete_return(real_unused):
    """A concrete body still gets normal parameter analysis."""
    return None


def different_raise(real_unused):
    raise ValueError("not an interface placeholder")


def multiple_placeholders(real_unused):
    pass
    ...
''',
        },
    )
    unused = {
        finding["full_name"] for finding in result["unused_parameters"]
    }
    unused_functions = {
        finding["full_name"] for finding in result["unused_functions"]
    }

    assert unused == {
        "stubs.bare_pass.contract_arg",
        "stubs.concrete_return.real_unused",
        "stubs.different_raise.real_unused",
        "stubs.multiple_placeholders.real_unused",
    }
    assert "stubs.bare_pass" in unused_functions


def test_type_checking_contract_scope_and_shadowing(tmp_path):
    unused = _unused_parameters(
        tmp_path,
        {
            "type_contracts.py": '''
from typing import TYPE_CHECKING, TYPE_CHECKING as TC
import typing as t

runtime_flag = True

if TC:
    def alias_type_only(unused):
        return None
else:
    def runtime_else(unused):
        return None

if t.TYPE_CHECKING:
    def module_type_only(unused):
        return None

if not TC:
    def runtime_not_guard(unused):
        return None

TYPE_CHECKING = runtime_flag
if TYPE_CHECKING:
    def shadowed_guard(unused):
        return None

def runtime_sibling(unused):
    return None


def outer():
    if TC:
        def nested_type_only(unused):
            return None


def locally_shadowed():
    if TC:
        def nested_runtime(unused):
            return None
    TC = runtime_flag


def local_import():
    from typing import TYPE_CHECKING as LOCAL_TC
    if LOCAL_TC:
        def nested_local_type_only(unused):
            return None


CLASS_TC = runtime_flag


class ClassLocalAlias:
    from typing import TYPE_CHECKING as CLASS_TC

    def method(self):
        if CLASS_TC:
            def nested_runtime(unused):
                return None


NESTED_TC = runtime_flag


class OuterClassLocalAlias:
    from typing import TYPE_CHECKING as NESTED_TC

    class Inner:
        if NESTED_TC:
            def nested_runtime(unused):
                return None


def guarded_in_compounds(items, manager, value):
    try:
        if TC:
            def nested_try_type_only(unused):
                return None
    finally:
        pass

    for item in items:
        if TC:
            def nested_for_type_only(unused):
                return None

    while value:
        if TC:
            def nested_while_type_only(unused):
                return None
        break

    with manager:
        if TC:
            def nested_with_type_only(unused):
                return None

    match value:
        case _:
            if TC:
                def nested_match_type_only(unused):
                    return None


def comprehension_target_does_not_shadow(items):
    [item for TC in items]
    if TC:
        def nested_type_only(unused):
            return None


from typing import TYPE_CHECKING as CONDITIONAL_TC

if runtime_flag:
    import runtime_config as CONDITIONAL_TC

if CONDITIONAL_TC:
    def conditionally_shadowed(unused):
        return None


from typing import TYPE_CHECKING as TRY_TC

try:
    import runtime_config as TRY_TC
    raise RuntimeError
except RuntimeError:
    if TRY_TC:
        def try_shadowed(unused):
            return None


from typing import TYPE_CHECKING as LATE_TC


def module_late_rebind():
    if LATE_TC:
        def nested_runtime(unused):
            return None


LATE_TC = runtime_flag


def local_late_rebind():
    from typing import TYPE_CHECKING as LOCAL_LATE_TC

    def inner():
        if LOCAL_LATE_TC:
            def nested_runtime(unused):
                return None

    LOCAL_LATE_TC = runtime_flag
''',
        },
    )

    assert "type_contracts.alias_type_only.unused" not in unused
    assert "type_contracts.module_type_only.unused" not in unused
    assert "type_contracts.runtime_else.unused" in unused
    assert "type_contracts.runtime_not_guard.unused" in unused
    assert "type_contracts.shadowed_guard.unused" in unused
    assert "type_contracts.runtime_sibling.unused" in unused
    assert (
        "type_contracts.outer.nested_type_only.unused" not in unused
    )
    assert (
        "type_contracts.locally_shadowed.nested_runtime.unused" in unused
    )
    assert (
        "type_contracts.local_import.nested_local_type_only.unused" not in unused
    )
    assert (
        "type_contracts.ClassLocalAlias.method.nested_runtime.unused" in unused
    )
    assert "type_contracts.Inner.nested_runtime.unused" in unused
    for nested_name in (
        "nested_try_type_only",
        "nested_for_type_only",
        "nested_while_type_only",
        "nested_with_type_only",
        "nested_match_type_only",
    ):
        assert (
            f"type_contracts.guarded_in_compounds.{nested_name}.unused"
            not in unused
        )
    assert (
        "type_contracts.comprehension_target_does_not_shadow."
        "nested_type_only.unused"
        not in unused
    )
    assert "type_contracts.conditionally_shadowed.unused" in unused
    assert "type_contracts.try_shadowed.unused" in unused
    assert (
        "type_contracts.module_late_rebind.nested_runtime.unused" in unused
    )
    assert (
        "type_contracts.local_late_rebind.inner.nested_runtime.unused" in unused
    )


def test_only_shared_parameters_of_resolved_overrides_are_contracts(tmp_path):
    unused = _unused_parameters(
        tmp_path,
        {
            "base.py": '''
class Parent:
    def render(self, value, shared_option=None):
        return value

    def variadic(self, *items, **options):
        return None

    @staticmethod
    def convert(value, shared_option=None):
        return value
''',
            "mid.py": '''
from base import Parent


class Mid(Parent):
    pass
''',
            "children.py": '''
from base import Parent
from mid import Mid


class Child(Mid):
    def render(self, value, shared_option=None, child_only=None):
        return value

    def variadic(self, *args, **kwargs):
        return None

    def convert(self, value, shared_option=None):
        return value


class RenamedChild(Parent):
    def render(self, value, renamed_option=None):
        return value


class Unrelated:
    def render(self, value, shared_option=None):
        return value


class PrivateBase:
    def __secret(self, private_unused=None):
        return None


class PrivateChild(PrivateBase):
    def __secret(self, private_unused=None):
        return None


def replacement(*args, **kwargs):
    return None


class ShadowedOverride(Parent):
    def render(self, value, shared_option=None):
        return value

    render = replacement
''',
            "generic_child.py": '''
from base import Parent


class GenericChild(Parent[int]):
    def render(self, value, shared_option=None):
        return value
''',
            "alias_child.py": '''
import base as b


class AliasChild(b.Parent):
    def render(self, value, shared_option=None):
        return value
''',
            "external_parent.py": '''
class Parent:
    def render(self, value, shared_option=None):
        return value
''',
            "shadowed_parent.py": '''
from external_parent import Parent


class Parent:
    def render(self, value, local_option=None):
        return value


class Child(Parent):
    def render(self, value, shared_option=None):
        return value
''',
            "external_attr.py": '''
class Parent:
    def render(self, value, shared_option=None):
        return value
''',
            "shadowed_attr.py": '''
import external_attr as namespace

namespace = object()


class Child(namespace.Parent):
    def render(self, value, shared_option=None):
        return value
''',
            "reverse_external.py": '''
class Parent:
    def render(self, value, shared_option=None):
        return value
''',
            "reverse_binding.py": '''
class Parent:
    def render(self, value, local_option=None):
        return value


from reverse_external import Parent


class Child(Parent):
    def render(self, value, shared_option=None):
        return value
''',
        },
    )

    assert "base.Parent.render.shared_option" not in unused
    assert "children.Child.render.shared_option" not in unused
    assert "children.Child.render.child_only" in unused
    assert "base.Parent.variadic.items" not in unused
    assert "base.Parent.variadic.options" not in unused
    assert "children.Child.variadic.args" not in unused
    assert "children.Child.variadic.kwargs" not in unused
    assert "base.Parent.convert.shared_option" in unused
    assert "children.Child.convert.shared_option" in unused
    assert "children.RenamedChild.render.renamed_option" in unused
    assert "children.Unrelated.render.shared_option" in unused
    assert "generic_child.GenericChild.render.shared_option" not in unused
    assert "alias_child.AliasChild.render.shared_option" not in unused
    assert "children.PrivateChild.__secret.private_unused" in unused
    assert "children.ShadowedOverride.render.shared_option" in unused
    assert "external_parent.Parent.render.shared_option" in unused
    assert "shadowed_parent.Parent.render.local_option" in unused
    assert "shadowed_parent.Child.render.shared_option" in unused
    assert "external_attr.Parent.render.shared_option" in unused
    assert "shadowed_attr.Child.render.shared_option" in unused
    assert "reverse_external.Parent.render.shared_option" not in unused
    assert "reverse_binding.Parent.render.local_option" in unused
    assert "reverse_binding.Child.render.shared_option" not in unused


def test_dynamic_dispatch_only_exempts_forwarded_handler_kwargs(tmp_path):
    unused = _unused_parameters(
        tmp_path,
        {
            "visitors.py": '''
class DynamicVisitor:
    def visit(self, node, **kwargs):
        getattr(self, f"visit_{type(node).__name__}")(node, **kwargs)

    def visit_Item(self, node, extra=None, **kwargs):
        return node


class DifferentlyNamedKwargs:
    def visit(self, node, **options):
        getattr(self, f"visit_{type(node).__name__}")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node


class SuffixedDispatcher:
    def visit(self, node, **options):
        getattr(self, f"visit_{type(node).__name__}_impl")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node

    def visit_Item_impl(self, node, **kwargs):
        return node


class NoDispatcher:
    def visit_Item(self, node, **kwargs):
        return node


class NoForwarding:
    def visit(self, node, **kwargs):
        getattr(self, f"visit_{type(node).__name__}")(node)

    def visit_Item(self, node, **kwargs):
        return node


class LiteralLookup:
    def visit(self, node, **kwargs):
        getattr(self, "visit_Item")(node, **kwargs)

    def visit_Item(self, node, **kwargs):
        return node


class ConstantFormattedLookup:
    def visit(self, node, **kwargs):
        getattr(self, f"visit_{'Item'}")(node, **kwargs)

    def visit_Item(self, node, **kwargs):
        return node

    def visit_Other(self, node, **kwargs):
        return node


class ConvertedLookup:
    def visit(self, node, **options):
        getattr(self, f"visit_{type(node).__name__!r}")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node


class ShadowedGetattr:
    def visit(self, node, **options):
        def getattr(obj, name):
            return lambda *args, **kwargs: None
        getattr(self, f"visit_{type(node).__name__}")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node


class ComprehensionTarget:
    def visit(self, node, **options):
        [item for getattr in ()]
        getattr(self, f"visit_{type(node).__name__}")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node


class WrongReceiver:
    def visit(self, node, **options):
        getattr(registry, f"visit_{type(node).__name__}")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node


class StaticReceiver:
    @staticmethod
    def visit(node, **options):
        getattr(self, f"visit_{type(node).__name__}")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node


class BaseDispatcher:
    def visit(self, node, **options):
        getattr(self, f"visit_{type(node).__name__}")(node, **options)


class InheritedHandler(BaseDispatcher):
    def visit_Item(self, node, **kwargs):
        return node


class BaseHandler:
    def visit_Item(self, node, **kwargs):
        return node


class InheritedDispatcher(BaseHandler):
    def visit(self, node, **options):
        getattr(self, f"visit_{type(node).__name__}")(node, **options)


class OverridesDispatcher(BaseDispatcher):
    def visit(self, node, **options):
        return node

    def visit_Item(self, node, **kwargs):
        return node


def runtime_dispatch(node, **options):
    return node


class AttributeOverride(BaseDispatcher):
    visit = runtime_dispatch

    def visit_Item(self, node, **kwargs):
        return node


class HeaderShadow(BaseDispatcher):
    def helper(self, option=(visit := runtime_dispatch)):
        return option

    def visit_Item(self, node, **kwargs):
        return node


class PlainDispatcher:
    def visit(self, node, **options):
        return node


class StaticFirst(PlainDispatcher, BaseDispatcher):
    def visit_Item(self, node, **kwargs):
        return node


class DynamicFirst(BaseDispatcher, PlainDispatcher):
    def visit_Item(self, node, **kwargs):
        return node


def make_base():
    return PlainDispatcher


class UnknownFirst(make_base(), BaseDispatcher):
    def visit_Item(self, node, **kwargs):
        return node


class NestedDispatcherOnly:
    def helper(self):
        def nested(node, **options):
            getattr(self, f"visit_{type(node).__name__}")(node, **options)
        return nested

    def visit_Item(self, node, **kwargs):
        return node
''',
            "shadowed_builtin.py": '''
def getattr(obj, name):
    return lambda *args, **kwargs: None


class ShadowedBuiltin:
    def visit(self, node, **options):
        getattr(self, f"visit_{type(node).__name__}")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node
''',
            "imported_getattr.py": '''
from helpers import getattr


class ImportedGetattr:
    def visit(self, node, **options):
        getattr(self, f"visit_{type(node).__name__}")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node
''',
            "aliased_getattr.py": '''
import helpers as getattr


class AliasedGetattr:
    def visit(self, node, **options):
        getattr(self, f"visit_{type(node).__name__}")(node, **options)

    def visit_Item(self, node, **kwargs):
        return node
''',
        },
    )

    assert "visitors.DynamicVisitor.visit_Item.kwargs" not in unused
    assert "visitors.DynamicVisitor.visit_Item.extra" in unused
    assert "visitors.DifferentlyNamedKwargs.visit_Item.kwargs" not in unused
    assert "visitors.SuffixedDispatcher.visit_Item.kwargs" in unused
    assert "visitors.SuffixedDispatcher.visit_Item_impl.kwargs" not in unused
    assert "visitors.NoDispatcher.visit_Item.kwargs" in unused
    assert "visitors.NoForwarding.visit.kwargs" in unused
    assert "visitors.NoForwarding.visit_Item.kwargs" in unused
    assert "visitors.LiteralLookup.visit_Item.kwargs" in unused
    assert "visitors.ConstantFormattedLookup.visit_Item.kwargs" in unused
    assert "visitors.ConstantFormattedLookup.visit_Other.kwargs" in unused
    assert "visitors.ConvertedLookup.visit_Item.kwargs" in unused
    assert "visitors.ShadowedGetattr.visit_Item.kwargs" in unused
    assert "visitors.ComprehensionTarget.visit_Item.kwargs" not in unused
    assert "visitors.WrongReceiver.visit_Item.kwargs" in unused
    assert "visitors.StaticReceiver.visit_Item.kwargs" in unused
    assert "visitors.InheritedHandler.visit_Item.kwargs" not in unused
    assert "visitors.BaseHandler.visit_Item.kwargs" not in unused
    assert "visitors.OverridesDispatcher.visit_Item.kwargs" in unused
    assert "visitors.AttributeOverride.visit_Item.kwargs" in unused
    assert "visitors.HeaderShadow.visit_Item.kwargs" in unused
    assert "visitors.StaticFirst.visit_Item.kwargs" in unused
    assert "visitors.DynamicFirst.visit_Item.kwargs" not in unused
    assert "visitors.UnknownFirst.visit_Item.kwargs" in unused
    assert "visitors.NestedDispatcherOnly.visit_Item.kwargs" in unused
    assert "shadowed_builtin.ShadowedBuiltin.visit_Item.kwargs" in unused
    assert "imported_getattr.ImportedGetattr.visit_Item.kwargs" in unused
    assert "aliased_getattr.AliasedGetattr.visit_Item.kwargs" in unused
