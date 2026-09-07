"""Contract fixtures are parsed only; no target imports or callbacks execute."""

import ast
import textwrap

import pytest

from skylos.deadcode.external_protocols import find_external_protocol_callbacks
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.visitors.base import Visitor


_CLIENT = """\
class Client:
    @staticmethod
    def download(uri, *args): return uri, ''
    def unrelated(self): return 1
    def _private(self): return 2
"""


def _collect(tmp_path, source, extra_paths=()):
    path = tmp_path / "app.py"
    tree = ast.parse(textwrap.dedent(source))
    visitor = Visitor("app", path)
    visitor.visit(tree)
    visitor.finalize()
    definitions = {definition.name: definition for definition in visitor.defs}
    parsed = [ParsedPythonFile(path, tree)]
    parsed.extend(
        ParsedPythonFile(tmp_path / name, ast.parse("")) for name in extra_paths
    )
    edges = find_external_protocol_callbacks(definitions, parsed, tmp_path)
    assert all(definition.references == 0 for definition, _ in edges)
    return [
        (method.name, caller.name if caller is not None else None)
        for method, caller in edges
    ]


@pytest.mark.parametrize(
    "import_line,callee",
    [
        ("import m3u8", "m3u8.load"),
        ("import m3u8 as playlist", "playlist.load"),
        ("from m3u8 import load", "load"),
        ("from m3u8 import load as read", "read"),
    ],
)
@pytest.mark.parametrize(
    "arguments",
    [
        "uri, http_client=Client()",
        "uri, None, {}, None, Client()",
    ],
)
def test_proven_imports_return_only_caller_owned_download(
    tmp_path, import_line, callee, arguments
):
    source = (
        _CLIENT
        + f"def wrapper(uri):\n    {import_line}\n    return {callee}({arguments})\n"
    )
    assert _collect(tmp_path, source) == [("app.Client.download", "app.wrapper")]


def test_module_execution_has_no_deferred_owner(tmp_path):
    source = (
        _CLIENT
        + "import m3u8\nm3u8.load('s3://example.invalid/list', http_client=Client())\n"
    )
    assert _collect(tmp_path, source) == [("app.Client.download", None)]


def test_assigned_instance_alias_and_duplicate_calls(tmp_path):
    source = (
        _CLIENT
        + """\
from m3u8 import load
def wrapper(uri):
    client = Client()
    alias = client
    load(uri, http_client=alias)
    return load(uri, http_client=client)
"""
    )
    assert _collect(tmp_path, source) == [("app.Client.download", "app.wrapper")]


def test_nested_function_keeps_its_own_caller(tmp_path):
    source = (
        _CLIENT
        + """\
import m3u8
def outer(uri):
    def inner():
        return m3u8.load(uri, http_client=Client())
    return inner
"""
    )
    assert _collect(tmp_path, source) == [("app.Client.download", "app.outer.inner")]


@pytest.mark.parametrize(
    "body",
    [
        "def wrapper(m3u8, uri): return m3u8.load(uri, http_client=Client())",
        "def wrapper(uri):\n    m3u8 = local\n    return m3u8.load(uri, http_client=Client())",
        "def wrapper(uri):\n    m3u8.load(uri, http_client=Client())\n    m3u8 = local",
        "def wrapper(uri):\n    Client = local\n    return m3u8.load(uri, http_client=Client())",
        "def wrapper(uri):\n    client = Client()\n    client = object()\n    return m3u8.load(uri, http_client=client)",
        "m3u8.load = local\ndef wrapper(uri): return m3u8.load(uri, http_client=Client())",
        "Client.download = local\ndef wrapper(uri): return m3u8.load(uri, http_client=Client())",
        "from other import *\ndef wrapper(uri): return m3u8.load(uri, http_client=Client())",
        "def wrapper(uri): return m3u8.load(uri, http_client=Client())\nm3u8 = local",
        "def wrapper(uri): return m3u8.load(uri, http_client=Client())\nClient = local",
        "def wrapper(uri):\n    return uri\n    m3u8.load(uri, http_client=Client())",
        "def wrapper(uri):\n    if True:\n        return uri\n    m3u8.load(uri, http_client=Client())",
    ],
)
def test_shadowed_mutated_or_unreachable_calls_do_not_prove_use(tmp_path, body):
    assert _collect(tmp_path, _CLIENT + "import m3u8\n" + body + "\n") == []


@pytest.mark.parametrize(
    "call",
    [
        "m3u8.loads(uri, http_client=Client())",
        "m3u8.load(uri, client=Client())",
        "m3u8.load(uri, http_client=unknown)",
        "m3u8.load(*args, http_client=Client())",
        "m3u8.load(uri, http_client=Client(), **options)",
        "m3u8.load(http_client=Client())",
        "m3u8.load(uri, uri=uri, http_client=Client())",
        "m3u8.load(uri, http_client=Client(), unexpected=True)",
        "m3u8.load(uri, None, {}, None, Client(), True, None)",
    ],
)
def test_wrong_contract_or_visibly_invalid_call_is_not_an_edge(tmp_path, call):
    source = _CLIENT + f"import m3u8\ndef wrapper(uri): return {call}\n"
    assert _collect(tmp_path, source) == []


@pytest.mark.parametrize(
    "path", ["m3u8.py", "m3u8/__init__.py", "src/m3u8.py", "lib/m3u8/client.py"]
)
def test_local_modules_disable_external_contract(tmp_path, path):
    source = (
        _CLIENT
        + "import m3u8\ndef wrapper(uri): return m3u8.load(uri, http_client=Client())\n"
    )
    assert _collect(tmp_path, source, (path,)) == []


def test_import_in_an_unrelated_function_does_not_leak(tmp_path):
    source = (
        _CLIENT
        + """\
def imports_only():
    import m3u8
def wrapper(uri):
    return m3u8.load(uri, http_client=Client())
"""
    )
    assert _collect(tmp_path, source) == []


def test_unknown_flow_is_not_promoted(tmp_path):
    source = (
        _CLIENT
        + """\
def wrapper(uri):
    if condition:
        import m3u8
    return m3u8.load(uri, http_client=Client())
"""
    )
    assert _collect(tmp_path, source) == []


@pytest.mark.parametrize(
    "uri", ["playlist.m3u8", "./playlist.m3u8", "file:///tmp/list.m3u8"]
)
def test_literal_local_uri_does_not_invoke_the_client(tmp_path, uri):
    source = _CLIENT + f"import m3u8\nm3u8.load({uri!r}, http_client=Client())\n"
    assert _collect(tmp_path, source) == []


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
@pytest.mark.parametrize(
    "binding",
    [
        "def {name}(function): return other\n",
        "from other import replacement as {name}\n",
    ],
)
def test_shadowed_method_decorators_do_not_prove_callback_identity(
    tmp_path, decorator, binding
):
    source = (
        binding.format(name=decorator)
        + _CLIENT.replace("staticmethod", decorator)
        + "import m3u8\ndef wrapper(uri): return m3u8.load(uri, http_client=Client())\n"
    )
    assert _collect(tmp_path, source) == []


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_class_local_method_decorator_is_not_a_builtin(tmp_path, decorator):
    client = _CLIENT.replace("staticmethod", decorator).replace(
        "class Client:\n", f"class Client:\n    {decorator} = replacement\n"
    )
    source = (
        client
        + "import m3u8\ndef wrapper(uri): return m3u8.load(uri, http_client=Client())\n"
    )
    assert _collect(tmp_path, source) == []


_PARENT = """\
class Parent:
    @staticmethod
    def download(uri, *args): return uri, ''
"""


def _inherited(tmp_path, source, client="Client()"):
    return _collect(
        tmp_path,
        source
        + f"\nfrom m3u8 import load\ndef wrapper(uri): return load(uri, http_client={client})\n",
    )


@pytest.mark.parametrize("client", ["Client()", "Client"])
@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_inherited_static_and_class_methods(tmp_path, client, decorator):
    source = _PARENT.replace("staticmethod", decorator) + "class Client(Parent): pass\n"
    assert _inherited(tmp_path, source, client) == [
        ("app.Parent.download", "app.wrapper")
    ]


def test_inherited_instance_method_requires_an_instance(tmp_path):
    source = "class Parent:\n    def download(self, uri, *args): return uri, ''\nclass Client(Parent): pass\n"
    assert _inherited(tmp_path, source) == [("app.Parent.download", "app.wrapper")]
    assert _inherited(tmp_path, source, "Client") == []


def test_direct_instance_method_is_not_a_class_callback(tmp_path):
    source = "class Client:\n    def download(self, uri, timeout, headers, verify_ssl): return uri, ''\n"
    assert _inherited(tmp_path, source, "Client") == []
    assert _inherited(tmp_path, source) == [("app.Client.download", "app.wrapper")]


@pytest.mark.parametrize(
    "bases,expected", [("Left, Right", "Left"), ("Right, Left", "Right")]
)
def test_multiple_inheritance_preserves_base_order(tmp_path, bases, expected):
    source = _PARENT.replace("Parent", "Left") + _PARENT.replace("Parent", "Right")
    source += f"class Client({bases}): pass\n"
    assert _inherited(tmp_path, source) == [(f"app.{expected}.download", "app.wrapper")]


def test_diamond_uses_c3_not_depth_first_lookup(tmp_path):
    source = _PARENT + "class Left(Parent): pass\n"
    source += _PARENT.replace("class Parent:", "class Right(Parent):")
    source += "class Client(Left, Right): pass\n"
    assert _inherited(tmp_path, source) == [("app.Right.download", "app.wrapper")]


def test_subclass_override_does_not_promote_parent_method(tmp_path):
    source = _PARENT + _PARENT.replace("class Parent:", "class Client(Parent):")
    assert _inherited(tmp_path, source) == [("app.Client.download", "app.wrapper")]


def test_base_alias_is_captured_when_class_is_defined(tmp_path):
    source = (
        _PARENT + "Alias = Parent\nclass Client(Alias): pass\nAlias = replacement\n"
    )
    assert _inherited(tmp_path, source) == [("app.Parent.download", "app.wrapper")]


def test_explicit_object_base_is_supported(tmp_path):
    source = (
        _PARENT.replace("class Parent:", "class Parent(object):")
        + "class Client(Parent): pass\n"
    )
    assert _inherited(tmp_path, source) == [("app.Parent.download", "app.wrapper")]


@pytest.mark.parametrize(
    "suffix",
    [
        "class Client(Parent):\n    download = None\n",
        "class Client(Parent):\n    @custom\n    def download(self, uri, *args): return uri, ''\n",
        "class Client(unknown): pass\n",
        "class Client(Parent, unknown): pass\n",
        "class Client(factory()): pass\n",
        "Alias = replacement\nclass Client(Alias): pass\n",
        "class Client(Parent): pass\nParent.download = replacement\n",
        "class Client(Parent): pass\nClient.download = replacement\n",
        "class Client(Parent): pass\nsetattr(Parent, 'download', replacement)\n",
        "class Client(Parent, Parent): pass\n",
        "class A: pass\nclass B: pass\nclass Left(A, B): pass\nclass Right(B, A): pass\nclass Client(Left, Right, Parent): pass\n",
    ],
)
def test_unproven_or_masked_inherited_callbacks_are_not_promoted(tmp_path, suffix):
    assert _inherited(tmp_path, _PARENT + suffix) == []


@pytest.mark.parametrize(
    "prefix",
    [
        "def staticmethod(function): return replacement\n",
        "from helpers import replacement as staticmethod\n",
    ],
)
def test_inherited_decorator_identity_must_be_proven(tmp_path, prefix):
    source = prefix + _PARENT + "class Client(Parent): pass\n"
    assert _inherited(tmp_path, source) == []


@pytest.mark.parametrize(
    "body",
    [
        "def __init__(self):\n        self.download = replacement",
        "def __init__(self):\n        setattr(self, 'download', replacement)",
        "def __init__(self):\n        delattr(self, 'download')",
        "def __getattribute__(self, name):\n        return replacement",
    ],
)
def test_instance_shadow_does_not_promote_inherited_download(tmp_path, body):
    source = _PARENT + f"class Client(Parent):\n    {body}\n"
    assert _inherited(tmp_path, source) == []
    # Neither instance initialization nor instance attribute lookup changes the
    # inherited static method when the library receives the class itself.
    assert _inherited(tmp_path, source, "Client") == [
        ("app.Parent.download", "app.wrapper")
    ]
