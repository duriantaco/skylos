"""Cleanup requires an actual handle lifetime, not just an opening syntax."""

import ast
import textwrap

import pytest

from skylos.rules.quality.logic_foundation import MissingResourceCleanupRule


def findings(source):
    tree = ast.parse(textwrap.dedent(source))
    rule = MissingResourceCleanupRule()
    context = {"filename": "service.py"}
    return [finding for node in ast.walk(tree)
            for finding in rule.visit_node(node, context) or []]


@pytest.mark.parametrize("body", [
    'handle = open(path)\nwith handle:\n    return handle.read()',
    'handle = open(path)\nhandle.close()',
    'try:\n    handle = open(path)\nexcept OSError:\n    return None\nwith handle:\n    return handle.read()',
    'try:\n    handle = open(path)\nexcept OSError:\n    raise\nwith handle:\n    return handle.read()',
])
def test_immediate_cleanup_of_successfully_acquired_handle(body):
    assert not findings('def read(path):\n' + textwrap.indent(body, '    '))


@pytest.mark.parametrize("body", [
    'handle = open(path)\nwork()\nhandle.close()',
    'handle = open(path)\nif enabled:\n    with handle:\n        work()',
    'handle = open(path)\nwith other_context(), handle:\n    work()',
    'handle = open(path)\nother.close()',
    'handle = open(path)\nif enabled:\n    handle.close()',
    'try:\n    handle = open(path)\nexcept OSError:\n    pass\nwith handle:\n    work()',
    'try:\n    handle = open(path)\n    work()\nexcept OSError:\n    return None\nwith handle:\n    work()',
    'handle = sqlite3.connect(path)\nwith handle:\n    handle.execute("SELECT 1")',
])
def test_uncertain_or_nonclosing_cleanup_preserves_the_finding(body):
    result = findings('def read(path):\n' + textwrap.indent(body, '    '))
    assert any(finding['rule_id'] == 'SKY-L008' for finding in result)


def test_chained_assignment_does_not_assume_unaliased_handle():
    result = findings('''
        def read(path):
            original = alias = open(path)
            original.close()
    ''')
    assert result


@pytest.mark.parametrize("source", [
    '''
        import sqlite3
        def read(path, open=sqlite3.connect):
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        import sqlite3
        open = sqlite3.connect
        def read(path):
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        import sqlite3
        import requests
        requests.Session = sqlite3.connect
        def read(path):
            handle = requests.Session(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        from sqlite3 import connect as open
        def read(path):
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        import requests
        import sqlite3
        alias = requests
        alias.Session = sqlite3.connect
        def read(path):
            handle = requests.Session(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        from unknown import *
        def read(path):
            handle = open(path)
            with handle:
                handle.read()
    ''',
    '''
        import sqlite3
        def read(path):
            globals()['open'] = sqlite3.connect
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        import builtins
        import sqlite3
        setattr(builtins, 'open', sqlite3.connect)
        def read(path):
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        from unittest.mock import patch
        patch('builtins.open', sqlite3.connect).start()
        def read(path):
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        import requests
        from unittest.mock import patch as replace
        replace.object(requests, 'Session', sqlite3.connect).start()
        def read(path):
            handle = requests.Session(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        def read(path, requests):
            handle = requests.Session(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        def read(path):
            handle = requests.Session(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        import sqlite3
        def install():
            globals()['open'] = sqlite3.connect
        install()
        def read(path):
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        import sqlite3
        class Install:
            globals()['open'] = sqlite3.connect
        def read(path):
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        import builtins
        import sqlite3
        getattr(builtins, '__dict__')['open'] = sqlite3.connect
        def read(path):
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
    '''
        import sqlite3
        def install():
            globals()['open'] = sqlite3.connect
        def read(path):
            install()
            handle = open(path)
            with handle:
                handle.execute('SELECT 1')
    ''',
])
def test_with_handle_does_not_trust_rebound_or_unproven_resource_factory(source):
    assert any(item['rule_id'] == 'SKY-L008' for item in findings(source))


@pytest.mark.parametrize("binding, factory", [
    ('from builtins import open', 'open(path)'),
    ('import requests', 'requests.Session()'),
    ('import socket', 'socket.socket()'),
    ('import tempfile', 'tempfile.TemporaryFile()'),
    ('import http.client', "http.client.HTTPConnection('localhost')"),
    ('from pathlib import Path', 'Path(path).open()'),
])
def test_with_handle_accepts_import_proven_closing_resource_contract(binding, factory):
    source = f'{binding}\ndef read(path):\n    handle = {factory}\n    with handle:\n        work()'
    assert not findings(source)


def test_unrelated_function_reflection_does_not_rebind_the_builtin_open():
    assert not findings('''
        def execute_module(code, module):
            exec(code, module.__dict__)
        def read(path):
            try:
                handle = open(path)
            except OSError:
                return None
            with handle:
                return handle.read()
    ''')


def test_explicit_immediate_close_remains_valid_for_a_rebound_factory():
    assert not findings('''
        import sqlite3
        def read(path, open=sqlite3.connect):
            handle = open(path)
            handle.close()
    ''')


@pytest.mark.parametrize("body", [
    'if enabled:\n    handle = open(path)\n    return handle.read()',
    'for item in path:\n    handle = open(item)\n    print(handle.read())',
    'while enabled:\n    handle = open(path)\n    enabled = handle.readline()',
    'try:\n    enabled = int(path)\nexcept ValueError:\n    handle = open(path)\n    return handle.read()',
    'try:\n    enabled = 1\nfinally:\n    handle = open(path)\n    print(handle.read())',
    'match enabled:\n    case "read":\n        handle = open(path)\n        return handle.read()',
    'if enabled:\n    handle = open(path)\n    return json.load(handle)',
    'if enabled:\n    handle = open(path)\n    other.data = json.load(handle)',
    'if enabled:\n    handle = open(path)\n    data = handle.read()\n    if data:\n        handle.close()',
    'if enabled:\n    try:\n        handle = open(path)\n        return handle.read()\n    finally:\n        other.close()',
])
def test_resource_opened_inside_a_block_is_still_checked(body):
    result = findings('def read(path, enabled, other):\n' + textwrap.indent(body, '    '))
    assert [item['line'] for item in result if item['rule_id'] == 'SKY-L008']


@pytest.mark.parametrize("body", [
    'if enabled:\n    with open(path) as handle:\n        return handle.read()',
    'if enabled:\n    try:\n        handle = open(path)\n        return handle.read()\n    finally:\n        handle.close()',
    'if enabled:\n    handle = open(path)\n    return handle',
    'for item in path:\n    handle = open(item)\n    yield handle',
    'if enabled:\n    handle = open(path)\n    return Reader(handle)',
    'if enabled:\n    handle = open(path)\n    reader = Reader(handle)\n    return reader',
    'if enabled:\n    handle = open(path)\n    other.enter_context(handle)',
    'if enabled:\n    handle = open(path)\n    other.stream = other.wrap_stream(handle)',
    'with other:\n    handle = open(path)\n    return handle.read()',
])
def test_block_resources_with_cleanup_or_new_owner_are_not_reported(body):
    assert not findings('def read(path, enabled, other):\n' + textwrap.indent(body, '    '))


def test_attribute_handle_needs_a_close_in_its_module():
    closed = findings('''
        class Owner:
            def __init__(self, path, enabled):
                if enabled:
                    self.stream = open(path)
            def close(self):
                self.stream.close()
    ''')
    leaked = findings('''
        class Holder:
            def __init__(self, path, enabled):
                if enabled:
                    self.stream = open(path)
            def close(self):
                self.other.close()
    ''')
    assert not closed
    assert [item['line'] for item in leaked] == [5]


def test_attribute_handle_closed_after_being_taken_off_its_object():
    teardown = '''
        import sqlite3
        def get_db(g, path):
            if "db" not in g:
                g.db = sqlite3.connect(path)
            return g.db
        def close_db(g):
            db = g.pop("{key}", None)
            if db is not None:
                db.close()
    '''
    assert not findings(teardown.format(key="db"))
    assert [item['line'] for item in findings(teardown.format(key="cache"))] == [5]


OPENER = 'class Leaks:\n    def acquire(self, path):\n        self.stream = open(path)\n'


@pytest.mark.parametrize(("closer", "leaks"), [
    ('class Other:\n    def close(self):\n        self.stream.close()\n', True),
    ('class Other:\n    def drain(self):\n        with self.stream:\n            pass\n', True),
    ('class Other:\n    def drain(self, stack):\n        stack.callback(self.stream.close)\n', True),
    ('class Other:\n    def drain(self):\n        stream = getattr(self, "stream")\n        stream.close()\n', True),
    ('class Child(Leaks, RuntimeError):\n    def close(self):\n        self.stream.close()\n', False),
    ('class Closer:\n    def close(self):\n        self.stream.close()\nclass Both(Leaks, Closer):\n    pass\n', False),
    ('def shutdown(conn):\n    conn.stream.close()\n', False),
])
def test_attribute_handle_needs_a_close_on_the_same_object(closer, leaks):
    result = findings(OPENER + closer)
    assert bool(result) is leaks


def test_attribute_handle_closed_by_a_base_class_is_not_reported():
    assert not findings('''
        class Closer:
            def close(self):
                self.stream.close()
        class Leaks(Closer):
            def acquire(self, path):
                self.stream = open(path)
    ''')


@pytest.mark.parametrize(("body", "leaks"), [
    ('if enabled:\n    try:\n        pass\n    finally:\n        handle.close()\nhandle = open(path)\nreturn handle.read()', True),
    ('try:\n    pass\nfinally:\n    handle.close()\nhandle = open(path)\nreturn handle.read()', True),
    ('try:\n    handle = open(path)\n    return handle.read()\nfinally:\n    handle.close()', False),
    ('handle = open(path)\ntry:\n    return handle.read()\nfinally:\n    handle.close()', False),
    ('if enabled:\n    handle = open(path)\nelse:\n    handle = open(path)\ntry:\n    return handle.read()\nfinally:\n    handle.close()', False),
])
def test_finally_counts_only_when_it_runs_after_the_open(body, leaks):
    result = findings('def read(path, handle, enabled):\n' + textwrap.indent(body, '    '))
    assert bool(result) is leaks


READER_ONLY = 'class Reader:\n    def __init__(self, handle):\n        self.data = handle.read()\n'


@pytest.mark.parametrize(("classes", "body", "leaks"), [
    (READER_ONLY, 'handle = open(path)\nreturn Reader(handle)', True),
    (READER_ONLY, 'handle = open(path)\nreader = Reader(handle)\nreturn reader', True),
    ('class Reader:\n    def __init__(self, handle):\n        self.f = handle\n    def close(self):\n        self.f.close()\n',
     'handle = open(path)\nreturn Reader(handle)', False),
    ('class Base:\n    def __init__(self, handle):\n        self.handle = handle\nclass Reader(Base):\n    def __init__(self, handle):\n        super().__init__(handle)\n',
     'handle = open(path)\nreturn Reader(handle)', False),
    ('class Base:\n    def __init__(self, handle):\n        self.handle = handle\nclass Reader(Base):\n    pass\n',
     'handle = open(path)\nreturn Reader(handle)', False),
    ('import io\n', 'handle = open(path)\nreturn io.BufferedReader(handle)', False),
    ('from wrappers import Reader\n', 'handle = open(path)\nreturn Reader(handle)', False),
    ('import dataclasses\n@dataclasses.dataclass\nclass Reader:\n    handle: object\n',
     'handle = open(path)\nreturn Reader(handle)', False),
])
def test_local_constructor_must_keep_the_handle_it_is_given(classes, body, leaks):
    result = findings(classes + 'def read(path):\n' + textwrap.indent(body, '    '))
    assert bool(result) is leaks


@pytest.mark.parametrize(("body", "leaks"), [
    ('handle = open(path)\nif enabled:\n    try:\n        pass\n    finally:\n        handle.close()\nreturn handle.read()', True),
    ('try:\n    handle = open(path)\n    return handle.read()\nfinally:\n    if enabled:\n        handle.close()', True),
    ('try:\n    handle = open(path)\n    return handle.read()\nfinally:\n    def cleanup():\n        handle.close()', True),
    ('handle = open(path)\nif enabled:\n    return handle.read()\ntry:\n    return handle.read()\nfinally:\n    handle.close()', True),
    ('try:\n    handle = open(path)\n    return handle.read()\nfinally:\n    if enabled:\n        handle.close()\n    else:\n        handle.close()', False),
    ('try:\n    handle = open(path)\n    return handle.read()\nfinally:\n    if enabled:\n        handle.close()\n        return None\n    handle.close()', False),
    ('try:\n    handle = open(path)\n    return handle.read()\nfinally:\n    handle = other\n    handle.close()', True),
])
def test_finally_cleanup_must_execute_for_the_opened_handle(body, leaks):
    source = 'def read(path, enabled, other):\n' + textwrap.indent(body, '    ')
    assert bool(findings(source)) is leaks


@pytest.mark.parametrize(("initializer", "arguments", "leaks"), [
    ('if keep:\n    self.handle = handle\nelse:\n    self.data = handle.read()', 'handle, False', True),
    ('if keep:\n    self.handle = handle\nelse:\n    self.data = handle.read()', 'handle, True', False),
    ('if keep:\n    self.handle = handle\nelse:\n    self.data = handle.read()', 'handle, keep', True),
    ('if keep:\n    self.handle = handle\nelse:\n    self.other = handle', 'handle, keep', False),
    ('self.data = handle.read()\ndef retain():\n    self.handle = handle', 'handle, keep', True),
    ('self.handle = handle\nself.handle = None', 'handle, keep', True),
    ('alias = handle\nalias = None\nself.handle = alias', 'handle, keep', True),
    ('alias = handle\nself.handle = alias', 'handle, keep', False),
    ('if keep:\n    return\nself.handle = handle', 'handle, keep', True),
])
def test_constructor_ownership_must_survive_each_return_path(initializer, arguments, leaks):
    source = 'class Reader:\n    def __init__(self, handle, keep):\n'
    source += textwrap.indent(initializer, '        ') + '\n'
    source += 'def read(path, keep):\n    handle = open(path)\n'
    source += '    return Reader(' + arguments + ')\n'
    assert bool(findings(source)) is leaks


@pytest.mark.parametrize(("source", "leaks"), [
    ('class First:\n    class Service:\n        def acquire(self, path):\n            self.stream = open(path)\nclass Second:\n    class Service:\n        def close(self):\n            self.stream.close()', True),
    ('def first():\n    class Service:\n        def acquire(self, path):\n            self.stream = open(path)\ndef second():\n    class Service:\n        def close(self):\n            self.stream.close()', True),
    ('class Outer:\n    class Base:\n        def close(self):\n            self.stream.close()\n    class Service(Base):\n        def acquire(self, path):\n            self.stream = open(path)', False),
    ('class Outer:\n    class Base:\n        def close(self):\n            self.stream.close()\nclass Service(Outer.Base):\n    def acquire(self, path):\n        self.stream = open(path)', False),
])
def test_same_named_nested_classes_do_not_share_cleanup(source, leaks):
    assert bool(findings(source)) is leaks


@pytest.mark.parametrize(("body", "leaks"), [
    ('handle = open(path)\ntry:\n    handle = other\n    return handle.read()\nfinally:\n    handle.close()', True),
    ('try:\n    handle = open(path)\n    handle = other\n    return handle.read()\nfinally:\n    handle.close()', True),
    ('try:\n    if enabled:\n        handle = open(path)\n    else:\n        handle = open(path)\n    return handle.read()\nfinally:\n    handle.close()', False),
])
def test_finally_cleanup_tracks_rebinding_without_merging_exclusive_branches(body, leaks):
    source = 'def read(path, enabled, other):\n' + textwrap.indent(body, '    ')
    assert bool(findings(source)) is leaks


def test_conditional_value_inside_a_stored_container_does_not_prove_ownership():
    assert findings('''
        class Reader:
            def __init__(self, handle, keep):
                self.handles = [handle if keep else None]
        def read(path):
            handle = open(path)
            return Reader(handle, False)
    ''')


@pytest.mark.parametrize("arguments", ["handle, handle", "first=handle, second=handle"])
def test_constructor_may_retain_another_parameter_bound_to_the_same_handle(arguments):
    source = '''
        class Reader:
            def __init__(self, first, second):
                first = None
                self.handle = second
        def read(path):
            handle = open(path)
            return Reader(ARGUMENTS)
    '''.replace('ARGUMENTS', arguments)
    assert not findings(source)


@pytest.mark.parametrize(("handler", "leaks"), [
    ('handle = other', True),
    ('log()', False),
])
def test_nested_finally_closes_the_handle_from_before_its_handler(handler, leaks):
    source = '''
def read(path, other):
    handle = open(path)
    try:
        return handle.read()
    finally:
        try:
            work()
        except Exception:
            HANDLER
        finally:
            handle.close()
'''.replace('HANDLER', handler)
    assert bool(findings(source)) is leaks


@pytest.mark.parametrize("target", ['self.handle', 'self.items[0]'])
def test_constructor_deleting_its_stored_handle_does_not_keep_ownership(target):
    source = '''
class Reader:
    def __init__(self, handle):
        self.items = {}
        TARGET = handle
        del TARGET
def read(path):
    handle = open(path)
    return Reader(handle)
'''.replace('TARGET', target)
    assert findings(source)


def test_finally_identity_assignment_preserves_the_acquired_handle():
    assert not findings('''
        def read(path):
            try:
                handle = open(path)
                return handle.read()
            finally:
                handle = handle
                handle.close()
    ''')


@pytest.mark.parametrize(("initializer", "leaks"), [
    ('self.handle = handle\nself.handle: object', False),
    ('handle: object\nself.handle = handle', False),
    ('self.handle = handle\nself.handle: object = None', True),
])
def test_constructor_annotations_do_not_overwrite_without_a_value(initializer, leaks):
    source = 'class Reader:\n    def __init__(self, handle):\n'
    source += textwrap.indent(initializer, '        ') + '\n'
    source += 'def read(path):\n    handle = open(path)\n    return Reader(handle)\n'
    assert bool(findings(source)) is leaks


def test_finally_annotation_without_a_value_preserves_the_handle():
    assert not findings('''
        def read(path):
            try:
                handle = open(path)
                return handle.read()
            finally:
                handle: object
                handle.close()
    ''')
