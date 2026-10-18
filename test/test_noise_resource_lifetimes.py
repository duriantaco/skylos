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
