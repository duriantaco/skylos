"""Copy-only defaults need proven constructors and no original alias escape."""

import ast
import textwrap

import pytest

from skylos.analysis.file_processing import set_linter_node_types
from skylos.core.linter import LinterVisitor
from skylos.rules.quality.logic import MutableDefaultRule


def _findings(source):
    rules = [MutableDefaultRule()]
    set_linter_node_types(rules)
    visitor = LinterVisitor(rules, "application.py")
    visitor.visit(ast.parse(textwrap.dedent(source)))
    return visitor.findings


def test_copy_proof_runs_through_the_production_node_dispatch():
    findings = _findings("""
        def copied(items=[]):
            return list(items)

        def shared(items=[]):
            items.append(1)
            return items
    """)
    assert [(finding["rule_id"], finding["name"]) for finding in findings] == [
        ("SKY-L001", "shared")
    ]


@pytest.mark.parametrize(
    "source",
    [
        "def build(items=[]):\n    return list(items)",
        "def build(items=[]):\n    return set(items)",
        "def build(items=[]):\n    return dict(items)",
        "def build(*, headers={}):\n    return dict(headers)",
        "def build(items=[], /):\n    return list(items)",
        "async def build(items=[]):\n    return list(items)",
        "import builtins\ndef build(items=[]):\n    return builtins.list(items)",
        "from builtins import dict as fresh\ndef build(headers={}):\n    return fresh(headers)",
        """
        def build(headers={}):
            copy = dict(headers)
            copy['content-type'] = 'text/plain'
            return copy
        """,
        """
        from requests.structures import CaseInsensitiveDict
        class Response:
            def __init__(self, url, headers={}, status_code=200):
                self.url = url
                self.headers = CaseInsensitiveDict(headers)
                self.status_code = status_code
        """,
        """
        import requests.structures as structures
        def build(headers={}):
            return structures.CaseInsensitiveDict(headers)
        """,
        """
        from requests.structures import CaseInsensitiveDict as Headers
        def build(headers={}):
            return Headers(headers)
        """,
    ],
)
def test_proven_empty_default_copies_have_independent_storage(source):
    assert _findings(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "def build(items=[]):\n    pass",
        "def build(items=[]):\n    return items",
        "def build(items=[]):\n    items.append(1)\n    return list(items)",
        "def build(items=[]):\n    alias = items\n    return list(items)",
        "def build(items=[]):\n    return unknown_constructor(items)",
        "def build(items=[]):\n    copy = list(items)\n    expose(items)\n    return copy",
        "def build(items=[]):\n    items = list(items)\n    return items",
        "def build(items=[]):\n    items = []\n    return list(items)",
        "def build(items=[[]]):\n    return list(items)",
        "def build(headers={'nested': []}):\n    return dict(headers)",
        "def build(items=list()):\n    return list(items)",
        "def build(items=[]):\n    return list(*items)",
        "def build(headers={}):\n    return dict(headers, extra=1)",
        "def build(items=[]):\n    return list(items, items)",
        "def build(items=[]):\n    def later():\n        return list(items)\n    return later",
        "def build(items=[]):\n    later = lambda: list(items)\n    return later",
        "def build(items=[]):\n    return [list(items) for _ in range(2)]",
        """
        class CaseInsensitiveDict:
            def __init__(self, headers):
                self.headers = headers
        def build(headers={}):
            return CaseInsensitiveDict(headers)
        """,
        "from other import CaseInsensitiveDict\ndef build(headers={}):\n    return CaseInsensitiveDict(headers)",
        """
        from requests.structures import CaseInsensitiveDict
        CaseInsensitiveDict = custom_constructor
        def build(headers={}):
            return CaseInsensitiveDict(headers)
        """,
        """
        from requests.structures import CaseInsensitiveDict
        def build(CaseInsensitiveDict, headers={}):
            return CaseInsensitiveDict(headers)
        """,
        "dict = custom_constructor\ndef build(headers={}):\n    return dict(headers)",
        "def build(dict, headers={}):\n    return dict(headers)",
        "from framework import dict\ndef build(headers={}):\n    return dict(headers)",
        """
        import builtins as py
        py.dict = custom_constructor
        def build(headers={}):
            return py.dict(headers)
        """,
        """
        from requests import structures
        from requests import structures as other
        other.CaseInsensitiveDict = custom_constructor
        def build(headers={}):
            return structures.CaseInsensitiveDict(headers)
        """,
        """
        from framework import *
        def build(headers={}):
            return dict(headers)
        """,
        "def build(items=[]):\n    locals()['items'].append(1)\n    return list(items)",
        "def build(items=[]):\n    reflect = locals\n    reflect()['items'].append(1)\n    return list(items)",
        "from builtins import locals as inspect_locals\ndef build(items=[]):\n    inspect_locals()['items'].append(1)\n    return list(items)",
        "def build(items=[]):\n    return list(items)\nbuild.__defaults__[0].append(1)",
        """
        import builtins
        builtins.__dict__['list'] = custom_constructor
        def build(items=[]):
            return list(items)
        """,
        """
        __builtins__['list'] = custom_constructor
        def build(items=[]):
            return list(items)
        """,
        """
        from unittest import mock
        from requests import structures
        mock.patch('requests.structures.CaseInsensitiveDict', custom_constructor).start()
        def build(headers={}):
            return structures.CaseInsensitiveDict(headers)
        """,
        """
        from unittest.mock import patch as replace
        from requests import structures
        replace.object(structures, 'CaseInsensitiveDict', custom_constructor).start()
        def build(headers={}):
            return structures.CaseInsensitiveDict(headers)
        """,
        """
        from requests import structures
        alias = structures
        alias.CaseInsensitiveDict = custom_constructor
        def build(headers={}):
            return structures.CaseInsensitiveDict(headers)
        """,
        """
        from unittest import mock
        from requests.structures import CaseInsensitiveDict
        mock.patch.object(CaseInsensitiveDict, '__init__', custom_constructor).start()
        def build(headers={}):
            return CaseInsensitiveDict(headers)
        """,
        """
        from inspect import signature
        def build(items=[]):
            signature(build).parameters['items'].default.append('shared')
            return list(items)
        """,
        """
        import inspect
        def build(items=[]):
            inspect.Signature.from_callable(build).parameters['items'].default.append('shared')
            return list(items)
        """,
        """
        from inspect import getfullargspec as describe
        def build(items=[]):
            describe(build).defaults[0].append('shared')
            return list(items)
        """,
        """
        from operator import attrgetter as inspect_attribute
        def build(items=[]):
            inspect_attribute('__defaults__')(build)[0].append('shared')
            return list(items)
        """,
        """
        def build(items=[]):
            build.__getattribute__('__defaults__')[0].append('shared')
            return list(items)
        """,
        """
        def build(items=[]):
            try:
                setup()
            except Exception as items:
                return list(items)
        """,
        """
        def build(items=[]):
            match incoming:
                case items:
                    return list(items)
        """,
        """
        def build(items=[]):
            import module as items
            return list(items)
        """,
        """
        def build(items=[]):
            def items():
                return []
            return list(items)
        """,
    ],
)
def test_original_default_escapes_mutations_and_uncertain_copies_remain_flagged(source):
    findings = _findings(source)
    assert any(finding["rule_id"] == "SKY-L001" for finding in findings)


def test_copy_proof_is_per_default_and_does_not_suppress_a_mutated_sibling():
    findings = _findings(
        """
        def build(headers={}, items=[]):
            copied = dict(headers)
            items.append('shared')
            return copied, items
        """
    )
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-L001"
    assert findings[0]["col"] == 28


def test_standalone_function_without_module_binding_evidence_stays_visible():
    function = ast.parse("def build(items=[]):\n    return list(items)").body[0]
    findings = MutableDefaultRule().visit_node(function, {"filename": "application.py"})
    assert findings and findings[0]["rule_id"] == "SKY-L001"
