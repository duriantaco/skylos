"""Known credential query values survive real local dictionary mutation."""

import ast
import textwrap

import pytest

from skylos.rules.danger.danger import scan_file_with_tree


def _findings(body):
    source = (
        "import os\nimport logging\nimport httpx\n"
        "from urllib.parse import urlencode\n"
        "from starlette.datastructures import QueryParams\n" + textwrap.dedent(body)
    )
    findings = []
    scan_file_with_tree(ast.parse(source), "query.py", findings, source=source)
    return [finding for finding in findings if finding["rule_id"] == "SKY-D251"]


@pytest.mark.parametrize(
    "mutation",
    [
        "params.update({'token': os.getenv('API_TOKEN')})",
        "params.update(token=os.getenv('API_TOKEN'))",
        "params.update([('token', os.getenv('API_TOKEN'))])",
        "params.setdefault('token', os.getenv('API_TOKEN'))",
        "alias = params\nalias.update({'token': os.getenv('API_TOKEN')})",
        "holder = [params]\nholder[0].update({'token': os.getenv('API_TOKEN')})",
    ],
)
@pytest.mark.parametrize(
    "output",
    [
        "logging.info('%s', httpx.URL('https://example.test/', params=params))",
        "print('https://example.test/?' + urlencode(params))",
        "print(str(QueryParams(params)))",
    ],
)
def test_mutated_credential_query_reaches_output(mutation, output):
    findings = _findings("params = {}\n" + mutation + "\n" + output)
    assert len(findings) == 1
    assert findings[0]["file"] == "query.py"
    assert findings[0]["severity"] == "HIGH"
    evidence = findings[0]["metadata"]["security_evidence"]
    assert evidence["sources"] == ["environment variable API_TOKEN"]
    assert evidence["evidence_kind"] == "source_to_sink"


@pytest.mark.parametrize(
    "body",
    [
        "params = {}\nparams.update({'token': 'public'})\nprint(urlencode(params))",
        "params = {}\nparams.update({'token': os.getenv('HOME')})\nprint(urlencode(params))",
        "params = {'status': 'ready'}\nparams.update({'token': os.getenv('API_TOKEN')})\nprint(urlencode({'status': params['status']}))",
        "params = {}\nparams.update({'token': os.getenv('API_TOKEN')})\nparams.update({'token': '[REDACTED]'})\nprint(urlencode(params))",
        "params = {'token': os.getenv('API_TOKEN')}\nalias = params\nalias.update(token='[REDACTED]')\nprint(urlencode(params))",
        "params = {'token': os.getenv('API_TOKEN')}\nholder = {'query': params}\nparams.update(token='[REDACTED]')\nprint(urlencode(holder['query']))",
        "params = {}\nresult = params.update(token=os.getenv('API_TOKEN'))\nprint(result)",
        "params = {'token': 'public'}\nparams.setdefault('token', os.getenv('API_TOKEN'))\nprint(urlencode(params))",
        "params = {'token': 'public'}\nprint(params.setdefault('token', os.getenv('API_TOKEN')))",
        "def handler(params):\n    print(httpx.URL('https://example.test/', params=params))",
        "def handler(request):\n    print(request.url)\n    print(request.query_params)",
    ],
)
def test_public_query_projection_redaction_and_unproven_sources_stay_quiet(body):
    assert _findings(body) == []


def test_existing_setdefault_credential_is_returned_without_replacement():
    findings = _findings("""
        params = {'token': os.getenv('API_TOKEN')}
        value = params.setdefault('token', '[REDACTED]')
        print(value)
        print(urlencode(params))
    """)
    assert len(findings) == 2


def test_missing_setdefault_credential_is_returned_and_stored():
    findings = _findings("""
        from getpass import getpass
        params = {}
        value = params.setdefault('token', getpass())
        print(value)
        print(urlencode(params))
    """)
    assert len(findings) == 2
    assert all(
        finding["metadata"]["security_evidence"]["sources"]
        == ["getpass credential input"]
        for finding in findings
    )


def test_query_encoding_preserves_an_existing_credential_source():
    findings = _findings("""
        from urllib.parse import quote, quote_plus
        params = {'token': quote_plus(quote(os.getenv('API_TOKEN')))}
        print(urlencode(params))
    """)
    assert len(findings) == 1


def test_redaction_preserves_a_credential_sibling_after_update():
    findings = _findings("""
        params = {'first': os.getenv('API_TOKEN'), 'second': os.getenv('SERVICE_PASSWORD')}
        params.update(first='[REDACTED]')
        print(urlencode(params))
    """)
    assert len(findings) == 1
    assert findings[0]["metadata"]["security_evidence"]["sources"] == [
        "environment variable SERVICE_PASSWORD"
    ]


def test_dictionary_rebinding_does_not_rewrite_a_saved_query_alias():
    findings = _findings("""
        params = {}
        saved = params
        params = {}
        params.update(token=os.getenv('API_TOKEN'))
        print(urlencode(saved))
        print(urlencode(params))
    """)
    assert len(findings) == 1


@pytest.mark.parametrize(
    "construction", ["dict()", "dict(status='ready')", "dict([('status', 'ready')])"]
)
def test_builtin_dictionary_query_construction_supports_later_mutation(construction):
    findings = _findings(
        f"params = {construction}\n"
        "params.update(token=os.getenv('API_TOKEN'))\n"
        "print(urlencode(params))"
    )
    assert len(findings) == 1


def test_builtin_dictionary_projection_and_redaction_are_precise():
    assert (
        _findings("""
        from builtins import dict as make_dict
        params = make_dict(token=os.getenv('API_TOKEN'), status='ready')
        print(params['status'])
        params.update(token='[REDACTED]')
        print(urlencode(params))
    """)
        == []
    )


def test_update_keyword_unpacking_and_override_order_follow_real_values():
    findings = _findings("""
        params = {}
        params.update(**{'token': os.getenv('API_TOKEN')}, **{'status': 'ready'})
        print(urlencode(params))
        params.update({'token': os.getenv('API_TOKEN')}, token='[REDACTED]')
        print(urlencode(params))
    """)
    assert len(findings) == 1


def test_shadowed_dictionary_constructor_does_not_prove_redaction():
    findings = _findings("""
        def handler(dict):
            params = dict(token=os.getenv('API_TOKEN'))
            params.update(token='[REDACTED]')
            print(urlencode(params))
    """)
    assert len(findings) == 1


def test_method_receiver_is_bound_before_an_argument_rebinds_its_name():
    findings = _findings("""
        first = {}
        second = {}
        receiver = first
        receiver.update(other=(receiver := second), token=os.getenv('API_TOKEN'))
        print(urlencode(second))
        print(urlencode(first))
    """)
    assert [finding["line"] for finding in findings] == [12]


def test_argument_mutation_refreshes_the_original_bound_receiver():
    findings = _findings("""
        params = {}
        params.update(token=(params.setdefault('token', os.getenv('API_TOKEN')), '[REDACTED]')[1])
        print(urlencode(params))
    """)
    assert findings == []


def test_argument_mutation_keeps_an_unoverwritten_credential_sibling():
    findings = _findings("""
        params = {}
        params.update(status=(params.setdefault('token', os.getenv('API_TOKEN')), 'ready')[1])
        print(urlencode(params))
    """)
    assert len(findings) == 1


def test_later_keyword_mutation_refreshes_an_earlier_mapping_argument():
    findings = _findings("""
        values = {}
        params = {}
        params.update(values, status=(values.setdefault('token', os.getenv('API_TOKEN')), 'ready')[1])
        print(urlencode(params))
    """)
    assert len(findings) == 1


def test_constructor_mapping_argument_is_read_after_keyword_side_effects():
    findings = _findings("""
        values = {}
        params = dict(values, status=(values.setdefault('token', os.getenv('API_TOKEN')), 'ready')[1])
        print(urlencode(params))
    """)
    assert len(findings) == 1
