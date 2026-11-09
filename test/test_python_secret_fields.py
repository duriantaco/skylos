"""D251 follows actual credential writes into local structured values."""

import ast
import textwrap

import pytest

from skylos.rules.danger.danger import scan_file_with_tree


def _findings(body):
    source = (
        "import os\nimport logging\nlogger = logging.getLogger(__name__)\n"
        + textwrap.dedent(body)
    )
    result = []
    scan_file_with_tree(ast.parse(source), "sample.py", result, source=source)
    return [finding for finding in result if finding["rule_id"] == "SKY-D251"]


@pytest.mark.parametrize(
    "body",
    [
        """
    record = make_record()
    record.value = os.getenv('API_TOKEN')
    logger.info('%s', record.value)
    """,
        """
    record = make_record()
    alias = record
    alias.value = os.getenv('API_TOKEN')
    print(record.value)
    """,
        """
    def handler(record):
        record.value = os.getenv('API_TOKEN')
        print(record.value)
    """,
        """
    def handler(record, flag):
        if flag:
            record.value = os.getenv('API_TOKEN')
        else:
            record.value = 'public'
        logger.info('%s', record.value)
    """,
        """
    record = make_record()
    record.value = os.getenv('API_TOKEN')
    print({'payload': record.value})
    """,
        """
    record = transform(os.getenv('API_TOKEN'))
    logger.info('%s', record.value)
    """,
    ],
)
def test_credential_field_reaches_output(body):
    result = _findings(body)
    assert len(result) == 1
    assert result[0]["severity"] == "HIGH"
    assert result[0]["metadata"]["security_evidence"]["sources"] == [
        "environment variable API_TOKEN"
    ]


@pytest.mark.parametrize(
    "body",
    [
        """
    record = make_record()
    record.value = os.getenv('API_TOKEN')
    record.status = 'ready'
    print(record.status)
    """,
        """
    record = make_record()
    record.value = os.getenv('API_TOKEN')
    record.value = '[REDACTED]'
    print(record.value)
    """,
        """
    def handler(record, other):
        record.value = os.getenv('API_TOKEN')
        print(other.value)
    """,
        """
    def handler(record):
        print(record.password)
    """,
        """
    first = make_record()
    second = make_record()
    first.value = os.getenv('API_TOKEN')
    print(second.value)
    """,
        """
    def handler(record, flag):
        record.value = os.getenv('API_TOKEN')
        if flag:
            record.value = '[REDACTED]'
        else:
            record.value = 'public'
        print(record.value)
    """,
    ],
)
def test_public_fields_redaction_and_unrelated_objects_stay_quiet(body):
    assert _findings(body) == []


def test_opaque_credential_alternative_is_not_lost_at_field_join():
    assert (
        len(
            _findings("""
        def handler(flag):
            if flag:
                record = make_record()
                record.status = 'ready'
            else:
                record = transform(os.getenv('API_TOKEN'))
            print(record.status)
    """)
        )
        == 1
    )


@pytest.mark.parametrize(
    "container, projection",
    [
        ("[record]", "values[0]"),
        ("{'record': record}", "values['record']"),
        ("[[record]]", "values[0][0]"),
    ],
)
def test_field_redaction_updates_container_object_aliases(container, projection):
    assert (
        _findings(f"""
        record = make_record()
        record.value = os.getenv('API_TOKEN')
        values = {container}
        record.value = '[REDACTED]'
        print({projection}.value)
    """)
        == []
    )


@pytest.mark.parametrize(
    "container, projection",
    [
        ("[record]", "values[0]"),
        ("{'record': record}", "values['record']"),
    ],
)
def test_field_source_write_updates_container_object_aliases(container, projection):
    assert (
        len(
            _findings(f"""
        record = make_record()
        values = {container}
        record.value = os.getenv('API_TOKEN')
        print({projection}.value)
    """)
        )
        == 1
    )


def test_redacting_one_field_keeps_a_credential_sibling_visible():
    assert (
        len(
            _findings("""
        record = make_record()
        record.first = os.getenv('API_TOKEN')
        record.second = os.getenv('API_TOKEN')
        values = [record]
        record.first = '[REDACTED]'
        print(values[0].second)
    """)
        )
        == 1
    )


def test_rebinding_object_name_keeps_the_original_container_object():
    assert (
        len(
            _findings("""
        record = make_record()
        record.value = os.getenv('API_TOKEN')
        values = [record]
        record = make_record()
        record.value = '[REDACTED]'
        print(values[0].value)
    """)
        )
        == 1
    )
