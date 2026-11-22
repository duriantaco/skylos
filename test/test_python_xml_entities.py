"""Analyze XML parser configuration without executing the fixture source."""

from textwrap import dedent

import pytest

from skylos.rules.danger.danger import scan_ctx


def _scan(tmp_path, code):
    path = tmp_path / "reader.py"
    path.write_text(dedent(code).lstrip(), encoding="utf-8")
    return [row for row in scan_ctx(tmp_path, [path]) if row["rule_id"] == "SKY-D236"]


@pytest.mark.parametrize(
    "parse",
    [
        "etree.parse(document, parser)",
        "etree.fromstring(document, parser=parser)",
        "etree.XML(document, parser=parser)",
    ],
)
def test_marks_the_parse_operation_and_its_configuration(tmp_path, parse):
    results = _scan(
        tmp_path,
        f"""
        from lxml import etree

        def read(document):
            parser = etree.XMLParser(resolve_entities=True)
            return {parse}
    """,
    )
    assert [(row["line"], row["severity"]) for row in results] == [(5, "HIGH")]
    assert "line 4" in results[0]["message"]


def test_captures_parser_alias_before_reassignment(tmp_path):
    results = _scan(
        tmp_path,
        """
        from lxml.etree import XMLParser as Factory, fromstring as decode

        def read(document):
            parser = Factory(resolve_entities=True)
            original = parser
            parser = Factory(resolve_entities=False)
            decode(document, parser)
            return decode(document, original)
    """,
    )
    assert [row["line"] for row in results] == [8]


def test_inline_parser_and_snapshot_of_configuration(tmp_path):
    results = _scan(
        tmp_path,
        """
        import lxml.etree as xml

        def read(document):
            enable = True
            parser = xml.XMLParser(resolve_entities=enable)
            enable = False
            xml.parse(document, parser)
            return xml.parse(document, xml.XMLParser(resolve_entities=True))
    """,
    )
    assert [row["line"] for row in results] == [7, 8]


@pytest.mark.parametrize(
    "options",
    ["", "resolve_entities=False", 'resolve_entities="internal"', "no_network=False"],
)
def test_default_restricted_and_unrelated_options(tmp_path, options):
    assert not _scan(
        tmp_path,
        f"""
        from lxml import etree

        def read(document):
            unused = etree.XMLParser(resolve_entities=True)
            parser = etree.XMLParser({options})
            return etree.fromstring(document, parser=parser)
    """,
    )


def test_shadowed_names_and_unrelated_parse_calls(tmp_path):
    assert not _scan(
        tmp_path,
        """
        from lxml import etree

        def read(document, other):
            parser = etree.XMLParser(resolve_entities=True)
            other.parse(document, parser)

        def decode(etree, document):
            return etree.parse(document, etree.XMLParser(resolve_entities=True))
    """,
    )


def test_project_local_package_with_the_same_import_name(tmp_path):
    (tmp_path / "lxml.py").write_text("class etree: pass\n", encoding="utf-8")
    assert not _scan(
        tmp_path,
        """
        from lxml import etree

        def read(document):
            return etree.parse(document, etree.XMLParser(resolve_entities=True))
    """,
    )


@pytest.mark.parametrize(
    "parse",
    [
        "parser.parse(document)",
        "read_xml(document, parser=parser)",
    ],
)
def test_sax_parse_tracks_explicit_external_entities(tmp_path, parse):
    findings = _scan(
        tmp_path,
        f"""
        from xml.sax import make_parser
        from xml.sax.handler import feature_external_ges as external
        from xml.dom.pulldom import parseString as read_xml

        def read(document):
            parser = make_parser()
            alias = parser
            alias.setFeature(external, True)
            return {parse}
        """,
    )
    assert [(finding["line"], finding["severity"]) for finding in findings] == [(9, "HIGH")]
    assert "line 8" in findings[0]["message"]


@pytest.mark.parametrize(
    "before_parse",
    [
        "alias.setFeature(feature_external_ges, False)",
        "parser = make_parser()",
        "configure(parser)",
    ],
)
def test_sax_proof_is_invalidated_by_reconfiguration(tmp_path, before_parse):
    assert not _scan(
        tmp_path,
        f"""
        from xml.sax import make_parser
        from xml.sax.handler import feature_external_ges

        def read(document, configure):
            parser = make_parser()
            alias = parser
            parser.setFeature(feature_external_ges, True)
            {before_parse}
            return parser.parse(document)
        """,
    )


def test_sax_setting_without_parse_is_quiet(tmp_path):
    assert not _scan(
        tmp_path,
        """
        from xml.sax import make_parser
        from xml.sax.handler import feature_external_ges

        parser = make_parser()
        parser.setFeature(feature_external_ges, True)
        """,
    )
