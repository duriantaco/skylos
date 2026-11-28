"""Native .NET reader policy checks from inert source fixtures."""

import pytest

from skylos.visitors.languages.csharp.danger import scan_danger


@pytest.mark.parametrize(
    ("body", "lines"),
    [
        (
            """var policy = new XmlReaderSettings {
                   DtdProcessing = DtdProcessing.Parse,
                   XmlResolver = new XmlUrlResolver()
               };
               var reader = XmlReader.Create(input, policy);""",
            [8],
        ),
        (
            """XmlReaderSettings policy = new();
               policy.DtdProcessing = DtdProcessing.Parse;
               policy.XmlResolver = new XmlUrlResolver();
               var reader = XmlReader.Create(input, settings: policy);""",
            [7],
        ),
        (
            """var policy = new XmlReaderSettings();
               policy.DtdProcessing = DtdProcessing.Parse;
               policy.XmlResolver = new XmlUrlResolver();
               var alias = policy;
               alias.XmlResolver = null;
               var reader = XmlReader.Create(input, policy);""",
            [],
        ),
        (
            """var policy = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
               var reader = XmlReader.Create(input, policy);""",
            [],
        ),
        (
            """var policy = new XmlReaderSettings { XmlResolver = new XmlUrlResolver() };
               var reader = XmlReader.Create(input, policy);""",
            [],
        ),
        (
            """var policy = new XmlReaderSettings {
                   DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver()
               };
               return;
               var reader = XmlReader.Create(input, policy);""",
            [],
        ),
        (
            """var policy = new XmlReaderSettings {
                   DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver()
               };
               var reader = AnotherReader.Create(input, policy);""",
            [],
        ),
        (
            """var reader = XmlReader.Create(input, new XmlReaderSettings {
                   DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver()
               });""",
            [4],
        ),
        (
            """var policy = new XmlReaderSettings {
                   DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver()
               };
               using (var reader = XmlReader.Create(input, policy)) { }""",
            [7],
        ),
        (
            """var policy = new XmlReaderSettings {
                   DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver()
               };
               if (enabled) { policy.XmlResolver = null; }
               var reader = XmlReader.Create(input, policy);""",
            [8],
        ),
        (
            """var policy = new XmlReaderSettings {
                   DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver()
               };
               System.Action prepare = () => XmlReader.Create(input, policy);""",
            [],
        ),
        (
            """var policy = new XmlReaderSettings {
                   DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver()
               };
               Configure(policy);
               var reader = XmlReader.Create(input, policy);""",
            [],
        ),
        (
            """var policy = new XmlReaderSettings();
               if (enabled) { policy.DtdProcessing = DtdProcessing.Parse; }
               if (!enabled) { policy.XmlResolver = new XmlUrlResolver(); }
               var reader = XmlReader.Create(input, policy);""",
            [],
        ),
        (
            """var policy = new XmlReaderSettings();
               if (enabled) { policy.DtdProcessing = DtdProcessing.Parse; }
               else { policy.XmlResolver = new XmlUrlResolver(); }
               var reader = XmlReader.Create(input, policy);""",
            [],
        ),
    ],
)
def test_settings_reach_native_reader(body, lines):
    source = (
        "using System.Xml;\nclass DocumentParser {\n"
        "    void Parse(System.IO.TextReader input, bool enabled) {\n"
        f"        {body}\n    }}\n}}\n"
    )
    rows = scan_danger("DocumentParser.cs", source)
    assert [
        (row["rule_id"], row["line"]) for row in rows if row["rule_id"] == "SKY-D236"
    ] == [("SKY-D236", line) for line in lines]


def test_resolves_aliases_and_ignores_local_provider():
    source = """using Reader = global::System.Xml.XmlReader;
using X = System.Xml;
class XmlReader { public static void Create(object a, object b) {} }
class DocumentParser {
    void Parse(System.IO.TextReader input) {
        var settings = new X.XmlReaderSettings {
            DtdProcessing = X.DtdProcessing.Parse, XmlResolver = new X.XmlUrlResolver()
        };
        Reader.Create(input, settings);
        XmlReader.Create(input, settings);
    }
}"""
    assert [
        (row["rule_id"], row["line"])
        for row in scan_danger("DocumentParser.cs", source)
    ] == [("SKY-D236", 9)]
