from __future__ import annotations

import pytest

from skylos.visitors.languages.csharp._lex import mask_comments_and_strings
from skylos.visitors.languages.csharp.danger import scan_danger
from skylos.visitors.languages.csharp.quality import scan_quality


@pytest.mark.parametrize(
    "literal",
    [
        '"""return; Process.Start(data); class Ghost {} // not a comment"""',
        '"""\nreturn;\nProcess.Start(data);\nclass Ghost {}\n"""',
        '"""Contains a quote: " and two quotes: ""; return;"""',
        '""""Contains three quotes: """; return;""""',
        '$"""return; Process.Start(data); {data}"""',
        '$$"""return; Process.Start(data); {{data}}"""',
    ],
)
def test_raw_literals_mask_as_a_whole_and_preserve_offsets(literal):
    source = f"var value = {literal};\nProcess.Start(data);"

    masked = mask_comments_and_strings(source)

    assert len(masked) == len(source)
    assert [index for index, char in enumerate(masked) if char == "\n"] == [
        index for index, char in enumerate(source) if char == "\n"
    ]
    assert masked[: len("var value = ")] == "var value = "
    assert (
        masked[len("var value = ") : len("var value = ") + len(literal)].strip() == ""
    )
    assert masked.endswith(";\nProcess.Start(data);")


def test_raw_string_code_like_text_does_not_create_quality_or_security_findings():
    source = '''public class Runner {
  public void Run(string data) {
    var text = """
return;
Process.Start(data);
""";
    Process.Start("dotnet");
  }
}'''

    assert scan_quality("Runner.cs", source) == []
    assert scan_danger("Runner.cs", source) == []


def test_interpolated_raw_holes_are_conservatively_masked_for_now():
    # Raw interpolation expression analysis is not implemented. The lexer must
    # not expose template text as C# statements or claim to analyze its holes.
    source = '$$"""Process.Start(data); {{data}}"""'

    assert mask_comments_and_strings(source) == " " * len(source)


@pytest.mark.parametrize("literal", ['$"""tool {data}"""', '$$"""tool {{data}}"""'])
def test_security_scan_does_not_misparse_raw_interpolation_holes(literal):
    # Known coverage gap: taint in interpolated raw holes is not analyzed yet.
    # The lexer must not treat raw text as an ordinary interpolated string.
    source = f"public class Runner {{ void Run(string data) {{ Process.Start({literal}); }} }}"

    assert scan_danger("Runner.cs", source) == []


def test_nested_literal_in_raw_interpolation_does_not_end_outer_literal():
    source = 'var text = $$"""{{"""return;"""}} Process.Start(data);""";\nWork();'

    masked = mask_comments_and_strings(source)

    assert (
        masked
        == "var text = "
        + " " * (source.index(";\nWork();") - len("var text = "))
        + ";\nWork();"
    )


def test_raw_delimiter_inside_other_string_is_not_a_raw_opener():
    source = 'var text = @"She said """" hi";\nWork();'

    masked = mask_comments_and_strings(source)

    assert len(masked) == len(source)
    assert masked.endswith(";\nWork();")


def test_long_dollar_run_without_raw_delimiter_is_preserved():
    source = "$" * 10_000

    assert mask_comments_and_strings(source) == source


def test_regular_interpolated_string_holes_still_reach_security_scan():
    source = 'public class Runner { public void Run(string data) { Process.Start($"tool {data}"); } }'

    assert [finding["rule_id"] for finding in scan_danger("Runner.cs", source)] == [
        "SKY-D212"
    ]
