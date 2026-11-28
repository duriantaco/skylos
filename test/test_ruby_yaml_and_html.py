"""Exercise native unsafe deserialization and Rails HTML output proof."""

import pytest

from skylos.visitors.languages.ruby import scan_ruby_file


def scan(tmp_path, source):
    path = tmp_path / "example.rb"
    path.write_text(source, encoding="utf-8")
    return scan_ruby_file(str(path))[7]


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("require 'yaml'\nYAML.unsafe_load(STDIN.read)", [(2, "use")]),
        (
            "require 'psych'\nReader = ::Psych\nReader.unsafe_load(ARGV[0])",
            [(3, "use")],
        ),
        ("require 'psych'\nPsych.unsafe_load(value)", [(2, "review")]),
        ("require 'psych'\nPsych.unsafe_load('mode: default')", []),
        ("require 'yaml'\nYAML.safe_load(ARGV[0])\nYAML.load(ARGV[0])", []),
        (
            "require 'psych'\nmodule Other\n  Psych = Object.new\n  Psych.unsafe_load(ARGV[0])\nend",
            [],
        ),
        (
            "class Psych\n  def self.unsafe_load(value); end\nend\nPsych.unsafe_load(ARGV[0])",
            [],
        ),
    ],
)
def test_explicit_unsafe_load(tmp_path, body, expected):
    rows = [row for row in scan(tmp_path, body) if row["rule_id"] == "SKY-D206"]
    assert [
        (row["line"], row["metadata"]["security_evidence"]["assessment"])
        for row in rows
    ] == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("render html: params[:label].html_safe", [3]),
        (
            "value = helpers.raw(request.query_parameters[:label])\n    render html: value",
            [4],
        ),
        ("render html: params[:label]", []),
        ("render html: helpers.sanitize(params[:label]).html_safe", []),
        ("render html: view_context.raw(helpers.html_escape(params[:label]))", []),
        ("render html: params[:label].html_safe if false", []),
        ("value = params[:label].html_safe\n    render plain: value", []),
        ("value = params[:label].html_safe\n    render html: 'fixed'", []),
        ("render html: object.raw(params[:label])", []),
        ("render html: 'fixed'.html_safe", []),
    ],
)
def test_only_request_data_rendered_as_raw_html(tmp_path, body, expected):
    source = f"class PageController < ApplicationController\n  def show\n    {body}\n  end\nend\n"
    rows = [row for row in scan(tmp_path, source) if row["rule_id"] == "SKY-D226"]
    assert [row["line"] for row in rows] == expected


def test_rails_yaml_replaces_unproven_review_with_request_evidence(tmp_path):
    source = """require 'yaml'
class SettingsController < ApplicationController
  def show
    value = params[:preferences]
    ::YAML.unsafe_load(value)
  end
end
"""
    rows = [row for row in scan(tmp_path, source) if row["rule_id"] == "SKY-D206"]
    assert len(rows) == 1
    assert rows[0]["line"] == 5
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["metadata"]["security_evidence"]["sources"] == [
        "Rails request parameters"
    ]
