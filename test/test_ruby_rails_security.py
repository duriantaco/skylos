"""Exercise native Rails request findings through the Ruby file and project paths."""

import json

import pytest

from skylos.visitors.languages.ruby import scan_ruby_file


def controller(method_body, *, base="ApplicationController", declarations=""):
    return f"""{declarations}
class ExportsController < {base}
  def show
    {method_body}
  end
end
"""


def scan(tmp_path, source):
    path = tmp_path / "controller.rb"
    path.write_text(source, encoding="utf-8")
    result = scan_ruby_file(str(path), _include_analysis_metadata=True)
    assert result[25] is None
    return result


@pytest.mark.parametrize(
    ("operation", "rule"),
    [
        (
            'statement = "select " + params[:field]\n    ActiveRecord::Base.connection.execute(statement)',
            "SKY-D211",
        ),
        ("Report.where(params[:filter])", "SKY-D211"),
        ("Report.find_by_sql(params[:query])", "SKY-D211"),
        ("Net::HTTP.get(URI(request.query_parameters[:destination]))", "SKY-D216"),
        (
            "address = URI.parse(params[:destination])\n    Net::HTTP.get_response(address)",
            "SKY-D216",
        ),
        ("URI.open(params[:destination])", "SKY-D216"),
    ],
)
def test_request_flows(tmp_path, operation, rule):
    result = scan(
        tmp_path,
        controller(operation, declarations="class Report < ApplicationRecord; end"),
    )
    assert [f["rule_id"] for f in result[7]] == [rule]
    assert result[7][0]["source"] == "Rails request parameters"
    assert result[4].security_coverage["checked_sinks"] == 1


@pytest.mark.parametrize(
    "operation",
    [
        'Report.where("name = ?", params[:name])',
        'Report.find_by_sql(["select * from reports where name = ?", params[:name]])',
        "Report.where(name: params[:name])",
        'Net::HTTP.get(URI("https://docs.example/items/#{params[:id]}"))',
        'URI.open("https://docs.example/items/" + params[:id])',
        "Cache.get(params[:id])",
        "Schedule.where(params[:day])",
        "AuditLog.execute(params[:query])",
    ],
)
def test_safe_and_unproven_flows(tmp_path, operation):
    assert (
        scan(
            tmp_path,
            controller(operation, declarations="class Report < ApplicationRecord; end"),
        )[7]
        == []
    )


def test_visible_controller_and_provider_redefinitions(tmp_path):
    source = """
class ActionController::Base; end
class Custom < ActionController::Base
  def show; URI.open(params[:p]); end
end
class OverrideController < ApplicationController
  def params; {}; end
  def show; Net::HTTP.get(URI(params[:target])); end
end
class Local
  def read(params); URI.open(params[:url]); end
end
"""
    assert scan(tmp_path, source)[7] == []


def test_local_uri_constant_is_not_the_standard_provider(tmp_path):
    source = """
class LabelsController < ApplicationController
  URI = Class.new do
    def self.open(label)
      label
    end
  end

  def show
    URI.open(params[:label])
  end
end
"""
    assert scan(tmp_path, source)[7] == []


@pytest.mark.parametrize(
    "assignment",
    [
        'url = "https://docs.example/topics/" + params[:topic] + ".html"',
        '''if show_index?
      url = "https://docs.example/topics/index.html"
    else
      url = "https://docs.example/topics/" + params[:topic]
    end''',
        '''if show_index?
      url = "https://docs.example/topics/index/"
    else
      url = "https://docs.example/topics/guide/"
    end
    url += params[:topic]''',
    ],
)
def test_fixed_origin_survives_url_concatenation_and_branch_join(tmp_path, assignment):
    result = scan(tmp_path, controller(f"{assignment}\n    Net::HTTP.get(URI(url))"))
    assert result[7] == []
    assert result[4].security_coverage["checked_sinks"] == 1


def test_project_scan_reports_only_the_parameter_controlled_destination(tmp_path):
    from skylos.analyzer import analyze

    scan(
        tmp_path,
        controller(
            'URI.open(params[:url])\n    URI.open("https://docs.example/")',
            base="ActionController::API",
        ),
    )
    report = json.loads(analyze(str(tmp_path), conf=0, enable_danger=True))
    assert not report["analysis_errors"]
    assert [f["rule_id"] for f in report["danger"]] == ["SKY-D216"]
    assert report["analysis_summary"]["ruby_security_coverage"][0]["checked_sinks"] == 2
