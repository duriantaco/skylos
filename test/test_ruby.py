import json
import shutil
from pathlib import Path

import pytest

from skylos.visitors.languages.ruby import scan_ruby_file


FIXTURES = Path(__file__).resolve().parents[1] / "benchmarks"


def scan(tmp_path, source):
    path = tmp_path / "main.rb"
    path.write_text(source, encoding="utf-8")
    return scan_ruby_file(str(path), _include_analysis_metadata=True)


@pytest.mark.parametrize(
    ("fixture", "used", "unused"),
    [
        (
            "ruby_private_chain",
            {"Formatter#render", "Formatter#normalize"},
            {"Formatter#snapshot"},
        ),
        ("ruby_member_owners", {"TextCodec#process"}, {"BinaryCodec#process"}),
        (
            "ruby_callback_owner",
            {"PageController#authorize", "PageController#render_text"},
            {"PageController#preview", "PlainHandler#prepare"},
        ),
    ],
)
def test_ruby_frozen_liveness(fixture, used, unused):
    result = scan_ruby_file(
        str(FIXTURES / "dead_code" / "fixtures" / fixture / "main.rb")
    )
    definitions = {d.name: d for d in result[0]}
    references = {name for name, _file in result[1]}
    assert used <= definitions.keys()
    assert unused <= definitions.keys()
    assert used <= references
    assert not unused & references
    assert all(not definitions[name].is_exported for name in unused)


@pytest.mark.parametrize("fixture", ["ruby_command_shell", "ruby_command_string"])
def test_ruby_frozen_unsafe_commands(fixture):
    result = scan_ruby_file(
        str(FIXTURES / "security" / "fixtures" / fixture / "main.rb")
    )
    assert [f["rule_id"] for f in result[7]] == ["SKY-D212"]
    assert result[4].security_coverage["unresolved"] == []


@pytest.mark.parametrize("fixture", ["ruby_command_argv", "ruby_command_literal"])
def test_ruby_frozen_safe_commands(fixture):
    result = scan_ruby_file(
        str(FIXTURES / "security" / "fixtures" / fixture / "main.rb")
    )
    assert result[7] == []
    assert result[4].security_coverage["checked_sinks"] == 1
    assert result[4].security_coverage["unresolved"] == []


@pytest.mark.parametrize(
    "fixture", ["ruby_command_provider_unknown", "ruby_command_selector_unknown"]
)
def test_ruby_unknown_is_not_safe(fixture):
    result = scan_ruby_file(
        str(FIXTURES / "security" / "fixtures" / fixture / "main.rb")
    )
    assert result[7] == []
    assert result[4].security_coverage["status"] == "partial"
    assert result[4].security_coverage["unresolved"]


def test_ruby_read_and_syntax_errors_are_visible(tmp_path):
    missing = scan_ruby_file(
        str(tmp_path / "missing.rb"), _include_analysis_metadata=True
    )
    assert len(missing) == 28
    assert missing[25]["kind"] == "source_read_error"
    broken = scan(tmp_path, "class Broken\n def method(\n")
    assert broken[25]["kind"] == "syntax_error"
    empty = scan(tmp_path, "# definitions in comments do not count\n")
    assert empty[0] == []
    assert empty[25] is None


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("ruby_private_chain", {"Formatter#snapshot"}),
        ("ruby_member_owners", {"BinaryCodec#process"}),
        ("ruby_callback_owner", {"PageController#preview", "PlainHandler#prepare"}),
    ],
)
def test_ruby_native_analyzer_with_default_grep(tmp_path, fixture, expected):
    from skylos.analyzer import analyze

    root = tmp_path / "source"
    shutil.copytree(FIXTURES / "dead_code" / "fixtures" / fixture, root)
    result = json.loads(analyze(str(root), conf=0))
    assert not result["analysis_errors"]
    assert result["analysis_summary"]["languages"] == {"Ruby": 1}
    assert {f["full_name"] for f in result["unused_functions"]} == expected
    assert result["unused_classes"] == []


@pytest.mark.parametrize(
    "source",
    [
        'payload = ARGV[0]\nKernel.exec("sh", "-c", payload)\n',
        'payload = STDIN.read\nKernel.spawn("sh", "-c", payload)\n',
        "payload = ARGV[0]\n`echo #{payload}`\n",
        'payload = "echo " + ARGV[0]\nKernel.system(payload)\n',
        'if enabled\n payload = ARGV[0]\nelse\n payload = "fixed"\nend\nKernel.system(payload)\n',
        'if enabled\n payload = "fixed"\nelse\n payload = ARGV[0]\nend\nKernel.system(payload)\n',
        'payload = ARGV[0]\nKernel.system(payload, "data")\n',
    ],
)
def test_ruby_command_sources_and_branches(tmp_path, source):
    result = scan(tmp_path, source)
    assert result[25] is None
    assert [f["rule_id"] for f in result[7]] == ["SKY-D212"]


@pytest.mark.parametrize(
    "source",
    [
        'payload = ARGV[0]\npayload = "fixed"\nKernel.system(payload)\n',
        "Kernel.system(\"echo #{ARGV[0] == 'yes'}\")\n",
        "text = %q{Kernel.system(ARGV[0])}\n# Kernel.system(ARGV[0])\n",
        "class Runner\n def self.system(value); value; end\nend\nRunner.system(ARGV[0])\n",
        "text = <<~TEXT\nKernel.system(ARGV[0])\nTEXT\n",
    ],
)
def test_ruby_command_negative_controls(tmp_path, source):
    result = scan(tmp_path, source)
    assert result[25] is None
    assert result[7] == []


@pytest.mark.parametrize(
    "source",
    [
        'require_relative "patch"\nKernel.system(ARGV[0])\n',
        "Kernel = MyRunner\nKernel.system(ARGV[0])\n",
        'ARGV = ["fixed"]\nKernel.system(ARGV[0])\n',
        "module App\n module Kernel; end\n Kernel.system(ARGV[0])\nend\n",
        "def execute(command)\n Kernel.system(command)\nend\n",
        'Kernel.system("tool", ARGV[0])\n',
        "Kernel.system(*ARGV)\n",
        "runner = Kernel\nrunner.system(ARGV[0])\n",
        "runner = Kernel\nrunner = Custom\nrunner.system(ARGV[0])\n",
        "Kernel.method(:system).call(ARGV[0])\n",
        "class String\n def to_s; 'fixed'; end\nend\nKernel.system(ARGV[0].to_s)\n",
    ],
)
def test_ruby_provider_and_flow_uncertainty_is_visible(tmp_path, source):
    result = scan(tmp_path, source)
    assert result[25] is None
    assert result[7] == []
    assert result[5].security_coverage["status"] == "partial"
    assert result[5].security_coverage["unresolved"]


def test_ruby_relative_loaded_override_stays_unknown(tmp_path):
    (tmp_path / "patch.rb").write_text(
        "module Kernel\n def self.system(*args); args; end\nend\n"
    )
    result = scan(tmp_path, 'require_relative "patch"\nKernel.system(ARGV[0])\n')
    assert result[7] == []
    assert result[12] == [{"source": "patch", "names": [], "line": 1}]
    assert result[5].security_coverage["unresolved"]


def test_ruby_unknown_reaches_native_summary(tmp_path):
    from skylos.analyzer import analyze

    scan(tmp_path, "Kernel.public_send(ARGV[0], ARGV[1])\n")
    result = json.loads(analyze(str(tmp_path), conf=0, enable_danger=True))
    coverage = result["analysis_summary"]["ruby_security_coverage"]
    assert len(coverage) == 1
    assert coverage[0]["status"] == "partial"
    assert coverage[0]["unresolved"]
    assert result.get("danger", []) == []


def test_ruby_parser_unavailable_is_incomplete(tmp_path, monkeypatch):
    from skylos.visitors.languages.ruby import core

    monkeypatch.setattr(core, "tree_sitter_ruby", None)
    result = scan(tmp_path, "class Service; end\n")
    assert result[0] == []
    assert result[25]["kind"] == "parser_unavailable"


def test_ruby_visibility_singletons_and_namespaces(tmp_path):
    result = scan(
        tmp_path,
        """module App
class Service
  def self.publish; 1; end
  private def helper; 2; end
  def hidden; 3; end
  private :hidden
  class << self
    private
    def internal; 4; end
  end
end
end
App::Service.publish
""",
    )
    definitions = {d.name: d for d in result[0]}
    assert definitions["App.Service.publish"].is_exported
    assert not definitions["App.Service#helper"].is_exported
    assert not definitions["App.Service#hidden"].is_exported
    assert not definitions["App.Service.internal"].is_exported
    assert "App.Service.publish" in {name for name, _ in result[1]}


def test_ruby_literal_and_dynamic_dispatch_preserve_only_receiver_owner(tmp_path):
    result = scan(
        tmp_path,
        """class Used
  def run(name)
    send(:literal)
    send(name)
  end
  private
  def literal; 1; end
  def dynamic; 2; end
end
class Other
  private
  def dynamic; 3; end
end
Used.new.run(ARGV[0])
""",
    )
    references = {name for name, _ in result[1]}
    assert {"Used#literal", "Used#dynamic"} <= references
    assert "Other#dynamic" not in references
    assert result[4].deadcode_coverage["unresolved"]


def test_ruby_rails_callback_block_and_dynamic_selector(tmp_path):
    result = scan(
        tmp_path,
        """class Controller < ActionController::Base
  before_action { authorize }
  private
  def authorize; 1; end
  def abandoned; 2; end
end
class DynamicController < ActionController::Base
  callback = :prepare
  before_action callback
  private
  def prepare; 1; end
end
""",
    )
    references = {name for name, _ in result[1]}
    assert {"Controller#authorize", "DynamicController#prepare"} <= references
    assert "Controller#abandoned" not in references


@pytest.mark.parametrize(
    "prefix", ["module ActionController; class Base; end; end\n", ""]
)
def test_ruby_rails_macro_override_and_namespace_lookalike(tmp_path, prefix):
    override = "" if prefix else "def self.before_action(name); name; end"
    result = scan(
        tmp_path,
        prefix
        + f"""class Controller < ActionController::Base
  {override}
  before_action :prepare
  private
  def prepare; 1; end
end
""",
    )
    assert "Controller#prepare" not in {name for name, _ in result[1]}


def test_ruby_self_recursion_is_not_a_root(tmp_path):
    from skylos.analyzer import analyze

    scan(
        tmp_path,
        "class Service\n private\n def recursive; recursive; end\nend\nService.new\n",
    )
    result = json.loads(analyze(str(tmp_path), conf=0))
    assert {f["full_name"] for f in result["unused_functions"]} == {"Service#recursive"}


def test_ruby_directives_only_come_from_ast_comments(tmp_path):
    result = scan(
        tmp_path,
        """text = %q{# skylos: ignore}
text = <<~TEXT
# skylos: ignore
TEXT
Kernel.system(ARGV[0]) # skylos: ignore[SKY-D212]
""",
    )
    assert result[13] == set()
    assert result[26] == {5: {"SKY-D212"}}
    assert result[7] == []
    assert len(result[14]) == 1


@pytest.mark.parametrize(
    ("source", "active", "suppressed"),
    [
        ("Kernel.system(ARGV[0]) # skylos: ignore[SKY-D212]\n", 0, 1),
        ("text = %q{# skylos: ignore}\nKernel.system(ARGV[0])\n", 1, 0),
        ("text = <<~TEXT\n# skylos: ignore\nTEXT\nKernel.system(ARGV[0])\n", 1, 0),
    ],
)
def test_ruby_native_directive_partition(tmp_path, source, active, suppressed):
    from skylos.analyzer import analyze

    scan(tmp_path, source)
    result = json.loads(analyze(str(tmp_path), conf=0, enable_danger=True))
    assert len(result.get("danger", [])) == active
    assert (
        len([f for f in result.get("suppressed", []) if f.get("rule_id") == "SKY-D212"])
        == suppressed
    )


def test_ruby_foreign_names_strings_and_comments_do_not_rescue(tmp_path):
    from skylos.analyzer import analyze

    scan(
        tmp_path,
        """class Service
  private
  def snapshot; 1; end
end
Service.new
text = "snapshot"
# snapshot is only a comment
""",
    )
    (tmp_path / "other.py").write_text(
        "class Other:\n    def snapshot(self):\n        return 1\n\nOther().snapshot()\n"
    )
    result = json.loads(analyze(str(tmp_path), conf=0))
    assert {f["full_name"] for f in result["unused_functions"]} == {"Service#snapshot"}


def test_ruby_required_top_level_call_stays_live(tmp_path):
    from skylos.analyzer import analyze

    (tmp_path / "helper.rb").write_text(
        'def render_page; "ready"; end\ndef abandoned; "old"; end\n'
    )
    scan(tmp_path, 'require_relative "helper"\nrender_page\n')
    result = json.loads(analyze(str(tmp_path), conf=0))
    assert not result["analysis_errors"]
    assert {f["full_name"] for f in result["unused_functions"]} == {"abandoned"}


def test_ruby_source_size_and_symlink_failures_are_visible(tmp_path, monkeypatch):
    import skylos.visitors.languages.ruby as ruby

    monkeypatch.setattr(ruby, "MAX_RUBY_SOURCE_BYTES", 8)
    result = scan(tmp_path, "# too many bytes for the configured limit\n")
    assert result[25]["kind"] == "source_read_error"
    target = tmp_path / "outside.rb"
    target.write_text("# target\n")
    link = tmp_path / "linked.rb"
    link.symlink_to(target)
    result = ruby.scan_ruby_file(str(link), _include_analysis_metadata=True)
    assert result[25]["kind"] == "source_read_error"


@pytest.mark.parametrize(
    "source",
    [
        "payload = ARGV[0]\nclass Service\n Kernel.system(payload)\nend\n",
        "payload = ARGV[0]\nitems.each do |payload|\n Kernel.system(payload)\nend\n",
        'begin\n payload = ARGV[0]\nensure\n payload = "fixed"\nend\nKernel.system(payload)\n',
    ],
)
def test_ruby_unmodeled_scope_or_ensure_is_not_false_command_proof(tmp_path, source):
    result = scan(tmp_path, source)
    assert result[25] is None
    assert result[7] == []
    assert result[5].security_coverage["unresolved"]


@pytest.mark.parametrize("modifier", ["if", "unless"])
def test_ruby_conditional_modifier_preserves_unassigned_path(tmp_path, modifier):
    result = scan(
        tmp_path,
        f'payload = ARGV[0]\npayload = "fixed" {modifier} enabled\nKernel.system(payload)\n',
    )
    assert [f["rule_id"] for f in result[7]] == ["SKY-D212"]


@pytest.mark.parametrize(
    "source",
    [
        'payload="fixed"\npayload ||= Kernel.system(ARGV[0])\n',
        "payload=false\npayload &&= Kernel.system(ARGV[0])\n",
        "payload &&= ARGV[0]\nKernel.system(payload)\n",
    ],
)
def test_ruby_short_circuit_does_not_execute_unused_rhs(tmp_path, source):
    result = scan(tmp_path, source)
    assert result[25] is None
    assert result[7] == []


@pytest.mark.parametrize(
    "source",
    [
        'payload="fixed"\npayload=ARGV[0] if false\nKernel.system(payload)\n',
        'payload="fixed"\npayload=ARGV[0] unless true\nKernel.system(payload)\n',
        "if false\n Kernel.system(ARGV[0])\nend\n",
        "false && Kernel.system(ARGV[0])\n",
        "true || Kernel.system(ARGV[0])\n",
    ],
)
def test_ruby_constant_false_path_is_not_a_command_source(tmp_path, source):
    assert scan(tmp_path, source)[7] == []
