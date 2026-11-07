"""Independent syntax-only Ruby boundary reproductions and negative controls."""

import pytest

from skylos.visitors.languages.ruby import scan_ruby_file


def _scan(tmp_path, source):
    path = tmp_path / "main.rb"
    path.write_text(source, encoding="utf-8")
    result = scan_ruby_file(str(path), _include_analysis_metadata=True)
    assert result[25] is None
    return result


@pytest.mark.parametrize(
    ("source", "count"),
    [
        ('payload="fixed"\npayload ||= ARGV[0]\nKernel.system(payload)\n', 0),
        ("payload=nil\npayload ||= ARGV[0]\nKernel.system(payload)\n", 1),
        ("payload=false\npayload &&= ARGV[0]\nKernel.system(payload)\n", 0),
        ('payload="fixed"\npayload &&= ARGV[0]\nKernel.system(payload)\n', 1),
        ('payload=ARGV[0]\npayload += " suffix"\nKernel.system(payload)\n', 1),
        ('payload="prefix "\npayload += ARGV[0]\nKernel.system(payload)\n', 1),
        ('payload="prefix"\npayload += " suffix"\nKernel.system(payload)\n', 0),
    ],
)
def test_compound_assignment_preserves_value_and_short_circuit_semantics(
    tmp_path, source, count
):
    result = _scan(tmp_path, source)
    assert len(result[7]) == count


def test_replaced_stdin_global_is_unknown_not_a_demonstrated_source(tmp_path):
    result = _scan(tmp_path, "$stdin=CustomReader\nKernel.system($stdin.read)\n")
    assert result[7] == []
    assert result[4].security_coverage["status"] == "partial"
    assert result[4].security_coverage["unresolved"]


@pytest.mark.parametrize("guard", ["if enabled", "unless enabled", "if false"])
def test_modifier_assignment_cannot_erase_taint_from_unmodified_path(tmp_path, guard):
    result = _scan(
        tmp_path,
        f'payload=ARGV[0]\npayload="fixed" {guard}\nKernel.system(payload)\n',
    )
    assert [finding["rule_id"] for finding in result[7]] == ["SKY-D212"]


def test_absolute_constant_receiver_keeps_exact_global_owner(tmp_path):
    result = _scan(
        tmp_path,
        """class Worker
  private
  def run; 1; end
end
module App
  class Worker
    private
    def run; 2; end
  end
  class Runner
    def go; ::Worker.new.send(:run); end
  end
end
App::Runner.new.go
""",
    )
    references = {name for name, _file in result[1]}
    assert "Worker#run" in references
    assert "App.Worker#run" not in references


def test_lexical_superclass_call_keeps_inherited_method_on_exact_owner(tmp_path):
    result = _scan(
        tmp_path,
        """class Base
  private
  def normalize; 0; end
end
module App
  class Base
    private
    def normalize; 1; end
  end
  class Child < Base
    def render; normalize; end
  end
end
App::Child.new.render
""",
    )
    references = {name for name, _file in result[1]}
    assert "App.Base#normalize" in references
    assert "Base#normalize" not in references
