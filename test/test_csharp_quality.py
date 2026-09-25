from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.visitors.languages.csharp import scan_csharp_file
from skylos.visitors.languages.csharp.quality import scan_quality


def test_csharp_unreachable_after_direct_block_terminators():
    source = """class Example {
  void A() { return; Work(); }
  void B() { throw new Exception(); Work(); }
  void C() { while (true) { break; Work(); } }
  void D() { while (true) { continue; Work(); } }
}
"""

    findings = scan_quality("Example.cs", source)

    assert [finding["rule_id"] for finding in findings] == ["SKY-UC002"] * 4
    assert [finding["line"] for finding in findings] == [2, 3, 4, 5]
    assert [finding["message"] for finding in findings] == [
        "Unreachable code after return.",
        "Unreachable code after throw.",
        "Unreachable code after break.",
        "Unreachable code after continue.",
    ]


def test_csharp_quality_skips_conditional_exits_comments_and_strings():
    source = """class Example {
  void A(bool value) { if (value) return; Work(); }
  void B(bool value) { if (value) { return; } Work(); }
  string C() { return "return; Work();"; }
  void D() { // return; Work();
    Work();
  }
  void E() { return; // Work();
  }
}"""

    assert scan_quality("Example.cs", source) == []


def test_csharp_unreachable_after_return_with_object_initializer():
    source = """class Example {
  object A() {
    return new { Value = 1 };
    Work();
  }
}
"""

    findings = scan_quality("Example.cs", source)

    assert len(findings) == 1
    assert findings[0]["line"] == 4
    assert findings[0]["col"] == 4


def test_csharp_quality_respects_switch_and_goto_labels():
    source = """class Example {
  void A(int value) {
    switch (value) {
      case 1: Work(); break;
      case 2: Work(); break;
      default: Work(); break;
    }
  }
  void B() { goto Again; return; Again: Work(); }
}
"""

    assert scan_quality("Example.cs", source) == []


def test_csharp_quality_does_not_merge_conditional_compilation_branches():
    source = """class Example {
  void A() {
#if DEBUG
    return;
#else
    Work();
#endif
  }
}
"""

    assert scan_quality("Example.cs", source) == []


def test_csharp_quality_flag_and_analyzer_routing(tmp_path: Path):
    file_path = tmp_path / "Example.cs"
    file_path.write_text("public class Example { public void A() { return; Work(); } }")

    enabled = scan_csharp_file(str(file_path), {}, enable_quality_rules=True)
    disabled = scan_csharp_file(str(file_path), {}, enable_quality_rules=False)
    result = json.loads(analyze(str(tmp_path), conf=0, enable_quality=True))

    assert [item["rule_id"] for item in enabled[6]] == ["SKY-UC002"]
    assert disabled[6] == []
    assert [item["rule_id"] for item in result["quality"]].count("SKY-UC002") == 1
