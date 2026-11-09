from skylos.core.grep_verify import (
    _apply_deterministic_rules,
    _search_verification_evidence,
)
from skylos.core.grep_verify_common import detect_language, source_globs_for_language


def test_csharp_grep_uses_its_language_and_source_glob():
    assert detect_language("Helpers.cs") == "csharp"
    assert source_globs_for_language("csharp") == ["*.cs"]


def test_unrelated_csharp_text_cannot_rescue_a_different_owner():
    finding = {
        "file": "Dead.cs",
        "type": "method",
        "name": "Dead.Hidden",
        "full_name": "Demo.Dead.Hidden",
        "simple_name": "Hidden",
        "line": 1,
    }
    text = {"references": ["Other.cs:3: other.Hidden();", "notes.py:3: Hidden()"]}
    assert _apply_deterministic_rules(text, finding) is None


def test_csharp_grep_does_not_invoke_python_search(monkeypatch, tmp_path):
    import skylos.core.grep_verify as module

    def forbidden(*args, **kwargs):
        raise AssertionError("C# cannot be verified by Python text strategies")

    monkeypatch.setattr(module, "multi_strategy_search", forbidden)
    finding = {
        "file": str(tmp_path / "Dead.cs"),
        "type": "variable",
        "name": "value",
        "simple_name": "value",
    }
    assert _search_verification_evidence(finding, str(tmp_path)) == {}


def test_csharp_text_does_not_rescue_an_unrelated_private_cpp_function(tmp_path):
    from skylos.core.grep_verify_strategies import _run_general_reference_strategies

    source = tmp_path / "dead.cpp"
    source.write_text(
        "static int amberPrivate() { return 1; }\nint main() { return 0; }\n"
    )
    (tmp_path / "Other.cs").write_text(
        "public class Other { public void Run() { client.amberPrivate(); } }\n"
    )
    finding = {
        "file": str(source),
        "line": 1,
        "name": "amberPrivate",
        "full_name": "amberPrivate",
        "simple_name": "amberPrivate",
        "type": "function",
    }
    results = _run_general_reference_strategies(
        finding, str(tmp_path), simple_name="amberPrivate", max_per_strategy=5
    )
    assert _apply_deterministic_rules(results, finding) is None
