# test_gate_kwargs.py
from skylos.gatekeeper import run_gate_interaction, check_gate
from skylos.constants import parse_exclude_folders


def test_gate_interaction_accepts_kwargs():
    result = {"unused_functions": [], "danger": [], "quality": [], "secrets": []}
    config = {}
    exit_code = run_gate_interaction(
        result=result, config=config, strict=False, force=False
    )
    # no findings = pass
    assert exit_code == 0


def test_gate_interaction_fails_on_positional():
    import pytest

    with pytest.raises(TypeError):
        run_gate_interaction({}, {})


def test_check_gate_strict_with_findings():
    result = {"unused_functions": [{"name": "foo", "file": "x.py", "line": 1}]}
    passed, reasons = check_gate(result, {}, strict=True)
    assert passed is False
    assert "Strict mode" in reasons[0]


def test_check_gate_passes_clean():
    result = {"unused_functions": [], "danger": [], "quality": [], "secrets": []}
    passed, reasons = check_gate(result, {})
    assert passed is True
    assert reasons == []


def test_default_excludes_filter_venv():
    excludes = parse_exclude_folders(use_defaults=True)
    assert "venv" in excludes or ".venv" in excludes
    assert "__pycache__" in excludes
    assert ".git" in excludes


def test_agent_review_respects_excludes(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    venv = tmp_path / "venv" / "lib" / "pkg"
    venv.mkdir(parents=True)
    (venv / "big.py").write_text("y = 2")

    excludes = parse_exclude_folders(use_defaults=True)

    all_py = list(tmp_path.rglob("*.py"))
    filtered = [f for f in all_py if not any(ex in f.parts for ex in excludes)]

    assert len(all_py) == 2
    # venv one is excluded
    assert len(filtered) == 1
    assert filtered[0].name == "app.py"
