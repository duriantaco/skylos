"""The scan accepts --security and answers a mistyped flag with a short hint."""

import json

import skylos.cli as cli


def _main_exit():
    try:
        cli.main()
    except SystemExit as exc:
        return exc.code
    return 0


def test_security_is_an_alias_for_danger(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", str(tmp_path), "--security", "--no-upload"]
    )
    monkeypatch.setattr(cli, "load_config", lambda *_a, **_k: {})
    monkeypatch.setattr(cli, "print_badge", lambda *_a, **_k: None)

    def analyze(*_args, **kwargs):
        seen.update(kwargs)
        return json.dumps({"analysis_summary": {"total_files": 0}})

    monkeypatch.setattr(cli, "run_analyze", analyze)
    _main_exit()

    assert seen.get("enable_danger") is True


def test_misspelled_flag_gets_a_short_hint_instead_of_the_usage(
    monkeypatch, capsys, tmp_path
):
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["skylos", str(tmp_path), "--securty"])

    assert _main_exit() == 2

    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 2
    assert lines[0].endswith(
        ": error: unrecognized arguments: --securty (did you mean --security?)"
    )
    assert lines[1] == "See the scan flags: skylos . --help"


def test_unknown_flag_without_a_close_match_has_no_guess(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("SKYLOS_ADDOPTS", raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["skylos", str(tmp_path), "--zzzz"])

    assert _main_exit() == 2

    err = capsys.readouterr().err
    assert "unrecognized arguments: --zzzz\n" in err
    assert "did you mean" not in err
    assert "usage:" not in err
