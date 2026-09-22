import pytest

import skylos.cli as cli


@pytest.mark.parametrize("subcommand", ["scan", "remediate", "verify"])
def test_agent_parser_common_runtime_defaults(subcommand):
    parser = cli._build_agent_parser()
    args = parser.parse_args([subcommand, "."])

    assert args.model == cli.DEFAULT_AGENT_MODEL
    assert args.provider is None
    assert args.base_url is None


@pytest.mark.parametrize("subcommand", ["scan", "remediate", "verify"])
def test_agent_parser_common_runtime_flags_round_trip(subcommand):
    parser = cli._build_agent_parser()
    args = parser.parse_args(
        [
            subcommand,
            ".",
            "--model",
            "claude-sonnet-4-20250514",
            "--provider",
            "anthropic",
            "--base-url",
            "https://custom.endpoint",
        ]
    )

    assert args.model == "claude-sonnet-4-20250514"
    assert args.provider == "anthropic"
    assert args.base_url == "https://custom.endpoint"


@pytest.mark.parametrize("subcommand", ["scan", "verify"])
def test_agent_parser_jev_modes_are_opt_in_and_exclusive(subcommand):
    parser = cli._build_agent_parser()
    defaults = parser.parse_args([subcommand, "."])
    assert defaults.dead_code_review == "llm"
    assert defaults.jev_precheck is False
    assert defaults.jev_judge is False

    for mode in ("llm", "jev", "jev-llm"):
        selected = parser.parse_args(
            [subcommand, ".", "--dead-code-review", mode]
        )
        assert selected.dead_code_review == mode

    judge = parser.parse_args([subcommand, ".", "--jev-judge"])
    assert judge.jev_judge is True
    assert judge.jev_precheck is False

    precheck = parser.parse_args([subcommand, ".", "--jev-precheck"])
    assert precheck.jev_precheck is True
    assert precheck.jev_judge is False

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(
            [subcommand, ".", "--jev-judge", "--jev-precheck"]
        )
    assert exc.value.code == 2

    with pytest.raises(SystemExit) as exc:
        parser.parse_args(
            [subcommand, ".", "--dead-code-review", "jev", "--jev-judge"]
        )
    assert exc.value.code == 2
