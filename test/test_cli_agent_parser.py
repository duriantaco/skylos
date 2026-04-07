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
