"""Top-level release preflight dispatch and CI exit behavior."""

from __future__ import annotations

import io
import json

import pytest
from rich.console import Console

import skylos.cli as cli
from skylos.commands import preflight_cmd
from skylos.commands.preflight_cmd import run_preflight_command


IMAGE = "registry.example.com/team/app@sha256:" + "a" * 64


def _payload(status: str) -> dict:
    checks = []
    if status == "PASS":
        checks.append({"id": "artifact_identity", "status": "PASS"})
    return {
        "schema_version": 1,
        "kind": "gpu_artifact_preflight",
        "status": status,
        "artifact": {
            "reference": IMAGE,
            "identity": "sha256:" + "a" * 64,
            "identity_verified": True,
        },
        "profile": {},
        "inventory": {},
        "targets": [
            {
                "name": "t4",
                "status": status,
                "checks": checks,
                "reasons": [],
                "evidence": [],
            }
        ],
        "errors": [],
    }


@pytest.mark.parametrize(
    ("status", "expected_exit"),
    [("PASS", 0), ("FAIL", 1), ("UNKNOWN", 2)],
)
def test_preflight_status_has_ci_safe_exit_code(
    tmp_path, monkeypatch, capsys, status, expected_exit
):
    monkeypatch.chdir(tmp_path)
    calls = []

    def fake_preflight(target, *, project_root):
        calls.append((target, project_root))
        return _payload(status)

    exit_code = run_preflight_command(
        [IMAGE],
        run_preflight_func=fake_preflight,
    )

    assert exit_code == expected_exit
    assert calls == [(IMAGE, tmp_path.resolve())]
    assert json.loads(capsys.readouterr().out) == _payload(status)


def test_preflight_without_argument_defers_to_release_receipt_discovery(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    calls = []

    def fake_preflight(target, *, project_root):
        calls.append((target, project_root))
        return _payload("UNKNOWN")

    assert run_preflight_command([], run_preflight_func=fake_preflight) == 2
    assert calls == [(None, tmp_path.resolve())]
    assert json.loads(capsys.readouterr().out)["status"] == "UNKNOWN"


def test_main_dispatches_preflight_as_a_top_level_command(monkeypatch):
    from skylos.commands import preflight_cmd

    calls = []

    def fake_command(argv, *, console_factory):
        calls.append((argv, console_factory))
        return 2

    monkeypatch.setattr(preflight_cmd, "run_preflight_command", fake_command)
    monkeypatch.setattr(cli.sys, "argv", ["skylos", "preflight", IMAGE])

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2
    assert calls == [([IMAGE], cli.Console)]


@pytest.mark.parametrize(
    "payload",
    [
        {**_payload("PASS"), "schema_version": 2},
        {**_payload("PASS"), "schema_version": True},
        {
            key: value
            for key, value in _payload("PASS").items()
            if key != "schema_version"
        },
        {**_payload("PASS"), "kind": "other"},
        {key: value for key, value in _payload("PASS").items() if key != "kind"},
        {**_payload("PASS"), "status": "pass"},
        {**_payload("PASS"), "status": "passed"},
        {**_payload("PASS"), "status": "ok"},
        {**_payload("PASS"), "status": ["PASS"]},
        {**_payload("PASS"), "artifact": "not-an-object"},
        {**_payload("PASS"), "profile": "not-an-object"},
        {**_payload("PASS"), "inventory": "not-an-object"},
        {**_payload("PASS"), "targets": "not-a-list"},
        {**_payload("PASS"), "targets": ["not-an-object"]},
        {
            **_payload("PASS"),
            "targets": [{"name": "t4", "status": "pass"}],
        },
        {
            **_payload("PASS"),
            "targets": [{"name": "t4", "status": {"value": "PASS"}}],
        },
        {
            **_payload("PASS"),
            "targets": [
                {
                    "name": "t4",
                    "status": "PASS",
                    "checks": [{"id": "identity", "status": "pass"}],
                }
            ],
        },
        {
            **_payload("PASS"),
            "targets": [
                {
                    "name": "t4",
                    "status": "PASS",
                    "checks": [{"id": "identity", "status": ["PASS"]}],
                }
            ],
        },
        {**_payload("PASS"), "errors": "not-a-list"},
    ],
    ids=[
        "wrong-schema",
        "boolean-schema",
        "missing-schema",
        "wrong-kind",
        "missing-kind",
        "lower-status",
        "status-alias-passed",
        "status-alias-ok",
        "non-string-status",
        "artifact-not-object",
        "profile-not-object",
        "inventory-not-object",
        "targets-not-list",
        "target-not-object",
        "lower-target-status",
        "non-string-target-status",
        "lower-check-status",
        "non-string-check-status",
        "errors-not-list",
    ],
)
def test_invalid_report_schema_is_rejected_before_json_output(payload, capsys):
    assert (
        run_preflight_command(
            [IMAGE],
            run_preflight_func=lambda *_args, **_kwargs: payload,
        )
        == 2
    )

    output = capsys.readouterr().out
    assert "invalid report" in output
    assert not output.lstrip().startswith("{")


@pytest.mark.parametrize(
    "payload",
    [
        {**_payload("PASS"), "targets": []},
        {
            **_payload("PASS"),
            "targets": [{"name": "t4", "status": "FAIL"}],
        },
        {
            **_payload("PASS"),
            "targets": [{"name": "t4", "status": "UNKNOWN"}],
        },
        {
            **_payload("PASS"),
            "errors": [{"code": "incomplete", "message": "missing proof"}],
        },
        {
            **_payload("PASS"),
            "artifact": {
                **_payload("PASS")["artifact"],
                "identity_verified": False,
            },
        },
        {
            **_payload("PASS"),
            "artifact": {
                **_payload("PASS")["artifact"],
                "identity": "",
            },
        },
        {
            **_payload("PASS"),
            "artifact": {
                **_payload("PASS")["artifact"],
                "identity": 123,
            },
        },
        {
            **_payload("PASS"),
            "targets": [{"name": "t4", "status": "PASS"}],
        },
        {
            **_payload("PASS"),
            "targets": [{"name": "t4", "status": "PASS", "checks": []}],
        },
        {
            **_payload("PASS"),
            "targets": [
                {
                    "name": "t4",
                    "status": "PASS",
                    "checks": [{"id": "platform", "status": "PASS"}],
                }
            ],
        },
        {
            **_payload("PASS"),
            "targets": [
                {
                    "name": "t4",
                    "status": "PASS",
                    "checks": [{"id": "identity", "status": "UNKNOWN"}],
                }
            ],
        },
        {
            **_payload("FAIL"),
            "targets": [{"name": "t4", "status": "PASS"}],
        },
        {
            **_payload("UNKNOWN"),
            "targets": [{"name": "t4", "status": "FAIL"}],
        },
        {
            **_payload("UNKNOWN"),
            "targets": [{"name": "t4", "status": "PASS"}],
        },
    ],
    ids=[
        "pass-without-targets",
        "pass-with-failed-target",
        "pass-with-unknown-target",
        "pass-with-errors",
        "pass-with-unverified-identity",
        "pass-with-empty-identity",
        "pass-with-non-string-identity",
        "pass-without-checks",
        "pass-with-empty-checks",
        "pass-without-artifact-identity-check",
        "pass-with-unknown-check",
        "fail-without-failed-target",
        "unknown-with-failed-target",
        "unknown-with-only-passed-targets",
    ],
)
def test_inconsistent_report_cannot_return_success(payload, capsys):
    assert (
        run_preflight_command(
            [IMAGE],
            run_preflight_func=lambda *_args, **_kwargs: payload,
        )
        == 2
    )
    assert "invalid report" in capsys.readouterr().out


def test_tty_rendering_neutralizes_controls_newlines_and_markup(
    tmp_path, monkeypatch
):
    class TtyBuffer(io.StringIO):
        def isatty(self):
            return True

    stream = TtyBuffer()
    console = Console(file=stream, force_terminal=False, width=240)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(preflight_cmd.sys, "stdout", stream)
    payload = _payload("UNKNOWN")
    payload["artifact"] = {
        "reference": "artifact\nforged\x1b[31m",
        "identity": "sha256:abc\ridentity",
        "identity_verified": False,
    }
    payload["targets"] = [
        {
            "name": "target\nforged\x9b31m",
            "status": "UNKNOWN",
            "platform": "linux/amd64\tforged",
            "checks": [
                {
                    "id": "identity\ncheck",
                    "status": "UNKNOWN",
                    "message": "line one\r\nline two\x00[red]literal[/red]",
                }
            ],
            "reasons": [
                "reason\nforged\x85next bidi\u202eforged [red]literal[/red]"
            ],
            "evidence": [
                {
                    "kind": "cubin\nkind",
                    "value": "sm_75\x1b[2J",
                    "source": "binary\tname",
                }
            ],
        }
    ]
    payload["errors"] = [
        {"code": "bad\ncode", "message": "detail\rforged\x00"}
    ]

    assert (
        run_preflight_command(
            [IMAGE],
            console_factory=lambda: console,
            run_preflight_func=lambda *_args, **_kwargs: payload,
        )
        == 2
    )

    rendered = stream.getvalue()
    assert any("artifact forged" in line for line in rendered.splitlines())
    assert any("target forged" in line for line in rendered.splitlines())
    assert any("identity check" in line for line in rendered.splitlines())
    assert "[red]literal[/red]" in rendered
    for control in ("\x00", "\x1b", "\x85", "\x9b", "\r", "\t", "\u202e"):
        assert control not in rendered
    for escaped_control in ("\\x00", "\\x1b", "\\x85", "\\x9b", "\\u202e"):
        assert escaped_control in rendered
