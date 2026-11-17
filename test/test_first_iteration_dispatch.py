"""Early-return backend tails are dead; actual or unresolved consumers remain live."""

import pytest

from test.test_blind_repo_dead_code_precision import _backend_channel, _unused


def _project(tmp_path, body, extra=""):
    _backend_channel(
        tmp_path,
        """
from .chan import Chan

def run(channel, target):
    for action in channel.actions:
        for label, method_name in action.backends:
"""
        + "\n".join("            " + line for line in body.splitlines())
        + """

run(Chan(), "x")
"""
        + extra,
    )


def test_unconditional_return_does_not_keep_later_private_backend(tmp_path):
    _project(tmp_path, "return getattr(channel, method_name)(target=target)")
    unused = _unused(tmp_path)
    assert "pkg.chan.Chan._cli_read" not in unused
    assert "pkg.chan.Chan._api_read" in unused
    assert "pkg.chan.Chan._stale" in unused


@pytest.mark.parametrize(
    "body",
    [
        "getattr(channel, method_name)(target=target)",
        "if target:\n    return getattr(channel, method_name)(target=target)",
    ],
)
def test_loop_that_can_visit_later_backends_keeps_them(tmp_path, body):
    _project(tmp_path, body)
    assert "pkg.chan.Chan._api_read" not in _unused(tmp_path)


def test_actual_reference_to_later_backend_survives_exclusion(tmp_path):
    _project(
        tmp_path,
        "return getattr(channel, method_name)(target=target)",
        'Chan()._api_read(target="direct")\n',
    )
    assert "pkg.chan.Chan._api_read" not in _unused(tmp_path)


def test_escaped_backend_rows_have_unknown_consumers_and_keep_evidence(tmp_path):
    _project(
        tmp_path,
        "return getattr(channel, method_name)(target=target)",
        "print(Chan().actions)\n",
    )
    assert "pkg.chan.Chan._api_read" not in _unused(tmp_path)


def test_other_opaque_lookup_keeps_existing_conservative_evidence(tmp_path):
    _project(
        tmp_path,
        "return getattr(channel, method_name)(target=target)",
        "getattr(Chan(), input())()\n",
    )
    assert "pkg.chan.Chan._api_read" not in _unused(tmp_path)


def test_aliased_reflection_prevents_closed_consumer_proof(tmp_path):
    _project(
        tmp_path,
        "return getattr(channel, method_name)(target=target)",
        'lookup = getattr\nlookup(Chan(), "_api_read")(target="other")\n',
    )
    assert "pkg.chan.Chan._api_read" not in _unused(tmp_path)


def test_custom_attribute_dispatch_prevents_exclusion(tmp_path):
    _project(
        tmp_path,
        "return getattr(channel, method_name)(target=target)",
        "class Proxy:\n    def __getattr__(self, name):\n        return name\n",
    )
    assert "pkg.chan.Chan._api_read" not in _unused(tmp_path)


def test_literal_reflective_field_escape_prevents_exclusion(tmp_path):
    _project(
        tmp_path,
        "return getattr(channel, method_name)(target=target)",
        'print(getattr(getattr(Chan(), "actions")[0], "backends"))\n',
    )
    assert "pkg.chan.Chan._api_read" not in _unused(tmp_path)


def test_outer_record_passed_to_unknown_consumer_prevents_exclusion(tmp_path):
    _project(tmp_path, "return getattr(channel, method_name)(target=target)")
    path = tmp_path / "pkg/dispatch.py"
    source = path.read_text().replace(
        "        for label, method_name",
        "        consume(action)\n        for label, method_name",
    )
    path.write_text(source)
    assert "pkg.chan.Chan._api_read" not in _unused(tmp_path)
