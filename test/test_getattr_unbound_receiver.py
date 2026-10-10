"""Unbound dispatch can receive a different receiver; no fixture is executed."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _scan(tmp_path, callsite):
    source = """
        class Local:
            def dispatch(self, action):
                return getattr(self, f"do_{action}")()
            def do_refund(self):
                return 1
        class Remote:
            def do_refund(self):
                return 2
        other = Remote()
    """
    assert write_text_no_symlink(
        tmp_path / "app.py",
        textwrap.dedent(source).lstrip() + textwrap.dedent(callsite).lstrip(),
    )
    result = json.loads(
        analyze(str(tmp_path.resolve()), trace_file=False, grep_verify=False)
    )
    assert not result.get("analysis_errors")
    unused = {item["full_name"] for item in result["unused_functions"]}
    entries = {
        entry["qualified_name"]: entry
        for entry in result["dead_code_evidence"]["symbols"]
    }
    return result, unused, entries


@pytest.mark.parametrize(
    "callsite",
    [
        "register(Local.dispatch)\n",
        "callback = Local.dispatch\nregister(callback)\n",
        "register([Local.dispatch])\n",
        "register(getattr(Local, 'dispatch'))\n",
        "def callback():\n    return Local.dispatch\nregister(callback())\n",
        "def invoke(receiver):\n    return Local.dispatch(receiver, 'refund')\ninvoke(external_receiver())\n",
    ],
)
def test_escaped_unbound_dispatch_keeps_unknown_receiver_possible(tmp_path, callsite):
    result, unused, entries = _scan(tmp_path, callsite)

    assert "app.Remote.do_refund" not in unused
    remote = entries["app.Remote.do_refund"]
    assert remote["classification"] == "uncertain"
    assert remote["decision"]["live_evidence_count"] == 0
    assert "static_reference" not in {event["kind"] for event in remote["evidence"]}
    assert (
        result["analysis_summary"]["dead_code_evidence"]["classifications"]["uncertain"]
        >= 1
    )


def test_direct_unbound_dispatch_preserves_explicit_remote_receiver(tmp_path):
    _, unused, _ = _scan(tmp_path, "Local.dispatch(Remote(), 'refund')\n")

    assert "app.Remote.do_refund" not in unused


@pytest.mark.parametrize(
    "callsite",
    [
        "register(Local().dispatch)\n",
        "register(getattr(Local(), 'dispatch'))\n",
    ],
)
def test_bound_dispatch_remains_scoped_to_actual_receiver(tmp_path, callsite):
    _, unused, _ = _scan(tmp_path, callsite)

    assert "app.Local.do_refund" not in unused
    assert "app.Remote.do_refund" in unused


@pytest.mark.parametrize("unbound_export", [True, False])
def test_module_callback_lookup_preserves_receiver_kind(tmp_path, unbound_export):
    handlers = (
        """
        class Local:
            def dispatch(self, action):
                return getattr(self, f"do_{action}")()
            def do_refund(self): return 1
        dispatch = Local.dispatch
        """
        if unbound_export
        else "def dispatch(action): return action\n"
    )
    sources = {
        "handlers.py": handlers,
        "remote.py": """
            class Remote:
                def do_refund(self): return 2
            other = Remote()
        """,
        "app.py": """
            import handlers
            import remote
            register(getattr(handlers, "dispatch"))
        """,
    }
    for name, source in sources.items():
        assert write_text_no_symlink(tmp_path / name, textwrap.dedent(source).lstrip())
    result = json.loads(
        analyze(str(tmp_path.resolve()), trace_file=False, grep_verify=False)
    )
    assert not result.get("analysis_errors")
    unused = {item["full_name"] for item in result["unused_functions"]}
    entries = {
        entry["qualified_name"]: entry
        for entry in result["dead_code_evidence"]["symbols"]
    }
    remote = entries["remote.Remote.do_refund"]
    if unbound_export:
        assert "remote.Remote.do_refund" not in unused
        assert remote["classification"] == "uncertain"
        assert remote["decision"]["live_evidence_count"] == 0
    else:
        assert "remote.Remote.do_refund" in unused
        assert remote["classification"] == "likely_dead"
