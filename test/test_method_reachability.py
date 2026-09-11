"""Frozen method-reachability acceptance cases; fixture source is never executed."""

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(root, name, source):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, textwrap.dedent(source).lstrip())
    return path


def _scan(path, **options):
    return json.loads(analyze(str(path.resolve()), trace_file=False, **options))


def _unused(result):
    return {item["full_name"] for item in result.get("unused_functions", [])}


def _pair(first="NorthernCodec", second="SouthernCodec"):
    return (
        f"class {first}:\n"
        "    def encode_payload(self): return 1\n\n"
        f"class {second}:\n"
        "    def encode_payload(self): return 2\n\n"
    )


def _cycle():
    return textwrap.dedent("""
        class PacketWorker:
            def advance_phase(self, count):
                return self.finish_phase(count - 1) if count else 1

            def finish_phase(self, count):
                return self.advance_phase(count - 1) if count else 2

        worker = PacketWorker()
    """).lstrip()


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("both_live", [False, True])
@pytest.mark.parametrize(
    "first,second",
    [("NorthernCodec", "SouthernCodec"), ("northern_codec", "southern_codec")],
    ids=["capitalized", "lowercase"],
)
def test_same_name_methods_resolve_to_their_receiver(
    tmp_path, grep_verify, both_live, first, second
):
    source = _pair(first, second)
    source += f"north = {first}()\nsouth = {second}()\nnorth.encode_payload()\n"
    if both_live:
        source += "south.encode_payload()\n"
    _write(tmp_path, "worker.py", source)

    result = _scan(tmp_path, grep_verify=grep_verify)
    expected = {f"worker.{first}.encode_payload", f"worker.{second}.encode_payload"}
    assert _unused(result) & expected == (
        set() if both_live else {f"worker.{second}.encode_payload"}
    )


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "usage",
    [
        "north = NorthernCodec()\nalias = north\nalias.encode_payload()\n",
        "Factory = NorthernCodec\nnorth = Factory()\nnorth.encode_payload()\n",
        (
            "def launch():\n"
            "    north = NorthernCodec()\n"
            "    alias = north\n"
            "    return alias.encode_payload()\n"
            "launch()\n"
        ),
    ],
    ids=["module-receiver-alias", "constructor-alias", "local-receiver-alias"],
)
def test_receiver_aliases_keep_only_the_resolved_method(tmp_path, grep_verify, usage):
    _write(tmp_path, "worker.py", _pair() + "south = SouthernCodec()\n" + usage)

    unused = _unused(_scan(tmp_path, grep_verify=grep_verify))

    assert "worker.NorthernCodec.encode_payload" not in unused
    assert "worker.SouthernCodec.encode_payload" in unused


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "binding,constructor",
    [
        ("from codecs_local import NorthernCodec as Factory", "Factory"),
        ("import codecs_local as local", "local.NorthernCodec"),
    ],
    ids=["imported-class-alias", "module-alias"],
)
def test_import_aliases_preserve_class_identity(
    tmp_path, grep_verify, binding, constructor
):
    _write(tmp_path, "codecs_local.py", _pair())
    _write(
        tmp_path,
        "main.py",
        f"{binding}\nfrom codecs_local import SouthernCodec\n"
        f"north = {constructor}()\nsouth = SouthernCodec()\n"
        "north.encode_payload()\n",
    )

    unused = _unused(_scan(tmp_path, grep_verify=grep_verify))

    assert "codecs_local.NorthernCodec.encode_payload" not in unused
    assert "codecs_local.SouthernCodec.encode_payload" in unused


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize("recursive", [False, True], ids=["chain", "cycle"])
def test_self_method_groups_require_a_reachable_caller(
    tmp_path, grep_verify, live, recursive
):
    source = _cycle()
    if not recursive:
        source = source.replace("self.advance_phase(count - 1) if count else 2", "2")
    if live:
        source += "worker.advance_phase(3)\n"
    _write(tmp_path, "worker.py", source)

    expected = {"worker.PacketWorker.advance_phase", "worker.PacketWorker.finish_phase"}
    assert _unused(_scan(tmp_path, grep_verify=grep_verify)) & expected == (
        set() if live else expected
    )


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("keyword", [False, True], ids=["positional", "keyword"])
def test_local_argument_flow_does_not_lose_a_live_method(
    tmp_path, grep_verify, keyword
):
    source = _pair() + textwrap.dedent("""
        def dispatch(codec):
            return codec.encode_payload()

        north = NorthernCodec()
        south = SouthernCodec()
    """)
    source += "dispatch(codec=north)\n" if keyword else "dispatch(north)\n"
    _write(tmp_path, "worker.py", source)

    unused = _unused(_scan(tmp_path, grep_verify=grep_verify))

    # Precision for the unused southern method can stay conservative in this
    # first pass, but passing a known receiver must never lose its live method.
    assert "worker.NorthernCodec.encode_payload" not in unused


@pytest.mark.parametrize(
    "usage",
    [
        (
            "codec = NorthernCodec()\ncodec.encode_payload()\n"
            "codec = SouthernCodec()\ncodec.encode_payload()\n"
        ),
        (
            "from external import choose\n"
            "if choose():\n    codec = NorthernCodec()\n"
            "else:\n    codec = SouthernCodec()\ncodec.encode_payload()\n"
        ),
        (
            "from external import choose\n"
            "codec = NorthernCodec() if choose() else SouthernCodec()\n"
            "codec.encode_payload()\n"
        ),
    ],
    ids=["receiver-reassignment", "branch-join", "conditional-expression"],
)
def test_multiple_possible_receivers_preserve_live_methods(tmp_path, usage):
    _write(tmp_path, "worker.py", _pair() + usage)

    unused = _unused(_scan(tmp_path))

    assert (
        not {
            "worker.NorthernCodec.encode_payload",
            "worker.SouthernCodec.encode_payload",
        }
        & unused
    )


@pytest.mark.parametrize(
    "source,protected",
    [
        (
            _cycle() + "class Child(PacketWorker): pass\nChild().advance_phase(3)\n",
            {"PacketWorker.advance_phase", "PacketWorker.finish_phase"},
        ),
        (
            "class Descriptor:\n"
            "    def __get__(self, instance, owner): return instance.finish_phase\n"
            "class PacketWorker:\n"
            "    advance_phase = Descriptor()\n"
            "    def finish_phase(self): return 1\n"
            "PacketWorker().advance_phase()\n",
            {"PacketWorker.finish_phase"},
        ),
        (
            "from external import register\n"
            "class Registry(type):\n"
            "    def __new__(mcls, name, bases, namespace):\n"
            "        register(namespace)\n"
            "        return super().__new__(mcls, name, bases, namespace)\n"
            "class PacketWorker(metaclass=Registry):\n"
            "    def advance_phase(self): return self.finish_phase()\n"
            "    def finish_phase(self): return self.advance_phase()\n"
            "worker = PacketWorker()\n",
            {"PacketWorker.advance_phase", "PacketWorker.finish_phase"},
        ),
        (
            _pair() + "north = NorthernCodec()\nsouth = SouthernCodec()\n"
            "north.encode_payload = south.encode_payload\nnorth.encode_payload()\n",
            {"SouthernCodec.encode_payload"},
        ),
        (
            "from external import register\n" + _cycle() + "register(worker)\n",
            {"PacketWorker.advance_phase", "PacketWorker.finish_phase"},
        ),
        (
            "from external import register\n"
            + _cycle()
            + "register(worker.advance_phase)\n",
            {"PacketWorker.advance_phase", "PacketWorker.finish_phase"},
        ),
    ],
    ids=["inheritance", "descriptor", "metaclass", "monkeypatch", "escape", "callback"],
)
def test_dynamic_class_boundaries_preserve_possible_entry_methods(
    tmp_path, source, protected
):
    _write(tmp_path, "worker.py", source)

    unused = _unused(_scan(tmp_path))

    assert not {f"worker.{name}" for name in protected} & unused


@pytest.mark.parametrize("scope", ["file", "changed-file", "excluded-directory"])
def test_partial_scan_does_not_prove_method_cycles_dead(tmp_path, scope):
    worker = _write(tmp_path, "worker.py", _cycle())
    _write(
        tmp_path,
        "consumers/main.py",
        "from worker import worker\nworker.advance_phase(3)\n",
    )
    if scope == "file":
        result = _scan(worker)
    elif scope == "changed-file":
        result = _scan(tmp_path, changed_files={str(worker.resolve())})
    else:
        result = _scan(tmp_path, exclude_folders=["consumers"])

    assert not {
        "worker.PacketWorker.advance_phase",
        "worker.PacketWorker.finish_phase",
    } & _unused(result)


def test_cache_tracks_adding_and_removing_method_roots(tmp_path):
    expected = {"worker.PacketWorker.advance_phase", "worker.PacketWorker.finish_phase"}
    for live in (False, True, False):
        source = _cycle() + ("worker.advance_phase(3)\n" if live else "")
        _write(tmp_path, "worker.py", source)
        expected_unused = set() if live else expected
        for cache_enabled in (False, True, True):
            result = _scan(tmp_path, grep_cache=cache_enabled)
            assert _unused(result) & expected == expected_unused


@pytest.mark.parametrize("case", ["same-name", "cycle"])
def test_default_cli_reports_methods_and_explains_unreachable_groups(tmp_path, case):
    repo_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(repo_root)
    for live in (False, True):
        if case == "cycle":
            source = _cycle() + ("worker.advance_phase(3)\n" if live else "")
            expected = {
                "worker.PacketWorker.advance_phase",
                "worker.PacketWorker.finish_phase",
            }
        else:
            source = (
                _pair()
                + (
                    "north = NorthernCodec()\nsouth = SouthernCodec()\n"
                    "north.encode_payload()\n"
                )
                + ("south.encode_payload()\n" if live else "")
            )
            expected = {"worker.SouthernCodec.encode_payload"}
        _write(tmp_path, "worker.py", source)
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                "from skylos.cli import main; main()",
                str(tmp_path.resolve()),
                "--format",
                "json",
                "--no-upload",
            ],
            cwd=repo_root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr
        result = json.loads(completed.stdout)
        assert _unused(result) & expected == (set() if live else expected)
        if case == "cycle" and not live:
            symbols = {
                item["qualified_name"]: item
                for item in result["dead_code_evidence"]["symbols"]
            }
            for name in expected:
                assert (
                    "no_reachable_callers" in symbols[name]["decision"]["reason_tags"]
                )
