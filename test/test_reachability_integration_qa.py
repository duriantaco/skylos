"""Independent public-output checks for Python dead-code reachability.

Fixture modules are parsed by Skylos, never imported or executed. Expectations
come from visible application roots and references in each fixture.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, textwrap.dedent(source).lstrip())


def _scan(path, **options):
    return json.loads(analyze(str(path.resolve()), trace_file=False, **options))


def _unused(result):
    return {item["full_name"] for item in result.get("unused_functions", [])}


def _cycle_source(*, live=False):
    return textwrap.dedent(
        """
        def obsolete_alpha(value):
            if value <= 0:
                return 0
            return obsolete_beta(value - 1)

        def obsolete_beta(value):
            if value <= 0:
                return 0
            return obsolete_alpha(value - 1)

        def obsolete_entry():
            return obsolete_alpha(2)
        """
    ) + ("\nprint(obsolete_entry())\n" if live else "\nprint('ready')\n")


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("live", [False, True])
def test_recursive_group_requires_a_reachable_caller(tmp_path, grep_verify, live):
    _write(tmp_path / "worker.py", _cycle_source(live=live))

    unused = _unused(_scan(tmp_path, grep_verify=grep_verify))

    expected = {
        "worker.obsolete_alpha",
        "worker.obsolete_beta",
        "worker.obsolete_entry",
    }
    assert unused & expected == (set() if live else expected)


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("call_style", ["inline", "multiline", "parenthesized"])
@pytest.mark.parametrize("live", [False, True])
def test_dead_chain_is_independent_of_call_whitespace(
    tmp_path, grep_verify, call_style, live
):
    call = {
        "inline": "def obsolete_alpha(value): return obsolete_beta(value)\n",
        "multiline": "def obsolete_alpha(value):\n    return obsolete_beta(value)\n",
        "parenthesized": (
            "def obsolete_alpha(value):\n"
            "    return (obsolete_beta) (\n        value\n    )\n"
        ),
    }[call_style]
    _write(
        tmp_path / "worker.py",
        "def obsolete_beta(value):\n    return value + 1\n\n"
        + call
        + "\ndef obsolete_entry():\n    return obsolete_alpha(2)\n\n"
        + ("print(obsolete_entry())\n" if live else "print('ready')\n"),
    )

    unused = _unused(_scan(tmp_path, grep_verify=grep_verify))

    expected = {
        "worker.obsolete_alpha",
        "worker.obsolete_beta",
        "worker.obsolete_entry",
    }
    assert unused & expected == (set() if live else expected)


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("second_is_live", [False, True])
def test_resolved_import_does_not_rescue_other_module_same_name(
    tmp_path, grep_verify, second_is_live
):
    _write(tmp_path / "alpha.py", "def read_record(): return 'alpha'\n")
    _write(tmp_path / "beta.py", "def read_record(): return 'beta'\n")
    main = "from alpha import read_record\nprint(read_record())\n"
    if second_is_live:
        main += "from beta import read_record as read_other\nprint(read_other())\n"
    _write(tmp_path / "main.py", main)

    unused = _unused(_scan(tmp_path, grep_verify=grep_verify))

    assert "alpha.read_record" not in unused
    assert ("beta.read_record" in unused) is (not second_is_live)


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("root_kind", ["callback", "export", "entrypoint"])
def test_external_entry_and_callback_roots_keep_transitive_helpers_live(
    tmp_path, grep_verify, root_kind
):
    source = """
        def process_leaf():
            return 1

        def run_public():
            return process_leaf()
    """
    if root_kind == "callback":
        source = textwrap.dedent(source) + (
            "\nimport atexit\natexit.register(run_public)\n"
        )
    elif root_kind == "export":
        source = textwrap.dedent(source) + "\n__all__ = ['run_public']\n"
    else:
        _write(
            tmp_path / "pyproject.toml",
            """
            [project]
            name = "reachability-fixture"
            version = "0.0.0"
            [project.scripts]
            reachability-fixture = "worker:run_public"
            """,
        )
    _write(tmp_path / "worker.py", source)

    unused = _unused(_scan(tmp_path, grep_verify=grep_verify))

    assert "worker.run_public" not in unused
    assert "worker.process_leaf" not in unused


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "definition_site",
    [
        "def unused_receiver(value=live_helper()): return value\n",
        "class UnusedContainer:\n    value = live_helper()\n",
        "def unused_receiver(value: live_helper()): return value\n",
        (
            "def attach(value):\n    return lambda func: func\n\n"
            "@attach(live_helper())\ndef unused_receiver(): return None\n"
        ),
    ],
    ids=["default", "class-body", "annotation", "decorator"],
)
def test_definition_time_expression_is_live_even_when_body_is_dead(
    tmp_path, grep_verify, definition_site
):
    _write(
        tmp_path / "worker.py",
        "def live_helper():\n    return int\n\n" + definition_site,
    )

    assert "worker.live_helper" not in _unused(_scan(tmp_path, grep_verify=grep_verify))


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("selection", ["file", "changed-file", "excluded-directory"])
def test_partial_scope_does_not_invent_an_unreachable_group(
    tmp_path, grep_verify, selection
):
    worker = tmp_path / "worker.py"
    _write(worker, _cycle_source())
    _write(
        tmp_path / "consumers" / "main.py",
        "from worker import obsolete_entry\nprint(obsolete_entry())\n",
    )
    if selection == "file":
        result = _scan(worker, grep_verify=grep_verify)
    elif selection == "changed-file":
        result = _scan(
            tmp_path,
            grep_verify=grep_verify,
            changed_files={str(worker.resolve())},
        )
    else:
        result = _scan(tmp_path, grep_verify=grep_verify, exclude_folders=["consumers"])

    # A focused scan must preserve recursive members whose external caller is
    # outside the selected file; it has no closed-world proof they are dead.
    assert not {"worker.obsolete_alpha", "worker.obsolete_beta"} & _unused(result)


def test_grep_cache_observes_adding_and_removing_a_real_caller(tmp_path):
    _write(tmp_path / "worker.py", _cycle_source())
    caller = tmp_path / "main.py"
    states = [
        "print('ready')\n",
        "from worker import obsolete_entry\nprint(obsolete_entry())\n",
        "print('ready')\n",
    ]
    expected = {
        "worker.obsolete_alpha",
        "worker.obsolete_beta",
        "worker.obsolete_entry",
    }
    for index, source in enumerate(states):
        _write(caller, source)
        cold = _unused(_scan(tmp_path, grep_cache=False)) & expected
        cached = _unused(_scan(tmp_path, grep_cache=True)) & expected
        repeated = _unused(_scan(tmp_path, grep_cache=True)) & expected
        assert cold == cached == repeated == (set() if index == 1 else expected)


def test_real_cli_reports_dead_cycle_and_keeps_live_variant(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(repo_root)
    expected = {
        "worker.obsolete_alpha",
        "worker.obsolete_beta",
        "worker.obsolete_entry",
    }
    for live in (False, True):
        _write(tmp_path / "worker.py", _cycle_source(live=live))
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


def test_external_configuration_rescue_revives_callees_in_the_same_scan(tmp_path):
    _write(
        tmp_path / "helpers.py",
        "def prepare_record():\n    return 42\n",
    )
    _write(
        tmp_path / "workflow.py",
        "def queue_task():\n"
        "    from helpers import prepare_record\n"
        "    return prepare_record()\n",
    )
    _write(tmp_path / "jobs.yaml", "handler_module: workflow.py\n")

    first = _scan(tmp_path, grep_cache=True)
    repeated = _scan(tmp_path, grep_cache=True)

    expected = {"workflow.queue_task", "helpers.prepare_record"}
    assert not _unused(first) & expected
    assert not _unused(repeated) & expected
    symbols = {
        item["qualified_name"]: item for item in first["dead_code_evidence"]["symbols"]
    }
    helper_kinds = {
        event["kind"] for event in symbols["helpers.prepare_record"]["evidence"]
    }
    assert "reachable_from_root" in helper_kinds
    assert "grep_rescue" not in helper_kinds
    assert first["analysis_summary"]["grep_verify"]["rescued_count"] == 1


def test_group_evidence_distinguishes_unreachable_calls_from_no_references(tmp_path):
    _write(tmp_path / "worker.py", _cycle_source())

    result = _scan(tmp_path)
    by_name = {
        item["qualified_name"]: item for item in result["dead_code_evidence"]["symbols"]
    }

    for name in ("worker.obsolete_alpha", "worker.obsolete_beta"):
        entry = by_name[name]
        assert "no_reachable_callers" in entry["decision"]["reason_tags"]
        assert "no_refs" not in entry["decision"]["reason_tags"]
        kinds = {event["kind"] for event in entry["evidence"]}
        assert "no_reachable_callers" in kinds
        assert "no_static_references" not in kinds
    assert "no_refs" in by_name["worker.obsolete_entry"]["decision"]["reason_tags"]


def _write_duplicate_basename_modules(root):
    for package, operator in (("north", "+"), ("south", "-")):
        _write(root / package / "__init__.py", "")
        _write(
            root / package / "tasks.py",
            f"def decode_packet(value):\n    return value {operator} 1\n",
        )


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("second_is_live", [False, True])
def test_qualified_calls_distinguish_duplicate_module_basenames(
    tmp_path, grep_verify, second_is_live
):
    _write_duplicate_basename_modules(tmp_path)
    main = "import north.tasks\nprint(north.tasks.decode_packet(2))\n"
    if second_is_live:
        main += "import south.tasks\nprint(south.tasks.decode_packet(2))\n"
    _write(tmp_path / "main.py", main)

    result = _scan(tmp_path, grep_verify=grep_verify)
    unused = _unused(result)

    assert "north.tasks.decode_packet" not in unused
    assert ("south.tasks.decode_packet" in unused) is (not second_is_live)
    if not second_is_live:
        entries = {
            item["qualified_name"]: item
            for item in result["dead_code_evidence"]["symbols"]
        }
        reasons = entries["south.tasks.decode_packet"]["decision"]["reason_tags"]
        assert "no_refs" in reasons
        assert "no_reachable_callers" not in reasons


@pytest.mark.parametrize("grep_verify", [False, True])
def test_unresolved_receiver_preserves_same_named_function_candidates(
    tmp_path, grep_verify
):
    _write_duplicate_basename_modules(tmp_path)
    _write(
        tmp_path / "gateway.py",
        """
        __all__ = ["dispatch"]

        def dispatch(backend):
            return backend.decode_packet(2)
        """,
    )

    # The public callback accepts an unknown backend. Either package module
    # can satisfy that interface; the attribute hint cannot be discarded as
    # though it resolved to a different, known symbol.
    unused = _unused(_scan(tmp_path, grep_verify=grep_verify))
    protected = {
        "gateway.dispatch",
        "north.tasks.decode_packet",
        "south.tasks.decode_packet",
    }
    assert not protected & unused


def test_unused_import_does_not_share_its_function_grep_verdict(tmp_path):
    _write(
        tmp_path / "worker.py",
        "def calculate_payload():\n    return 42\n",
    )
    _write(
        tmp_path / "importer.py",
        "from worker import calculate_payload\nprint('ready')\n",
    )
    repo_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(repo_root)
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

    for result in (_scan(tmp_path), json.loads(completed.stdout)):
        # Importing the function protects its public definition under the
        # existing grep policy. The unused local import binding remains a
        # separate finding despite sharing the function's qualified name.
        assert "worker.calculate_payload" not in _unused(result)
        assert any(
            Path(item["file"]).name == "importer.py"
            and item["simple_name"] == "calculate_payload"
            for item in result.get("unused_imports", [])
        )
