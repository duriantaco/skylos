"""Celery backend proofs use effective settings and current module exports."""

import json

import pytest

from skylos.analyzer import Skylos


PROVIDERS = """class CandidateBackend:
    def __init__(self, app=None, url=None):
        pass

class ReplacementBackend:
    def __init__(self, app=None, url=None):
        pass

def make_backend(app=None, url=None):
    return object()

class DeadNeighbor:
    pass
"""
APP = 'from celery import Celery\napp = Celery("worker")\n'
SELECT = 'app.conf.update(result_backend="providers:CandidateBackend")\n'


def _scan(tmp_path, monkeypatch, app, providers, confidence, grep):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    for name, source in {
        "app.py": app,
        "providers.py": providers,
        "alternate.py": 'result_backend = "rpc://"\n',
    }.items():
        (tmp_path / name).write_text(source, encoding="utf-8")
    scanner = Skylos()
    result = json.loads(
        scanner.analyze(str(tmp_path), thr=confidence, grep_verify=grep)
    )
    assert not result.get("analysis_errors")
    definitions = {definition.name: definition for definition in scanner.defs.values()}
    unused = {
        item.get("full_name") or item.get("name")
        for bucket in ("unused_classes", "unused_functions")
        for item in result.get(bucket, [])
    }
    assert "providers.DeadNeighbor" in unused
    return definitions, unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
@pytest.mark.parametrize(
    "registration",
    [
        SELECT,
        'app.conf.result_backend = "providers.CandidateBackend"\n',
        'app.conf["result_backend"] = "providers:CandidateBackend"\n',
        'app.conf.update({"result_backend": "providers:CandidateBackend"})\n',
        'config = app.conf\nconfig.update(result_backend="providers:CandidateBackend")\n',
        'app = Celery("worker", result_backend="providers:CandidateBackend")\n',
        'app = Celery("worker", backend="providers:CandidateBackend")\n',
        SELECT + 'app.conf.update(task_serializer="json")\n',
        SELECT + 'del app.conf["unrelated"]\n',
        SELECT + "from config import debug\nif debug:\n    print(app)\n",
        SELECT
        + 'from config import debug\nif debug:\n    app.conf.update(task_serializer="json")\n',
        SELECT + 'app.backend\napp.conf.update(result_backend="rpc://")\n',
    ],
)
def test_selected_backend_remains_live(
    tmp_path, monkeypatch, confidence, grep, registration
):
    definitions, unused = _scan(
        tmp_path, monkeypatch, APP + registration, PROVIDERS, confidence, grep
    )
    assert definitions["providers.CandidateBackend"].heuristic_refs.get(
        "framework_root"
    )
    assert "providers.CandidateBackend" not in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
@pytest.mark.parametrize(
    "replacement",
    [
        'app.conf.result_backend = "rpc://"\n',
        'app.conf["result_backend"] = "rpc://"\n',
        'app.conf.update(result_backend="rpc://")\n',
        'app.conf.update({"result_backend": "rpc://"})\n',
        'replacement = {"result_backend": "rpc://"}\napp.conf.update(replacement)\n',
        "app.conf.update(**replacement)\n",
        'del app.conf["result_backend"]\n',
        'app.config_from_object("alternate")\n',
        "app.conf = replacement\n",
        'False and app.backend\napp.conf.result_backend = "rpc://"\n',
        'pending = lambda: app.backend\napp.conf.result_backend = "rpc://"\n',
    ],
)
def test_replaced_backend_does_not_remain_a_root(
    tmp_path, monkeypatch, confidence, grep, replacement
):
    definitions, unused = _scan(
        tmp_path, monkeypatch, APP + SELECT + replacement, PROVIDERS, confidence, grep
    )
    assert not definitions["providers.CandidateBackend"].heuristic_refs.get(
        "framework_root"
    )
    assert "providers.CandidateBackend" in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
@pytest.mark.parametrize("target", ["CandidateBackend", "make_backend"])
def test_rebound_module_export_does_not_resurrect_original(
    tmp_path, monkeypatch, confidence, grep, target
):
    app = APP + f'app.conf.update(result_backend="providers:{target}")\n'
    providers = PROVIDERS + f"\n{target} = ReplacementBackend\n"
    definitions, unused = _scan(tmp_path, monkeypatch, app, providers, confidence, grep)
    assert not definitions[f"providers.{target}"].heuristic_refs.get("framework_root")
    assert f"providers.{target}" in unused
    assert definitions["providers.ReplacementBackend"].heuristic_refs.get(
        "framework_root"
    )


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_export_alias_retains_the_captured_definition(
    tmp_path, monkeypatch, confidence, grep
):
    providers = (
        PROVIDERS
        + "\nSelected = CandidateBackend\nCandidateBackend = ReplacementBackend\n"
    )
    app = APP + 'app.conf.update(result_backend="providers:Selected")\n'
    definitions, _ = _scan(tmp_path, monkeypatch, app, providers, confidence, grep)
    assert definitions["providers.CandidateBackend"].heuristic_refs.get(
        "framework_root"
    )
    assert not definitions["providers.ReplacementBackend"].heuristic_refs.get(
        "framework_root"
    )


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_backend_defined_in_a_constant_branch_is_selected(
    tmp_path, monkeypatch, confidence, grep
):
    providers = "if True:\n" + "".join(
        "    " + line for line in PROVIDERS.splitlines(keepends=True)
    )
    definitions, unused = _scan(
        tmp_path, monkeypatch, APP + SELECT, providers, confidence, grep
    )
    assert definitions["providers.CandidateBackend"].heuristic_refs.get(
        "framework_root"
    )
    assert "providers.CandidateBackend" not in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_deleted_backend_export_does_not_root_original(
    tmp_path, monkeypatch, confidence, grep
):
    definitions, unused = _scan(
        tmp_path,
        monkeypatch,
        APP + SELECT,
        PROVIDERS + "\ndel CandidateBackend\n",
        confidence,
        grep,
    )
    assert not definitions["providers.CandidateBackend"].heuristic_refs.get(
        "framework_root"
    )
    if not grep:
        # Generic grep can retain a name referenced by ``del`` independently.
        assert "providers.CandidateBackend" in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
@pytest.mark.parametrize("first", ["rpc://", "providers:ReplacementBackend"])
def test_loaded_backend_is_not_replaced_by_a_later_setting(
    tmp_path, monkeypatch, confidence, grep, first
):
    app = APP + f'app.conf.result_backend = "{first}"\napp.backend\n' + SELECT
    definitions, unused = _scan(tmp_path, monkeypatch, app, PROVIDERS, confidence, grep)
    assert not definitions["providers.CandidateBackend"].heuristic_refs.get(
        "framework_root"
    )
    assert "providers.CandidateBackend" in unused
    if first != "rpc://":
        assert definitions["providers.ReplacementBackend"].heuristic_refs.get(
            "framework_root"
        )


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
@pytest.mark.parametrize(
    "expression,cache",
    [
        ("(app.backend for item in [1])", "none"),
        ("[app.backend for item in []]", "none"),
        ("[app.backend for item in [1] if False]", "none"),
        ("{app.backend for item in []}", "none"),
        ("{item: app.backend for item in [1] if False}", "none"),
        ("[app.backend for item in [1]]", "exact"),
        ("{app.backend for item in [1]}", "exact"),
        ("{item: app.backend for item in [1]}", "exact"),
        ("[app.backend for item in [1] if True]", "exact"),
        ("(item for item in [app.backend])", "exact"),
        ("(item for item in [] for other in [app.backend])", "none"),
        ("[app.backend for item in values]", "possible"),
        ("[app.backend for item in [1] if enabled]", "possible"),
        ("[item for item in [1] if app.backend]", "exact"),
        ("[item for item in [1] if False for other in [app.backend]]", "none"),
        ("(item for item in (app.backend if enabled else []))", "possible"),
        ("[app.backend for item in [1] if []]", "none"),
        ("[app.backend for item in [1] if not False]", "exact"),
        ("[app.backend for app in [SimpleNamespace(backend=1)]]", "none"),
        (
            "[value for app in [SimpleNamespace(backend=1)] for value in [app.backend]]",
            "none",
        ),
    ],
)
def test_comprehension_evaluation_controls_backend_cache(
    tmp_path, monkeypatch, confidence, grep, expression, cache
):
    app = (
        "from celery import Celery\nfrom configuration import values, enabled\n"
        "from types import SimpleNamespace\n"
        'app = Celery("worker", backend="providers:CandidateBackend")\n'
        f"pending = {expression}\n"
        'app.conf.result_backend = "providers:ReplacementBackend"\n'
    )
    definitions, unused = _scan(tmp_path, monkeypatch, app, PROVIDERS, confidence, grep)
    first = definitions["providers.CandidateBackend"].heuristic_refs
    final = definitions["providers.ReplacementBackend"].heuristic_refs
    assert bool(first.get("framework_root")) == (cache == "exact")
    assert bool(final.get("framework_root")) == (cache != "exact")
    if cache == "none":
        assert "providers.CandidateBackend" in unused
    else:
        assert "providers.CandidateBackend" not in unused
    if cache == "exact":
        assert "providers.ReplacementBackend" in unused
    else:
        assert "providers.ReplacementBackend" not in unused
    if cache == "possible":
        assert first.get("dead_code_liveness:possible_celery_result_backend")


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
def test_backend_settings_are_kept_per_app(tmp_path, monkeypatch, confidence, grep):
    app = (
        APP
        + SELECT
        + (
            'other = Celery("other", result_backend="providers:ReplacementBackend")\n'
            'other.conf.update(result_backend="rpc://")\n'
        )
    )
    definitions, unused = _scan(tmp_path, monkeypatch, app, PROVIDERS, confidence, grep)
    assert definitions["providers.CandidateBackend"].heuristic_refs.get(
        "framework_root"
    )
    assert not definitions["providers.ReplacementBackend"].heuristic_refs.get(
        "framework_root"
    )
    assert "providers.ReplacementBackend" in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("grep", [False, True])
@pytest.mark.parametrize(
    "app",
    [
        "class Fake:\n    pass\napp = Fake()\n" + SELECT,
        "from celery import Celery\nclass Fake:\n    pass\nCelery = Fake\napp = Celery()\n"
        + SELECT,
        'from celery import Celery\ndef unused_setup():\n    app = Celery("worker")\n'
        '    app.conf.update(result_backend="providers:CandidateBackend")\n    return app\n',
    ],
)
def test_unproven_celery_owner_does_not_root_backend(
    tmp_path, monkeypatch, confidence, grep, app
):
    definitions, unused = _scan(tmp_path, monkeypatch, app, PROVIDERS, confidence, grep)
    assert not definitions["providers.CandidateBackend"].heuristic_refs.get(
        "framework_root"
    )
    assert "providers.CandidateBackend" in unused
