import pytest

from test.web_framework_fixtures import _scan, _unused


@pytest.mark.parametrize(
    ("registration", "callback_live"),
    [
        ("worker.register_task(Notify())", True),
        ("worker.register_task(task=Notify())", True),
        ("instance = Notify()\nworker.register_task(instance)", True),
        ("class Child(Notify): pass\nworker.register_task(Child())", True),
        ("other.register_task(Notify())", False),
        ("worker.conf.register_task(Notify())", False),
        ("worker = other\nworker.register_task(Notify())", False),
        (
            "worker.register_task = other.register_task\nworker.register_task(Notify())",
            False,
        ),
        ("if False:\n    worker.register_task(Notify())", False),
    ],
)
def test_celery_task_registration_proves_selected_members(
    tmp_path, registration, callback_live
):
    result = _scan_registered(tmp_path, registration)
    for member in ("jobs.Notify.run", "jobs.Notify.on_success"):
        evidence = result["definitions"][member]["dead_code_evidence"]
        assert (
            any(item["kind"] == "framework_root" for item in evidence) is callback_live
        )
    assert ("jobs.record_delivery" not in _unused(result)) is callback_live
    assert (
        "jobs.Notify.name" not in _unused(result, "unused_variables")
    ) is callback_live
    assert "jobs.Notify.retired" in _unused(result)
    if callback_live:
        assert not _unused(result, "unused_parameters") & {
            f"jobs.Notify.on_success.{name}"
            for name in ("retval", "task_id", "args", "kwargs")
        }


def _scan_registered(tmp_path, registration):
    worker_source = """from celery import Celery as Queue
worker = Queue("test")
class LocalQueue:
    def register_task(self, task):
        return task
other = LocalQueue()
"""
    return _scan(
        tmp_path, {"jobs.py": worker_source + _TASK_SOURCE + registration + "\n"}
    )


_TASK_SOURCE = """from celery import Task
class Notify(Task):
    name = "notify"
    def run(self, payload):
        return send_notice(payload)
    def on_success(self, retval, task_id, args, kwargs):
        return record_delivery()
    def retired(self):
        return None
def record_delivery():
    return "recorded"
def send_notice(payload):
    return payload.strip()
"""


@pytest.mark.parametrize(
    ("app_source", "task_export", "expected"),
    [
        ('from celery import Celery\nworker = Celery("test")', "", True),
        ("from providers import worker", "", True),
        ("from providers import worker", "\nNotify = replacement", False),
        ("from providers import other as worker", "", False),
    ],
)
def test_celery_cross_module_task_registration(
    tmp_path, app_source, task_export, expected
):
    result = _scan(
        tmp_path,
        {
            "jobs.py": _TASK_SOURCE + task_export,
            "providers.py": """
                from celery import Celery
                worker = Celery("test")
                class Lookalike:
                    def register_task(self, task): return task
                other = Lookalike()
            """,
            "worker.py": app_source + "\nfrom jobs import Notify as TaskClass\n"
            "task = TaskClass()\nworker.register_task(task)\n",
        },
    )
    evidence = result["definitions"]["jobs.Notify.on_success"]["dead_code_evidence"]
    assert any(item["kind"] == "framework_root" for item in evidence) is expected
    assert ("jobs.Notify.name" not in _unused(result, "unused_variables")) is expected
    assert ("jobs.record_delivery" not in _unused(result)) is expected


@pytest.mark.parametrize("export", ["Reusable = Notify", "Reusable = replacement"])
def test_celery_task_base_resolves_imported_alias(tmp_path, export):
    result = _scan(
        tmp_path,
        {
            "jobs.py": _TASK_SOURCE + export + "\n",
            "worker.py": """
                from celery import Celery
                from jobs import Reusable
                worker = Celery("test")
                class Delivery(Reusable):
                    def retired(self): return "retired"
                worker.register_task(Delivery())
            """,
        },
    )
    expected = export == "Reusable = Notify"
    assert ("jobs.record_delivery" not in _unused(result)) is expected
    assert ("jobs.Notify.name" not in _unused(result, "unused_variables")) is expected
    assert "worker.Delivery.retired" in _unused(result)
