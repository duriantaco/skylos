import ast
import json

from skylos.analyzer import analyze
from skylos.rules.quality.concurrency import LockOrderRule, ThreadSharedStateRule


def _findings(rule, code):
    tree = ast.parse(code)
    findings = []
    context = {"filename": "app.py"}
    for node in ast.walk(tree):
        result = rule.visit_node(node, context)
        if result:
            findings.extend(result)
    return findings


def test_detects_inconsistent_lock_order():
    code = """
import threading

user_lock = threading.Lock()
account_lock = threading.Lock()

def update_user():
    with user_lock:
        with account_lock:
            pass

def update_account():
    with account_lock:
        with user_lock:
            pass
"""

    findings = _findings(LockOrderRule(), code)

    assert any(f["rule_id"] == "SKY-Q403" for f in findings)


def test_allows_consistent_lock_order():
    code = """
import threading

user_lock = threading.Lock()
account_lock = threading.Lock()

def update_user():
    with user_lock:
        with account_lock:
            pass

def update_account():
    with user_lock:
        with account_lock:
            pass
"""

    findings = _findings(LockOrderRule(), code)

    assert not any(f["rule_id"] == "SKY-Q403" for f in findings)


def test_allows_reversed_inner_locks_under_same_outer_guard():
    code = """
import threading

guard_lock = threading.Lock()
user_lock = threading.Lock()
account_lock = threading.Lock()

def update_user():
    with guard_lock:
        with user_lock:
            with account_lock:
                pass

def update_account():
    with guard_lock:
        with account_lock:
            with user_lock:
                pass
"""

    findings = _findings(LockOrderRule(), code)

    assert not any(f["rule_id"] == "SKY-Q403" for f in findings)


def test_detects_thread_target_mutating_shared_state_without_lock():
    code = """
import threading

events = []
counter = 0

def worker():
    global counter
    counter += 1
    events.append("done")

def run():
    thread = threading.Thread(target=worker)
    thread.start()
"""

    findings = _findings(ThreadSharedStateRule(), code)

    assert any(f["rule_id"] == "SKY-Q404" for f in findings)


def test_detects_thread_target_list_append_without_global_statement():
    code = """
import threading

events = []

def worker():
    events.append("done")

def run():
    thread = threading.Thread(target=worker)
    thread.start()
"""

    findings = _findings(ThreadSharedStateRule(), code)

    assert any(f["rule_id"] == "SKY-Q404" for f in findings)


def test_allows_thread_target_mutating_shared_state_under_lock():
    code = """
import threading

events = []
events_lock = threading.Lock()

def worker():
    with events_lock:
        events.append("done")

def run():
    thread = threading.Thread(target=worker)
    thread.start()
"""

    findings = _findings(ThreadSharedStateRule(), code)

    assert not any(f["rule_id"] == "SKY-Q404" for f in findings)


def test_allows_threadsafe_queue_and_deque_worker_state():
    code = """
import queue
import threading
from collections import deque

jobs = queue.Queue()
events = deque()

def worker():
    jobs.put("done")
    events.append("done")

def run():
    thread = threading.Thread(target=worker)
    thread.start()
"""

    findings = _findings(ThreadSharedStateRule(), code)

    assert not any(f["rule_id"] == "SKY-Q404" for f in findings)


def test_popular_repo_structures_do_not_emit_new_reliability_false_positives(tmp_path):
    src = tmp_path / "src" / "acme"
    django_app = tmp_path / "backend" / "users"
    fastapi_app = tmp_path / "services" / "api"
    src.mkdir(parents=True)
    django_app.mkdir(parents=True)
    fastapi_app.mkdir(parents=True)

    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "workers.py").write_text(
        """
import queue
import threading
from collections import deque

jobs = queue.Queue()
events = deque()

def worker():
    jobs.put("done")
    events.append("done")

def run():
    thread = threading.Thread(target=worker)
    thread.start()
""",
        encoding="utf-8",
    )
    (src / "locks.py").write_text(
        """
import threading

guard_lock = threading.Lock()
user_lock = threading.Lock()
account_lock = threading.Lock()

def update_user():
    with guard_lock:
        with user_lock:
            with account_lock:
                pass

def update_account():
    with guard_lock:
        with account_lock:
            with user_lock:
                pass
""",
        encoding="utf-8",
    )
    (django_app / "views.py").write_text(
        """
from .models import User

def get_queryset():
    return User.objects.all()

def filtered_queryset():
    return User.objects.filter(active=True).all()
""",
        encoding="utf-8",
    )
    (fastapi_app / "main.py").write_text(
        """
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health():
    return {"ok": True}
""",
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), conf=0, enable_quality=True))
    new_rule_ids = {
        finding.get("rule_id")
        for finding in result.get("quality", [])
        if finding.get("rule_id") in {"SKY-Q403", "SKY-Q404", "SKY-P404"}
    }

    assert new_rule_ids == set()
