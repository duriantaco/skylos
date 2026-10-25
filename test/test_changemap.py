import json
import subprocess

import pytest

from skylos.changemap import build_change_map, render_markdown, render_text


def git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Skylos Test", "-c", "user.email=test@example.invalid", *args],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout.strip()


def write(root, files):
    for name, source in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)  # skylos: ignore[SKY-D324] fixed paths under a fresh pytest tmp_path


def repo(root, files):
    write(root, files)
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    return root


def symbol(change_map, full_name):
    matches = [s for s in change_map["symbols"] if s["full_name"] == full_name]
    assert len(matches) == 1, [s["full_name"] for s in change_map["symbols"]]
    return matches[0]


AUTH = "def require_auth(user):\n    if not user:\n        raise PermissionError\n"


def test_removed_auth_call_is_reported_and_read_first(tmp_path):
    repo(tmp_path, {
        "auth.py": AUTH,
        "app.py": (
            "from auth import require_auth\n\n"
            "def handler(user, data):\n"
            "    require_auth(user)\n"
            "    return save(data)\n\n"
            "def save(data):\n"
            "    return data\n\n"
            "def other():\n"
            "    return 1\n"
        ),
    })
    write(tmp_path, {"app.py": (
        "from auth import require_auth\n\n"
        "def handler(user, data):\n"
        "    return save(data)\n\n"
        "def save(data):\n"
        "    return data\n\n"
        "def other():\n"
        "    return 2\n"
    )})
    result = build_change_map(tmp_path, "HEAD")
    handler = symbol(result, "app.handler")
    assert handler["status"] == "modified"
    assert handler["calls_removed"] == ["auth.require_auth"]
    assert handler["security_removed"] == ["auth.require_auth"]
    assert result["read_first"][0] == handler["id"]
    assert symbol(result, "app.other")["security_removed"] == []


def test_call_moved_into_new_helper_is_not_removed(tmp_path):
    repo(tmp_path, {
        "auth.py": AUTH,
        "app.py": (
            "from auth import require_auth\n\n"
            "def handler(user):\n"
            "    require_auth(user)\n"
            "    return 1\n"
        ),
    })
    write(tmp_path, {"app.py": (
        "from auth import require_auth\n\n"
        "def handler(user):\n"
        "    _guard(user)\n"
        "    return 1\n\n"
        "def _guard(user):\n"
        "    require_auth(user)\n"
    )})
    result = build_change_map(tmp_path, "HEAD")
    handler = symbol(result, "app.handler")
    assert handler["calls_removed"] == []
    assert handler["calls_moved"] == ["auth.require_auth"]
    assert handler["security_removed"] == []
    assert symbol(result, "app._guard")["status"] == "added"


def test_call_moved_into_existing_helper_is_not_removed(tmp_path):
    repo(tmp_path, {
        "auth.py": AUTH,
        "app.py": (
            "from auth import require_auth\n\n"
            "def _guard(user):\n"
            "    require_auth(user)\n\n"
            "def handler(user):\n"
            "    require_auth(user)\n"
            "    return 1\n"
        ),
    })
    write(tmp_path, {"app.py": (
        "from auth import require_auth\n\n"
        "def _guard(user):\n"
        "    require_auth(user)\n\n"
        "def handler(user):\n"
        "    _guard(user)\n"
        "    return 1\n"
    )})
    handler = symbol(build_change_map(tmp_path, "HEAD"), "app.handler")
    assert handler["calls_moved"] == ["auth.require_auth"]
    assert handler["security_removed"] == []


def test_auth_call_replaced_by_same_named_local_stub_is_still_reported(tmp_path):
    repo(tmp_path, {
        "auth.py": AUTH,
        "app.py": (
            "from auth import require_auth\n\n"
            "def handler(user):\n"
            "    require_auth(user)\n"
            "    return 1\n"
        ),
    })
    write(tmp_path, {"app.py": (
        "def require_auth(user):\n"
        "    return None\n\n"
        "def handler(user):\n"
        "    require_auth(user)\n"
        "    return 1\n"
    )})
    handler = symbol(build_change_map(tmp_path, "HEAD"), "app.handler")
    assert handler["security_removed"] == ["auth.require_auth"]
    assert handler["calls_moved"] == []


def test_auth_call_moved_into_helper_that_drops_it_is_reported(tmp_path):
    repo(tmp_path, {
        "auth.py": AUTH,
        "app.py": (
            "from auth import require_auth\n\n"
            "def handler(user):\n"
            "    require_auth(user)\n"
            "    return 1\n"
        ),
    })
    write(tmp_path, {"app.py": (
        "from auth import require_auth\n\n"
        "def handler(user):\n"
        "    _guard(user)\n"
        "    return 1\n\n"
        "def _guard(user):\n"
        "    return user\n"
    )})
    handler = symbol(build_change_map(tmp_path, "HEAD"), "app.handler")
    assert handler["security_removed"] == ["auth.require_auth"]


def test_removed_auth_decorator_is_reported(tmp_path):
    repo(tmp_path, {"app.py": (
        "def login_required(fn):\n"
        "    return fn\n\n"
        "@login_required\n"
        "def admin_page():\n"
        "    return 'secret'\n"
    )})
    write(tmp_path, {"app.py": (
        "def login_required(fn):\n"
        "    return fn\n\n"
        "def admin_page():\n"
        "    return 'secret'\n"
    )})
    page = symbol(build_change_map(tmp_path, "HEAD"), "app.admin_page")
    assert page["decorators_removed"] == ["login_required"]
    assert page["security_removed"] == ["@login_required"]


def test_signature_change_flags_caller_outside_the_change(tmp_path):
    repo(tmp_path, {
        "pricing.py": "def total(items):\n    return sum(items)\n",
        "report.py": (
            "from pricing import total\n\n"
            "def report():\n"
            "    value = 1\n"
            "    return total([value])\n"
        ),
    })
    write(tmp_path, {"pricing.py": "def total(items, tax):\n    return sum(items) * tax\n"})
    total = symbol(build_change_map(tmp_path, "HEAD"), "pricing.total")
    assert total["signature_changed"] is True
    assert total["before"]["signature"] == "items"
    assert total["after"]["signature"] == "items, tax"
    assert total["callers"] == [
        {"name": "report.report", "file": "report.py", "line": 5, "in_change": False, "is_test": False}
    ]
    assert total["callers_not_updated"] == 1


def test_signature_change_with_updated_caller_is_not_flagged(tmp_path):
    repo(tmp_path, {
        "pricing.py": "def total(items):\n    return sum(items)\n",
        "report.py": "from pricing import total\n\ndef report():\n    return total([1])\n",
    })
    write(tmp_path, {
        "pricing.py": "def total(items, tax):\n    return sum(items) * tax\n",
        "report.py": "from pricing import total\n\ndef report():\n    return total([1], 2)\n",
    })
    total = symbol(build_change_map(tmp_path, "HEAD"), "pricing.total")
    assert total["callers"][0]["in_change"] is True
    assert total["callers_not_updated"] == 0


def test_deleted_function_still_called_elsewhere_is_reported(tmp_path):
    repo(tmp_path, {
        "util.py": "def helper():\n    return 1\n\ndef keep():\n    return 2\n",
        "use.py": "from util import helper\n\ndef use():\n    return helper()\n",
    })
    write(tmp_path, {"util.py": "def keep():\n    return 2\n"})
    helper = symbol(build_change_map(tmp_path, "HEAD"), "util.helper")
    assert helper["status"] == "deleted"
    assert helper["still_referenced_by"] == ["use.use"]


def test_comment_only_change_inside_function_is_not_a_symbol_change(tmp_path):
    repo(tmp_path, {"app.py": "def f():\n    # old\n    return 1\n"})
    write(tmp_path, {"app.py": "def f():\n    # new wording\n    return 1\n"})
    assert build_change_map(tmp_path, "HEAD")["symbols"] == []


def test_untracked_new_file_is_mapped_as_added(tmp_path):
    repo(tmp_path, {"app.py": "def f():\n    return 1\n"})
    write(tmp_path, {"new.py": "def fresh():\n    return 2\n"})
    fresh = symbol(build_change_map(tmp_path, "HEAD"), "new.fresh")
    assert fresh["status"] == "added"
    assert fresh["callers"] == []
    assert "no callers found" in fresh["reasons"]


def test_same_shape_changes_are_grouped(tmp_path):
    base = "".join(f"def f{i}(x):\n    return x\n\n" for i in range(3))
    head = "".join(f"def f{i}(x):\n    audit(x)\n    return x\n\n" for i in range(3))
    repo(tmp_path, {"app.py": "def audit(x):\n    return x\n\n" + base})
    write(tmp_path, {"app.py": "def audit(x):\n    return x\n\n" + head})
    result = build_change_map(tmp_path, "HEAD")
    assert result["groups"] == [{
        "status": "modified",
        "calls_added": ["app.audit"],
        "calls_removed": [],
        "members": ["app.py::f0", "app.py::f1", "app.py::f2"],
    }]


def test_non_python_and_unparsable_files_are_listed_in_coverage(tmp_path):
    repo(tmp_path, {"app.py": "def f():\n    return 1\n", "README.md": "old\n"})
    write(tmp_path, {"app.py": "def f(:\n", "README.md": "new\n"})
    coverage = build_change_map(tmp_path, "HEAD")["coverage"]
    assert coverage["not_mapped"] == ["README.md"]
    assert coverage["unparsed"] == ["app.py"]


def test_method_changes_use_class_qualified_names(tmp_path):
    repo(tmp_path, {"svc.py": "class Store:\n    def get(self, key):\n        return key\n"})
    write(tmp_path, {"svc.py": "class Store:\n    def get(self, key):\n        return key.lower()\n"})
    get = symbol(build_change_map(tmp_path, "HEAD"), "svc.Store.get")
    assert get["kind"] == "method"
    assert get["status"] == "modified"


def test_change_map_is_deterministic(tmp_path):
    repo(tmp_path, {
        "a.py": "def a():\n    return b()\n\ndef b():\n    return 1\n",
        "c.py": "from a import a\n\ndef c():\n    return a()\n",
    })
    write(tmp_path, {"a.py": "def a(x=1):\n    return b() + x\n\ndef b():\n    return 2\n"})
    first = json.dumps(build_change_map(tmp_path, "HEAD"), sort_keys=True)
    second = json.dumps(build_change_map(tmp_path, "HEAD"), sort_keys=True)
    assert first == second


def test_invalid_base_ref_raises_a_clear_error(tmp_path):
    repo(tmp_path, {"app.py": "def f():\n    return 1\n"})
    with pytest.raises(ValueError, match="base"):
        build_change_map(tmp_path, "no-such-ref")


def test_unchanged_test_caller_is_counted_apart_from_production_callers(tmp_path):
    repo(tmp_path, {
        "pricing.py": "def total(items):\n    return sum(items)\n",
        "report.py": "from pricing import total\n\ndef report():\n    return total([1])\n",
        "tests/test_pricing.py": "from pricing import total\n\ndef test_total():\n    assert total([1]) == 1\n",
    })
    write(tmp_path, {
        "pricing.py": "def total(items, tax=1):\n    return sum(items) * tax\n",
        "report.py": "from pricing import total\n\ndef report():\n    return total([1], 2)\n",
    })
    total = symbol(build_change_map(tmp_path, "HEAD"), "pricing.total")
    assert total["callers_not_updated"] == 0
    assert total["test_callers_not_updated"] == 1


def test_new_subprocess_call_is_risky_but_result_attributes_are_not_calls(tmp_path):
    repo(tmp_path, {"run.py": "import subprocess\n\ndef go():\n    return 0\n"})
    write(tmp_path, {"run.py": (
        "import subprocess\n\n"
        "def go():\n"
        "    try:\n"
        "        return subprocess.run(['ls'], check=False).returncode\n"
        "    except subprocess.SubprocessError:\n"
        "        return 1\n"
    )})
    go = symbol(build_change_map(tmp_path, "HEAD"), "run.go")
    assert go["risky_calls_added"] == ["subprocess.run"]
    assert go["calls_added"] == ["subprocess.run"]


def _removed_auth_repo(tmp_path):
    repo(tmp_path, {
        "auth.py": AUTH,
        "app.py": "from auth import require_auth\n\ndef handler(user):\n    require_auth(user)\n    return 1\n",
        "notes.md": "old\n",
    })
    write(tmp_path, {
        "app.py": "from auth import require_auth\n\ndef handler(user):\n    return 1\n\ndef helper():\n    return 2\n",
        "notes.md": "new\n",
    })
    return build_change_map(tmp_path, "HEAD")


def test_markdown_puts_removed_auth_first_with_reason_and_code(tmp_path):
    text = render_markdown(_removed_auth_repo(tmp_path), repo_url="https://github.com/o/r", head_sha="abc123")
    read_first = text.split("#### Read first")[1].split("####")[0]
    assert "**1. `handler`** modified · **flagged** · [app.py:3](https://github.com/o/r/blob/abc123/app.py#L3-L4)" in read_first
    assert "**2. `helper`** added · [app.py:6]" in read_first
    assert "- Why: stopped calling auth.require_auth" in read_first
    assert "- Removed security checks: `auth.require_auth`" in read_first
    assert "Before (lines 3-5):" in read_first
    assert "Not mapped: 1 file(s) that are not Python or TypeScript/JavaScript." in text
    assert "```python\ndef handler(user):" in text
    assert "computed from the code, not written by a model" in text


def test_markdown_lists_symbols_after_the_top_three_under_safe_to_skim(tmp_path):
    repo(tmp_path, {"m.py": "def keep():\n    return 0\n"})
    write(tmp_path, {"m.py": "def keep():\n    return 0\n" + "".join(f"\ndef f{i}():\n    return {i}\n" for i in range(5))})
    text = render_markdown(build_change_map(tmp_path, "HEAD"))
    read_first = text.split("#### Read first")[1].split("####")[0]
    skim = text.split("#### Safe to skim")[1]
    assert "**3. `f2`** added" in read_first
    assert "- `f3` added · m.py:13 · 0 caller(s)" in skim
    assert "- `f4` added · m.py:16 · 0 caller(s)" in skim


def test_text_render_has_no_markdown_and_same_order(tmp_path):
    text = render_text(_removed_auth_repo(tmp_path))
    assert "`" not in text
    assert text.index("READ FIRST") < text.index("1. handler  modified  FLAGGED  app.py:3") < text.index("2. helper  added  app.py:6")
    assert "     Removed security checks: auth.require_auth" in text


def test_markdown_is_capped_for_pull_request_comments(tmp_path):
    body = "".join(f"def f{i}(x):\n    return x\n\n" for i in range(400))
    head = "".join(f"def f{i}(x):\n    return x + {i}\n\n" for i in range(400))
    repo(tmp_path, {"big.py": body})
    write(tmp_path, {"big.py": head})
    text = render_markdown(build_change_map(tmp_path, "HEAD"))
    assert len(text) <= 60100
    assert "+357 more in the JSON output" in text


GUARD_BASE = (
    "from fastapi import Depends, HTTPException\n\n"
    "def get_user():\n"
    "    return None\n\n"
    "def require_permission(name):\n"
    "    return get_user\n\n"
    "def cancel(request, user=Depends(get_user)):\n"
    "    if user is None or user.role != 'admin':\n"
    "        raise HTTPException(status_code=403, detail='admin only')\n"
    "    return {'ok': True}\n"
)


def test_deleted_inline_403_check_is_a_removed_security_check(tmp_path):
    repo(tmp_path, {"routes.py": GUARD_BASE})
    write(tmp_path, {"routes.py": GUARD_BASE.replace(
        "    if user is None or user.role != 'admin':\n        raise HTTPException(status_code=403, detail='admin only')\n", ""
    )})
    cancel = symbol(build_change_map(tmp_path, "HEAD"), "routes.cancel")
    assert cancel["security_removed"] == ["inline 403 check"]
    assert cancel["guards_replaced_by"] == []
    assert "removed inline 403 check" in cancel["reasons"]
    assert cancel["risk"] >= 6


def test_inline_check_replaced_by_permission_dependency_is_reported_as_replaced(tmp_path):
    repo(tmp_path, {"routes.py": GUARD_BASE})
    write(tmp_path, {"routes.py": GUARD_BASE.replace(
        "def cancel(request, user=Depends(get_user)):\n    if user is None or user.role != 'admin':\n"
        "        raise HTTPException(status_code=403, detail='admin only')\n",
        "def cancel(request, user=Depends(require_permission('platform.manage'))):\n",
    )})
    result = build_change_map(tmp_path, "HEAD")
    cancel = symbol(result, "routes.cancel")
    assert cancel["security_removed"] == []
    assert cancel["guards_replaced_by"] == ["require_permission"]
    assert "access check changed: inline 403 check replaced by require_permission" in cancel["reasons"]
    assert result["read_first"][0] == cancel["id"]


def test_new_optional_parameter_is_compatible_and_names_callers_using_the_default(tmp_path):
    repo(tmp_path, {
        "redact.py": "def redact(text):\n    return text\n",
        "use.py": "from redact import redact\n\ndef show(t):\n    return redact(t)\n",
    })
    write(tmp_path, {"redact.py": "def redact(text, secrets=frozenset()):\n    return text\n"})
    redact = symbol(build_change_map(tmp_path, "HEAD"), "redact.redact")
    assert redact["signature_change"] == "compatible"
    assert redact["new_optional_params"] == ["secrets"]
    assert redact["callers_not_updated"] == 1
    assert "new optional parameter secrets; 1 caller(s) not in this change use the default" in redact["reasons"]


def test_new_required_parameter_is_breaking(tmp_path):
    repo(tmp_path, {
        "redact.py": "def redact(text):\n    return text\n",
        "use.py": "from redact import redact\n\ndef show(t):\n    return redact(t)\n",
    })
    write(tmp_path, {"redact.py": "def redact(text, secrets):\n    return text\n"})
    redact = symbol(build_change_map(tmp_path, "HEAD"), "redact.redact")
    assert redact["signature_change"] == "breaking"
    assert "breaking signature change, 1 caller(s) not in this change" in redact["reasons"]


def test_module_constant_change_lists_the_functions_that_use_it(tmp_path):
    repo(tmp_path, {"run.py": "CMD = ['python']\n\ndef go():\n    return CMD + ['x']\n\ndef other():\n    return 1\n"})
    write(tmp_path, {"run.py": "CMD = ['python', '-I']\n\ndef go():\n    return CMD + ['x']\n\ndef other():\n    return 1\n"})
    result = build_change_map(tmp_path, "HEAD")
    assert result["module_changes"] == [{"file": "run.py", "name": "CMD", "line": 1, "used_by": ["go"]}]
    assert result["symbols"] == []


def test_read_first_shows_top_symbols_even_without_alarms(tmp_path):
    repo(tmp_path, {"m.py": "def a():\n    return 1\n\ndef b():\n    return a()\n"})
    write(tmp_path, {"m.py": "def a():\n    return 2\n\ndef b():\n    return a() + 1\n"})
    result = build_change_map(tmp_path, "HEAD")
    assert result["read_first"] == ["m.py::a", "m.py::b"]
    assert result["flagged"] == []


def test_every_flagged_symbol_is_read_first_and_never_safe_to_skim(tmp_path):
    def handlers(guarded):
        call = ""
        if guarded:
            call = "    require_auth(user)\n"
        return "from auth import require_auth\n" + "".join(
            f"\ndef h{i}(user):\n{call}    return {i}\n" for i in range(5)
        )

    repo(tmp_path, {"auth.py": AUTH, "app.py": handlers(True)})
    write(tmp_path, {"app.py": handlers(False)})
    result = build_change_map(tmp_path, "HEAD")
    ids = [f"app.py::h{i}" for i in range(5)]
    assert sorted(result["flagged"]) == ids
    assert sorted(result["read_first"]) == ids
    text = render_markdown(result)
    assert "#### Safe to skim" not in text
    assert "**5. `h" in text.split("#### Read first")[1]


def test_audit_logging_does_not_count_as_a_replacement_access_check(tmp_path):
    repo(tmp_path, {"routes.py": GUARD_BASE + "\ndef log_auth_event(name):\n    return name\n"})
    write(tmp_path, {"routes.py": GUARD_BASE.replace(
        "    if user is None or user.role != 'admin':\n        raise HTTPException(status_code=403, detail='admin only')\n",
        "    log_auth_event('cancel')\n",
    ) + "\ndef log_auth_event(name):\n    return name\n"})
    cancel = symbol(build_change_map(tmp_path, "HEAD"), "routes.cancel")
    assert cancel["security_removed"] == ["inline 403 check"]
    assert cancel["guards_replaced_by"] == []


def test_function_moved_to_a_new_file_is_marked_moved_not_new_risk(tmp_path):
    body = "def stop(proc):\n    subprocess.run(['kill', str(proc)])\n    return True\n"
    repo(tmp_path, {
        "manager.py": "import subprocess\n\n" + body + "\ndef run(p):\n    return stop(p)\n",
    })
    write(tmp_path, {
        "manager.py": "from process import stop\n\ndef run(p):\n    return stop(p)\n",
        "process.py": "import subprocess\n\n" + body,
    })
    result = build_change_map(tmp_path, "HEAD")
    moved = symbol(result, "process.stop")
    old = symbol(result, "manager.stop")
    assert moved["moved_from"] == "manager.py::stop"
    assert old["moved_to"] == "process.py::stop"
    assert moved["risky_calls_added"] == []
    assert "moved from manager.py, code unchanged" in moved["reasons"]
    assert moved["id"] not in result["flagged"]


def test_new_constants_and_test_constants_are_not_module_value_changes(tmp_path):
    repo(tmp_path, {
        "app.py": "LIMIT = 1\n\ndef f():\n    return LIMIT\n",
        "tests/test_app.py": "CANARY = 'a'\n\ndef test_f():\n    assert CANARY\n",
    })
    write(tmp_path, {
        "app.py": "LIMIT = 1\nNEW = 2\n\ndef f():\n    return LIMIT + NEW\n",
        "tests/test_app.py": "CANARY = 'b'\n\ndef test_f():\n    assert CANARY\n",
    })
    assert build_change_map(tmp_path, "HEAD")["module_changes"] == []


def test_methods_moved_into_a_new_subclass_without_text_changes_are_mapped(tmp_path):
    base = (
        "class Backend:\n"
        "    def receive(self):\n        return 1\n\n"
        "    def offload(self, tags):\n        return tags\n"
    )
    head = (
        "class Backend:\n"
        "    def receive(self):\n        return 1\n\n\n"
        "class HandoffBackend(Backend):\n"
        "    def offload(self, tags):\n        return tags\n"
    )
    repo(tmp_path, {"iface.py": base})
    write(tmp_path, {"iface.py": head})
    result = build_change_map(tmp_path, "HEAD")
    old = symbol(result, "iface.Backend.offload")
    new = symbol(result, "iface.HandoffBackend.offload")
    assert old["status"] == "deleted"
    assert new["status"] == "added"
    assert new["moved_from"] == "iface.py::Backend.offload"
    assert symbol(result, "iface.HandoffBackend")["status"] == "added"


def test_constructor_calls_count_as_callers_of_init(tmp_path):
    repo(tmp_path, {
        "mw.py": "class Middleware:\n    def __init__(self, guard):\n        self.guard = guard\n",
        "agent.py": "from mw import Middleware\n\ndef agent():\n    return Middleware(guard=None)\n",
    })
    write(tmp_path, {"mw.py": "class Middleware:\n    def __init__(self, guard, skills=None):\n        self.guard = guard\n        self.skills = skills\n"})
    init = symbol(build_change_map(tmp_path, "HEAD"), "mw.Middleware.__init__")
    assert [c["name"] for c in init["callers"]] == ["agent.agent"]
    assert init["callers"][0]["line"] == 4


def test_changed_security_class_setting_is_flagged_with_the_methods_that_read_it(tmp_path):
    base = (
        "class ClaudeCode:\n"
        "    permission_mode = 'plan'\n"
        "    timeout = 30\n\n"
        "    def build(self):\n        return ['--permission-mode', self.permission_mode]\n\n"
        "    def other(self):\n        return self.timeout\n"
    )
    repo(tmp_path, {"cli.py": base})
    write(tmp_path, {"cli.py": base.replace("'plan'", "'dontAsk'")})
    result = build_change_map(tmp_path, "HEAD")
    cls = symbol(result, "cli.ClaudeCode")
    assert cls["values_changed"] == [
        {"name": "permission_mode", "before": "'plan'", "after": "'dontAsk'", "used_by": ["ClaudeCode.build"], "security": True}
    ]
    assert "security setting changed: permission_mode 'plan' → 'dontAsk'" in cls["reasons"]
    assert result["flagged"] == ["cli.py::ClaudeCode"]


def test_authentication_and_british_spellings_count_as_security_names(tmp_path):
    base = (
        "def check_authentication(user):\n    return user\n\n"
        "def authorise(user):\n    return user\n\n"
        "def handler(user):\n    check_authentication(user)\n    authorise(user)\n    return 1\n\n"
        "class View:\n    authentication_classes = ['Session']\n\n"
        "    def get(self):\n        return self.authentication_classes\n"
    )
    repo(tmp_path, {"views.py": base})
    write(tmp_path, {"views.py": base.replace("    check_authentication(user)\n    authorise(user)\n", "").replace("['Session']", "[]")})
    result = build_change_map(tmp_path, "HEAD")
    assert symbol(result, "views.handler")["security_removed"] == ["views.authorise", "views.check_authentication"]
    assert symbol(result, "views.View")["values_changed"][0]["security"] is True
    assert sorted(result["flagged"]) == ["views.py::View", "views.py::handler"]


def test_changed_plain_class_setting_is_listed_but_not_flagged(tmp_path):
    base = "class Job:\n    retries = 3\n\n    def run(self):\n        return self.retries\n"
    repo(tmp_path, {"job.py": base})
    write(tmp_path, {"job.py": base.replace("retries = 3", "retries = 5")})
    result = build_change_map(tmp_path, "HEAD")
    job = symbol(result, "job.Job")
    assert job["values_changed"][0]["used_by"] == ["Job.run"]
    assert job["values_changed"][0]["security"] is False
    assert result["flagged"] == []


def test_removing_a_dataclass_field_is_a_breaking_constructor_change(tmp_path):
    repo(tmp_path, {
        "session.py": (
            "from dataclasses import dataclass\n\n"
            "@dataclass\nclass Session:\n    protocol: str\n    receiver: object\n    session_id: str\n"
        ),
        "use.py": "from session import Session\n\ndef make():\n    return Session('p', None, 's')\n",
    })
    write(tmp_path, {"session.py": (
        "from dataclasses import dataclass\n\n"
        "@dataclass\nclass Session:\n    protocol: str\n    session_id: str\n"
    )})
    session = symbol(build_change_map(tmp_path, "HEAD"), "session.Session")
    assert session["signature_change"] == "breaking"
    assert session["callers_not_updated"] == 1
    assert "breaking signature change, 1 caller(s) not in this change" in session["reasons"]


def test_rendered_map_shows_changed_class_values_and_their_readers(tmp_path):
    base = "class ClaudeCode:\n    permission_mode = 'plan'\n\n    def build(self):\n        return [self.permission_mode]\n"
    repo(tmp_path, {"cli.py": base})
    write(tmp_path, {"cli.py": base.replace("'plan'", "'dontAsk'")})
    text = render_markdown(build_change_map(tmp_path, "HEAD"))
    assert "- Value changed: `permission_mode` 'plan' → 'dontAsk' (read by `ClaudeCode.build`)" in text


def test_constructor_callers_need_a_real_call_not_a_type_annotation(tmp_path):
    repo(tmp_path, {
        "pub.py": "class Publisher:\n    def __init__(self, backend):\n        self.backend = backend\n",
        "use.py": (
            "from pub import Publisher\n\n"
            "def make():\n    return Publisher(None)\n\n"
            "def typed(p: Publisher):\n    return p\n"
        ),
    })
    write(tmp_path, {"pub.py": "class Publisher:\n    def __init__(self, backend, *, quiet=False):\n        self.backend = backend\n"})
    init = symbol(build_change_map(tmp_path, "HEAD"), "pub.Publisher.__init__")
    assert [c["name"] for c in init["callers"]] == ["use.make"]


def test_calls_through_a_subfolder_import_root_are_resolved(tmp_path):
    repo(tmp_path, {
        "mda/rt/__init__.py": "",
        "mda/rt/file_tools.py": "class FileTools:\n    def __init__(self, guard):\n        self.guard = guard\n",
        "mda/agent.py": "from rt.file_tools import FileTools\n\ndef agent():\n    return FileTools(guard=None)\n",
    })
    write(tmp_path, {"mda/rt/file_tools.py": "class FileTools:\n    def __init__(self, guard, skills=None):\n        self.guard = guard\n"})
    init = symbol(build_change_map(tmp_path, "HEAD"), "mda.rt.file_tools.FileTools.__init__")
    assert [c["file"] for c in init["callers"]] == ["mda/agent.py"]


def test_method_called_on_an_untyped_receiver_is_a_possible_caller(tmp_path):
    repo(tmp_path, {
        "svc.py": "class Service:\n    def attach(self, transport):\n        return transport\n",
        "use.py": (
            "from svc import Service\n\n"
            "def wire(service, t):\n    return service.attach(t)\n"
        ),
        "other.py": "def unrelated(thing, t):\n    return thing.attach(t)\n",
    })
    write(tmp_path, {"svc.py": "class Service:\n    def attach(self, transport):\n        return [transport]\n"})
    attach = symbol(build_change_map(tmp_path, "HEAD"), "svc.Service.attach")
    assert attach["callers"] == []
    assert attach["possible_callers"] == [
        {"name": "use.wire", "file": "use.py", "line": 4, "in_change": False, "is_test": False}
    ]


def test_rendered_map_labels_possible_callers_as_unproven(tmp_path):
    repo(tmp_path, {
        "svc.py": "class Service:\n    def attach(self, transport):\n        return transport\n",
        "use.py": "from svc import Service\n\ndef wire(service, t):\n    return service.attach(t)\n",
    })
    write(tmp_path, {"svc.py": "class Service:\n    def attach(self, transport):\n        return [transport]\n"})
    text = render_markdown(build_change_map(tmp_path, "HEAD"))
    assert "- Called by: none found" in text
    assert "- Maybe called by (same method name, receiver type not proven): `wire` use.py:4" in text


SERVICE_BASE = (
    "class Base:\n    def attach(self, transport):\n        return transport\n\n\n"
    "class Service(Base):\n    def attach(self, transport):\n        return transport\n\n"
    "    @property\n    def protocol(self):\n        return 'tcp'\n"
)
SERVICE_HEAD = SERVICE_BASE.replace("        return transport\n\n    @property", "        return [transport]\n\n    @property").replace("return 'tcp'", "return 'udp'")


def _typed_repo(tmp_path, use_source):
    repo(tmp_path, {"svc.py": SERVICE_BASE, "use.py": use_source})
    write(tmp_path, {"svc.py": SERVICE_HEAD})
    return build_change_map(tmp_path, "HEAD")


def _names(entries):
    return [e["name"] for e in entries]


def test_annotated_parameter_receiver_is_a_proven_caller(tmp_path):
    result = _typed_repo(tmp_path, "from svc import Service\n\ndef wire(service: Service, t):\n    return service.attach(t)\n")
    attach = symbol(result, "svc.Service.attach")
    assert _names(attach["callers"]) == ["use.wire"]
    assert attach["callers"][0]["line"] == 4
    assert attach["possible_callers"] == []


def test_optional_and_string_annotations_are_proven_callers(tmp_path):
    result = _typed_repo(tmp_path, (
        "from typing import Optional\nfrom svc import Service\n\n"
        "def a(s: Optional[Service], t):\n    return s.attach(t)\n\n"
        "def b(s: 'Service | None', t):\n    return s.attach(t)\n"
    ))
    assert _names(symbol(result, "svc.Service.attach")["callers"]) == ["use.a", "use.b"]


def test_self_attribute_typed_in_init_or_class_body_is_a_proven_caller(tmp_path):
    result = _typed_repo(tmp_path, (
        "from svc import Service\n\n"
        "class Publisher:\n"
        "    def __init__(self, service: Service):\n        self.service = service\n\n"
        "    def send(self, t):\n        return self.service.attach(t)\n\n\n"
        "class Holder:\n"
        "    service: Service\n\n"
        "    def send(self, t):\n        return self.service.attach(t)\n\n\n"
        "class Builder:\n"
        "    def __init__(self):\n        self.service = Service()\n\n"
        "    def send(self, t):\n        return self.service.attach(t)\n"
    ))
    assert _names(symbol(result, "svc.Service.attach")["callers"]) == ["use.Builder.send", "use.Holder.send", "use.Publisher.send"]


def test_local_instance_receiver_is_a_proven_caller(tmp_path):
    result = _typed_repo(tmp_path, "from svc import Service\n\ndef run(t):\n    service = Service()\n    return service.attach(t)\n")
    assert _names(symbol(result, "svc.Service.attach")["callers"]) == ["use.run"]


def test_property_read_on_a_typed_receiver_is_a_proven_caller(tmp_path):
    result = _typed_repo(tmp_path, "from svc import Service\n\ndef proto(service: Service):\n    return service.protocol\n")
    prop = symbol(result, "svc.Service.protocol")
    assert _names(prop["callers"]) == ["use.proto"]
    assert prop["callers"][0]["line"] == 4


def test_receiver_typed_as_the_base_class_stays_a_possible_caller(tmp_path):
    result = _typed_repo(tmp_path, "from svc import Base, Service\n\ndef wire(service: Base, t):\n    return service.attach(t)\n")
    attach = symbol(result, "svc.Service.attach")
    assert attach["callers"] == []
    assert _names(attach["possible_callers"]) == ["use.wire"]


def test_receiver_typed_as_an_unrelated_class_is_not_a_caller_at_all(tmp_path):
    result = _typed_repo(tmp_path, (
        "from svc import Service\n\n"
        "class Other:\n    def attach(self, t):\n        return t\n\n"
        "def wire(other: Other, t):\n    return other.attach(t)\n"
    ))
    attach = symbol(result, "svc.Service.attach")
    assert attach["callers"] == []
    assert attach["possible_callers"] == []


def test_self_use_in_a_subclass_that_overrides_the_member_is_not_a_caller_of_the_base(tmp_path):
    base = (
        "class Training:\n"
        "    @property\n    def protocols(self):\n        return ('nccl',)\n\n\n"
        "class Tinker(Training):\n"
        "    @property\n    def protocols(self):\n        return ('tinker',)\n\n"
        "    def attach(self):\n        return self.protocols\n\n\n"
        "class Slime(Training):\n"
        "    def attach(self):\n        return self.protocols\n"
    )
    repo(tmp_path, {"svc.py": base})
    write(tmp_path, {"svc.py": base.replace("('nccl',)", "('nccl', 'gloo')")})
    prop = symbol(build_change_map(tmp_path, "HEAD"), "svc.Training.protocols")
    assert _names(prop["callers"]) == ["svc.Slime.attach"]


SURFACE_BASE = (
    "from dataclasses import dataclass\n\n"
    "@dataclass\nclass Surface:\n    tools: tuple = ()\n    root: str = ''\n    guards: tuple = ()\n"
)
SURFACE_HEAD = SURFACE_BASE.replace("    root: str = ''\n", "    skills: tuple = ()\n    root: str = ''\n")


def test_field_inserted_mid_order_is_safe_when_callers_use_keywords(tmp_path):
    repo(tmp_path, {
        "surface.py": SURFACE_BASE,
        "plan.py": "from surface import Surface\n\ndef plan():\n    return Surface(tools=(), root='/r')\n",
    })
    write(tmp_path, {"surface.py": SURFACE_HEAD})
    result = build_change_map(tmp_path, "HEAD")
    surface = symbol(result, "surface.Surface")
    assert surface["signature_change"] == "breaking"
    assert surface["callers_not_updated"] == 0
    assert "incompatible signature change, but no caller outside this change breaks" in surface["reasons"]
    assert surface["id"] not in result["flagged"]


def test_field_inserted_mid_order_breaks_a_positional_caller(tmp_path):
    repo(tmp_path, {
        "surface.py": SURFACE_BASE,
        "plan.py": "from surface import Surface\n\ndef plan():\n    return Surface((), '/r')\n",
    })
    write(tmp_path, {"surface.py": SURFACE_HEAD})
    result = build_change_map(tmp_path, "HEAD")
    surface = symbol(result, "surface.Surface")
    assert surface["callers_not_updated"] == 1
    assert surface["id"] in result["flagged"]


def test_removed_keyword_breaks_the_caller_that_passes_it(tmp_path):
    repo(tmp_path, {
        "api.py": "def fetch(url, timeout=5, retries=1):\n    return url\n",
        "use.py": "from api import fetch\n\ndef a():\n    return fetch('x', retries=3)\n\ndef b():\n    return fetch('y')\n",
    })
    write(tmp_path, {"api.py": "def fetch(url, timeout=5):\n    return url\n"})
    fetch = symbol(build_change_map(tmp_path, "HEAD"), "api.fetch")
    assert fetch["callers_not_updated"] == 1
    assert fetch["breaking_callers"] == ["use.a"]


def test_method_call_checks_arguments_after_self(tmp_path):
    repo(tmp_path, {
        "svc.py": "class Service:\n    def attach(self, transport):\n        return transport\n",
        "use.py": "from svc import Service\n\ndef wire(service: Service):\n    return service.attach('tcp')\n",
    })
    write(tmp_path, {"svc.py": "class Service:\n    def attach(self, transport, *, retries=0):\n        return transport\n"})
    attach = symbol(build_change_map(tmp_path, "HEAD"), "svc.Service.attach")
    assert attach["signature_change"] == "compatible"
    assert attach["breaking_callers"] == []


PARSE_BASE = (
    "def parse(units):\n"
    "    out = []\n"
    "    for unit in units:\n"
    "        if not any(c.isalnum() for c in unit):\n"
    "            raise ValueError('units must contain a letter or number')\n"
    "        out.append(unit)\n"
    "    return out\n"
)


def test_removed_validation_raise_is_flagged(tmp_path):
    repo(tmp_path, {"q.py": PARSE_BASE})
    write(tmp_path, {"q.py": PARSE_BASE.replace("            raise ValueError('units must contain a letter or number')\n", "            continue\n")})
    result = build_change_map(tmp_path, "HEAD")
    parse = symbol(result, "q.parse")
    assert parse["rejections_removed"] == ["raise ValueError('units must contain a letter or number')"]
    assert "stopped rejecting: raise ValueError('units must contain a letter or number')" in parse["reasons"]
    assert parse["id"] in result["flagged"]


def test_raise_moved_into_a_helper_is_not_a_removed_rejection(tmp_path):
    repo(tmp_path, {"q.py": PARSE_BASE})
    write(tmp_path, {"q.py": (
        "def _check(unit):\n"
        "    if not any(c.isalnum() for c in unit):\n"
        "        raise ValueError('units must contain a letter or number')\n\n"
        "def parse(units):\n"
        "    out = []\n"
        "    for unit in units:\n"
        "        _check(unit)\n"
        "        out.append(unit)\n"
        "    return out\n"
    )})
    result = build_change_map(tmp_path, "HEAD")
    parse = symbol(result, "q.parse")
    assert parse["rejections_removed"] == []
    assert parse["id"] not in result["flagged"]


def test_removed_non_validation_raise_is_listed_but_not_flagged(tmp_path):
    base = "def get(cache, key):\n    if key not in cache:\n        raise KeyError(key)\n    return cache[key]\n"
    repo(tmp_path, {"c.py": base})
    write(tmp_path, {"c.py": "def get(cache, key):\n    return cache.get(key)\n"})
    result = build_change_map(tmp_path, "HEAD")
    get = symbol(result, "c.get")
    assert get["rejections_removed"] == ["raise KeyError()"]
    assert get["id"] not in result["flagged"]
