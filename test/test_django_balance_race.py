from textwrap import indent

import pytest

from skylos.rules.danger.danger import scan_ctx

MODEL = """from django.db import models

class Account(models.Model):
    credits = models.IntegerField()
"""

VIEW = """from django.db import transaction
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from .models import Account
{decorator}def spend(request, account_id, amount):
{body}
"""

URLS = """from django.urls import path
from .views import spend

urlpatterns = [path("spend/<int:account_id>/<int:amount>/", spend)]
"""

DEBIT = """account = Account.objects.get(pk=account_id)
if account.credits < amount:
    return None
account.credits -= amount
account.save(update_fields=["credits"])"""


def _scan(tmp_path, body=DEBIT, *, decorator="", model=MODEL, urls=URLS):
    app = tmp_path / "ledger"
    app.mkdir()
    (app / "__init__.py").touch()
    (app / "models.py").write_text(model)
    (app / "urls.py").write_text(urls)
    path = app / "views.py"
    path.write_text(VIEW.format(decorator=decorator, body=indent(body, "    ")))
    return [f for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == "SKY-D385"]


@pytest.mark.parametrize(
    "decorator",
    [
        "",
        "@require_POST\n",
        "@transaction.atomic\n",
        "@login_required\n",
        "@login_required(login_url='/sign-in/')\n",
    ],
)
def test_registered_django_view_reports_guarded_decrement(tmp_path, decorator):
    (row,) = _scan(tmp_path, decorator=decorator)
    assert (row["line"], row["symbol"], row["severity"]) == (
        10 + decorator.count("\n"),
        "spend",
        "MEDIUM",
    )
    assert "line " in row["message"]


@pytest.mark.parametrize(
    "prelude", ["cost = amount", "cost = 1", "delta = amount\ncost = delta"]
)
def test_amount_from_route_or_literal(tmp_path, prelude):
    debit = DEBIT.replace("amount", "cost")
    assert _scan(tmp_path, prelude + "\n" + debit)


def test_display_method_and_meta(tmp_path):
    model = (
        MODEL
        + """    def __str__(self):
        return f"Account {self.pk}"
    class Meta:
        verbose_name = "account"
        ordering = ("credits",)
"""
    )
    assert _scan(tmp_path, model=model)


def test_explicit_guarded_subtraction(tmp_path):
    body = DEBIT.replace(
        "account.credits -= amount", "account.credits = account.credits - amount"
    )
    assert _scan(tmp_path, body)


def test_transaction_without_lock_still_uses_stale_read(tmp_path):
    assert _scan(tmp_path, "with transaction.atomic():\n" + indent(DEBIT, "    "))


@pytest.mark.parametrize(
    "guard", ["account.credits >= amount", "amount <= account.credits"]
)
def test_positive_eligibility_branch(tmp_path, guard):
    read, _, _, change, save = DEBIT.splitlines()
    body = f"{read}\nif {guard}:\n" + indent(f"{change}\n{save}\nreturn True", "    ")
    assert _scan(tmp_path, body + "\nreturn False")


def test_reversed_insufficient_balance_comparison(tmp_path):
    body = DEBIT.replace("account.credits < amount", "amount > account.credits")
    assert _scan(tmp_path, body)


def test_different_amount_in_positive_guard(tmp_path):
    read, _, _, change, save = DEBIT.splitlines()
    body = f"{read}\nif account.credits >= 1:\n" + indent(f"{change}\n{save}", "    ")
    assert not _scan(tmp_path, body)


@pytest.mark.parametrize("wrapped", [False, True])
def test_preview_explicitly_rolls_back_the_default_atomic_block(tmp_path, wrapped):
    body = DEBIT + '\ntransaction.set_rollback(True, using="default")\nreturn None'
    decorator = "@transaction.atomic\n"
    if wrapped:
        body = 'with transaction.atomic(using="default"):\n' + indent(body, "    ")
        decorator = ""
    assert not _scan(tmp_path, body, decorator=decorator)


@pytest.mark.parametrize(
    "decorator,tail",
    [
        ("", "transaction.set_rollback(True)"),
        ("@transaction.atomic\n", "if amount == 1: transaction.set_rollback(True)"),
        (
            "@transaction.atomic\n",
            "transaction.set_rollback(True)\ntransaction.set_rollback(False)",
        ),
        ("@transaction.atomic\n", 'transaction.set_rollback(True, using="audit")'),
        ('@transaction.atomic(using="audit")\n', "transaction.set_rollback(True)"),
        ("@transaction.atomic\n", "other.set_rollback(True)"),
        (
            "@transaction.atomic\n",
            "transaction.set_rollback(True)\nreturn finish_preview()",
        ),
        ("@transaction.atomic\n", "transaction.set_rollback(amount == 1)"),
    ],
)
def test_uncertain_rollback_keeps_review(tmp_path, decorator, tail):
    assert _scan(tmp_path, DEBIT + "\n" + tail, decorator=decorator)


def test_rollback_after_atomic_exits_keeps_review(tmp_path):
    body = "with transaction.atomic():\n" + indent(DEBIT, "    ")
    assert _scan(tmp_path, body + "\ntransaction.set_rollback(True)")


@pytest.mark.parametrize(
    "setting",
    [
        'DATABASE_ROUTERS = ["app.Routing"]',
        'DATABASES = {"default": {}, "ledger": {}}',
        "from django.db import router\nrouter.routers = [custom_router]",
        "from django.db import transaction\ntransaction.set_rollback = custom_rollback",
        'from django.db import transaction\nsetattr(transaction, "set_rollback", custom_rollback)',
    ],
)
def test_custom_routing_or_transaction_helpers_keep_the_review(tmp_path, setting):
    (tmp_path / "settings.py").write_text(setting)
    assert _scan(
        tmp_path,
        DEBIT + "\ntransaction.set_rollback(True)",
        decorator="@transaction.atomic\n",
    )


@pytest.mark.parametrize(
    "body",
    [
        DEBIT.replace(".objects.get(", ".objects.select_for_update().get("),
        DEBIT.replace(
            "account.credits -= amount", "account.credits = F('credits') - amount"
        ),
        'Account.objects.filter(pk=account_id, credits__gte=amount).update(credits=F("credits") - amount)',
        "with guard:\n" + indent(DEBIT, "    "),
        "with transaction.atomic():\n"
        + indent(
            "Account.objects.select_for_update().get(pk=account_id)\n" + DEBIT, "    "
        ),
        "return None\n" + DEBIT,
        "if False:\n" + indent(DEBIT, "    "),
        DEBIT.replace('["credits"]', '["updated"]'),
        DEBIT.replace("if account.credits", "if another.credits"),
        DEBIT.replace("account.credits -=", "account.visits -="),
        DEBIT.replace("account.credits -= amount", "account.credits -= 0"),
        DEBIT.replace("    return None", "    log()"),
        DEBIT.replace("account.save", "different.save"),
        DEBIT.replace("pk=account_id", "pk=lock_account()"),
        "cost = 0\n" + DEBIT.replace("amount", "cost"),
        "cost = lock_debit()\n" + DEBIT.replace("amount", "cost"),
        DEBIT.replace(
            "account.credits -= amount", "account.credits = other.credits - amount"
        ),
    ],
)
def test_protected_or_unrelated_update(tmp_path, body):
    assert not _scan(tmp_path, body)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"urls": "urlpatterns = []"},
        {"urls": URLS.replace("from django.urls", "from routing")},
        {"urls": URLS + "urlpatterns = []\n"},
        {"model": MODEL.replace("models.Model", "object")},
        {"model": MODEL + "    def save(self, *args, **kwargs): pass\n"},
        {"model": MODEL + "    objects = LockingManager()\n"},
        {"model": MODEL + "Account.save = custom_save\n"},
        {"model": MODEL + "    class Meta:\n        abstract = True\n"},
        {"model": MODEL + "    class Meta:\n        verbose_name = configure()\n"},
        {
            "model": MODEL
            + "    @custom_method\n    def __str__(self): return self.pk\n"
        },
        {"decorator": "@distributed_lock\n"},
    ],
)
def test_requires_framework_model_route_and_unmodified_operations(tmp_path, kwargs):
    assert not _scan(tmp_path, **kwargs)


def test_finding_in_cli_json(tmp_path, monkeypatch, capsys):
    import json
    import sys

    from skylos.cli import main

    _scan(tmp_path)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "--danger",
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
        ],
    )
    main()
    report = json.loads(capsys.readouterr().out)
    assert not report.get("analysis_errors")
    (finding,) = [f for f in report["danger"] if f["rule_id"] == "SKY-D385"]
    assert finding["line"] == 10
