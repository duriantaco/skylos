"""Evidence required to link a Django setting read to an RSA size operand."""

import ast
from textwrap import dedent

import pytest

from skylos.rules.danger.danger_fs.path_provenance import _Unit
from skylos.rules.danger.django_rsa_consumers import rsa_setting_lookups
from skylos.rules.danger.oslo_config_options import ConfigProject

_CONSUMER = """\
from django.db import models
from worker import launch

class Record(models.Model):
    width = models.PositiveIntegerField(null=True)

class Issuer:
    def generate(self, row):
        size = row.width or self.standard
        launch('openssl genrsa -out {0} {1}'.format('cert.pem', size))

    def cycle(self):
        self.standard = setting('signing_size')
        selection = Record.objects.filter(active=True)
        for row in selection:
            self.generate(row)
"""

_WORKER = """\
import subprocess

def launch(cmd, prefix=None, captured=True, **opts):
    if prefix is not None:
        cmd = prefix + cmd
    opts['shell'] = True
    if captured:
        opts.update(stdout=subprocess.PIPE)
    proc = subprocess.Popen(cmd, **opts)
    return proc.wait()
"""


def _matches(root, consumer, worker=_WORKER):
    project = ConfigProject(root, True)
    for name, source in (("consumer", consumer), ("worker", worker)):
        path = root / f"{name}.py"
        source = dedent(source)
        path.write_text(source)
        unit = _Unit(path, path.name, ast.parse(source), False)
        unit.module_names = project._module_names(unit)
        project.units.append(unit)
        project.by_path[path] = unit
        for module in unit.module_names:
            project.modules.setdefault(module, []).append(unit)
    project._index()
    return [
        (
            next(arg.value for arg in lookup.args if isinstance(arg, ast.Constant)),
            ast.unparse(generator.func),
        )
        for _, lookup, generator, _ in rsa_setting_lookups(project, project.units[0])
    ]


@pytest.mark.parametrize(
    "command",
    [
        "'openssl genrsa -out {0} {1}'.format('cert.pem', size)",
        "f'openssl genrsa {size}'",
        "'/usr/bin/openssl genrsa {}'.format(size)",
    ],
)
def test_follows_nullable_override_and_real_runner(tmp_path, command):
    original = "'openssl genrsa -out {0} {1}'.format('cert.pem', size)"
    assert _matches(tmp_path, _CONSUMER.replace(original, command)) == [
        ("signing_size", "launch")
    ]


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("null=True", "null=False"),
        ("active=True", "width__isnull=False"),
        ("size = row.width", "row.width = 4096\n        size = row.width"),
        ("size = row.width", "setattr(row, 'width', 4096)\n        size = row.width"),
        ("        launch(", "        if size >= 2048:\n            launch("),
        ("self.generate(row)", "row.width = 4096\n            self.generate(row)"),
        ("launch(", "self.unrelated("),
        ("'cert.pem', size", "size, 4096"),
        ("genrsa -out {0} {1}", "genrsa -out {} {1}"),
        ("genrsa -out {0} {1}", "genrsa -out {0} 4096 && echo {1}"),
        ("row.width or self.standard", "max(self.standard, 2048)"),
        ("models.Model", "object"),
        ("width = models", "objects = unrelated_manager()\n    width = models"),
        ("selection = Record", "self.harden()\n        selection = Record"),
        ("selection = Record", "self.standard = 4096\n        selection = Record"),
    ],
)
def test_abstains_when_fallback_or_execution_is_unproven(
    tmp_path, original, replacement
):
    assert original in _CONSUMER
    assert _matches(tmp_path, _CONSUMER.replace(original, replacement)) == []


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("opts['shell'] = True", "opts['shell'] = False"),
        ("Popen(cmd,", "Popen(['echo', cmd],"),
        ("if prefix is not None:", "if captured:"),
        ("proc = subprocess", "return 0\n    proc = subprocess"),
        (
            "proc = subprocess",
            "opts['executable'] = '/bin/true'\n    proc = subprocess",
        ),
    ],
)
def test_wrapper_must_execute_its_original_command(tmp_path, original, replacement):
    assert _matches(tmp_path, _CONSUMER, _WORKER.replace(original, replacement)) == []


@pytest.mark.parametrize(
    ("expression", "matches"),
    [
        ("['openssl', 'genrsa', str(setting('bits'))]", True),
        ("f'openssl genrsa {setting(\"bits\")}', shell=True", True),
        ("f'openssl genrsa {setting(\"bits\")}', shell=False", False),
        ("['openssl', 'genrsa', '-out', setting('bits'), '4096']", False),
        ("['openssl', 'genrsa', setting('bits')], executable='echo'", False),
    ],
)
def test_native_subprocess_uses_the_size_operand(tmp_path, expression, matches):
    source = f"import subprocess\ndef generate():\n    subprocess.run({expression})\n"
    assert _matches(tmp_path, source) == (
        [("bits", "subprocess.run")] if matches else []
    )


_NULL_GUARD = """\
import subprocess
from django.db import models

class Tenant(models.Model):
    custom_bits = models.IntegerField(null=True)

def issue(config, tenant: Tenant):
    bits = tenant.custom_bits
    if bits is None:
        bits = option(config, 'key_bits')
    return subprocess.run(['openssl', 'genrsa', str(bits)])
"""


def test_nullable_model_parameter_and_explicit_none_guard(tmp_path):
    assert _matches(tmp_path, _NULL_GUARD) == [("key_bits", "subprocess.run")]


@pytest.mark.parametrize(
    ("choice", "matches"),
    [
        ("field if field is not None else default", True),
        ("default if field is None else field", True),
        ("field if tenant.capacity is not None else default", False),
        ("tenant.capacity if field is not None else default", False),
        ("field if config.custom_bits is not None else default", False),
        ("default if field is not None else field", False),
        ("field if field is not None else max(default, 2048)", False),
        ("field if field is not None else 2048", False),
        ("field if field is not None else default\n    bits = max(bits, 2048)", False),
    ],
)
def test_nullable_ternary_uses_same_field_and_unmodified_fallback(
    tmp_path, choice, matches
):
    choice = choice.replace("field", "tenant.custom_bits").replace(
        "default", "option('key_bits', config)"
    )
    source = _NULL_GUARD.replace(
        "bits = tenant.custom_bits\n    if bits is None:\n        bits = option(config, 'key_bits')",
        f"bits = {choice}",
    )
    assert _matches(tmp_path, source) == (
        [("key_bits", "subprocess.run")] if matches else []
    )


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("tenant: Tenant", "tenant"),
        ("def issue(config", "@decorated\ndef issue(config"),
        ("tenant: Tenant", "tenant: unrelated.Tenant"),
        ("models.Model", "object"),
        ("null=True", "null=False"),
        ("models.IntegerField", "custom.IntegerField"),
        ("tenant.custom_bits", "tenant.unknown_field"),
        ("is None", "is not None"),
        ("bits is None", "config is None"),
        ("bits = option", "unused = option"),
        ("bits = option", "return 4096\n        bits = option"),
        ("bits = option(config, 'key_bits')", "bits = 4096"),
        (
            "bits = tenant.custom_bits",
            "tenant.custom_bits = 4096\n    bits = tenant.custom_bits",
        ),
        ("    return subprocess", "    bits = max(bits, 2048)\n    return subprocess"),
        (
            "    return subprocess",
            "    if bits < 2048:\n        return\n    return subprocess",
        ),
        ("str(bits)", "str(max(bits, 2048))"),
        ("'genrsa', str(bits)", "'genrsa', '-out', str(bits), '4096'"),
        (
            "    custom_bits",
            "    def __getattribute__(self, name):\n        return 4096\n    custom_bits",
        ),
    ],
)
def test_none_guard_requires_nullable_size_and_exact_operand(
    tmp_path, original, replacement
):
    assert _matches(tmp_path, _NULL_GUARD.replace(original, replacement)) == []


_METHOD_MODEL = """\
from django.db import models
class Account(models.Model):
    private_bits = models.IntegerField(null=True)
    def selected(self, policy):
        requested = self.private_bits
        if requested is not None:
            return requested
        return setting('global_key_size', policy)
"""
_METHOD_CALL = """\
import subprocess
from worker import Account
def generate(account: Account, policy):
    bits = account.selected(policy)
    return subprocess.run(['openssl', 'genrsa', str(bits)])
"""


@pytest.mark.parametrize("input_arg", ["policy", "{}", "policy={}"])
def test_cross_module_method_reaches_size_operand(tmp_path, input_arg):
    source = _METHOD_CALL.replace(
        "account.selected(policy)", f"account.selected({input_arg})"
    )
    assert _matches(tmp_path, source, _METHOD_MODEL) == [
        ("global_key_size", "subprocess.run")
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        ("return requested", "return 4096"),
        ("if requested is not None", "if requested is None"),
        ("if requested is not None", "if self.other_width is not None"),
        (
            "        return setting",
            "        return max(4096, setting('global_key_size', policy))\n        return setting",
        ),
        ("    def selected", "    @staticmethod\n    def selected"),
        (
            "    def selected",
            "    def __getattr__(self, name): return other\n    def selected",
        ),
        ("IntegerField(null=True)", "IntegerField(null=False)"),
    ],
)
def test_method_summary_requires_unmodified_nullable_selection(tmp_path, mutation):
    assert not _matches(tmp_path, _METHOD_CALL, _METHOD_MODEL.replace(*mutation))


@pytest.mark.parametrize(
    "suffix",
    [
        "\nfrom worker import Account\nAccount.selected = lambda self, policy: 4096\n",
        "\nfrom worker import Account as Owner\nsetattr(Owner, 'selected', lambda self, policy: 4096)\n",
        "\nfrom worker import Account\ndel Account.selected\n",
        "\nfrom worker import Account\ndelattr(Account, 'selected')\n",
        "\nclass Hardened(Account):\n    def selected(self, policy): return 4096\n",
    ],
)
def test_ambiguous_or_replaced_method_is_quiet(tmp_path, suffix):
    assert not _matches(tmp_path, _METHOD_CALL + suffix, _METHOD_MODEL)


@pytest.mark.parametrize(
    "replace",
    [
        ("bits = account", "account.private_bits = 4096\n    bits = account"),
        (
            "bits = account",
            "if not account.private_bits:\n        return\n    bits = account",
        ),
        ("bits = account", "patch(account)\n    bits = account"),
        ("str(bits)", "str(max(2048, bits))"),
        (
            "account.selected(policy)",
            "account.selected(setattr(account, 'private_bits', 4096))",
        ),
        ("account.selected(policy)", "account.selected()"),
    ],
)
def test_bound_method_requires_intact_receiver_and_operand(tmp_path, replace):
    assert not _matches(tmp_path, _METHOD_CALL.replace(*replace), _METHOD_MODEL)


@pytest.mark.parametrize(
    "choose",
    [
        "if original is not None:\n        size = field\n    else:\n        size = option('key_bits', config)",
        "size = field if original is not None else option('key_bits', config)",
        "size = option('key_bits', config) if original is None else field",
    ],
)
def test_aliases_feed_the_same_nullable_field_through_both_branches(tmp_path, choose):
    before = "bits = tenant.custom_bits\n    if bits is None:\n        bits = option(config, 'key_bits')"
    after = (
        "original = tenant.custom_bits\n    field = original\n    "
        + choose
        + "\n    bits = size"
    )
    assert _matches(tmp_path, _NULL_GUARD.replace(before, after)) == [
        ("key_bits", "subprocess.run")
    ]
