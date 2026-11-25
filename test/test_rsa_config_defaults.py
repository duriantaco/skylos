from textwrap import dedent

import pytest

from skylos.rules.danger.danger import scan_ctx

SCHEMA = """\
from oslo_config import cfg
settings = cfg.CONF
def declare(*args, **options):
    target = options.pop('conf', settings)
    group = options.pop('group', None)
    return target.register_opt(cfg.IntOpt(*args, **options), group=group)
def setup():
    declare('width', group='documents', default=1024)
    declare('width', group='unrelated', default=1024)
"""
CONSUMER = """\
from subprocess import check_call
from app import settings_api
class Builder:
    def __init__(self, group, **extra):
        self.params = {'bits': int(group.width)}
        self.params.update(extra)
    def invoke(self, cmd):
        rendered = cmd % self.params
        check_call(rendered.split())
    def generate(self):
        self.invoke("openssl genrsa %(bits)d")
class Documents(Builder):
    def __init__(self):
        super().__init__(settings_api.conf.documents)
"""
FACADE = "from app import options\noptions.setup()\nconf = options.settings\n"


def run(root, schema=SCHEMA, source=CONSUMER, facade=FACADE):
    app = root / "app"
    app.mkdir(exist_ok=True)
    inputs = {"options.py": schema, "builder.py": source, "settings_api.py": facade}
    for name, body in inputs.items():
        (app / name).write_text(dedent(body))
    return [
        (f["line"], f["message"])
        for f in scan_ctx(root, [app / name for name in inputs])
        if f["rule_id"] == "SKY-D383"
    ]


def test_weak_group_is_attributed_to_its_declaration(tmp_path):
    [(line, msg)] = run(tmp_path)
    assert line == 8 and "documents.width" in msg and "1024" in msg
    assert not run(
        tmp_path,
        SCHEMA.replace("'documents', default=1024", "'documents', default=2048"),
    )


def test_direct_configuration_registration_and_argv(tmp_path):
    schema = """\
from oslo_config import cfg
cfg.CONF.register_opt(cfg.IntOpt('width', default=1024), group='tokens')
"""
    consumer = """\
from app import options
from oslo_config.cfg import CONF
import subprocess
def build():
    subprocess.run(['openssl', 'genrsa', str(CONF.tokens.width)])
"""
    [(line, msg)] = run(tmp_path, schema, consumer, "")
    assert line == 2 and "tokens.width" in msg


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("openssl genrsa %(bits)d", "openssl version %(bits)d"),
        (
            "check_call(rendered.split())",
            "return\n        check_call(rendered.split())",
        ),
        (
            "check_call(rendered.split())",
            "check_call = print\n        check_call(rendered.split())",
        ),
        ("cmd % self.params", '"openssl version"'),
        ("self.params.update(extra)", "self.params['bits'] = 3072"),
        (
            "self.params.update(extra)",
            "extra['bits'] = 3072\n        self.params.update(extra)",
        ),
        ("self.params.update(extra)", "self.params = {'bits': 3072}"),
        ("settings_api.conf.documents)", "settings_api.conf.documents, bits=3072)"),
        ('self.invoke("openssl genrsa', 'return\n        self.invoke("openssl genrsa'),
        ("def invoke(self, cmd):", "@staticmethod\n    def invoke(self, cmd):"),
    ],
)
def test_requires_intact_rsa_command_and_mapping(tmp_path, old, new):
    assert not run(tmp_path, source=CONSUMER.replace(old, new))


@pytest.mark.parametrize(
    "change",
    [
        "settings.set_default('width', 3072, group='documents')",
        "settings.set_override('width', 4096, group='documents')",
        "settings.documents.width = 3072",
        "setattr(settings.documents, 'width', 3072)",
        "declare('width', group='documents', default=3072)",
    ],
)
def test_control_overrides_and_ambiguous_registrations(tmp_path, change):
    assert not run(tmp_path, schema=SCHEMA + "    " + change + "\n")


def test_unused_setup_or_unreachable_registration(tmp_path):
    assert not run(tmp_path, facade=FACADE.replace("options.setup()", "pass"))
    assert not run(
        tmp_path, schema=SCHEMA.replace("def setup():", "def setup():\n    return")
    )


def test_dominating_key_size_guard_and_dead_override(tmp_path):
    schema = """\
from oslo_config import cfg
cfg.CONF.register_opt(cfg.IntOpt('width', default=1024), group='tokens')
if False:
    cfg.CONF.set_override('width', 2048, group='tokens')
"""
    consumer = """\
from app import options
from oslo_config.cfg import CONF
import subprocess
def build():
    subprocess.run(['openssl', 'genrsa', str(CONF.tokens.width)])
"""
    assert run(tmp_path, schema, consumer, "")
    guarded = consumer.replace(
        "    subprocess.run",
        "    if CONF.tokens.width < 2048:\n        return\n    subprocess.run",
    )
    assert not run(tmp_path, schema, guarded, "")


def test_disconnected_or_shadowed_schema(tmp_path):
    consumer = "from oslo_config.cfg import CONF\nimport subprocess\nsubprocess.run(['openssl', 'genrsa', str(CONF.documents.width)])\n"
    assert not run(tmp_path, source=consumer)
    assert not run(
        tmp_path,
        schema=SCHEMA.replace(
            "from oslo_config import cfg", "from unrelated import cfg"
        ),
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "self.params = {'bits':",
            "if group.width < 2048:\n            raise ValueError()\n        self.params = {'bits':",
        ),
        (
            'self.invoke("openssl genrsa',
            'if self.params["bits"] < 2048:\n            return\n        self.invoke("openssl genrsa',
        ),
        (
            "class Documents(Builder):",
            "class Documents(Builder):\n    generate = lambda self: None",
        ),
    ],
)
def test_overridden_dispatch_or_validated_option(tmp_path, old, new):
    assert not run(tmp_path, source=CONSUMER.replace(old, new))


def test_multiple_defaults_are_reported_in_source_order(tmp_path):
    additional = (
        CONSUMER[CONSUMER.index("class Documents(") :]
        .replace("Documents", "Other")
        .replace("conf.documents", "conf.unrelated")
    )
    assert [line for line, _ in run(tmp_path, source=CONSUMER + additional)] == [8, 9]


_BULK_SCHEMA = """\
from oslo_config import cfg
opts = [
    cfg.StrOpt('label', default='test'),
    cfg.IntOpt('width', default=1024),
    cfg.IntOpt('other', default=4096),
]
cfg.CONF.register_opts(opts, group='documents')
cfg.CONF.register_cli_opts((cfg.IntOpt('width', default=4096),), group='audit')
"""
_BULK_CONSUMER = """\
from app import options
from oslo_config import cfg
import subprocess

def create():
    subprocess.run(['openssl', 'genrsa', str(cfg.CONF.documents.width)], check=True)
"""


@pytest.mark.parametrize("method", ["register_opts", "register_cli_opts"])
def test_bulk_default_reports_individual_declaration(tmp_path, method):
    schema = _BULK_SCHEMA.replace("CONF.register_opts", "CONF." + method)
    [(line, msg)] = run(tmp_path, schema, _BULK_CONSUMER, "")
    assert line == 4 and "documents.width" in msg
    assert not run(
        tmp_path, schema.replace("default=1024", "default=2048"), _BULK_CONSUMER, ""
    )


@pytest.mark.parametrize(
    "edit",
    [
        "opts.clear()",
        "opts.append(cfg.IntOpt('width', default=4096))",
        "opts = []",
        "alias = opts",
        "cfg.CONF.register_opt(cfg.IntOpt('width', default=4096), group='documents')",
        "cfg.CONF.register_opts([cfg.IntOpt('width', default=4096)], group='documents')",
        "cfg.CONF.register_opts([cfg.IntOpt('width', default=4096)], group=read_group())",
        "cfg.CONF.register_opts(other_options(), group='documents')",
        "cfg.CONF.register_opts = print",
    ],
)
def test_bulk_declaration_requires_unambiguous_group_and_options(tmp_path, edit):
    schema = _BULK_SCHEMA.replace(
        "cfg.CONF.register_opts(opts", edit + "\ncfg.CONF.register_opts(opts"
    )
    assert not run(tmp_path, schema, _BULK_CONSUMER, "")


def test_inline_tuple_and_other_group(tmp_path):
    schema = _BULK_SCHEMA.replace("opts = [", "cfg.CONF.register_opts((").replace(
        "]\ncfg.CONF.register_opts(opts, group='documents')", "), group='documents')"
    )
    assert run(tmp_path, schema, _BULK_CONSUMER, "")[0][0] == 4
    assert not run(
        tmp_path, schema, _BULK_CONSUMER.replace("documents.width", "audit.width"), ""
    )
    assert not run(
        tmp_path,
        schema.replace("from oslo_config import cfg", "from mock import cfg"),
        _BULK_CONSUMER,
        "",
    )
