"""Literal logging factories are used only through real configuration consumers."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _scan(root, source, extra=None):
    files = {
        "pkg/__init__.py": "",
        "pkg/formatters.py": "class Active: pass\nclass Retired: pass\n",
        "app.py": source,
        **(extra or {}),
    }
    for path, body in files.items():
        write_fixture(root, path, textwrap.dedent(body).lstrip(), overwrite=True)
    return json.loads(analyze(str(root), conf=60, grep_verify=False, grep_cache=False))


def _unused(result):
    return {item["full_name"] for item in result.get("unused_classes", [])}


_CONFIG = "{'version': 1, 'formatters': {'active': {'()': 'pkg.formatters.Active'}}}"


@pytest.mark.parametrize(
    "provider",
    [
        "import logging.config\nlogging.config.dictConfig",
        "from logging.config import dictConfig as apply\napply",
    ],
)
def test_real_dictconfig_consumes_literal_factory(tmp_path, provider):
    header, call = provider.rsplit("\n", 1)
    result = _scan(tmp_path, header + "\n" + call + "(" + _CONFIG + ")\n")
    assert "pkg.formatters.Active" not in _unused(result)
    assert "pkg.formatters.Retired" in _unused(result)


def test_configuration_default_passes_through_instance_to_consumer(tmp_path):
    result = _scan(
        tmp_path,
        f"""
        import logging.config
        CONFIG = {_CONFIG}
        class Server:
            def __init__(self, log_config=CONFIG):
                self.log_config = log_config
                self.configure_logging()
            def configure_logging(self):
                logging.config.dictConfig(self.log_config)
        Server()
    """,
    )
    assert "pkg.formatters.Active" not in _unused(result)
    assert "pkg.formatters.Retired" in _unused(result)


@pytest.mark.parametrize(
    "body",
    [
        f"CONFIG = {_CONFIG}\n",
        f"import logging.config\nCONFIG = {_CONFIG}\nCONFIG = {{}}\nlogging.config.dictConfig(CONFIG)\n",
        f"from local_logging import dictConfig\ndictConfig({_CONFIG})\n",
        f"import logging.config\nlogging.config.dictConfig = replacement\nlogging.config.dictConfig({_CONFIG})\n",
        f"import logging.config\ndef unused(): logging.config.dictConfig({_CONFIG})\n",
        f"import logging.config\nif False: logging.config.dictConfig({_CONFIG})\n",
        f"import logging.config\ndef unused(logging): logging.config.dictConfig({_CONFIG})\nunused(replacement)\n",
        "import logging.config\nlogging.config.dictConfig({'version': 1, 'description': 'pkg.formatters.Active'})\n",
    ],
)
def test_strings_and_unproved_consumers_do_not_rescue_factory(tmp_path, body):
    result = _scan(
        tmp_path, body, {"local_logging.py": "def dictConfig(config): return config\n"}
    )
    assert "pkg.formatters.Active" in _unused(result)
    assert "pkg.formatters.Retired" in _unused(result)


def test_replaced_constructor_argument_does_not_consume_its_default(tmp_path):
    result = _scan(
        tmp_path,
        f"""
        import logging.config
        CONFIG = {_CONFIG}
        class Server:
            def __init__(self, log_config=CONFIG):
                self.log_config = log_config
                self.configure_logging()
            def configure_logging(self):
                logging.config.dictConfig(self.log_config)
        Server(log_config={{}})
    """,
    )
    assert "pkg.formatters.Active" in _unused(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "CONFIG.clear()",
        "alias = CONFIG\nalias.clear()",
        "CONFIG['formatters']['active']['()'] = 'pkg.formatters.Retired'",
        "CONFIG['formatters'] = {}",
    ],
)
def test_mutated_configuration_does_not_credit_stale_factory(tmp_path, mutation):
    result = _scan(
        tmp_path,
        f"import logging.config\nCONFIG = {_CONFIG}\n{mutation}\nlogging.config.dictConfig(CONFIG)\n",
    )
    assert "pkg.formatters.Active" in _unused(result)


def test_class_configuration_and_consistent_module_imports(tmp_path):
    result = _scan(
        tmp_path,
        "import logging\nimport logging.config\nlogging.config.dictConfig({'version': 1, 'formatters': {'active': {'class': 'pkg.formatters.Active'}}})\n",
    )
    assert "pkg.formatters.Active" not in _unused(result)
    assert "pkg.formatters.Retired" in _unused(result)


def test_project_logging_module_does_not_supply_stdlib_consumer(tmp_path):
    result = _scan(
        tmp_path,
        f"import logging.config\nlogging.config.dictConfig({_CONFIG})\n",
        {
            "logging/__init__.py": "",
            "logging/config.py": "def dictConfig(config): return config\n",
        },
    )
    assert "pkg.formatters.Active" in _unused(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "self.log_config.clear()",
        "self.log_config['formatters']['active']['()'] = 'pkg.formatters.Retired'",
    ],
)
def test_destructive_instance_configuration_change_does_not_credit_default(
    tmp_path, mutation
):
    result = _scan(
        tmp_path,
        f"""
        import logging.config
        CONFIG = {_CONFIG}
        class Server:
            def __init__(self, log_config=CONFIG):
                self.log_config = log_config
                self.configure_logging()
            def configure_logging(self):
                {mutation}
                logging.config.dictConfig(self.log_config)
        Server()
    """,
    )
    assert "pkg.formatters.Active" in _unused(result)


def test_path_string_branch_does_not_mutate_dictionary_default(tmp_path):
    result = _scan(
        tmp_path,
        f"""
        import logging.config
        CONFIG = {_CONFIG}
        class Server:
            def __init__(self, log_config=CONFIG):
                self.log_config = log_config
                self.configure_logging()
            def configure_logging(self):
                if isinstance(self.log_config, str) and self.log_config.endswith('.json'):
                    return
                logging.config.dictConfig(self.log_config)
        Server()
    """,
    )
    assert "pkg.formatters.Active" not in _unused(result)
    assert "pkg.formatters.Retired" in _unused(result)


@pytest.mark.parametrize(
    "setup",
    [
        "selected = CONFIG['formatters']['active']\nselected['()'] = 'pkg.formatters.Retired'",
        "wrapped = {'selected': CONFIG['formatters']['active']}\nwrapped['selected']['()'] = 'pkg.formatters.Retired'",
        "def mutate(config):\n    config.clear()\nmutate(CONFIG)",
        "from helpers import mutate\nmutate(CONFIG)",
        "unknown(CONFIG)",
        "import logging.config as lc\nalias = lc\nalias.dictConfig = lambda config: None",
        "import logging.config as lc\nalias = lc\nsetattr(alias, 'dictConfig', replacement)",
    ],
)
def test_projected_argument_and_provider_aliases_do_not_credit_stale_factory(
    tmp_path, setup
):
    result = _scan(
        tmp_path,
        f"import logging.config\nCONFIG = {_CONFIG}\n{setup}\nlogging.config.dictConfig(CONFIG)\n",
        {"helpers.py": "def mutate(config):\n    config.clear()\n"},
    )
    assert "pkg.formatters.Active" in _unused(result)


@pytest.mark.parametrize(
    "write",
    ["server.config = {}", "alias = server\nalias.config = {}", "del server.config"],
)
def test_external_instance_write_does_not_credit_constructor_default(tmp_path, write):
    result = _scan(
        tmp_path,
        textwrap.dedent(f"""
        import logging.config
        CONFIG = {_CONFIG}
        class Server:
            def __init__(self, config=CONFIG):
                self.config = config
            def configure(self):
                logging.config.dictConfig(self.config)
        server = Server()
    """)
        + "\n"
        + write
        + "\nserver.configure()\n",
    )
    assert "app.Server" in result["definitions"]
    assert "pkg.formatters.Active" in _unused(result)


@pytest.mark.parametrize("kind", ["os.PathLike", "PathLikeAlias"])
def test_pathlike_branch_cannot_consume_a_literal_dictionary(tmp_path, kind):
    result = _scan(
        tmp_path,
        f"""
        import logging.config
        import os
        from os import PathLike as PathLikeAlias
        CONFIG = {_CONFIG}
        class Server:
            def __init__(self, config=CONFIG):
                self.config = config
                self.configure()
            def configure(self):
                if isinstance(self.config, {kind}):
                    self.config = os.fspath(self.config)
                if isinstance(self.config, dict):
                    self.config['formatters']['active']['use_colors'] = True
                    logging.config.dictConfig(self.config)
                elif isinstance(self.config, str) and unknown(self.config):
                    return
        Server()
        """,
    )
    assert "pkg.formatters.Active" not in _unused(result)
    assert "pkg.formatters.Retired" in _unused(result)


@pytest.mark.parametrize(
    "setup",
    [
        "os.PathLike = replacement",
        "alias = os\nalias.PathLike = replacement",
        "",
    ],
)
def test_pathlike_lookalikes_do_not_exclude_possible_mutation(tmp_path, setup):
    extra = {"os.py": "class PathLike: pass\n"} if not setup else None
    result = _scan(
        tmp_path,
        f"import logging.config\nimport os\nCONFIG = {_CONFIG}\n{setup}\n"
        "if isinstance(CONFIG, os.PathLike):\n    unknown(CONFIG)\n"
        "logging.config.dictConfig(CONFIG)\n",
        extra,
    )
    assert "pkg.formatters.Active" in _unused(result)


def test_nested_string_type_guard_does_not_prove_the_outer_dictionary_type(tmp_path):
    result = _scan(
        tmp_path,
        f"""
        import logging.config
        CONFIG = {_CONFIG[:-1]}, 'description': 'active'}}
        if isinstance(CONFIG['description'], str):
            CONFIG.clear()
        logging.config.dictConfig(CONFIG)
        """,
    )
    assert "pkg.formatters.Active" in _unused(result)


@pytest.mark.parametrize(
    "setup",
    [
        "os.PathLike.register(dict)",
        "alias = os.PathLike\nalias.register(dict)",
        "register = os.PathLike.register\nregister(dict)",
        "os.PathLike.__subclasshook__ = replacement",
        "setattr(os.PathLike, '__subclasshook__', replacement)",
        "unknown(os.PathLike)",
    ],
)
def test_mutable_pathlike_type_does_not_exclude_possible_mutation(tmp_path, setup):
    result = _scan(
        tmp_path,
        f"import logging.config\nimport os\nCONFIG = {_CONFIG}\n{setup}\n"
        "if isinstance(CONFIG, os.PathLike):\n    CONFIG.clear()\n"
        "logging.config.dictConfig(CONFIG)\n",
    )
    assert "pkg.formatters.Active" in _unused(result)
