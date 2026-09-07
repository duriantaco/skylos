"""Imported client fixtures are static data; their modules never execute."""

import json
import textwrap

import pytest

from skylos.analyzer import Skylos
from skylos.core.safe_cache_io import write_text_no_symlink


CLIENT = """
class Client:
    @staticmethod
    def download(uri, *_):
        return uri, ""

    def unrelated(self):
        return None
"""


def _scan(tmp_path, files, grep_verify):
    for relative_path, source in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, textwrap.dedent(source).lstrip())
    analyzer = Skylos()
    result = json.loads(
        analyzer.analyze(
            str(tmp_path),
            thr=0,
            grep_verify=grep_verify,
            grep_cache=False,
            trace_file=False,
            enable_dependency_hallucinations=False,
        )
    )
    return analyzer, {item["full_name"] for item in result.get("unused_functions", [])}


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "import_line,client,provider,caller_path",
    [
        ("from clients import Client", "Client", "clients", "playlist.py"),
        ("from clients import Client as Adapter", "Adapter", "clients", "playlist.py"),
        ("import clients", "clients.Client", "clients", "playlist.py"),
        ("import clients as adapters", "adapters.Client", "clients", "playlist.py"),
        ("from pkg.clients import Client", "Client", "pkg.clients", "playlist.py"),
        ("from .clients import Client", "Client", "pkg.clients", "pkg/playlist.py"),
    ],
)
def test_live_imported_client_uses_the_defining_file(
    tmp_path, grep_verify, import_line, client, provider, caller_path
):
    caller = (
        f"{import_line}\nfrom m3u8 import load\n\n"
        "def fetch(uri):\n"
        f"    return load(uri, http_client={client}())\n"
        '\nfetch("s3://example/playlist.m3u8")\n'
    )
    analyzer, unused = _scan(
        tmp_path,
        {
            "pkg/__init__.py": "",
            f"{provider.replace('.', '/')}.py": CLIENT,
            caller_path: caller,
            "other.py": CLIENT,
        },
        grep_verify,
    )

    callback = analyzer.defs[f"{provider}.Client.download"]
    assert callback.references > 0
    assert "dead_code_liveness:external_protocol" in callback.heuristic_refs
    assert callback.name not in unused
    assert analyzer.defs[f"{provider}.Client.unrelated"].references == 0
    assert analyzer.defs["other.Client.download"].references == 0


@pytest.mark.parametrize("grep_verify", [False, True])
def test_uncalled_wrapper_does_not_activate_an_imported_client(tmp_path, grep_verify):
    analyzer, unused = _scan(
        tmp_path,
        {
            "clients.py": CLIENT,
            "playlist.py": """
                from clients import Client
                from m3u8 import load
                def unused_wrapper(uri):
                    return load(uri, http_client=Client())
            """,
        },
        grep_verify,
    )
    assert "playlist.unused_wrapper" in unused
    assert analyzer.defs["clients.Client.download"].references == 0


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "provider",
    [
        CLIENT + "\nClient = object()\n",
        CLIENT + "\nClient.download = replacement\n",
        "from custom import staticmethod\n" + CLIENT,
    ],
)
def test_rebound_provider_does_not_prove_an_imported_callback(
    tmp_path, grep_verify, provider
):
    analyzer, _ = _scan(
        tmp_path,
        {
            "clients.py": provider,
            "playlist.py": """
                from clients import Client
                from m3u8 import load
                load("s3://example/playlist.m3u8", http_client=Client())
            """,
        },
        grep_verify,
    )
    assert analyzer.defs["clients.Client.download"].references == 0


@pytest.mark.parametrize("grep_verify", [False, True])
def test_parameter_shadowing_does_not_activate_an_imported_client(
    tmp_path, grep_verify
):
    analyzer, _ = _scan(
        tmp_path,
        {
            "clients.py": CLIENT,
            "playlist.py": """
                from clients import Client
                from m3u8 import load
                def fetch(Client):
                    return load("s3://example/playlist.m3u8", http_client=Client())
                fetch(replacement)
            """,
        },
        grep_verify,
    )
    assert analyzer.defs["clients.Client.download"].references == 0


@pytest.mark.parametrize("grep_verify", [False, True])
def test_imported_inherited_method_uses_provider_scope(tmp_path, grep_verify):
    provider = CLIENT + "\nclass Derived(Client):\n    pass\n"
    analyzer, unused = _scan(
        tmp_path,
        {
            "clients.py": provider,
            "playlist.py": """
                from clients import Derived
                from m3u8 import load
                staticmethod = replacement
                load("s3://example/playlist.m3u8", http_client=Derived())
            """,
        },
        grep_verify,
    )
    assert analyzer.defs["clients.Client.download"].references > 0
    assert "clients.Client.download" not in unused


@pytest.mark.parametrize("grep_verify", [False, True])
def test_relative_import_with_only_module_level_callback(tmp_path, grep_verify):
    analyzer, unused = _scan(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/clients.py": CLIENT,
            "pkg/playlist.py": """
                from .clients import Client
                from m3u8 import load
                load("s3://example/playlist.m3u8", http_client=Client())
            """,
        },
        grep_verify,
    )
    callback = analyzer.defs["pkg.clients.Client.download"]
    assert callback.references > 0
    assert "dead_code_liveness:external_protocol" in callback.heuristic_refs
    assert callback.name not in unused
