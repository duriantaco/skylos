"""Static-only regressions for clients consumed by external libraries."""

import json
import textwrap

import pytest

from skylos.analyzer import Skylos
from skylos.core.safe_cache_io import write_text_no_symlink


CLIENT = """
def decode_playlist(uri):
    return uri, ""

class Boto3Client:
    @staticmethod
    def download(uri, *_):
        return decode_playlist(uri)

    def unused_operation(self):
        return None
"""


def _scan(tmp_path, source, grep_verify):
    assert write_text_no_symlink(
        tmp_path / "playlist.py", textwrap.dedent(source).lstrip()
    )
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
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    return analyzer, unused


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "import_line,call",
    [
        (
            "from m3u8 import load as m3u8_load",
            "m3u8_load(uri, http_client=Boto3Client())",
        ),
        ("import m3u8", "m3u8.load(uri, http_client=Boto3Client())"),
        ("import m3u8 as parser", "parser.load(uri, None, {}, None, Boto3Client())"),
    ],
)
def test_live_external_client_keeps_only_callback_alive(
    tmp_path, grep_verify, import_line, call
):
    source = CLIENT + (
        f"\ndef load_m3u8_from_s3(uri):\n"
        f"    {import_line}\n"
        f"    return {call}\n"
        '\nload_m3u8_from_s3("s3://example/playlist.m3u8")\n'
    )
    analyzer, unused = _scan(tmp_path, source, grep_verify)

    assert "playlist.Boto3Client.download" not in unused
    assert "playlist.load_m3u8_from_s3" not in unused
    assert "playlist.decode_playlist" not in unused
    assert "playlist.Boto3Client.unused_operation" in unused
    callback = analyzer.defs["playlist.Boto3Client.download"]
    assert "playlist.load_m3u8_from_s3" in callback.called_by
    assert (
        "playlist.Boto3Client.download"
        in analyzer.defs["playlist.load_m3u8_from_s3"].calls
    )
    assert "reachable_from_root" in callback.heuristic_refs
    assert (
        "reachable_from_root"
        in analyzer.defs["playlist.decode_playlist"].heuristic_refs
    )


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("call_count", [1, 2])
def test_uncalled_wrapper_does_not_keep_external_callback_alive(
    tmp_path, grep_verify, call_count
):
    source = CLIENT + (
        "\ndef load_m3u8_from_s3(uri):\n"
        "    from m3u8 import load\n"
        + "    load(uri, http_client=Boto3Client())\n"
        * call_count
    )
    analyzer, unused = _scan(tmp_path, source, grep_verify)

    assert "playlist.load_m3u8_from_s3" in unused
    # An unused class can cover its methods in the rendered findings. Check
    # actual liveness too, so that grouping cannot hide a spurious rescue.
    assert analyzer.defs["playlist.Boto3Client.download"].references == 0
    assert analyzer.defs["playlist.Boto3Client.unused_operation"].references == 0
    assert (
        "reachable_from_root"
        not in analyzer.defs["playlist.Boto3Client.download"].heuristic_refs
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_module_level_external_callback_is_an_execution_root(tmp_path, grep_verify):
    source = CLIENT + (
        "\nfrom m3u8 import load\n"
        'load("s3://example/playlist.m3u8", http_client=Boto3Client())\n'
    )
    analyzer, unused = _scan(tmp_path, source, grep_verify)

    assert "playlist.Boto3Client.download" not in unused
    assert "playlist.decode_playlist" not in unused
    assert "playlist.Boto3Client.unused_operation" in unused
    assert (
        "top_level_execution"
        in analyzer.defs["playlist.Boto3Client.download"].heuristic_refs
    )
    assert (
        "reachable_from_root"
        in analyzer.defs["playlist.decode_playlist"].heuristic_refs
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_local_m3u8_module_does_not_get_external_protocol(tmp_path, grep_verify):
    (tmp_path / "m3u8.py").write_text(
        "def load(uri, http_client):\n    return uri\n", encoding="utf-8"
    )
    _, unused = _scan(
        tmp_path,
        CLIENT + '\nfrom m3u8 import load\nload("uri", http_client=Boto3Client())\n',
        grep_verify,
    )

    assert "playlist.Boto3Client.download" in unused


@pytest.mark.parametrize("grep_verify", [False, True])
def test_parameter_shadowing_does_not_get_external_protocol(tmp_path, grep_verify):
    source = (
        CLIENT
        + """
from m3u8 import load

def forward(load, uri):
    return load(uri, http_client=Boto3Client())

forward(lambda *args, **kwargs: None, "uri")
"""
    )
    _, unused = _scan(tmp_path, source, grep_verify)

    assert "playlist.Boto3Client.download" in unused


@pytest.mark.parametrize("grep_verify", [False, True])
def test_local_library_body_already_keeps_callback_alive(tmp_path, grep_verify):
    (tmp_path / "external_m3u8.py").write_text(
        "def load(uri, http_client):\n    return http_client.download(uri)\n",
        encoding="utf-8",
    )
    source = (
        CLIENT
        + """
def load_m3u8_from_s3(uri):
    from external_m3u8 import load
    return load(uri, http_client=Boto3Client())

load_m3u8_from_s3("s3://example/playlist.m3u8")
"""
    )
    _, unused = _scan(tmp_path, source, grep_verify)

    assert "playlist.Boto3Client.download" not in unused
    assert "playlist.load_m3u8_from_s3" not in unused


@pytest.mark.parametrize("live", [False, True])
def test_external_callback_reaches_literal_plugin_registry(tmp_path, live):
    (tmp_path / "plugins.py").write_text(
        "def decode_playlist(uri):\n    return uri\n", encoding="utf-8"
    )
    source = """
import importlib
from m3u8 import load

HANDLER_PATHS = {"playlist": "plugins:decode_playlist"}

class Client:
    @staticmethod
    def download(uri, *_):
        handler_path = HANDLER_PATHS["playlist"]
        module_name, func_name = handler_path.split(":")
        handler = getattr(importlib.import_module(module_name), func_name)
        return handler(uri), ""

def load_wrapper(uri):
    return load(uri, http_client=Client())
"""
    if live:
        source += '\nload_wrapper("s3://example/playlist.m3u8")\n'
    analyzer, unused = _scan(tmp_path, source, grep_verify=False)

    assert ("plugins.decode_playlist" not in unused) is live
    assert (analyzer.defs["plugins.decode_playlist"].references > 0) is live


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("mutual", [False, True])
@pytest.mark.parametrize("live", [False, True])
def test_callback_cycle_needs_a_live_caller(tmp_path, grep_verify, mutual, live):
    other = "SecondClient" if mutual else "FirstClient"
    source = (
        "from m3u8 import load\n\n"
        "class FirstClient:\n"
        "    @staticmethod\n"
        "    def download(uri, *_):\n"
        f"        return load(uri, http_client={other}())\n"
    )
    if mutual:
        source += (
            "\nclass SecondClient:\n"
            "    @staticmethod\n"
            "    def download(uri, *_):\n"
            "        return load(uri, http_client=FirstClient())\n"
        )
    if live:
        source += '\nload("s3://example/playlist.m3u8", http_client=FirstClient())\n'
    analyzer, _ = _scan(tmp_path, source, grep_verify)

    # These fixtures are only scanned, never executed. Even a recursive
    # callback must not become a liveness root just because it references itself.
    for client in {"FirstClient", other}:
        assert (analyzer.defs[f"playlist.{client}.download"].references > 0) is live


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "ordinary_use",
    [
        'Boto3Client.download("uri")',
        "from eventlib import register\nregister(Boto3Client.download)",
    ],
)
def test_unused_external_wrapper_preserves_ordinary_method_use(
    tmp_path, grep_verify, ordinary_use
):
    source = (
        CLIENT
        + ordinary_use
        + """

def unused_wrapper(uri):
    from m3u8 import load
    return load(uri, http_client=Boto3Client())
"""
    )
    analyzer, unused = _scan(tmp_path, source, grep_verify)

    assert "playlist.unused_wrapper" in unused
    assert "playlist.Boto3Client.download" not in unused
    assert analyzer.defs["playlist.Boto3Client.download"].references > 0


@pytest.mark.parametrize("grep_verify", [False, True])
def test_dead_ordinary_caller_does_not_root_an_external_cycle(tmp_path, grep_verify):
    source = """
from m3u8 import load

class FirstClient:
    @staticmethod
    def download(uri, *_):
        return load(uri, http_client=SecondClient())

class SecondClient:
    @staticmethod
    def download(uri, *_):
        return load(uri, http_client=FirstClient())

def unused_wrapper(uri):
    return FirstClient.download(uri)
"""
    analyzer, unused = _scan(tmp_path, source, grep_verify)

    assert "playlist.unused_wrapper" in unused
    # Grep can already match both methods by name from the dead wrapper's
    # textual use. Neither method may gain a new external callback edge.
    second = analyzer.defs["playlist.SecondClient.download"]
    assert "playlist.FirstClient.download" not in second.called_by
    assert "dead_code_liveness:external_protocol" not in second.heuristic_refs
    if not grep_verify:
        assert second.references == 0
        assert analyzer.defs["playlist.FirstClient.download"].references == 0


@pytest.mark.parametrize("grep_verify", [False, True])
def test_external_callback_preserves_constructor_and_local_protocol_dependencies(
    tmp_path, grep_verify
):
    source = """
from m3u8 import load

class Decoder:
    def decode(self):
        return "playlist", ""

def invoke(decoder):
    return decoder.decode()

class Client:
    @staticmethod
    def download(uri, *_):
        return invoke(Decoder())

def load_wrapper(uri):
    return load(uri, http_client=Client())

load_wrapper("s3://example/playlist.m3u8")
"""
    analyzer, unused = _scan(tmp_path, source, grep_verify)

    for name in ("playlist.Decoder", "playlist.Decoder.decode", "playlist.invoke"):
        assert analyzer.defs[name].references > 0
        assert name not in unused


@pytest.mark.parametrize("grep_verify", [False, True])
def test_unused_class_constructor_is_not_an_external_callback_root(
    tmp_path, grep_verify
):
    source = (
        CLIENT
        + """
from m3u8 import load

class UnusedService:
    def __init__(self):
        load("s3://example/playlist.m3u8", http_client=Boto3Client())

def unused_wrapper():
    return UnusedService()
"""
    )
    analyzer, unused = _scan(tmp_path, source, grep_verify)

    assert "playlist.unused_wrapper" in unused
    assert analyzer.defs["playlist.Boto3Client.download"].references == 0


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize("nested_callback", [False, True])
def test_callback_constructor_keeps_its_dependencies(
    tmp_path, grep_verify, live, nested_callback
):
    prepare = (
        'load("s3://example/second.m3u8", http_client=SecondClient())'
        if nested_callback
        else "prepare()"
    )
    source = """
from m3u8 import load

def prepare():
    return "playlist", ""

class SecondClient:
    @staticmethod
    def download(uri, *_):
        return prepare()

class Decoder:
    def __init__(self):
        self.contents = PREPARE

    def decode(self):
        return self.contents

    def unused_operation(self):
        return None

class Client:
    @staticmethod
    def download(uri, *_):
        return Decoder().decode()

def load_wrapper(uri):
    return load(uri, http_client=Client())
""".replace("PREPARE", prepare)
    if live:
        source += '\nload_wrapper("s3://example/playlist.m3u8")\n'
    analyzer, unused = _scan(tmp_path, source, grep_verify)

    assert analyzer.defs["playlist.Decoder.unused_operation"].references == 0
    if live:
        for name in (
            "playlist.Decoder",
            "playlist.Decoder.__init__",
            "playlist.prepare",
        ):
            assert analyzer.defs[name].references > 0
            assert name not in unused
        if nested_callback:
            assert analyzer.defs["playlist.SecondClient.download"].references > 0
    else:
        assert "playlist.load_wrapper" in unused
        assert analyzer.defs["playlist.Client.download"].references == 0
        assert analyzer.defs["playlist.SecondClient.download"].references == 0
