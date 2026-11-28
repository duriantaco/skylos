import ast
from textwrap import dedent

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.danger import scan_ctx
from skylos.rules.quality.logic_security import MissingNetworkTimeoutRule


@pytest.mark.parametrize(
    ("code", "lines"),
    [
        (
            "from ssl import SSLContext as Context, PROTOCOL_TLSv1_1 as VERSION\nContext(VERSION)",
            [2],
        ),
        (
            "import ssl as tls\ntls.wrap_socket(sock, ssl_version=tls.PROTOCOL_TLSv1)",
            [2],
        ),
        ("from OpenSSL import SSL as tls\ntls.Context(tls.TLSv1_1_METHOD)", [2]),
        (
            "import ssl as tls\ncontext = tls.create_default_context()\ncontext.minimum_version = tls.TLSVersion.TLSv1_1",
            [3],
        ),
        (
            "import ssl\ncontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\nclient = context\nclient.minimum_version = ssl.TLSVersion.TLSv1",
            [4],
        ),
        ("import ssl\nContext = ssl.SSLContext\nContext(ssl.PROTOCOL_TLSv1_1)", [3]),
        (
            "import ssl\ncontext = ssl.create_default_context()\ncontext.minimum_version = ssl.TLSVersion.TLSv1_2",
            [],
        ),
        (
            "import ssl\nssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\nssl.wrap_socket(sock)",
            [],
        ),
        ("from OpenSSL import SSL as tls\ntls.Context(tls.SSLv23_METHOD)", []),
        ("import ssl\nversion = ssl.PROTOCOL_TLSv1\nprint(version)", []),
        (
            (
                "from OpenSSL import SSL as tls\n"
                "context = tls.Context(tls.TLS_METHOD)\n"
                "context.set_min_proto_version(tls.TLS1_1_VERSION)"
            ),
            [3],
        ),
        (
            (
                "import ssl\n"
                "def make(protocol=ssl.PROTOCOL_TLSv1_1):\n"
                "    return ssl.SSLContext(protocol)"
            ),
            [3],
        ),
        (
            (
                "import ssl\n"
                "def make(*, version=ssl.TLSVersion.TLSv1):\n"
                "    ctx = ssl.create_default_context()\n"
                "    ctx.minimum_version = version\n"
                "    return ctx"
            ),
            [4],
        ),
        (
            (
                "import ssl\n"
                "def reporting(protocol=ssl.PROTOCOL_TLSv1):\n"
                "    return protocol"
            ),
            [],
        ),
        ("import ssl\nssl.SSLContext = custom\nssl.SSLContext(ssl.PROTOCOL_TLSv1)", []),
        (
            "import ssl\ndef client(ssl):\n    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)",
            [],
        ),
        (
            "import ssl\ncontext = custom()\ncontext.minimum_version = ssl.TLSVersion.TLSv1",
            [],
        ),
    ],
)
def test_obsolete_tls_protocol_selection(tmp_path, code, lines):
    path = tmp_path / "transport.py"
    path.write_text(code, encoding="utf-8")
    assert [
        (finding["rule_id"], finding["line"])
        for finding in scan_ctx(tmp_path, [path])
        if finding["rule_id"] == "SKY-D430"
    ] == [("SKY-D430", line) for line in lines]


def test_httpx_reports_explicit_absence_and_keeps_library_defaults(tmp_path):
    code = dedent("""\
        from httpx import Client as SyncClient, AsyncClient
        import httpx as http
        import requests
        http.get(url)
        SyncClient()
        AsyncClient(timeout=5)
        SyncClient(timeout=None)
        http.stream("GET", url, timeout=None)
        client = AsyncClient()
        client.get(url, timeout=None)
        requests.get(url)
        def other(http):
            return http.get(url, timeout=None)
        class Client:
            pass
        Client(timeout=None)
    """)
    linter = LinterVisitor([MissingNetworkTimeoutRule()], str(tmp_path / "client.py"))
    linter.visit(ast.parse(code))
    assert [
        (finding["rule_id"], finding["line"], finding["name"])
        for finding in linter.findings
    ] == [
        ("SKY-L031", 7, "httpx.Client"),
        ("SKY-L031", 8, "httpx.stream"),
        ("SKY-L031", 10, "httpx.AsyncClient.get"),
        ("SKY-L031", 11, "requests.get"),
    ]


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (
            (
                "from cryptography.hazmat.primitives.ciphers import Cipher, modes\n"
                "Cipher(algorithm, modes.ECB())"
            ),
            [2],
        ),
        (
            (
                "from cryptography.hazmat.primitives.ciphers import Cipher, modes\n"
                "def make(algorithm):\n"
                "    mode = modes.ECB()\n"
                "    return Cipher(algorithm=algorithm, mode=mode)"
            ),
            [4],
        ),
        (
            "from Crypto.Cipher import AES as Cipher\nCipher.new(key, mode=Cipher.MODE_ECB)",
            [2],
        ),
        (
            "from Cryptodome.Cipher.AES import new, MODE_ECB\nnew(key, MODE_ECB)",
            [2],
        ),
        (
            "from Crypto.Cipher import AES\nAES.new(key, AES.MODE_GCM)",
            [],
        ),
        (
            (
                "from cryptography.hazmat.primitives.ciphers import Cipher, modes\n"
                "modes.ECB()"
            ),
            [],
        ),
        (
            (
                "from Crypto.Cipher import AES\n"
                "def make(AES, key):\n"
                "    return AES.new(key, AES.MODE_ECB)"
            ),
            [],
        ),
    ],
)
def test_python_ecb_requires_a_resolved_cipher_configuration(tmp_path, code, expected):
    path = tmp_path / "cipher.py"
    path.write_text(code, encoding="utf-8")
    assert [
        (finding["rule_id"], finding["line"])
        for finding in scan_ctx(tmp_path, [path])
        if finding["rule_id"] == "SKY-D384"
    ] == [("SKY-D384", line) for line in expected]
