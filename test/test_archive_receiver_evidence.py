"""Archive claims require receiver evidence; unknown receivers remain visible."""

import ast

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.danger.danger_fs import path_flow


def _scan(source, tmp_path):
    findings = []
    checker = path_flow._PathFlowChecker(str(tmp_path / "application.py"), findings)
    checker.visit(ast.parse(source))
    return [finding for finding in findings if finding["rule_id"] == "SKY-D326"]


@pytest.mark.parametrize(
    "source",
    [
        "class Decoder:\n    def extract(self, data):\n        return 'decoded'\n"
        "decoder = Decoder()\ndecoder.extract(payload)\n",
        "class Decoder:\n    def extractall(self, data):\n        return 42\n"
        "Decoder().extractall(payload)\n",
        "from opentelemetry import propagate\npropagate.extract(headers)\n",
        "from opentelemetry import propagate as context_api\ncontext_api.extract(headers)\n",
        "import opentelemetry.propagate as context_api\ncontext_api.extract(headers)\n",
        "import opentelemetry.propagate\nopentelemetry.propagate.extract(headers)\n",
        "from opentelemetry import propagate\ncontext_api = propagate\ncontext_api.extract(headers)\n",
        "try:\n    from opentelemetry import propagate\nexcept ImportError:\n    raise\n"
        "def middleware(headers):\n    return propagate.extract(headers)\n",
    ],
)
def test_proven_non_archive_operation_is_not_archive_finding(source, tmp_path):
    assert _scan(source, tmp_path) == []


@pytest.mark.parametrize(
    "source",
    [
        "def unpack(archive, member):\n    archive.extract(member)\n",
        "import tarfile\nwith tarfile.open(upload) as archive:\n    archive.extractall(destination)\n",
        "from zipfile import ZipFile as Container\nwith Container(upload) as archive:\n    archive.extract(member)\n",
        "from opentelemetry import propagate\ndef unpack(propagate, member):\n    propagate.extract(member)\n",
        "from opentelemetry import propagate\npropagate = unknown_provider()\npropagate.extract(member)\n",
        "from opentelemetry import propagate\npropagate.extract = unknown\npropagate.extract(member)\n",
        "from opentelemetry import propagate\ncontext_api = propagate\ncontext_api.extract = unknown\npropagate.extract(member)\n",
        "from opentelemetry import propagate\npatch(propagate)\npropagate.extract(member)\n",
        "import opentelemetry.propagate\npatch(opentelemetry.propagate)\n"
        "opentelemetry.propagate.extract(member)\n",
        "import opentelemetry.propagate\nmonkeypatch.setattr(opentelemetry.propagate, 'extract', unknown)\n"
        "opentelemetry.propagate.extract(member)\n",
        "try:\n    from opentelemetry import propagate\nexcept ImportError:\n    propagate = fallback\npropagate.extract(member)\n",
        "if available:\n    from opentelemetry import propagate\npropagate.extract(member)\n",
        "class Decoder:\n    def extract(self, data):\n        return archive.extract(data)\n"
        "Decoder().extract(payload)\n",
        "class Decoder:\n    def extract(self, data):\n        return data.decode()\n"
        "Decoder().extract(payload)\n",
    ],
)
def test_unsafe_or_unresolved_lookalike_remains(source, tmp_path):
    findings = _scan(source, tmp_path)
    assert findings
    assert (
        findings[-1]["metadata"]["receiver_resolution"]["archive_operation"]
        == "unresolved"
    )


@pytest.mark.parametrize("namespace", [False, True])
def test_local_provider_takes_precedence_over_external_contract(tmp_path, namespace):
    if namespace:
        (tmp_path / "opentelemetry").mkdir()
    else:
        assert write_text_no_symlink(
            tmp_path / "opentelemetry.py", "propagate = unknown\n"
        )
    assert _scan(
        "from opentelemetry import propagate\npropagate.extract(member)\n", tmp_path
    )


def test_receiver_failure_retains_archive_finding(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise RuntimeError("resolver unavailable")

    monkeypatch.setattr(path_flow, "archive_receiver_evidence", fail)
    assert _scan(
        "from opentelemetry import propagate\npropagate.extract(member)\n", tmp_path
    )
