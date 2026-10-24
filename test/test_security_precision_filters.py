"""Security findings that read ordinary code or text as an attack, next to
the real cases that must still be reported.

Translated documentation is not a homoglyph attack, a joiner required by a
script's spelling hides nothing, a project's own ``extract`` method and
``zipfile`` cannot escape the destination, and code that reads a secret from
the environment or an unkeyed sentence is not a hard-coded secret.
"""

from pathlib import Path

from skylos.rules.danger.danger import scan_ctx as scan_danger
from skylos.rules.secrets import scan_ctx as scan_secrets
from skylos.security.injection_scanner import scan_file


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _d260_lines(tmp_path, name, text):
    findings = scan_file(_write(tmp_path, name, text))
    return sorted(f["line"] for f in findings if f["rule_id"] == "SKY-D260")


def _secret_providers(text, rel):
    return [
        finding.get("provider")
        for finding in scan_secrets(
            {"relpath": rel, "lines": text.splitlines(True), "tree": None},
            ignore_tests=False,
        )
    ]


def test_translated_language_links_are_not_homoglyphs(tmp_path):
    text = (
        "# Project\n"
        "[English](README.md) | [Русский](https://docs.example.com/ru/) | [Español](es.md)\n"
        "Сначала установите пакет и запустите сервер.\n"
    )
    assert _d260_lines(tmp_path, "README.md", text) == []


def test_mixed_script_words_are_still_homoglyphs(tmp_path):
    text = (
        "# Setup\n"
        "Log in at pаypal.com before you continue.\n"
        "Then run the ехес helper with the token.\n"
    )
    assert _d260_lines(tmp_path, "README.md", text) == [2, 3]


def test_persian_zero_width_non_joiner_is_spelling(tmp_path):
    text = "# راهنما\nاین برنامه فایل\u200cها را بررسی می\u200cکند.\n"
    assert _d260_lines(tmp_path, "README.fa.md", text) == []


def test_invisible_characters_outside_joining_scripts_are_still_reported(tmp_path):
    text = "# Notes\nRun the in\u200cstaller first.\nاین برنامه\u200bفایل را بررسی می\u200cکند.\n"
    assert _d260_lines(tmp_path, "README.md", text) == [2, 3]


def test_zero_width_joiner_in_emoji_is_not_reported(tmp_path):
    text = "# Team\nBuilt by \U0001f469\u200d\U0001f4bb engineers.\n"
    assert _d260_lines(tmp_path, "README.md", text) == []


def test_agent_instruction_file_keeps_strict_joiner_checks(tmp_path):
    text = "# Agent\nاین برنامه فایل\u200cها را بررسی می\u200cکند.\n"
    findings = scan_file(_write(tmp_path, "AGENTS.md", text))
    assert {f["line"] for f in findings if f["rule_id"] == "SKY-D266"} == {2}


def test_own_extract_method_is_not_archive_extraction(tmp_path):
    path = _write(
        tmp_path,
        "extractor.py",
        "import tarfile\n\n\n"
        "class VideoExtractor:\n"
        "    def extract(self, **kwargs):\n"
        "        return kwargs\n\n"
        "    def download(self, **kwargs):\n"
        "        self.extract(**kwargs)\n",
    )
    rules = {f["rule_id"] for f in scan_danger(tmp_path, [path])}
    assert "SKY-D326" not in rules


def test_archive_subclass_extract_is_still_reported(tmp_path):
    path = _write(
        tmp_path,
        "archive.py",
        "import tarfile\n\n\n"
        "class Bundle(tarfile.TarFile):\n"
        "    def extract(self, member, path=''):\n"
        "        return super().extract(member, path)\n\n"
        "    def unpack(self, member, destination):\n"
        "        self.extract(member, destination)\n",
    )
    lines = [
        f["line"] for f in scan_danger(tmp_path, [path]) if f["rule_id"] == "SKY-D326"
    ]
    assert 9 in lines


def test_tar_extraction_with_data_filter_is_not_reported(tmp_path):
    path = _write(
        tmp_path,
        "unpack.py",
        "import tarfile\n\n\n"
        "def unpack(archive_path, destination):\n"
        "    with tarfile.open(archive_path) as archive:\n"
        "        archive.extractall(destination, filter='data')\n"
        "    with tarfile.open(archive_path) as other:\n"
        "        other.extractall(destination)\n",
    )
    lines = [
        f["line"] for f in scan_danger(tmp_path, [path]) if f["rule_id"] == "SKY-D326"
    ]
    assert lines == [8]


def test_environment_lookup_is_not_a_credential_literal():
    text = (
        "jobs:\n  review:\n    steps:\n      - run: |\n"
        "          client = OpenAI(\n"
        '            api_key=os.getenv("OPENAI_API_KEY")\n'
        "          )\n"
    )
    assert "config_credential" not in _secret_providers(text, "workflow.yaml")


def test_environment_lookup_with_a_literal_default_is_still_reported():
    secret = "sk_live_" + "51HqLyjWDarjtT1zdp7dcXyZ"
    text = f'settings:\n  api_key: os.getenv("API_KEY", "{secret}")\n'
    assert _secret_providers(text, "settings.yaml")


def test_unkeyed_sentence_is_not_a_high_entropy_secret():
    text = 'MESSAGE = ["Copy the full share URL, then paste it into the box"]\n'
    assert "generic" not in _secret_providers(text, "messages.py")


def test_keyed_sentence_remains_reportable_as_a_passphrase():
    text = 'PASSWORD = "vivid quartz flamingo jumps over lazy brown hedgehog"\n'
    assert _secret_providers(text, "settings.py")


def test_unkeyed_random_token_is_still_reported():
    token = "9xQ2mK7pL4vR8tW1zN6bY3cH5jD0fG2sA"
    assert "generic" in _secret_providers(f'value = "{token}"\n', "app.py")


def _analyzed_secrets(tmp_path, files, **options):
    import json

    from skylos.analyzer import analyze

    for name, text in files.items():
        _write(tmp_path, name, text)
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_secrets=True,
            grep_verify=False,
            trace_file=False,
            **options,
        )
    )
    return result, [f for f in result["secrets"] if f["rule_id"] == "SKY-S101"]


PUBLIC_ID = "MS4wLjABAAAATJPY7LAlaa5X-c8uNdWkvz0jUGgpw4eeXIwu_8BhvqE"


def test_public_identifier_secret_is_hidden_but_still_fails_the_gate(tmp_path):
    from skylos.core.gatekeeper import check_gate
    from skylos.reporting.listing import is_listed

    result, secrets = _analyzed_secrets(
        tmp_path,
        {"config.py": f'# 2. sec_user_id: "{PUBLIC_ID}"\nCREATORS = []\n'},
        all_advice=False,
    )
    assert len(secrets) == 1
    assert secrets[0]["listing"]["reason"] == "likely-public-identifier"
    assert not is_listed(secrets[0], "secrets")
    passed, reasons = check_gate(result, {"gate": {"max_secrets": 0}})
    assert passed is False
    assert any("secret" in reason.lower() for reason in reasons)


def test_all_advice_lists_demoted_secrets(tmp_path):
    from skylos.reporting.listing import is_listed

    _result, secrets = _analyzed_secrets(
        tmp_path,
        {"config.py": f'# 2. sec_user_id: "{PUBLIC_ID}"\nCREATORS = []\n'},
        all_advice=True,
    )
    assert secrets and all(is_listed(f, "secrets") for f in secrets)


def test_credential_named_identifier_is_never_demoted(tmp_path):
    from skylos.reporting.listing import is_listed

    _result, secrets = _analyzed_secrets(
        tmp_path,
        {"config.py": f'# session_id: "{PUBLIC_ID}"\nCREATORS = []\n'},
        all_advice=False,
    )
    assert secrets and all(is_listed(f, "secrets") for f in secrets)


def test_secret_without_public_evidence_stays_listed(tmp_path):
    from skylos.reporting.listing import is_listed

    token = "9xQ2mK7pL4vR8tW1zN6bY3cH5jD0fG2sA"
    _result, secrets = _analyzed_secrets(
        tmp_path, {"config.py": f'value = "{token}"\n'}, all_advice=False
    )
    assert secrets and all(is_listed(f, "secrets") for f in secrets)
