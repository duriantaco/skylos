"""The upgrade notice never waits on the network and never nags wrongly."""

import json
import time

import pytest

from skylos.core import update_check


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.delenv("SKYLOS_NO_TELEMETRY", raising=False)
    for name in update_check._CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    return tmp_path / "skylos" / "latest-version.json"


def _store(cache, latest, age=0):
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"latest": latest, "checked": time.time() - age}))


def _no_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("the network must not be used")

    monkeypatch.setattr(update_check.urllib.request, "urlopen", fail)


@pytest.mark.parametrize(
    ("latest", "current", "expected"),
    [
        ("5.7.0", "5.6.0", True),
        ("5.10.0", "5.9.9", True),
        ("6.0", "5.6.0", True),
        ("5.6.0", "5.6.0", False),
        ("5.6", "5.6.0", False),
        ("5.5.9", "5.6.0", False),
        ("5.7.0", "5.6.0.dev3+g1a2b3c", False),
        ("5.7.0", "0.0.0+unknown", False),
        ("5.7.0rc1", "5.6.0", False),
        ("not a version", "5.6.0", False),
    ],
)
def test_only_a_higher_plain_release_counts_as_newer(latest, current, expected):
    assert update_check.is_newer(latest, current) is expected


def test_notice_names_both_versions_and_the_upgrade_command(cache, monkeypatch):
    _no_network(monkeypatch)
    _store(cache, "5.7.0")

    assert update_check.upgrade_notice("5.6.0") == (
        "Skylos 5.7.0 is available (you have 5.6.0). Upgrade: pip install -U skylos"
    )


def test_no_notice_when_current_or_nothing_is_known(cache, monkeypatch):
    _no_network(monkeypatch)

    assert update_check.upgrade_notice("5.6.0") is None
    _store(cache, "5.6.0")
    assert update_check.upgrade_notice("5.6.0") is None


@pytest.mark.parametrize("variable", ["SKYLOS_NO_TELEMETRY", "CI", "GITHUB_ACTIONS"])
def test_opt_out_and_ci_never_ask_or_tell(cache, monkeypatch, variable):
    _no_network(monkeypatch)
    _store(cache, "9.0.0", age=update_check.CACHE_SECONDS * 2)
    monkeypatch.setenv(variable, "1")

    assert update_check.latest_version() is None
    assert update_check.refresh_in_background() is None
    assert update_check.upgrade_notice("5.6.0") is None


def test_fresh_cache_is_used_without_the_network(cache, monkeypatch):
    _no_network(monkeypatch)
    _store(cache, "5.7.0", age=60)

    assert update_check.latest_version() == "5.7.0"
    assert update_check.refresh_in_background() is None


def test_stale_cache_is_refreshed_and_stored(cache, monkeypatch):
    _store(cache, "5.7.0", age=update_check.CACHE_SECONDS + 5)
    monkeypatch.setattr(update_check, "fetch_latest", lambda timeout=0: "5.8.0")

    assert update_check.latest_version() == "5.8.0"
    assert json.loads(cache.read_text())["latest"] == "5.8.0"


def test_background_refresh_stores_the_answer(cache, monkeypatch):
    monkeypatch.setattr(update_check, "fetch_latest", lambda timeout=0: "5.8.0")

    thread = update_check.refresh_in_background()
    thread.join(5)

    assert json.loads(cache.read_text())["latest"] == "5.8.0"


def test_a_failed_request_keeps_the_old_answer_and_raises_nothing(cache, monkeypatch):
    def offline(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setattr(update_check.urllib.request, "urlopen", offline)
    _store(cache, "5.7.0", age=update_check.CACHE_SECONDS + 5)

    assert update_check.fetch_latest() is None
    assert update_check.latest_version() == "5.7.0"


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[]", b'{"info": []}', b'{"info": {"version": "<script>"}}'],
)
def test_a_malformed_pypi_answer_is_ignored(cache, monkeypatch, body):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return body

    monkeypatch.setattr(
        update_check.urllib.request, "urlopen", lambda *args, **kwargs: Response()
    )

    assert update_check.fetch_latest() is None


def test_a_corrupt_cache_file_is_ignored(cache, monkeypatch):
    _no_network(monkeypatch)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text('{"latest": "\\u001b[31mowned", "checked": "soon"}')

    assert update_check.cached_latest() is None
    assert update_check.upgrade_notice("5.6.0") is None


def test_doctor_reports_an_available_upgrade(cache, monkeypatch, capsys):
    import skylos
    from skylos.commands import doctor_cmd

    _no_network(monkeypatch)
    _store(cache, "999.0.0")
    monkeypatch.setattr(skylos, "__version__", "5.6.0")

    assert doctor_cmd.run_doctor_command(["--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)["checks"]["skylos"]
    assert report == {
        "status": "ok",
        "version": "5.6.0",
        "latest_version": "999.0.0",
        "update_available": True,
    }

    assert doctor_cmd.run_doctor_command([]) == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "Skylos 999.0.0 is available (you have 5.6.0)" in text
    assert "pip install -U skylos" in text


def test_doctor_json_never_asks_the_network(cache, monkeypatch, capsys):
    import skylos
    from skylos.commands import doctor_cmd

    _no_network(monkeypatch)
    monkeypatch.setattr(skylos, "__version__", "5.6.0")

    assert doctor_cmd.run_doctor_command(["--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)["checks"]["skylos"]
    assert report == {"status": "ok", "version": "5.6.0"}

    _store(cache, "999.0.0", age=update_check.CACHE_SECONDS * 3)
    assert doctor_cmd.run_doctor_command(["--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)["checks"]["skylos"]
    assert report["latest_version"] == "999.0.0"
    assert report["update_available"] is True


def test_doctor_stays_the_same_when_the_lookup_is_off(cache, monkeypatch, capsys):
    import skylos
    from skylos.commands import doctor_cmd

    _no_network(monkeypatch)
    _store(cache, "999.0.0")
    monkeypatch.setenv("SKYLOS_NO_TELEMETRY", "1")
    monkeypatch.setattr(skylos, "__version__", "5.6.0")

    assert doctor_cmd.run_doctor_command(["--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)["checks"]["skylos"]
    assert report == {"status": "ok", "version": "5.6.0"}


def test_scan_notice_is_only_printed_on_a_terminal(cache, monkeypatch):
    import skylos
    from skylos.commands import scan_cmd

    _no_network(monkeypatch)
    _store(cache, "999.0.0")
    monkeypatch.setattr(skylos, "__version__", "5.6.0")
    printed = []

    class Recorder:
        def print(self, text):
            printed.append(text)

    monkeypatch.setattr(scan_cmd, "_terminal_output", lambda: False)
    scan_cmd._print_upgrade_notice(Recorder())
    assert printed == []

    monkeypatch.setattr(scan_cmd, "_terminal_output", lambda: True)
    scan_cmd._print_upgrade_notice(Recorder())
    assert len(printed) == 1
    assert "Skylos 999.0.0 is available (you have 5.6.0)" in printed[0]
