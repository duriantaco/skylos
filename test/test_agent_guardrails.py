"""Organization agent guardrails: fetch, cache, merge, enforcement, events."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import time
from argparse import Namespace
from pathlib import Path

import pytest

from skylos.cloud import guardrails as g
from skylos.commands.guardrails_cmd import run_guardrails_command
from skylos.commands.hook_cmd import HookDeps, run_hook_command

API = "https://cloud.test"
TOKEN = "sk_proj_" + "x" * 32
STRIPE_LIVE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
SECRET_FILE = f"STRIPE_KEY={STRIPE_LIVE}\n"

# Reference output of compileCodeownersPattern in the cloud
# (src/lib/codeowners/parse.ts), generated with node from that file.
TS_REFERENCE = [
    ["*", "^(?:.*/)?[^/]*(?:/.*)?$"],
    ["**", "^.*$"],
    ["/**", "^.*$"],
    ["docs/*", "^docs/[^/]*$"],
    ["/apps/github", "^apps/github(?:/.*)?$"],
    ["**/logs", "^(?:.*/)?logs(?:/.*)?$"],
    ["*.js", "^(?:.*/)?[^/]*\\.js(?:/.*)?$"],
    ["apps/", "^(?:.*/)?apps/.*$"],
    ["/docs/", "^docs/.*$"],
    ["/build/logs", "^build/logs(?:/.*)?$"],
    ["docs/**", "^docs/.*$"],
    ["a/**/b", "^a/(?:.*/)?b(?:/.*)?$"],
    ["a/**/**/b", "^a/(?:.*/)?b(?:/.*)?$"],
    ["**/**", "^.*$"],
    ["foo?.txt", "^(?:.*/)?foo[^/]\\.txt(?:/.*)?$"],
    ["src/**/*.py", "^src/(?:.*/)?[^/]*\\.py(?:/.*)?$"],
    [".env*", "^(?:.*/)?\\.env[^/]*(?:/.*)?$"],
    ["infra/", "^(?:.*/)?infra/.*$"],
    ["/.github/workflows/", "^\\.github/workflows/.*$"],
    ["a.b+c(d)$e{f}|g^h", "^(?:.*/)?a\\.b\\+c\\(d\\)\\$e\\{f\\}\\|g\\^h(?:/.*)?$"],
    ["x/***/y", "^x/[^/]*/y(?:/.*)?$"],
    ["!x", None],
    ["[a]", None],
    ["a\\b", None],
    ["a//b", None],
    ["/", None],
    ["**/a/**", "^(?:.*/)?a/.*$"],
]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _env(root: Path, **extra) -> dict[str, str]:
    return {
        "CLAUDE_PROJECT_DIR": str(root),
        "SKYLOS_TOKEN": TOKEN,
        "SKYLOS_API_URL": API,
        **extra,
    }


def _policy(**overrides) -> dict:
    policy = {
        "secrets_in_edits": "block",
        "package_installs": {k: "block" for k in g.PACKAGE_KINDS},
        "security_min_severity": None,
        "protected_paths": [],
        "allow_local_loosening": False,
        "report_events": False,
    }
    policy.update(overrides)
    return policy


def _cache(
    home: Path, *, status="active", policy=None, fetched_at=None, **extra
) -> Path:
    path = g.cache_path(home, g.cache_key(API, TOKEN))
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "schema": 1,
        "status": status,
        "organization": {"id": "org-1", "name": "Acme"},
        "version": 3,
        "policy": policy if status == "active" else None,
        "refresh_after_seconds": 900,
        "fetched_at": time.time() if fetched_at is None else fetched_at,
        **extra,
    }
    path.write_text(json.dumps(doc))
    return path


class FakePopen:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))

    @property
    def actions(self):
        return [
            argv[argv.index("skylos.cloud.guardrails") + 1] for argv, _ in self.calls
        ]


def _run(
    root,
    home,
    event,
    payload,
    *,
    client="claude",
    env=None,
    verify=None,
    checker=None,
    popen=None,
):
    (root / ".git").mkdir(exist_ok=True)
    deps = HookDeps(
        verify=verify or (lambda target, **_: {"status": "pass", "findings": []}),
        install_checker=checker,
        guardrails_home=home,
        popen=popen or FakePopen(),
    )
    deps.env = env if env is not None else _env(root)
    stdout = io.StringIO()
    code = run_hook_command(
        [event, "--client", client],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=deps,
    )
    text = stdout.getvalue().strip()
    return code, (json.loads(text) if text else None), deps


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        text, encoding="utf-8"
    )  # skylos: ignore[SKY-D324] fixture under tmp_path
    return path


def _edit(path: Path, new: str, session="s1"):
    return {
        "session_id": session,
        "cwd": str(path.parent),
        "tool_name": "Edit",
        "tool_input": {"file_path": str(path), "old_string": "x", "new_string": new},
    }


def _queued(home: Path) -> list[dict]:
    path = home / g.CACHE_DIR / f"{g.cache_key(API, TOKEN)}.events.json"
    return json.loads(path.read_text())["events"] if path.exists() else []


def _mark_reporting_notice_shown(home: Path) -> None:
    path = home / g.CACHE_DIR / f"{g.cache_key(API, TOKEN)}.notices.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"reporting:org-1": 1}))


class FakePost:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append(
            {
                "url": url,
                "headers": headers,
                "body": json.loads(body),
                "timeout": timeout,
            }
        )
        response = (
            self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        )
        if isinstance(response, Exception):
            raise response
        status, payload = response
        return status, json.dumps(payload).encode()


def _active_response(**policy_overrides):
    return (
        200,
        {
            "ok": True,
            "status": "active",
            "organization": {"id": "org-1", "name": "Acme"},
            "version": 4,
            "policy": _policy(**policy_overrides),
            "refresh_after_seconds": 600,
        },
    )


# --------------------------------------------------------------------------
# Settings and merge
# --------------------------------------------------------------------------


@pytest.mark.parametrize("pattern,expected", TS_REFERENCE)
def test_protected_path_compiler_matches_cloud_compiler(pattern, expected):
    assert g.compile_codeowners_pattern(pattern) == expected


def test_protected_match_semantics():
    patterns = ["/infra/", "*.pem", "docs/*"]
    assert g.protected_match("infra/main.tf", patterns) == "/infra/"
    assert g.protected_match("app/infra/main.tf", patterns) is None  # anchored
    assert g.protected_match("keys/server.pem", patterns) == "*.pem"
    assert g.protected_match("docs/a.md", patterns) == "docs/*"
    assert g.protected_match("docs/sub/a.md", patterns) is None  # direct children only
    assert g.protected_match("/etc/passwd", patterns) is None


def test_defaults_are_todays_behaviour():
    settings = g.GuardrailSettings()
    assert settings.secrets_in_edits == "block"
    assert all(settings.package_decision(k) == "block" for k in g.PACKAGE_KINDS)
    assert settings.security_min_severity is None
    assert settings.protected_paths == ()


def test_parse_settings_rejects_bad_values_and_unknown_keys():
    values, problems = g.parse_settings(
        {
            "secrets_in_edits": "off",
            "package_installs": {"missing_package": "warn", "bogus": "warn"},
            "security_min_severity": "high",
            "protected_paths": ["infra/**", "!neg", "[x]", "infra/**"],
            "surprise": True,
        }
    )
    assert "secrets_in_edits" not in values
    assert values["package_installs"] == {"missing_package": "warn"}
    assert values["security_min_severity"] == "HIGH"
    assert values["protected_paths"] == ("infra/**",)
    assert len(problems) == 5


def test_stricter_of_never_loosens_org_settings():
    org = g.GuardrailSettings(
        secrets_in_edits="block",
        package_installs={
            "missing_package": "warn",
            "missing_version": "block",
            "typosquat": "block",
        },
        security_min_severity="HIGH",
        protected_paths=("infra/**",),
    )
    merged = g.stricter_of(
        org,
        {
            "secrets_in_edits": "warn",  # looser: ignored
            "package_installs": {"missing_package": "block", "typosquat": "warn"},
            "security_min_severity": "CRITICAL",  # looser: ignored
            "protected_paths": ("secrets/**",),
        },
    )
    assert merged.secrets_in_edits == "block"
    assert merged.package_decision("missing_package") == "block"  # stricter: applied
    assert merged.package_decision("typosquat") == "block"
    assert merged.security_min_severity == "HIGH"
    assert merged.protected_paths == ("infra/**", "secrets/**")
    lower = g.stricter_of(org, {"security_min_severity": "MEDIUM"})
    assert lower.security_min_severity == "MEDIUM"  # blocks more: stricter


# --------------------------------------------------------------------------
# Cached context
# --------------------------------------------------------------------------


def test_not_logged_in_uses_local_settings(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _write(
        root / "pyproject.toml", '[tool.skylos.guardrails]\nsecrets_in_edits = "warn"\n'
    )
    context = g.load_context(root, {}, home=home)
    assert context.source == "local"
    assert context.settings.secrets_in_edits == "warn"
    assert context.allow_local_loosening is True
    assert context.notices == []


def test_org_policy_forbids_loosening(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _write(
        root / "pyproject.toml",
        '[tool.skylos.guardrails]\nsecrets_in_edits = "warn"\nprotected_paths = ["local/**"]\n',
    )
    _cache(home, policy=_policy(protected_paths=["infra/**"]))
    context = g.load_context(root, _env(root), home=home)
    assert context.source == "org" and context.org_enforced
    assert context.settings.secrets_in_edits == "block"
    assert context.settings.protected_paths == ("infra/**", "local/**")


def test_org_policy_allows_loosening(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _write(
        root / "pyproject.toml", '[tool.skylos.guardrails]\nsecrets_in_edits = "warn"\n'
    )
    _cache(home, policy=_policy(allow_local_loosening=True))
    context = g.load_context(root, _env(root), home=home)
    assert context.source == "org" and not context.org_enforced
    assert context.settings.secrets_in_edits == "warn"


def test_stale_policy_stays_in_force(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _cache(
        home,
        policy=_policy(secrets_in_edits="block", protected_paths=["x/**"]),
        fetched_at=time.time() - 30 * 86400,
    )
    context = g.load_context(root, _env(root), home=home)
    assert context.source == "org"
    assert context.settings.protected_paths == ("x/**",)
    assert g.refresh_due(context)


def _creds(home: Path, plan: str = "pro") -> None:
    _write(home / "credentials.json", json.dumps({"token": TOKEN, "plan": plan}))


@pytest.mark.parametrize(
    "status,plan,notice",
    [
        ("unavailable", "pro", "policy-unavailable"),
        ("unavailable", "free", None),  # a free workspace has no org policy
        ("unauthorized", "pro", "key-rejected"),
        ("not_configured", "pro", None),
        ("plan_required", "free", None),
        ("unsupported", "pro", None),
    ],
)
def test_unavailable_policy_falls_back_to_local_and_says_so_once(
    tmp_path, status, plan, notice
):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _creds(home, plan)
    _cache(home, status=status)
    context = g.load_context(root, _env(root), home=home)
    assert context.source == "default"
    assert [n for n, _ in context.notices] == ([notice] if notice else [])


def test_never_fetched_is_silent_and_starts_a_refresh(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    popen = FakePopen()
    _code, out, _deps = _run(
        root,
        home,
        "pre-read",
        {"tool_name": "Read", "tool_input": {"file_path": str(root / "a.py")}},
        popen=popen,
    )
    assert out is None
    assert popen.actions == ["refresh"]
    # Backoff: the next hook does not start another one.
    _run(
        root,
        home,
        "pre-read",
        {"tool_name": "Read", "tool_input": {"file_path": str(root / "a.py")}},
        popen=popen,
    )
    assert popen.actions == ["refresh"]
    argv, kwargs = popen.calls[0]
    assert argv[argv.index("-m") :][:3] == ["-m", "skylos.cloud.guardrails", "refresh"]
    assert (
        kwargs["stdin"] == subprocess.DEVNULL
        and kwargs.get("start_new_session") is True
    )
    # Never started from the repository (a repo-level skylos/ would shadow us).
    assert kwargs["cwd"] == str(home) and kwargs["env"]["PYTHONSAFEPATH"] == "1"
    if sys.version_info >= (3, 11):
        assert "-P" in argv


def test_policy_load_has_a_hard_time_budget(tmp_path, monkeypatch):
    def slow(*_args, **_kwargs):
        time.sleep(5)

    monkeypatch.setattr(g, "load_org_context", slow)
    started = time.monotonic()
    context = g.load_context_bounded(tmp_path, {}, home=tmp_path, budget=0.2)
    assert time.monotonic() - started < 1.5
    assert context.source == "default"
    assert "in time" in context.reason
    # Nothing could be read: the local escape hatches are not honoured.
    assert context.ignores_local_escape_hatches()


def test_slow_local_config_never_drops_org_policy(tmp_path, monkeypatch):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _cache(home, policy=_policy(protected_paths=["infra/**"]))

    def slow_local(_root):
        time.sleep(5)
        return {"secrets_in_edits": "warn"}, []

    monkeypatch.setattr(g, "read_local_settings", slow_local)
    context = g.load_context_bounded(root, _env(root), home=home, budget=0.3)
    assert context.source == "org" and context.org_enforced
    assert context.settings.protected_paths == ("infra/**",)
    assert context.settings.secrets_in_edits == "block"
    assert "ignored" in context.reason


def test_oversized_pyproject_is_ignored(tmp_path):
    root = tmp_path / "repo"
    _write(
        root / "pyproject.toml",
        '[tool.skylos.guardrails]\nsecrets_in_edits = "warn"\n#'
        + "x" * g.MAX_LOCAL_CONFIG_BYTES,
    )
    values, problems = g.read_local_settings(root)
    assert values == {} and problems


def test_future_fetched_at_is_never_fresh(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _cache(home, policy=_policy(), fetched_at=time.time() + 365 * 86400)
    assert g.refresh_due(g.load_context(root, _env(root), home=home))


def test_repo_link_cannot_switch_to_a_laxer_workspace(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    strict, lax = "tok-strict-" + "a" * 20, "tok-lax-" + "b" * 20
    _write(
        home / "credentials.json",
        json.dumps({"token": strict, "tokens": {"p-lax": {"token": lax}}}),
    )
    _write(root / ".skylos" / "link.json", json.dumps({"project_id": "p-lax"}))
    env = {"SKYLOS_API_URL": API}
    for token, policy in (
        (strict, _policy(secrets_in_edits="block", protected_paths=["infra/**"])),
        (
            lax,
            _policy(
                secrets_in_edits="warn", allow_local_loosening=True, report_events=True
            ),
        ),
    ):
        path = g.cache_path(home, g.cache_key(API, token))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "status": "active",
                    "organization": {"id": token, "name": token},
                    "version": 1,
                    "policy": policy,
                    "fetched_at": time.time(),
                }
            )
        )
    context = g.load_context(root, env, home=home)
    assert context.key == g.cache_key(API, lax)  # fetch with the linked key
    assert context.settings.secrets_in_edits == "block"
    assert context.settings.protected_paths == ("infra/**",)
    assert context.org_enforced  # loosening only if every workspace allows it
    # A repo-controlled link cannot choose another saved workspace as the
    # destination for this repository's event paths.
    assert context.report_events is False
    assert context.merged_workspaces == 2

    event = g.make_event(
        hook="post-edit",
        client="claude",
        category="secret",
        decision="block",
        file="src/private.py",
    )
    assert event is not None
    events_path = home / g.CACHE_DIR / f"{g.cache_key(API, lax)}.events.json"
    events_path.write_text(json.dumps({"events": [event]}))
    post = FakePost([(200, {"ok": True, "accepted": 1})])
    held = g.send_events(env, root, home=home, post=post)
    assert held["sent"] == 0 and held["kept"] == 1
    assert post.calls == []

    # An explicit operator-provided token makes the destination unambiguous.
    selected = {**env, "SKYLOS_TOKEN": lax}
    assert g.load_context(root, selected, home=home).report_events is True


def test_org_name_is_sanitized_for_display():
    assert (
        g.clean_display_text("Acme\x1b[31m [bold]x[/bold]\u202e")
        == "Acme(31m (bold)x(/bold)"
    )


def test_api_url_must_be_https_except_localhost():
    g.check_api_url("https://skylos.dev")
    g.check_api_url("http://127.0.0.1:8080")
    g.check_api_url("http://localhost:3000")
    for bad in (
        "http://skylos.dev",
        "https://user:pw@skylos.dev",
        "file:///etc/passwd",
        "ftp://x",
    ):
        with pytest.raises(ValueError):
            g.check_api_url(bad)


def test_http_post_never_follows_redirects(tmp_path):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append((self.path, self.headers.get("Authorization")))
            self.send_response(302)
            self.send_header("Location", "/stolen")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _body = g._http_post(
            f"http://127.0.0.1:{server.server_port}/api/sync/agent-guardrails",
            {"Authorization": "Bearer secret"},
            b"{}",
            5,
        )
    finally:
        server.shutdown()
    assert status == 302
    assert [path for path, _auth in hits] == ["/api/sync/agent-guardrails"]


def test_pathological_pattern_is_rejected_and_matcher_is_linear():
    evil = "*a*a*a*a*a*a*a*a*a*a*a*c"
    assert g.compile_codeowners_pattern(evil) is None
    assert g.parse_settings({"protected_paths": [evil]})[0]["protected_paths"] == ()
    # Even if such a pattern reached the matcher, it must not backtrack.
    started = time.monotonic()
    assert not g._tokens_match([("any0",), ("seg", evil), ("any0",)], ["a" * 4000])
    assert not g._glob_segment(evil, "a" * 4000)
    assert time.monotonic() - started < 2.0


def test_matcher_agrees_with_regex_on_many_paths():
    import random
    import re

    segments = [
        "a",
        "b",
        "docs",
        "apps",
        "github",
        "logs",
        "x",
        "y",
        "infra",
        "src",
        "m.py",
        "f.js",
        ".env",
        ".envrc",
        "foo1.txt",
    ]
    rng = random.Random(7)
    for pattern, source in TS_REFERENCE:
        if source is None:
            continue
        regex = re.compile(source)
        for _ in range(300):
            path = "/".join(rng.choice(segments) for _ in range(rng.randint(1, 5)))
            assert bool(regex.match(path)) == bool(
                g.protected_match(path, [pattern], case_insensitive=False)
            ), (pattern, path)


def test_case_insensitive_matching():
    assert (
        g.protected_match("INFRA/Main.tf", ["infra/**"], case_insensitive=True)
        == "infra/**"
    )
    assert (
        g.protected_match("INFRA/Main.tf", ["infra/**"], case_insensitive=False) is None
    )


def test_unavailable_notice_is_shown_once(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _creds(home)
    _cache(home, status="unavailable")
    payload = {"tool_name": "Read", "tool_input": {"file_path": str(root / "a.py")}}
    _c, first, _d = _run(root, home, "pre-read", payload)
    _c, second, _d = _run(root, home, "pre-read", payload)
    assert "use local settings" in first["systemMessage"]
    assert second is None


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------


def test_refresh_writes_cache_and_sends_only_minimal_checkin(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    post = FakePost([_active_response(protected_paths=["infra/**"])])
    doc = g.refresh_policy(
        root, _env(root), home=home, agents=["claude-code", "bogus"], post=post
    )
    assert doc["status"] == "active" and doc["version"] == 4
    assert doc["policy"]["protected_paths"] == ["infra/**"]
    call = post.calls[0]
    assert call["url"] == API + g.POLICY_ENDPOINT
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert call["timeout"] <= g.FETCH_TIMEOUT_SECONDS
    assert set(call["body"]) == {"machine_id", "agents", "cli_version"}
    assert call["body"]["agents"] == ["claude-code"]
    assert g._UUID_RE.match(call["body"]["machine_id"])
    assert str(tmp_path) not in json.dumps(call["body"])
    context = g.load_context(root, _env(root), home=home)
    assert context.settings.protected_paths == ("infra/**",)
    # Same machine id every time.
    g.refresh_policy(root, _env(root), home=home, post=post)
    assert post.calls[1]["body"]["machine_id"] == call["body"]["machine_id"]


def test_network_failure_keeps_previous_policy(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    g.refresh_policy(
        root,
        _env(root),
        home=home,
        post=FakePost([_active_response(secrets_in_edits="warn")]),
    )
    doc = g.refresh_policy(
        root, _env(root), home=home, post=FakePost([TimeoutError("slow")])
    )
    assert doc["status"] == "active" and doc["last_error"] == "TimeoutError"
    assert (
        g.load_context(root, _env(root), home=home).settings.secrets_in_edits == "warn"
    )
    # A garbage answer also keeps it.
    g.refresh_policy(
        root,
        _env(root),
        home=home,
        post=FakePost([(200, {"ok": True, "status": "weird"})]),
    )
    assert g.load_context(root, _env(root), home=home).source == "org"


@pytest.mark.parametrize(
    "response", [(404, {"error": "not found"}), (200, "<html>not found</html>")]
)
def test_server_without_endpoint_is_silent(tmp_path, response):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _creds(home)
    doc = g.refresh_policy(root, _env(root), home=home, post=FakePost([response]))
    assert doc["status"] == "unsupported"
    context = g.load_context(root, _env(root), home=home)
    assert context.source == "default" and context.notices == []
    # A policy fetched earlier is not dropped by such an answer.
    g.refresh_policy(root, _env(root), home=home, post=FakePost([_active_response()]))
    g.refresh_policy(root, _env(root), home=home, post=FakePost([response]))
    assert g.load_context(root, _env(root), home=home).source == "org"


def test_rejected_key_drops_org_policy(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    g.refresh_policy(root, _env(root), home=home, post=FakePost([_active_response()]))
    g.refresh_policy(
        root,
        _env(root),
        home=home,
        post=FakePost([(401, {"error": "Invalid API token"})]),
    )
    context = g.load_context(root, _env(root), home=home)
    assert context.source == "default" and "rejected" in context.reason


def test_credential_resolution_uses_repo_link(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _write(root / ".skylos" / "link.json", json.dumps({"project_id": "p2"}))
    _write(
        home / "credentials.json",
        json.dumps({"token": "default-token", "tokens": {"p2": {"token": "p2-token"}}}),
    )
    assert g.resolve_credential(root, {}, home) == "p2-token"
    assert g.resolve_credential(tmp_path / "other", {}, home) == "default-token"
    assert g.resolve_credential(root, {"SKYLOS_TOKEN": "env"}, home) == "env"


# --------------------------------------------------------------------------
# Enforcement in the hooks
# --------------------------------------------------------------------------


def test_secret_warn_downgrades_block_to_note(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    config = _write(root / ".env.example", SECRET_FILE)
    payload = {
        "session_id": "s",
        "tool_name": "Write",
        "tool_input": {"file_path": str(config)},
    }
    _c, blocked, _d = _run(root, home, "post-edit", payload)
    assert blocked["decision"] == "block"
    _cache(home, policy=_policy(secrets_in_edits="warn"))
    _c, warned, _d = _run(root, home, "post-edit", payload)
    assert "decision" not in warned
    assert "not blocking" in warned["hookSpecificOutput"]["additionalContext"]


def test_local_config_cannot_loosen_org_secrets(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _write(
        root / "pyproject.toml", '[tool.skylos.guardrails]\nsecrets_in_edits = "warn"\n'
    )
    config = _write(root / ".env.example", SECRET_FILE)
    payload = {
        "session_id": "s",
        "tool_name": "Write",
        "tool_input": {"file_path": str(config)},
    }
    _cache(home, policy=_policy())
    _c, out, _d = _run(root, home, "post-edit", payload)
    assert out["decision"] == "block"


def _security_verify(severity):
    def verify(target, **_):
        return {
            "status": "fail",
            "findings": [
                {
                    "rule_id": "SKY-D215",
                    "severity": severity,
                    "category": "security",
                    "message": "Possible path traversal",
                    "range": {"file": Path(target).name, "start_line": 2},
                }
            ],
        }

    return verify


def test_security_min_severity_blocks_findings_without_evidence(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    app = _write(root / "app.py", "def load(path):\n    return open(path).read()\n")
    payload = _edit(app, "def load(path):\n    return open(path).read()")
    _c, note, _d = _run(
        root, home, "post-edit", payload, verify=_security_verify("HIGH")
    )
    assert "decision" not in note  # built-in policy: a note (no untrusted source)
    _cache(home, policy=_policy(security_min_severity="HIGH"))
    _c, out, _d = _run(
        root, home, "post-edit", payload, verify=_security_verify("HIGH")
    )
    assert out["decision"] == "block" and "SKY-D215" in out["reason"]
    _c, low, _d = _run(
        root, home, "post-edit", payload, verify=_security_verify("MEDIUM")
    )
    assert "decision" not in low  # below the threshold


def test_pre_edit_denies_protected_path_for_claude(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    target = _write(root / "infra" / "main.tf", "x\n")
    _cache(home, policy=_policy(protected_paths=["/infra/"]))
    _c, out, _d = _run(
        root,
        home,
        "pre-edit",
        {"tool_name": "Edit", "tool_input": {"file_path": str(target)}},
    )
    decision = out["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "infra/main.tf" in decision["permissionDecisionReason"]
    _c, ok, _d = _run(
        root,
        home,
        "pre-edit",
        {"tool_name": "Edit", "tool_input": {"file_path": str(root / "app.py")}},
    )
    assert ok is None


def test_pre_edit_without_protected_paths_is_a_no_op(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _c, out, deps = _run(
        root,
        home,
        "pre-edit",
        {"tool_name": "Edit", "tool_input": {"file_path": str(root / "x.py")}},
    )
    assert out is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_protected_path_after_edit_blocks_until_reverted(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@example.com"],
        ["config", "user.name", "T"],
    ):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    target = _write(root / "infra" / "main.tf", "resource a {}\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-qm", "init"], cwd=root, check=True, capture_output=True
    )
    _cache(home, policy=_policy(protected_paths=["infra/**"]))

    target.write_text("resource a {}\nresource b {}\n")
    patch = (
        "*** Begin Patch\n*** Update File: infra/main.tf\n+resource b {}\n*** End Patch"
    )
    payload = {
        "session_id": "s1",
        "turn_id": "t",
        "cwd": str(root),
        "tool_name": "apply_patch",
        "tool_input": {"command": patch},
    }
    _c, out, _d = _run(root, home, "post-edit", payload, client="codex")
    assert out["decision"] == "block" and "SKY-GUARD-PATH" in out["reason"]

    stop = {"session_id": "s1", "turn_id": "t"}
    _c, blocked, _d = _run(root, home, "stop", stop, client="codex")
    assert blocked["decision"] == "block"

    subprocess.run(
        ["git", "checkout", "--", "infra/main.tf"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    _c, passed, _d = _run(root, home, "stop", stop, client="codex")
    assert passed == {}


def _missing_checker(command, root):
    return {
        "packages": [{"ecosystem": "PyPI", "name": "reqeusts-pro"}],
        "findings": [
            {
                "rule_id": "SKY-D222",
                "state": "missing_package",
                "message": "PyPI package 'reqeusts-pro' does not exist on PyPI",
            }
        ],
    }


def _bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def test_package_warn_allows_with_message(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _cache(
        home,
        policy=_policy(
            package_installs={
                "missing_package": "warn",
                "missing_version": "block",
                "typosquat": "block",
            }
        ),
    )
    _c, out, _d = _run(
        root,
        home,
        "pre-bash",
        _bash("pip install reqeusts-pro"),
        checker=_missing_checker,
    )
    assert "hookSpecificOutput" not in out
    assert "reqeusts-pro" in out["systemMessage"]
    _c, cursor, _d = _run(
        root,
        home,
        "pre-bash",
        {
            "command": "pip install reqeusts-pro",
            "hook_event_name": "beforeShellExecution",
        },
        client="cursor",
        checker=_missing_checker,
    )
    assert cursor["permission"] == "allow" and "reqeusts-pro" in cursor["agent_message"]


def _allowlist_checker():
    from skylos.rules.ai_defect.install_command import check_install_command
    from skylos.rules.ai_defect.manifest_dependency_hallucination import (
        STATUS_MISSING_PACKAGE,
    )

    def checker(command, root):
        return check_install_command(
            command, root, status_checker=lambda *_a: STATUS_MISSING_PACKAGE
        )

    return checker


def test_org_forbidding_loosening_ignores_local_allowlist(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _write(
        root / "pyproject.toml",
        '[tool.skylos]\nhooks_allow_packages = ["internal-thing"]\n',
    )
    command = _bash("pip install internal-thing")
    _c, local, _d = _run(root, home, "pre-bash", command, checker=_allowlist_checker())
    assert local is None  # no org policy: the allowlist applies
    _cache(home, policy=_policy())
    _c, out, _d = _run(root, home, "pre-bash", command, checker=_allowlist_checker())
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "hooks_allow_packages" not in reason and "workspace admin" in reason
    _cache(home, policy=_policy(allow_local_loosening=True))
    _c, loose, _d = _run(root, home, "pre-bash", command, checker=_allowlist_checker())
    assert loose is None


def test_disable_env_ignored_only_when_org_forbids_loosening(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    config = _write(root / ".env.example", SECRET_FILE)
    payload = {
        "session_id": "s",
        "tool_name": "Write",
        "tool_input": {"file_path": str(config)},
    }
    env = _env(root, SKYLOS_HOOKS_DISABLE="all")
    _c, off, _d = _run(root, home, "post-edit", payload, env=env)
    assert off is None
    _cache(home, policy=_policy())
    _c, on, _d = _run(root, home, "post-edit", payload, env=env)
    assert on["decision"] == "block"
    _cache(home, policy=_policy(allow_local_loosening=True))
    _c, loose, _d = _run(root, home, "post-edit", payload, env=env)
    assert loose is None


def test_broken_cache_never_blocks_or_raises(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    path = g.cache_path(home, g.cache_key(API, TOKEN))
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    code, out, _d = _run(root, home, "pre-bash", _bash("ls"))
    assert code == 0 and out is None


# --------------------------------------------------------------------------
# Events: minimal, redacted, only after the notice, bounded
# --------------------------------------------------------------------------

FORBIDDEN_EVENT_TEXT = (
    STRIPE_LIVE,
    "STRIPE_KEY",
    "reqeusts-pro",
    "pip install",
    "os.system",
    "def load",
)


def test_reporting_notice_then_minimal_events(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _cache(home, policy=_policy(report_events=True, protected_paths=["infra/**"]))
    config = _write(root / "cfg" / ".env.example", SECRET_FILE)
    popen = FakePopen()
    _c, out, _d = _run(
        root,
        home,
        "post-edit",
        {
            "session_id": "s",
            "tool_name": "Write",
            "tool_input": {"file_path": str(config)},
        },
        popen=popen,
    )
    assert out["decision"] == "block"
    assert g.REPORTING_NOTICE in out["systemMessage"]
    assert (
        "Your organization receives guardrail events: rule, file path, agent — never code"
        in out["systemMessage"]
    )
    assert "send" in popen.actions

    # The notice is shown once.
    _c, again, _d = _run(
        root,
        home,
        "pre-bash",
        _bash("pip install reqeusts-pro"),
        checker=_missing_checker,
        popen=popen,
    )
    assert "systemMessage" not in again
    _c, _o, _d = _run(
        root,
        home,
        "pre-edit",
        {
            "tool_name": "Write",
            "tool_input": {"file_path": str(root / "infra" / "x.tf")},
        },
        popen=popen,
    )

    events = _queued(home)
    assert {e["category"] for e in events} == {
        "secret",
        "package_missing",
        "protected_path",
    }
    for event in events:
        assert set(event) == {
            "hook",
            "agent",
            "category",
            "rule_id",
            "decision",
            "file",
            "occurred_at",
        }
        assert event["agent"] == "claude-code"
    by_cat = {e["category"]: e for e in events}
    assert by_cat["secret"]["file"] == "cfg/.env.example"
    assert by_cat["package_missing"]["file"] is None
    assert by_cat["protected_path"]["file"] == "infra/x.tf"

    blob = (
        json.dumps(events)
        + (home / g.CACHE_DIR)
        .joinpath(f"{g.cache_key(API, TOKEN)}.events.json")
        .read_text()
    )
    for forbidden in (*FORBIDDEN_EVENT_TEXT, str(tmp_path)):
        assert forbidden not in blob

    post = FakePost([(200, {"ok": True, "accepted": 3})])
    result = g.send_events(_env(root), root, home=home, post=post)
    assert result["sent"] == 3 and _queued(home) == []
    sent = post.calls[0]
    assert sent["url"] == API + g.EVENTS_ENDPOINT
    assert set(sent["body"]) == {"cli_version", "events"}
    wire = json.dumps(sent["body"])
    for forbidden in (*FORBIDDEN_EVENT_TEXT, str(tmp_path), str(root)):
        assert forbidden not in wire


def test_no_events_without_reporting(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _cache(home, policy=_policy(report_events=False))
    popen = FakePopen()
    _c, out, _d = _run(
        root,
        home,
        "pre-bash",
        _bash("pip install reqeusts-pro"),
        checker=_missing_checker,
        popen=popen,
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _queued(home) == [] and "send" not in popen.actions


def test_events_wait_for_the_notice(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _cache(home, policy=_policy(report_events=True))
    context = g.load_context(root, _env(root), home=home)
    g.queue_events(
        context,
        [
            g.make_event(
                hook="stop",
                client="cursor",
                category="secret",
                decision="block",
                file="a.py",
            )
        ],
    )
    post = FakePost([(200, {"ok": True})])
    result = g.send_events(_env(root), root, home=home, post=post)
    assert post.calls == [] and result["kept"] == 1


def test_event_fields_are_sanitized():
    assert g.safe_rel_path("/abs/path.py") is None
    assert g.safe_rel_path("../up.py") is None
    assert g.safe_rel_path("a\\b.py") is None
    assert g.safe_rel_path("C:/x.py") is None
    assert g.safe_rel_path("~/x.py") is None
    assert g.safe_rel_path("a/./b.py") is None
    assert g.safe_rel_path("src/app.py") == "src/app.py"
    event = g.make_event(
        hook="post-edit",
        client="claude",
        category="secret",
        decision="block",
        rule_id="SKY-S101/x",
        file="/etc/x",
    )
    assert event["rule_id"] is None and event["file"] is None
    assert (
        g.make_event(
            hook="post-edit", client="claude", category="made-up", decision="block"
        )
        is None
    )
    # A tampered queue entry is re-validated before sending.
    wire = g._wire_event(
        {
            **event,
            "rule_id": "SKY-S101",
            "file": "src/a.py",
            "code": "secret()",
            "command": "rm -rf /",
        }
    )
    assert set(wire) == set(g._WIRE_FIELDS)


def test_send_failures_keep_queue_bounded_and_refusals_drop(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _cache(home, policy=_policy(report_events=True))
    _mark_reporting_notice_shown(home)
    context = g.load_context(root, _env(root), home=home)
    for _ in range(30):
        g.queue_events(
            context,
            [
                g.make_event(
                    hook="stop",
                    client="codex",
                    category="secret",
                    decision="block",
                    file=f"f{i}.py",
                )
                for i in range(10)
            ],
        )
    assert len(_queued(home)) == g.MAX_QUEUE_EVENTS

    busy = FakePost([(429, {"code": "RATE_LIMITED"})])
    result = g.send_events(_env(root), root, home=home, post=busy)
    assert result["sent"] == 0 and result["kept"] == g.MAX_QUEUE_EVENTS
    offline = FakePost([OSError("down")])
    assert (
        g.send_events(_env(root), root, home=home, post=offline)["kept"]
        == g.MAX_QUEUE_EVENTS
    )

    ok = FakePost([(200, {"ok": True}), (403, {"code": "REPORTING_OFF"})])
    result = g.send_events(_env(root), root, home=home, post=ok)
    assert result["sent"] == g.MAX_BATCH_EVENTS and result["kept"] == 0
    assert all(len(c["body"]["events"]) <= g.MAX_BATCH_EVENTS for c in ok.calls)


def test_reporting_turned_off_discards_queue(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _cache(home, policy=_policy(report_events=True))
    context = g.load_context(root, _env(root), home=home)
    g.queue_events(
        context,
        [
            g.make_event(
                hook="stop", client="codex", category="secret", decision="block"
            )
        ],
    )
    _cache(home, policy=_policy(report_events=False))
    post = FakePost([(200, {"ok": True})])
    assert g.send_events(_env(root), root, home=home, post=post)["dropped"] == 1
    assert post.calls == [] and _queued(home) == []


# --------------------------------------------------------------------------
# skylos agent guardrails
# --------------------------------------------------------------------------


def test_guardrails_command_refresh_prints_policy_and_notice(tmp_path, monkeypatch):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    monkeypatch.setattr(
        g, "detect_installed_agents", lambda _root, _home=None: ["claude-code"]
    )
    lines: list[str] = []
    post = FakePost(
        [_active_response(report_events=True, security_min_severity="HIGH")]
    )
    code = run_guardrails_command(
        Namespace(path=str(root), refresh=True, json=False),
        print_func=lines.append,
        env=_env(root),
        home=home,
        post=post,
    )
    text = "\n".join(lines)
    assert code == 0
    assert "Organization policy v4 from Acme is in force" in text
    assert "HIGH or above" in text
    assert g.REPORTING_NOTICE in text
    assert g.reporting_notice_shown(home, g.cache_key(API, TOKEN))
    assert post.calls[0]["body"]["agents"] == ["claude-code"]

    lines.clear()
    run_guardrails_command(
        Namespace(path=str(root), refresh=False, json=True),
        print_func=lines.append,
        env=_env(root),
        home=home,
    )
    data = json.loads(lines[0])
    assert data["source"] == "org" and data["report_events"] is True


def test_guardrails_command_not_logged_in(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    lines: list[str] = []
    run_guardrails_command(
        Namespace(path=str(root), refresh=True, json=False),
        print_func=lines.append,
        env={},
        home=tmp_path / "home",
    )
    assert "not logged in" in lines[0]


# --------------------------------------------------------------------------
# Security regressions
# --------------------------------------------------------------------------


def test_background_child_never_imports_a_repo_local_skylos_package(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    marker = tmp_path / "PWNED"
    _write(root / "skylos" / "__init__.py", f"open({str(marker)!r}, 'w').write('x')\n")
    _write(root / "skylos" / "cloud" / "__init__.py", "")
    _write(
        root / "skylos" / "cloud" / "guardrails.py",
        f"open({str(marker)!r}, 'w').write('x')\n",
    )
    context = g.GuardrailContext(key="k" * 32, home=home)
    started = []

    def popen(argv, **kwargs):
        # No credentials in HOME and an unroutable API: the child does no network.
        assert "PYTHONPATH" not in kwargs["env"]
        assert "PYTHONHOME" not in kwargs["env"]
        assert "PYTHONUSERBASE" not in kwargs["env"]
        kwargs["env"] = {
            **kwargs["env"],
            "HOME": str(tmp_path / "userhome"),
            "SKYLOS_API_URL": "https://127.0.0.1:9",
        }
        kwargs["env"].pop("SKYLOS_TOKEN", None)
        started.append(subprocess.Popen(argv, **kwargs))

    env = {
        "PYTHONPATH": str(root),
        "PYTHONHOME": str(root),
        "PYTHONUSERBASE": str(root),
    }
    assert g.spawn_background(
        context, "refresh", root=root, client="claude", env=env, popen=popen
    )
    started[0].wait(timeout=60)
    assert started[0].returncode == 0
    assert not marker.exists()


def test_agent_edits_to_skylos_home_are_denied(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    _cache(home, policy=_policy())
    cache_file = g.cache_path(home, g.cache_key(API, TOKEN))
    _c, pre, _d = _run(
        root,
        home,
        "pre-edit",
        {"tool_name": "Write", "tool_input": {"file_path": str(cache_file)}},
    )
    assert pre["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "~/.skylos" in pre["hookSpecificOutput"]["permissionDecisionReason"]
    patch = f"*** Begin Patch\n*** Update File: {home / 'credentials.json'}\n+x\n*** End Patch"
    _c, post, _d = _run(
        root,
        home,
        "post-edit",
        {
            "tool_name": "apply_patch",
            "turn_id": "t",
            "cwd": str(root),
            "tool_input": {"command": patch},
        },
        client="codex",
    )
    assert post["decision"] == "block"


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_shell_write_to_protected_path_is_caught_at_stop(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    root.mkdir()
    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@example.com"],
        ["config", "user.name", "T"],
    ):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    _write(root / "infra" / "main.tf", "a\n")
    _write(root / "infra" / "human.tf", "h\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-qm", "init"], cwd=root, check=True, capture_output=True
    )
    # The developer's own uncommitted change before the session: not blamed.
    (root / "infra" / "human.tf").write_text("human edit\n")
    _cache(home, policy=_policy(protected_paths=["infra/**"]))

    _run(
        root,
        home,
        "pre-bash",
        {
            "session_id": "s9",
            "tool_name": "Bash",
            "tool_input": {"command": "echo x >> infra/main.tf"},
        },
    )
    (root / "infra" / "main.tf").write_text("a\nx\n")  # what the shell command did
    _c, out, _d = _run(root, home, "stop", {"session_id": "s9"})
    assert out["decision"] == "block"
    assert "infra/main.tf" in out["reason"] and "human.tf" not in out["reason"]

    subprocess.run(
        ["git", "checkout", "--", "infra/main.tf"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    _c, clean, _d = _run(root, home, "stop", {"session_id": "s9"})
    assert clean == {}
