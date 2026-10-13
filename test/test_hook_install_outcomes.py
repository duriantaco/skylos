"""Explicit outcomes for installs the pre-bash hook cannot verify, and how
each agent receives them."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from skylos.commands.hook_cmd import HookDeps, run_hook_command
from skylos.commands.hook_install_policy import load_install_policy
from skylos.commands.hook_registry_context import is_trusted, registry_context
from skylos.rules.ai_defect.install_command import check_install_command


class Registry:
    """Fake status checker: name -> status, records lookups."""

    def __init__(self, statuses=None, default="present"):
        self.statuses = statuses or {}
        self.default = default
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, ecosystem, name, version, cache):
        self.calls.append((ecosystem, name, version))
        return self.statuses.get(name, self.default)


@pytest.fixture(autouse=True)
def no_global_npm_bins(monkeypatch):
    monkeypatch.setattr("skylos.commands.hook_install_parse._global_bin_dirs", list)


@pytest.fixture
def project(tmp_path) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    return root


@pytest.fixture
def home(tmp_path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


def check(command, project, home, registry=None, *, env=None, trusted=()):
    return check_install_command(
        command,
        project,
        status_checker=registry or Registry(),
        env=env or {},
        home=home,
        trusted_registries=trusted,
    )


def outcomes(result) -> list[str]:
    return [entry["outcome"] for entry in result["unverified"]]


# --------------------------------------------------------------------------
# check_install_command
# --------------------------------------------------------------------------


def test_missing_present_and_unreachable(project, home):
    registry = Registry({"fake-pkg": "missing_package", "offline": "unknown"})
    result = check("pip install requests fake-pkg offline", project, home, registry)
    assert [f["name"] for f in result["findings"]] == ["fake-pkg"]
    assert [(u["name"], u["outcome"]) for u in result["unverified"]] == [
        ("offline", "unreachable")
    ]


def test_missing_version_is_a_finding(project, home):
    registry = Registry({"requests": "missing_version"})
    result = check("pip install requests==99.0.0", project, home, registry)
    assert result["findings"][0]["rule_id"] == "SKY-D225"


def test_runner_packages_are_checked(project, home):
    registry = Registry({"cowsy": "missing_package"})
    result = check("npx -y cowsy hi && uvx ruff check", project, home, registry)
    assert [f["name"] for f in result["findings"]] == ["cowsy"]
    assert ("PyPI", "ruff", "") in registry.calls


def test_direct_sources_are_listed_and_not_looked_up(project, home):
    registry = Registry()
    result = check(
        "npm i github:cline/cline#b181e0 && pip install git+https://github.com/x/y",
        project,
        home,
        registry,
    )
    assert registry.calls == []
    assert [d["ecosystem"] for d in result["direct"]] == ["npm", "PyPI"]
    assert "cline/cline" in result["direct"][0]["source"]
    assert result["findings"] == []


def test_dynamic_names_are_unverified(project, home):
    result = check("pip install $PKG && cat x | xargs npm i", project, home)
    assert outcomes(result) == ["dynamic", "dynamic"]


def test_untrusted_registry_override_is_not_looked_up(project, home):
    registry = Registry()
    result = check(
        "pip install --index-url https://pypi.corp.example/simple internal",
        project,
        home,
        registry,
    )
    assert registry.calls == []
    (entry,) = result["unverified"]
    assert entry["outcome"] == "registry_override"
    assert entry["registry"] == "https://pypi.corp.example/simple"


def test_trusted_registry_override_is_private(project, home):
    result = check(
        "pip install --index-url https://pypi.corp.example/simple internal",
        project,
        home,
        trusted=("pypi.corp.example",),
    )
    assert outcomes(result) == ["private"]


def test_trusted_registry_path_prefix(project, home):
    assert is_trusted("https://h.example/simple/x", ("https://h.example/simple",))
    assert not is_trusted("https://h.example/other", ("https://h.example/simple",))
    assert not is_trusted("https://evil.example/simple", ("h.example",))
    assert not is_trusted("https://h.example.evil.com/simple", ("h.example",))


def test_allowlisted_package_is_not_looked_up(project, home):
    (project / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        '[tool.skylos]\nhooks_allow_packages = ["npm:my-reactt"]\n'
    )
    registry = Registry({"my-reactt": "missing_package"})
    result = check("npm i my-reactt", project, home, registry)
    assert registry.calls == []
    assert outcomes(result) == ["allowlisted"]


def test_scoped_npm_registry_from_npmrc(project, home):
    (project / ".npmrc").write_text("@corp:registry=https://npm.pkg.github.com\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    registry = Registry({"@corp/ui": "missing_package"})
    result = check("npm i @corp/ui lodash", project, home, registry)
    # The scoped package is never sent to the public registry.
    assert [call[1] for call in registry.calls] == ["lodash"]
    assert outcomes(result) == ["not_public"]
    assert result["findings"] == []
    trusted = check("npm i @corp/ui", project, home, Registry(),
                    trusted=("npm.pkg.github.com",))  # fmt: skip
    assert outcomes(trusted) == ["private"]


def test_user_npmrc_default_registry_downgrades_missing(project, home):
    (home / ".npmrc").write_text("registry=https://npm.corp.example/\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    registry = Registry({"internal-lib": "missing_package"})
    result = check("npm i internal-lib lodash", project, home, registry)
    assert result["findings"] == []
    assert outcomes(result) == ["not_public"]
    assert "npm.corp.example" in result["unverified"][0]["reason"]


def test_public_npmrc_registry_changes_nothing(project, home):
    (project / ".npmrc").write_text("registry=https://registry.npmjs.org/\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    registry = Registry({"fake-pkg": "missing_package"})
    result = check("npm i fake-pkg", project, home, registry)
    assert [f["name"] for f in result["findings"]] == ["fake-pkg"]


def test_pip_config_index_downgrades_missing(project, home, tmp_path):
    conf = tmp_path / "pip.conf"
    conf.write_text("[global]\nindex-url = https://pypi.corp.example/simple\n")
    registry = Registry({"corp-utils": "missing_package"})
    result = check(
        "pip install corp-utils", project, home, registry,
        env={"PIP_CONFIG_FILE": str(conf)},
    )  # fmt: skip
    assert result["findings"] == []
    assert outcomes(result) == ["not_public"]


def test_environment_index_downgrades_missing(project, home):
    registry = Registry({"corp-utils": "missing_package"})
    result = check(
        "uv add corp-utils", project, home, registry,
        env={"UV_INDEX_URL": "https://pypi.corp.example/simple"},
    )  # fmt: skip
    assert outcomes(result) == ["not_public"]


def test_pyproject_uv_index_downgrades_missing(project, home):
    (project / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        '[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\n'
    )
    registry = Registry({"corp-utils": "missing_package", "fake": "missing_package"})
    result = check("uv add corp-utils", project, home, registry)
    assert outcomes(result) == ["not_public"]


def test_typosquat_still_blocks_with_private_index(project, home):
    registry = Registry({"reqeusts": "present"})
    result = check(
        "pip install reqeusts", project, home, registry,
        env={"PIP_INDEX_URL": "https://pypi.corp.example/simple"},
    )  # fmt: skip
    assert [f["state"] for f in result["findings"]] == ["suspicious_existing"]


def test_goprivate_modules_are_not_sent_to_the_proxy(project, home):
    registry = Registry()
    result = check(
        "go get github.com/corp/internal/pkg@v1.2.0 github.com/gorilla/mux",
        project, home, registry,
        env={"GOPRIVATE": "github.com/corp/*"},
    )  # fmt: skip
    assert [call[1] for call in registry.calls] == ["github.com/gorilla/mux"]
    assert outcomes(result) == ["private"]


def test_goprivate_from_go_env_file(project, home, tmp_path):
    env_file = tmp_path / "goenv"
    env_file.write_text("GOPRIVATE=example.corp\n")
    context = registry_context(project, project, {"GOENV": str(env_file)}, home)
    assert context.go_is_private("example.corp/team/lib")
    assert not context.go_is_private("example.com/team/lib")


def test_poetry_named_source_downgrades_missing(project, home):
    registry = Registry({"corp-lib": "missing_package"})
    result = check("poetry add --source corp corp-lib", project, home, registry)
    assert result["findings"] == []
    assert outcomes(result) == ["not_public"]


def test_jsr_packages_are_checked_against_jsr(project, home):
    registry = Registry({"@std/nope": "missing_package"})
    result = check("deno add jsr:@std/path jsr:@std/nope", project, home, registry)
    assert ("JSR", "@std/path", "") in registry.calls
    assert [f["name"] for f in result["findings"]] == ["@std/nope"]
    assert "JSR" in result["findings"][0]["message"]


def test_too_many_packages_are_reported_not_dropped(project, home):
    names = " ".join(f"pkg{i}" for i in range(30))
    result = check(f"pip install {names}", project, home)
    assert len(result["packages"]) == 25
    assert outcomes(result) == ["too_many"] * 5


def test_local_and_manifest_counts(project, home):
    result = check(
        "pip install -e . -r requirements.txt && npm ci && npm i ../lib", project, home
    )
    assert result["local"] == 2 and result["manifest"] == 1
    assert result["findings"] == result["unverified"] == result["direct"] == []


def test_cache_keeps_authoritative_answers_only(project, home):
    registry = Registry({"offline": "unknown"})
    check_install_command(
        "pip install requests offline", project, status_checker=registry,
        cache_root=project, env={}, home=home, trusted_registries=(),
    )  # fmt: skip
    registry.calls.clear()
    check_install_command(
        "pip install requests offline", project, status_checker=registry,
        cache_root=project, env={}, home=home, trusted_registries=(),
    )  # fmt: skip
    assert [call[1] for call in registry.calls] == ["offline"]


def test_checker_exception_counts_as_unreachable(project, home):
    def boom(*_args):
        raise TimeoutError("slow")

    result = check_install_command(
        "pip install requests", project, status_checker=boom, env={}, home=home,
        trusted_registries=(),
    )  # fmt: skip
    assert outcomes(result) == ["unreachable"]


def test_registry_http_errors_are_unknown(monkeypatch):
    from skylos.rules.ai_defect import (
        install_command,
        manifest_dependency_hallucination,
    )

    for status in (429, 500, 503, 403, None):
        monkeypatch.setattr(
            manifest_dependency_hallucination,
            "_registry_http_status",
            lambda *_a, _s=status, **_k: _s,
        )
        for ecosystem, name in (("PyPI", "requests"), ("npm", "lodash")):
            assert (
                install_command.check_install_package_status(ecosystem, name, "", {})
                == "unknown"
            ), (status, ecosystem)


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


def test_policy_defaults(tmp_path):
    policy = load_install_policy(tmp_path)
    assert (policy.direct_source, policy.on_unverified, policy.block_hook_bypass) == (
        "ask",
        "ask",
        True,
    )


def test_policy_values_and_invalid_fallbacks(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.skylos.hooks]\n"
        'direct_source = "DENY"\n'
        'on_unverified = "warn"\n'
        'trusted_registries = ["npm.corp.example"]\n'
    )
    policy = load_install_policy(tmp_path)
    assert policy.direct_source == "deny"
    assert policy.on_unverified == "ask"  # invalid -> default, never allow
    assert policy.trusted_registries == ("npm.corp.example",)
    assert any("on_unverified" in p for p in policy.problems)


def test_broken_pyproject_uses_defaults(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.skylos.hooks\n")
    assert load_install_policy(tmp_path).direct_source == "ask"


# --------------------------------------------------------------------------
# Through the hook: what each agent receives
# --------------------------------------------------------------------------


class FakeChecker:
    def __init__(self, result):
        self.result = {"packages": [], "findings": [], "unverified": [], "direct": [],
                       **result}  # fmt: skip

    def __call__(self, command, root):
        return self.result


DIRECT_RESULT = {
    "direct": [
        {
            "ecosystem": "npm",
            "name": "",
            "spec": "github:cline/cline#b181e0",
            "tool": "npm install",
            "runs": False,
            "source": "GitHub repository cline/cline (ref b181e0)",
        }
    ]
}
UNREACHABLE_RESULT = {
    "packages": [{"ecosystem": "PyPI", "name": "requests", "version": ""}],
    "unverified": [
        {
            "ecosystem": "PyPI",
            "name": "requests",
            "version": "",
            "tool": "pip install",
            "reason": "registry unreachable",
            "outcome": "unreachable",
        }
    ],
}
OVERRIDE_RESULT = {
    "unverified": [
        {
            "ecosystem": "PyPI",
            "name": "torch",
            "tool": "pip install",
            "reason": "private registry",
            "outcome": "registry_override",
            "registry": "https://user:pw@download.example/whl",
        }
    ],
}
PRIVATE_RESULT = {
    "unverified": [
        {
            "ecosystem": "npm",
            "name": "@corp/ui",
            "tool": "npm i",
            "reason": "trusted registry",
            "outcome": "private",
        },
        {
            "ecosystem": "npm",
            "name": "mine",
            "tool": "npm i",
            "reason": "allowlisted",
            "outcome": "allowlisted",
        },
    ],
}
FINDING = {"message": "npm package 'cowsy' does not exist on the npm registry."}


def run_hook(project, result, *, client="claude", pyproject=None, command="npm i x"):
    if pyproject is not None:
        (project / "pyproject.toml").write_text(pyproject)  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    stdout = io.StringIO()
    deps = HookDeps(
        env={"CLAUDE_PROJECT_DIR": str(project)},
        install_checker=FakeChecker(result),
    )
    if client == "cursor":
        payload = {"hook_event_name": "beforeShellExecution", "command": command}
    else:
        payload = {"session_id": "s1", "tool_name": "Bash",
                   "tool_input": {"command": command}}  # fmt: skip
        if client == "codex":
            payload["turn_id"] = "t1"
    code = run_hook_command(
        ["pre-bash", "--client", client],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=deps,
    )
    assert code == 0
    text = stdout.getvalue().strip()
    return json.loads(text) if text else None


def last_log(project):
    lines = (project / ".skylos" / "hook.log").read_text().splitlines()
    return json.loads(lines[-1])


@pytest.mark.parametrize("result", [DIRECT_RESULT, UNREACHABLE_RESULT, OVERRIDE_RESULT])
def test_claude_asks_for_unverifiable_installs(project, result):
    out = run_hook(project, result)
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    assert spec["permissionDecisionReason"].startswith("Skylos could not verify")
    assert "Skylos asked the user" in spec["additionalContext"]
    assert last_log(project)["outcome"] == "ask"


@pytest.mark.parametrize("result", [DIRECT_RESULT, UNREACHABLE_RESULT, OVERRIDE_RESULT])
def test_cursor_asks_for_unverifiable_installs(project, result):
    out = run_hook(project, result, client="cursor")
    assert out["permission"] == "ask"
    assert out["user_message"] and out["agent_message"]


@pytest.mark.parametrize("result", [DIRECT_RESULT, UNREACHABLE_RESULT, OVERRIDE_RESULT])
def test_codex_denies_because_it_cannot_ask(project, result):
    out = run_hook(project, result, client="codex")
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "deny"
    assert "Codex hooks cannot ask" in spec["permissionDecisionReason"]


def test_direct_source_message_names_the_source(project):
    out = run_hook(project, DIRECT_RESULT)
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "github:cline/cline#b181e0" in reason
    assert "GitHub repository cline/cline" in reason


def test_override_message_hides_url_credentials(project):
    out = run_hook(project, OVERRIDE_RESULT)
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "download.example/whl" in reason
    assert "user:pw" not in reason
    assert "trusted_registries" in reason


def test_policy_deny(project):
    out = run_hook(
        project, DIRECT_RESULT,
        pyproject='[tool.skylos.hooks]\ndirect_source = "deny"\n',
    )  # fmt: skip
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    out = run_hook(project, DIRECT_RESULT, client="cursor")
    assert out["permission"] == "deny"


def test_policy_allow_is_never_silent(project, capsys):
    pyproject = (
        '[tool.skylos.hooks]\ndirect_source = "allow"\non_unverified = "allow"\n'
    )
    out = run_hook(project, DIRECT_RESULT, pyproject=pyproject)
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert "did not verify" in out["systemMessage"]
    assert "did not verify" in out["hookSpecificOutput"]["additionalContext"]
    assert last_log(project)["outcome"] == "note"
    out = run_hook(project, UNREACHABLE_RESULT, client="codex")
    assert "did not verify" in out["systemMessage"]
    out = run_hook(project, UNREACHABLE_RESULT, client="cursor")
    assert out == {"permission": "allow"}
    assert "did not verify" in capsys.readouterr().err


def test_separate_knobs_combine_to_the_stricter(project):
    pyproject = '[tool.skylos.hooks]\ndirect_source = "allow"\non_unverified = "deny"\n'
    combined = {**DIRECT_RESULT, "unverified": UNREACHABLE_RESULT["unverified"]}
    out = run_hook(project, combined, pyproject=pyproject)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    out = run_hook(project, DIRECT_RESULT)
    assert "permissionDecision" not in out["hookSpecificOutput"]  # allow + note


def test_findings_always_deny_and_list_everything(project):
    result = {**DIRECT_RESULT, "findings": [FINDING],
              "unverified": UNREACHABLE_RESULT["unverified"]}  # fmt: skip
    for client in ("claude", "codex"):
        out = run_hook(project, result, client=client)
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "cowsy" in reason and "cline/cline" in reason and "requests" in reason
    out = run_hook(project, result, client="cursor")
    assert out["permission"] == "deny"


def test_private_and_allowlisted_pass_quietly(project):
    assert run_hook(project, PRIVATE_RESULT) is None
    assert run_hook(project, PRIVATE_RESULT, client="cursor") == {"permission": "allow"}
    assert last_log(project)["outcome"] == "pass"


def test_invalid_policy_value_asks_and_says_so(project):
    out = run_hook(
        project, DIRECT_RESULT,
        pyproject='[tool.skylos.hooks]\ndirect_source = "yes please"\n',
    )  # fmt: skip
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    assert "policy problem" in spec["permissionDecisionReason"]


def test_ask_log_has_no_command_text(project):
    run_hook(project, DIRECT_RESULT, command="npm i github:secret-org/secret-repo")
    log = (project / ".skylos" / "hook.log").read_text()
    assert "secret-org" not in log
    entry = json.loads(log.splitlines()[-1])
    assert entry["direct"] == 1 and entry["outcome"] == "ask"


# --------------------------------------------------------------------------
# Through the hook with the real checker (registry stubbed)
# --------------------------------------------------------------------------


@pytest.fixture
def stub_registry(monkeypatch):
    registry = Registry({"cowsy": "missing_package", "flaky": "unknown"})
    monkeypatch.setattr(
        "skylos.rules.ai_defect.install_command.check_install_package_status", registry
    )
    return registry


def run_real(project, command, client="claude"):
    stdout = io.StringIO()
    deps = HookDeps(
        env={"CLAUDE_PROJECT_DIR": str(project), "HOME": str(project / "h")}
    )
    payload = {"session_id": "s1", "tool_name": "Bash",
               "tool_input": {"command": command}, "cwd": str(project)}  # fmt: skip
    if client == "codex":
        payload["turn_id"] = "t1"
    run_hook_command(["pre-bash", "--client", client], stdin=io.StringIO(json.dumps(payload)),
                     stdout=stdout, deps=deps)  # fmt: skip
    text = stdout.getvalue().strip()
    return json.loads(text) if text else None


def test_real_checker_npx_missing_package_denied(project, stub_registry):
    out = run_real(project, "npx -y cowsy hi")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "cowsy" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_real_checker_local_bin_needs_no_lookup(project, stub_registry):
    bins = project / "node_modules" / ".bin"
    bins.mkdir(parents=True)
    (bins / "tsc").write_text("")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    assert run_real(project, "npx tsc --noEmit") is None
    assert stub_registry.calls == []


def test_real_checker_unreachable_registry_asks(project, stub_registry):
    out = run_real(project, "pip install flaky")
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert (
        "registry unreachable" in out["hookSpecificOutput"]["permissionDecisionReason"]
    )


def test_real_checker_trusted_registry_from_pyproject(project, stub_registry):
    (project / "pyproject.toml").write_text(  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        '[tool.skylos.hooks]\ntrusted_registries = ["https://pypi.corp.example"]\n'
    )
    assert (
        run_real(project, "pip install -i https://pypi.corp.example/simple x") is None
    )
    out = run_real(project, "pip install -i https://evil.example/simple x")
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_real_checker_manifest_and_local_installs_pass(project, stub_registry):
    for command in ("npm ci", "pip install -r requirements.txt", "pip install -e .",
                    "uv sync", "npm install", "go mod download"):  # fmt: skip
        assert run_real(project, command) is None, command
    assert stub_registry.calls == []


# --------------------------------------------------------------------------
# Long commands: what Skylos cannot read is never treated as checked
# --------------------------------------------------------------------------


def test_command_longer_than_the_parser_reads_asks(project, stub_registry):
    padding = "echo " + "x " * 9000
    for tail in ("npm i evil-pkg", "git commit --no-verify -m x"):
        out = run_real(project, f"{padding}&& {tail}")
        spec = out["hookSpecificOutput"]
        assert spec["permissionDecision"] == "ask", tail
        assert "too long to check" in spec["permissionDecisionReason"]
    out = run_real(project, f"{padding}&& npm i evil-pkg", client="codex")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_long_heredoc_file_write_is_not_too_long(project, stub_registry):
    body = "\n".join(f"# pip install thing{i}" for i in range(3000))
    command = f"cat > notes.py <<'EOF'\n{body}\nEOF"
    assert len(command) > 16384
    assert run_real(project, command) is None


def test_long_command_without_install_or_git_is_skipped(project, stub_registry):
    assert run_real(project, "echo " + "x " * 9000) is None


def test_overlong_package_spec_is_not_read(project, home):
    result = check("npm i " + "a" * 600, project, home)
    assert outcomes(result) == ["dynamic"]


def test_codex_guidance_matches_what_could_not_be_verified(project):
    out = run_hook(project, UNREACHABLE_RESULT, client="codex")
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "Retry when the registry answers" in reason
    assert "published package by name" not in reason
    out = run_hook(project, DIRECT_RESULT, client="codex")
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "published package by name" in reason
