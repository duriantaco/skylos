import hashlib
import json
import subprocess
import sys
from io import StringIO

import pytest
from rich.console import Console

from skylos.cicd.init_setup import detect_done_setup
from skylos.commands import open_cmd, setup_cmd
from skylos.done.config import parse_done_config

WIDE = 15
NARROW = 13


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "shop"
    root.mkdir()
    (root / "shop.py").write_text("def total(items):\n    return sum(items)\n\n\ndef checkout(items):\n    return total(items)\n")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "start")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: None)
    return root


@pytest.fixture(autouse=True)
def no_external_calls(monkeypatch):
    monkeypatch.setattr(setup_cmd, "hook_probe", lambda command: "5.4.0")
    monkeypatch.setattr(setup_cmd, "cloud_login_found", lambda root: False)

    def unexpected(root, args, input=None):
        raise AssertionError(f"unexpected gh call: {args}")

    def no_credential_lookup(root):
        raise AssertionError("cicd init must take the login decision from setup")

    def no_login(*args, **kwargs):
        raise AssertionError("setup must never start the Cloud login")

    monkeypatch.setattr(setup_cmd, "_gh", unexpected)
    monkeypatch.setattr("skylos.commands.cicd_cmd._cloud_login_found", no_credential_lookup)
    monkeypatch.setattr("skylos.cloud.login.run_login", no_login)


def _run(root, *argv):
    buffer = StringIO()
    code = setup_cmd.run_setup_command([str(root), *argv], console=Console(file=buffer, width=250, highlight=False))
    return code, buffer.getvalue()


def _row(label, text, width=WIDE, mark="✓"):
    return f"{mark} {label.ljust(width)}  {text}"


def _pytest_repo(repo):
    (repo / "pyproject.toml").write_text('[project]\nname = "shop"\nversion = "0"\n')
    (repo / "tests").mkdir()
    (repo / "tests" / "test_shop.py").write_text("from shop import total\n\n\ndef test_total():\n    assert total([1, 2]) == 3\n")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "tests")
    _git(repo, "remote", "add", "origin", "https://github.com/acme/shop.git")
    return repo


def _skylos_handlers(path, event):
    config = json.loads(path.read_text())
    handlers = [handler for group in config["hooks"][event] for handler in group["hooks"]]
    return [handler["command"] for handler in handlers if "skylos hook" in handler["command"]]


def _all_commands(path):
    config = json.loads(path.read_text())
    return [handler["command"] for groups in config["hooks"].values() for group in groups for handler in group["hooks"]]


def _blob_sha(path):
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


class FakeGh:
    def __init__(self, root, *, authed=True, merged=False, ruleset=None):
        self.root = root
        self.authed = authed
        self.merged = merged
        self.ruleset = ruleset
        self.calls = []

    def _done(self, args, code, stdout="", stderr=""):
        return subprocess.CompletedProcess(["gh", *args], code, stdout, stderr)

    def __call__(self, root, args, input=None):
        assert root == self.root
        self.calls.append((args, input))
        if args == ["auth", "status"]:
            if self.authed:
                return self._done(args, 0)
            return self._done(args, 1, "", "You are not logged into any GitHub hosts.")
        if args == ["api", "repos/{owner}/{repo}/contents/.github/workflows/skylos.yml"]:
            if not self.merged:
                return self._done(args, 1, "", "gh: Not Found (HTTP 404)")
            return self._done(args, 0, json.dumps({"sha": _blob_sha(root / ".github/workflows/skylos.yml")}))
        if args == ["api", "repos/{owner}/{repo}/rulesets?per_page=100"]:
            if self.ruleset is None:
                return self._done(args, 0, "[]")
            return self._done(args, 0, json.dumps([{"id": 7, "name": "Skylos"}, {"id": 8, "name": "Other"}]))
        if args == ["api", "repos/{owner}/{repo}/rulesets/7"]:
            return self._done(args, 0, json.dumps(self.ruleset))
        if args == ["api", "--method", "POST", "repos/{owner}/{repo}/rulesets", "--input", "-"]:
            return self._done(args, 0, json.dumps({"id": 9, "enforcement": "active"}))
        raise AssertionError(f"unexpected gh call: {args}")

    def posted(self):
        return [json.loads(input) for args, input in self.calls if "POST" in args]


def _ruleset(*contexts, enforcement="active"):
    return {
        "id": 7,
        "name": "Skylos",
        "target": "branch",
        "enforcement": enforcement,
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "required_status_checks": [{"context": context} for context in contexts],
                },
            }
        ],
    }


def test_setup_writes_agent_steps_mcp_and_ci_then_is_idempotent(repo):
    (repo / "CLAUDE.md").write_text("# Shop\n\nRun the tests with pytest.\n")

    code, output = _run(repo)

    assert code == 0
    claude = (repo / "CLAUDE.md").read_text()
    assert claude.startswith("# Shop\n\nRun the tests with pytest.\n\n<!-- skylos:start -->")
    assert "skylos done --base main" in claude
    assert (repo / "AGENTS.md").read_text() == setup_cmd.agent_block("main")
    assert json.loads((repo / ".mcp.json").read_text()) == {"mcpServers": {"skylos": {"command": "skylos", "args": ["mcp"]}}}
    assert (repo / ".github/workflows/skylos.yml").is_file()
    assert _row("Codex", "not installed; when you install it run: codex mcp add skylos --") in output
    assert "2 functions and classes in 1 files" in output
    assert "Commit " in output and "AGENTS.md" in output and ".skylos/graph/.gitignore" in output
    assert "Next" in output and "skylos open" in output

    before = {name: (repo / name).read_text() for name in ("CLAUDE.md", "AGENTS.md", ".mcp.json", ".github/workflows/skylos.yml")}
    code, output = _run(repo)

    assert code == 0
    assert {name: (repo / name).read_text() for name in before} == before
    assert "CLAUDE.md, AGENTS.md: up to date" in output
    assert ".mcp.json: Skylos tools already connected" in output
    assert "skylos.yml: up to date" in output


def test_setup_replaces_only_its_own_block_and_respects_agents_import(repo):
    (repo / "AGENTS.md").write_text("intro\n<!-- skylos:start -->\nold text\n<!-- skylos:end -->\noutro\n")
    (repo / "CLAUDE.md").write_text("@AGENTS.md\n")

    code, output = _run(repo, "--no-ci", "--base", "origin/develop")

    assert code == 0
    agents = (repo / "AGENTS.md").read_text()
    assert agents.startswith("intro\n<!-- skylos:start -->\n## Skylos")
    assert agents.endswith("<!-- skylos:end -->\noutro\n")
    assert "old text" not in agents
    assert "skylos done --base origin/develop" in agents
    assert (repo / "CLAUDE.md").read_text() == "@AGENTS.md\n"
    assert "AGENTS.md: Skylos steps updated" in output
    assert not (repo / ".github").exists()


def test_setup_keeps_other_mcp_servers_and_leaves_broken_json_alone(repo):
    (repo / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}, "extra": 1}))

    assert _run(repo, "--no-ci")[0] == 0
    assert json.loads((repo / ".mcp.json").read_text()) == {
        "mcpServers": {"other": {"command": "x"}, "skylos": {"command": "skylos", "args": ["mcp"]}},
        "extra": 1,
    }

    (repo / ".mcp.json").write_text("{not json")
    code, output = _run(repo, "--no-ci")

    assert code == 1
    assert (repo / ".mcp.json").read_text() == "{not json"
    assert ".mcp.json is not valid JSON" in output


def test_setup_adds_codex_once(repo, monkeypatch):
    calls = []
    state = {"added": False}

    def fake_run(args, **kwargs):
        calls.append(args[1:])
        if args[2] == "get":
            registered = json.dumps({"transport": {"type": "stdio", "command": state.get("command", ""), "args": ["mcp"]}})
            return subprocess.CompletedProcess(args, 0 if state["added"] else 1, registered, "")
        state["added"] = True
        state["command"] = args[5]
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: "/usr/local/bin/codex" if name == "codex" else "/venv/bin/skylos")
    monkeypatch.setattr(setup_cmd, "_run_quiet", lambda args: fake_run(args))
    monkeypatch.setattr(sys, "argv", ["pytest"])

    _, first = _run(repo, "--no-ci")
    _, second = _run(repo, "--no-ci")

    state["command"] = "/opt/homebrew/bin/skylos"
    code, third = _run(repo, "--no-ci")

    assert calls == [
        ["mcp", "get", "skylos", "--json"],
        ["mcp", "add", "skylos", "--", "/venv/bin/skylos", "mcp"],
        ["mcp", "get", "skylos", "--json"],
        ["mcp", "get", "skylos", "--json"],
    ]
    assert "Codex          Skylos tools connected" in first
    assert "Codex          Skylos tools already connected" in second
    assert code == 1
    assert "connected to a different Skylos (/opt/homebrew/bin/skylos)" in third
    assert "codex mcp remove skylos && codex mcp add skylos -- /venv/bin/skylos mcp" in third


def test_setup_refuses_outside_a_git_repository(tmp_path):
    code, output = _run(tmp_path)

    assert code == 1
    assert "run it inside a git repository" in output
    assert list(tmp_path.iterdir()) == []


def test_default_base_prefers_origin_head_then_main(repo):
    assert setup_cmd.default_base(repo) == "main"
    _git(repo, "update-ref", "refs/remotes/origin/trunk", "HEAD")
    _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
    assert setup_cmd.default_base(repo) == "origin/trunk"


def test_open_compares_with_the_detected_base(repo, monkeypatch):
    seen = []
    monkeypatch.setattr("skylos.commands.graph_cmd.run_graph_command", lambda argv, console=None: seen.append(argv) or 0)
    buffer = StringIO()
    console = Console(file=buffer, width=200, highlight=False)

    _git(repo, "checkout", "-q", "-b", "agent/work")
    assert open_cmd.run_open_command([str(repo), "--no-browser"], console=console) == 0
    _git(repo, "checkout", "-q", "main")
    assert open_cmd.run_open_command([str(repo), "--no-browser"], console=console) == 0

    assert seen[0][:5] == ["open", "--path", str(repo.resolve()), "--since", "main"]
    assert seen[1][:5] == ["open", "--path", str(repo.resolve()), "--since", "HEAD"]
    assert "Showing changes since this branch left main." in buffer.getvalue()
    assert "Showing uncommitted changes." in buffer.getvalue()


def test_setup_and_open_are_registered_commands():
    from skylos.cli_core.dispatch import EARLY_COMMAND_HANDLERS
    import skylos.cli as cli

    assert callable(getattr(cli, EARLY_COMMAND_HANDLERS["setup"]))
    assert callable(getattr(cli, EARLY_COMMAND_HANDLERS["open"]))


def test_setup_warns_when_path_starts_a_different_skylos(repo, monkeypatch):
    monkeypatch.setattr(setup_cmd, "skylos_command", lambda: "/venv/bin/skylos")
    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: {"skylos": "/opt/homebrew/bin/skylos"}.get(name))

    code, output = _run(repo, "--no-ci")

    assert code == 1
    assert "your PATH starts /opt/homebrew/bin/skylos, not this Skylos" in output
    assert json.loads((repo / ".mcp.json").read_text())["mcpServers"]["skylos"] == {"command": "skylos", "args": ["mcp"]}

    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: {"skylos": "/venv/bin/skylos"}.get(name))
    code, output = _run(repo, "--no-ci")
    assert code == 0
    assert "your PATH starts" not in output


def test_setup_finishes_a_pytest_repo_and_is_idempotent(repo, monkeypatch):
    _pytest_repo(repo)
    original = (repo / "pyproject.toml").read_text()
    probes = []
    monkeypatch.setattr(setup_cmd, "hook_probe", lambda command: probes.append(list(command)) or "5.4.0")
    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: {"gh": "/usr/bin/gh"}.get(name))
    gh = FakeGh(repo, authed=True, merged=False)
    monkeypatch.setattr(setup_cmd, "_gh", gh)

    code, output = _run(repo)

    assert code == 0
    assert probes == [["skylos"]]
    claude = repo / ".claude/settings.json"
    codex = repo / ".codex/hooks.json"
    assert len(_all_commands(claude)) == 9 and len(_all_commands(codex)) == 6
    assert all(command.startswith("skylos hook ") and "--client claude" in command for command in _all_commands(claude))
    assert all(command.startswith("skylos hook ") and "--client codex" in command for command in _all_commands(codex))
    assert (repo / "pyproject.toml").read_text() == original + (
        "\n[tool.skylos.done]\n# written by skylos setup; Done reads this table from the base branch\ntest_budget_seconds = 300\n"
    )
    done = parse_done_config((repo / "pyproject.toml").read_text())
    assert done.configured and done.test_command is None and done.problems == ()
    assert "name: Skylos Done" in (repo / ".github/workflows/skylos.yml").read_text()
    assert (repo / ".skylos/.gitignore").is_file()
    assert _row("Agent hooks", ".claude/settings.json, .codex/hooks.json: Skylos checks every edit and the finished change") in output
    assert _row("Tests", "pyproject.toml: [tool.skylos.done] added; Done runs pytest once it is committed") in output
    assert _row("Required checks", "waits for .github/workflows/skylos.yml to be merged into main", mark="-") in output
    assert (
        "Commit pyproject.toml, .claude/settings.json, .codex/hooks.json, .github/workflows/skylos.yml, .mcp.json, "
        ".skylos/.gitignore, .skylos/graph/.gitignore, AGENTS.md, CLAUDE.md so your team and CI get them."
    ) in output
    assert "Merge .github/workflows/skylos.yml, then run skylos setup again: it makes the checks required." in output
    assert "Hooks start with the next Claude Code session; in Codex, trust them once with /hooks." in output
    assert gh.posted() == []

    tracked = ("CLAUDE.md", "AGENTS.md", ".mcp.json", ".github/workflows/skylos.yml", ".claude/settings.json", ".codex/hooks.json", "pyproject.toml", ".skylos/.gitignore")
    before = {name: (repo / name).read_bytes() for name in tracked}
    code, output = _run(repo)

    assert code == 0
    assert {name: (repo / name).read_bytes() for name in tracked} == before
    assert len(_skylos_handlers(claude, "Stop")) == 1 and len(_skylos_handlers(codex, "Stop")) == 1
    assert _row("Agent hooks", ".claude/settings.json, .codex/hooks.json: up to date") in output
    assert _row("Tests", "pyproject.toml: [tool.skylos.done] already set") in output
    assert "Hooks start with" not in output
    assert gh.posted() == []


def test_setup_leaves_an_existing_done_table_alone(repo):
    text = '[project]\nname = "shop"\n\n[tool.skylos.done]\ntest_command = "pytest -q"\ntest_budget_seconds = 60\n'
    (repo / "pyproject.toml").write_text(text)

    code, output = _run(repo, "--no-ci")

    assert code == 0
    assert (repo / "pyproject.toml").read_text() == text
    assert _row("Tests", "pyproject.toml: [tool.skylos.done] already set", NARROW) in output


def test_setup_writes_no_done_table_without_tests(repo):
    code, output = _run(repo, "--no-ci")

    assert code == 0
    assert not (repo / "pyproject.toml").exists()
    assert _row("Tests", "no pytest, Vitest or Jest tests found; set test_command in [tool.skylos.done] when you have some", NARROW, mark="-") in output


def test_setup_writes_vitest_settings_to_the_file_done_reads(repo):
    (repo / "package.json").write_text(json.dumps({"devDependencies": {"vitest": "^3.2.0"}}))
    (repo / "skylos.toml").write_text("complexity = 10\n")
    assert not detect_done_setup(repo).enabled

    code, output = _run(repo, "--no-ci")

    assert code == 0
    assert (repo / "skylos.toml").read_text() == (
        "complexity = 10\n\n[done]\n# written by skylos setup; Done reads this table from the base branch\n"
        'test_command = "npx vitest run --reporter=default --reporter=junit --outputFile.junit=reports/junit.xml"\n'
        'junit_xml = "reports/junit.xml"\n'
    )
    assert not (repo / "pyproject.toml").exists()
    assert _row("Tests", "skylos.toml: [done] added; Done runs Vitest once it is committed", NARROW) in output
    done = parse_done_config((repo / "skylos.toml").read_text())
    assert done.test_command[:3] == ("npx", "vitest", "run") and done.junit_xml == "reports/junit.xml"
    assert detect_done_setup(repo).enabled
    assert detect_done_setup(repo).install_commands[-1] == "npm install"


def test_setup_asks_for_jest_junit_before_writing_the_done_table(repo):
    (repo / "package.json").write_text(json.dumps({"devDependencies": {"jest": "^30.0.0"}}))

    code, output = _run(repo, "--no-ci")

    assert code == 0
    assert not (repo / "pyproject.toml").exists()
    assert _row("Tests", "Jest found: run npm install --save-dev jest-junit, then skylos setup again", NARROW, mark="-") in output


def test_setup_makes_the_checks_required_once_the_workflow_is_merged(repo, monkeypatch):
    _pytest_repo(repo)
    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: {"gh": "/usr/bin/gh"}.get(name))
    gh = FakeGh(repo, authed=True, merged=True)
    monkeypatch.setattr(setup_cmd, "_gh", gh)

    code, output = _run(repo)

    assert code == 0
    assert gh.posted() == [
        {
            "name": "Skylos",
            "target": "branch",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": False,
                        "required_status_checks": [{"context": "Skylos Quality Gate"}, {"context": "Skylos Done"}],
                    },
                }
            ],
        }
    ]
    assert _row("Required checks", "ruleset Skylos created: Skylos Quality Gate, Skylos Done must pass to merge into main") in output
    assert "then run skylos setup again" not in output

    gh = FakeGh(repo, authed=True, merged=True, ruleset=_ruleset("Skylos Done", "Skylos Quality Gate"))
    monkeypatch.setattr(setup_cmd, "_gh", gh)
    code, output = _run(repo)

    assert code == 0
    assert gh.posted() == []
    assert _row("Required checks", "ruleset Skylos already requires Skylos Quality Gate, Skylos Done on main") in output

    gh = FakeGh(repo, authed=True, merged=True, ruleset=_ruleset("Skylos Quality Gate"))
    monkeypatch.setattr(setup_cmd, "_gh", gh)
    code, output = _run(repo)

    assert code == 0
    assert gh.posted() == []
    assert _row(
        "Required checks",
        "ruleset Skylos requires Skylos Quality Gate (active); the workflow has Skylos Quality Gate, Skylos Done: fix it under Settings → Rules → Rulesets",
        mark="-",
    ) in output

    gh = FakeGh(repo, authed=True, merged=True)
    monkeypatch.setattr(setup_cmd, "_gh", lambda root, args, input=None: _forbidden(gh, root, args, input))
    code, output = _run(repo)

    assert code == 0
    assert _row(
        "Required checks",
        "could not create the ruleset (HTTP 403: Resource not accessible by integration); needs admin access and a public repository or a paid plan",
        mark="-",
    ) in output


def _forbidden(gh, root, args, input):
    if "--method" in args:
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="HTTP 403: Resource not accessible by integration\n")
    return gh(root, args, input)


def test_setup_says_what_is_missing_for_required_checks(repo, monkeypatch):
    _pytest_repo(repo)

    code, output = _run(repo)

    assert code == 0
    assert _row("Required checks", "needs the GitHub CLI: install gh (https://cli.github.com), then run skylos setup again", mark="-") in output
    assert "Merge .github/workflows/skylos.yml, then run skylos setup again: it makes the checks required." in output

    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: {"gh": "/usr/bin/gh"}.get(name))
    gh = FakeGh(repo, authed=False)
    monkeypatch.setattr(setup_cmd, "_gh", gh)
    code, output = _run(repo)

    assert code == 0
    assert gh.calls == [(["auth", "status"], None)]
    assert _row("Required checks", "run gh auth login, then skylos setup again", mark="-") in output

    _git(repo, "remote", "set-url", "origin", "https://gitlab.com/acme/shop.git")
    code, output = _run(repo)

    assert code == 0
    assert gh.calls == [(["auth", "status"], None)]
    assert _row("Required checks", "origin is not on GitHub; require the Skylos checks in your code host's branch settings", mark="-") in output
    assert "then run skylos setup again" not in output


def test_setup_without_codex_installs_only_claude_hooks(repo):
    code, output = _run(repo, "--no-ci", "--no-codex")

    assert code == 0
    assert (repo / ".claude/settings.json").is_file()
    assert not (repo / ".codex").exists()
    assert _row("Agent hooks", ".claude/settings.json: Skylos checks every edit and the finished change", NARROW) in output


def test_setup_refuses_hooks_when_the_path_skylos_lacks_hook_support(repo, monkeypatch):
    monkeypatch.setattr(setup_cmd, "hook_probe", lambda command: None)

    code, output = _run(repo, "--no-ci")

    assert code == 1
    assert not (repo / ".claude").exists() and not (repo / ".codex").exists()
    assert _row("Agent hooks", "not installed: the `skylos` on PATH does not support `skylos hook`", NARROW, mark="!") in output


UPLOAD_JOB = "name: Skylos Cloud upload"


def _row_index(output, label):
    return next(i for i, line in enumerate(output.splitlines()) if f" {label.ljust(WIDE)}  " in line)


def test_setup_says_cloud_is_not_connected_without_starting_the_login(repo):
    _pytest_repo(repo)

    code, output = _run(repo)

    assert code == 0
    assert _row("Skylos Cloud", setup_cmd.CLOUD_NOT_CONNECTED, mark="-") in output
    assert _row_index(output, "PR check") < _row_index(output, "Skylos Cloud") < _row_index(output, "Required checks")
    assert UPLOAD_JOB not in (repo / ".github/workflows/skylos.yml").read_text()
    assert "Cloud upload: off" not in output


def test_setup_connected_writes_the_upload_jobs_and_says_so(repo, monkeypatch):
    _pytest_repo(repo)
    monkeypatch.setattr(setup_cmd, "cloud_login_found", lambda root: True)

    code, output = _run(repo)

    assert code == 0
    assert _row("Skylos Cloud", setup_cmd.CLOUD_CONNECTED) in output
    assert UPLOAD_JOB in (repo / ".github/workflows/skylos.yml").read_text()


def test_setup_connected_does_not_claim_an_upload_the_workflow_lacks(repo, monkeypatch):
    _pytest_repo(repo)
    _run(repo)
    assert UPLOAD_JOB not in (repo / ".github/workflows/skylos.yml").read_text()
    monkeypatch.setattr(setup_cmd, "cloud_login_found", lambda root: True)

    code, output = _run(repo)

    assert _row("Skylos Cloud", setup_cmd.CLOUD_CONNECTED_NO_UPLOAD + setup_cmd.CLOUD_WORKFLOW_WITHOUT_UPLOAD) in output
    assert UPLOAD_JOB not in (repo / ".github/workflows/skylos.yml").read_text()

    code, output = _run(repo, "--yes")

    assert code == 0
    assert _row("Skylos Cloud", setup_cmd.CLOUD_CONNECTED) in output
    assert UPLOAD_JOB in (repo / ".github/workflows/skylos.yml").read_text()


def test_setup_connected_without_ci_only_points_to_skylos_cloud(repo, monkeypatch):
    monkeypatch.setattr(setup_cmd, "cloud_login_found", lambda root: True)

    code, output = _run(repo, "--no-ci")

    assert code == 0
    assert _row("Skylos Cloud", setup_cmd.CLOUD_CONNECTED_NO_UPLOAD, width=NARROW) in output
    assert not (repo / ".github").exists()
