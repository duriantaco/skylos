import io
import json
from argparse import Namespace
from datetime import datetime, timedelta

from skylos.commands.agent_recap_cmd import (
    TS_FORMAT,
    classify,
    read_records,
    log_files,
    run_agent_recap_command,
    summarize,
)
from skylos.core.safe_cache_io import write_text_no_symlink


def _ts(days_ago: float = 0.0) -> str:
    return (datetime.now() - timedelta(days=days_ago)).strftime(TS_FORMAT)


def _fixture_records() -> list[dict]:
    recent = _ts(1)
    rec = lambda **kw: {"ts": recent, "client": "claude", **kw}
    records = []
    records += [rec(event="pre-bash", outcome="block", packages=1, findings=1) for _ in range(2)]
    records.append(rec(event="pre-bash", outcome="block", packages=1, findings=0, direct=1))
    records.append(rec(event="pre-read", outcome="block", findings=2))
    records.append(rec(event="pre-bash", outcome="block", findings=1, secret_sources=1))
    records.append(rec(event="pre-bash", outcome="block-bypass", bypasses=1))
    records += [
        {**rec(event="post-edit", outcome="block", files=1, findings=1), "client": "codex"}
        for _ in range(3)
    ]
    records += [rec(event="post-edit", outcome="pass", files=1, findings=0) for _ in range(5)]
    records.append(rec(event="stop", outcome="block", done_verdict="incomplete", stop_blocks=1))
    records.append(rec(event="pre-bash", outcome="ask", packages=1, findings=0, unverified=1))
    records.append(rec(event="pre-bash", outcome="error", error="ValueError"))
    records += [rec(event="pre-bash", outcome="skip") for _ in range(20)]
    records.append({"ts": _ts(30), "client": "claude", "event": "pre-read", "outcome": "block"})
    return records


def _repo(tmp_path, records=None, raw_extra: str = ""):
    # Pytest's private temp root may have a symlinked system prefix on macOS.
    tmp_path = tmp_path.resolve()
    (tmp_path / ".git").mkdir()
    if records is not None:
        log_dir = tmp_path / ".skylos"
        log_dir.mkdir()
        body = "".join(json.dumps(r) + "\n" for r in records) + raw_extra
        assert write_text_no_symlink(log_dir / "hook.log", body)
    return tmp_path


def _run(path, **kw):
    out = io.StringIO()
    args = Namespace(path=str(path), days=kw.get("days", 7), format=kw.get("format", "table"))
    code = run_agent_recap_command(args, stdout=out)
    return code, out.getvalue()


def test_classify_maps_each_block_kind():
    assert classify({"event": "pre-bash", "outcome": "block", "packages": 2, "findings": 1}) == "install_hallucinated"
    assert classify({"event": "pre-bash", "outcome": "block", "packages": 1, "findings": 0}) == "install_unverified"
    assert classify({"event": "pre-bash", "outcome": "block", "secret_sources": 1, "findings": 3}) == "secret_shell"
    assert classify({"event": "pre-bash", "outcome": "block-bypass"}) == "hook_bypass"
    assert classify({"event": "pre-bash", "outcome": "ask"}) == "install_ask"
    assert classify({"event": "pre-read", "outcome": "block"}) == "secret_read"
    assert classify({"event": "post-edit", "outcome": "block"}) == "edit_issue"
    assert classify({"event": "stop", "outcome": "block"}) == "done_refused"
    for outcome in ("pass", "skip", "note", "error", "allow", "gave-up"):
        assert classify({"event": "pre-bash", "outcome": outcome}) is None
    assert classify({"event": "stop", "outcome": "gave-up"}) is None


def test_default_table_counts_the_last_seven_days(tmp_path):
    repo = _repo(tmp_path, _fixture_records(), raw_extra="{not json\n")
    code, text = _run(repo)
    assert code == 0
    assert "Blocked before it ran" in text
    assert "     2  installs of packages that look hallucinated or typosquatted" in text
    assert "     1  install from a source Skylos can't verify" in text
    assert "     1  read of a file holding secrets" in text
    assert "     1  shell command that would print a secret" in text
    assert "     1  attempt to skip Git hooks or checks" in text
    assert "Sent back to the agent to fix" in text
    assert "     3  edits that added a security issue" in text
    assert '     1  "done" while checks still failed' in text
    assert "Asked you first" in text
    assert "     1  install Skylos couldn't verify" in text
    assert "Checked: 37 hook runs · 1 allowed without a check (hook error): run `skylos doctor`" in text
    assert "Agents: Claude Code 34 · Codex 3" in text
    assert "Nothing here was uploaded." in text
    assert "Nothing blocked" not in text


def test_json_totals(tmp_path):
    repo = _repo(tmp_path, _fixture_records())
    code, text = _run(repo, format="json")
    data = json.loads(text)
    assert code == 0
    assert data["blocked_total"] == 6
    assert data["sent_back_total"] == 4
    assert data["asked_total"] == 1
    assert data["runs"] == 37
    assert data["errors"] == 1
    assert data["window_days"] == 7
    assert data["log_found"] is True
    assert data["categories"]["secret_read"] == 1


def test_days_zero_counts_the_whole_log(tmp_path):
    repo = _repo(tmp_path, _fixture_records())
    _, text = _run(repo, days=0, format="json")
    data = json.loads(text)
    assert data["categories"]["secret_read"] == 2
    assert data["runs"] == 38


def test_no_log_points_to_install_hooks(tmp_path):
    repo = _repo(tmp_path)
    code, text = _run(repo)
    assert code == 0
    assert "No hook log here yet." in text
    assert "skylos agent install-hooks" in text


def test_only_old_records_points_to_doctor(tmp_path):
    repo = _repo(tmp_path, [{"ts": _ts(20), "event": "pre-read", "outcome": "block", "client": "claude"}])
    code, text = _run(repo)
    assert code == 0
    assert "No hook activity in the last 7 days." in text
    assert "skylos doctor" in text


def test_only_passes_says_nothing_blocked(tmp_path):
    recs = [{"ts": _ts(0.5), "event": "post-edit", "outcome": "pass", "client": "cursor"} for _ in range(4)]
    _, text = _run(_repo(tmp_path, recs))
    assert "Nothing blocked in the last 7 days." in text
    assert "Checked: 4 hook runs" in text
    assert "Agents: Cursor 4" in text
    assert "Blocked before it ran" not in text


def test_rotated_log_is_read_first(tmp_path):
    repo = _repo(tmp_path, [{"ts": _ts(0.2), "event": "pre-read", "outcome": "block"}])
    old = {"ts": _ts(0.4), "event": "pre-bash", "outcome": "block-bypass"}
    (repo / ".skylos" / "hook.log.1").write_text(json.dumps(old) + "\n")
    files = log_files(repo)
    assert [f.name for f in files] == ["hook.log.1", "hook.log"]
    summary = summarize(read_records(files), days=7)
    assert summary["blocked_total"] == 2


def test_symlinked_log_is_never_followed(tmp_path):
    repo = _repo(tmp_path)
    secret = tmp_path / "elsewhere.log"
    secret.write_text(json.dumps({"ts": _ts(0.1), "event": "pre-read", "outcome": "block"}) + "\n")
    (repo / ".skylos").mkdir()
    (repo / ".skylos" / "hook.log").symlink_to(secret)
    assert log_files(repo) == []
    _, text = _run(repo)
    assert "No hook log here yet." in text


def test_subdirectory_resolves_to_the_git_root(tmp_path):
    repo = _repo(tmp_path, [{"ts": _ts(0.1), "event": "pre-read", "outcome": "block"}])
    sub = repo / "pkg" / "inner"
    sub.mkdir(parents=True)
    _, text = _run(sub, format="json")
    assert json.loads(text)["categories"]["secret_read"] == 1


def test_not_a_directory_exits_two(tmp_path):
    code, text = _run(tmp_path / "missing")
    assert code == 2
    assert "Not a directory" in text


def test_doctor_activity_line(tmp_path):
    from skylos.commands.doctor_hooks import hook_activity_line

    repo = _repo(tmp_path)
    assert hook_activity_line(repo) == "No hook runs recorded in this repository yet."
    (repo / ".skylos").mkdir()
    log = repo / ".skylos" / "hook.log"
    log.write_text(json.dumps({"ts": _ts(10), "event": "pre-read", "outcome": "block"}) + "\n")
    line = hook_activity_line(repo)
    assert line.startswith("Last hook run here: ")
    assert line.endswith("nothing blocked in the last 7 days")
    with log.open("a") as fh:
        fh.write(json.dumps({"ts": _ts(0.1), "event": "pre-bash", "outcome": "block", "packages": 1, "findings": 1}) + "\n")
    assert hook_activity_line(repo).endswith("1 blocked or sent back in the last 7 days (skylos agent recap)")
