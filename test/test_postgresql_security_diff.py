import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from skylos.cicd import review
from test.test_cicd_review_sticky import FakeGitHub

pytest.importorskip("pglast")

_GRANTS = """GRANT SELECT
ON TABLE app.shared
TO PUBLIC;
GRANT UPDATE ON TABLE app.already_shared
TO PUBLIC;
GRANT USAGE
ON SCHEMA shared
TO PUBLIC;
"""
_ROUTINE = """CREATE FUNCTION app.rebuild() RETURNS int
    SECURITY DEFINER
    SET search_path TO pg_catalog
    LANGUAGE SQL AS 'SELECT 1';
"""
_ROLE = """CREATE ROLE backup
    NOLOGIN
    BYPASSRLS;
"""
_IN_TRANSACTION = "BEGIN;\nGRANT UPDATE ON x TO PUBLIC;\n"


def test_sql_security_diff_checks_the_change_across_lines(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)

    def git(*args):
        return subprocess.run(
            [
                "git",
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgSign=false",
                *args,
            ],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    git("init", "-q")
    (repo / "pyproject.toml").write_text('[tool.skylos.sql]\ndialect="postgresql"\n')
    (repo / "grants.sql").write_text(_GRANTS)
    (repo / "routine.sql").write_text(_ROUTINE)
    (repo / "roles.sql").write_text(_ROLE)
    git("add", "grants.sql", "routine.sql", "roles.sql", "pyproject.toml")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    (repo / "grants.sql").write_text(
        _GRANTS.replace("GRANT SELECT", "GRANT UPDATE")
        .replace("GRANT USAGE", "GRANT CREATE")
        .replace(
            "app.already_shared\nTO PUBLIC;",
            "app.already_shared\nTO PUBLIC; -- shared by design",
        )
    )
    (repo / "routine.sql").write_text(
        _ROUTINE.replace("    SET search_path TO pg_catalog\n", "")
    )
    (repo / "roles.sql").write_text(_ROLE.replace("NOLOGIN", "LOGIN"))
    (repo / "rollback.sql").write_text(_IN_TRANSACTION + "ROLLBACK;\n")
    git("add", "rollback.sql")
    git("commit", "-qam", "change migrations")

    report = tmp_path / "report.json"
    env = dict(os.environ, SKYLOS_JOBS="1")
    env["PYTHONPATH"] = os.pathsep.join(
        [str(Path(__file__).resolve().parents[1]), *sys.path]
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "skylos.cli",
            ".",
            "--danger",
            "--diff",
            base,
            "--no-cache",
            "--no-upload",
            "--no-clipboard",
            "--no-provenance",
            "--format",
            "json",
            "-o",
            str(report),
        ],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(report.read_text())
    expected = {
        ("SKY-D417", "routine.sql", 2),
        ("SKY-D418", "grants.sql", 8),
        ("SKY-D419", "roles.sql", 3),
        ("SKY-D420", "grants.sql", 3),
    }
    assert {
        (f["rule_id"], Path(f["file"]).name, f["line"])
        for f in data.get("danger", [])
        if f["file"].endswith(".sql")
    } == expected

    # Exercise real Git and the real review renderer. Intercept only GitHub I/O.
    gh = FakeGitHub()
    real_run = subprocess.run
    monkeypatch.setattr(review, "_gh_available", lambda: True)
    monkeypatch.setattr(
        review.subprocess,
        "run",
        lambda cmd, **kw: gh(cmd, **kw) if cmd[0] == "gh" else real_run(cmd, **kw),
    )
    review.run_pr_review(data, pr_number=7, repo="acme/app", diff_base=base)
    body = gh.issue_comments[0]["body"]
    groups = re.findall(r"^- `(SKY-D\d+)` · ([0-9]+) finding", body, re.MULTILINE)
    assert sorted(groups) == sorted((rule, "1") for rule, _, _ in expected)
    assert not gh.review_comments
    assert "could not be verified" not in body

    # A saved scan can describe earlier content. Keep that review visible,
    # while distinguishing its recorded location from freshly confirmed evidence.
    (repo / "grants.sql").write_text(_GRANTS + "-- migration documentation\n")
    git("commit", "-qam", "revise migration")
    review.run_pr_review(data, pr_number=7, repo="acme/app", diff_base=base)
    assert "could not be verified against this revision" in gh.issue_comments[0]["body"]
    assert "`SKY-D420` · 1 finding" in gh.issue_comments[0]["body"]


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ("GRANT UPDATE, INSERT ON x TO PUBLIC;", "GRANT UPDATE ON x TO PUBLIC;", {}),
        ("", _IN_TRANSACTION + "ROLLBACK;", {}),
        (
            _IN_TRANSACTION + "ROLLBACK;",
            _IN_TRANSACTION + "COMMIT;",
            {("SKY-D420", 2): 1},
        ),
        (
            _IN_TRANSACTION + "REVOKE UPDATE ON x FROM PUBLIC;\nCOMMIT;",
            _IN_TRANSACTION + "COMMIT;",
            {("SKY-D420", 2): 1},
        ),
        (
            "GRANT UPDATE ON x TO PUBLIC;",
            "GRANT UPDATE ON y TO PUBLIC;",
            {("SKY-D420", 1): 1},
        ),
        (
            "GRANT UPDATE ON x TO PUBLIC;",
            "GRANT UPDATE ON x TO PUBLIC;\nGRANT UPDATE ON x TO PUBLIC;",
            {("SKY-D420", 2): 1},
        ),
        (
            _ROUTINE.replace("    SET search_path TO pg_catalog\n", ""),
            _ROUTINE.replace("    SET search_path TO pg_catalog\n", "").replace(
                "SELECT 1", "SELECT 2"
            ),
            {},
        ),
        (
            "BEGIN;\nGRANT UPDATE ON x TO PUBLIC;\nCOMMIT;",
            "BEGIN;\n-- staff agreement\nGRANT UPDATE ON x TO PUBLIC;\nCOMMIT;",
            {},
        ),
    ],
)
def test_comparison_preserves_new_locations_and_stays_quiet_on_known_reviews(
    before, after, expected
):
    from skylos.visitors.languages.postgresql_review_diff import new_review_locations

    _, new = new_review_locations(before, after, [(2, 2)])
    assert dict(new) == expected
