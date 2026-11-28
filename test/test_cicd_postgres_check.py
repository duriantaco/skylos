import subprocess

import pytest

from skylos.cicd.postgres_check import _grants, _introduced, check_postgres

CONFIG = '[tool.skylos.sql.production]\ndirectories = ["db/prod"]\nforbid_public_writes = true\n'
PATH = "db/prod/01.sql"
GRANT = "GRANT UPDATE ON TABLE app.users TO PUBLIC;"


def _git(repo, *args):
    return subprocess.check_output(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        cwd=repo,
        text=True,
    ).strip()


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / PATH).parent.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(CONFIG)
    return tmp_path


def _commit(repo):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "fixture")
    return _git(repo, "rev-parse", "HEAD")


def test_pr_and_checkout_cannot_change_policy_or_scanned_blob(repo):
    pytest.importorskip("pglast")
    base = _commit(repo)
    (repo / "pyproject.toml").write_text("")
    (repo / PATH).write_text(GRANT)
    head = _commit(repo)
    (repo / PATH).write_text("SELECT 1;")
    result = check_postgres(repo, base, head)
    assert result["checked_files"] == 1
    assert result["status"] == "fail"
    assert [(v["file"], v["line"]) for v in result["violations"]] == [(PATH, 1)]


def test_missing_commit_fails_even_if_policy_absent(repo):
    (repo / "pyproject.toml").write_text("")
    base = _commit(repo)
    for head in ("HEAD", "-h", "0" * 40):
        assert check_postgres(repo, base, head)["status"] == "fail"


@pytest.mark.parametrize(
    "config",
    [
        "[tool.skylos.sql.production]\ndirectories=[]",
        CONFIG + "forbid_public_write = true",
        CONFIG + 'allow_public_writes = [{path = "db/prod/*.sql", fingerprint = ""}]',
        '[tool.skylos.sql.production]\ndirectories = ["../db"]',
        "[tool.skylos.sql]\nproduction = true",
        "[tool.skylos.sql",
    ],
)
def test_invalid_trusted_policy_fails(repo, config):
    (repo / "pyproject.toml").write_text(config)
    base = _commit(repo)
    assert (
        check_postgres(repo, base, base)["unchecked_files"][0]["file"]
        == "pyproject.toml"
    )


def test_symlinked_ancestor_or_protected_file_fails(repo):
    base = _commit(repo)
    (repo / "db/prod").rmdir()
    (repo / "db").rmdir()
    (repo / "db").symlink_to("elsewhere")
    head = _commit(repo)
    result = check_postgres(repo, base, head)
    assert result["unchecked_files"][0]["file"] == "db"


def test_moved_into_scope_gets_no_baseline_credit(repo):
    pytest.importorskip("pglast")
    (repo / "elsewhere.sql").write_text(GRANT)
    base = _commit(repo)
    (repo / "elsewhere.sql").rename(repo / PATH)
    head = _commit(repo)
    assert check_postgres(repo, base, head)["violations"][0]["file"] == PATH


@pytest.mark.parametrize(
    ("before", "after", "fail"),
    [
        ("UPDATE, DELETE", "DELETE", False),
        ("UPDATE (a, b)", "UPDATE (a)", False),
        ("UPDATE (a)", "UPDATE", True),
        ("UPDATE", "UPDATE, DELETE", True),
        ("UPDATE", "UPDATE, SELECT", False),
        ("UPDATE, DELETE", "DELETE, UPDATE", False),
    ],
)
def test_privilege_changes(before, after, fail):
    pytest.importorskip("pglast")
    baseline = _grants(GRANT.replace("UPDATE", before), True)
    candidate = _grants(GRANT.replace("UPDATE", after), True)
    assert bool(list(_introduced(candidate, baseline, PATH, set()))) == fail


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("SET ROLE app;", "SET ROLE ops;"),
        ("SET search_path = a;", "SET search_path = b;"),
        (
            "SELECT pg_catalog.set_config('search_path','a',false);",
            "SELECT pg_catalog.set_config('search_path','b',false);",
        ),
        ("\\connect app\n", "\\connect data\n"),
    ],
)
def test_context_changes_need_new_approval(a, b):
    pytest.importorskip("pglast")
    grant = "GRANT UPDATE ON users TO PUBLIC;"
    before = _grants(a + grant, True)
    after = _grants(b + grant, True)
    exceptions = {(PATH, before[0].fingerprint)}
    assert len(list(_introduced(after, before, PATH, exceptions))) == 1


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            "ALTER DEFAULT PRIVILEGES FOR ROLE alpha GRANT INSERT ON TABLES TO PUBLIC;",
            "ALTER DEFAULT PRIVILEGES FOR ROLE beta GRANT INSERT ON TABLES TO PUBLIC;",
        ),
        (
            "ALTER DEFAULT PRIVILEGES IN SCHEMA alpha GRANT INSERT ON TABLES TO PUBLIC;",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA beta GRANT INSERT ON TABLES TO PUBLIC;",
        ),
        (
            "CREATE SCHEMA alpha GRANT UPDATE ON users TO PUBLIC;",
            "CREATE SCHEMA beta GRANT UPDATE ON users TO PUBLIC;",
        ),
        (
            "GRANT UPDATE (a) ON app.users TO PUBLIC;",
            "GRANT UPDATE (b) ON app.users TO PUBLIC;",
        ),
    ],
)
def test_target_changes_need_new_approval(before, after):
    pytest.importorskip("pglast")
    baseline = _grants(before, True)
    candidate = _grants(after, True)
    assert (
        len(
            list(
                _introduced(
                    candidate, baseline, PATH, {(PATH, baseline[0].fingerprint)}
                )
            )
        )
        == 1
    )


def test_exception_cannot_double_its_baseline_or_cover_a_second_path():
    pytest.importorskip("pglast")
    baseline = _grants(GRANT, True)
    candidate = _grants(GRANT + "\r\n" + GRANT, True)
    exceptions = {(PATH, baseline[0].fingerprint)}
    assert [r["line"] for r in _introduced(candidate, baseline, PATH, exceptions)] == [
        2
    ]
    assert list(_introduced(baseline, [], "db/prod/other.sql", exceptions))


def test_nul_cannot_truncate_protected_sql(repo):
    pytest.importorskip("pglast")
    base = _commit(repo)
    (repo / PATH).write_bytes(b"SELECT 1;\0")
    head = _commit(repo)
    assert "NUL" in check_postgres(repo, base, head)["unchecked_files"][0]["reason"]


@pytest.mark.parametrize(
    ("before", "after", "fail"),
    [
        ("app.a, app.b", "app.b", False),
        ("app.a, app.b", "app.b, app.a", False),
        ("app.a", "app.a, app.b", True),
        ("app.a", "app.b", True),
    ],
)
def test_grant_target_changes(before, after, fail):
    pytest.importorskip("pglast")
    baseline = _grants(GRANT.replace("app.users", before), True)
    candidate = _grants(GRANT.replace("app.users", after), True)
    assert bool(list(_introduced(candidate, baseline, PATH, set()))) == fail


@pytest.mark.parametrize(
    "setting",
    [
        "SET LOCAL lock_timeout = '1s';",
        "SET statement_timeout = 500;",
        "SELECT pg_catalog.set_config('lock_timeout','1s',true);",
    ],
)
def test_timing_settings_do_not_change_a_grant(setting):
    pytest.importorskip("pglast")
    baseline = _grants(GRANT, True)
    candidate = _grants(setting + GRANT, True)
    assert not list(_introduced(candidate, baseline, PATH, set()))


def test_credit_allocation_for_two_overlapping_prior_grants():
    pytest.importorskip("pglast")
    baseline = _grants(
        GRANT.replace("UPDATE", "UPDATE, DELETE")
        + GRANT.replace("UPDATE", "UPDATE, INSERT"),
        True,
    )
    candidate = _grants(GRANT + GRANT.replace("UPDATE", "DELETE"), True)
    assert not list(_introduced(candidate, baseline, PATH, set()))
    assert not list(_introduced(candidate[::-1], baseline, PATH, set()))


def test_specific_exception_preserves_other_genuine_baseline_credit():
    pytest.importorskip("pglast")
    baseline = _grants(GRANT.replace("UPDATE", "UPDATE, DELETE"), True)
    candidate = _grants(GRANT + GRANT.replace("UPDATE", "DELETE"), True)
    assert not list(
        _introduced(candidate, baseline, PATH, {(PATH, candidate[0].fingerprint)})
    )


def _new_grants(before, after):
    return list(_introduced(_grants(after, True), _grants(before, True), PATH, set()))


@pytest.mark.parametrize(
    "irrelevant",
    [
        "BEGIN; SELECT 1; COMMIT;",
        "REVOKE UPDATE ON app.users FROM writer;",
        "REVOKE UPDATE ON app.other FROM PUBLIC;",
    ],
)
def test_unrelated_transaction_and_revoke_preserve_grant_identity(irrelevant):
    pytest.importorskip("pglast")
    assert not _new_grants(GRANT, irrelevant + GRANT)


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("ROLLBACK", 0),
        ("COMMIT", 1),
        ("ROLLBACK TO s; COMMIT", 0),
        ("RELEASE s; COMMIT", 1),
        ("SAVEPOINT s; ROLLBACK TO s; COMMIT", 1),
        ("RELEASE s; ROLLBACK AND CHAIN; COMMIT", 0),
    ],
)
def test_grants_require_a_committed_transaction(action, expected):
    pytest.importorskip("pglast")
    candidate = "BEGIN; SAVEPOINT s;" + GRANT + action + ";"
    assert len(_new_grants("BEGIN;" + GRANT + "ROLLBACK;", candidate)) == expected


def test_committed_exposure_and_removal_of_its_later_revocation():
    pytest.importorskip("pglast")
    revoke = "REVOKE UPDATE ON app.users FROM PUBLIC;"
    assert not _new_grants("", "BEGIN;" + GRANT + revoke + "COMMIT;")
    assert len(_new_grants("", GRANT + revoke)) == 1
    assert len(_new_grants(GRANT + revoke, GRANT)) == 1
    assert not _new_grants(GRANT + "BEGIN;" + revoke + "ROLLBACK;", GRANT)


@pytest.mark.parametrize(
    ("baseline", "candidate", "expected"),
    [
        (
            "GRANT UPDATE(a,b) ON app.users TO PUBLIC; REVOKE UPDATE(a) ON app.users FROM PUBLIC;",
            "GRANT UPDATE(a) ON app.users TO PUBLIC;",
            1,
        ),
        (
            "GRANT UPDATE(a,b) ON app.users TO PUBLIC; REVOKE UPDATE(a) ON app.users FROM PUBLIC;",
            "GRANT UPDATE(b) ON app.users TO PUBLIC;",
            0,
        ),
        (GRANT + "REVOKE UPDATE(a) ON app.users FROM PUBLIC;", GRANT, 0),
        (GRANT + "REVOKE GRANT OPTION FOR UPDATE ON app.users FROM PUBLIC;", GRANT, 0),
        (
            "GRANT UPDATE ON app.users, app.other TO PUBLIC; REVOKE UPDATE ON app.users FROM PUBLIC;",
            GRANT,
            1,
        ),
        (
            "GRANT UPDATE, DELETE ON app.users TO PUBLIC; REVOKE UPDATE ON app.users FROM PUBLIC;",
            "GRANT DELETE ON app.users TO PUBLIC;",
            0,
        ),
        (
            "ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT UPDATE ON TABLES TO PUBLIC; ALTER DEFAULT PRIVILEGES IN SCHEMA app REVOKE UPDATE ON TABLES FROM PUBLIC;",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT UPDATE ON TABLES TO PUBLIC;",
            1,
        ),
        (GRANT + "SET ROLE other; REVOKE UPDATE ON app.users FROM PUBLIC;", GRANT, 0),
    ],
)
def test_direct_revoke_matches_targets_privileges_and_grantor(
    baseline, candidate, expected
):
    pytest.importorskip("pglast")
    assert len(_new_grants(baseline, candidate)) == expected


@pytest.mark.parametrize(
    "setting",
    [
        "SET LOCAL search_path = app;",
        "SELECT set_config('search_path', 'app', true);",
    ],
)
def test_local_resolution_setting_cannot_escape_commit(setting):
    pytest.importorskip("pglast")
    grant = "GRANT UPDATE ON users TO PUBLIC;"
    outside = "BEGIN;" + setting + "COMMIT;" + grant
    inside = "BEGIN;" + setting + grant + "COMMIT;"
    assert not _new_grants(grant, outside)
    assert len(_new_grants(outside, inside)) == 1


def test_uncertain_transaction_blocks_only_relevant_grants(repo):
    pytest.importorskip("pglast")
    base = _commit(repo)
    path = repo / PATH
    path.write_text(
        "BEGIN; GRANT SELECT ON app.users TO reader; PREPARE TRANSACTION 'id';"
    )
    read_head = _commit(repo)
    assert check_postgres(repo, base, read_head)["status"] == "pass"
    path.write_text("BEGIN;" + GRANT + "PREPARE TRANSACTION 'id';")
    write_head = _commit(repo)
    assert (
        "transaction"
        in check_postgres(repo, base, write_head)["unchecked_files"][0]["reason"]
    )


@pytest.mark.parametrize(
    ("before", "after", "count"),
    [
        (
            "GRANT UPDATE, DELETE ON app.users TO PUBLIC;",
            GRANT + GRANT.replace("UPDATE", "DELETE"),
            0,
        ),
        (
            GRANT + GRANT.replace("UPDATE", "DELETE"),
            "GRANT UPDATE, DELETE ON app.users TO PUBLIC;",
            0,
        ),
        (
            "GRANT UPDATE ON app.a, app.b TO PUBLIC;",
            "GRANT UPDATE ON app.a TO PUBLIC; GRANT UPDATE ON app.b TO PUBLIC;",
            0,
        ),
        (
            "GRANT UPDATE ON app.a TO PUBLIC; GRANT DELETE ON app.b TO PUBLIC;",
            "GRANT UPDATE, DELETE ON app.a, app.b TO PUBLIC;",
            1,
        ),
        (
            "GRANT UPDATE(a,b) ON app.users TO PUBLIC;",
            "GRANT UPDATE(a) ON app.users TO PUBLIC; GRANT UPDATE(b) ON app.users TO PUBLIC;",
            0,
        ),
        (
            GRANT,
            "GRANT UPDATE(a) ON app.users TO PUBLIC; GRANT UPDATE(b) ON app.users TO PUBLIC;",
            0,
        ),
        (
            GRANT,
            "GRANT UPDATE(a) ON app.users TO PUBLIC; GRANT UPDATE(a) ON app.users TO PUBLIC;",
            1,
        ),
        (
            "GRANT UPDATE(a) ON app.users TO PUBLIC; GRANT UPDATE(b) ON app.users TO PUBLIC;",
            GRANT,
            1,
        ),
    ],
)
def test_regrouping_preserves_each_targets_right_and_occurrence(before, after, count):
    pytest.importorskip("pglast")
    assert len(_new_grants(before, after)) == count


def test_over_budget_regrouping_cannot_approve_a_new_right(monkeypatch):
    pytest.importorskip("pglast")
    monkeypatch.setattr("skylos.cicd.postgres_check._MAX_GRANT_CELLS", 1)
    before = "GRANT UPDATE ON app.a TO PUBLIC; GRANT DELETE ON app.b TO PUBLIC;"
    after = "GRANT UPDATE, DELETE ON app.a, app.b TO PUBLIC;"
    assert len(_new_grants(before, after)) == 1
    assert not _new_grants(before, before)


def test_regrouping_cannot_transfer_exception_budget():
    pytest.importorskip("pglast")
    baseline = _grants("GRANT UPDATE, DELETE ON app.users TO PUBLIC;", True)
    after = _grants(GRANT + GRANT.replace("UPDATE", "DELETE") + GRANT + GRANT, True)
    allowed = {(PATH, after[0].fingerprint)}
    assert len(list(_introduced(after, baseline, PATH, allowed))) == 1
