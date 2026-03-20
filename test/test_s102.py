"""Tests for SKY-S102: Client-Side Secret Exposure."""

from skylos.rules.secrets import scan_ctx


def _make_ctx(relpath, lines, tree=None):
    return {"relpath": relpath, "lines": lines, "tree": tree}


def _rule_ids(findings):
    return [f["rule_id"] for f in findings]


# --- Client-path elevation tests ---


def test_s102_secret_in_static_dir():
    """S101 findings in static/ should be elevated to S102."""
    ctx = _make_ctx(
        "static/config.js",
        ['const key = "sk_live_abcdef1234567890";\n'],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    assert findings
    assert all(f["rule_id"] == "SKY-S102" for f in findings)
    assert "client-accessible path" in findings[0]["message"].lower()


def test_s102_secret_in_public_dir():
    ctx = _make_ctx(
        "public/env.js",
        ['const t = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";\n'],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    assert findings
    assert all(f["rule_id"] == "SKY-S102" for f in findings)


def test_s102_secret_in_next_dir():
    ctx = _make_ctx(
        ".next/static/chunks/config.js",
        ['const k = "sk_live_abcdef1234567890";\n'],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    assert findings
    assert all(f["rule_id"] == "SKY-S102" for f in findings)


def test_s102_secret_in_dist_dir():
    ctx = _make_ctx(
        "dist/bundle.js",
        ['const k = "glpat-abcdefghij1234567890";\n'],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    assert findings
    assert all(f["rule_id"] == "SKY-S102" for f in findings)


# --- Normal path stays S101 ---


def test_s101_stays_in_normal_path():
    """Secrets in non-client paths should remain S101."""
    ctx = _make_ctx(
        "src/config.py",
        ['API_KEY = "sk_live_abcdef1234567890"\n'],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    assert findings
    assert all(f["rule_id"] == "SKY-S101" for f in findings)


def test_s101_stays_in_lib_path():
    ctx = _make_ctx(
        "lib/settings.py",
        ['token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"\n'],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    assert findings
    assert all(f["rule_id"] == "SKY-S101" for f in findings)


# --- process.env detection in JS/TS ---


def test_s102_process_env_secret_key():
    ctx = _make_ctx(
        "src/api.ts",
        ["const key = process.env.SECRET_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert s102
    assert "process.env.SECRET_KEY" in s102[0]["message"]


def test_s102_process_env_api_key():
    ctx = _make_ctx(
        "src/client.js",
        ["const k = process.env.API_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert s102


def test_s102_process_env_database_password():
    ctx = _make_ctx(
        "app/db.tsx",
        ["const db = process.env.DATABASE_PASSWORD;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert s102


def test_s102_process_env_auth_token():
    ctx = _make_ctx(
        "components/fetch.jsx",
        ["fetch(url, { headers: { Authorization: process.env.AUTH_TOKEN } });\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert s102


def test_s102_process_env_private_key():
    ctx = _make_ctx(
        "utils/sign.ts",
        ["const pk = process.env.PRIVATE_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert s102


# --- NEXT_PUBLIC_ and other public prefixes should NOT be flagged ---


def test_next_public_not_flagged():
    ctx = _make_ctx(
        "src/config.ts",
        ["const url = process.env.NEXT_PUBLIC_API_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


def test_react_app_not_flagged():
    ctx = _make_ctx(
        "src/config.js",
        ["const url = process.env.REACT_APP_SECRET_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


def test_vite_not_flagged():
    ctx = _make_ctx(
        "src/config.ts",
        ["const url = process.env.VITE_AUTH_TOKEN;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


def test_nuxt_public_not_flagged():
    ctx = _make_ctx(
        "src/config.ts",
        ["const url = process.env.NUXT_PUBLIC_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


def test_expo_public_not_flagged():
    ctx = _make_ctx(
        "src/config.ts",
        ["const url = process.env.EXPO_PUBLIC_TOKEN;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


# --- process.env in non-JS files should not trigger S102 ---


def test_process_env_in_python_not_flagged():
    ctx = _make_ctx(
        "src/config.py",
        ["# process.env.SECRET_KEY  (comment in Python)\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


# --- Combined: client path + process.env ---


def test_s102_both_client_path_and_process_env():
    """File in static/ with process.env should get S102 for both reasons."""
    ctx = _make_ctx(
        "static/app.js",
        [
            'const stripe = "sk_live_abcdef1234567890";\n',
            "const secret = process.env.SECRET_KEY;\n",
        ],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    assert findings
    assert all(f["rule_id"] == "SKY-S102" for f in findings)
