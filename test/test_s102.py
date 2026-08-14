"""Tests for SKY-S102: Client-Side Secret Exposure."""

import json

import pytest

from skylos.analyzer import analyze
import skylos.rules.secrets as secrets
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
    assert all(f["severity"] == "CRITICAL" for f in findings)
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


def test_s102_process_env_secret_key_in_explicit_client_module():
    ctx = _make_ctx(
        "src/account.client.ts",
        ["const key = process.env.SECRET_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert s102
    assert "process.env.SECRET_KEY" in s102[0]["message"]
    assert {f["severity"] for f in s102} == {"HIGH"}


def test_s102_process_env_api_key():
    ctx = _make_ctx(
        "src/client.js",
        ["const k = process.env.API_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert s102


def test_server_component_process_env_database_password_not_flagged():
    ctx = _make_ctx(
        "app/db.tsx",
        ["const db = process.env.DATABASE_PASSWORD;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


def test_s102_process_env_auth_token():
    ctx = _make_ctx(
        "components/fetch.jsx",
        [
            '"use client";\n',
            "fetch(url, { headers: { Authorization: process.env.AUTH_TOKEN } });\n",
        ],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert s102
    assert {f["severity"] for f in s102} == {"HIGH"}


def test_ambiguous_server_utility_process_env_private_key_not_flagged():
    ctx = _make_ctx(
        "utils/sign.ts",
        ["const pk = process.env.PRIVATE_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


def test_next_app_api_route_server_env_secrets_are_not_client_exposure():
    ctx = _make_ctx(
        "app/api/stripe/webhook/route.ts",
        [
            "const stripeKey = process.env.STRIPE_API_KEY;\n",
            "const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)


def test_next_pages_api_route_server_env_secret_is_not_client_exposure():
    ctx = _make_ctx(
        "pages/api/github/webhook.ts",
        ["const secret = process.env.GITHUB_WEBHOOK_SECRET;\n"],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)


def test_use_client_hardcoded_secret_preserves_critical_severity_as_s102():
    ctx = _make_ctx(
        "components/payment.tsx",
        [
            '"use client";\n',
            'const key = "sk_' + 'live_abcdef1234567890";\n',
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)
    exposed = [finding for finding in findings if finding["rule_id"] == "SKY-S102"]

    assert exposed
    assert {finding["severity"] for finding in exposed} == {"CRITICAL"}


def test_public_html_hardcoded_secret_is_critical_s102():
    ctx = _make_ctx(
        "public/index.html",
        ['<script>const key = "sk_' + 'live_abcdef1234567890";</script>\n'],
    )

    findings = scan_ctx(ctx, ignore_tests=False)
    exposed = [finding for finding in findings if finding["rule_id"] == "SKY-S102"]

    assert exposed
    assert {finding["severity"] for finding in exposed} == {"CRITICAL"}


def test_client_mjs_process_env_secret_is_high_s102():
    ctx = _make_ctx(
        "public/assets/config.mjs",
        ["export const secret = process.env.PAYMENT_SECRET_KEY;\n"],
    )

    findings = scan_ctx(ctx, ignore_tests=False)
    exposed = [finding for finding in findings if finding["rule_id"] == "SKY-S102"]

    assert exposed
    assert {finding["severity"] for finding in exposed} == {"HIGH"}


def test_next_generated_server_bundle_is_not_client_exposure():
    ctx = _make_ctx(
        ".next/server/app/api/stripe/webhook/route.js",
        ["const secret = process.env.STRIPE_WEBHOOK_SECRET;\n"],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)


def test_build_client_bundle_process_env_secret_is_high_s102():
    ctx = _make_ctx(
        "build/client/chunks/config.js",
        ["const secret = process.env.PAYMENT_SECRET_KEY;\n"],
    )

    findings = scan_ctx(ctx, ignore_tests=False)
    exposed = [finding for finding in findings if finding["rule_id"] == "SKY-S102"]

    assert exposed
    assert {finding["severity"] for finding in exposed} == {"HIGH"}


def test_use_client_after_another_directive_is_still_client_context():
    ctx = _make_ctx(
        "components/account.tsx",
        [
            '"use strict";\n',
            '"use client";\n',
            "const secret = process.env.ACCOUNT_SECRET;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" in _rule_ids(findings)


def test_use_client_with_trailing_comment_is_client_context():
    ctx = _make_ctx(
        "components/account.tsx",
        [
            '"use client"; // Next.js client boundary\n',
            "const secret = process.env.ACCOUNT_SECRET;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" in _rule_ids(findings)


def test_use_client_after_long_comment_prologue_is_client_context():
    ctx = _make_ctx(
        "components/account.tsx",
        [
            *("// generated header\n" for _ in range(65)),
            '"use client";\n',
            "const secret = process.env.ACCOUNT_SECRET;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" in _rule_ids(findings)


def test_client_env_binding_budget_does_not_fail_open(monkeypatch):
    monkeypatch.setattr(secrets, "_MAX_CLIENT_ENV_BINDINGS", 2)
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "const first = 1;\n",
            "const second = 2;\n",
            "const third = 3;\n",
            "const exposed = process.env.ACCOUNT_SECRET;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" in _rule_ids(findings)


@pytest.mark.parametrize(
    ("limit_name", "limit"),
    [
        ("_MAX_CLIENT_ENV_BINDINGS", 2),
        ("_MAX_CLIENT_ENV_NODES", 4),
        ("_MAX_CLIENT_ENV_PARSE_BYTES", 32),
    ],
    ids=["binding-budget", "node-budget", "parse-budget"],
)
def test_client_env_alias_budget_overflow_emits_incomplete(
    monkeypatch, limit_name, limit
):
    monkeypatch.setattr(secrets, limit_name, limit)
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "const first = 1;\n",
            "const second = 2;\n",
            "const runtimeEnv = process.env;\n",
            "const exposed = runtimeEnv.ACCOUNT_SECRET;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)
    incomplete = [
        finding
        for finding in findings
        if finding["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    ]

    assert len(incomplete) == 1
    assert incomplete[0]["metadata"]["analysis_complete"] is False


def test_client_env_alias_budget_safe_lookalike_stays_quiet(monkeypatch):
    monkeypatch.setattr(secrets, "_MAX_CLIENT_ENV_BINDINGS", 1)
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "const first = 1;\n",
            "const runtimeEnv = browserRuntime;\n",
            "const exposed = runtimeEnv.ACCOUNT_SECRET;\n",
        ],
    )

    assert scan_ctx(ctx, ignore_tests=False) == []


@pytest.mark.parametrize(
    "source",
    [
        "const runtimeEnv = process.env as NodeJS.ProcessEnv;\n"
        "const exposed = runtimeEnv.ACCOUNT_SECRET;\n",
        "const { ACCOUNT_SECRET } = process.env;\n",
        "const runtimeEnv = process.env;\nconst { ACCOUNT_SECRET } = runtimeEnv;\n",
    ],
    ids=["typed-alias", "direct-destructure", "alias-destructure"],
)
def test_client_env_parse_budget_fallback_covers_alias_shapes(monkeypatch, source):
    monkeypatch.setattr(secrets, "_MAX_CLIENT_ENV_PARSE_BYTES", 16)
    ctx = _make_ctx("src/account.client.ts", source.splitlines(True))

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-ANALYSIS-INCOMPLETE" in _rule_ids(findings)


def test_client_env_parse_budget_emits_incomplete_candidate(monkeypatch):
    monkeypatch.setattr(secrets, "_MAX_CLIENT_ENV_PARSE_BYTES", 32)
    ctx = _make_ctx(
        "src/account.client.ts",
        ["const exposed = process.env.ACCOUNT_SECRET;\n"],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    incomplete = [
        finding
        for finding in findings
        if finding["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    ]
    assert len(incomplete) == 1
    assert incomplete[0]["metadata"]["analysis_complete"] is False


def test_truncated_use_client_ownership_emits_incomplete(monkeypatch):
    monkeypatch.setattr(secrets, "_MAX_CLIENT_ENV_PARSE_BYTES", 32)
    ctx = _make_ctx(
        "components/account.tsx",
        [
            "//" + ("generated" * 20) + "\n",
            '"use client";\n',
            "const exposed = process.env.ACCOUNT_SECRET;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)
    incomplete = [
        finding
        for finding in findings
        if finding["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    ]

    assert len(incomplete) == 1
    assert "ownership" in incomplete[0]["message"]
    assert incomplete[0]["metadata"]["analysis_complete"] is False


def test_truncated_use_client_ownership_without_sensitive_candidate_is_quiet(
    monkeypatch,
):
    monkeypatch.setattr(secrets, "_MAX_CLIENT_ENV_PARSE_BYTES", 32)
    ctx = _make_ctx(
        "components/account.tsx",
        [
            "//" + ("generated" * 20) + "\n",
            '"use client";\n',
            'const theme = "dark";\n',
        ],
    )

    assert scan_ctx(ctx, ignore_tests=False) == []


def test_use_client_comment_decoy_does_not_create_client_context():
    ctx = _make_ctx(
        "lib/server-config.ts",
        [
            '// "use client";\n',
            "const secret = process.env.ACCOUNT_SECRET;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)


def test_next_route_under_client_named_package_remains_server_only():
    ctx = _make_ctx(
        "packages/client/src/app/webhooks/stripe/route.ts",
        ["const secret = process.env.STRIPE_WEBHOOK_SECRET;\n"],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)


# --- Public env prefixes ---


def test_next_public_not_flagged():
    ctx = _make_ctx(
        "src/client/config.ts",
        ["const url = process.env.NEXT_PUBLIC_API_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


def test_nuxt_public_not_flagged():
    ctx = _make_ctx(
        "src/client/config.ts",
        ["const url = process.env.NUXT_PUBLIC_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    s102 = [f for f in findings if f["rule_id"] == "SKY-S102"]
    assert not s102


def test_generic_public_prefix_not_flagged_in_client_context():
    ctx = _make_ctx(
        "src/client/config.ts",
        ["const url = process.env.PUBLIC_API_KEY;\n"],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    assert "SKY-S102" not in _rule_ids(findings)


@pytest.mark.parametrize(
    "env_name",
    [
        "NEXT_PUBLIC_SECRET_KEY",
        "REACT_APP_PRIVATE_KEY",
        "VITE_AUTH_TOKEN",
        "NUXT_PUBLIC_DATABASE_URL",
        "EXPO_PUBLIC_PASSWORD",
        "PUBLIC_CREDENTIALS",
    ],
)
def test_sensitive_semantic_name_with_public_prefix_is_flagged(env_name):
    ctx = _make_ctx(
        "src/client/config.ts",
        [f"const exposed = process.env.{env_name};\n"],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert len(exposed) == 1
    assert exposed[0]["severity"] == "HIGH"
    assert "public env var" in exposed[0]["message"].lower()


def test_import_meta_and_bracket_env_access_are_detected():
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "const first = import.meta.env.PAYMENT_SECRET;\n",
            'const second = process.env["ACCOUNT_TOKEN"];\n',
        ],
    )
    findings = scan_ctx(ctx, ignore_tests=False)
    exposed = [finding for finding in findings if finding["rule_id"] == "SKY-S102"]
    assert {finding["env_name"] for finding in exposed} == {
        "PAYMENT_SECRET",
        "ACCOUNT_TOKEN",
    }


@pytest.mark.parametrize(
    ("reference", "env_name"),
    [
        ('process["env"].ACCOUNT_SECRET', "ACCOUNT_SECRET"),
        ('process["env"]["ACCOUNT_TOKEN"]', "ACCOUNT_TOKEN"),
        ('import.meta["env"].PAYMENT_SECRET', "PAYMENT_SECRET"),
        ('import.meta["env"]["PRIVATE_KEY"]', "PRIVATE_KEY"),
    ],
    ids=[
        "process-dot-property",
        "process-bracket-property",
        "import-meta-dot-property",
        "import-meta-bracket-property",
    ],
)
def test_bracketed_env_objects_are_detected(reference, env_name):
    ctx = _make_ctx(
        "src/account.client.ts",
        [f"const exposed = {reference};\n"],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert {finding["env_name"] for finding in exposed} == {env_name}


@pytest.mark.parametrize(
    "env_object",
    ['process["env"]', 'import.meta["env"]'],
    ids=["process", "import-meta"],
)
def test_bracketed_env_object_aliases_are_detected(env_object):
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            f"const runtimeEnv = {env_object};\n",
            "const appEnv = runtimeEnv;\n",
            "const exposed = appEnv.ACCOUNT_SECRET;\n",
        ],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert {finding["env_name"] for finding in exposed} == {"ACCOUNT_SECRET"}


def test_shadowed_process_with_bracketed_env_is_not_node_process():
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "function render(process: Runtime) {\n",
            '  return process["env"].ACCOUNT_SECRET;\n',
            "}\n",
        ],
    )

    assert "SKY-S102" not in _rule_ids(scan_ctx(ctx, ignore_tests=False))


def test_comments_strings_regexes_jsx_text_and_template_text_are_not_env_accesses():
    ctx = _make_ctx(
        "src/account.client.tsx",
        [
            "// process.env.SECRET_KEY\n",
            'const docs = "process.env.AUTH_TOKEN";\n',
            "const pattern = /process.env.PRIVATE_KEY/;\n",
            "const template = `process.env.DATABASE_PASSWORD`;\n",
            "const view = <pre>process.env.ACCOUNT_SECRET</pre>;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)


def test_env_access_inside_template_substitution_is_detected():
    ctx = _make_ctx(
        "src/account.client.ts",
        ["const value = `prefix-${process.env.ACCOUNT_SECRET}`;\n"],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert {finding["env_name"] for finding in exposed} == {"ACCOUNT_SECRET"}


def test_destructured_env_properties_are_detected():
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "const { SECRET_KEY, databasePassword: password, "
            '["AUTH_TOKEN"]: token } = process.env;\n'
        ],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert {finding["env_name"] for finding in exposed} == {
        "SECRET_KEY",
        "databasePassword",
        "AUTH_TOKEN",
    }


def test_destructured_env_property_with_default_is_detected():
    ctx = _make_ctx(
        "src/account.client.ts",
        ['const { SECRET_KEY = "fallback" } = process.env;\n'],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert {finding["env_name"] for finding in exposed} == {"SECRET_KEY"}


def test_bounded_const_env_alias_chain_is_detected():
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "const runtimeEnv = process.env;\n",
            "const appEnv = runtimeEnv;\n",
            "const accountEnv = appEnv;\n",
            "const token = accountEnv.accountToken;\n",
        ],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert {finding["env_name"] for finding in exposed} == {"accountToken"}


def test_destructuring_from_const_env_alias_is_detected():
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "const runtimeEnv = process.env;\n",
            "const { privateKey } = runtimeEnv;\n",
        ],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert {finding["env_name"] for finding in exposed} == {"privateKey"}


def test_env_alias_shadowed_by_parameter_is_not_treated_as_process_env():
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "const runtimeEnv = process.env;\n",
            "function render(runtimeEnv: Record<string, string>) {\n",
            "  return runtimeEnv.SECRET_KEY;\n",
            "}\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)


def test_shadowed_process_binding_is_not_treated_as_node_process():
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "function render(process: Runtime) {\n",
            "  return process.env.SECRET_KEY;\n",
            "}\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)


def test_function_scoped_var_process_binding_is_not_treated_as_node_process():
    ctx = _make_ctx(
        "src/account.client.ts",
        [
            "function render() {\n",
            "  if (usePolyfill) { var process = browserRuntime; }\n",
            "  return process.env.SECRET_KEY;\n",
            "}\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)


@pytest.mark.parametrize(
    "reference,env_name",
    [
        ("process.env.secret_key", "secret_key"),
        ("process.env.databasePassword", "databasePassword"),
        ('process.env["AuthToken"]', "AuthToken"),
    ],
)
def test_lowercase_and_camel_case_sensitive_env_names_are_detected(reference, env_name):
    ctx = _make_ctx(
        "src/account.client.ts",
        [f"const exposed = {reference};\n"],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert {finding["env_name"] for finding in exposed} == {env_name}


@pytest.mark.parametrize("relpath", ["build/server/config.js", "dist/server/config.js"])
def test_generated_server_bundles_are_not_client_exposure(relpath):
    ctx = _make_ctx(
        relpath,
        [
            'const hardcoded = "sk_' + 'live_abcdef1234567890";\n',
            "const runtime = process.env.ACCOUNT_SECRET;\n",
        ],
    )

    findings = scan_ctx(ctx, ignore_tests=False)

    assert "SKY-S102" not in _rule_ids(findings)
    assert "SKY-S101" in _rule_ids(findings)


def test_explicit_public_path_wins_over_server_filename_convention():
    ctx = _make_ctx(
        "public/config.server.js",
        [
            'const hardcoded = "sk_' + 'live_abcdef1234567890";\n',
            "const runtime = process.env.ACCOUNT_SECRET;\n",
        ],
    )

    exposed = [
        finding
        for finding in scan_ctx(ctx, ignore_tests=False)
        if finding["rule_id"] == "SKY-S102"
    ]

    assert {finding["severity"] for finding in exposed} == {"CRITICAL", "HIGH"}


@pytest.mark.parametrize(
    ("relpath", "source"),
    [
        (
            "public/config.css",
            'body { --token: "sk_' + 'live_abcdef1234567890"; }\n',
        ),
        (
            "public/app.js.map",
            '{"sourcesContent":["const token = \\"sk_'
            + 'live_abcdef1234567890\\";"]}\n',
        ),
    ],
)
def test_public_css_and_source_maps_are_scanned_for_hardcoded_secrets(relpath, source):
    findings = scan_ctx(_make_ctx(relpath, [source]), ignore_tests=False)

    exposed = [finding for finding in findings if finding["rule_id"] == "SKY-S102"]

    assert exposed
    assert {finding["severity"] for finding in exposed} == {"CRITICAL"}


@pytest.mark.parametrize(
    ("relpath", "source"),
    [
        (
            "public/styles.css",
            '.hero { background: url("/assets/Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1.css"); }\n',
        ),
        (
            "public/app.js.map",
            '{"file":"Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1.js",'
            '"names":["Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9"]}\n',
        ),
    ],
)
def test_public_generated_asset_hashes_are_not_client_secrets(relpath, source):
    findings = scan_ctx(_make_ctx(relpath, [source]), ignore_tests=False)

    assert not {
        finding["rule_id"]
        for finding in findings
        if finding["rule_id"] in {"SKY-S101", "SKY-S102"}
    }


def test_all_enabled_scan_has_one_s102_owner(tmp_path):
    source_file = tmp_path / "account.client.ts"
    source_file.write_text(
        "const exposed = process.env.ACCOUNT_SECRET;\n",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_secrets=True,
            enable_quality=False,
            enable_dependency_hallucinations=False,
        )
    )

    danger_s102 = [
        finding
        for finding in result.get("danger", [])
        if finding.get("rule_id") == "SKY-S102"
    ]
    secret_s102 = [
        finding
        for finding in result.get("secrets", [])
        if finding.get("rule_id") == "SKY-S102"
    ]
    assert danger_s102 == []
    assert len(secret_s102) == 1


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
