import ast
import pytest
from skylos.rules.secrets import scan_ctx

ELLIPSIS = "…"


def _ctx_from_source(src, rel="app.py", with_ast=False):
    if with_ast:
        tree = ast.parse(src)
    else:
        tree = None

    lines = src.splitlines(True)

    context = {"relpath": rel, "lines": lines, "tree": tree}

    return context


def test_github_and_generic_both_fire_on_token_assignment():
    src = 'GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n'

    findings = list(scan_ctx(_ctx_from_source(src)))

    providers = set()
    for finding in findings:
        provider_name = finding["provider"]
        providers.add(provider_name)

    assert "github" in providers
    assert "generic" in providers

    github_previews = []
    for finding in findings:
        if finding["provider"] == "github":
            preview = finding["preview"]
            github_previews.append(preview)

    assert len(github_previews) > 0
    first_preview = github_previews[0]
    assert first_preview.startswith("ghp_")
    assert ELLIPSIS in first_preview


@pytest.mark.parametrize(
    "line,provider",
    [
        ('GITLAB_PAT = "glpat-A1b2C3d4E5f6G7h8I9j0"\n', "gitlab"),
        ('SLACK_BOT = "xoxb-1234567890ABCDEF12"\n', "slack"),
        ('STRIPE = "sk_live_a1B2c3D4e5F6g7H8"\n', "stripe"),
        ('GOOGLE = "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\n', "google_api_key"),
        ('SENDGRID = "SG.AAAAABBBBBCCCCCC.DDDDDEEEEEFFFFFFF"\n', "sendgrid"),
        ('TWILIO = "SK0123456789abcdef0123456789abcdef"\n', "twilio"),
        ('PK = "-----BEGIN RSA PRIVATE KEY-----"\n', "private_key_block"),
        ('AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"\n', "aws_access_key_id"),
    ],
)
def test_provider_patterns(line, provider):
    findings = list(scan_ctx(_ctx_from_source(line)))
    assert any(f["provider"] == provider for f in findings)


def test_aws_secret_access_key_special_case():
    src = 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
    findings = list(scan_ctx(_ctx_from_source(src)))
    hit = None
    for finding in findings:
        if finding["provider"] == "aws_secret_access_key":
            hit = finding
            break

    assert hit is not None
    assert "entropy" in hit and isinstance(hit["entropy"], float)
    assert ELLIPSIS in hit["preview"]


def test_ignore_directive_suppresses_matches():
    src = 'GITHUB_TOKEN = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # skylos: ignore[SKY-S101]\n'
    findings = list(scan_ctx(_ctx_from_source(src)))
    assert findings == []


def test_allowlist_patterns_suppresses_line():
    src = 'TWILIO = "SKabcdefabcdefabcdefabcdefabcdefabcd"\n'
    allow = [r"TWILIO\s*="]
    findings = list(scan_ctx(_ctx_from_source(src), allowlist_patterns=allow))
    assert findings == []


def test_scan_comments_toggle():
    line = "# cred: xoxb-1234567890ABCDEF12 appears only in comment\n"
    findings_default = list(scan_ctx(_ctx_from_source(line)))

    found_slack = False
    for finding in findings_default:
        if finding["provider"] == "slack":
            found_slack = True
            break

    assert found_slack

    findings_off = list(scan_ctx(_ctx_from_source(line), scan_comments=False))
    assert findings_off == []


def test_scan_docstrings_toggle_with_ast():
    src = '''"""
module docstring with a GITHUB token: ghp_1234567890abcdef1234567890abcdef1234
"""
def f():
    """Function docstring with AWS AKIAABCDEFGHIJKLMNOP key."""
    return 1
'''
    f1 = list(scan_ctx(_ctx_from_source(src, with_ast=True)))
    providers_in_f1 = set()
    for finding in f1:
        provider_name = finding["provider"]
        providers_in_f1.add(provider_name)
    assert "github" in providers_in_f1 or "aws_access_key_id" in providers_in_f1

    f2 = list(scan_ctx(_ctx_from_source(src, with_ast=True), scan_docstrings=False))
    assert f2 == []


def test_suffix_and_path_filters():
    ctx_txt = _ctx_from_source(
        'X="ghp_1234567890abcdef1234567890abcdef1234"\n', rel="notes.txt"
    )
    assert list(scan_ctx(ctx_txt)) == []

    ctx_vendor = _ctx_from_source('X="AKIAABCDEFGHIJKLMNOP"\n', rel="vendor/app.py")
    out = list(scan_ctx(ctx_vendor, ignore_path_substrings=["vendor"]))
    assert out == []


def test_masking_behavior_short_and_long():
    short = 'X = "ABCDEFGH"\n'
    long = 'token = "ABCDEFGHIJKLMNOPKLMN"\n'

    short_findings = scan_ctx(_ctx_from_source(short))

    f_short = None
    for finding in short_findings:
        if finding["provider"] == "generic":
            f_short = finding
            break

    long_findings = scan_ctx(_ctx_from_source(long))

    f_long = None
    for finding in long_findings:
        if finding["provider"] == "generic":
            f_long = finding
            break

    assert f_short is None

    long_preview = f_long["preview"]
    starts_with_abcd = long_preview.startswith("ABCD")
    ends_with_klmn = long_preview.endswith("KLMN")
    contains_ellipsis = ELLIPSIS in long_preview

    assert starts_with_abcd and ends_with_klmn and contains_ellipsis


def test_safe_hints_suppress_detection():
    safe_line = 'EXAMPLE_TOKEN = "sk_test_this_is_example_value_not_real_123456"\n'
    out = list(scan_ctx(_ctx_from_source(safe_line)))
    assert out == []


def test_generic_is_suppressed_in_test_paths():
    src = 'X = "o2uV7Ew1kZ9Q3nR8sT5yU6pX4cJ2mL7a"\n'
    findings = list(scan_ctx(_ctx_from_source(src, rel="tests/unit/test_secrets.py")))

    generic_findings = []
    for f in findings:
        if f["provider"] == "generic":
            generic_findings.append(f)

    assert len(generic_findings) == 0


def test_normal_strings_ignored():
    src = 'X = "config_path"\n'
    ctx = _ctx_from_source(src)
    findings = list(scan_ctx(ctx))

    generic_findings = []
    for f in findings:
        if f["provider"] == "generic":
            generic_findings.append(f)

    assert len(generic_findings) == 0
