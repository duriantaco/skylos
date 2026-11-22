"""TS/JS test code and translation catalogs, each next to the shape that must
stay reported.

Test code follows the policy Python test code has: only provider-shaped
secrets are reported (SKY-S101), and a hazard that exists only in a deployed
app (a token in a user's web storage, SKY-D270; a hard-coded local URL,
SKY-D248) is not reported in a spec, as TLS verification off is not in a
Python test. Other security rules still apply in tests.

SKY-D260: a ZWNJ inside a Persian word, a direction mark beside Arabic
letters, a word break pasted with Tamil or Portuguese text in a catalog and a
Greek letter typed in Greek text are spelling. Embedding and override
controls, mixed invisible runs and joiners inside Latin words are not.
"""

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.core.test_paths import is_test_code_path
from skylos.security.injection_scanner import scan_file
from skylos.visitors.languages.typescript import scan_typescript_file

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
GITHUB_TOKEN = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Yz"
ZWSP, ZWNJ, LRM, RLO = "\u200b", "\u200c", "\u200e", "\u202e"


def _rules(tmp_path, name: str, code: str) -> list[tuple[str, int]]:
    write_text_no_symlink(tmp_path / "package.json", "{}\n", encoding="utf-8")
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, code, encoding="utf-8")
    return sorted(
        (finding["rule_id"], finding["line"])
        for finding in scan_typescript_file(str(path))[7]
    )


# --- Test code --------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("src/app/app.guard.spec.ts", True),
        ("src/app/login/LoginPage.test.tsx", True),
        ("cypress/e2e/login.cy.ts", True),
        ("test/cypress/e2e/forgedJwt.spec.ts", True),
        ("e2e/checkout.ts", True),
        ("src/__tests__/auth.ts", True),
        ("src/app/app.guard.ts", False),
        ("app/test/page.tsx", False),
        ("pages/login.test.tsx", False),
    ],
)
def test_js_test_code_paths(tmp_path, name, expected):
    assert is_test_code_path(name, tmp_path) is expected


STORAGE = "localStorage.setItem('token', 'eyJhbGciOi.fixture')\n"


def test_web_storage_in_a_spec_is_not_reported(tmp_path):
    assert ("SKY-D270", 1) not in _rules(tmp_path, "src/app/app.guard.spec.ts", STORAGE)
    assert ("SKY-D270", 1) not in _rules(tmp_path, "cypress/e2e/login.cy.ts", STORAGE)


def test_web_storage_in_app_code_is_still_reported(tmp_path):
    assert ("SKY-D270", 1) in _rules(tmp_path, "src/app/app.guard.ts", STORAGE)


def test_fixture_tokens_in_a_spec_are_not_secrets(tmp_path):
    code = f"const token = '{JWT}'\nconst signature = 'Xk9mPq2Lr7Tn4Vb8Wc1Z3Yh5Jd7Fg0Sa2Qe7Pu'\n"
    rules = _rules(tmp_path, "src/app/last-login-ip.component.spec.ts", code)
    assert not [rule for rule in rules if rule[0] == "SKY-S101"]


def test_a_provider_token_in_a_spec_is_still_reported(tmp_path):
    rules = _rules(
        tmp_path, "src/app/deploy.spec.ts", f"const pat = '{GITHUB_TOKEN}'\n"
    )
    assert ("SKY-S101", 1) in rules


def test_the_same_fixture_token_in_app_code_is_reported(tmp_path):
    assert ("SKY-S101", 1) in _rules(
        tmp_path, "src/app/auth.ts", f"const token = '{JWT}'\n"
    )


def test_test_runner_config_may_point_at_localhost(tmp_path):
    code = "export default { e2e: { baseUrl: 'http://localhost:3000/app' } }\n"
    assert ("SKY-D248", 1) not in _rules(tmp_path, "cypress.config.ts", code)
    assert ("SKY-D248", 1) in _rules(tmp_path, "src/config.ts", code)


def test_other_security_rules_still_apply_in_tests(tmp_path):
    code = "export function run(input: string) {\n  return eval(input)\n}\n"
    assert ("SKY-D201", 2) in _rules(tmp_path, "test/e2e/contact.spec.ts", code)


# --- SKY-D260 in translation catalogs ----------------------------------------


def _d260(tmp_path, name: str, text: str) -> list[tuple[int, str]]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return sorted(
        (finding["line"], finding["type"])
        for finding in scan_file(path, scan_path=name)
        if finding["rule_id"] == "SKY-D260"
    )


@pytest.mark.parametrize(
    "name,value",
    [
        # ZWNJ between Persian letters, also beside an LRM and at a word end.
        ("i18n/fa_IR.json", f"تعداد تراکنش{LRM}{ZWNJ}ها، پیش{ZWNJ}فرض را عوض کنید."),
        ("i18n/fa_IR.json", f"گذرواژه{ZWNJ}"),
        # An LRM beside Persian letters orders the words around it.
        ("i18n/fa_IR.json", f"ارز دیجیتال{LRM} را انتخاب کنید"),
        # Word breaks pasted with the translation.
        ("intl/messages/pt-PT.json", f"A IA {ZWSP * 4}não mostra a palavra-passe."),
        ("intl/messages/ta-IN.json", f"கடவுச்சொல், {ZWSP}உங்கள் கணக்கு"),
        ("intl/messages/km-KH.json", f"{ZWSP}ដំណើរការ"),
    ],
)
def test_script_formatting_in_catalogs_is_not_reported(tmp_path, name, value):
    assert _d260(tmp_path, name, f'{{\n  "LABEL": "{value}"\n}}\n') == []


def test_a_native_letter_in_a_catalog_line_of_that_script_is_not_a_disguise(tmp_path):
    value = "Παρακαλώ καταχωρήστε ένα αναγνωριστικό παραγγελίας (Οrder ID)."
    assert _d260(tmp_path, "i18n/el_GR.json", f'{{\n  "ORDER": "{value}"\n}}\n') == []


@pytest.mark.parametrize(
    "name,value,kind",
    [
        ("i18n/fa_IR.json", f"user{RLO}nimda", "hidden_char"),
        ("i18n/pt_PT.json", f"A IA {ZWSP}{ZWNJ}{ZWSP}{ZWNJ}não", "hidden_char"),
        ("i18n/en.json", f"Run the in{ZWNJ}staller first.", "hidden_char"),
        ("i18n/en.json", f"Sign in as ad{LRM}min first.", "hidden_char"),
        (
            "config/settings.json",
            f"A IA {ZWSP}não mostra a palavra-passe.",
            "hidden_char",
        ),
        ("i18n/en.json", "Please confirm your Οrder now.", "mixed_script"),
    ],
)
def test_hidden_or_disguised_text_stays_reported(tmp_path, name, value, kind):
    found = _d260(tmp_path, name, f'{{\n  "LABEL": "{value}"\n}}\n')
    assert (2, kind) in found


def test_only_the_misplaced_joiner_on_a_line_is_reported(tmp_path):
    value = f"فایل{ZWNJ}ها را بررسی می{ZWNJ}کند و in{ZWNJ}staller را اجرا کنید."
    found = _d260(tmp_path, "docs/README.fa.md", f"# راهنما\n{value}\n")
    assert found == [(2, "hidden_char")]


@pytest.mark.parametrize(
    "line",
    [
        f'LABEL = "ارز دیجیتال{LRM} را انتخاب کنید"\n',
        f'LABEL = "گذرواژه{ZWNJ}"\n',
        f'LABEL = "تراکنش{LRM}{ZWNJ}ها"\n',
    ],
)
def test_source_code_keeps_the_strict_rules(tmp_path, line):
    """In Python source an invisible character can sit in a string the
    program compares; only a joiner between two letters is spelling."""
    assert _d260(tmp_path, "labels.py", line)


def test_a_joiner_between_persian_letters_in_source_is_spelling(tmp_path):
    assert _d260(tmp_path, "labels.py", f'LABEL = "پیش{ZWNJ}فرض"\n') == []
