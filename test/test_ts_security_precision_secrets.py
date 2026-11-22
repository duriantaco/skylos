"""SKY-S101/S102: values that are not credentials by construction, each next
to a lookalike that must stay reported.

Translation catalogs hold reader text in every script (labels without a full
stop, ``{{placeholders}}``, Myanmar or Japanese sentences); character
alphabets, template expressions, cryptocurrency addresses, password hashes in
comments and policy or challenge names are public or structural. A random
token, a provider key or a weak password stays reported wherever it sits.
"""

import pytest

from skylos.core.message_catalogs import is_message_catalog_path
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules import secret_shapes
from skylos.rules.secrets import is_client_exposure_context, scan_ctx
from skylos.visitors.languages.typescript import scan_typescript_file

RANDOM = "q7Rk2Vx9Lm4Tz8Wc1Nb6-Yh3Jd5Fg0Sa2Qe7Pu"
BCRYPT = "$2a$10$8Zo/1e8KM8QzqOKqbDlYlONBOzukWXrM.IiyzqHRYDXqwB3gzDsba"
BITCOIN = "1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm"
DASH = "Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW"
SEGWIT = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
# The private key of the Bitcoin wiki's WIF example: Base58Check, 37 bytes.
WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"


def _secrets(src: str, rel: str) -> list[dict]:
    return [
        finding
        for finding in scan_ctx(
            {"relpath": rel, "lines": src.splitlines(True), "tree": None},
            ignore_tests=False,
        )
        if finding["rule_id"] in {"SKY-S101", "SKY-S102"}
    ]


def _ts_secrets(tmp_path, name: str, code: str) -> list[dict]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, code, encoding="utf-8")
    return [
        finding
        for finding in scan_typescript_file(str(path))[7]
        if finding["rule_id"] == "SKY-S101"
    ]


# --- Translation catalogs ---------------------------------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        ("frontend/src/assets/i18n/en.json", True),
        ("data/static/i18n/fa_IR.json", True),
        ("public/intl/messages/az-AZ.json", True),
        ("config/locales/devise.en.yml", True),
        ("public/locales/pt-BR/common.json", True),
        ("lib/l10n/app_en.arb", True),
        ("src/pt_BR.json", True),
        ("i18n/tlh_AA.json", True),
        ("src/en.json", False),
        ("locales/app.json", False),
        ("app/locales/secrets.json", False),
        ("data/static/users.yml", False),
        ("i18n/en.ts", False),
    ],
)
def test_catalog_paths(path, expected):
    assert is_message_catalog_path(path) is expected


@pytest.mark.parametrize(
    "entry",
    [
        '"INVALID_PASSWORD_LENGTH": "Password must be {{length}} characters long."',
        '"LABEL_CONFIRM_CURRENT_PASSWORD": "Confirm your current password"',
        '"LABEL_INITIAL_2FA_TOKEN": "Kimlik doğrulayıcınızdan ilk token"',
        '"LABEL_TWO_FACTOR_AUTH_TOKEN": "Κωδικός token εφαρμογής ελέγχου ταυτότητας (2FA token)"',
        '"MANDATORY_PASSWORD_REPEAT": "ကျေးဇူးပြု၍ လျှို့ဝှက်စကားလုံးအား ထပ်မံထည့်သွင်းပါ"',
        '"INVALID_PASSWORD_LENGTH": "パスワードは {{length}} 文字以上で入力してください"',
        '"INITIAL_TOKEN_TOOLTIP": "從authenticator輸入的驗證碼必須有6個字元"',
        '"LABEL_TWO_FACTOR_AUTH_TOKEN": "Zwöifaktorouthentisierigs-Token"',
        '"min-password-length": "Minimum length of {n} characters"',
        '"incorrect-username-password": "Incorrecte gebruikersnaam/wachtwoord."',
        '"api-key": "API-ключ"',
        '"api-key": "API-Schlüssel"',
        '"deleted-api-keys": "{count, plural, one {# API key} other {# API keys}} deleted"',
    ],
)
def test_catalog_text_under_credential_keys_is_not_a_secret(entry):
    assert _secrets("{\n  " + entry + "\n}\n", "public/locales/de/common.json") == []


@pytest.mark.parametrize(
    "entry",
    [
        f'"apiKey": "{RANDOM}"',
        '"stripe_key": "sk_live_' + "4eC39HqLyjWDarjtT1zdp7dc" + '"',
        '"password": "Sommer2024!Xy"',
        f'"RESET_TOKEN_HINT": "Use code {RANDOM} now, friends."',
    ],
)
def test_a_real_key_in_a_catalog_is_still_reported(entry):
    findings = _secrets("{\n  " + entry + "\n}\n", "src/assets/i18n/en.json")
    assert findings
    # A catalog under assets/ is served to browsers: the relabel stays.
    assert {finding["rule_id"] for finding in findings} == {"SKY-S102"}


def test_a_label_outside_a_catalog_can_still_be_a_passphrase():
    src = '{\n  "LABEL_CONFIRM_CURRENT_PASSWORD": "Confirm your current password"\n}\n'
    assert _secrets(src, "config/app.json")


def test_a_gettext_message_id_is_text_but_a_token_only_in_the_value_is_not():
    blob = "IvLuRfBJYlmStf9XfL6ckJFngyd9LfV1JaaN"
    message = f"Unlock the premium challenge <!--{blob}--> to access it."
    copied = f'{{\n  "{message}": "{message}"\n}}\n'
    assert _secrets(copied, "data/static/i18n/en.json") == []
    translated = (
        f'{{\n  "Unlock the premium challenge to access it.": "{message}"\n}}\n'
    )
    assert _secrets(translated, "data/static/i18n/de_DE.json")


@pytest.mark.parametrize(
    "value",
    [
        "Password must be {{length}} characters long.",
        "يجب أن تكون كلمة المرور {{length}} حرفاً.",
        "アカウントを保護しましょう。デフォルトのパスワードを変更してください。",
        "{count, plural, one {# token} other {# tokens}} were revoked.",
    ],
)
def test_sentences_with_placeholders_or_other_scripts_are_reader_text(value):
    assert secret_shapes.is_message_sentence(value)
    assert (
        _secrets(f'const messages = {{ passwordHint: "{value}" }}\n', "src/messages.ts")
        == []
    )


@pytest.mark.parametrize(
    "value",
    [
        "Winter2024! Is Coming, aB3dE5fG Friends.",
        "vivid quartz flamingo jumps over lazy brown hedgehog",
        f"Use code {RANDOM[:20]} now, friends.",
        "Confirm your current password",
    ],
)
def test_passphrases_and_codes_are_not_sentences(value):
    assert not secret_shapes.is_message_sentence(value)


@pytest.mark.parametrize(
    "path,client",
    [
        ("public/app.json", True),
        ("frontend/src/assets/i18n/en.json", True),
        ("src/statics/app.json", False),
        ("mypublic/app.json", False),
        ("src/public_api/app.json", False),
        ("layout/out.json", False),
    ],
)
def test_client_exposure_matches_whole_path_segments(path, client):
    assert is_client_exposure_context(path, []) is client


# --- High-entropy values that are not credentials ---------------------------


def test_an_ordered_alphabet_ending_in_zero_is_not_a_secret(tmp_path):
    code = f"const hashidsAlphabet = '{ALPHABET}'\n"
    assert _ts_secrets(tmp_path, "routes/restore.ts", code) == []
    assert _secrets(f'ALPHABET = "{ALPHABET}"\n', "alphabet.py") == []


def test_a_shuffled_or_random_value_is_still_a_secret(tmp_path):
    code = f"const signingKey = '{RANDOM.replace('-', '')}'\n"
    assert _ts_secrets(tmp_path, "routes/sign.ts", code)


def test_half_a_template_expression_is_not_a_secret():
    src = (
        "models.sequelize.query(`SELECT * FROM Users WHERE email = "
        "'${req.body.email}' AND password = '${security.hash(req.body.password "
        "|| '')}' AND deletedAt IS NULL`)\n"
    )
    assert _secrets(src, "routes/login.ts") == []


@pytest.mark.parametrize(
    "line",
    [
        'creation_token = "${var.project_name}-sqlite-data"\n',
        'ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n',
    ],
)
def test_terraform_interpolations_and_policy_names_are_not_secrets(line):
    assert _secrets(line, "terraform/main.tf") == []


@pytest.mark.parametrize(
    "line",
    [
        f'creation_token = "${{var.project_name}}-{RANDOM}"\n',
        f'api_token = "${{TOKEN:-{RANDOM}}}"\n',
        f'ssl_policy = "{RANDOM}"\n',
    ],
)
def test_a_random_value_beside_an_interpolation_is_still_reported(line):
    assert _secrets(line, "terraform/main.tf")


@pytest.mark.parametrize("address", [BITCOIN, DASH, SEGWIT])
def test_cryptocurrency_addresses_are_public(tmp_path, address):
    assert secret_shapes.is_crypto_address(address)
    yaml = f"donations:\n  data: 'bitcoin:{address}'\n  address: '{address}'\n"
    assert _secrets(yaml, "frontend/src/app/payment.yml") == []
    code = f"const wallet = {{ address: '{address}' }}\n"
    assert _ts_secrets(tmp_path, "src/payment.ts", code) == []


@pytest.mark.parametrize(
    "token",
    [WIF, BITCOIN[:-1] + "n", SEGWIT[:-1] + "x"],
)
def test_a_private_key_or_a_broken_address_is_not_an_address(token):
    assert not secret_shapes.is_crypto_address(token)
    assert _secrets(f'wallet_key: "{token}"\n', "wallet.yml")


def test_a_password_hash_in_a_comment_is_not_reported():
    src = f'//"password" : "{BCRYPT}", // Admin_123\n'
    assert _secrets(src, "artifacts/db-reset.js") == []
    assert _secrets(f'    password: "{BCRYPT}"\n', "docs/users.md") == []


def test_a_password_hash_in_code_is_still_reported():
    src = f'const admin = {{ "password" : "{BCRYPT}" }}\n'
    assert _secrets(src, "artifacts/db-reset.js")


def test_a_camel_case_name_under_a_generic_key_is_not_a_secret():
    assert (
        _secrets(
            "- name: Sandbox\n  key: web3SandboxChallenge\n", "data/challenges.yml"
        )
        == []
    )
    assert _secrets(
        "- name: Sandbox\n  key: Xk9mPq2Lr7Tn4Vb8Wc1Z3\n", "data/challenges.yml"
    )
