"""SKY-D250 follows a ``random``/``random.Random`` value inside its function
(str, slicing, f-strings, encodings, local names, a module helper's return)
into a credential-named store or keyword, the session, a cookie value or a
comparison with a request cookie. Jitter, sampling, display shuffles,
user-agent choice, ``SystemRandom`` and ``secrets`` stay quiet. Runs the
production analyzer path."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.reporting.listing import is_listed

REPORTED = {
    "store_key_name": (
        "import random\n"
        "def remember(store, num):\n"
        "    cookie = 'remember' + str(num)\n"
        "    value = str(random.normalvariate(0, 1))[2:]\n"
        "    store[cookie] = value\n"
    ),
    "set_cookie_value": (
        "import base64\n"
        "import random\n"
        "def finish(response):\n"
        "    value = str(base64.b64encode(random.randbytes(32)))\n"
        "    response.set_cookie('sid', value)\n"
        "    return response\n"
    ),
    "random_instance_keyword": (
        "import random\n"
        "def render_page(render):\n"
        "    rng = random.Random()\n"
        "    marker = rng.getrandbits(64).to_bytes(8, 'big').hex()\n"
        "    label = f'n-{marker}'\n"
        "    return render('page.html', nonce=label)\n"
    ),
    "session_store": (
        "import random\n"
        "from flask import session\n"
        "def start_challenge():\n"
        "    session['captcha_answer'] = random.randint(1000, 9999)\n"
    ),
    "cookie_comparison": (
        "import random\n"
        "from flask import request\n"
        "def check():\n"
        "    expected = str(random.uniform(0, 1))\n"
        "    return request.cookies.get('remember') == expected\n"
    ),
    "aliased_import": (
        "import string\n"
        "from random import choices as pick\n"
        "def issue(store, user):\n"
        "    code = ''.join(pick(string.digits, k=6))\n"
        "    store[user.reset_token_key] = code\n"
    ),
    "module_alias": (
        "import random as rnd\n"
        "def issue(response):\n"
        "    response.set_cookie('remember', value=str(rnd.gauss(0, 1)))\n"
    ),
    "local_wrapper": (
        "import random\n"
        "def _digits():\n"
        "    return str(random.random())[2:10]\n"
        "def issue(response):\n"
        "    response.set_cookie('remember', _digits())\n"
    ),
    "augmented_credential": (
        "import random\n"
        "def build(n):\n"
        "    otp_code = ''\n"
        "    for _ in range(n):\n"
        "        otp_code += str(random.randint(0, 9))\n"
        "    return otp_code\n"
    ),
}

QUIET = {
    "retry_jitter": (
        "import random\n"
        "import time\n"
        "def backoff(attempt, base):\n"
        "    time.sleep(base * random.uniform(0.5, 1.5))\n"
        "    delay = random.uniform(0.1, 0.3) * attempt\n"
        "    time.sleep(delay)\n"
    ),
    "sampling": (
        "import random\n"
        "def preview(rows):\n"
        "    subset = random.sample(rows, 10)\n"
        "    return [row.id for row in subset]\n"
    ),
    "display_shuffle": (
        "import random\n"
        "def board(deck, items, context):\n"
        "    cards = list(deck)\n"
        "    random.shuffle(cards)\n"
        "    context['cards'] = cards\n"
        "    order = random.sample(items, len(items))\n"
        "    context['items'] = order\n"
        "    return context\n"
    ),
    "user_agent": (
        "import random\n"
        "import requests\n"
        "AGENTS = ['a', 'b']\n"
        "def fetch(url):\n"
        "    headers = {'User-Agent': random.choice(AGENTS)}\n"
        "    session = requests.Session()\n"
        "    session.headers['User-Agent'] = random.choice(AGENTS)\n"
        "    return session.get(url, headers=headers)\n"
    ),
    "system_random": (
        "import random\n"
        "from flask import session\n"
        "def issue(response):\n"
        "    rng = random.SystemRandom()\n"
        "    session['token'] = str(rng.random())\n"
        "    response.set_cookie('sid', str(random.SystemRandom().getrandbits(64)))\n"
    ),
    "secrets_module": (
        "import secrets\n"
        "from flask import session\n"
        "def issue(response):\n"
        "    session['csrf'] = secrets.token_hex(16)\n"
        "    response.set_cookie('sid', secrets.token_urlsafe(16))\n"
    ),
    "rebound_before_use": (
        "import random\n"
        "import secrets\n"
        "def issue(response):\n"
        "    value = str(random.random())\n"
        "    value = secrets.token_urlsafe(16)\n"
        "    response.set_cookie('sid', value)\n"
    ),
    "random_index_choice": (
        "import random\n"
        "from flask import session\n"
        "THEMES = ['dark', 'light']\n"
        "def pick_theme():\n"
        "    session['theme'] = THEMES[random.randrange(len(THEMES))]\n"
    ),
}


@pytest.fixture(scope="module")
def weak_random_rows(tmp_path_factory):
    root = tmp_path_factory.mktemp("weak_random")
    (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    package = root / "app"
    package.mkdir()
    for name, code in {**REPORTED, **QUIET}.items():
        (package / f"{name}.py").write_text(code)
    result = json.loads(
        analyze(str(root), enable_danger=True, grep_verify=False, all_advice=False)
    )
    rows = {}
    for row in result.get("danger", []):
        if row.get("rule_id") == "SKY-D250":
            stem = row["file"].replace("\\", "/").rsplit("/", 1)[-1][:-3]
            rows.setdefault(stem, []).append(row)
    return rows


@pytest.mark.parametrize("case", sorted(REPORTED))
def test_weak_random_flowing_into_security_use_is_listed(weak_random_rows, case):
    rows = weak_random_rows.get(case, [])
    assert len(rows) == 1
    assert rows[0]["severity"] == "MEDIUM"
    assert is_listed(rows[0], "danger")


@pytest.mark.parametrize("case", sorted(QUIET))
def test_non_security_random_and_strong_sources_stay_quiet(weak_random_rows, case):
    assert weak_random_rows.get(case) is None
