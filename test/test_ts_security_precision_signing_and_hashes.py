"""SKY-S101: a literal passed where a library takes its signing key or salt,
however short or common (``session({ secret: 'keyboard cat' })``,
``process.env.JWT_SECRET || 'superSecret'``).

SKY-D207/D208: an MD5 helper is listed when its callers hash passwords or
store its result as a password; one whose callers hash other data stays a
low-risk hash.
"""

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.listing import LOW_RISK_REASON, demotion_reason
from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.weak_hash_callers import (
    list_weak_hashes_of_credentials,
)


def _write(root, name: str, code: str):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, code, encoding="utf-8")
    return path


def _danger(tmp_path, name: str, code: str) -> list[dict]:
    write_text_no_symlink(tmp_path / "package.json", "{}\n", encoding="utf-8")
    return scan_typescript_file(str(_write(tmp_path, name, code)))[7]


def _signing(tmp_path, code: str, name: str = "src/server.ts") -> list[tuple[int, str]]:
    return sorted(
        (finding["line"], finding["severity"])
        for finding in _danger(tmp_path, name, code)
        if finding["rule_id"] == "SKY-S101" and finding.get("secret_sink")
    )


@pytest.mark.parametrize(
    "code,line,severity",
    [
        (
            (
                "var session = require('express-session')\n"
                "app.use(session({\n  secret: 'keyboard cat',\n  resave: true\n}))\n"
            ),
            3,
            "CRITICAL",
        ),
        (
            (
                "import * as jwt from 'jsonwebtoken'\n"
                "export const sign = (id: number) =>\n"
                "  jwt.sign({ id }, process.env.JWT_SECRET || 'superSecret')\n"
            ),
            3,
            "HIGH",
        ),
        (
            (
                "import { expressjwt as jwt } from 'express-jwt'\n"
                "export const auth = jwt({ secret: process.env.JWT_SECRET ?? 'superSecret', algorithms: ['HS256'] })\n"
            ),
            2,
            "HIGH",
        ),
        (
            (
                "const { verify } = require('jsonwebtoken')\n"
                "const KEY = 'secret'\n"
                "module.exports = (token) => verify(token, KEY)\n"
            ),
            2,
            "CRITICAL",
        ),
        (
            "import cookieParser from 'cookie-parser'\napp.use(cookieParser('kekse'))\n",
            2,
            "CRITICAL",
        ),
        (
            (
                "import crypto from 'node:crypto'\n"
                "export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9').update(data)\n"
            ),
            2,
            "CRITICAL",
        ),
        (
            (
                "import Hashids from 'hashids/cjs'\n"
                "const hashids = new Hashids('this is my salt', 60, 'abcdefghijklmnopqrstuvwxyz')\n"
            ),
            2,
            "CRITICAL",
        ),
    ],
)
def test_a_literal_signing_secret_is_reported(tmp_path, code, line, severity):
    assert (line, severity) in _signing(tmp_path, code)


@pytest.mark.parametrize(
    "code",
    [
        (
            "var session = require('express-session')\n"
            "app.use(session({ secret: process.env.SESSION_SECRET, resave: true }))\n"
        ),
        (
            "import * as jwt from 'jsonwebtoken'\n"
            "export const sign = (id: number) => jwt.sign({ id }, process.env.JWT_SECRET!)\n"
        ),
        (
            "import * as jwt from 'jsonwebtoken'\n"
            "export const sign = (id: number, key: string) => jwt.sign({ id }, key)\n"
        ),
        (
            "import crypto from 'crypto'\n"
            "export const digest = (data: string) => crypto.createHash('sha256').update('salt')\n"
        ),
        # A function of the same name that is not the library's.
        (
            "function session(options: object) { return options }\n"
            "session({ secret: 'keyboard cat' })\n"
        ),
        "import { sign } from './local-signer'\nsign({ id: 1 }, 'superSecret')\n",
    ],
)
def test_environment_keys_and_unrelated_calls_are_not_reported(tmp_path, code):
    assert _signing(tmp_path, code) == []


def test_a_signing_literal_in_a_spec_follows_the_test_policy(tmp_path):
    code = (
        "import * as jwt from 'jsonwebtoken'\n"
        "const token = jwt.sign({ id: 1 }, 'superSecret')\n"
    )
    assert _signing(tmp_path, code, name="test/api/login.spec.ts") == []


# --- Weak hashes of credentials -----------------------------------------------

HELPER = (
    "import crypto from 'crypto'\n"
    "export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')\n"
)


def _weak_hash(tmp_path, callers: dict[str, str]) -> dict:
    write_text_no_symlink(tmp_path / "package.json", "{}\n", encoding="utf-8")
    helper = _write(tmp_path, "lib/insecurity.ts", HELPER)
    files = [helper] + [_write(tmp_path, name, code) for name, code in callers.items()]
    findings = [
        finding
        for finding in scan_typescript_file(str(helper))[7]
        if finding["rule_id"] == "SKY-D207"
    ]
    assert len(findings) == 1
    assert findings[0]["low_risk_context"]["caller_supplied"] == {
        "function": "hash",
        "parameters": ["data"],
    }
    list_weak_hashes_of_credentials(findings, files, tmp_path)
    return findings[0]


@pytest.mark.parametrize(
    "callers",
    [
        {
            "routes/login.ts": (
                "import * as security from '../lib/insecurity'\n"
                "export const login = (req) => db.find(req.body.email, security.hash(req.body.password))\n"
            )
        },
        {
            "models/user.ts": (
                "const security = require('../lib/insecurity')\n"
                "class User { set password (clear: string) {\n"
                "  this.setDataValue('password', security.hash(clear))\n} }\n"
            )
        },
        {
            "models/account.ts": (
                "import { hash as digest } from '../lib/insecurity'\n"
                "export const account = (value: string) => ({ password: digest(value) })\n"
            )
        },
    ],
)
def test_a_helper_that_hashes_passwords_is_listed(tmp_path, callers):
    finding = _weak_hash(tmp_path, callers)
    assert "low_risk_context" not in finding
    assert finding["hash_input_evidence"]["calls"]
    assert demotion_reason(finding) is None


@pytest.mark.parametrize(
    "callers",
    [
        {},
        {
            "scripts/package.ts": (
                "import { hash } from '../lib/insecurity'\n"
                "export const checksum = (content: string) => hash(content)\n"
            )
        },
        {
            # bcrypt.hash(password) is another library's function.
            "routes/register.ts": (
                "import bcrypt from 'bcrypt'\n"
                "export const register = (req) => bcrypt.hash(req.body.password, 10)\n"
            )
        },
    ],
)
def test_a_helper_that_hashes_other_data_stays_low_risk(tmp_path, callers):
    finding = _weak_hash(tmp_path, callers)
    assert finding["low_risk_context"]["reason"] == "non-sensitive-hash-input"
    assert demotion_reason(finding) == LOW_RISK_REASON
