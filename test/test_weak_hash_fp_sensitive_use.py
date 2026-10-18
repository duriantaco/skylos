"""SKY-D207/D208 report MD5/SHA1 only when collision or preimage resistance
matters: the hashed data is sensitive, the digest feeds a security decision,
or the code is an authentication/crypto routine. Content fingerprints, cache
keys, dedup ids, ETags, shard keys and truncated display ids are not reported.
"""

import ast

import pytest

from skylos.core.linter import LinterVisitor
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx


HASH_RULES = {"SKY-D207", "SKY-D208"}


def _both_paths(tmp_path, code):
    """(scan_ctx findings, LinterVisitor findings) as sorted (rule, line)."""
    path = tmp_path / "weak_hash_case.py"
    assert write_text_no_symlink(path, code, encoding="utf-8")
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.visit(ast.parse(code))
    scanned = scan_ctx(tmp_path, [path])
    return [
        sorted(
            (item["rule_id"], item["line"])
            for item in findings
            if item["rule_id"] in HASH_RULES
        )
        for findings in (scanned, linter.findings)
    ]


# --- not security relevant: no sensitive data, no security decision ---------

# agent-pr-bench real-02 (raganything/batch_parser.py): a streamed file digest
# stored in a manifest to detect changed files between runs.
REAL_02_CHANGE_DETECTION = """\
import hashlib
from pathlib import Path


class BatchParser:
    @staticmethod
    def _compute_md5(file_path):
        md5 = hashlib.md5()
        with Path(file_path).open("rb") as file_obj:
            for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
                md5.update(chunk)
        return md5.hexdigest()

    @classmethod
    def _file_signature(cls, file_path):
        metadata = {"path": str(Path(file_path).resolve())}
        metadata["md5"] = cls._compute_md5(file_path)
        return metadata

    def _filter_incremental_files(self, file_paths, manifest):
        changed = []
        for file_path in file_paths:
            if manifest.get(file_path) != self._file_signature(file_path):
                changed.append(file_path)
        return changed
"""

# agent-pr-bench real-03 (tools/job_key.py): a truncated SHA1 suffix that keeps
# a capped dedup key / folder name deterministic.
REAL_03_TRUNCATED_KEY_SUFFIX = """\
import hashlib

HASH_LEN = 8


def _cap(slug, limit):
    if len(slug) <= limit:
        return slug
    digest = hashlib.sha1(slug.encode("utf-8")).hexdigest()[:HASH_LEN]
    return f"{slug[:limit].rstrip('-')}-{digest}"


def make_key(company, title, url=""):
    company_slug = _cap(company, 40) or "unknown-company"
    title_slug = _cap(title, 60)
    if not title_slug:
        basis = title.strip().lower()
        digest = hashlib.sha1((str(title) + str(url)).encode("utf-8")).hexdigest()[:HASH_LEN]
        title_slug = basis or f"untitled-{digest}"
    return f"{company_slug}_{title_slug}"
"""

FINGERPRINTS_AND_IDS = """\
import hashlib


def cache_key(data):
    return hashlib.md5(data).hexdigest()


def etag(body):
    return hashlib.sha1(body).hexdigest()


def shard_for(user_id, shards):
    return int(hashlib.md5(user_id.encode()).hexdigest(), 16) % shards


def gravatar_url(email):
    return "https://www.gravatar.com/avatar/" + hashlib.md5(email.strip().lower().encode()).hexdigest()


def dedupe(blobs):
    seen = set()
    for blob in blobs:
        digest = hashlib.sha1(blob).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        yield blob


def unchanged(path, previous):
    with open(path, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest() == previous["md5"]


content_id = hashlib.md5(b"blob").hexdigest()
hashlib.sha1(b"fixture")
"""

LOOKUPS_SORTING_AND_OPERATOR_INPUT = """\
import hashlib
import inspect
import sys

import click


def memo_key(fn):
    return hashlib.md5(str(inspect.signature(fn)).encode()).hexdigest()


def order(items):
    return sorted(items, key=lambda item: hashlib.sha1(item).hexdigest())


def put(cache, url, resp):
    cache[hashlib.md5(url.encode()).hexdigest()] = resp


@click.command()
def verify(path, expected):
    if hashlib.md5(open(path, "rb").read()).hexdigest() != expected:
        sys.exit(1)
"""

# Held-out scrapy (utils/request.py): the digest is stored *into* a memo dict;
# the later ``key not in cache`` compares the key, not the digest. A password
# stored on ``user`` does not make every later ``user.*`` value a password.
STORED_INTO_CONTAINERS = """\
import hashlib
import json


def fingerprint(request, cache):
    cache_key = (request.method, request.url)
    if cache_key not in cache:
        payload = json.dumps({"url": request.url}, sort_keys=True)
        cache[cache_key] = hashlib.sha1(payload.encode()).digest()
    return cache[cache_key]


def register(user, password):
    user.password_hash = generate_password_hash(password)
    user.avatar = hashlib.md5(user.email.lower().encode()).hexdigest()
"""

ROUTE_CONTENT_ADDRESSING = """\
import hashlib


@app.post("/upload")
def upload(file, store):
    name = hashlib.md5(file.read()).hexdigest()
    store.save(name, file)
    return {"id": name}


@app.get("/asset")
def asset(resp, data):
    resp.headers["ETag"] = hashlib.sha1(data).hexdigest()
    return resp
"""


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        pytest.param(
            "import hashlib\n"
            "def store(user, password):\n"
            "    user.digest = hashlib.md5(password.encode()).hexdigest()\n",
            [("SKY-D207", 3)],
            id="password-input",
        ),
        pytest.param(
            "import hashlib\n"
            "from flask import request\n"
            "def register(db):\n"
            "    raw = request.form['password']\n"
            "    h = hashlib.sha1()\n"
            "    h.update(raw.encode())\n"
            "    db.save(h.hexdigest())\n",
            [("SKY-D208", 5)],
            id="password-flows-into-update",
        ),
        pytest.param(
            "import hashlib\n"
            "def fingerprint(token):\n"
            "    return hashlib.sha1(token).hexdigest()\n",
            [("SKY-D208", 3)],
            id="token-input",
        ),
        pytest.param(
            "import hashlib\n"
            "def digest_with(salt, data):\n"
            "    return hashlib.md5(salt + data).hexdigest()\n",
            [("SKY-D207", 3)],
            id="salted-input",
        ),
        pytest.param(
            "import hashlib\n"
            "from flask import abort, request\n"
            "def check_download(data):\n"
            "    if hashlib.md5(data).hexdigest() != request.args['h']:\n"
            "        abort(403)\n",
            [("SKY-D207", 4)],
            id="compared-to-request-value",
        ),
        pytest.param(
            "import hashlib\n"
            "def check(body, row):\n"
            "    digest = hashlib.md5(body).hexdigest()\n"
            "    return digest == row.api_key\n",
            [("SKY-D207", 3)],
            id="local-compared-to-credential",
        ),
        pytest.param(
            "import hashlib\n"
            "def save(record, raw):\n"
            "    record.password_hash = hashlib.sha1(raw).hexdigest()\n",
            [("SKY-D208", 3)],
            id="stored-as-password-hash",
        ),
        pytest.param(
            "import hashlib\n"
            "def save(raw):\n"
            "    return {'password': hashlib.md5(raw).hexdigest()}\n",
            [("SKY-D207", 3)],
            id="stored-under-password-key",
        ),
        pytest.param(
            "import hashlib, time\n"
            "def generate_session_id(user):\n"
            "    return hashlib.md5(f'{user}{time.time()}'.encode()).hexdigest()\n",
            [("SKY-D207", 3)],
            id="returned-as-session-id",
        ),
        pytest.param(
            "import hashlib\n"
            "def authenticate(user, given):\n"
            "    digest = hashlib.md5(given.encode()).hexdigest()\n"
            "    return digest == user.stored\n",
            [("SKY-D207", 3)],
            id="authentication-routine",
        ),
        pytest.param(
            "import hashlib, hmac\n"
            "def mac(raw_key, msg):\n"
            "    return hmac.new(hashlib.md5(raw_key).digest(), msg, hashlib.sha256).hexdigest()\n",
            [("SKY-D207", 3)],
            id="digest-is-hmac-key",
        ),
        pytest.param(
            "import hashlib\n"
            "from Crypto.Cipher import AES\n"
            "def box(material, blob):\n"
            "    cipher = AES.new(hashlib.md5(material).digest(), AES.MODE_ECB)\n"
            "    return cipher.encrypt(blob)\n",
            [("SKY-D207", 4)],
            id="digest-is-cipher-key",
        ),
        pytest.param(
            "import hashlib\n"
            "from hmac import compare_digest\n"
            "def verify(body, header):\n"
            "    return compare_digest(hashlib.sha1(body).hexdigest(), header)\n",
            [("SKY-D208", 4)],
            id="constant-time-compare",
        ),
        pytest.param(
            "import hashlib\n"
            '@app.post("/upload")\n'
            "def upload(payload, row):\n"
            "    return hashlib.md5(payload).hexdigest() == row.checksum\n",
            [("SKY-D207", 4)],
            id="route-input-compared",
        ),
        pytest.param(
            "import hashlib\n"
            "import requests\n"
            "def fetch(url, expected):\n"
            "    data = requests.get(url, timeout=10).content\n"
            "    if hashlib.sha1(data).hexdigest() != expected:\n"
            "        raise ValueError('checksum mismatch')\n"
            "    return data\n",
            [("SKY-D208", 5)],
            id="download-integrity-check",
        ),
        pytest.param(
            "import hashlib\n"
            "from flask import abort, request\n"
            "@app.post('/hook')\n"
            "def hook():\n"
            "    sent = request.headers['X-Hub-Sig']\n"
            "    expected = hashlib.sha1(request.data).hexdigest()\n"
            "    if sent != expected:\n"
            "        abort(401)\n",
            [("SKY-D208", 6)],
            id="webhook-digest-compared-to-header",
        ),
        pytest.param(
            "import hashlib\n"
            "def check(raw, row):\n"
            "    if (digest := hashlib.md5(raw).hexdigest()) == row.password:\n"
            "        return digest\n",
            [("SKY-D207", 3)],
            id="walrus-compared-to-password",
        ),
        pytest.param(
            "import hashlib\n"
            "def cache_key(password):\n"
            "    return hashlib.md5(password).hexdigest()\n",
            [("SKY-D207", 3)],
            id="neutral-name-does-not-hide-password",
        ),
        pytest.param(
            "import hashlib\n"
            "digest = hashlib.sha1(b'blob', usedforsecurity=True).hexdigest()\n",
            [("SKY-D208", 2)],
            id="explicit-security-use",
        ),
    ],
)
def test_security_relevant_weak_hashes_are_reported(tmp_path, code, expected):
    assert _both_paths(tmp_path, code) == [expected, expected]


def test_usedforsecurity_false_still_suppresses_sensitive_use(tmp_path):
    code = (
        "import hashlib\n"
        "def store(user, password):\n"
        "    user.password_hash = hashlib.md5(password, usedforsecurity=False).hexdigest()\n"
    )
    assert _both_paths(tmp_path, code) == [[], []]
