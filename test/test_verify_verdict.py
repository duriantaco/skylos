from __future__ import annotations

import base64
import builtins
import copy
import hashlib
import io
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from skylos.commands import verify_verdict_cmd
from skylos.commands.verify_verdict_cmd import (
    DEFAULT_KEYS_URL,
    MAX_KEYS_BYTES,
    NotVerified,
    run_verify_verdict_command,
)
from skylos.verdict import (
    VERDICT_BUNDLE_SCHEMA,
    VERDICT_PAYLOAD_TYPE,
    VerdictExpectations,
    dsse_pae,
    verdict_key_id,
    verify_verdict_bundle,
)

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

FIXTURES = Path(__file__).parent / "fixtures" / "verdicts"
KEYS = FIXTURES / "verdict_keys.json"
PASSED = FIXTURES / "verdict_passed.json"
FAILED = FIXTURES / "verdict_failed.json"
COMMIT = "3f2a9c1e5b7d4a6c8e0f1a2b3c4d5e6f7a8b9c0d"
FIXTURE_KEY_ID = "skylos-verdict-a0065c999b24100a"
PROJECT_ID = "11111111-1111-1111-1111-111111111111"
WORKSPACE_ID = "55555555-5555-5555-5555-555555555555"
SIGNED_AT = datetime(2026, 9, 29, 0, 0, 1, tzinfo=timezone.utc)
UNBOUND_LINE = (
    "The project is not bound to its repository by GitHub repository id, "
    "so Skylos can't prove the results came from this commit's code."
)
JSON_FIELDS = {
    "verified",
    "verdict",
    "verified_level",
    "commit",
    "repository",
    "repository_binding",
    "project_id",
    "workspace_id",
    "scan_id",
    "policy_hash",
    "key_id",
    "time_verified",
    "repository_verified",
    "reason",
}


# ------------------------------------------------------------------ helpers


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(tmp_path: Path, name: str, value) -> str:
    path = tmp_path / name
    text = value if isinstance(value, str) else json.dumps(value)
    # All callers pass literal filenames beneath pytest's tmp_path.
    path.write_text(text, encoding="utf-8")  # skylos: ignore[SKY-D324]
    return str(path)


def _run(capsys, *argv: str):
    code = run_verify_verdict_command(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def _statement(bundle: dict) -> dict:
    return json.loads(base64.b64decode(bundle["envelope"]["payload"]))


def _spki_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _published(public_key, *, key_id: str | None = None) -> dict:
    pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return {
        "key_id": key_id or verdict_key_id(_spki_der(public_key)),
        "algorithm": "ed25519",
        "public_key_pem": pem,
        "status": "active",
    }


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _summary(**overrides) -> dict:
    summary = json.loads(_load(PASSED)["summary_json"])
    summary.update(overrides)
    return summary


def _verdict_level(summary: dict) -> str:
    """Python mirror of verdictLevel in check-verdict.ts."""
    if summary["verdict"] != "PASSED":
        return "FAILED"
    if summary.get("gate_overridden"):
        return "SKYLOS_GATE_OVERRIDDEN"
    if (summary.get("gate") or {}).get("enabled") is False:
        return "SKYLOS_GATE_DISABLED"
    if (summary.get("gate") or {}).get("enabled") is not True:
        return "SKYLOS_GATE_UNKNOWN"
    return "SKYLOS_POLICY_PASSED"


def _bound_summary(**overrides) -> dict:
    """A summary with the newer fields: workspace, verified binding, gate."""
    fields = {
        "workspace": {"id": WORKSPACE_ID},
        "repository_binding": "verified",
        "gate": {"enabled": True, "mode": "block"},
        "check_hold": None,
    }
    fields.update(overrides)
    return _summary(**fields)


def _build_statement(summary: dict, summary_json: str) -> dict:
    """Python mirror of buildVerdictStatement in check-verdict.ts."""
    if summary.get("repository"):
        resource = f"git+https://{summary['repository']}@{summary['commit']}"
    else:
        resource = f"skylos-project:{summary['project']['id']}@{summary['commit']}"
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": resource, "digest": {"gitCommit": summary["commit"]}}],
        "predicateType": "https://slsa.dev/verification_summary/v1",
        "predicate": {
            "verifier": {
                "id": "https://skylos.dev/verifiers/pr-check",
                "version": {"skylos-cloud": "test"},
            },
            "timeVerified": "2026-09-29T00:00:01.000Z",
            "resourceUri": resource,
            "policy": {"uri": "https://skylos.dev/p", "digest": {"sha256": "b" * 64}},
            "inputAttestations": [
                {
                    "uri": "https://skylos.dev/api/verdicts/x",
                    "digest": {
                        "sha256": hashlib.sha256(summary_json.encode()).hexdigest()
                    },
                }
            ],
            "verificationResult": summary["verdict"],
            "verifiedLevels": [_verdict_level(summary)],
        },
    }


def _sign(private_key, statement: dict, summary_json: str, *, keyid=None) -> dict:
    payload = json.dumps(statement, separators=(",", ":")).encode()
    sig = private_key.sign(dsse_pae(VERDICT_PAYLOAD_TYPE, payload))
    return {
        "schema": VERDICT_BUNDLE_SCHEMA,
        "envelope": {
            "payloadType": VERDICT_PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [
                {
                    "keyid": keyid
                    or verdict_key_id(_spki_der(private_key.public_key())),
                    "sig": base64.b64encode(sig).decode(),
                }
            ],
        },
        "summary_json": summary_json,
    }


def _signed_bundle(tmp_path, summary: dict, *, mutate_statement=None):
    """A bundle signed by a fresh test key, plus a keys file that trusts it."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    summary_json = _canonical(summary)
    statement = _build_statement(summary, summary_json)
    if mutate_statement:
        mutate_statement(statement)
    bundle = _sign(private_key, statement, summary_json)
    keys = {"keys": [_published(private_key.public_key())]}
    return _write(tmp_path, "bundle.json", bundle), _write(tmp_path, "keys.json", keys)


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = io.BytesIO(body)

    def read(self, size=-1):
        return self._body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeOpener:
    def __init__(self, body: bytes = b"", error: Exception | None = None):
        self.body = body
        self.error = error
        self.calls: list[tuple[str, float]] = []

    def open(self, request, timeout=None):
        self.calls.append((request.full_url, timeout))
        if self.error is not None:
            raise self.error
        return _FakeResponse(self.body)


@pytest.fixture
def fake_opener(monkeypatch):
    opener = _FakeOpener(KEYS.read_bytes())
    monkeypatch.setattr(verify_verdict_cmd, "_build_opener", lambda: opener)
    return opener


# ---------------------------------------------- parity with the TS reference


def test_dsse_pae_matches_spec_and_counts_bytes():
    # Test vector from the DSSE v1 protocol specification.
    assert (
        dsse_pae("http://example.com/HelloWorld", b"hello world")
        == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )
    # Lengths are UTF-8 byte counts, as Buffer.length is in the TS reference.
    assert dsse_pae("té", "é".encode()) == b"DSSEv1 3 t\xc3\xa9 2 \xc3\xa9"


@pytest.mark.parametrize("fixture", [PASSED, FAILED])
def test_python_pae_is_the_message_the_ts_reference_signed(fixture):
    bundle = _load(fixture)
    key = _load(KEYS)["keys"][0]
    public_key = serialization.load_pem_public_key(key["public_key_pem"].encode())
    envelope = bundle["envelope"]
    payload = base64.b64decode(envelope["payload"])

    expected = (
        f"DSSEv1 {len(VERDICT_PAYLOAD_TYPE)} {VERDICT_PAYLOAD_TYPE} {len(payload)} ".encode()
        + payload
    )
    assert dsse_pae(envelope["payloadType"], payload) == expected
    # Raises InvalidSignature unless the bytes equal what check-verdict.ts signed.
    public_key.verify(base64.b64decode(envelope["signatures"][0]["sig"]), expected)


def test_key_id_derivation_matches_the_ts_reference():
    key = _load(KEYS)["keys"][0]
    public_key = serialization.load_pem_public_key(key["public_key_pem"].encode())
    pem_body = "".join(
        line for line in key["public_key_pem"].splitlines() if "-----" not in line
    )

    assert key["key_id"] == FIXTURE_KEY_ID
    assert verdict_key_id(_spki_der(public_key)) == FIXTURE_KEY_ID
    assert verdict_key_id(base64.b64decode(pem_body)) == FIXTURE_KEY_ID


def test_verifier_returns_statement_summary_and_key():
    result = verify_verdict_bundle(
        _load(PASSED),
        _load(KEYS)["keys"],
        VerdictExpectations(commit=COMMIT.upper(), project=PROJECT_ID),
    )

    assert result.ok and result.reason is None
    assert result.key_id == FIXTURE_KEY_ID
    assert result.summary["scan"]["id"] == "22222222-2222-2222-2222-222222222222"
    assert result.statement["predicate"]["verificationResult"] == "PASSED"


# -------------------------------------------------------------- happy paths


def test_passed_fixture_verifies(capsys):
    code, out, err = _run(capsys, str(PASSED), "--keys", str(KEYS))

    assert code == 0
    assert err == ""
    # The fixture predates repository_binding, so its binding is unverified.
    assert out.splitlines() == [
        f"Verified: PASSED for github.com/example-org/example-api@{COMMIT} "
        "(level SKYLOS_POLICY_PASSED, scan 22222222-2222-2222-2222-222222222222, "
        f"policy bbbbbbbbbbbb, key {FIXTURE_KEY_ID}, "
        "verified 2026-09-29T00:00:01.000Z)",
        UNBOUND_LINE,
    ]


def test_failed_fixture_verifies_without_require_passed(capsys):
    code, out, _ = _run(capsys, str(FAILED), "--keys", str(KEYS))

    assert code == 0
    assert out.startswith("Verified: FAILED for github.com/example-org/example-api@")


@pytest.mark.parametrize(("fixture", "expected"), [(PASSED, 0), (FAILED, 1)])
def test_require_passed_exit_codes(capsys, fixture, expected):
    code, out, _ = _run(capsys, str(fixture), "--keys", str(KEYS), "--require-passed")

    assert code == expected
    assert out.startswith("Verified: ")
    assert ("--require-passed: the verified result is FAILED." in out) == (
        expected == 1
    )


@pytest.mark.parametrize("commit", [COMMIT, COMMIT.upper(), f"  {COMMIT}\n"])
def test_commit_match_is_case_insensitive(capsys, commit):
    code, _, _ = _run(capsys, str(PASSED), "--keys", str(KEYS), "--commit", commit)

    assert code == 0


def test_commit_mismatch_is_not_verified(capsys):
    other = "a" * 40
    code, out, err = _run(capsys, str(PASSED), "--keys", str(KEYS), "--commit", other)

    assert code == 2
    assert out == ""
    assert (
        err.strip() == f"Not verified: The verdict is for commit {COMMIT}, not {other}."
    )


def test_empty_commit_fails_closed(capsys):
    code, _, err = _run(capsys, str(PASSED), "--keys", str(KEYS), "--commit", "")

    assert code == 2
    assert "--commit is empty" in err


def test_bundle_from_stdin(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(PASSED.read_bytes())))

    code, out, _ = _run(capsys, "-", "--keys", str(KEYS))

    assert code == 0
    assert out.startswith("Verified: PASSED")


def test_first_valid_trusted_signature_wins(capsys, tmp_path):
    bundle = _load(PASSED)
    bundle["envelope"]["signatures"].insert(0, {"keyid": "not-a-key", "sig": "!!"})
    bundle["envelope"]["signatures"].insert(0, None)

    code, _, _ = _run(capsys, _write(tmp_path, "b.json", bundle), "--keys", str(KEYS))

    assert code == 0


# ---------------------------------------------------------- tamper detection


def _expect_not_verified(capsys, bundle_path: str, keys_path: str, reason: str):
    code, out, err = _run(capsys, bundle_path, "--keys", keys_path)
    assert code == 2
    assert out == ""
    assert err.strip() == f"Not verified: {reason}"


def _expect_not_verified_with(
    capsys, bundle_path: str, keys_path: str, flags: list[str], reason: str
):
    code, out, err = _run(capsys, bundle_path, "--keys", keys_path, *flags)
    assert code == 2
    assert out == ""
    assert err.strip() == f"Not verified: {reason}"


def test_tampered_payload_is_rejected(capsys, tmp_path):
    bundle = _load(FAILED)
    statement = _statement(bundle)
    statement["predicate"]["verificationResult"] = "PASSED"
    bundle["envelope"]["payload"] = base64.b64encode(
        json.dumps(statement, separators=(",", ":")).encode()
    ).decode()

    _expect_not_verified(
        capsys,
        _write(tmp_path, "b.json", bundle),
        str(KEYS),
        "No valid signature from a trusted Skylos key.",
    )


def test_tampered_signature_is_rejected(capsys, tmp_path):
    bundle = _load(PASSED)
    sig = bytearray(base64.b64decode(bundle["envelope"]["signatures"][0]["sig"]))
    sig[0] ^= 0x01
    bundle["envelope"]["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()

    _expect_not_verified(
        capsys,
        _write(tmp_path, "b.json", bundle),
        str(KEYS),
        "No valid signature from a trusted Skylos key.",
    )


def test_edited_summary_is_rejected(capsys, tmp_path):
    bundle = _load(FAILED)
    bundle["summary_json"] = bundle["summary_json"].replace(
        '"new_unsuppressed":1', '"new_unsuppressed":0'
    )
    assert bundle["summary_json"] != _load(FAILED)["summary_json"]

    _expect_not_verified(
        capsys,
        _write(tmp_path, "b.json", bundle),
        str(KEYS),
        "The summary does not match the signed digest.",
    )


def test_wrong_key_is_rejected(capsys, tmp_path):
    other = ed25519.Ed25519PrivateKey.generate().public_key()
    keys = _write(tmp_path, "keys.json", {"keys": [_published(other)]})

    _expect_not_verified(
        capsys, str(PASSED), keys, "No valid signature from a trusted Skylos key."
    )


def test_published_key_id_must_belong_to_its_key(capsys, tmp_path):
    # An attacker signs a forged PASSED verdict and publishes their key under
    # the real Skylos key id; the id does not derive from their key.
    attacker = ed25519.Ed25519PrivateKey.generate()
    summary = _summary()
    summary_json = _canonical(summary)
    statement = _build_statement(summary, summary_json)
    forged = _sign(attacker, statement, summary_json, keyid=FIXTURE_KEY_ID)
    lying_keys = {"keys": [_published(attacker.public_key(), key_id=FIXTURE_KEY_ID)]}

    _expect_not_verified(
        capsys,
        _write(tmp_path, "forged.json", forged),
        _write(tmp_path, "keys.json", lying_keys),
        "No valid signature from a trusted Skylos key.",
    )

    # Control: the same forgery verifies when the key is published honestly,
    # so the rejection above came from the key-id check.
    honest = _sign(attacker, statement, summary_json)
    code, _, _ = _run(
        capsys,
        _write(tmp_path, "honest.json", honest),
        "--keys",
        _write(
            tmp_path, "honest-keys.json", {"keys": [_published(attacker.public_key())]}
        ),
    )
    assert code == 0


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda b: b.update(schema="skylos.verdict-bundle/v2"),
            "Unknown bundle schema.",
        ),
        (lambda b: b.pop("schema"), "Unknown bundle schema."),
        (
            lambda b: b["envelope"].update(payloadType="application/json"),
            "The envelope is not a DSSE in-toto envelope.",
        ),
        (
            lambda b: b["envelope"].update(payload="not base64!"),
            "The envelope is not a DSSE in-toto envelope.",
        ),
        (
            lambda b: b["envelope"].update(payload=b["envelope"]["payload"] + "\n"),
            "The envelope is not a DSSE in-toto envelope.",
        ),
        (
            lambda b: b["envelope"].update(signatures={}),
            "The envelope is not a DSSE in-toto envelope.",
        ),
        (lambda b: b.pop("summary_json"), "The bundle has no summary."),
    ],
)
def test_malformed_bundles_are_rejected(capsys, tmp_path, mutate, reason):
    bundle = copy.deepcopy(_load(PASSED))
    mutate(bundle)

    _expect_not_verified(capsys, _write(tmp_path, "b.json", bundle), str(KEYS), reason)


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("this is not json", "The bundle is not JSON."),
        ('{"schema": NaN}', "The bundle is not JSON."),
        ("[]", "The bundle is not a JSON object."),
    ],
)
def test_non_json_bundle_is_rejected(capsys, tmp_path, content, reason):
    _expect_not_verified(capsys, _write(tmp_path, "b.json", content), str(KEYS), reason)


def test_missing_bundle_file_is_not_verified(capsys, tmp_path):
    code, _, err = _run(capsys, str(tmp_path / "missing.json"), "--keys", str(KEYS))

    assert code == 2
    assert err.startswith("Not verified: Could not read the bundle")


# ------------------------------------------- signed but inconsistent content


def test_summary_that_disagrees_with_statement_is_rejected(capsys, tmp_path):
    def claim_passed(statement):
        statement["predicate"]["verificationResult"] = "PASSED"

    bundle, keys = _signed_bundle(
        tmp_path, _summary(verdict="FAILED"), mutate_statement=claim_passed
    )

    _expect_not_verified(
        capsys, bundle, keys, "The summary and the signed statement disagree."
    )


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda s: s.update(predicateType="https://slsa.dev/provenance/v1"),
            "The signed statement is not a Skylos verification summary.",
        ),
        (
            lambda s: s["subject"].append(s["subject"][0]),
            "The signed statement is not a Skylos verification summary.",
        ),
        (
            lambda s: s["subject"][0]["digest"].update(gitCommit="3f2a9c1"),
            "The signed statement has no commit.",
        ),
        (
            lambda s: s["predicate"].update(verificationResult="UNKNOWN"),
            "The signed statement has no result.",
        ),
    ],
)
def test_signed_statement_shape_is_checked(capsys, tmp_path, mutate, reason):
    bundle, keys = _signed_bundle(tmp_path, _summary(), mutate_statement=mutate)

    _expect_not_verified(capsys, bundle, keys, reason)


def test_unverified_upload_identity_is_called_out(capsys, tmp_path):
    summary = _bound_summary(
        upload_identity={
            "type": "project_api_key",
            "repository_verified": False,
            "workflow": None,
            "run_id": None,
            "actor": None,
            "api_key_label": "ci-deploy",
        }
    )
    bundle, keys = _signed_bundle(tmp_path, summary)

    code, out, _ = _run(capsys, bundle, "--keys", keys)

    assert code == 0
    assert out.splitlines()[1] == (
        'The results were uploaded with a project API key "ci-deploy", so '
        "Skylos can't prove they came from this commit's code."
    )


def test_project_without_repository_verifies(capsys, tmp_path):
    bundle, keys = _signed_bundle(tmp_path, _summary(repository=None))

    code, out, _ = _run(capsys, bundle, "--keys", keys)

    assert code == 0
    assert out.startswith(f"Verified: PASSED for Skylos project example-api@{COMMIT} ")


# ------------------------------------------------------------------ key sets


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("nope", "The key set is not JSON."),
        ('{"keys": {}}', 'The key set has no "keys" list.'),
        ("[]", 'The key set has no "keys" list.'),
    ],
)
def test_bad_key_set_is_not_verified(capsys, tmp_path, content, reason):
    _expect_not_verified(
        capsys, str(PASSED), _write(tmp_path, "k.json", content), reason
    )


def test_default_keys_url_is_fetched_over_https(capsys, fake_opener):
    code, _, _ = _run(capsys, str(PASSED))

    assert code == 0
    assert fake_opener.calls == [(DEFAULT_KEYS_URL, 10)]


def test_custom_https_keys_url(capsys, fake_opener):
    code, _, _ = _run(capsys, str(PASSED), "--keys", "https://keys.example.com/k.json")

    assert code == 0
    assert fake_opener.calls == [("https://keys.example.com/k.json", 10)]


@pytest.mark.parametrize(
    "url",
    [
        "http://skylos.dev/.well-known/skylos-verdict-keys.json",
        "file:///etc/keys",
        "https://",
    ],
)
def test_non_https_keys_url_is_rejected(capsys, fake_opener, url):
    code, _, err = _run(capsys, str(PASSED), "--keys", url)

    assert code == 2
    assert "must use https://" in err
    assert fake_opener.calls == []


@pytest.mark.parametrize(
    ("error", "detail"),
    [
        (
            urllib.error.HTTPError(DEFAULT_KEYS_URL, 503, "Unavailable", {}, None),
            "HTTP 503",
        ),
        (urllib.error.URLError("timed out"), "timed out"),
        (TimeoutError("The read operation timed out"), "timed out"),
    ],
)
def test_unreachable_keys_url_is_not_verified(capsys, monkeypatch, error, detail):
    opener = _FakeOpener(error=error)
    monkeypatch.setattr(verify_verdict_cmd, "_build_opener", lambda: opener)

    code, _, err = _run(capsys, str(PASSED))

    assert code == 2
    assert err.startswith("Not verified: Could not fetch the key set from")
    assert detail in err


def test_oversized_key_set_is_not_verified(capsys, monkeypatch):
    opener = _FakeOpener(b" " * (MAX_KEYS_BYTES + 1))
    monkeypatch.setattr(verify_verdict_cmd, "_build_opener", lambda: opener)

    code, _, err = _run(capsys, str(PASSED))

    assert code == 2
    assert "larger than" in err


def test_redirects_must_stay_on_https():
    handler = verify_verdict_cmd._HttpsOnlyRedirects()
    request = urllib.request.Request(DEFAULT_KEYS_URL)

    with pytest.raises(NotVerified, match="redirected away from https"):
        handler.redirect_request(
            request, None, 302, "Found", {}, "http://evil.test/k.json"
        )

    followed = handler.redirect_request(
        request, None, 302, "Found", {}, "https://cdn.skylos.dev/k.json"
    )
    assert followed.full_url == "https://cdn.skylos.dev/k.json"


# ----------------------------------------------------- optional dependency


def test_missing_cryptography_exits_2_with_install_hint(
    capsys, monkeypatch, fake_opener
):
    real_import = builtins.__import__

    def no_cryptography(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("No module named 'cryptography'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_cryptography)

    code, out, err = _run(capsys, str(PASSED))

    assert code == 2
    assert out == ""
    assert "Install it with: pip install cryptography" in err
    assert "skylos[verdict]" in err
    assert fake_opener.calls == []


# --------------------------------------------------------------- JSON output


def test_json_output_for_verified_verdict(capsys):
    code, out, err = _run(capsys, str(FAILED), "--keys", str(KEYS), "--json")

    payload = json.loads(out)
    assert code == 0
    assert err == ""
    assert set(payload) == JSON_FIELDS
    assert payload == {
        "verified": True,
        "verdict": "FAILED",
        "verified_level": "FAILED",
        "commit": COMMIT,
        "repository": "github.com/example-org/example-api",
        # The fixture predates repository_binding: missing means unverified.
        "repository_binding": "unverified",
        "project_id": PROJECT_ID,
        "workspace_id": None,
        "scan_id": "22222222-2222-2222-2222-222222222222",
        "policy_hash": "b" * 64,
        "key_id": FIXTURE_KEY_ID,
        "time_verified": "2026-09-29T00:00:01.000Z",
        "repository_verified": False,
        "reason": None,
    }


def test_json_output_with_require_passed_failure(capsys):
    code, out, _ = _run(
        capsys, str(FAILED), "--keys", str(KEYS), "--json", "--require-passed"
    )

    payload = json.loads(out)
    assert code == 1
    assert payload["verified"] is True
    assert payload["verdict"] == "FAILED"
    assert payload["reason"] == "--require-passed: the verified result is FAILED."


def test_json_output_for_unverified_bundle(capsys, tmp_path):
    bundle = _write(tmp_path, "b.json", {"schema": "other"})

    code, out, err = _run(capsys, bundle, "--keys", str(KEYS), "--json")

    payload = json.loads(out)
    assert code == 2
    assert err == ""
    assert set(payload) == JSON_FIELDS
    assert payload["verified"] is False
    assert payload["reason"] == "Unknown bundle schema."
    assert all(payload[key] is None for key in JSON_FIELDS - {"verified", "reason"})


# ------------------------------------------------------------ CLI wiring


def test_cli_dispatches_verify_verdict(monkeypatch, capsys):
    import skylos.cli as cli

    monkeypatch.setattr(
        sys, "argv", ["skylos", "verify-verdict", str(PASSED), "--keys", str(KEYS)]
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("Verified: PASSED")


def test_cli_help_is_the_argparse_help(monkeypatch, capsys):
    import skylos.cli as cli

    monkeypatch.setattr(sys, "argv", ["skylos", "verify-verdict", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "--require-passed" in out
    assert DEFAULT_KEYS_URL in out


# ------------------------------------------------ deployment expectations


def _expect_passes(capsys, bundle: str, keys: str, *flags: str) -> str:
    code, out, err = _run(capsys, bundle, "--keys", keys, *flags)
    assert (code, err) == (0, "")
    return out


@pytest.fixture
def clock(monkeypatch):
    """Pin the command's clock; returns a setter."""

    def set_now(now: datetime) -> None:
        monkeypatch.setattr(verify_verdict_cmd, "_utc_now", lambda: now)

    set_now(SIGNED_AT + timedelta(hours=1))
    return set_now


@pytest.mark.parametrize(
    "repository",
    ["github.com/example-org/example-api", "GitHub.com/Example-Org/Example-API"],
)
def test_repository_match_is_case_insensitive(capsys, repository):
    _expect_passes(capsys, str(PASSED), str(KEYS), "--repository", repository)


def test_repository_mismatch_is_not_verified(capsys):
    _expect_not_verified_with(
        capsys,
        str(PASSED),
        str(KEYS),
        ["--repository", "github.com/example-org/other"],
        "The verdict is for repository github.com/example-org/example-api, "
        "not github.com/example-org/other.",
    )


def test_repository_required_but_verdict_has_none(capsys, tmp_path):
    bundle, keys = _signed_bundle(tmp_path, _bound_summary(repository=None))

    _expect_not_verified_with(
        capsys,
        bundle,
        keys,
        ["--repository", "github.com/example-org/example-api"],
        "The verdict is for repository none, not github.com/example-org/example-api.",
    )


def test_project_match_and_mismatch(capsys):
    _expect_passes(capsys, str(PASSED), str(KEYS), "--project", PROJECT_ID)
    _expect_not_verified_with(
        capsys,
        str(PASSED),
        str(KEYS),
        ["--project", "99999999-9999-9999-9999-999999999999"],
        f"The verdict is for project {PROJECT_ID}, "
        "not 99999999-9999-9999-9999-999999999999.",
    )


def test_workspace_missing_from_old_verdict_is_a_mismatch(capsys):
    _expect_passes(capsys, str(PASSED), str(KEYS))
    _expect_not_verified_with(
        capsys,
        str(PASSED),
        str(KEYS),
        ["--workspace", WORKSPACE_ID],
        "The verdict belongs to a different workspace.",
    )


def test_workspace_match_and_mismatch(capsys, tmp_path):
    bundle, keys = _signed_bundle(tmp_path, _bound_summary())

    _expect_passes(capsys, bundle, keys, "--workspace", WORKSPACE_ID)
    _expect_not_verified_with(
        capsys,
        bundle,
        keys,
        ["--workspace", "66666666-6666-6666-6666-666666666666"],
        "The verdict belongs to a different workspace.",
    )


@pytest.mark.parametrize(
    "flag", ["--commit", "--repository", "--project", "--workspace"]
)
def test_empty_expectation_fails_closed(capsys, flag):
    code, _, err = _run(capsys, str(PASSED), "--keys", str(KEYS), flag, " ")

    assert code == 2
    assert err.strip() == f"Not verified: {flag} is empty."


def test_require_repository_verified_rejects_missing_binding(capsys):
    # The fixture is a verified GitHub OIDC upload but has no binding field.
    _expect_not_verified_with(
        capsys,
        str(PASSED),
        str(KEYS),
        ["--require-repository-verified"],
        "The verdict is not bound to a verified repository upload.",
    )


def test_require_repository_verified_accepts_bound_oidc_upload(capsys, tmp_path):
    bundle, keys = _signed_bundle(tmp_path, _bound_summary())

    out = _expect_passes(capsys, bundle, keys, "--require-repository-verified")
    assert out.count("\n") == 1  # no "can't prove" line


@pytest.mark.parametrize(
    "overrides",
    [
        {"repository_binding": "unverified"},
        {
            "upload_identity": {
                "type": "project_api_key",
                "repository_verified": False,
                "workflow": None,
                "run_id": None,
                "actor": None,
                "api_key_label": "ci",
            }
        },
    ],
)
def test_require_repository_verified_needs_binding_and_oidc(
    capsys, tmp_path, overrides
):
    bundle, keys = _signed_bundle(tmp_path, _bound_summary(**overrides))

    _expect_passes(capsys, bundle, keys)
    _expect_not_verified_with(
        capsys,
        bundle,
        keys,
        ["--require-repository-verified"],
        "The verdict is not bound to a verified repository upload.",
    )


@pytest.mark.parametrize(
    ("now", "max_age"),
    [
        (SIGNED_AT + timedelta(hours=23), "24h"),
        (SIGNED_AT + timedelta(minutes=89), "90m"),
        (SIGNED_AT + timedelta(days=7), "7d"),
        # A signing time up to five minutes ahead is clock skew, not an error.
        (SIGNED_AT - timedelta(minutes=4), "1h"),
    ],
)
def test_max_age_accepts_recent_verdicts(capsys, clock, now, max_age):
    clock(now)

    _expect_passes(capsys, str(PASSED), str(KEYS), "--max-age", max_age)


def test_max_age_rejects_old_verdicts(capsys, clock):
    clock(SIGNED_AT + timedelta(days=7, seconds=1))

    _expect_not_verified_with(
        capsys,
        str(PASSED),
        str(KEYS),
        ["--max-age", "7d"],
        "The verdict is older than the allowed age.",
    )


def test_max_age_rejects_future_signing_time(capsys, clock):
    clock(SIGNED_AT - timedelta(minutes=6))

    _expect_not_verified_with(
        capsys,
        str(PASSED),
        str(KEYS),
        ["--max-age", "7d"],
        "The verdict has an invalid signing time.",
    )


@pytest.mark.parametrize("time_verified", ["yesterday", "2026-09-29T00:00:01", 17])
def test_max_age_rejects_unparseable_signing_time(capsys, tmp_path, time_verified):
    def set_time(statement):
        statement["predicate"]["timeVerified"] = time_verified

    bundle, keys = _signed_bundle(tmp_path, _bound_summary(), mutate_statement=set_time)

    _expect_passes(capsys, bundle, keys)
    _expect_not_verified_with(
        capsys,
        bundle,
        keys,
        ["--max-age", "7d"],
        "The verdict has an invalid signing time.",
    )


@pytest.mark.parametrize(
    "value", ["7", "0d", "-1h", "7 days", "1.5h", "", "99999999999999999999w"]
)
def test_max_age_rejects_bad_durations(capsys, value):
    # The equals form sends negative values to the validator on Python 3.12.
    with pytest.raises(SystemExit) as exc:
        run_verify_verdict_command(
            [str(PASSED), "--keys", str(KEYS), f"--max-age={value}"]
        )

    assert exc.value.code == 2
    assert "invalid duration" in capsys.readouterr().err


def test_recommended_deploy_gate(capsys, tmp_path, clock):
    bundle, keys = _signed_bundle(tmp_path, _bound_summary())

    out = _expect_passes(
        capsys,
        bundle,
        keys,
        "--commit",
        COMMIT,
        "--repository",
        "github.com/example-org/example-api",
        "--require-repository-verified",
        "--max-age",
        "7d",
        "--require-passed",
    )
    assert out.startswith("Verified: PASSED for github.com/example-org/example-api@")


# ------------------------------------------------------ verified levels


def _level_bundle(tmp_path, **overrides):
    return _signed_bundle(tmp_path, _bound_summary(**overrides))


def test_overridden_gate_needs_allow_override(capsys, tmp_path):
    bundle, keys = _level_bundle(tmp_path, gate_overridden=True)

    code, out, _ = _run(capsys, bundle, "--keys", keys, "--require-passed")
    assert code == 1
    assert "level SKYLOS_GATE_OVERRIDDEN" in out
    assert "An admin overrode the gate for this commit (merge anyway)." in out
    assert out.strip().endswith(
        "--require-passed: an admin overrode the gate (SKYLOS_GATE_OVERRIDDEN); "
        "add --allow-override to accept overrides."
    )

    code, _, _ = _run(
        capsys, bundle, "--keys", keys, "--require-passed", "--allow-override"
    )
    assert code == 0


@pytest.mark.parametrize("allow_override", [False, True])
def test_disabled_gate_never_satisfies_require_passed(capsys, tmp_path, allow_override):
    bundle, keys = _level_bundle(tmp_path, gate={"enabled": False, "mode": None})
    flags = ["--require-passed"] + (["--allow-override"] if allow_override else [])

    code, out, _ = _run(capsys, bundle, "--keys", keys, *flags)

    assert code == 1
    assert "level SKYLOS_GATE_DISABLED" in out
    assert "The workspace gate is off, so this PASSED is not a policy decision." in out
    assert out.strip().endswith(
        "--require-passed: the workspace gate is off (SKYLOS_GATE_DISABLED); "
        "only a policy pass is accepted."
    )


def test_disabled_gate_verifies_without_require_passed(capsys, tmp_path):
    bundle, keys = _level_bundle(tmp_path, gate={"enabled": False, "mode": None})

    out = _expect_passes(capsys, bundle, keys)
    assert out.startswith("Verified: PASSED for ")


@pytest.mark.parametrize(
    "levels",
    [
        [],
        ["SLSA_BUILD_LEVEL_3"],
        # A disabled gate is refused even next to a policy pass.
        ["SKYLOS_POLICY_PASSED", "SKYLOS_GATE_DISABLED"],
    ],
)
def test_require_passed_needs_the_policy_passed_level(capsys, tmp_path, levels):
    def set_levels(statement):
        statement["predicate"]["verifiedLevels"] = levels

    bundle, keys = _signed_bundle(
        tmp_path, _bound_summary(), mutate_statement=set_levels
    )

    code, out, _ = _run(
        capsys, bundle, "--keys", keys, "--require-passed", "--allow-override"
    )

    assert code == 1
    assert "--require-passed: " in out


def test_allow_override_requires_require_passed(capsys):
    with pytest.raises(SystemExit) as exc:
        run_verify_verdict_command(
            [str(PASSED), "--keys", str(KEYS), "--allow-override"]
        )

    assert exc.value.code == 2
    assert (
        "--allow-override only applies with --require-passed" in capsys.readouterr().err
    )


def test_json_reports_level_and_require_passed_reason(capsys, tmp_path):
    bundle, keys = _level_bundle(tmp_path, gate_overridden=True)

    code, out, _ = _run(capsys, bundle, "--keys", keys, "--json", "--require-passed")
    payload = json.loads(out)

    assert code == 1
    assert set(payload) == JSON_FIELDS
    assert payload["verified"] is True
    assert payload["verified_level"] == "SKYLOS_GATE_OVERRIDDEN"
    assert payload["workspace_id"] == WORKSPACE_ID
    assert payload["repository_binding"] == "verified"
    assert payload["repository_verified"] is True
    assert "SKYLOS_GATE_OVERRIDDEN" in payload["reason"]


def test_verifier_expectations_match_ts_semantics(tmp_path):
    project_id = "abcdef00-1111-4111-8111-111111111111"
    bundle_path, keys_path = _signed_bundle(
        tmp_path, _bound_summary(project={"id": project_id, "name": "api"})
    )
    bundle, keys = _load(Path(bundle_path)), _load(Path(keys_path))["keys"]

    def reason(**expect):
        return verify_verdict_bundle(bundle, keys, VerdictExpectations(**expect)).reason

    # Ids are compared exactly, repositories case-insensitively (as in TS).
    assert reason(project=project_id) is None
    assert reason(project=project_id.upper()) == (
        f"The verdict is for project {project_id}, not {project_id.upper()}."
    )
    assert reason(workspace=WORKSPACE_ID) is None
    assert reason(repository="GITHUB.COM/EXAMPLE-ORG/EXAMPLE-API") is None
    assert reason(require_repository_verified=True) is None
    assert reason(max_age=timedelta(days=1), now=SIGNED_AT + timedelta(days=2)) == (
        "The verdict is older than the allowed age."
    )
    assert reason(max_age=timedelta(days=1), now=SIGNED_AT) is None


def test_a_pass_without_recorded_gate_settings_is_not_a_policy_pass(capsys, tmp_path):
    bundle, keys = _level_bundle(tmp_path, gate={"enabled": None, "mode": None})

    code, out, _ = _run(
        capsys, bundle, "--keys", keys, "--require-passed", "--allow-override"
    )

    assert code == 1
    assert "level SKYLOS_GATE_UNKNOWN" in out
    assert out.strip().endswith(
        "--require-passed: the scan recorded no gate settings (SKYLOS_GATE_UNKNOWN); "
        "upload a fresh scan to get a policy decision."
    )


@pytest.mark.parametrize("trust", ["verified_ci", "trusted_api_key"])
def test_require_trusted_upload_accepts_trusted_uploads(capsys, tmp_path, trust):
    identity = {**_bound_summary()["upload_identity"], "trust": trust}
    bundle, keys = _signed_bundle(tmp_path, _bound_summary(upload_identity=identity))

    _expect_passes(capsys, bundle, keys, "--require-trusted-upload")


@pytest.mark.parametrize("trust", [None, "unverified", "VERIFIED_CI"])
def test_require_trusted_upload_rejects_unverified_and_older_verdicts(
    capsys, tmp_path, trust
):
    # None: a verdict signed before Skylos Cloud recorded upload trust.
    identity = dict(_bound_summary()["upload_identity"])
    identity.pop("trust", None)
    if trust is not None:
        identity["trust"] = trust
    bundle, keys = _signed_bundle(tmp_path, _bound_summary(upload_identity=identity))

    _expect_passes(capsys, bundle, keys)
    _expect_not_verified_with(
        capsys,
        bundle,
        keys,
        ["--require-trusted-upload"],
        "The verdict is not for a trusted upload "
        "(CI with OIDC, or a CI key the project trusts).",
    )


def test_positional_max_age_still_rejects_an_ancient_trusted_verdict(tmp_path):
    identity = {**_bound_summary()["upload_identity"], "trust": "verified_ci"}
    bundle_path, keys_path = _signed_bundle(
        tmp_path,
        _bound_summary(upload_identity=identity),
        mutate_statement=lambda statement: statement["predicate"].update(
            timeVerified="2000-01-01T00:00:00.000Z"
        ),
    )
    # This constructor predates require_trusted_upload; its sixth argument
    # must remain the age limit rather than becoming a truthy trust flag.
    expectations = VerdictExpectations(None, None, None, None, False, timedelta(days=1))

    result = verify_verdict_bundle(
        _load(Path(bundle_path)), _load(Path(keys_path))["keys"], expectations
    )

    assert not result.ok
    assert result.reason == "The verdict is older than the allowed age."


@pytest.mark.parametrize(
    ("hours_after_signing", "expected_reason"),
    [(12, None), (48, "The verdict is older than the allowed age.")],
)
def test_positional_max_age_and_now_keep_the_original_clock(
    tmp_path, hours_after_signing, expected_reason
):
    signed_at = datetime(2000, 1, 1, tzinfo=timezone.utc)
    bundle_path, keys_path = _signed_bundle(
        tmp_path,
        _bound_summary(),
        mutate_statement=lambda statement: statement["predicate"].update(
            timeVerified="2000-01-01T00:00:00.000Z"
        ),
    )
    expectations = VerdictExpectations(
        None,
        None,
        None,
        None,
        False,
        timedelta(days=1),
        signed_at + timedelta(hours=hours_after_signing),
    )

    result = verify_verdict_bundle(
        _load(Path(bundle_path)), _load(Path(keys_path))["keys"], expectations
    )

    assert result.ok is (expected_reason is None)
    assert result.reason == expected_reason


@pytest.mark.parametrize("trust", [None, "unverified", "trusted_api_key"])
def test_trusted_upload_keyword_works_with_existing_positional_expectations(
    tmp_path, trust
):
    identity = dict(_bound_summary()["upload_identity"])
    if trust is not None:
        identity["trust"] = trust
    bundle_path, keys_path = _signed_bundle(
        tmp_path, _bound_summary(upload_identity=identity)
    )
    expectations = VerdictExpectations(
        None,
        None,
        None,
        None,
        False,
        timedelta(days=1),
        SIGNED_AT,
        require_trusted_upload=True,
    )

    result = verify_verdict_bundle(
        _load(Path(bundle_path)), _load(Path(keys_path))["keys"], expectations
    )

    assert result.ok is (trust == "trusted_api_key")
    if trust != "trusted_api_key":
        assert result.reason == (
            "The verdict is not for a trusted upload "
            "(CI with OIDC, or a CI key the project trusts)."
        )
