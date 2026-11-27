from pathlib import Path

import pytest

from skylos.visitors.languages.rust import scan_rust_file

PROLOGUE = """
use secrecy::{ExposeSecret, SecretString};
use openssl::symm::{encrypt as enc, Cipher};
use openssl::hash::MessageDigest as Digest;
use openssl::sign::Signer;
use openssl::pkey::{PKey, Private};
use rusqlite::Connection;
fn run(pass: &SecretString, public: &str, k: &PKey<Private>, db: &Connection) {
    let raw = pass.expose_secret();
"""
RULES = {"SKY-D207", "SKY-D208", "SKY-D251", "SKY-D386", "SKY-D387", "SKY-D388"}


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("let _ = md5::compute(raw.as_bytes());", "SKY-D207"),
        (
            "let md = Digest::sha1(); let _ = openssl::hash::hash(md, raw.as_bytes());",
            "SKY-D208",
        ),
        ("let _ = md5::compute(public.as_bytes());", None),
        ("let _ = openssl::hash::hash(Digest::sha256(), raw.as_bytes());", None),
        ("let hash = Digest::sha1(); let _ = hash;", None),
        ('use log::warn as record; record!("credential {}", raw);', "SKY-D251"),
        ('log::info!("credential {raw}");', "SKY-D251"),
        ('tracing::info!(auth = %pass.expose_secret(), "authenticated");', "SKY-D251"),
        ('log::warn!("credential length {}", raw.len());', None),
        ('log::warn!("credential {:?}", pass);', None),
        ('log::warn!("escaped {{raw}}");', None),
        ('mod log { } macro_rules! warn { ($($t:tt)*) => {} } warn!("{}", raw);', None),
        (
            "let cipher = Cipher::des_cbc(); let _ = enc(cipher, &[0; 8], Some(&[0; 8]), public.as_bytes());",
            "SKY-D386",
        ),
        ("let _ = enc(Cipher::rc4(), &[0; 16], None, public.as_bytes());", "SKY-D386"),
        (
            "let _ = enc(Cipher::aes_256_gcm(), &[0; 32], Some(&[0; 12]), public.as_bytes());",
            None,
        ),
        ("let cipher = Cipher::des_cbc(); let _ = cipher.key_len();", None),
        (
            "let _ = openssl::symm::decrypt(Cipher::des_cbc(), &[0; 8], Some(&[0; 8]), public.as_bytes());",
            None,
        ),
        (
            'let _ = db.execute("INSERT INTO accounts(password) VALUES (?1)", [raw]);',
            "SKY-D387",
        ),
        (
            'let _ = db.execute("UPDATE accounts SET password_hash = ?1 WHERE id = 1", [raw]);',
            "SKY-D387",
        ),
        (
            'let _ = db.execute("SELECT id FROM accounts WHERE password = ?1", [raw]);',
            None,
        ),
        (
            'let _ = db.execute("INSERT INTO access_log(tag) VALUES (?1)", [public]);',
            None,
        ),
        (
            'let _ = db.execute("INSERT INTO accounts(password_hash) VALUES (?1)", [derive_hash(raw)]);',
            None,
        ),
        (
            'let _ = jsonwebtoken::EncodingKey::from_secret(b"example-only-static-text");',
            "SKY-D388",
        ),
        ("let _ = jsonwebtoken::EncodingKey::from_secret(raw.as_bytes());", None),
        ('let _ = jsonwebtoken::DecodingKey::from_rsa_pem(b"public material");', None),
        (
            'mod jsonwebtoken {pub struct EncodingKey; impl EncodingKey { pub fn from_secret(_: &[u8]) {} }} jsonwebtoken::EncodingKey::from_secret(b"example-only-static-text");',
            None,
        ),
    ],
)
def test_sensitive_operations(tmp_path, body, expected):
    path = Path(tmp_path, "src", "lib.rs")
    path.parent.mkdir()
    path.write_text(PROLOGUE + body + "\n}\n", encoding="utf-8")
    findings = [f for f in scan_rust_file(str(path), {})[7] if f["rule_id"] in RULES]
    assert [f["rule_id"] for f in findings] == ([expected] if expected else [])
    assert all("example-only-static-text" not in f["message"] for f in findings)


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        (
            "use sha1::{Digest as _, Sha1}; let mut h = Sha1::new(); h.update(raw.as_bytes());",
            "SKY-D208",
        ),
        (
            "use sha1::Digest; let mut h = sha1::Sha1::new(); h.update(public.as_bytes());",
            None,
        ),
        (
            "use cbc::cipher::{BlockEncryptMut, KeyIvInit}; let h = cbc::Encryptor::<des::Des>::new(key.into(), iv.into()); let _ = h.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(public.as_bytes());",
            "SKY-D386",
        ),
        (
            "use cbc::cipher::KeyIvInit; let _ = cbc::Encryptor::<des::Des>::new(key.into(), iv.into());",
            None,
        ),
        (
            "use aes_gcm::KeyInit; let key = [0x2au8; 16]; let _ = aes_gcm::Aes128Gcm::new((&key).into());",
            "SKY-D388",
        ),
        (
            "use aes_gcm::KeyInit; let key = [0u8; 16]; let _ = aes_gcm::Aes256Gcm::new_from_slice(&key);",
            None,
        ),
        (
            "use aes_gcm::KeyInit; let mut key = [0u8; 32]; fill(&mut key); let _ = aes_gcm::Aes256Gcm::new((&key).into());",
            None,
        ),
        ('let _ = jsonwebtoken::EncodingKey::from_base64_secret("!!!!");', None),
        (
            'let _ = jsonwebtoken::EncodingKey::from_base64_secret("c2FtcGxl");',
            "SKY-D388",
        ),
        (
            'let mut text = raw.to_owned(); text.clear(); log::info!("cleared {}", text);',
            None,
        ),
        ('let _deferred = || log::info!("{}", raw);', None),
    ],
)
def test_secret_api_variants(tmp_path, body, rule):
    path = tmp_path / "app.rs"
    path.write_text(
        PROLOGUE.replace("run(pass:", "run(key: &[u8; 8], iv: &[u8; 8], pass:")
        + body
        + "\n}"
    )
    hits = [
        f["rule_id"] for f in scan_rust_file(str(path), {})[7] if f["rule_id"] in RULES
    ]
    assert hits == ([rule] if rule else [])


def test_exposed_text_is_replaced_through_mutable_borrow(tmp_path):
    path = tmp_path / "src.rs"
    path.write_text("""
        use secrecy::{ExposeSecret, SecretString};
        fn redact(text: &mut String) { text.clear(); }
        fn run(pw: &SecretString, conn: &rusqlite::Connection) {
            let mut raw = pw.expose_secret().to_string();
            redact(&mut raw);
            log::info!("{}", raw);
            conn.execute("INSERT INTO users(password) VALUES (?1)", [raw]).unwrap();
        }
    """)
    assert not [
        r
        for r in scan_rust_file(str(path), {})[7]
        if r["rule_id"] in {"SKY-D251", "SKY-D387"}
    ]
