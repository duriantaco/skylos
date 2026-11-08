# Secret detection

`--secrets` (or `-a`) looks for credentials written into files: API keys,
tokens, passwords and private keys. Every secret it reports fails the
quality gate, whatever the configured limits, because a committed key is
exposed the moment it is pushed. The rule pages are SKY-S101 (a secret in a
file) and SKY-S102 (a secret in code that ships to the browser).

## What it finds

| Kind | Examples | Severity |
|:--|:--|:--|
| Provider keys | GitHub `ghp_…` and `github_pat_…`, GitLab `glpat-…`, Slack tokens and webhook URLs, Stripe `sk_live_…`, AWS `AKIA…`, Google `AIza…`, SendGrid, Twilio, npm `npm_…`, PyPI `pypi-…`, DigitalOcean, Hugging Face `hf_…` | CRITICAL |
| Private keys | RSA, EC, OpenSSH, PKCS#8 and PGP private-key blocks with key material | CRITICAL |
| Structured credentials | AWS secret keys and key pairs, Azure Storage connection strings, Google service-account files, private JSON Web Keys | CRITICAL |
| Encoded keys | provider keys hidden in base64 or URL encoding | CRITICAL |
| Generic secrets | a quoted, random-looking value assigned to a name such as `api_key`, `token`, `secret` or `password` (HIGH when unquoted in a `.env` or config file) | CRITICAL |
| Unnamed random values | a long value that mixes upper case, lower case and digits, with no secret-like name earlier on the line | HIGH |
| Passwords in URLs and config | `postgres://app:pa55word@db/…`, `password: …` in a config file | HIGH |

A provider key needs only its shape; generic values must also look random
(enough entropy over enough characters). Identifiers, file paths, URLs
without credentials, prose and `${VAR}` references are not secrets.

## Which files

Source files in every supported language, configuration files (`.yml`,
`.json`, `.toml`, `.ini`, `.properties`, `.xml`, Terraform and others),
`.env` files, Dockerfiles, `.npmrc` and `.pypirc`, HTML, CSS and source
maps, and shell scripts. Markdown, text, `.pem` and `.key` files, SSH keys
and `.aws/credentials` are checked for provider keys and private keys only.

## Avoiding test fixtures and examples

- **Test code.** In test files and folders (`tests/`, `test_*.py`,
  `__tests__/`, `*.test.ts`, `testdata/`, `*_test.go` and similar) only
  provider keys and private keys are reported. A random-looking fixture
  value is left alone; a real-looking GitHub token is not.
- **Placeholders.** A provider-shaped value containing a placeholder word,
  such as `example`, `sample`, `fake`, `dummy`, `placeholder` or
  `changeme`, as a separate word is skipped: `ghp_example000…` is,
  `ghp_000…` is not.
- **Published examples.** The example keys that AWS and Slack print in their
  own documentation are skipped.
- **Placeholder passwords** such as `password` or `changeme` in URLs and
  config files are skipped.

## In the browser

Code under `public/`, `static/`, `.next/static/` and similar folders, and
files marked `"use client"`, ships to every visitor. A secret there is
reported as SKY-S102. So is a server-only environment variable read in
client code, such as `process.env.STRIPE_SECRET_KEY`.

## Outside a scan

- `skylos done` checks only the lines a change adds, and ignores any
  suppression marker added in the same change.
- The agent hooks check files as a coding agent edits them, and block an
  agent from reading `.env` files and other credential stores.

To silence one value, put `skylos: ignore[SKY-S101]` on its line with the
reason (see "Silencing a finding"). Then revoke the key anyway.
