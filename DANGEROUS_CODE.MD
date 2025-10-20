| Rule ID | Pattern | Why it's risky | Safer alternative / Fix |
|---------|---------|----------------|-------------------------|
| SKY-D201 | `eval(...)` | Arbitrary code execution | Use `ast.literal_eval` or a dedicated parser |
| SKY-D202 | `exec(...)` | Arbitrary code execution | Remove or use explicit dispatch |
| SKY-D203 | `pickle.load(...)` | Untrusted deserialization can execute code | Avoid for untrusted data. Only load trusted pickle files |
| SKY-D204 | `pickle.loads(...)` | Same as above | Same as above |
| SKY-D205 | `yaml.load(...)` (no SafeLoader) | Can construct arbitrary objects | `yaml.safe_load(...)` or `yaml.load(..., Loader=SafeLoader)` |
| SKY-D206 | `hashlib.md5(...)` | Weak hash | `hashlib.sha256(...)` Use HMAC-SHA256 for authenticity |
| SKY-D207 | `hashlib.sha1(...)` | Same as above | Same as above |
| SKY-D208 | `requests.*(verify=False)` | Disables TLS verification | Keep default `verify=True` or set `verify=/path/to/your/ca-bundle.pem` |
| SKY-D211 | `cursor.execute` / `executemany` / `executescript` with string-built or tainted SQL | SQL injection (cursor) | Use parameterized queries (e.g., `WHERE name = ?` with params tuple) |
| SKY-D212 | `os.system(<tainted/constructed>)` or `subprocess.*(..., shell=True, <tainted>)` | Command injection | `subprocess.run([cmd, ...], check=True)`; if shell required, strict allowlist & quoting |
| SKY-D215 | `open(path)` / `os.(path)` / `shutil.(path)` with tainted path | Path traversal (e.g., `../../etc/passwd`) | Join to a fixed base, `resolve()`, enforce containment, allowlist filenames; reject absolute/`..` |
| SKY-D216 | `requests`/`httpx.*(url)` / `urllib.request.urlopen(url)` with tainted URL | SSRF (server-side request forgery) | Allowlist domains, validate/sanitize URLs, use internal DNS resolution |
| SKY-D217 | `sqlalchemy..text(...)`, `pandas..read_sql*`, `*.objects.raw(...)` with string-built or tainted SQL | SQL injection (raw-api) | Use bound parameters/ORM query builders; never concatenate input into SQL |