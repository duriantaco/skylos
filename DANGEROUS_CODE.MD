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
| SKY-D222 | Importing a package that does not exist on PyPI | Dependency hallucination / supply chain attack | Verify package names; pin dependencies from trusted sources |
| SKY-D223 | Importing a package that exists on PyPI but is not declared in requirements | Undeclared dependency | Add to `requirements.txt`, `pyproject.toml`, or `setup.py` |
| SKY-D230 | `redirect(user_input)` / `HttpResponseRedirect(user_input)` with tainted URL | Open redirect — attacker controls where users are sent | Validate against an allowlist of paths/domains; never redirect to raw user input |
| SKY-D231 | `CORS_ALLOW_ALL_ORIGINS = True` / `Access-Control-Allow-Origin: *` / `CORS()` without explicit origins | CORS misconfiguration — any origin can make authenticated requests | Set explicit allowed origins: `CORS(app, origins=["https://yourdomain.com"])` |
| SKY-D232 | `jwt.decode(algorithms=['none'])` / `jwt.decode(verify=False)` / `options={'verify_signature': False}` | JWT signature bypass — attacker can forge tokens | Always verify signatures; use strong algorithms like HS256 or RS256 |
| SKY-D233 | `marshal.loads(...)` / `shelve.open(...)` / `jsonpickle.decode(...)` / `dill.loads(...)` / `dill.load(...)` | Untrusted deserialization — arbitrary code execution | Use `json` for untrusted data; only deserialize from trusted sources |
| SKY-D234 | `Meta.fields = '__all__'` in Django ModelForm or DRF Serializer | Mass assignment — exposes all model fields including sensitive ones | Explicitly list fields: `fields = ['name', 'email']` |

## MCP Server Security

| Rule ID | Pattern | Why it's risky | Safer alternative / Fix |
|---------|---------|----------------|-------------------------|
| SKY-D240 | Tool docstring/description containing `<system>`, `<instruction>`, hidden Unicode, or prompt injection phrases | Tool poisoning — attacker-controlled tool metadata tricks the LLM into unsafe actions | Review all tool descriptions for hidden instructions; strip HTML tags; validate tool metadata |
| SKY-D241 | `server.run(transport="sse")` or `transport="streamable-http"` without `auth` | Unauthenticated network transport — any client can invoke tools | Add `auth=` or `auth_server_provider=` to `server.run()` for network transports |
| SKY-D242 | `@server.resource("file:///{path}")` with unconstrained path template | Overly permissive resource URI — allows path traversal to read arbitrary files | Constrain URI templates: use fixed prefixes like `docs://docs/{name}` |
| SKY-D243 | `server.run(host="0.0.0.0")` without `auth` | Network-exposed MCP — server accessible from any network interface without authentication | Bind to `127.0.0.1` or add authentication when exposing to network |
| SKY-D244 | Hardcoded API keys/tokens as default parameter values in `@server.tool()` functions | Secret exposure — credentials visible in source and MCP tool schemas | Use environment variables: `os.environ["API_KEY"]` |

## TypeScript / JavaScript

| Rule ID | Pattern | Why it's risky | Safer alternative / Fix |
|---------|---------|----------------|-------------------------|
| SKY-D501 | `eval(...)` | Arbitrary code execution | Use `JSON.parse()` or a dedicated parser |
| SKY-D502 | `element.innerHTML = userInput` | XSS — injects arbitrary HTML/scripts | Use `textContent`, or sanitize with DOMPurify |
| SKY-D503 | `document.write(...)` | XSS — can overwrite the entire page with attacker-controlled content | Use DOM APIs (`createElement`, `appendChild`) |
| SKY-D504 | `new Function(...)` | Equivalent to `eval()` — arbitrary code execution | Use explicit function definitions or `JSON.parse()` |
| SKY-D505 | `setTimeout(string)` / `setInterval(string)` | String argument is evaluated as code (implicit eval) | Pass a function reference: `setTimeout(() => { ... })` |
| SKY-D506 | `child_process.exec(cmd)` | Command injection — shell interprets the string | Use `child_process.execFile()` or `spawn()` with argument arrays |
| SKY-D507 | `element.outerHTML = userInput` | XSS — replaces element and its container with attacker HTML | Use `textContent`, or sanitize with DOMPurify |

## Sanitizers

Skylos recognizes these functions as sanitizers that clear taint in their respective contexts:

| Context | Sanitizer functions | Clears taint for |
|---------|-------------------|-----------------|
| XSS | `html.escape()`, `markupsafe.escape()`, `Markup.escape()`, `bleach.clean()`, `bleach.linkify()`, `cgi.escape()` | XSS flows (SKY-D502, D503, D507) |
| Command Injection | `shlex.quote()`, `shlex.join()` | Command flows (SKY-D212) |
| URL / SSRF | `urllib.parse.quote()`, `urllib.parse.quote_plus()` | SSRF flows (SKY-D216) |
| Path Traversal | `os.path.basename()`, `pathlib.PurePath.name` | Path flows (SKY-D215) |

Sanitizers are context-specific: `html.escape()` clears XSS taint but does **not** clear SQL or command injection taint.

## Compliance Mapping

| Rule ID | OWASP Top 10 (2021) | PCI DSS 4.0 |
|---------|---------------------|-------------|
| SKY-D211, D217 | A03 — Injection | 6.2.4 |
| SKY-D212 | A03 — Injection | 6.2.4 |
| SKY-D215 | A01 — Broken Access Control | — |
| SKY-D216 | A10 — SSRF | — |
| SKY-D222, D223 | A06 — Vulnerable Components | 6.3.2 |
| SKY-D230 | A01 — Broken Access Control | — |
| SKY-D231 | A05 — Security Misconfiguration | — |
| SKY-D232 | A02 — Cryptographic Failures | 6.2.4 |
| SKY-D233 | A08 — Insecure Deserialization | 6.2.4 |
| SKY-D234 | A01 — Broken Access Control | — |
| SKY-D240 | A03 — Injection | 6.2.4 |
| SKY-D241 | A07 — Auth Failures | 6.5.10 |
| SKY-D242 | A01 — Broken Access Control | — |
| SKY-D243 | A05 — Security Misconfiguration | 1.3.1 |
| SKY-D244 | — | 3.5.1 |