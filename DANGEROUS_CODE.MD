| Rule ID | Pattern | Why it's risky | Safer alternative / Fix |
|---------|---------|----------------|-------------------------|
| SKY-D201 | `eval(...)` | Arbitrary code execution | Use `ast.literal_eval` or a dedicated parser |
| SKY-D202 | `exec(...)` | Arbitrary code execution | Remove or use explicit dispatch |
| SKY-D203 | `os.system(...)` | Command injection, weak error handling | `subprocess.run([...], check=True)` (no shell) |
| SKY-D204 | `pickle.load(...)` | Untrusted deserialization can execute code | Avoid for untrusted data. Only load trusted pickle files |
| SKY-D205 | `pickle.loads(...)` | Same as above | Same as above |
| SKY-D206 | `yaml.load(...)` (no `SafeLoader`) | Can construct arbitrary objects | `yaml.safe_load(...)` or `yaml.load(..., Loader=SafeLoader)` |
| SKY-D207 | `hashlib.md5(...)` | Weak hash | `hashlib.sha256(...)` Use HMAC-SHA256 for authenticity |
| SKY-D208 | `hashlib.sha1(...)` | Same as above | Same as above |
| SKY-D209 | `subprocess.*(..., shell=True)` | Shell parsing -> command injection via metacharacters | Pass args list; **do not** use `shell=True` |
| SKY-D210 | `requests.*(verify=False)` | Disables TLS verification| Keep default `verify=True` or set `verify=/path/to/your/ca-bundle.pem` |