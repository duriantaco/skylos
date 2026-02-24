import type { Severity, Category } from "./types";

export interface RuleMeta {
  name: string;
  severity: Severity;
  category: Category;
  description: string;
  owasp?: string;
  cwe?: string;
  pciDss?: string;
  fix?: string;
  language?: string;
}

const RULES: Record<string, RuleMeta> = {
  "DEAD-FUNC": { name: "Unused function", severity: "INFO", category: "dead_code", description: "Function is defined but never called anywhere in the project.", fix: "Remove the function or add it to the whitelist." },
  "DEAD-IMPORT": { name: "Unused import", severity: "INFO", category: "dead_code", description: "Import is never referenced in the module.", fix: "Remove the import statement." },
  "DEAD-CLASS": { name: "Unused class", severity: "INFO", category: "dead_code", description: "Class is defined but never instantiated or referenced.", fix: "Remove the class or add it to the whitelist." },
  "DEAD-VAR": { name: "Unused variable", severity: "INFO", category: "dead_code", description: "Variable is assigned but never read.", fix: "Remove the variable or prefix with underscore." },
  "DEAD-PARAM": { name: "Unused parameter", severity: "INFO", category: "dead_code", description: "Parameter is declared but never used in the function body.", fix: "Remove the parameter or prefix with underscore." },

  "SKY-D201": { name: "eval() usage", severity: "HIGH", category: "security", description: "Use of eval() allows arbitrary code execution.", owasp: "A03:2021", pciDss: "6.2.4", fix: "Use ast.literal_eval() or a safe parser.", language: "python" },
  "SKY-D202": { name: "exec() usage", severity: "HIGH", category: "security", description: "Use of exec() allows arbitrary code execution.", owasp: "A03:2021", fix: "Avoid exec(); use safe alternatives.", language: "python" },
  "SKY-D203": { name: "os.system() usage", severity: "CRITICAL", category: "security", description: "os.system() runs shell commands and is vulnerable to injection.", owasp: "A03:2021", fix: "Use subprocess.run() with a list of args.", language: "python" },
  "SKY-D204": { name: "pickle.load deserialization", severity: "CRITICAL", category: "security", description: "Untrusted deserialization via pickle.load can execute arbitrary code.", owasp: "A08:2021", fix: "Use JSON or a safe serialization format.", language: "python" },
  "SKY-D205": { name: "pickle.loads deserialization", severity: "CRITICAL", category: "security", description: "Untrusted deserialization via pickle.loads can execute arbitrary code.", owasp: "A08:2021", fix: "Use JSON or a safe serialization format.", language: "python" },
  "SKY-D206": { name: "yaml.load without SafeLoader", severity: "HIGH", category: "security", description: "yaml.load without SafeLoader can execute arbitrary Python code.", fix: "Use yaml.safe_load() or pass Loader=SafeLoader.", language: "python" },
  "SKY-D207": { name: "Weak hash (MD5)", severity: "MEDIUM", category: "security", description: "MD5 is cryptographically broken and should not be used for security.", cwe: "CWE-328", fix: "Use SHA-256 or stronger.", language: "python" },
  "SKY-D208": { name: "Weak hash (SHA1)", severity: "MEDIUM", category: "security", description: "SHA1 is cryptographically weak and should not be used for security.", cwe: "CWE-328", fix: "Use SHA-256 or stronger.", language: "python" },
  "SKY-D209": { name: "subprocess with shell=True", severity: "HIGH", category: "security", description: "subprocess call with shell=True is vulnerable to command injection.", owasp: "A03:2021", fix: "Use shell=False and pass args as a list.", language: "python" },
  "SKY-D210": { name: "requests verify=False", severity: "HIGH", category: "security", description: "Disabling SSL verification allows man-in-the-middle attacks.", owasp: "A02:2021", fix: "Remove verify=False; fix certificate issues instead.", language: "python" },
  "SKY-D211": { name: "SQL Injection", severity: "CRITICAL", category: "security", description: "Tainted input used in SQL query without parameterization.", owasp: "A03:2021", pciDss: "6.2.4", cwe: "CWE-89", fix: "Use parameterized queries.", language: "python" },
  "SKY-D212": { name: "Command injection", severity: "CRITICAL", category: "security", description: "User input flows into a shell command without sanitization.", owasp: "A03:2021", pciDss: "6.2.4", cwe: "CWE-78", fix: "Use subprocess with a list of args; never shell=True with user input.", language: "python" },
  "SKY-D214": { name: "Broken access control", severity: "HIGH", category: "security", description: "Missing or insufficient authorization check.", owasp: "A01:2021", pciDss: "6.5.8", language: "python" },
  "SKY-D215": { name: "Path traversal", severity: "HIGH", category: "security", description: "Tainted input used in filesystem path without validation.", owasp: "A01:2021", cwe: "CWE-22", fix: "Validate and sanitize file paths; use os.path.realpath().", language: "python" },
  "SKY-D216": { name: "SSRF", severity: "CRITICAL", category: "security", description: "Tainted URL passed to HTTP client, allowing server-side request forgery.", owasp: "A10:2021", pciDss: "6.2.4", cwe: "CWE-918", fix: "Validate and allowlist URLs before making requests.", language: "python" },
  "SKY-D217": { name: "SQL injection (ORM)", severity: "CRITICAL", category: "security", description: "SQL injection via sqlalchemy.text(), pandas.read_sql(), or Django .raw().", owasp: "A03:2021", pciDss: "6.2.4", cwe: "CWE-89", fix: "Use parameterized queries.", language: "python" },
  "SKY-D222": { name: "Dependency hallucination", severity: "MEDIUM", category: "security", description: "Import references a module not in project dependencies.", language: "python" },
  "SKY-D223": { name: "Undeclared imports", severity: "MEDIUM", category: "security", description: "Import references an undeclared dependency.", language: "python" },
  "SKY-D226": { name: "XSS: mark_safe", severity: "CRITICAL", category: "security", description: "Untrusted content marked as safe, bypassing HTML escaping.", owasp: "A03:2021", cwe: "CWE-79", fix: "Never mark user input as safe; escape output.", language: "python" },
  "SKY-D227": { name: "XSS: unsafe template", severity: "HIGH", category: "security", description: "Unsafe inline template disables auto-escaping.", owasp: "A03:2021", cwe: "CWE-79", language: "python" },
  "SKY-D228": { name: "XSS: unescaped HTML", severity: "HIGH", category: "security", description: "HTML built from unescaped user input.", owasp: "A03:2021", cwe: "CWE-79", fix: "Escape all user input before embedding in HTML.", language: "python" },
  "SKY-D230": { name: "Open redirect", severity: "HIGH", category: "security", description: "User-controlled URL used in redirect without validation.", owasp: "A01:2021", cwe: "CWE-601", fix: "Validate redirect URLs against an allowlist.", language: "python" },
  "SKY-D231": { name: "CORS misconfiguration", severity: "HIGH", category: "security", description: "Overly permissive CORS configuration.", owasp: "A05:2021", fix: "Restrict allowed origins to trusted domains.", language: "python" },
  "SKY-D232": { name: "JWT vulnerability", severity: "CRITICAL", category: "security", description: "JWT configured with algorithms=[\"none\"], verify=False, or similar weakness.", owasp: "A02:2021", pciDss: "6.2.4", fix: "Use strong algorithms (RS256/ES256) and always verify.", language: "python" },
  "SKY-D233": { name: "Unsafe deserialization", severity: "CRITICAL", category: "security", description: "Untrusted deserialization via marshal, shelve, jsonpickle, or dill.", owasp: "A08:2021", pciDss: "6.2.4", fix: "Use JSON or a safe serialization format.", language: "python" },
  "SKY-D234": { name: "Mass assignment", severity: "HIGH", category: "security", description: "Meta.fields = '__all__' exposes all model fields.", owasp: "A01:2021", fix: "Explicitly list allowed fields.", language: "python" },
  "SKY-D240": { name: "MCP tool poisoning", severity: "CRITICAL", category: "security", description: "Prompt injection in MCP tool metadata/descriptions.", fix: "Sanitize all tool metadata; never embed user input in descriptions.", language: "python" },
  "SKY-D241": { name: "MCP unauthenticated transport", severity: "HIGH", category: "security", description: "MCP network transport without authentication.", owasp: "A07:2021", pciDss: "6.5.10", fix: "Add authentication to MCP transports.", language: "python" },
  "SKY-D242": { name: "MCP permissive URI", severity: "HIGH", category: "security", description: "MCP resource URI allows path traversal.", fix: "Validate and restrict resource URIs.", language: "python" },
  "SKY-D243": { name: "MCP exposed server", severity: "CRITICAL", category: "security", description: "MCP server bound to 0.0.0.0 without authentication.", pciDss: "1.3.1", fix: "Bind to localhost or add authentication.", language: "python" },
  "SKY-D244": { name: "MCP hardcoded secrets", severity: "CRITICAL", category: "security", description: "Hardcoded secrets in MCP tool parameter defaults.", pciDss: "3.5.1", fix: "Use environment variables or a secrets manager.", language: "python" },

  "SKY-D501": { name: "eval() usage", severity: "CRITICAL", category: "security", description: "eval() allows arbitrary code execution.", cwe: "CWE-95", fix: "Use JSON.parse() or safe alternatives.", language: "typescript" },
  "SKY-D502": { name: "Unsafe innerHTML", severity: "HIGH", category: "security", description: "innerHTML assignment can lead to XSS.", owasp: "A03:2021", cwe: "CWE-79", fix: "Use textContent or a sanitizer like DOMPurify.", language: "typescript" },
  "SKY-D503": { name: "document.write()", severity: "HIGH", category: "security", description: "document.write() can lead to XSS vulnerabilities.", cwe: "CWE-79", fix: "Use DOM manipulation methods instead.", language: "typescript" },
  "SKY-D504": { name: "new Function()", severity: "CRITICAL", category: "security", description: "new Function() is equivalent to eval().", cwe: "CWE-95", fix: "Avoid dynamic code generation.", language: "typescript" },
  "SKY-D505": { name: "setTimeout/setInterval with string", severity: "HIGH", category: "security", description: "setTimeout/setInterval with string argument is equivalent to eval().", cwe: "CWE-95", fix: "Pass a function reference instead of a string.", language: "typescript" },
  "SKY-D506": { name: "child_process.exec()", severity: "HIGH", category: "security", description: "child_process.exec() can lead to command injection.", cwe: "CWE-78", fix: "Use execFile() with explicit arguments.", language: "typescript" },
  "SKY-D507": { name: "Unsafe outerHTML", severity: "HIGH", category: "security", description: "outerHTML assignment can lead to XSS.", cwe: "CWE-79", fix: "Use safe DOM APIs.", language: "typescript" },
  "SKY-D508": { name: "Hardcoded secret", severity: "CRITICAL", category: "secrets", description: "Potential hardcoded secret or API key in source code.", pciDss: "3.5.1", fix: "Use environment variables or a secrets manager.", language: "typescript" },
  "SKY-D509": { name: "dangerouslySetInnerHTML", severity: "HIGH", category: "security", description: "dangerouslySetInnerHTML bypasses React's XSS protections.", owasp: "A03:2021", cwe: "CWE-79", fix: "Sanitize HTML with DOMPurify before rendering.", language: "typescript" },
  "SKY-D510": { name: "Prototype pollution", severity: "HIGH", category: "security", description: "Prototype pollution via __proto__ access.", cwe: "CWE-1321", fix: "Use Object.create(null) or validate property names.", language: "typescript" },
  "SKY-D511": { name: "Potential SSRF", severity: "MEDIUM", category: "security", description: "HTTP request with variable URL may allow SSRF.", owasp: "A10:2021", cwe: "CWE-918", fix: "Validate URLs against an allowlist.", language: "typescript" },
  "SKY-D513": { name: "Weak hash algorithm", severity: "MEDIUM", category: "security", description: "MD5 or SHA1 used for hashing; cryptographically weak.", cwe: "CWE-328", fix: "Use SHA-256 or stronger.", language: "typescript" },
  "SKY-D515": { name: "Open redirect", severity: "HIGH", category: "security", description: "res.redirect() with variable argument allows open redirect.", owasp: "A01:2021", cwe: "CWE-601", fix: "Validate redirect URLs against an allowlist.", language: "typescript" },
  "SKY-D516": { name: "SQL injection", severity: "CRITICAL", category: "security", description: "SQL injection via template literals in query/exec/execute.", owasp: "A03:2021", cwe: "CWE-89", fix: "Use parameterized queries.", language: "typescript" },

  "SKY-S101": { name: "Hardcoded secret", severity: "CRITICAL", category: "secrets", description: "Hardcoded API key, password, token, or credential in source code.", pciDss: "3.5.1", cwe: "CWE-798", fix: "Use environment variables or a secrets manager." },

  "SKY-L001": { name: "Mutable default argument", severity: "HIGH", category: "quality", description: "Mutable object used as default argument; shared across calls.", cwe: "CWE-665", fix: "Use None as default and create the mutable inside the function.", language: "python" },
  "SKY-L002": { name: "Bare except", severity: "MEDIUM", category: "quality", description: "Bare except block catches all exceptions including SystemExit and KeyboardInterrupt.", fix: "Catch specific exceptions (e.g., except ValueError).", language: "python" },
  "SKY-L003": { name: "Dangerous comparison", severity: "LOW", category: "quality", description: "Using == with True/False/None instead of 'is'.", fix: "Use 'is None', 'is True', 'is False'.", language: "python" },
  "SKY-L004": { name: "Anti-pattern try block", severity: "MEDIUM", category: "quality", description: "Try block is too large, deeply nested, or has complex control flow.", fix: "Reduce try block scope to the minimum necessary.", language: "python" },
  "SKY-L005": { name: "Unused exception variable", severity: "LOW", category: "quality", description: "Exception variable in except clause is never used.", fix: "Use 'except ExceptionType:' without variable, or use the variable.", language: "python" },
  "SKY-L006": { name: "Inconsistent return", severity: "MEDIUM", category: "quality", description: "Some code paths return a value while others return None implicitly.", fix: "Ensure all code paths return explicitly.", language: "python" },

  "SKY-Q301": { name: "High cyclomatic complexity", severity: "WARN", category: "quality", description: "Function has high cyclomatic complexity (threshold: 10).", fix: "Break the function into smaller, focused functions." },
  "SKY-Q302": { name: "Deep nesting", severity: "MEDIUM", category: "quality", description: "Code is nested too deeply (threshold: 3 levels).", fix: "Use early returns, guard clauses, or extract helper functions." },
  "SKY-Q401": { name: "Async blocking call", severity: "HIGH", category: "quality", description: "Blocking call inside async function (e.g., time.sleep, requests).", fix: "Use async equivalents (asyncio.sleep, aiohttp).", language: "python" },
  "SKY-Q501": { name: "God class", severity: "MEDIUM", category: "quality", description: "Class has too many methods (>20) or attributes (>15).", fix: "Split into smaller, focused classes." },
  "SKY-Q701": { name: "High coupling", severity: "MEDIUM", category: "quality", description: "High coupling between objects (CBO metric).", fix: "Reduce dependencies between classes." },
  "SKY-Q702": { name: "Low cohesion", severity: "MEDIUM", category: "quality", description: "Low cohesion within class (LCOM metric).", fix: "Group related methods and attributes." },
  "SKY-C303": { name: "Too many arguments", severity: "MEDIUM", category: "quality", description: "Function has too many parameters (>5 required, >10 total).", fix: "Group related parameters into a data class or dict." },
  "SKY-C304": { name: "Function too long", severity: "MEDIUM", category: "quality", description: "Function exceeds 50 lines.", fix: "Break into smaller functions." },
  "SKY-P401": { name: "Memory risk: file.read()", severity: "LOW", category: "quality", description: "file.read()/readlines() loads entire file into RAM.", fix: "Read in chunks or iterate line by line.", language: "python" },
  "SKY-P402": { name: "Memory risk: read_csv", severity: "LOW", category: "quality", description: "pandas.read_csv() without chunksize loads entire file.", fix: "Use chunksize parameter for large files.", language: "python" },
  "SKY-P403": { name: "Nested loop (O(N^2))", severity: "LOW", category: "quality", description: "Nested loop detected; potential O(N^2) performance issue.", fix: "Consider using sets, dicts, or itertools for better performance." },

  "SKY-UC001": { name: "Unreachable code", severity: "MEDIUM", category: "quality", description: "Code after return/raise/break/continue is unreachable.", fix: "Remove unreachable code." },
};

export function getRuleMeta(ruleId: string): RuleMeta | undefined {
  return RULES[ruleId];
}

export function getSeverityForRule(ruleId: string): Severity {
  return RULES[ruleId]?.severity ?? "INFO";
}

export function getAllRules(): Record<string, RuleMeta> {
  return RULES;
}
