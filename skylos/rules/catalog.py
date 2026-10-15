from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class RuleCatalogEntry:
    id: str
    name: str
    category: str
    finding_type: str = field(kw_only=True)
    severity: str | None = None
    source: str = "builtin"
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["aliases"] = list(self.aliases)
        return data


# Keep this catalog aligned with skylos-docs/docs/rules-reference.mdx.
_RULES = (
    RuleCatalogEntry("SKY-U001", "Unused function", "dead_code", finding_type="review"),
    RuleCatalogEntry("SKY-U002", "Unused import", "dead_code", finding_type="review"),
    RuleCatalogEntry("SKY-U003", "Unused variable", "dead_code", finding_type="review"),
    RuleCatalogEntry("SKY-U004", "Unused class", "dead_code", finding_type="review"),
    RuleCatalogEntry(
        "SKY-U005", "Unused dependency", "dead_code", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-U006", "Unused parameter", "dead_code", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-UC001", "Unreachable Python code", "dead_code", finding_type="defect"
    ),
    RuleCatalogEntry(
        "SKY-UC002", "Unreachable statement", "dead_code", finding_type="defect"
    ),
    RuleCatalogEntry(
        "SKY-A101",
        "Test assertion weakening",
        "ai_defect",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A102",
        "High-risk change without tests",
        "ai_defect",
        "LOW",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A103",
        "CI permission expansion",
        "ai_defect",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A104",
        "Public CLI surface drift",
        "ai_defect",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A105",
        "Contract route guard missing",
        "ai_defect",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A106",
        "Suspicious dependency version bump",
        "ai_defect",
        "LOW",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A110", "Test deleted", "ai_defect", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-A111", "Test newly skipped", "ai_defect", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-A112", "Test settings loosened", "ai_defect", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-A113",
        "Tests fail when Skylos runs them",
        "ai_defect",
        "HIGH",
        finding_type="defect",
    ),
    RuleCatalogEntry(
        "SKY-A114",
        "Skylos settings or hooks changed",
        "ai_defect",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A115",
        "Test answer hard-coded in code",
        "ai_defect",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A116",
        "Code detects the test run",
        "ai_defect",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A117",
        "Comparison rigged to always pass",
        "ai_defect",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A118",
        "Inline suppression added",
        "ai_defect",
        "LOW",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A119",
        "Linter or scanner settings weakened",
        "ai_defect",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A120",
        "Changed line not checked by tests",
        "ai_defect",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A121", "CI check weakened", "ai_defect", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-A122",
        "AI-reviewer settings changed",
        "ai_defect",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A125",
        "Scanner suppression marker added",
        "ai_defect",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A135",
        "Code left unused by the change",
        "ai_defect",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-A136", "New code nothing calls", "ai_defect", "LOW", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-A137",
        "New code only tests call",
        "ai_defect",
        "LOW",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-SCA-LIC001",
        "Dependency license policy violation",
        "dependency",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-C401", "Duplicated code clone", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-CIRC", "Circular dependency", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-Q301", "Cyclomatic complexity", "quality", finding_type="advice"
    ),
    RuleCatalogEntry("SKY-Q302", "Deep nesting", "quality", finding_type="advice"),
    RuleCatalogEntry(
        "SKY-C303", "Too many function arguments", "quality", finding_type="advice"
    ),
    RuleCatalogEntry("SKY-C304", "Function too long", "quality", finding_type="advice"),
    RuleCatalogEntry(
        "SKY-Q305", "Duplicate branch logic", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-Q306", "Cognitive complexity", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-Q401", "Async blocking call", "quality", finding_type="defect"
    ),
    RuleCatalogEntry(
        "SKY-Q402", "Await in loop", "quality", "LOW", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-Q403",
        "Inconsistent lock acquisition order",
        "quality",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-Q404",
        "Thread shared state mutation",
        "quality",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-Q405", "Async Promise executor", "quality", "HIGH", finding_type="defect"
    ),
    RuleCatalogEntry(
        "SKY-Q406",
        "Async Array.forEach callback",
        "quality",
        "HIGH",
        finding_type="defect",
    ),
    RuleCatalogEntry(
        "SKY-Q407",
        "Discarded async Array.map result",
        "quality",
        "HIGH",
        finding_type="defect",
    ),
    RuleCatalogEntry("SKY-Q501", "God class", "quality", finding_type="advice"),
    RuleCatalogEntry("SKY-Q502", "Class too large", "quality", finding_type="advice"),
    RuleCatalogEntry("SKY-Q701", "High coupling", "quality", finding_type="advice"),
    RuleCatalogEntry("SKY-Q702", "Low cohesion", "quality", finding_type="advice"),
    RuleCatalogEntry(
        "SKY-Q801", "High instability", "quality", "MEDIUM", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-Q802", "High distance from main sequence", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-Q803", "Architecture zone warning", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-Q804", "Dependency inversion violation", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-Q805",
        "Architecture layer policy violation",
        "quality",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-Q806", "Opaque identifier", "quality", "LOW", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-L001", "Mutable default argument", "quality", finding_type="defect"
    ),
    RuleCatalogEntry("SKY-L002", "Bare except block", "quality", finding_type="review"),
    RuleCatalogEntry(
        "SKY-L003", "Dangerous comparison", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L004", "Anti-pattern try block", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-L005", "Unused exception variable", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-L006", "Shadowed loop variable", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L007", "Empty error handler", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L008", "Missing resource cleanup", "quality", finding_type="review"
    ),
    RuleCatalogEntry("SKY-L009", "Debug leftover", "quality", finding_type="review"),
    RuleCatalogEntry(
        "SKY-L010", "Security TODO marker", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L011", "Disabled security control", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L012", "Phantom symbol reference", "ai_defect", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L013", "Insecure randomness", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L014", "Hardcoded credential", "quality", finding_type="review"
    ),
    RuleCatalogEntry("SKY-L016", "Undefined config", "quality", finding_type="review"),
    RuleCatalogEntry(
        "SKY-L017", "Error information disclosure", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L020", "Overly broad file permissions", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L021", "Security regression", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L023", "Phantom decorator", "ai_defect", finding_type="review"
    ),
    RuleCatalogEntry("SKY-L024", "Stale mock", "quality", finding_type="review"),
    RuleCatalogEntry(
        "SKY-L026",
        "Unfinished code or placeholder default",
        "quality",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-L027", "Duplicate string literal", "quality", finding_type="advice"
    ),
    RuleCatalogEntry("SKY-L028", "Too many returns", "quality", finding_type="advice"),
    RuleCatalogEntry("SKY-L029", "Boolean trap", "quality", finding_type="advice"),
    RuleCatalogEntry(
        "SKY-L030",
        "Broad exception with trivial handler",
        "quality",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-L031", "Missing network timeout", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L032", "Mock or placeholder data", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-L033", "No-effect statement", "quality", finding_type="defect"
    ),
    RuleCatalogEntry(
        "SKY-L034", "Repeated mutable alias", "quality", "MEDIUM", finding_type="defect"
    ),
    RuleCatalogEntry(
        "SKY-L035", "Blanket ESLint disable", "quality", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-P401", "Inefficient loop pattern", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-P402", "Repeated expensive operation", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-P403", "Suspicious performance pattern", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-P404",
        "Unbounded eager ORM query",
        "quality",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-T101", "Missing type annotations", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-T102", "Weak framework route typing", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-T103",
        "Suspicious chained type assertion",
        "quality",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-T104",
        "TypeScript compiler suppression directive",
        "quality",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-T105",
        "Unvalidated JSON type assertion",
        "quality",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-T106",
        "Unsafe exported API type",
        "quality",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-F101", "Framework handler practice issue", "quality", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-F102", "Framework route missing auth", "quality", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-R101",
        "Python type-check policy",
        "quality",
        "MEDIUM",
        finding_type="advice",
    ),
    RuleCatalogEntry(
        "SKY-R102", "Python lint policy", "quality", "LOW", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-R103", "Skylos gate policy", "quality", "LOW", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-R104", "Pre-commit policy", "quality", "LOW", finding_type="advice"
    ),
    RuleCatalogEntry(
        "SKY-R105",
        "TypeScript type-check policy",
        "quality",
        "LOW",
        finding_type="advice",
    ),
    RuleCatalogEntry(
        "SKY-E002", "Empty file", "dead_code", "LOW", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-E003",
        "Unused TypeScript/JavaScript file",
        "dead_code",
        "LOW",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D200", "Dangerous call pattern", "security", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D201",
        "Dynamic code execution via eval",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D202",
        "Dynamic code execution via exec",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D203",
        "OS command execution",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D204",
        "Unsafe pickle deserialization",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D205",
        "Unsafe pickle.loads deserialization",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D206", "Unsafe YAML load", "security", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D207", "Weak MD5 hash", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D208", "Weak SHA1 hash", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D209",
        "Subprocess shell execution",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D210",
        "TLS verification disabled",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D211",
        "SQL injection",
        "security",
        "CRITICAL",
        aliases=("sqli",),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D212", "Command injection", "security", "CRITICAL", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D215",
        "Path traversal",
        "security",
        "HIGH",
        aliases=("lfi", "file traversal"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D216",
        "Server-side request forgery",
        "security",
        "CRITICAL",
        aliases=("ssrf",),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D217", "Raw SQL execution", "security", "CRITICAL", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D222",
        "Dependency hallucination",
        "ai_defect",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D223",
        "Undeclared third-party dependency",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D224",
        "API signature hallucination",
        "ai_defect",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D225",
        "Dependency version hallucination",
        "ai_defect",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D226",
        "Cross-site scripting: untrusted content marked safe",
        "security",
        "CRITICAL",
        aliases=("xss", "cross site scripting", "cross-site scripting"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D227",
        "Cross-site scripting: unsafe inline template",
        "security",
        "HIGH",
        aliases=("xss", "cross site scripting", "cross-site scripting"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D228",
        "Cross-site scripting: HTML built from user input",
        "security",
        "HIGH",
        aliases=("xss", "cross site scripting", "cross-site scripting"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D230",
        "Open redirect",
        "security",
        "HIGH",
        aliases=("redirect",),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D231",
        "Unsafe CORS configuration",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D232",
        "Unsafe JWT handling",
        "security",
        "CRITICAL",
        aliases=("jwt",),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D233",
        "Unsafe deserialization",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D234", "Mass assignment", "security", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D235",
        "Remote command execution sink",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D240",
        "MCP tool description poisoning",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D241",
        "MCP unauthenticated network transport",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D242",
        "MCP overly permissive resource URI",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D243",
        "MCP network-exposed server without auth",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D244",
        "MCP hardcoded tool parameter secret",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D245", "Dynamic require", "security", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D246",
        "JWT decode without verification",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D247", "CORS wildcard origin", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D248",
        "Hardcoded internal URL",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D250", "Weak random source", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D251", "Sensitive data in logs", "security", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D252", "Insecure cookie", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D253",
        "Timing-unsafe comparison",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D254",
        "HTTP session trust boundary violation",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D260",
        "Prompt injection exposure",
        "security",
        "HIGH",
        aliases=("prompt injection", "hidden unicode"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D261",
        "Untrusted input to LLM prompt",
        "security",
        "HIGH",
        aliases=("dynamic prompt injection", "llm prompt injection"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D262",
        "Unsafe LLM output handling",
        "security",
        "CRITICAL",
        aliases=("llm output", "improper output handling"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D263",
        "Sensitive data sent to LLM",
        "security",
        "HIGH",
        aliases=("llm data leakage", "sensitive disclosure"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D264",
        "Excessive agent tool privilege",
        "security",
        "HIGH",
        aliases=("excessive agency", "dangerous agent tool"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D265",
        "Unsafe ML model deserialization",
        "security",
        "CRITICAL",
        aliases=("model deserialization", "pickle model"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D266",
        "AI config instruction injection",
        "security",
        "CRITICAL",
        aliases=("rules file backdoor", "agent instruction injection"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D267",
        "Unbounded LLM consumption",
        "security",
        "MEDIUM",
        aliases=("llm cost blowup", "unbounded consumption"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D270",
        "Sensitive data in storage",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D271",
        "Error information disclosure over HTTP",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D280",
        "Next.js mutating API route missing authentication",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D281",
        "Next.js server action SQL injection",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D282",
        "Webhook signature verification issue",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D290",
        "GitHub Actions dangerous trigger",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D291",
        "GitHub Actions excessive permissions",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D292",
        "GitHub Actions unpinned action",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D293",
        "GitHub Actions persisted checkout credentials",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D294",
        "GitHub Actions template injection",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D295",
        "GitHub Actions self-hosted runner",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D296",
        "GitHub Actions unpinned container image",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D297",
        "GitHub Actions secrets inheritance",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D298",
        "GitHub Actions overprovisioned secrets",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D299",
        "GitHub Actions secret outside environment",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D300",
        "GitHub Actions unsafe environment file write",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D301",
        "GitHub Actions hardcoded container credential",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D302",
        "GitHub Actions broad GitHub App token",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D303",
        "GitHub Actions unsound contains condition",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D304",
        "GitHub Actions spoofable bot condition",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D305",
        "GitHub Actions unsound multiline condition",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D306",
        "GitHub Actions insecure commands enabled",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D307",
        "GitHub Actions anonymous definition",
        "security",
        "LOW",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D308",
        "GitHub Actions cache poisoning risk",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D309",
        "GitHub Actions broad secret environment",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D310",
        "GitHub Actions OIDC build-script exposure",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D311",
        "GitHub Actions lax artifact upload",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D312",
        "GitHub Actions JavaScript install scripts",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D313",
        "GitHub Actions privileged job missing timeout",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D350",
        "GitHub Actions AI agent on untrusted trigger without actor gate",
        "security",
        "CRITICAL",
        aliases=("ai agent", "claude-code-action", "run-gemini-cli", "prompt injection"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D351",
        "GitHub Actions AI agent write-access check widened",
        "security",
        "CRITICAL",
        aliases=("allowed_non_write_users", "allowed_bots", "allow-users"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D352",
        "GitHub Actions AI agent with shell on untrusted trigger",
        "security",
        "HIGH",
        aliases=("dangerously-skip-permissions", "yolo", "danger-full-access"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D353",
        "GitHub Actions untrusted text in AI agent prompt",
        "security",
        "HIGH",
        aliases=("prompt injection", "agent prompt"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D354",
        "GitHub Actions AI agent action with published advisory",
        "security",
        "HIGH",
        aliases=("GHSA-8q5r-mmjf-575q", "GHSA-wpqr-6v78-jr5g"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D510", "Prototype pollution", "security", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-D314",
        "GitLab CI mutable container image",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D315",
        "GitLab CI unpinned external include",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D316",
        "GitLab CI literal secret variable",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D317",
        "GitLab CI untrusted eval",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D318",
        "GitLab CI Docker-in-Docker TLS disabled",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D319",
        "GitLab CI OIDC local-script exposure",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D320",
        "GitLab CI release cache poisoning risk",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D321",
        "GitLab CI privileged job missing timeout",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D322",
        "GitLab CI dynamic runner tag",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D323",
        "GitLab CI ambiguous secret token",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D324",
        "Symlink-following file write",
        "security",
        "HIGH",
        aliases=("symlink",),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D325",
        "Symlink-following file read",
        "security",
        "MEDIUM",
        aliases=("symlink",),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D326",
        "Unsafe archive extraction",
        "security",
        "HIGH",
        aliases=("zip slip", "symlink"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D327",
        "Shell or agent data exfiltration",
        "security",
        "CRITICAL",
        aliases=("exfiltration", "secret exfiltration"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D328",
        "Remote script piped to shell",
        "security",
        "HIGH",
        aliases=("curl bash", "remote script"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D329",
        "Broad destructive shell command",
        "security",
        "HIGH",
        aliases=("destructive command",),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D330",
        "Docker Compose privileged edge container",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D331",
        "Docker Compose host device exposure",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D332",
        "Docker Compose host networking on edge service",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D333",
        "Systemd edge service runs as root",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D334",
        "Systemd root service executes mutable path",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D335",
        "Systemd edge service missing sandboxing",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D336",
        "Systemd broad edge service privilege",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D337",
        "Package registry or index override",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D338",
        "Sensitive host scope access",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D339",
        "Persistent environment mutation",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D340",
        "Unapproved package or artifact publish",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D341",
        "Untrusted package-managed tool execution",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D342",
        "Dockerfile remote ADD without checksum",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D343",
        "Dockerfile literal secret build value",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D344",
        "Trojan Source bidirectional Unicode",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D345",
        "Mutable Hugging Face artifact revision",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D346",
        "Flask debug mode enabled",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D347",
        "Unsafe logging config listener",
        "security",
        "MEDIUM",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D348",
        "Insecure temporary filename",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-D349",
        "Server-side template injection",
        "security",
        "CRITICAL",
        aliases=("ssti", "template injection"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-DEP001",
        "Externally deployed route is missing a required auth guard",
        "security",
        "HIGH",
        aliases=("deployment", "kubernetes", "ingress", "route guard"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-DEP002",
        "External Ingress exposes the Flask development debugger",
        "security",
        "HIGH",
        aliases=("deployment", "kubernetes", "ingress", "flask debug"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-DEP003",
        "External Ingress routes to a reload-mode application server",
        "reliability",
        "MEDIUM",
        aliases=("deployment", "kubernetes", "ingress", "reload"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-GPU000",
        "GPU release contract is invalid or incomplete",
        "reliability",
        "HIGH",
        aliases=("gpu", "cuda", "release contract", "compatibility proof"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-GPU001",
        "CUDA image requires newer NVIDIA driver",
        "reliability",
        "HIGH",
        aliases=("gpu", "cuda", "driver", "container"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-GPU002",
        "CUDA target architecture missing from build",
        "reliability",
        "HIGH",
        aliases=("gpu", "cuda", "architecture", "ptx"),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-GPU003",
        "TensorRT engine is not portable across target GPUs",
        "reliability",
        "HIGH",
        aliases=("gpu", "tensorrt", "engine", "portability"),
        finding_type="review",
    ),
    # Go reliability checks follow their Python equivalent (SKY-L008 missing
    # resource cleanup, MEDIUM); unsafe use follows gosec G103 (LOW).
    RuleCatalogEntry(
        "SKY-G203", "Go defer in loop", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-G206",
        "Go unsafe package import",
        "security",
        "LOW",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-G207", "Go weak MD5 hash", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-G208", "Go weak SHA1 hash", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-G209", "Go weak RNG", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-G210",
        "Go TLS verification disabled",
        "security",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-G211", "Go SQL injection", "security", "CRITICAL", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-G212",
        "Go command injection",
        "security",
        "CRITICAL",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-G215", "Go path traversal", "security", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-G216",
        "Go SSRF",
        "security",
        "CRITICAL",
        aliases=("ssrf",),
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-G220", "Go open redirect", "security", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-G221", "Go insecure cookie", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-G260", "Go unclosed resource", "security", "MEDIUM", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-G280", "Go weak TLS version", "security", "HIGH", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-S101", "Secret detected", "secrets", "CRITICAL", finding_type="review"
    ),
    RuleCatalogEntry(
        "SKY-S102",
        "Client-side secret exposure",
        "secrets",
        "HIGH",
        finding_type="review",
    ),
    RuleCatalogEntry(
        "SKY-SC001",
        "Smart contract security issue",
        "security",
        "HIGH",
        finding_type="review",
    ),
)

_BY_ID = {}
for entry in _RULES:
    if entry.id in _BY_ID:
        raise ValueError(f"Duplicate rule ID: {entry.id}")
    if entry.finding_type not in {"defect", "review", "advice"}:
        raise ValueError(f"Invalid finding type for {entry.id}: {entry.finding_type}")
    _BY_ID[entry.id] = entry

# Compatibility for callers that identify maintainability advice. Reporting
# retains all three finding types; this set no longer defines hidden findings.
ADVISORY_QUALITY_RULES = frozenset(
    entry.id
    for entry in _RULES
    if entry.category == "quality" and entry.finding_type == "advice"
)


def get_rule_catalog(query: str | None = None) -> list[dict]:
    entries = sorted(_RULES, key=lambda entry: entry.id)
    normalized_query = _normalize(query or "")

    if normalized_query:
        terms = normalized_query.split()
        filtered_entries = []

        for entry in entries:
            search_text = _rule_search_text(entry)
            matched = True

            for term in terms:
                if term not in search_text:
                    matched = False
                    break

            if matched:
                filtered_entries.append(entry)

        entries = filtered_entries

    result = []
    for entry in entries:
        result.append(entry.to_dict())
    return result


def get_rule_name(rule_id: str, default: str = "Security issue") -> str:
    entry = _BY_ID.get(str(rule_id))
    if entry:
        return entry.name
    else:
        return default


def get_rule_finding_type(rule_id) -> str:
    """Return the catalog classification; unknown rules require review."""
    entry = _BY_ID.get(str(rule_id or "").strip().upper())
    return entry.finding_type if entry is not None else "review"


def is_advisory_quality_rule(rule_id) -> bool:
    entry = _BY_ID.get(str(rule_id or "").strip().upper())
    return bool(
        entry and entry.category == "quality" and entry.finding_type == "advice"
    )


def _rule_search_text(entry: RuleCatalogEntry) -> str:
    parts = [entry.id, entry.name, entry.category, entry.finding_type]

    if entry.severity:
        parts.append(entry.severity)

    for alias in entry.aliases:
        parts.append(alias)

    return _normalize(" ".join(parts))


def _normalize(value: str) -> str:
    text = str(value)
    text = text.casefold()
    text = text.replace("-", " ")
    text = text.replace("_", " ")
    return text
