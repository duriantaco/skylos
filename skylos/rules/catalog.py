from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class RuleCatalogEntry:
    id: str
    name: str
    category: str
    severity: str | None = None
    source: str = "builtin"
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["aliases"] = list(self.aliases)
        return data

# Keep this catalog aligned with skylos-docs/docs/rules-reference.mdx.
_RULES = (
    RuleCatalogEntry("SKY-U001", "Unused function", "dead_code"),
    RuleCatalogEntry("SKY-U002", "Unused import", "dead_code"),
    RuleCatalogEntry("SKY-U003", "Unused variable", "dead_code"),
    RuleCatalogEntry("SKY-U004", "Unused class", "dead_code"),
    RuleCatalogEntry("SKY-U005", "Unused dependency", "dead_code"),
    RuleCatalogEntry("SKY-U006", "Unused parameter", "dead_code"),
    RuleCatalogEntry("SKY-UC001", "Unreachable Python code", "dead_code"),
    RuleCatalogEntry("SKY-UC002", "Unreachable statement", "dead_code"),
    RuleCatalogEntry("SKY-C401", "Duplicated code clone", "quality"),
    RuleCatalogEntry("SKY-CIRC", "Circular dependency", "quality"),
    RuleCatalogEntry("SKY-Q301", "Cyclomatic complexity", "quality"),
    RuleCatalogEntry("SKY-Q302", "Deep nesting", "quality"),
    RuleCatalogEntry("SKY-C303", "Too many function arguments", "quality"),
    RuleCatalogEntry("SKY-C304", "Function too long", "quality"),
    RuleCatalogEntry("SKY-Q305", "Duplicate branch logic", "quality"),
    RuleCatalogEntry("SKY-Q306", "Cognitive complexity", "quality"),
    RuleCatalogEntry("SKY-Q401", "Async blocking call", "quality"),
    RuleCatalogEntry("SKY-Q402", "Await in loop", "quality", "MEDIUM"),
    RuleCatalogEntry("SKY-Q501", "God class", "quality"),
    RuleCatalogEntry("SKY-Q502", "Class too large", "quality"),
    RuleCatalogEntry("SKY-Q701", "High coupling", "quality"),
    RuleCatalogEntry("SKY-Q702", "Low cohesion", "quality"),
    RuleCatalogEntry("SKY-Q801", "High instability", "quality", "MEDIUM"),
    RuleCatalogEntry("SKY-Q802", "High distance from main sequence", "quality"),
    RuleCatalogEntry("SKY-Q803", "Architecture zone warning", "quality"),
    RuleCatalogEntry("SKY-Q804", "Dependency inversion violation", "quality"),
    RuleCatalogEntry("SKY-Q805", "Architecture layer policy violation", "quality"),
    RuleCatalogEntry("SKY-Q806", "Opaque identifier", "quality", "LOW"),
    RuleCatalogEntry("SKY-L001", "Mutable default argument", "quality"),
    RuleCatalogEntry("SKY-L002", "Bare except block", "quality"),
    RuleCatalogEntry("SKY-L003", "Dangerous comparison", "quality"),
    RuleCatalogEntry("SKY-L004", "Anti-pattern try block", "quality"),
    RuleCatalogEntry("SKY-L005", "Unused exception variable", "quality"),
    RuleCatalogEntry("SKY-L006", "Shadowed loop variable", "quality"),
    RuleCatalogEntry("SKY-L007", "Confusing boolean expression", "quality"),
    RuleCatalogEntry("SKY-L008", "Suspicious branch condition", "quality"),
    RuleCatalogEntry("SKY-L009", "Debug leftover", "quality"),
    RuleCatalogEntry("SKY-L010", "Security TODO marker", "quality"),
    RuleCatalogEntry("SKY-L011", "Disabled security control", "quality"),
    RuleCatalogEntry("SKY-L012", "Phantom function call", "quality"),
    RuleCatalogEntry("SKY-L013", "Insecure randomness", "quality"),
    RuleCatalogEntry("SKY-L014", "Hardcoded credential", "quality"),
    RuleCatalogEntry("SKY-L016", "Undefined config", "quality"),
    RuleCatalogEntry("SKY-L017", "Error information disclosure", "quality"),
    RuleCatalogEntry("SKY-L020", "Overly broad file permissions", "quality"),
    RuleCatalogEntry("SKY-L021", "Security regression", "quality"),
    RuleCatalogEntry("SKY-L023", "Phantom decorator", "quality"),
    RuleCatalogEntry("SKY-L024", "Stale mock", "quality"),
    RuleCatalogEntry("SKY-L026", "Unfinished generated code", "quality"),
    RuleCatalogEntry("SKY-L027", "Duplicate string literal", "quality"),
    RuleCatalogEntry("SKY-L028", "Too many returns", "quality"),
    RuleCatalogEntry("SKY-L029", "Boolean trap", "quality"),
    RuleCatalogEntry("SKY-L030", "Broad exception with trivial handler", "quality"),
    RuleCatalogEntry("SKY-L031", "Missing network timeout", "quality"),
    RuleCatalogEntry("SKY-L032", "Mock or placeholder data", "quality"),
    RuleCatalogEntry("SKY-L033", "No-effect statement", "quality"),
    RuleCatalogEntry("SKY-P401", "Inefficient loop pattern", "quality"),
    RuleCatalogEntry("SKY-P402", "Repeated expensive operation", "quality"),
    RuleCatalogEntry("SKY-P403", "Suspicious performance pattern", "quality"),
    RuleCatalogEntry("SKY-T101", "Missing type annotations", "quality"),
    RuleCatalogEntry("SKY-T102", "Weak framework route typing", "quality"),
    RuleCatalogEntry("SKY-F101", "Framework route missing auth", "quality"),
    RuleCatalogEntry("SKY-F102", "Framework handler practice issue", "quality"),
    RuleCatalogEntry("SKY-R101", "Python type-check policy", "quality", "MEDIUM"),
    RuleCatalogEntry("SKY-R102", "Python lint policy", "quality", "LOW"),
    RuleCatalogEntry("SKY-R103", "Skylos gate policy", "quality", "LOW"),
    RuleCatalogEntry("SKY-R104", "Pre-commit policy", "quality", "LOW"),
    RuleCatalogEntry("SKY-R105", "TypeScript type-check policy", "quality", "LOW"),
    RuleCatalogEntry("SKY-E002", "Empty file", "quality", "LOW"),
    RuleCatalogEntry("SKY-D200", "Dangerous call pattern", "security"),
    RuleCatalogEntry("SKY-D201", "Dynamic code execution via eval", "security", "HIGH"),
    RuleCatalogEntry("SKY-D202", "Dynamic code execution via exec", "security", "HIGH"),
    RuleCatalogEntry("SKY-D203", "OS command execution", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D204", "Unsafe pickle deserialization", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D205", "Unsafe pickle.loads deserialization", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D206", "Unsafe YAML load", "security", "HIGH"),
    RuleCatalogEntry("SKY-D207", "Weak MD5 hash", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D208", "Weak SHA1 hash", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D209", "Subprocess shell execution", "security", "HIGH"),
    RuleCatalogEntry("SKY-D210", "TLS verification disabled", "security", "HIGH"),
    RuleCatalogEntry("SKY-D211", "SQL injection", "security", "CRITICAL", aliases=("sqli",)),
    RuleCatalogEntry("SKY-D212", "Command injection", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D214", "Broken access control", "security", "HIGH"),
    RuleCatalogEntry("SKY-D215", "Path traversal", "security", "HIGH", aliases=("lfi", "file traversal")),
    RuleCatalogEntry("SKY-D216", "Server-side request forgery", "security", "CRITICAL", aliases=("ssrf",),),
    RuleCatalogEntry("SKY-D217", "Raw SQL execution", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D222", "Dependency hallucination", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D223", "Undeclared third-party dependency", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D226", "Cross-site scripting: untrusted content marked safe", "security", "CRITICAL",aliases=("xss", "cross site scripting", "cross-site scripting"),),
    RuleCatalogEntry("SKY-D227", "Cross-site scripting: unsafe inline template", "security", "HIGH", aliases=("xss", "cross site scripting", "cross-site scripting"),),
    RuleCatalogEntry("SKY-D228", "Cross-site scripting: HTML built from user input", "security", "HIGH", aliases=("xss", "cross site scripting", "cross-site scripting"),),
    RuleCatalogEntry("SKY-D230", "Open redirect", "security", "HIGH", aliases=("redirect",)),
    RuleCatalogEntry("SKY-D231", "Unsafe CORS configuration", "security", "HIGH"),
    RuleCatalogEntry("SKY-D232", "Unsafe JWT handling", "security", "CRITICAL", aliases=("jwt",)),
    RuleCatalogEntry("SKY-D233", "Unsafe deserialization", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D234", "Mass assignment", "security", "HIGH"),
    RuleCatalogEntry("SKY-D235", "Remote command execution sink", "security", "HIGH"),
    RuleCatalogEntry("SKY-D240", "MCP tool description poisoning", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D241", "MCP unauthenticated network transport", "security", "HIGH"),
    RuleCatalogEntry("SKY-D242", "MCP overly permissive resource URI", "security", "HIGH"),
    RuleCatalogEntry("SKY-D243", "MCP network-exposed server without auth", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D244", "MCP hardcoded tool parameter secret", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D245", "Dynamic require", "security", "HIGH"),
    RuleCatalogEntry("SKY-D246", "JWT decode without verification", "security", "HIGH"),
    RuleCatalogEntry("SKY-D247", "CORS wildcard origin", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D248", "Hardcoded internal URL", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D250", "Weak random source", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D251", "Sensitive data in logs", "security", "HIGH"),
    RuleCatalogEntry("SKY-D252", "Insecure cookie", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D253", "Timing-unsafe comparison", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D260", "Prompt injection exposure", "security", "HIGH", aliases=("prompt injection", "hidden unicode"),),
    RuleCatalogEntry("SKY-D270", "Sensitive data in storage", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D271", "Error information disclosure over HTTP", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D282", "Webhook signature verification issue", "security", "HIGH"),
    RuleCatalogEntry("SKY-D290", "GitHub Actions dangerous trigger", "security", "HIGH"),
    RuleCatalogEntry("SKY-D291", "GitHub Actions excessive permissions", "security", "HIGH"),
    RuleCatalogEntry("SKY-D292", "GitHub Actions unpinned action", "security", "HIGH"),
    RuleCatalogEntry("SKY-D293", "GitHub Actions persisted checkout credentials", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D294", "GitHub Actions template injection", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-D295", "GitHub Actions self-hosted runner", "security", "HIGH"),
    RuleCatalogEntry("SKY-D296", "GitHub Actions unpinned container image", "security", "HIGH"),
    RuleCatalogEntry("SKY-D297", "GitHub Actions secrets inheritance", "security", "HIGH"),
    RuleCatalogEntry("SKY-D298", "GitHub Actions overprovisioned secrets", "security", "HIGH"),
    RuleCatalogEntry("SKY-D299", "GitHub Actions secret outside environment", "security", "HIGH"),
    RuleCatalogEntry("SKY-D300", "GitHub Actions unsafe environment file write", "security", "HIGH"),
    RuleCatalogEntry("SKY-D301", "GitHub Actions hardcoded container credential", "security", "HIGH"),
    RuleCatalogEntry("SKY-D302", "GitHub Actions broad GitHub App token", "security", "HIGH"),
    RuleCatalogEntry("SKY-D303", "GitHub Actions unsound contains condition", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D304", "GitHub Actions spoofable bot condition", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D305", "GitHub Actions unsound multiline condition", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D306", "GitHub Actions insecure commands enabled", "security", "HIGH"),
    RuleCatalogEntry("SKY-D307", "GitHub Actions anonymous definition", "security", "LOW"),
    RuleCatalogEntry("SKY-D308", "GitHub Actions cache poisoning risk", "security", "HIGH"),
    RuleCatalogEntry("SKY-D309", "GitHub Actions broad secret environment", "security", "HIGH"),
    RuleCatalogEntry("SKY-D310", "GitHub Actions OIDC build-script exposure", "security", "HIGH"),
    RuleCatalogEntry("SKY-D311", "GitHub Actions lax artifact upload", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D312", "GitHub Actions JavaScript install scripts", "security", "HIGH"),
    RuleCatalogEntry("SKY-D313", "GitHub Actions privileged job missing timeout", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D510", "Prototype pollution", "security", "HIGH"),
    RuleCatalogEntry("SKY-D314", "GitLab CI mutable container image", "security", "HIGH"),
    RuleCatalogEntry("SKY-D315", "GitLab CI unpinned external include", "security", "HIGH"),
    RuleCatalogEntry("SKY-D316", "GitLab CI literal secret variable", "security", "HIGH"),
    RuleCatalogEntry("SKY-D317", "GitLab CI untrusted eval", "security", "HIGH"),
    RuleCatalogEntry("SKY-D318", "GitLab CI Docker-in-Docker TLS disabled", "security", "HIGH"),
    RuleCatalogEntry("SKY-D319", "GitLab CI OIDC local-script exposure", "security", "HIGH"),
    RuleCatalogEntry("SKY-D320", "GitLab CI release cache poisoning risk", "security", "HIGH"),
    RuleCatalogEntry("SKY-D321", "GitLab CI privileged job missing timeout", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D322", "GitLab CI dynamic runner tag", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D323", "GitLab CI ambiguous secret token", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-D324", "Symlink-following file write", "security", "HIGH", aliases=("symlink",)),
    RuleCatalogEntry("SKY-D325", "Symlink-following file read", "security", "MEDIUM", aliases=("symlink",)),
    RuleCatalogEntry("SKY-D326", "Unsafe archive extraction", "security", "HIGH", aliases=("zip slip", "symlink")),
    RuleCatalogEntry("SKY-G203", "Go defer in loop", "security", "HIGH"),
    RuleCatalogEntry("SKY-G206", "Go unsafe package import", "security", "HIGH"),
    RuleCatalogEntry("SKY-G207", "Go weak MD5 hash", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-G208", "Go weak SHA1 hash", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-G209", "Go weak RNG", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-G210", "Go TLS verification disabled", "security", "HIGH"),
    RuleCatalogEntry("SKY-G211", "Go SQL injection", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-G212", "Go command injection", "security", "CRITICAL"),
    RuleCatalogEntry("SKY-G215", "Go path traversal", "security", "HIGH"),
    RuleCatalogEntry("SKY-G216", "Go SSRF", "security", "CRITICAL", aliases=("ssrf",)),
    RuleCatalogEntry("SKY-G220", "Go open redirect", "security", "HIGH"),
    RuleCatalogEntry("SKY-G221", "Go insecure cookie", "security", "MEDIUM"),
    RuleCatalogEntry("SKY-G260", "Go unclosed resource", "security", "HIGH"),
    RuleCatalogEntry("SKY-G280", "Go weak TLS version", "security", "HIGH"),
    RuleCatalogEntry("SKY-S101", "Secret detected", "secrets", "CRITICAL"),
    RuleCatalogEntry("SKY-S102", "High-entropy generic secret", "secrets", "HIGH"),
    RuleCatalogEntry("SKY-SC001", "Smart contract security issue", "security", "HIGH"),
)

_BY_ID = {}
for entry in _RULES:
    if entry.id in _BY_ID:
        raise ValueError(f"Duplicate rule ID: {entry.id}")
    _BY_ID[entry.id] = entry


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


def _rule_search_text(entry: RuleCatalogEntry) -> str:
    parts = [entry.id, entry.name, entry.category]

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
