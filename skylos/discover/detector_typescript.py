from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from skylos.discover.integration import LLMIntegration
from skylos.visitors.languages.typescript.core import TypeScriptCore

TS_AI_EXTENSIONS = {
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
}

TS_PROVIDER_BY_IMPORT = {
    "openai": "OpenAI",
    "@anthropic-ai/sdk": "Anthropic",
    "@google/genai": "Google Gemini",
    "@google/generative-ai": "Google Gemini",
    "litellm": "LiteLLM",
    "ai": "Vercel AI SDK",
    "@ai-sdk/openai": "OpenAI",
    "@ai-sdk/anthropic": "Anthropic",
    "@ai-sdk/google": "Google Gemini",
    "@openai/agents": "OpenAI Agents SDK",
    "@anthropic-ai/claude-agent-sdk": "Claude Agent SDK",
}

TS_PROVIDER_BY_CONSTRUCTOR = {
    "OpenAI": "OpenAI",
    "Anthropic": "Anthropic",
    "GoogleGenAI": "Google Gemini",
    "GoogleGenerativeAI": "Google Gemini",
    "ChatOpenAI": "LangChain",
    "ChatAnthropic": "LangChain",
    "ChatGoogleGenerativeAI": "LangChain",
}

FLOATING_MODEL_ALIASES = {
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4.1",
    "gpt-4.1-mini",
    "gpt-4",
    "gpt-4-turbo",
    "gpt-3.5-turbo",
    "o1",
    "o1-mini",
    "o1-preview",
    "o3",
    "o3-mini",
    "o4-mini",
    "claude-3-opus",
    "claude-3-sonnet",
    "claude-3-haiku",
    "claude-3-5-sonnet",
    "claude-3-5-haiku",
    "claude-sonnet-4",
    "claude-haiku-4",
    "claude-opus-4",
    "gemini-pro",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
    "gemini-2.0-flash",
    "gemini-2.5-pro",
    "latest",
    "default",
}

PINNED_MODEL_RE = re.compile(r"-\d{4}-?\d{2}-?\d{2}")
IMPORT_RE = re.compile(
    r"import\s+(?P<clause>.+?)\s+from\s+['\"](?P<source>[^'\"]+)['\"]",
    re.DOTALL,
)
REQUIRE_DESTRUCT_RE = re.compile(
    r"(?:const|let|var)\s*{\s*(?P<names>[^}]+)\}\s*=\s*require\(\s*['\"](?P<source>[^'\"]+)['\"]\s*\)"
)
REQUIRE_DEFAULT_RE = re.compile(
    r"(?:const|let|var)\s+(?P<local>[A-Za-z_]\w*)\s*=\s*require\(\s*['\"](?P<source>[^'\"]+)['\"]\s*\)"
)
CLIENT_RE = re.compile(
    r"(?:const|let|var)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*new\s+"
    r"(?P<ctor>[A-Za-z_]\w*)\s*\((?P<args>.*?)\)",
    re.DOTALL,
)
GOOGLE_MODEL_RE = re.compile(
    r"(?:const|let|var)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<base>[A-Za-z_]\w*)\.getGenerativeModel\s*\((?P<args>.*?)\)",
    re.DOTALL,
)

MODEL_STRING_RE = re.compile(r"\bmodel\s*:\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
MODEL_FACTORY_RE = re.compile(
    r"\bmodel\s*:\s*(?P<factory>[A-Za-z_]\w*)\(\s*['\"](?P<model>[^'\"]+)['\"]",
    re.IGNORECASE,
)
MAX_TOKENS_RE = re.compile(
    r"\b(max_tokens|max_output_tokens|maxTokens|maxOutputTokens)\s*:",
    re.IGNORECASE,
)
SYSTEM_PROMPT_RE = re.compile(
    r"\b(system|systemPrompt)\s*:|role\s*:\s*['\"]system['\"]",
    re.IGNORECASE,
)
PROMPT_PAYLOAD_RE = re.compile(
    r"\b(prompt|messages|contents|input)\s*:|\.invoke\s*\(",
    re.IGNORECASE,
)
PROMPT_CONTEXT_RE = re.compile(
    r"\b(prompt|message|messages|input|content|contents|context|template|system)\b\s*[:=]",
    re.IGNORECASE,
)
PROMPT_CONTINUATION_RE = re.compile(
    r"\b(prompt|message|messages|input|content|contents|context|template|system)\b\s*[:=]\s*$",
    re.IGNORECASE,
)
PROMPT_DELIMITER_RE = [
    re.compile(r"```"),
    re.compile(r"<(user_input|user_message|context|query|document|instructions)>"),
    re.compile(r"<\w+>.*</\w+>", re.DOTALL),
]
VALIDATION_PATTERNS = [
    (re.compile(r"\bJSON\.parse\s*\("), "JSON.parse"),
    (re.compile(r"\.\s*parse\s*\("), "schema.parse"),
    (re.compile(r"\.\s*safeParse\s*\("), "schema.safeParse"),
    (re.compile(r"\bvalidate\s*\("), "validate"),
]
INPUT_LIMIT_PATTERNS = [
    (re.compile(r"\.\s*(slice|substring)\s*\(\s*0\s*,\s*\d+\s*\)"), "input slice"),
    (
        re.compile(r"\b\w+\s*\.\s*length\s*(?:>|>=|<|<=)\s*\d+", re.IGNORECASE),
        "input length check",
    ),
]
REQUEST_INPUT_PATTERNS = [
    (re.compile(r"\brequest\s*\.\s*json\s*\("), "Request JSON body"),
    (re.compile(r"\brequest\s*\.\s*formData\s*\("), "Request form data"),
    (re.compile(r"\brequest\s*\.\s*body\b"), "Request body"),
    (re.compile(r"\breq\s*\.\s*body\b"), "Express body"),
    (re.compile(r"\breq\s*\.\s*query\b"), "Express query params"),
    (re.compile(r"\breq\s*\.\s*params\b"), "Express route params"),
    (re.compile(r"\bsearchParams\s*\.\s*get\s*\("), "Search params"),
    (re.compile(r"\bformData\s*\.\s*get\s*\("), "Form data"),
]
LOGGING_RE = re.compile(
    r"\b(console\.(log|info|warn|error)|logger\.(debug|info|warn|error)|helicone|langsmith)\b",
    re.IGNORECASE,
)
RATE_LIMIT_RE = re.compile(
    r"\b(rateLimit|rateLimiter|ratelimit|Ratelimit|throttle|express-rate-limit|@upstash/ratelimit)\b",
    re.IGNORECASE,
)
PII_FILTER_RE = re.compile(r"\b(redact|pii|presidio|scrubadub)\b", re.IGNORECASE)
RAG_RE = re.compile(
    r"\b(retriever|vectorStore|similaritySearch|retrievedDocs|documents|context)\b",
    re.IGNORECASE,
)
DANGEROUS_SINK_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function"),
    (re.compile(r"\bexecSync\s*\("), "execSync"),
    (re.compile(r"\bexec\s*\("), "exec"),
    (re.compile(r"\bspawnSync\s*\("), "spawnSync"),
    (re.compile(r"\bspawn\s*\("), "spawn"),
]


@dataclass(frozen=True)
class JSImport:
    local_name: str
    source: str
    imported_name: str


@dataclass(frozen=True)
class TSClient:
    variable_name: str
    constructor_name: str
    provider: str
    model_value: str = ""


def collect_typescript_files(root: Path, exclude_folders: set[str]) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TS_AI_EXTENSIONS:
            continue
        if _should_skip_typescript_file(root, path, exclude_folders):
            continue
        files.append(path)
    return sorted(files)


def scan_typescript_file(
    root: Path, ts_file: Path
) -> tuple[str, list[LLMIntegration]] | None:
    try:
        source_bytes = ts_file.read_bytes()
    except OSError:
        return None

    source_text = source_bytes.decode("utf-8", errors="ignore")
    rel = str(ts_file.relative_to(root))

    core = TypeScriptCore(rel, source_bytes)
    imports = _parse_imports(source_text)
    clients = _detect_clients(source_text, imports)

    if not core.root_node:
        return rel, []

    integrations: list[LLMIntegration] = []
    seen: set[tuple[str, str, str]] = set()

    for call_node in _iter_call_nodes(core.root_node):
        func_node = call_node.child_by_field_name("function")
        if func_node is None:
            continue

        function_text = core._get_text(func_node)
        call_text = core._get_text(call_node)
        classified = _classify_call(function_text, imports, clients)
        if classified is None:
            continue

        provider, integration_type, client_name = classified
        location = f"{rel}:{call_node.start_point[0] + 1}"
        dedupe_key = (location, provider, integration_type)
        if dedupe_key in seen:
            continue

        scope_node = _find_scope_node(call_node) or core.root_node
        scope_text = core._get_text(scope_node)
        scope_start_line = scope_node.start_point[0] + 1

        model_value = _extract_model_value(call_text, imports, clients, client_name)
        input_sources = _collect_pattern_hits(
            scope_text, scope_start_line, REQUEST_INPUT_PATTERNS
        )
        output_validation_location = _first_pattern_location(
            scope_text, scope_start_line, VALIDATION_PATTERNS
        )
        input_length_limit_location = _first_pattern_location(
            scope_text, scope_start_line, INPUT_LIMIT_PATTERNS
        )
        output_sinks = _collect_pattern_hits(
            scope_text, scope_start_line, DANGEROUS_SINK_PATTERNS
        )

        prompt_sites: list[str] = []
        if integration_type != "embedding" and PROMPT_PAYLOAD_RE.search(
            call_text.replace("\n", " ")
        ):
            prompt_sites.append(location)

        integrations.append(
            LLMIntegration(
                provider=provider,
                location=location,
                integration_type=integration_type,
                prompt_sites=prompt_sites,
                input_sources=input_sources,
                output_sinks=output_sinks,
                has_system_prompt=bool(SYSTEM_PROMPT_RE.search(call_text)),
                model_pinned=_is_model_pinned(model_value),
                model_value=model_value,
                has_output_validation=bool(output_validation_location),
                output_validation_location=output_validation_location,
                has_prompt_delimiter=_has_prompt_delimiter(scope_text, call_text),
                has_input_length_limit=bool(input_length_limit_location),
                input_length_limit_location=input_length_limit_location,
                has_rag_context=bool(RAG_RE.search(scope_text)) and bool(prompt_sites),
                has_pii_filter=bool(PII_FILTER_RE.search(scope_text)),
                has_logging=bool(LOGGING_RE.search(scope_text)),
                has_max_tokens=bool(MAX_TOKENS_RE.search(call_text)),
                has_rate_limiting=bool(RATE_LIMIT_RE.search(scope_text)),
            )
        )
        seen.add(dedupe_key)

    return rel, integrations


def _should_skip_typescript_file(
    root: Path, path: Path, exclude_folders: set[str]
) -> bool:
    parts = path.relative_to(root).parts
    if any(part in exclude_folders for part in parts):
        return True
    if any(part.endswith(".egg-info") for part in parts):
        return True
    if path.name.endswith(".d.ts"):
        return True
    return False


def _parse_imports(source_text: str) -> dict[str, JSImport]:
    imports: dict[str, JSImport] = {}
    for match in IMPORT_RE.finditer(source_text):
        clause = match.group("clause").strip()
        source = match.group("source").strip()
        for imp in _parse_import_clause(clause, source):
            imports[imp.local_name] = imp

    for match in REQUIRE_DESTRUCT_RE.finditer(source_text):
        source = match.group("source").strip()
        for imp in _parse_commonjs_names(match.group("names"), source):
            imports[imp.local_name] = imp

    for match in REQUIRE_DEFAULT_RE.finditer(source_text):
        local = match.group("local").strip()
        source = match.group("source").strip()
        imports[local] = JSImport(local, source, "default")

    return imports


def _parse_import_clause(clause: str, source: str) -> list[JSImport]:
    clause = clause.replace("\n", " ").strip()
    items: list[JSImport] = []

    if clause.startswith("type "):
        clause = clause[5:].strip()

    if clause.startswith("* as "):
        local = clause[5:].strip()
        if local:
            items.append(JSImport(local, source, "*"))
        return items

    named_part = ""
    if "{" in clause and "}" in clause:
        start = clause.index("{")
        end = clause.rindex("}")
        named_part = clause[start + 1 : end]
        prefix = clause[:start].rstrip(", ").strip()
        if prefix:
            items.append(JSImport(prefix, source, "default"))
    elif clause:
        items.append(JSImport(clause, source, "default"))
        return items

    for spec in named_part.split(","):
        spec = spec.strip()
        if not spec or spec == "type":
            continue
        if spec.startswith("type "):
            spec = spec[5:].strip()
        if " as " in spec:
            imported_name, local_name = [part.strip() for part in spec.split(" as ", 1)]
        else:
            imported_name = spec
            local_name = spec
        items.append(JSImport(local_name, source, imported_name))

    return items


def _parse_commonjs_names(names: str, source: str) -> list[JSImport]:
    items: list[JSImport] = []
    for spec in names.split(","):
        spec = spec.strip()
        if not spec:
            continue
        if ":" in spec:
            imported_name, local_name = [part.strip() for part in spec.split(":", 1)]
        else:
            imported_name = spec
            local_name = spec
        items.append(JSImport(local_name, source, imported_name))
    return items


def _detect_clients(
    source_text: str, imports: dict[str, JSImport]
) -> dict[str, TSClient]:
    clients: dict[str, TSClient] = {}
    for match in CLIENT_RE.finditer(source_text):
        variable_name = match.group("name")
        constructor_name = match.group("ctor")
        args_text = match.group("args")

        imported = imports.get(constructor_name)
        provider = TS_PROVIDER_BY_CONSTRUCTOR.get(constructor_name)
        if provider is None and imported is not None:
            provider = TS_PROVIDER_BY_IMPORT.get(imported.source)
        if provider is None:
            continue

        model_value = _extract_model_value_from_text(args_text, imports)
        clients[variable_name] = TSClient(
            variable_name=variable_name,
            constructor_name=constructor_name,
            provider=provider,
            model_value=model_value,
        )

    for match in GOOGLE_MODEL_RE.finditer(source_text):
        variable_name = match.group("name")
        base_name = match.group("base")
        args_text = match.group("args")
        base_client = clients.get(base_name)
        if base_client is not None and base_client.provider == "Google Gemini":
            clients[variable_name] = TSClient(
                variable_name=variable_name,
                constructor_name="GenerativeModel",
                provider="Google Gemini",
                model_value=_extract_model_value_from_text(args_text, imports),
            )
    return clients


def _iter_call_nodes(root_node):
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == "call_expression":
            yield node
        for child in reversed(node.children):
            stack.append(child)


def _find_scope_node(node):
    current = node
    while current is not None:
        if current.type in {
            "function_declaration",
            "arrow_function",
            "function_expression",
            "method_definition",
            "program",
        }:
            return current
        current = current.parent
    return None


def _classify_call(
    function_text: str,
    imports: dict[str, JSImport],
    clients: dict[str, TSClient],
) -> tuple[str, str, str] | None:
    member_match = re.fullmatch(
        r"(?P<obj>[A-Za-z_]\w*)\.(?P<path>[A-Za-z_][\w\.]*)", function_text
    )
    if member_match:
        obj = member_match.group("obj")
        path = member_match.group("path")
        client = clients.get(obj)
        if client is not None:
            if path in {
                "chat.completions.create",
                "responses.create",
                "messages.create",
            }:
                return client.provider, "chat", obj
            if path == "embeddings.create":
                return client.provider, "embedding", obj
            if path in {
                "models.generateContent",
                "models.generateContentStream",
                "generateContent",
                "generateContentStream",
            }:
                return client.provider, "chat", obj
            if path == "invoke":
                return client.provider, "chat", obj

        imported_ns = imports.get(obj)
        if imported_ns is not None and imported_ns.source == "ai":
            if path in {"generateText", "streamText", "generateObject"}:
                return "Vercel AI SDK", "chat", ""
            if path in {"embed", "embedMany"}:
                return "Vercel AI SDK", "embedding", ""
        if imported_ns is not None and imported_ns.source == "litellm":
            if path in {"completion", "acompletion"}:
                return "LiteLLM", "chat", ""
            if path == "embedding":
                return "LiteLLM", "embedding", ""

    imported = imports.get(function_text)
    if imported is None:
        return None

    if imported.source == "ai" and function_text in {
        "generateText",
        "streamText",
        "generateObject",
    }:
        return "Vercel AI SDK", "chat", ""

    if imported.source == "ai" and function_text in {"embed", "embedMany"}:
        return "Vercel AI SDK", "embedding", ""

    if imported.source == "litellm" and function_text in {"completion", "acompletion"}:
        return "LiteLLM", "chat", ""

    if imported.source == "litellm" and function_text == "embedding":
        return "LiteLLM", "embedding", ""

    if imported.source == "@openai/agents" and function_text == "run":
        return "OpenAI Agents SDK", "agent", ""

    if imported.source == "@anthropic-ai/claude-agent-sdk" and function_text == "query":
        return "Claude Agent SDK", "agent", ""

    return None


def _extract_model_value(
    call_text: str,
    imports: dict[str, JSImport],
    clients: dict[str, TSClient],
    client_name: str,
) -> str:
    model_value = _extract_model_value_from_text(call_text, imports)
    if model_value:
        return model_value
    client = clients.get(client_name)
    if client is not None:
        return client.model_value
    return ""


def _extract_model_value_from_text(text: str, imports: dict[str, JSImport]) -> str:
    match = MODEL_STRING_RE.search(text)
    if match:
        return match.group(1).strip()

    match = MODEL_FACTORY_RE.search(text)
    if match:
        factory_name = match.group("factory").strip()
        imported = imports.get(factory_name)
        if imported is not None and imported.source.startswith("@ai-sdk/"):
            return match.group("model").strip()
    return ""


def _is_model_pinned(model_value: str) -> bool:
    if not model_value:
        return False
    lowered = model_value.lower().strip()
    if lowered in FLOATING_MODEL_ALIASES:
        return False
    return bool(PINNED_MODEL_RE.search(model_value))


def _has_prompt_delimiter(scope_text: str, call_text: str) -> bool:
    candidates = list(_extract_string_literals(call_text))
    lines = scope_text.splitlines()
    for idx, line in enumerate(lines):
        if not PROMPT_CONTEXT_RE.search(line):
            continue
        literals = _extract_string_literals(line)
        if literals:
            candidates.extend(literals)
            continue

        if idx + 1 < len(lines) and PROMPT_CONTINUATION_RE.search(line):
            candidates.extend(_extract_string_literals(lines[idx + 1]))

    for literal in candidates:
        for pattern in PROMPT_DELIMITER_RE:
            if pattern.search(literal):
                return True
    return False


def _extract_string_literals(scope_text: str) -> list[str]:
    literals: list[str] = []
    current = 0
    while current < len(scope_text):
        quote = scope_text[current]
        if quote not in {"'", '"', "`"}:
            current += 1
            continue

        end = current + 1
        escaped = False
        while end < len(scope_text):
            char = scope_text[end]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                literals.append(scope_text[current : end + 1])
                current = end
                break
            end += 1
        current += 1
    return literals


def _collect_pattern_hits(
    text: str, base_line: int, patterns: list[tuple[re.Pattern[str], str]]
) -> list[str]:
    hits: list[str] = []
    seen: set[str] = set()
    for pattern, label in patterns:
        for match in pattern.finditer(text):
            line = base_line + text.count("\n", 0, match.start())
            item = f"{label} (L{line})"
            if item not in seen:
                hits.append(item)
                seen.add(item)
    return hits


def _first_pattern_location(
    text: str, base_line: int, patterns: list[tuple[re.Pattern[str], str]]
) -> str:
    best_line: int | None = None
    best_label = ""
    for pattern, label in patterns:
        match = pattern.search(text)
        if match is None:
            continue
        line = base_line + text.count("\n", 0, match.start())
        if best_line is None or line < best_line:
            best_line = line
            best_label = label
    if best_line is None:
        return ""
    return f"{best_label} (L{best_line})"
