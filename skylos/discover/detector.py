from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional

from skylos.discover.integration import LLMIntegration, ToolDef
from skylos.discover.graph import (
    AIIntegrationGraph,
    GraphNode,
    GraphEdge,
    NodeType,
)

KNOWN_LLM_SDKS: dict[str, str] = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "google.generativeai": "Google Gemini",
    "google.genai": "Google Gemini",
    "cohere": "Cohere",
    "mistralai": "Mistral",
    "ollama": "Ollama",
    "together": "Together AI",
    "groq": "Groq",
    "fireworks": "Fireworks",
    "replicate": "Replicate",
    "litellm": "LiteLLM",
}

KNOWN_FRAMEWORKS: dict[str, str] = {
    "langchain": "LangChain",
    "langchain_core": "LangChain",
    "langchain_openai": "LangChain",
    "langchain_anthropic": "LangChain",
    "langchain_community": "LangChain",
    "langgraph": "LangGraph",
    "llama_index": "LlamaIndex",
    "crewai": "CrewAI",
    "autogen": "AutoGen",
    "haystack": "Haystack",
    "semantic_kernel": "Semantic Kernel",
    "dspy": "DSPy",
    "smolagents": "SmolAgents",
    "pydantic_ai": "PydanticAI",
}

LLM_CALL_PATTERNS: list[tuple[str, str, str]] = [
    ("chat.completions", "create", "chat"),
    ("completions", "create", "completion"),
    ("embeddings", "create", "embedding"),
    ("responses", "create", "chat"),
    ("messages", "create", "chat"),
    ("GenerativeModel", "generate_content", "chat"),
    ("GenerativeModel", "generate_content_async", "chat"),
    ("Client", "chat", "chat"),
    ("Client", "generate", "completion"),
    ("Client", "embed", "embedding"),
    ("chat", "complete", "chat"),
    ("chat", "complete_async", "chat"),
    ("Client", "embeddings", "embedding"),
    ("litellm", "completion", "chat"),
    ("litellm", "acompletion", "chat"),
    ("litellm", "embedding", "embedding"),
    ("client", "chat", "chat"),
    ("llm", "invoke", "chat"),
    ("llm", "predict", "chat"),
    ("chain", "invoke", "chat"),
    ("chain", "run", "chat"),
    ("agent", "invoke", "agent"),
    ("agent", "run", "agent"),
    ("agent_executor", "invoke", "agent"),
]

_GENERIC_OBJS = {"client", "llm", "chain", "agent", "agent_executor"}

_EXCLUDED_CALL_PREFIXES = {
    "subprocess", "os", "sys", "shutil", "pathlib", "json", "re",
    "logging", "http", "urllib", "socket", "threading", "multiprocessing",
    "hashlib", "hmac", "base64", "struct", "io", "csv", "xml",
    "collections", "itertools", "functools", "contextlib",
}

FLOATING_MODEL_ALIASES = {
    "gpt-4o",
    "gpt-4o-mini",
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
    "latest",
    "default",
}

PINNED_MODEL_RE = re.compile(r"-\d{4}-?\d{2}-?\d{2}")

_RAG_IMPORT_MODULES = (
    "chromadb", "pinecone", "weaviate", "qdrant_client",
    "faiss", "langchain_community.vectorstores",
    "langchain.vectorstores", "llama_index.vector_stores",
    "langchain_community.retrievers", "langchain.retrievers",
)
_PII_IMPORT_MODULES = (
    "presidio_analyzer", "presidio_anonymizer", "scrubadub",
    "pii_tools", "commonregex",
)

_RATE_LIMIT_DECORATORS = {"limit", "rate_limit", "ratelimit", "throttle"}

DANGEROUS_SINKS = {
    "eval": "code_execution",
    "exec": "code_execution",
    "compile": "code_execution",
    "subprocess.run": "shell",
    "subprocess.call": "shell",
    "subprocess.Popen": "shell",
    "subprocess.check_output": "shell",
    "subprocess.check_call": "shell",
    "os.system": "shell",
    "os.popen": "shell",
    "os.execvp": "shell",
    "os.execve": "shell",
    "shutil.rmtree": "filesystem",
}

SQL_SINKS = {"execute", "executemany", "raw", "execute_sql"}

INPUT_SOURCE_PATTERNS: dict[str, str] = {
    "request.form": "Flask form",
    "request.args": "Flask query params",
    "request.json": "Flask JSON body",
    "request.get_json": "Flask JSON body",
    "request.data": "Flask raw data",
    "request.files": "Flask file upload",
    "Request.query_params": "FastAPI query params",
    "Request.body": "FastAPI body",
    "sys.argv": "CLI arguments",
    "input": "stdin",
}

DELIMITER_PATTERNS = [
    re.compile(r"```"),
    re.compile(r"<(user_input|user_message|input|context|query|document|retrieved|instructions)>"),
    re.compile(r"<\w+>.*</\w+>", re.DOTALL),  # matched XML tags
    re.compile(r"\[INST\]"),  # Llama-style
    re.compile(r'"""'),  # triple quotes as delimiters
]

OUTPUT_VALIDATION_CALLS = {
    "json.loads",
    "json.load",
    "jsonschema.validate",
    "pydantic.parse_obj",
    "pydantic.model_validate",
    "pydantic.parse_raw",
    "BaseModel.model_validate",
    "BaseModel.parse_obj",
    "BaseModel.parse_raw",
    "TypeAdapter.validate_python",
    "TypeAdapter.validate_json",
    "schema.validate",
    "marshmallow.load",
    "ast.literal_eval",
}

OUTPUT_VALIDATION_SIMPLE = {
    "loads",
    "load",
    "validate",
    "model_validate",
    "parse_obj",
    "parse_raw",
    "validate_python",
    "validate_json",
    "literal_eval",
}

LENGTH_CHECK_FUNCTIONS = {"len", "length", "size"}


class _LLMDetectorVisitor(ast.NodeVisitor):
    def generic_visit(self, node: ast.AST) -> None:
        for _field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def __init__(self, filepath: str, source: str):
        self.filepath = filepath
        self.source = source
        self.source_lines = source.splitlines()

        self.imports: dict[str, str] = {}
        self.from_imports: dict[str, str] = {}
        self.detected_sdks: dict[str, str] = {}  # module -> provider
        self.detected_frameworks: dict[str, str] = {}  # module -> framework

        self.integrations: list[LLMIntegration] = []
        self.tool_defs: list[ToolDef] = []
        self.input_sources: list[str] = []
        self.output_sinks: list[str] = []
        self.prompt_sites: list[str] = []
        self.has_system_prompt = False

        self._raw_llm_calls: list[dict] = []

        self._var_assignments: dict[str, int] = {}
        self._string_constants: dict[str, str] = {}
        self._llm_response_vars: set[str] = set()
        self._user_input_vars: set[str] = set()

        self._func_output_validation: dict[str, str] = {}
        self._func_length_limit: dict[str, str] = {}
        self._func_output_sinks: dict[str, list[str]] = {}
        self._func_input_sources: dict[str, list[str]] = {}

        self._has_prompt_delimiter = False

        self._func_logging: dict[str, str] = {}
        self._func_rate_limiting: dict[str, str] = {}
        self._func_rag_context: dict[str, str] = {}
        self._func_pii_filter: dict[str, str] = {}
        self._has_rag_imports = False
        self._has_pii_imports = False

        self._func_prompt_sites: dict[str, list[str]] = {}
        self._func_tool_defs: dict[str, list[ToolDef]] = {}
        self._func_has_system_prompt: dict[str, bool] = {}
        self._func_has_prompt_delimiter: dict[str, bool] = {}

        self._prompt_site_has_delimiter: dict[str, bool] = {}
        self._module_prompt_vars: dict[str, list[str]] = {}
        self._func_name_refs: dict[str, set[str]] = {}
        self._current_assign_target: str | None = None

        self._current_func: Optional[str] = None
        self._current_func_line: int = 0
        self._current_func_decorators: list[str] = []
        self._current_func_dangerous_calls: list[str] = []
        self._current_func_has_schema: bool = False


    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
            self._check_sdk_import(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            full = f"{module}.{alias.name}" if module else alias.name
            self.from_imports[name] = full
            self._check_sdk_import(module)
            self._check_sdk_import(full)
        self.generic_visit(node)

    def _check_sdk_import(self, module: str) -> None:
        for sdk_mod, provider in KNOWN_LLM_SDKS.items():
            if module == sdk_mod or module.startswith(sdk_mod + "."):
                self.detected_sdks[sdk_mod] = provider
        for fw_mod, framework in KNOWN_FRAMEWORKS.items():
            if module == fw_mod or module.startswith(fw_mod + "."):
                self.detected_frameworks[fw_mod] = framework

        for rag_mod in _RAG_IMPORT_MODULES:
            if module == rag_mod or module.startswith(rag_mod + "."):
                self._has_rag_imports = True
        for pii_mod in _PII_IMPORT_MODULES:
            if module == pii_mod or module.startswith(pii_mod + "."):
                self._has_pii_imports = True

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_funcdef(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_funcdef(node)

    def _func_scope(self) -> str:
        return self._current_func or "__module__"

    def _visit_funcdef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        prev_func = self._current_func
        prev_line = self._current_func_line
        prev_decorators = self._current_func_decorators
        prev_dangerous = self._current_func_dangerous_calls
        prev_schema = self._current_func_has_schema

        self._current_func = node.name
        self._current_func_line = node.lineno
        self._current_func_decorators = [
            self._decorator_name(d) for d in node.decorator_list
        ]
        self._current_func_dangerous_calls = []
        self._current_func_has_schema = self._has_typed_args(node)

        scope = self._func_scope()
        self._func_output_sinks.setdefault(scope, [])
        self._func_input_sources.setdefault(scope, [])

        for dec_name in self._current_func_decorators:
            if dec_name in _RATE_LIMIT_DECORATORS:
                self._func_rate_limiting[scope] = f"{self.filepath}:{node.lineno}"
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in _RATE_LIMIT_DECORATORS:
                    self._func_rate_limiting[scope] = f"{self.filepath}:{node.lineno}"

        is_tool = self._is_tool_function(node)

        self.generic_visit(node)

        if is_tool:
            tool = ToolDef(
                name=node.name,
                location=f"{self.filepath}:{node.lineno}",
                has_typed_schema=self._current_func_has_schema,
                dangerous_calls=list(self._current_func_dangerous_calls),
            )
            self.tool_defs.append(tool)
            enclosing = prev_func or "__module__"
            self._func_tool_defs.setdefault(enclosing, []).append(tool)

        self._current_func = prev_func
        self._current_func_line = prev_line
        self._current_func_decorators = prev_decorators
        self._current_func_dangerous_calls = prev_dangerous
        self._current_func_has_schema = prev_schema

    def _decorator_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Call):
            return self._decorator_name(node.func)
        return ""

    def _is_tool_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec_name in self._current_func_decorators:
            if dec_name in ("tool", "function_tool", "structured_tool"):
                return True
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in ("tool", "function_tool"):
                    return True
            elif isinstance(dec, ast.Attribute):
                if dec.attr in ("tool", "function_tool"):
                    return True
        return False

    def _has_typed_args(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        args = node.args
        annotated = 0
        total = 0
        for arg in args.args:
            if arg.arg == "self":
                continue
            total += 1
            if arg.annotation is not None:
                annotated += 1
        return total > 0 and annotated == total


    def visit_Call(self, node: ast.Call) -> None:
        self._detect_llm_call(node)
        self._detect_input_source(node)
        self._detect_dangerous_sink(node)
        self._detect_output_validation(node)
        self._detect_length_check(node)
        self._detect_logging(node)
        self._detect_rag_call(node)
        self._detect_pii_call(node)
        self.generic_visit(node)

    def _detect_llm_call(self, node: ast.Call) -> None:
        call_chain = self._resolve_call_chain(node.func)
        if not call_chain:
            return

        provider = None
        integration_type = None

        for pattern_obj, pattern_method, itype in LLM_CALL_PATTERNS:
            if call_chain.endswith(f".{pattern_obj}.{pattern_method}"):
                integration_type = itype
                prefix = call_chain.rsplit(f".{pattern_obj}.{pattern_method}", 1)[0]
                provider = self._resolve_provider(prefix)
                break
            if call_chain.endswith(f".{pattern_method}") and len(call_chain.split(".")) >= 2:
                parts = call_chain.split(".")
                obj = parts[-2]
                if parts[0] in _EXCLUDED_CALL_PREFIXES:
                    continue
                if obj == pattern_obj or pattern_obj in _GENERIC_OBJS:
                    if pattern_obj in _GENERIC_OBJS and not (self.detected_sdks or self.detected_frameworks):
                        continue
                    integration_type = itype
                    provider = self._resolve_provider(parts[0])
                    break

        if not provider or not integration_type:
            provider, integration_type = self._detect_framework_call(node, call_chain)

        if not provider:
            return

        model_value = self._extract_model_kwarg(node)
        model_pinned = self._is_model_pinned(model_value) if model_value else False

        has_system = self._has_system_prompt_in_call(node)

        tools_in_call, tool_names = self._extract_tools_kwarg(node)

        if tools_in_call and integration_type == "chat":
            integration_type = "agent"

        location = f"{self.filepath}:{node.lineno}"

        has_max_tokens = any(
            kw.arg in ("max_tokens", "max_output_tokens", "maxTokens")
            for kw in node.keywords
        )

        self._raw_llm_calls.append({
            "provider": provider,
            "location": location,
            "integration_type": integration_type,
            "model_value": model_value or "",
            "model_pinned": model_pinned,
            "has_system_prompt": has_system,
            "has_tools": tools_in_call,
            "tool_names": tool_names,
            "func_scope": self._func_scope(),
            "has_max_tokens": has_max_tokens,
        })

    def finalize(self) -> None:
        for call in self._raw_llm_calls:
            scope = call["func_scope"]

            scoped_sinks = self._func_output_sinks.get(scope, [])
            if not scoped_sinks and scope == "__module__":
                scoped_sinks = self.output_sinks

            scoped_sources = self._func_input_sources.get(scope, [])
            if not scoped_sources and scope == "__module__":
                scoped_sources = self.input_sources

            has_validation = scope in self._func_output_validation
            validation_loc = self._func_output_validation.get(scope, "")

            has_length_limit = scope in self._func_length_limit
            length_limit_loc = self._func_length_limit.get(scope, "")

            has_logging = scope in self._func_logging
            has_rag = scope in self._func_rag_context
            has_pii = scope in self._func_pii_filter
            has_rate_limiting = scope in self._func_rate_limiting

            scoped_prompts = self._func_prompt_sites.get(scope, [])
            if not scoped_prompts:
                module_prompts = self._func_prompt_sites.get("__module__", [])
                referenced_vars = self._func_name_refs.get(scope, set())
                if referenced_vars and self._module_prompt_vars:
                    referenced_locs: set[str] = set()
                    for var in referenced_vars:
                        for loc in self._module_prompt_vars.get(var, []):
                            referenced_locs.add(loc)
                    scoped_prompts = [
                        p for p in module_prompts if p in referenced_locs
                    ]
                else:
                    scoped_prompts = module_prompts

            scoped_tools: list[ToolDef] = []
            if call["integration_type"] == "agent":
                scoped_tools = self._func_tool_defs.get(scope, [])
                if not scoped_tools:
                    module_tools = self._func_tool_defs.get("__module__", [])
                    tool_names = call.get("tool_names", [])
                    if tool_names:
                        tool_name_set = set(tool_names)
                        scoped_tools = [
                            t for t in module_tools if t.name in tool_name_set
                        ]
                    else:
                        scoped_tools = module_tools

            scoped_system = (
                call["has_system_prompt"]
                or self._func_has_system_prompt.get(scope, False)
                or self._func_has_system_prompt.get("__module__", False)
            )

            scoped_delimiter = self._func_has_prompt_delimiter.get(scope, False)
            if not scoped_delimiter and scoped_prompts:
                scoped_delimiter = any(
                    self._prompt_site_has_delimiter.get(loc, False)
                    for loc in scoped_prompts
                )

            integration = LLMIntegration(
                provider=call["provider"],
                location=call["location"],
                integration_type=call["integration_type"],
                prompt_sites=list(scoped_prompts),
                tools=list(scoped_tools),
                input_sources=list(scoped_sources),
                output_sinks=list(scoped_sinks),
                has_system_prompt=scoped_system,
                model_pinned=call["model_pinned"],
                model_value=call["model_value"],
                has_output_validation=has_validation,
                output_validation_location=validation_loc,
                has_prompt_delimiter=scoped_delimiter,
                has_input_length_limit=has_length_limit,
                input_length_limit_location=length_limit_loc,
                has_rag_context=has_rag,
                has_pii_filter=has_pii,
                has_logging=has_logging,
                has_max_tokens=call.get("has_max_tokens", False),
                has_rate_limiting=has_rate_limiting,
            )
            self.integrations.append(integration)

    def _detect_framework_call(
        self, node: ast.Call, call_chain: str
    ) -> tuple[Optional[str], Optional[str]]:
        for name, full in self.from_imports.items():
            if "langchain" in full:
                if call_chain == name and any(
                    kw in full
                    for kw in ("chat_models", "llms", "ChatOpenAI", "ChatAnthropic")
                ):
                    return "LangChain", "chat"
                if call_chain == name and any(
                    kw in full for kw in ("retrievers", "RetrievalQA", "VectorStore")
                ):
                    return "LangChain", "rag"

        for name, full in self.from_imports.items():
            if "llama_index" in full:
                if call_chain == name and "query_engine" in full.lower():
                    return "LlamaIndex", "rag"
                if call_chain == name and any(
                    kw in full for kw in ("LLM", "OpenAI", "Anthropic")
                ):
                    return "LlamaIndex", "chat"

        for name, full in self.from_imports.items():
            if "crewai" in full:
                if call_chain == name and "Agent" in full:
                    return "CrewAI", "agent"
                if call_chain == name and "Crew" in full:
                    return "CrewAI", "agent"

        return None, None

    def _resolve_provider(self, var_name: str) -> Optional[str]:
        if var_name in self.from_imports:
            full = self.from_imports[var_name]
            for sdk_mod, provider in KNOWN_LLM_SDKS.items():
                if full.startswith(sdk_mod):
                    return provider
            for fw_mod, framework in KNOWN_FRAMEWORKS.items():
                if full.startswith(fw_mod):
                    return framework

        if var_name in self.imports:
            full = self.imports[var_name]
            for sdk_mod, provider in KNOWN_LLM_SDKS.items():
                if full.startswith(sdk_mod):
                    return provider

        if len(self.detected_sdks) == 1:
            return next(iter(self.detected_sdks.values()))
        if len(self.detected_frameworks) == 1 and not self.detected_sdks:
            return next(iter(self.detected_frameworks.values()))

        lower = var_name.lower()
        for sdk_name, provider in KNOWN_LLM_SDKS.items():
            if sdk_name.replace(".", "") in lower:
                return provider

        if self.detected_sdks:
            return next(iter(self.detected_sdks.values()))
        if self.detected_frameworks:
            return next(iter(self.detected_frameworks.values()))

        return None

    def _resolve_call_chain(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            value_chain = self._resolve_call_chain(node.value)
            if value_chain:
                return f"{value_chain}.{node.attr}"
            return node.attr
        return ""

    def _extract_model_kwarg(self, node: ast.Call) -> Optional[str]:
        for kw in node.keywords:
            if kw.arg == "model":
                if isinstance(kw.value, ast.Constant) and isinstance(
                    kw.value.value, str
                ):
                    return kw.value.value
                if isinstance(kw.value, ast.Name):
                    return self._string_constants.get(
                        kw.value.id, kw.value.id
                    )
        if node.args and isinstance(node.args[0], ast.Constant):
            val = node.args[0].value
            if isinstance(val, str) and any(
                p in val.lower()
                for p in ("gpt", "claude", "gemini", "llama", "mistral", "command")
            ):
                return val
        return None

    def _is_model_pinned(self, model_value: str) -> bool:
        if not model_value:
            return False
        lower = model_value.lower().strip()
        if lower in FLOATING_MODEL_ALIASES:
            return False
        if PINNED_MODEL_RE.search(model_value):
            return True
        return False

    def _has_system_prompt_in_call(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "system":
                return True
            if kw.arg == "messages" and isinstance(kw.value, ast.List):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Dict):
                        for key, val in zip(elt.keys, elt.values):
                            if (
                                isinstance(key, ast.Constant)
                                and key.value == "role"
                                and isinstance(val, ast.Constant)
                                and val.value == "system"
                            ):
                                return True
        return False

    def _extract_tools_kwarg(self, node: ast.Call) -> tuple[bool, list[str]]:
        for kw in node.keywords:
            if kw.arg in ("tools", "functions"):
                names: list[str] = []
                if isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Name):
                            names.append(elt.id)
                return True, names
        return False, []

    def _add_input_source(self, loc: str) -> None:
        if loc not in self.input_sources:
            self.input_sources.append(loc)
        scope = self._func_scope()
        scoped = self._func_input_sources.setdefault(scope, [])
        if loc not in scoped:
            scoped.append(loc)

    def _detect_input_source(self, node: ast.Call) -> None:
        chain = self._resolve_call_chain(node.func)
        for pattern, label in INPUT_SOURCE_PATTERNS.items():
            if (
                chain == pattern
                or chain.endswith(f".{pattern}")
                or chain.startswith(f"{pattern}.")
                or f".{pattern}." in chain
            ):
                self._add_input_source(f"{label} (L{node.lineno})")
                return

        if chain == "input":
            self._add_input_source(f"stdin (L{node.lineno})")

        if chain.endswith(".parse_args"):
            self._add_input_source(f"CLI arguments (L{node.lineno})")

    def _add_output_sink(self, loc: str) -> None:
        if loc not in self.output_sinks:
            self.output_sinks.append(loc)
        scope = self._func_scope()
        scoped = self._func_output_sinks.setdefault(scope, [])
        if loc not in scoped:
            scoped.append(loc)

    def _detect_dangerous_sink(self, node: ast.Call) -> None:
        chain = self._resolve_call_chain(node.func)

        for sink_name, sink_type in DANGEROUS_SINKS.items():
            if chain == sink_name or chain.endswith(f".{sink_name}"):
                loc = f"{sink_name} (L{node.lineno})"
                self._add_output_sink(loc)
                if self._current_func:
                    self._current_func_dangerous_calls.append(
                        f"{sink_name} (L{node.lineno})"
                    )
                return

        if chain.endswith(".execute") or chain.endswith(".executemany"):
            if node.args and self._is_string_formatted(node.args[0]):
                loc = f"SQL injection risk (L{node.lineno})"
                self._add_output_sink(loc)
                if self._current_func:
                    self._current_func_dangerous_calls.append(loc)

    def _is_string_formatted(self, node: ast.expr) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        return False

    def _detect_output_validation(self, node: ast.Call) -> None:
        chain = self._resolve_call_chain(node.func)

        if chain in OUTPUT_VALIDATION_CALLS:
            loc = f"{self.filepath}:{node.lineno}"
            self._func_output_validation[self._func_scope()] = loc
            return

        func_name = chain.split(".")[-1] if chain else ""
        unambiguous_simple = {
            "model_validate", "parse_obj", "parse_raw",
            "validate_python", "validate_json", "literal_eval",
        }
        if func_name in unambiguous_simple:
            loc = f"{self.filepath}:{node.lineno}"
            self._func_output_validation[self._func_scope()] = loc

    def _detect_length_check(self, node: ast.Call) -> None:
        chain = self._resolve_call_chain(node.func)
        if chain == "len":
            loc = f"{self.filepath}:{node.lineno}"
            self._func_length_limit[self._func_scope()] = loc

    _LOGGING_FULL_PATTERNS = {
        "logging.info", "logging.debug", "logging.warning", "logging.error",
        "logger.info", "logger.debug", "logger.warning", "logger.error",
        "log.info", "log.debug", "log.warning", "log.error",
        "structlog.get_logger",
    }
    _LOGGING_METHODS = {"info", "debug", "warning", "error", "msg"}
    _LOGGING_OBJ_NAMES = {"log", "logger", "structlog", "app_logger", "app_log"}

    def _detect_logging(self, node: ast.Call) -> None:
        chain = self._resolve_call_chain(node.func)
        if chain in self._LOGGING_FULL_PATTERNS:
            self._func_logging[self._func_scope()] = f"{self.filepath}:{node.lineno}"
        elif "." in chain and chain.rsplit(".", 1)[-1] in self._LOGGING_METHODS:
            obj_part = chain.rsplit(".", 1)[0].rsplit(".", 1)[-1].lower()
            if obj_part in self._LOGGING_OBJ_NAMES:
                self._func_logging[self._func_scope()] = f"{self.filepath}:{node.lineno}"

    _RAG_UNAMBIGUOUS_METHODS = {
        "similarity_search", "similarity_search_with_score",
        "as_retriever", "get_relevant_documents",
        "get_or_create_collection",
    }
    _RAG_GENERIC_METHODS = {"query", "search", "retrieve", "invoke"}
    _RAG_OBJECT_PREFIXES = {
        "collection", "vectorstore", "vector_store", "retriever",
        "index", "store", "chroma", "pinecone", "weaviate", "qdrant",
        "faiss",
    }

    def _detect_rag_call(self, node: ast.Call) -> None:
        if not self._has_rag_imports:
            return
        chain = self._resolve_call_chain(node.func)
        method = chain.rsplit(".", 1)[-1] if "." in chain else chain

        if method in self._RAG_UNAMBIGUOUS_METHODS:
            self._func_rag_context[self._func_scope()] = f"{self.filepath}:{node.lineno}"
        elif method in self._RAG_GENERIC_METHODS and "." in chain:
            obj_part = chain.rsplit(".", 1)[0].rsplit(".", 1)[-1].lower()
            if any(obj_part.startswith(p) for p in self._RAG_OBJECT_PREFIXES):
                self._func_rag_context[self._func_scope()] = f"{self.filepath}:{node.lineno}"

    _PII_METHODS = {
        "analyze", "anonymize", "scrub", "redact",
        "detect_pii", "clean_pii", "mask_pii",
    }
    _PII_CALL_PATTERNS = {
        "AnalyzerEngine", "AnonymizerEngine", "Scrubber",
    }

    def _detect_pii_call(self, node: ast.Call) -> None:
        if not self._has_pii_imports:
            return
        chain = self._resolve_call_chain(node.func)
        method = chain.rsplit(".", 1)[-1] if "." in chain else chain
        if method in self._PII_METHODS or method in self._PII_CALL_PATTERNS:
            self._func_pii_filter[self._func_scope()] = f"{self.filepath}:{node.lineno}"


    def visit_Assign(self, node: ast.Assign) -> None:
        if (
            self._func_scope() == "__module__"
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            self._current_assign_target = node.targets[0].id

        self._detect_prompt_construction(node.value, node.lineno)

        for target in node.targets:
            if isinstance(target, ast.Name):
                self._var_assignments[target.id] = node.lineno
                if isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value, str
                ):
                    self._string_constants[target.id] = node.value.value

        self.generic_visit(node)
        self._current_assign_target = None

    def visit_Name(self, node: ast.Name) -> None:
        scope = self._func_scope()
        if scope != "__module__" and node.id in self._module_prompt_vars:
            self._func_name_refs.setdefault(scope, set()).add(node.id)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        static_parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                static_parts.append(str(value.value))

        combined = " ".join(static_parts).lower()
        prompt_keywords = {
            "system",
            "user",
            "assistant",
            "prompt",
            "instruction",
            "context",
            "you are",
            "respond",
            "answer",
            "generate",
            "summarize",
            "translate",
            "analyze",
        }
        if any(kw in combined for kw in prompt_keywords):
            loc = f"{self.filepath}:{node.lineno}"
            if loc not in self.prompt_sites:
                self.prompt_sites.append(loc)
            scope = self._func_scope()
            scoped = self._func_prompt_sites.setdefault(scope, [])
            if loc not in scoped:
                scoped.append(loc)

            if scope == "__module__" and self._current_assign_target:
                self._module_prompt_vars.setdefault(
                    self._current_assign_target, []
                ).append(loc)

            for pattern in DELIMITER_PATTERNS:
                if pattern.search(combined):
                    self._has_prompt_delimiter = True
                    self._func_has_prompt_delimiter[scope] = True
                    self._prompt_site_has_delimiter[loc] = True
                    break

        self.generic_visit(node)

    def _detect_prompt_construction(self, node: ast.expr, lineno: int) -> None:
        if isinstance(node, ast.JoinedStr):
            return

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            lower = node.value.lower()
            prompt_keywords = {
                "you are",
                "system:",
                "user:",
                "assistant:",
                "instructions:",
                "respond with",
                "your task",
                "given the following",
            }
            if any(kw in lower for kw in prompt_keywords):
                loc = f"{self.filepath}:{lineno}"
                if loc not in self.prompt_sites:
                    self.prompt_sites.append(loc)
                scope = self._func_scope()
                scoped = self._func_prompt_sites.setdefault(scope, [])
                if loc not in scoped:
                    scoped.append(loc)

                if scope == "__module__" and self._current_assign_target:
                    self._module_prompt_vars.setdefault(
                        self._current_assign_target, []
                    ).append(loc)

                if "system" in lower and ("you are" in lower or "your role" in lower):
                    self.has_system_prompt = True
                    self._func_has_system_prompt[scope] = True

                for pattern in DELIMITER_PATTERNS:
                    if pattern.search(node.value):
                        self._has_prompt_delimiter = True
                        self._func_has_prompt_delimiter[scope] = True
                        self._prompt_site_has_delimiter[loc] = True
                        break

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                if isinstance(node.func.value, ast.Constant) and isinstance(
                    node.func.value.value, str
                ):
                    lower = node.func.value.value.lower()
                    if any(
                        kw in lower
                        for kw in ("prompt", "system", "user", "instruction")
                    ):
                        loc = f"{self.filepath}:{lineno}"
                        if loc not in self.prompt_sites:
                            self.prompt_sites.append(loc)
                        scope = self._func_scope()
                        scoped = self._func_prompt_sites.setdefault(scope, [])
                        if loc not in scoped:
                            scoped.append(loc)


    def visit_Compare(self, node: ast.Compare) -> None:
        if isinstance(node.left, ast.Call):
            chain = self._resolve_call_chain(node.left.func)
            if chain == "len":
                loc = f"{self.filepath}:{node.lineno}"
                self._func_length_limit[self._func_scope()] = loc
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.slice, ast.Slice):
            if node.slice.upper is not None and isinstance(
                node.slice.upper, ast.Constant
            ):
                loc = f"{self.filepath}:{node.lineno}"
                self._func_length_limit[self._func_scope()] = loc
        self.generic_visit(node)


def detect_integrations(
    path: str | Path,
    *,
    exclude_folders: set[str] | None = None,
) -> tuple[list[LLMIntegration], AIIntegrationGraph]:

    root = Path(path).resolve()
    if exclude_folders is None:
        exclude_folders = {
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            ".tox",
            ".mypy_cache",
            ".pytest_cache",
            "dist",
            "build",
            "egg-info",
        }

    integrations: list[LLMIntegration] = []
    graph = AIIntegrationGraph()
    files_scanned = 0

    py_files = _collect_python_files(root, exclude_folders)
    for py_file in py_files:
        files_scanned += 1
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

        rel = str(py_file.relative_to(root))
        visitor = _LLMDetectorVisitor(rel, source)
        visitor.visit(tree)
        visitor.finalize()

        integrations.extend(visitor.integrations)

        _build_graph_from_visitor(visitor, graph, rel)

    return integrations, graph


def _collect_python_files(
    root: Path, exclude_folders: set[str]
) -> list[Path]:
    files = []
    for py_file in root.rglob("*.py"):
        parts = py_file.relative_to(root).parts
        if any(part in exclude_folders for part in parts):
            continue
        if any(part.endswith(".egg-info") for part in parts):
            continue
        files.append(py_file)
    return sorted(files)


def _build_graph_from_visitor(
    visitor: _LLMDetectorVisitor,
    graph: AIIntegrationGraph,
    filepath: str,
) -> None:
    for integration in visitor.integrations:
        call_id = f"call:{integration.location}"
        graph.add_node(
            GraphNode(
                id=call_id,
                node_type=NodeType.LLM_CALL,
                location=integration.location,
                label=f"{integration.provider} {integration.integration_type}",
                metadata={"provider": integration.provider, "type": integration.integration_type},
            )
        )

        for src in integration.input_sources:
            src_id = f"input:{filepath}:{src}"
            graph.add_node(
                GraphNode(
                    id=src_id,
                    node_type=NodeType.INPUT_SOURCE,
                    location=f"{filepath}:{src}",
                    label=src,
                )
            )
            graph.add_edge(
                GraphEdge(
                    source_id=src_id,
                    target_id=call_id,
                    edge_type="data_flow",
                    label="user input → LLM call",
                )
            )

        for prompt in integration.prompt_sites:
            prompt_id = f"prompt:{prompt}"
            graph.add_node(
                GraphNode(
                    id=prompt_id,
                    node_type=NodeType.PROMPT_SITE,
                    location=prompt,
                    label="prompt construction",
                )
            )
            graph.add_edge(
                GraphEdge(
                    source_id=prompt_id,
                    target_id=call_id,
                    edge_type="data_flow",
                    label="prompt → LLM call",
                )
            )

        for sink in integration.output_sinks:
            sink_id = f"sink:{filepath}:{sink}"
            graph.add_node(
                GraphNode(
                    id=sink_id,
                    node_type=NodeType.OUTPUT_SINK,
                    location=f"{filepath}:{sink}",
                    label=sink,
                )
            )
            graph.add_edge(
                GraphEdge(
                    source_id=call_id,
                    target_id=sink_id,
                    edge_type="data_flow",
                    label="LLM output → dangerous sink",
                )
            )

        for tool in integration.tools:
            tool_id = f"tool:{tool.location}"
            graph.add_node(
                GraphNode(
                    id=tool_id,
                    node_type=NodeType.TOOL_DEF,
                    location=tool.location,
                    label=f"tool: {tool.name}",
                    metadata={
                        "has_typed_schema": tool.has_typed_schema,
                        "dangerous_calls": tool.dangerous_calls,
                    },
                )
            )
            graph.add_edge(
                GraphEdge(
                    source_id=call_id,
                    target_id=tool_id,
                    edge_type="tool_call",
                    label=f"LLM → tool {tool.name}",
                )
            )

        if integration.has_output_validation:
            val_id = f"validation:{integration.output_validation_location}"
            graph.add_node(
                GraphNode(
                    id=val_id,
                    node_type=NodeType.VALIDATION,
                    location=integration.output_validation_location,
                    label="output validation",
                )
            )
            graph.add_edge(
                GraphEdge(
                    source_id=call_id,
                    target_id=val_id,
                    edge_type="data_flow",
                    label="LLM output → validation",
                )
            )
