import tempfile
from pathlib import Path

from skylos.discover.detector import _collect_ai_files, detect_integrations


def test_collect_ai_files_includes_python_and_typescript(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / "route.ts").write_text("export const value = 1;\n", encoding="utf-8")
    (repo / "types.d.ts").write_text("export type Foo = string;\n", encoding="utf-8")

    files = _collect_ai_files(repo, {"node_modules", ".git"})
    rel_paths = {str(path.relative_to(repo)) for path in files}

    assert rel_paths == {"app.py", "route.ts"}


def test_detects_openai_typescript_route_with_guardrail_signals():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        route_file = root / "app" / "api" / "chat" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_file.write_text(
            """
import OpenAI from "openai";

const client = new OpenAI();

export async function POST(request: Request) {
  const body = await request.json();
  const message = String(body.message).slice(0, 400);

  const response = await client.responses.create({
    model: "gpt-4o-2024-08-06",
    max_output_tokens: 300,
    input: `Answer briefly.\\n<user_input>${message}</user_input>`,
  });

  console.info("llm call complete");
  const parsed = JSON.parse(response.output_text);
  return Response.json(parsed);
}
""",
            encoding="utf-8",
        )

        integrations, _graph = detect_integrations(root)

    assert len(integrations) == 1
    integ = integrations[0]
    assert integ.provider == "OpenAI"
    assert integ.integration_type == "chat"
    assert integ.model_value == "gpt-4o-2024-08-06"
    assert integ.model_pinned is True
    assert integ.has_max_tokens is True
    assert integ.has_prompt_delimiter is True
    assert integ.has_output_validation is True
    assert integ.has_input_length_limit is True
    assert integ.has_logging is True
    assert integ.input_sources
    assert integ.prompt_sites == [integ.location]


def test_detects_vercel_ai_sdk_typescript_call():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app.ts").write_text(
            """
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";

export async function summarize(prompt: string) {
  return generateText({
    model: openai("gpt-4o"),
    prompt,
  });
}
""",
            encoding="utf-8",
        )

        integrations, _graph = detect_integrations(root)

    assert len(integrations) == 1
    integ = integrations[0]
    assert integ.provider == "Vercel AI SDK"
    assert integ.integration_type == "chat"
    assert integ.model_value == "gpt-4o"
    assert integ.model_pinned is False


def test_excludes_next_build_output_from_discovery(tmp_path):
    repo = tmp_path / "repo"
    built = repo / ".next" / "server"
    built.mkdir(parents=True)
    (built / "app.js").write_text(
        """
const { completion } = require("litellm");

export async function run(prompt) {
  return completion({
    model: "gpt-4o",
    messages: [{ role: "user", content: prompt }],
  });
}
""",
        encoding="utf-8",
    )

    integrations, _graph = detect_integrations(repo)
    assert integrations == []


def test_detects_google_generative_ai_model_variable_flow():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "gemini.ts").write_text(
            """
import { GoogleGenerativeAI } from "@google/generative-ai";

const genAI = new GoogleGenerativeAI("test-key");
const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro-001" });

export async function answer(question: string) {
  return model.generateContent(question);
}
""",
            encoding="utf-8",
        )

        integrations, _graph = detect_integrations(root)

    assert len(integrations) == 1
    integ = integrations[0]
    assert integ.provider == "Google Gemini"
    assert integ.integration_type == "chat"
    assert integ.model_value == "gemini-1.5-pro-001"
    assert integ.model_pinned is False


def test_detects_commonjs_litellm_usage():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "chat.cjs").write_text(
            """
const { completion } = require("litellm");

async function chat(prompt) {
  return completion({
    model: "gpt-4o",
    messages: [{ role: "user", content: prompt }],
  });
}
""",
            encoding="utf-8",
        )

        integrations, _graph = detect_integrations(root)

    assert len(integrations) == 1
    integ = integrations[0]
    assert integ.provider == "LiteLLM"
    assert integ.integration_type == "chat"
