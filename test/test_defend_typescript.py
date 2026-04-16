import tempfile
from pathlib import Path

from skylos.defend.engine import run_defense_checks
from skylos.discover.detector import detect_integrations


def _by_plugin(results):
    return {result.plugin_id: result for result in results}


def test_defend_typescript_route_passes_core_guardrails():
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

        integrations, graph = detect_integrations(root)
        results, score, ops_score = run_defense_checks(integrations, graph)

    by_plugin = _by_plugin(results)
    assert by_plugin["model-pinned"].passed is True
    assert by_plugin["cost-controls"].passed is True
    assert by_plugin["output-validation"].passed is True
    assert by_plugin["prompt-delimiter"].passed is True
    assert by_plugin["input-length-limit"].passed is True
    assert by_plugin["untrusted-input-to-prompt"].passed is True
    assert by_plugin["logging-present"].passed is True
    assert by_plugin["no-dangerous-sink"].passed is True
    assert score.score_pct > 0
    assert ops_score.total > 0


def test_defend_typescript_route_fails_missing_controls_and_dangerous_sink():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        route_file = root / "src" / "chat.ts"
        route_file.parent.mkdir(parents=True)
        route_file.write_text(
            """
import Anthropic from "@anthropic-ai/sdk";
import { execSync } from "node:child_process";

const client = new Anthropic();

export async function run(req: { body: { prompt: string } }) {
  const reply = await client.messages.create({
    model: "claude-sonnet-4",
    messages: [{ role: "user", content: `Tell me ${req.body.prompt}` }],
  });

  execSync(reply.content[0].text);
  return reply.content[0].text;
}
""",
            encoding="utf-8",
        )

        integrations, graph = detect_integrations(root)
        results, _score, _ops_score = run_defense_checks(integrations, graph)

    by_plugin = _by_plugin(results)
    assert by_plugin["model-pinned"].passed is False
    assert by_plugin["prompt-delimiter"].passed is False
    assert by_plugin["no-dangerous-sink"].passed is False


def test_jsx_markup_does_not_count_as_prompt_delimiter():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        page_file = root / "app" / "page.tsx"
        page_file.parent.mkdir(parents=True)
        page_file.write_text(
            """
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";

export default async function Page(req: { body: { prompt: string } }) {
  const result = await generateText({
    model: openai("gpt-4o"),
    prompt: `Tell me ${req.body.prompt}`,
  });

  return <div>{result.text}</div>;
}
""",
            encoding="utf-8",
        )

        integrations, graph = detect_integrations(root)
        results, _score, _ops_score = run_defense_checks(integrations, graph)

    by_plugin = _by_plugin(results)
    assert len(integrations) == 1
    assert integrations[0].has_prompt_delimiter is False
    assert by_plugin["prompt-delimiter"].passed is False


def test_unrelated_html_string_does_not_count_as_prompt_delimiter():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        page_file = root / "app" / "page.tsx"
        page_file.parent.mkdir(parents=True)
        page_file.write_text(
            """
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";

export default async function Page(req: { body: { prompt: string } }) {
  const html = "<div>hello</div>";
  const result = await generateText({
    model: openai("gpt-4o"),
    prompt: `Tell me ${req.body.prompt}`,
  });

  return html + result.text;
}
""",
            encoding="utf-8",
        )

        integrations, graph = detect_integrations(root)
        results, _score, _ops_score = run_defense_checks(integrations, graph)

    by_plugin = _by_plugin(results)
    assert len(integrations) == 1
    assert integrations[0].has_prompt_delimiter is False
    assert by_plugin["prompt-delimiter"].passed is False
