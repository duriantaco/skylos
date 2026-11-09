import json
import textwrap
from pathlib import Path

import pytest

from skylos.defend.engine import run_defense_checks
from skylos.defend.policy import compute_owasp_coverage
from skylos.discover.detector import detect_integrations
from skylos.discover.graph import NodeType
from skylos.discover.report import format_json, format_table


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip())


def _scan(root: Path, files: dict[str, str]):
    _write(root, files)
    integrations, graph = detect_integrations(root)
    results, score, _ops = run_defense_checks(integrations, graph)
    return integrations, graph, results, score


def _outcomes(results, integration) -> dict[str, bool]:
    return {
        r.plugin_id: r.passed
        for r in results
        if r.integration_location == integration.location
    }


def _messages(results, integration) -> dict[str, str]:
    return {
        r.plugin_id: r.message
        for r in results
        if r.integration_location == integration.location
    }


DEMO = {
    "app/__init__.py": "",
    "app/web.py": """
        from flask import Flask, request

        from app.assistant import answer

        app = Flask(__name__)


        @app.post("/chat")
        def chat():
            return {"reply": answer(request.json["message"])}
    """,
    "app/assistant.py": """
        import sqlite3

        from openai import OpenAI

        client = OpenAI()

        TOOLS = [
            {
                "type": "function",
                "function": {
                    "name": "run_sql",
                    "description": "Run a SQL query against the orders database",
                    "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
                },
            }
        ]


        def answer(question: str) -> str:
            prompt = f"You are Acme's support bot. Answer the customer: {question}"
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                tools=TOOLS,
            )
            message = response.choices[0].message
            if message.tool_calls:
                return str(run_sql(message.tool_calls[0].function.arguments))
            return message.content


        def run_sql(query: str):
            return sqlite3.connect("orders.db").execute(query).fetchall()
    """,
}


class TestDemoAssistant:
    def test_discover_finds_tool_http_input_and_hop_sink(self, tmp_path):
        integrations, graph, _results, _score = _scan(tmp_path, DEMO)

        assert len(integrations) == 1
        integ = integrations[0]
        assert integ.location == "app/assistant.py:21"
        assert integ.integration_type == "agent"
        assert [(t.name, t.location, t.has_typed_schema) for t in integ.tools] == [
            ("run_sql", "app/assistant.py:8", True)
        ]
        assert integ.tools[0].handler_location == "app/assistant.py:32"
        assert integ.tools[0].dangerous_calls == ["SQL execute of tool argument (L33)"]
        assert [p.label for p in integ.prompt_inputs] == [
            "Flask JSON body (app/web.py:10) → question → prompt (L20)"
        ]
        assert integ.prompt_inputs[0].delimited is False
        assert integ.has_prompt_delimiter is False
        assert integ.output_sinks == []
        assert integ.output_sink_flows == [
            "tool-call arguments → run_sql() → SQL execute (L33)"
        ]
        assert integ.input_sources == []

        input_nodes = graph.get_nodes_by_type(NodeType.INPUT_SOURCE)
        sink_nodes = graph.get_nodes_by_type(NodeType.OUTPUT_SINK)
        assert [n.label for n in input_nodes] == [integ.prompt_inputs[0].label]
        assert [n.label for n in sink_nodes] == integ.output_sink_flows

    def test_defend_reports_hop_sink_tool_scope_and_prompt_injection(self, tmp_path):
        integrations, _graph, results, score = _scan(tmp_path, DEMO)
        integ = integrations[0]
        outcomes = _outcomes(results, integ)
        messages = _messages(results, integ)

        assert outcomes["no-dangerous-sink"] is False
        assert "one call hop away" in messages["no-dangerous-sink"]
        assert "run_sql() → SQL execute (L33)" in messages["no-dangerous-sink"]
        assert "same scope" not in messages["no-dangerous-sink"]
        assert outcomes["tool-scope"] is False
        assert "run_sql: SQL execute of tool argument (L33)" in messages["tool-scope"]
        assert outcomes["tool-schema-present"] is True
        assert outcomes["untrusted-input-to-prompt"] is False
        assert (
            "Flask JSON body (app/web.py:10)" in messages["untrusted-input-to-prompt"]
        )
        assert outcomes["prompt-delimiter"] is False
        assert "input-length-limit" not in outcomes
        assert "output-pii-filter" not in outcomes
        assert (score.weighted_score, score.weighted_max) == (8, 45)
        assert score.risk_rating == "CRITICAL"

    def test_owasp_items_follow_plugin_mapping(self, tmp_path):
        _integrations, _graph, results, _score = _scan(tmp_path, DEMO)

        current = compute_owasp_coverage(results, framework="llm", version="2025")
        assert current["LLM01"]["status"] == "uncovered"
        assert current["LLM05"]["status"] == "uncovered"
        assert current["LLM06"]["status"] == "partial"
        legacy = compute_owasp_coverage(results, framework="llm", version="2024")
        assert legacy["LLM02"]["status"] == "uncovered"
        assert legacy["LLM08"]["status"] == "partial"

    def test_reports_render_new_evidence(self, tmp_path):
        integrations, graph, _results, _score = _scan(tmp_path, DEMO)

        table = format_table(integrations, files_scanned=3)
        assert (
            "Input: Flask JSON body (app/web.py:10) → question → prompt (L20)" in table
        )
        assert (
            "Tool:  run_sql (app/assistant.py:8), handler app/assistant.py:32" in table
        )
        assert "Sink:  tool-call arguments → run_sql() → SQL execute (L33)" in table

        data = json.loads(format_json(integrations, graph, files_scanned=3))
        item = data["integrations"][0]
        assert item["output_sink_flows"] == [
            "tool-call arguments → run_sql() → SQL execute (L33)"
        ]
        assert item["prompt_inputs"] == [
            {
                "label": "Flask JSON body (app/web.py:10) → question → prompt (L20)",
                "source": "Flask JSON body (app/web.py:10)",
                "parameter": "question",
                "prompt_location": "app/assistant.py:20",
                "delimited": False,
            }
        ]
        assert item["tools"][0]["kind"] == "schema"


TOOL_HEADER = """
    import json
    import sqlite3
    import subprocess

    from openai import OpenAI

    client = OpenAI()

    TOOLS = [
        {
            "type": "function",
            "function": {
                "name": "run_sql",
                "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
            },
        }
    ]
"""


def _agent_module(body: str) -> dict[str, str]:
    return {"app.py": textwrap.dedent(TOOL_HEADER) + textwrap.dedent(body)}


CLEAN_CASES = {
    "parameterized_handler": """
        def answer(question: str) -> str:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a support bot."},
                    {"role": "user", "content": question},
                ],
                tools=TOOLS,
            )
            message = response.choices[0].message
            if message.tool_calls:
                args = json.loads(message.tool_calls[0].function.arguments)
                return str(run_sql(args["order_id"]))
            return message.content


        def run_sql(order_id: int):
            conn = sqlite3.connect("orders.db")
            return conn.execute("SELECT status FROM orders WHERE id = ?", (order_id,)).fetchall()
    """,
    "declared_never_executed": """
        def answer(question: str) -> str:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": question}],
                tools=TOOLS,
            )
            return response.choices[0].message.content


        def run_sql(query: str):
            return sqlite3.connect("orders.db").execute(query).fetchall()
    """,
    "unrelated_dangerous_calls": """
        def answer(question: str) -> str:
            total = run_sql("SELECT count(*) FROM orders")
            mine = run_sql(question)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": question}],
                tools=TOOLS,
            )
            log_reply(response.choices[0].message.content)
            return str(total) + str(mine) + response.choices[0].message.content


        def log_reply(text):
            print(text)


        def rebuild_index():
            subprocess.run(["make", "index"], check=True)


        def run_sql(query: str):
            return sqlite3.connect("orders.db").execute(query).fetchall()
    """,
    "sanitized_at_dispatch": """
        def answer(question: str) -> str:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": question}],
                tools=TOOLS,
            )
            message = response.choices[0].message
            if message.tool_calls:
                args = json.loads(message.tool_calls[0].function.arguments)
                return str(run_sql(int(args["limit"]), args.get("note")))
            return message.content


        def run_sql(limit, note):
            conn = sqlite3.connect("orders.db")
            print(note)
            return conn.execute(f"SELECT * FROM orders LIMIT {limit}").fetchall()
    """,
    "two_hop_not_claimed": """
        def answer(question: str) -> str:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": question}],
                tools=TOOLS,
            )
            message = response.choices[0].message
            if message.tool_calls:
                return str(dispatch(message.tool_calls[0].function.arguments))
            return message.content


        def dispatch(arguments):
            return run_sql(arguments)


        def run_sql(query: str):
            return sqlite3.connect("orders.db").execute(query).fetchall()
    """,
}


class TestPrecisionControls:
    @pytest.mark.parametrize("case", sorted(CLEAN_CASES))
    def test_tool_flow_controls_stay_clean(self, tmp_path, case):
        integrations, _graph, results, _score = _scan(
            tmp_path, _agent_module(CLEAN_CASES[case])
        )

        assert len(integrations) == 1
        integ = integrations[0]
        outcomes = _outcomes(results, integ)
        assert [t.name for t in integ.tools] == ["run_sql"]
        assert integ.output_sinks == []
        assert integ.output_sink_flows == []
        assert integ.prompt_inputs == []
        assert outcomes["no-dangerous-sink"] is True
        assert outcomes["tool-scope"] is True
        assert "untrusted-input-to-prompt" not in outcomes
        assert "prompt-delimiter" not in outcomes

    @pytest.mark.parametrize(
        "case", ["declared_never_executed", "unrelated_dangerous_calls"]
    )
    def test_unexecuted_tool_message_is_honest(self, tmp_path, case):
        integrations, _graph, results, _score = _scan(
            tmp_path, _agent_module(CLEAN_CASES[case])
        )

        integ = integrations[0]
        assert integ.tools[0].handler_location == ""
        assert integ.tools[0].dangerous_calls == []
        message = _messages(results, integ)["tool-scope"]
        assert "no handler is called with the model's output for: run_sql" in message

    def test_two_hop_pass_message_states_the_limit(self, tmp_path):
        integrations, _graph, results, _score = _scan(
            tmp_path, _agent_module(CLEAN_CASES["two_hop_not_claimed"])
        )

        message = _messages(results, integrations[0])["no-dangerous-sink"]
        assert "one call hop away" in message

    def test_constant_prompt_has_no_prompt_input(self, tmp_path):
        integrations, _graph, results, _score = _scan(
            tmp_path,
            {
                "app.py": """
                    from openai import OpenAI

                    client = OpenAI()


                    def daily_summary(day):
                        response = client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": "You are a reporting bot. Summarize today's orders."}],
                        )
                        return response.choices[0].message.content
                """
            },
        )

        assert integrations[0].prompt_inputs == []
        assert "untrusted-input-to-prompt" not in _outcomes(results, integrations[0])

    def test_delimited_and_separate_user_messages_stay_clean(self, tmp_path):
        integrations, _graph, results, _score = _scan(
            tmp_path,
            {
                "app.py": """
                    from openai import OpenAI

                    client = OpenAI()


                    def answer(question: str) -> str:
                        response = client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[
                                {"role": "system", "content": "You are Acme's support bot."},
                                {"role": "user", "content": f"<user_input>{question}</user_input>"},
                            ],
                        )
                        return response.choices[0].message.content


                    def answer_plain(question: str) -> str:
                        response = client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[
                                {"role": "system", "content": "You are Acme's support bot."},
                                {"role": "user", "content": question},
                            ],
                        )
                        return response.choices[0].message.content
                """
            },
        )

        delimited, plain = sorted(
            integrations, key=lambda i: int(i.location.rsplit(":", 1)[-1])
        )
        assert [(p.parameter, p.delimited) for p in delimited.prompt_inputs] == [
            ("question", True)
        ]
        assert _outcomes(results, delimited)["prompt-delimiter"] is True
        assert _outcomes(results, delimited)["untrusted-input-to-prompt"] is True
        assert plain.prompt_inputs == []
        assert "prompt-delimiter" not in _outcomes(results, plain)

    def test_cross_file_link_needs_matching_module_and_untrusted_argument(
        self, tmp_path
    ):
        integrations, _graph, _results, _score = _scan(
            tmp_path,
            {
                "app/__init__.py": "",
                "app/assistant.py": """
                    from openai import OpenAI

                    client = OpenAI()


                    def answer(question, tone):
                        prompt = f"You are a support bot. Answer in a {tone} tone: {question}"
                        response = client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": prompt}],
                        )
                        return response.choices[0].message.content
                """,
                "app/other.py": """
                    def answer(question, tone):
                        return question
                """,
                "app/web.py": """
                    from flask import Flask, request

                    from app.assistant import answer
                    from app.other import answer as other_answer

                    app = Flask(__name__)


                    @app.post("/chat")
                    def chat():
                        return {"reply": answer("What are your hours?", "friendly")}


                    @app.post("/other")
                    def other():
                        return {"reply": other_answer(request.json["message"], "friendly")}


                    @app.post("/sized")
                    def sized():
                        return {"reply": answer("hi", len(request.json["tone"]))}
                """,
            },
        )

        assert [p.label for p in integrations[0].prompt_inputs] == [
            "question parameter → prompt (L7)",
            "tone parameter → prompt (L7)",
        ]

    def test_same_scope_flask_attribute_is_an_input_source(self, tmp_path):
        integrations, _graph, _results, _score = _scan(
            tmp_path,
            {
                "app.py": """
                    from flask import Flask, request
                    from openai import OpenAI

                    app = Flask(__name__)
                    client = OpenAI()


                    @app.post("/chat")
                    def chat():
                        text = request.json["message"]
                        return client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": text}],
                        )


                    def batch(request):
                        return client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": request.json["text"]}],
                        )
                """
            },
        )

        by_line = sorted(integrations, key=lambda i: int(i.location.rsplit(":", 1)[-1]))
        assert by_line[0].input_sources == ["Flask JSON body (L10)"]
        assert by_line[1].input_sources == []

    def test_generic_execute_without_sql_evidence_is_not_sql(self, tmp_path):
        integrations, _graph, results, _score = _scan(
            tmp_path,
            {
                "app.py": """
                    import json

                    from openai import OpenAI

                    client = OpenAI()
                    TOOLS = [{"type": "function", "function": {"name": "run_job", "parameters": {"type": "object", "properties": {"job": {"type": "string"}}}}}]


                    def agent(task: str):
                        response = client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": task}],
                            tools=TOOLS,
                        )
                        for call in response.choices[0].message.tool_calls or []:
                            run_job(**json.loads(call.function.arguments))


                    def run_job(job: str):
                        return registry.execute(job)
                """
            },
        )

        integ = integrations[0]
        assert integ.output_sink_flows == []
        assert _outcomes(results, integ)["tool-scope"] is True


ADVERSARIAL_CASES = {
    "aliases": (
        {
            "app.py": """
                import json
                import sqlite3 as db

                from openai import OpenAI as Client

                llm = Client()

                SQL_TOOL = {
                    "type": "function",
                    "function": {
                        "name": "run_sql",
                        "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
                    },
                }
                BASE_TOOLS = [SQL_TOOL]
                AGENT_TOOLS = BASE_TOOLS


                def answer(question):
                    q = question
                    prompt = "You are a support bot. Answer the customer: " + q
                    resp = llm.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": prompt}],
                        tools=AGENT_TOOLS,
                    )
                    calls = resp.choices[0].message.tool_calls or []
                    for call in calls:
                        handler = run_sql
                        handler(json.loads(call.function.arguments)["query"])
                    return resp.choices[0].message.content


                def run_sql(query):
                    statement = query
                    conn = db.connect("orders.db")
                    return conn.execute(statement).fetchall()
            """
        },
        "run_sql",
        "tool-call arguments → run_sql() → SQL execute (L37)",
        ["question parameter → prompt (L21)"],
    ),
    "helper_built_tools_dict_dispatch": (
        {
            "agent.py": """
                import json
                import subprocess

                from openai import OpenAI

                client = OpenAI()

                PROMPT = "You are a build assistant. Do this task: {task}"


                def build_tools():
                    tools = []
                    tools.append(
                        {
                            "type": "function",
                            "function": {
                                "name": "run_shell",
                                "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}},
                            },
                        }
                    )
                    return tools


                def run_shell(cmd: str):
                    return subprocess.run(cmd, shell=True, capture_output=True).stdout


                HANDLERS = {"run_shell": run_shell}


                def agent(task: str):
                    response = client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": PROMPT.format(task=task)}],
                        tools=build_tools(),
                    )
                    for call in response.choices[0].message.tool_calls or []:
                        handler = HANDLERS[call.function.name]
                        handler(**json.loads(call.function.arguments))
            """
        },
        "run_shell",
        "tool-call arguments → run_shell() → subprocess.run (L26)",
        ["task parameter → prompt (L35)"],
    ),
    "anthropic_tool_use": (
        {
            "agent.py": """
                import subprocess

                import anthropic

                client = anthropic.Anthropic()

                TOOLS = [
                    {
                        "name": "run_shell",
                        "description": "Run a shell command",
                        "input_schema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
                    }
                ]


                def agent(task: str):
                    resp = client.messages.create(
                        model="claude-sonnet-4-20250514",
                        max_tokens=1024,
                        messages=[{"role": "user", "content": task}],
                        tools=TOOLS,
                    )
                    for block in resp.content:
                        if block.type == "tool_use":
                            run_shell(block.input["cmd"])


                def run_shell(cmd):
                    return subprocess.run(cmd, shell=True)
            """
        },
        "run_shell",
        "tool-call arguments → run_shell() → subprocess.run (L29)",
        [],
    ),
    "late_tables_get_dispatch": (
        {
            "agent.py": """
                import json
                import shutil

                from openai import OpenAI

                client = OpenAI()


                def agent(task: str):
                    response = client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": task}],
                        tools=TOOLS,
                    )
                    for call in response.choices[0].message.tool_calls or []:
                        args = json.loads(call.function.arguments)
                        if call.function.name == "delete_path":
                            HANDLERS.get("delete_path")(args["path"])


                def delete_path(path: str):
                    shutil.rmtree(path)


                HANDLERS = {"delete_path": delete_path}

                TOOLS = [
                    {
                        "type": "function",
                        "name": "delete_path",
                        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
                    }
                ]
            """
        },
        "delete_path",
        "tool-call arguments → delete_path() → shutil.rmtree (L22)",
        [],
    ),
    "shadowed_sanitizer": (
        {
            "app.py": """
                import json
                import sqlite3

                from openai import OpenAI

                client = OpenAI()
                TOOLS = [{"type": "function", "function": {"name": "run_sql", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}}}}]


                def int(value):
                    return value


                def answer(question: str):
                    response = client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": question}],
                        tools=TOOLS,
                    )
                    args = json.loads(response.choices[0].message.tool_calls[0].function.arguments)
                    return run_sql(int(args["query"]))


                def run_sql(query):
                    return sqlite3.connect("orders.db").execute("SELECT " + query).fetchall()
            """
        },
        "run_sql",
        "tool-call arguments → run_sql() → SQL execute (L25)",
        [],
    ),
    "keyword_sql_without_db_import": (
        {
            "app.py": """
                import json

                from openai import OpenAI

                client = OpenAI()
                TOOLS = [{"type": "function", "function": {"name": "run_sql", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}}}}]


                def answer(question: str):
                    response = client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[{"role": "user", "content": question}],
                        tools=TOOLS,
                    )
                    for call in response.choices[0].message.tool_calls:
                        run_sql(call.function.arguments)


                def run_sql(query):
                    return conn.execute(sql=query)
            """
        },
        "run_sql",
        "tool-call arguments → run_sql() → SQL execute (L20)",
        [],
    ),
}


class TestAdversarialMustStillReport:
    @pytest.mark.parametrize("case", sorted(ADVERSARIAL_CASES))
    def test_tool_call_reaches_sink(self, tmp_path, case):
        files, tool_name, flow, prompt_labels = ADVERSARIAL_CASES[case]
        integrations, _graph, results, _score = _scan(tmp_path, files)

        assert len(integrations) == 1
        integ = integrations[0]
        outcomes = _outcomes(results, integ)
        assert [t.name for t in integ.tools] == [tool_name]
        assert integ.tools[0].has_typed_schema is True
        assert integ.tools[0].handler_location != ""
        assert integ.output_sink_flows == [flow]
        assert outcomes["no-dangerous-sink"] is False
        assert outcomes["tool-scope"] is False
        assert [p.label for p in integ.prompt_inputs] == prompt_labels
        if prompt_labels:
            assert outcomes["untrusted-input-to-prompt"] is False
            assert outcomes["prompt-delimiter"] is False

    def test_relative_import_route_proves_flask_form(self, tmp_path):
        integrations, _graph, results, _score = _scan(
            tmp_path,
            {
                "pkg/__init__.py": "",
                "pkg/assistant.py": """
                    from openai import OpenAI

                    client = OpenAI()


                    def answer(question):
                        prompt = "You are a support bot. Answer: {}".format(question)
                        response = client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": prompt}],
                        )
                        return response.choices[0].message.content
                """,
                "pkg/views.py": """
                    from flask import Flask, request

                    from .assistant import answer

                    app = Flask(__name__)


                    @app.post("/ask")
                    def ask():
                        text = request.form["text"]
                        return {"reply": answer(text)}
                """,
            },
        )

        integ = integrations[0]
        assert [p.label for p in integ.prompt_inputs] == [
            "Flask form (pkg/views.py:10) → question → prompt (L7)"
        ]
        assert _outcomes(results, integ)["untrusted-input-to-prompt"] is False

    @pytest.mark.parametrize(
        "template",
        [
            'f"<context>{doc}</context> You are a bot. Answer: {question}"',
            'f"You are a bot. Answer: <user_input>{question}"',
            'f"You are a bot. Answer: <b>{question}</i>"',
        ],
    )
    def test_delimiter_elsewhere_does_not_hide_raw_slot(self, tmp_path, template):
        integrations, _graph, results, _score = _scan(
            tmp_path,
            {
                "app.py": f"""
                    from openai import OpenAI

                    client = OpenAI()


                    def answer(question, doc=""):
                        prompt = {template}
                        return client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{{"role": "user", "content": prompt}}],
                        )
                """
            },
        )

        integ = integrations[0]
        raw = [p for p in integ.prompt_inputs if p.parameter == "question"]
        assert len(raw) == 1 and raw[0].delimited is False
        assert integ.has_prompt_delimiter is False
        assert _outcomes(results, integ)["prompt-delimiter"] is False

    def test_decorated_tool_executing_its_argument_is_tool_scope(self, tmp_path):
        integrations, _graph, results, _score = _scan(
            tmp_path,
            {
                "agent.py": '''
                    import sqlite3

                    from langchain_core.tools import tool
                    from openai import OpenAI

                    client = OpenAI()


                    @tool
                    def run_sql(query: str) -> str:
                        """Run a SQL query."""
                        return str(sqlite3.connect("orders.db").execute(query).fetchall())


                    @tool
                    def order_status(order_id: int) -> str:
                        """Look up one order."""
                        return str(sqlite3.connect("orders.db").execute("SELECT status FROM orders WHERE id = ?", (order_id,)).fetchall())


                    def agent(task: str):
                        return client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": task}],
                            tools=[run_sql, order_status],
                        )
                '''
            },
        )

        integ = integrations[0]
        calls = {t.name: t.dangerous_calls for t in integ.tools}
        assert calls == {
            "run_sql": ["SQL execute of tool argument (L12)"],
            "order_status": [],
        }
        assert _outcomes(results, integ)["tool-scope"] is False
