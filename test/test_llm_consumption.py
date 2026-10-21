from pathlib import Path

from skylos.rules.danger.danger import scan_ctx


def _write(tmp_path: Path, name: str, code: str) -> Path:
    file_path = tmp_path / name
    file_path.write_text(code, encoding="utf-8")
    return file_path


def _scan_one(tmp_path: Path, name: str, code: str):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def _rule_ids(findings):
    return {finding["rule_id"] for finding in findings}


def _d267_findings(findings):
    return [finding for finding in findings if finding["rule_id"] == "SKY-D267"]


def test_openai_call_without_token_or_timeout_flags_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "llm_no_bounds.py",
        """
from openai import OpenAI

client = OpenAI()

def answer(messages):
    return client.chat.completions.create(model="gpt-4o", messages=messages)
""",
    )

    d267 = _d267_findings(findings)
    assert d267
    assert "no max token limit" in d267[0]["message"]
    assert "no request timeout" in d267[0]["message"]


def test_openai_call_with_token_and_timeout_is_not_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "llm_bounded.py",
        """
from openai import OpenAI

client = OpenAI(timeout=30)

def answer(messages):
    return client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=400,
    )
""",
    )

    assert "SKY-D267" not in _rule_ids(findings)


def test_llm_call_inside_obvious_unbounded_loop_flags_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "llm_loop.py",
        """
import openai

def poll(messages):
    while True:
        openai.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            max_tokens=200,
            timeout=20,
        )
""",
    )

    d267 = _d267_findings(findings)
    assert d267
    assert "obvious unbounded loop" in d267[0]["message"]


def test_langchain_client_bounds_suppress_invoke_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "langchain_bounded.py",
        """
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(max_tokens=300, request_timeout=20)

def answer(question):
    return llm.invoke(question)
""",
    )

    assert "SKY-D267" not in _rule_ids(findings)


def test_agent_executor_without_iteration_cap_flags_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "agent_no_iteration_cap.py",
        """
from langchain.agents import initialize_agent

def build_agent(tools, llm):
    return initialize_agent(tools, llm)
""",
    )

    d267 = _d267_findings(findings)
    assert d267
    assert "no iteration or time cap" in d267[0]["message"]


def test_agent_executor_with_iteration_cap_is_not_d267(tmp_path):
    findings = _scan_one(
        tmp_path,
        "agent_iteration_cap.py",
        """
from langchain.agents import initialize_agent

def build_agent(tools, llm):
    return initialize_agent(tools, llm, max_iterations=5)
""",
    )

    assert "SKY-D267" not in _rule_ids(findings)



def _d267_messages(tmp_path, code):
    return [f["message"] for f in _d267_findings(_scan_one(tmp_path, "llm_kwargs.py", code))]


def test_limits_set_in_an_unpacked_local_dict_count(tmp_path):
    code = """
from litellm import completion

def ask(messages, timeout, max_tokens=1024):
    params = {"model": "gpt-4o", "messages": messages, "timeout": timeout}
    if max_tokens:
        params["max_tokens"] = max_tokens
    return completion(**params)

def ask_update(messages):
    params = dict(model="gpt-4o", messages=messages)
    params.update(max_tokens=512, request_timeout=30)
    return completion(**params)
"""
    assert _d267_messages(tmp_path, code) == []


def test_missing_limits_in_a_readable_dict_still_flag(tmp_path):
    code = """
from litellm import completion

def ask(messages):
    params = {"model": "gpt-4o", "messages": messages}
    params["temperature"] = 0
    return completion(**params)

def ask_timeout_only(messages):
    return completion(model="gpt-4o", messages=messages, **{"timeout": 30})
"""
    messages = _d267_messages(tmp_path, code)
    assert len(messages) == 2
    assert "no max token limit; no request timeout" in messages[0]
    assert "no max token limit" in messages[1]
    assert "no request timeout" not in messages[1]


def test_unreadable_unpacked_kwargs_make_no_missing_limit_claim(tmp_path):
    code = """
from litellm import completion

class Client:
    def ask(self, messages, **kwargs):
        return completion(model="gpt-4o", messages=messages, **kwargs)

    def ask_config(self, messages):
        return completion(model="gpt-4o", messages=messages, **self.extras)

def loop(messages):
    while True:
        completion(model="gpt-4o", messages=messages, **messages[0])
"""
    messages = _d267_messages(tmp_path, code)
    assert len(messages) == 1
    assert "unbounded loop" in messages[0]
    assert "no max token limit" not in messages[0]


def _d267_lines(tmp_path, code):
    findings = _d267_findings(_scan_one(tmp_path, "llm_flow.py", code))
    return sorted((f["line"], "no max token limit" in f["message"]) for f in findings)


def test_a_none_or_removed_limit_in_an_unpacked_dict_still_flags(tmp_path):
    code = """
from litellm import completion

def none_values(messages):
    params = {"model": "m", "messages": messages, "max_tokens": None, "timeout": 30}
    return completion(**params)

def removed(messages):
    params = {"model": "m", "max_tokens": 100, "timeout": 30}
    del params["max_tokens"]
    return completion(messages=messages, **params)

def popped(messages):
    params = dict(model="m", max_tokens=100, timeout=30)
    params.pop("max_tokens")
    return completion(messages=messages, **params)

def cleared(messages):
    params = {"max_tokens": 100, "timeout": 30}
    params.clear()
    params["timeout"] = 30
    return completion(messages=messages, **params)

def defaulted(messages):
    params = {"timeout": 30}
    params.setdefault("max_tokens", None)
    return completion(messages=messages, **params)

def merged(messages):
    params = {"max_tokens": 100, "timeout": 30}
    params |= {"max_tokens": None}
    return completion(messages=messages, **params)

def updated(messages):
    params = {"max_tokens": 100, "timeout": 30}
    params.update({"max_tokens": None})
    return completion(messages=messages, **params)
"""
    assert _d267_lines(tmp_path, code) == [
        (6, True), (11, True), (16, True), (22, True), (27, True), (32, True), (37, True)
    ]


def test_a_limit_set_on_only_some_paths_still_flags(tmp_path):
    code = """
from litellm import completion

def branch(messages, flag):
    params = {"timeout": 30}
    if flag:
        params["max_tokens"] = 100
    return completion(messages=messages, **params)

def later_iteration(messages, models):
    params = {"max_tokens": 100, "timeout": 30}
    for model in models:
        completion(model=model, messages=messages, **params)
        params.pop("max_tokens")

def failed_setup(messages, compute):
    params = {"timeout": 30}
    try:
        params["max_tokens"] = compute()
    except ValueError:
        pass
    return completion(messages=messages, **params)

def unmatched(messages, mode):
    params = {"timeout": 30}
    match mode:
        case "short":
            params["max_tokens"] = 10
    return completion(messages=messages, **params)
"""
    assert _d267_lines(tmp_path, code) == [(8, True), (13, True), (22, True), (29, True)]


def test_a_limit_set_on_every_path_counts(tmp_path):
    code = """
from litellm import completion

def guarded(messages, max_tokens=2048):
    params = {"timeout": 30}
    if max_tokens is not None:
        params["max_tokens"] = max_tokens
    return completion(messages=messages, **params)

def both(messages, flag):
    params = {"timeout": 30}
    if flag:
        params["max_tokens"] = 10
    else:
        params["max_tokens"] = 20
    return completion(messages=messages, **params)

def early_exit(messages, ok):
    params = {"max_tokens": 100, "timeout": 30}
    if not ok:
        params.pop("max_tokens")
        return None
    return completion(messages=messages, **params)

def every_case(messages, mode):
    params = {"timeout": 30}
    match mode:
        case "short":
            params["max_tokens"] = 10
        case _:
            params["max_tokens"] = 500
    return completion(messages=messages, **params)

def loop(messages, models):
    params = {"max_tokens": 100, "timeout": 30}
    for model in models:
        params["model"] = model
        completion(messages=messages, **params)
"""
    assert _d267_lines(tmp_path, code) == []


def test_a_dict_changed_out_of_sight_makes_no_claim(tmp_path):
    code = """
from litellm import completion

def aliased(messages):
    params = {"max_tokens": 100, "timeout": 30}
    other = params
    del other["max_tokens"]
    return completion(messages=messages, **params)

def closure(messages):
    def strip():
        params.pop("max_tokens")
    params = {"max_tokens": 100, "timeout": 30}
    strip()
    return completion(messages=messages, **params)

def passed(messages, prepare):
    params = {"model": "m", "timeout": 30}
    prepare(params)
    return completion(messages=messages, **params)

def dict(**values):
    return {}

def rebound_dict(messages):
    params = dict(max_tokens=None, timeout=None)
    return completion(messages=messages, **params)
"""
    assert _d267_lines(tmp_path, code) == []


def test_module_level_dicts(tmp_path):
    script = """
from litellm import completion

params = {"model": "m", "messages": []}
completion(**params)
"""
    assert _d267_lines(tmp_path, script) == [(5, True)]
    shared = """
from litellm import completion

params = {"model": "m", "messages": []}

def configure():
    params["max_tokens"] = 100

configure()
completion(**params)
"""
    assert _d267_lines(tmp_path, shared) == []


def test_a_nested_local_with_the_same_name_is_another_dict(tmp_path):
    code = """
from litellm import completion

def ask(messages):
    options = {"model": "gpt-4o", "messages": messages}

    def unrelated():
        options = {"timeout": 30}
        return options

    return completion(**options)

def shared(messages):
    options = {"model": "gpt-4o", "messages": messages}

    def configure():
        options["max_tokens"] = 100
        options["timeout"] = 30

    configure()
    return completion(**options)

def declared(messages):
    options = {"model": "gpt-4o", "messages": messages}

    def configure():
        nonlocal options
        options = {"max_tokens": 100, "timeout": 30}

    configure()
    return completion(**options)
"""
    assert _d267_lines(tmp_path, code) == [(11, True)]



def test_a_guarded_limit_counts_only_with_a_real_default_limit(tmp_path):
    code = """
from litellm import completion

def no_default(messages, max_tokens):
    params = {"timeout": 30}
    if max_tokens:
        params["max_tokens"] = max_tokens
    return completion(messages=messages, **params)

def none_default(messages, max_tokens=None):
    params = {"timeout": 30}
    if max_tokens is not None:
        params["max_tokens"] = max_tokens
    return completion(messages=messages, **params)

def rebound(messages, max_tokens=1024):
    max_tokens = None
    params = {"timeout": 30}
    if max_tokens:
        params["max_tokens"] = max_tokens
    return completion(messages=messages, **params)
"""
    assert _d267_lines(tmp_path, code) == [(8, True), (14, True), (21, True)]


def test_explicitly_disabled_limits_are_not_hidden_by_unknown_kwargs(tmp_path):
    code = """
from litellm import completion

def ask(messages, **kwargs):
    return completion(model="m", messages=messages, max_tokens=None, timeout=None, **kwargs)

def ask_bounded(messages, **kwargs):
    return completion(model="m", messages=messages, max_tokens=None, max_completion_tokens=50, **kwargs)
"""
    findings = _d267_findings(_scan_one(tmp_path, "llm_kwargs_disabled.py", code))
    assert [(f["line"], f["message"].split(":")[1].split(".")[0].strip()) for f in findings] == [
        (5, "no max token limit; no request timeout")
    ]
