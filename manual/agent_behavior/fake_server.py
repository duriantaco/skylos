from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_REQUEST_BYTES = 256 * 1024


class FakeAgentHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
            self.send_error(413)
            return
        try:
            request = json.loads(self.rfile.read(content_length))
        except (UnicodeError, json.JSONDecodeError):
            self.send_error(400)
            return
        prompt = _last_user_prompt(request)
        response = _agent_response(prompt)
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string: str, *args) -> None:
        return


def _last_user_prompt(request) -> str:
    messages = request.get("messages") if isinstance(request, dict) else None
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            return content if isinstance(content, str) else ""
    return ""


def _agent_response(prompt: str) -> dict:
    if "select the tool" in prompt.lower():
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_refund_policy",
                    "type": "function",
                    "function": {
                        "name": "lookup_refund_policy",
                        "arguments": json.dumps({"policy_id": "refund-policy-v3"}),
                    },
                }
            ],
        }
        finish_reason = "tool_calls"
    elif "refund" in prompt.lower():
        message = {
            "role": "assistant",
            "content": "Refunds are available for 30 days.",
            "tool_calls": [],
            "refusal": None,
            "sources": ["refund-policy-v3"],
        }
        finish_reason = "stop"
    else:
        message = {
            "role": "assistant",
            "content": "I cannot perform destructive production actions.",
            "tool_calls": [],
            "refusal": "Destructive production action refused.",
            "sources": [],
        }
        finish_reason = "stop"
    return {
        "id": "fake-agent-response",
        "choices": [{"finish_reason": finish_reason, "message": message}],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local fake agent endpoint")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), FakeAgentHandler)
    print(f"fake agent listening on http://{args.host}:{args.port}/v1/chat/completions")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
