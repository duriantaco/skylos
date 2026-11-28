from pathlib import Path

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        ('window.parent.postMessage({accessToken}, "*");\n', [1]),
        (
            (
                'const frame = document.querySelector("iframe");\n'
                "const target = frame.contentWindow;\n"
                'target.postMessage({accountId: account.id}, {targetOrigin: "*"});\n'
            ),
            [3],
        ),
        ('window.parent.postMessage({accessToken}, "https://app.example");\n', []),
        ('window.parent.postMessage({type: "ready"}, "*");\n', []),
        ('globalThis.window.postMessage({accessToken}, "*");\n', [1]),
        (
            (
                'window.addEventListener("message", event => {\n'
                '  fetch("/preferences", {method: "POST", body: JSON.stringify(event.data)});\n'
                "});\n"
            ),
            [2],
        ),
        (
            (
                'window.addEventListener("message", event => {\n'
                '  fetch("/preferences", {method: "GET"});\n'
                "  console.log(event.data);\n"
                "});\n"
            ),
            [],
        ),
        (
            (
                'window.addEventListener("message", event => {\n'
                "  event = trustedEvent;\n"
                "  document.body.innerHTML = event.data;\n"
                "});\n"
            ),
            [],
        ),
        (
            'const target = new Worker("worker.js");\ntarget.postMessage({accessToken}, "*");',
            [],
        ),
        ('function send(window) { window.postMessage({accessToken}, "*"); }', []),
        (
            'const window = {postMessage() {}};\nwindow.postMessage({accessToken}, "*");',
            [],
        ),
        (
            (
                'window.addEventListener("message", event => {\n'
                "  document.body.innerHTML = event.data.markup;\n"
                "});\n"
            ),
            [2],
        ),
        (
            (
                "function receive(event) {\n"
                "  const destination = event.data.url;\n"
                "  window.location.assign(destination);\n"
                "}\n"
                'window.addEventListener("message", receive);\n'
            ),
            [3],
        ),
        (
            (
                "window.onmessage = event => {\n"
                '  if (event.origin !== "https://app.example") return;\n'
                "  document.body.innerHTML = event.data.markup;\n"
                "};\n"
            ),
            [],
        ),
        (
            (
                'window.addEventListener("message", event => {\n'
                '  if (event.origin === "https://app.example") {\n'
                "    document.body.innerHTML = event.data.markup;\n"
                "  }\n"
                "});\n"
            ),
            [],
        ),
        (
            'window.addEventListener("message", event => console.log(event.data));\n',
            [],
        ),
        (
            (
                'const channel = new BroadcastChannel("app");\n'
                'channel.addEventListener("message", event => {\n'
                "  document.body.innerHTML = event.data;\n"
                "});\n"
            ),
            [],
        ),
        (
            (
                'window.addEventListener("message", event => {\n'
                '  const panel = {innerHTML: ""};\n'
                "  panel.innerHTML = event.data;\n"
                "});\n"
            ),
            [],
        ),
    ],
)
def test_browser_post_message_origin_policy(tmp_path, source, lines):
    path = tmp_path / "messages.ts"
    path.write_text(source)

    findings = scan_typescript_file(str(path), {})[7]
    assert [
        (Path(row["file"]).name, row["line"])
        for row in findings
        if row["rule_id"] == "SKY-D431"
    ] == [("messages.ts", line) for line in lines]
