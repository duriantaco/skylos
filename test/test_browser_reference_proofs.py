"""Browser liveness needs a consumer, a loaded script and resolved source effects."""

import json
import textwrap
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.deadcode.browser_refs import collect_browser_event_handler_refs
from skylos.visitors.languages.typescript.file_references import (
    collect_ts_path_references,
)
from test.fixture_paths import write_fixture


def _write(root, relative, source):
    return write_fixture(root, relative, textwrap.dedent(source).lstrip())


def _script(root, *, loaded=True, module=False):
    _write(
        root,
        "web/app.js",
        "function browserOnly() { return 1; }\nfunction untouched() { return 2; }\n",
    )
    if loaded:
        kind = ' type="module"' if module else ""
        _write(root, "index.html", f'<script{kind} src="web/app.js"></script>\n')


def _browser_refs(root):
    return {
        name
        for name, _ in collect_browser_event_handler_refs(root, list(root.rglob("*")))
    }


def _loaded_paths(root):
    scripts = {str(path.resolve()) for path in root.rglob("*.js")}
    roots, _ = collect_ts_path_references(root, scripts, scripts)
    return {str(Path(path).relative_to(root.resolve())) for path in roots}


@pytest.mark.parametrize(
    "source",
    [
        'label = "browserOnly"\nprint(label)\n',
        'message = "Example: browserOnly() is not used."\nprint(message)\n',
    ],
)
def test_labels_and_messages_leave_dead_functions_reported(tmp_path, source):
    _write(tmp_path, "app.py", source)
    _script(tmp_path, loaded=False)

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    names = {item.get("name") for item in result.get("unused_functions", [])}

    assert {"browserOnly", "untouched"} <= names
    assert _browser_refs(tmp_path) == set()


@pytest.mark.parametrize(
    "source",
    [
        """
    def list_scripts(folder, extension):
        return []

    def build():
        head = ""
        for script in list_scripts("assets", ".js"):
            head += f'<script src="{script}"></script>'
        return head

    print(build())
    """,
        '''
    def describe():
        """Example only: <script src="assets/stale.js"></script>"""
        return 1

    print(describe())
    ''',
    ],
)
def test_stub_and_docstring_leave_dead_files_reported(tmp_path, source):
    _write(tmp_path, "app.py", source)
    _write(tmp_path, "assets/stale.js", "function stale() { return 1; }\n")
    _write(
        tmp_path, "plugins/other/assets/orphan.js", "function orphan() { return 1; }\n"
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = {item["file"] for item in result.get("unused_files", [])}

    assert str(tmp_path / "assets/stale.js") in unused
    assert str(tmp_path / "plugins/other/assets/orphan.js") in unused
    assert _loaded_paths(tmp_path) == set()


@pytest.mark.parametrize(
    "source",
    [
        'import gradio as gr\nbutton = gr.Button()\nbutton.click(_js="browserOnly")\n',
        'from selenium import webdriver\ndriver = webdriver.Chrome()\ndriver.execute_script("browserOnly()")\n',
        'from nicegui import ui\nui.run_javascript("browserOnly()")\n',
        "page = '<script>browserOnly()</script>'\nprint(page)\n",
        "page = '<a href=\"javascript:browserOnly()\">open</a>'\nprint(page)\n",
    ],
)
def test_real_browser_consumers_reference_only_loaded_classic_functions(
    tmp_path, source
):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)

    assert "browserOnly" in _browser_refs(tmp_path)
    assert "untouched" not in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        'def execute_script(value):\n    return value\nexecute_script("browserOnly()")\n',
        'def run_javascript(value):\n    return value\nrun_javascript("browserOnly()")\n',
        'class Fake:\n    def click(self, **kwargs):\n        return kwargs\nbutton = Fake()\nbutton.click(_js="browserOnly")\n',
        'from nicegui import ui\nui.run_javascript = print\nui.run_javascript("browserOnly()")\n',
        'import gradio as gr\nbutton = gr.Button()\nbutton.click = print\nbutton.click(_js="browserOnly")\n',
        'from nicegui import ui\ndef unused():\n    ui.run_javascript("browserOnly()")\n',
        "page = '<p>Example: browserOnly()</p>'\nprint(page)\n",
        "page = '<script type=\"application/json\">browserOnly()</script>'\nprint(page)\n",
    ],
)
def test_browser_lookalikes_are_not_consumers(tmp_path, source):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)

    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize("loaded,module", [(False, False), (True, True)])
def test_real_consumer_does_not_rescue_unloaded_or_module_script(
    tmp_path, loaded, module
):
    _script(tmp_path, loaded=loaded, module=module)
    _write(
        tmp_path,
        "app.py",
        'from nicegui import ui\nui.run_javascript("browserOnly()")\n',
    )

    assert "browserOnly" not in _browser_refs(tmp_path)


def test_local_provider_shadow_is_not_a_browser_api(tmp_path):
    _script(tmp_path)
    _write(tmp_path, "nicegui.py", "ui = None\n")
    _write(
        tmp_path,
        "app.py",
        'from nicegui import ui\nui.run_javascript("browserOnly()")\n',
    )

    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        'from nicegui import ui\nif False:\n    ui.run_javascript("browserOnly()")\n',
        'from nicegui import ui\nasync def build():\n    ui.run_javascript("browserOnly()")\nbuild()\n',
        'from nicegui import ui\nsetattr(ui, "run_javascript", print)\nui.run_javascript("browserOnly()")\n',
    ],
)
def test_inactive_or_replaced_consumers_leave_functions_reported(tmp_path, source):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)

    assert "browserOnly" not in _browser_refs(tmp_path)


_LISTING_CASES = [
    (
        "import os",
        'for entry in os.scandir("assets"):\n    head += f\'<script src="{entry.path}"></script>\'',
    ),
    (
        "import os",
        'for name in os.listdir("assets"):\n    path = os.path.join("assets", name)\n    head += f\'<script src="{path}"></script>\'',
    ),
    (
        "import glob",
        'for path in glob.glob("assets/*.js"):\n    head += f\'<script src="{path}"></script>\'',
    ),
    (
        "from pathlib import Path",
        'for path in Path("assets").iterdir():\n    head += f\'<script src="{path}"></script>\'',
    ),
    (
        "from pathlib import Path",
        'for path in Path("assets").glob("*.js"):\n    head += f\'<script src="{path}"></script>\'',
    ),
    (
        "import os",
        'for directory, dirs, files in os.walk("assets"):\n    for name in files:\n        path = os.path.join(directory, name)\n        head += f\'<script src="{path}"></script>\'',
    ),
    (
        "import os\ndef files(folder):\n    return [os.path.join(folder, name) for name in os.listdir(folder)]",
        'for path in files("assets"):\n    head += f\'<script src="{path}"></script>\'',
    ),
]


@pytest.mark.parametrize("imports,loop", _LISTING_CASES)
def test_real_directory_effects_load_only_the_exact_directory(tmp_path, imports, loop):
    _write(tmp_path, "assets/active.js", "var active = 1;\n")
    _write(tmp_path, "plugins/other/assets/orphan.js", "var orphan = 1;\n")
    source = (
        imports
        + '\n\ndef build():\n    head = ""\n'
        + textwrap.indent(loop, "    ")
        + "\n    return head\n\nprint(build())\n"
    )
    _write(tmp_path, "app.py", source)

    assert _loaded_paths(tmp_path) == {"assets/active.js"}


@pytest.mark.parametrize("imports,loop", _LISTING_CASES)
def test_removing_directory_consumer_owner_call_removes_load_evidence(
    tmp_path, imports, loop
):
    _write(tmp_path, "assets/active.js", "var active = 1;\n")
    source = (
        imports
        + '\n\ndef build():\n    head = ""\n'
        + textwrap.indent(loop, "    ")
        + "\n    return head\n"
    )
    _write(tmp_path, "app.py", source)

    assert _loaded_paths(tmp_path) == set()


@pytest.mark.parametrize(
    "source",
    [
        'import os\ndef build(root):\n    head = ""\n    for name in os.listdir(root):\n        path = os.path.join(root, name)\n        head += f\'<script src="{path}"></script>\'\n    return head\nbuild(input())\n',
        'def fake(folder, extension):\n    return []\nfor path in fake("assets", ".js"):\n    print(f\'<script src="{path}"></script>\')\n',
        'from os import listdir\ndef listdir(folder):\n    return []\nfor name in listdir("assets"):\n    print(f\'<script src="assets/{name}"></script>\')\n',
        'import os\nos.listdir = lambda folder: []\nfor name in os.listdir("assets"):\n    print(f\'<script src="assets/{name}"></script>\')\n',
        'import os\nfor name in os.listdir("assets"):\n    print(f\'<script src="{name}"></script>\')\n',
    ],
)
def test_directory_lookalikes_and_unknown_roots_are_not_loads(tmp_path, source):
    _write(tmp_path, "assets/active.js", "var active = 1;\n")
    _write(tmp_path, "app.py", source)

    assert _loaded_paths(tmp_path) == set()


@pytest.mark.parametrize(
    "template",
    [
        '<script src="{path}.txt"></script>',
        '<script data-src="{path}"></script>',
        '<script src="{path!r}"></script>',
        '<!-- <script src="{path}"></script> -->',
    ],
)
def test_incomplete_or_nonloading_html_attributes_do_not_load_listed_paths(
    tmp_path, template
):
    _write(tmp_path, "assets/active.js", "var active = 1;\n")
    source = (
        'from pathlib import Path\nfor path in Path("assets").iterdir():\n    print(f'
        + repr(template)
        + ")\n"
    )
    _write(tmp_path, "app.py", source)

    assert _loaded_paths(tmp_path) == set()


def test_python_module_script_with_type_after_src_has_no_page_globals(tmp_path):
    _script(tmp_path, loaded=False)
    _write(
        tmp_path,
        "app.py",
        """
        from nicegui import ui
        page = '<script src="web/app.js" type="module"></script>'
        print(page)
        ui.run_javascript("browserOnly()")
    """,
    )

    assert _loaded_paths(tmp_path) == {"web/app.js"}
    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "effect", ["dirs[:] = []", "dirs.clear()", "files = []", "files.clear()"]
)
def test_mutated_walk_results_are_not_assumed_to_load_the_whole_tree(tmp_path, effect):
    _write(tmp_path, "assets/active.js", "var active = 1;\n")
    _write(tmp_path, "assets/nested/child.js", "var child = 1;\n")
    source = (
        'import os\nfor directory, dirs, files in os.walk("assets"):\n    '
        + effect
        + "\n    for name in files:\n        path = os.path.join(directory, name)\n        print(f'<script src=\"{path}\"></script>')\n"
    )
    _write(tmp_path, "app.py", source)

    assert _loaded_paths(tmp_path) == set()


@pytest.mark.parametrize(
    "source",
    [
        'def build():\n    import gradio as gr\n    control = gr.Button()\n    control.click(_js="browserOnly").then(_js="untouched")\nbuild()\n',
        'import gradio as gr\ncontrol = gr.Button()\ncontrol.click(_js="browserOnly").then(_js="untouched")\n',
    ],
)
def test_sdk_event_chains_and_source_local_imports_preserve_consumers(tmp_path, source):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)
    assert {"browserOnly", "untouched"} <= _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "javascript",
    [
        "// browserOnly()",
        "/* browserOnly() */",
        'function(){ console.log("browserOnly()"); }',
        "function(){ const message = `browserOnly()`; }",
        "function(){ const pattern = /browserOnly()/; }",
        "function(){ function browserOnly(){}; browserOnly(); }",
        "function(window){ window.browserOnly(); }",
    ],
)
def test_javascript_data_comments_and_local_calls_are_not_global_evidence(
    tmp_path, javascript
):
    _script(tmp_path)
    _write(
        tmp_path,
        "app.py",
        "import gradio as gr\ncontrol = gr.Button()\ncontrol.click(_js="
        + repr(javascript)
        + ")\n",
    )
    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize("loaded", [False, True])
def test_python_onclick_label_cannot_use_legacy_fallback(tmp_path, loaded):
    _script(tmp_path, loaded=loaded)
    _write(tmp_path, "app.py", "label = 'onclick=\"browserOnly()\"'\nprint(label)\n")
    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        'class Fake:\n    def __init__(self):\n        self.__provider__ = "gradio.Button"\ncontrol = Fake()\ncontrol.click(_js="browserOnly")\n',
        'import gradio as gr\ncontrol = gr.skip()\ncontrol.click(_js="browserOnly")\n',
    ],
)
def test_internal_or_noncomponent_sdk_values_cannot_forge_event_consumers(
    tmp_path, source
):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)
    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        'import sys\nsys.modules["gradio"] = None\nimport gradio as gr\nbutton = gr.Button()\nbutton.click(None, _js="browserOnly()")\n',
        'import sys\nsys.modules["os"] = None\nimport os\nhead = ""\nfor name in os.listdir("assets"):\n    head += f\'<script src="assets/{name}"></script>\'\n',
    ],
)
def test_replaced_provider_cannot_bypass_shared_source_proof(tmp_path, source):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)
    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            'from flask import Flask\napp = Flask(__name__)\n@app.route("/")\ndef page():\n    return \'<script src="assets/page.js"></script><button onclick="browserOnly()">go</button>\'\n',
            True,
        ),
        (
            'def route(value):\n    return lambda function: function\nclass Fake:\n    route = staticmethod(route)\napp = Fake()\n@app.route("/")\ndef page():\n    return \'<script src="assets/page.js"></script><button onclick="browserOnly()">go</button>\'\n',
            False,
        ),
    ],
)
def test_registered_framework_routes_require_actual_provider(
    tmp_path, source, expected
):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)
    assert ("browserOnly" in _browser_refs(tmp_path)) is expected


@pytest.mark.parametrize(
    "expression,expected",
    [
        ('Action("caption")', True),
        ("Action()", False),
        ('Action(unrelated="caption")', False),
    ],
)
def test_source_sdk_subclass_requires_valid_constructor_binding(
    tmp_path, expression, expected
):
    _script(tmp_path)
    source = """
        import gradio as gr
        class Action(gr.Button):
            def __init__(self, required):
                self.label = required
    """
    _write(
        tmp_path,
        "app.py",
        textwrap.dedent(source)
        + f'button = {expression}\nbutton.click(None, _js="browserOnly()")\n',
    )
    assert ("browserOnly" in _browser_refs(tmp_path)) is expected


@pytest.mark.parametrize(
    "replacement", ["gr.Button.click = print", 'setattr(gr.Button, "click", print)']
)
def test_sdk_class_method_replacement_is_not_browser_evidence(tmp_path, replacement):
    _script(tmp_path)
    source = (
        "import gradio as gr\n"
        + replacement
        + '\nbutton = gr.Button()\nbutton.click(_js="browserOnly()")\n'
    )
    _write(tmp_path, "app.py", source)
    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        'from flask import Flask\nFlask.route = print\napp = Flask(__name__)\n@app.route("/")\ndef page():\n    return \'<script src="assets/page.js"></script><button onclick="browserOnly()">go</button>\'\n',
        'from nicegui import ui\nui.page = print\n@ui.page("/")\ndef page():\n    return \'<script src="assets/page.js"></script><button onclick="browserOnly()">go</button>\'\n',
    ],
)
def test_registered_route_provider_method_replacement_is_not_evidence(tmp_path, source):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)
    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        'import gradio as gr\nbutton = gr.Slider()\nisinstance(button, gr.Slider)\nevent = button.change\nevent(**dict(_js="browserOnly"))\n',
        'import gradio as gr\nfrom argparse import ArgumentParser\nparser = ArgumentParser()\nparser.add_argument("--data", type=dict)\nbutton = gr.Button()\nbutton.click(**dict(_js="browserOnly"))\n',
        'import gradio as gr\nbutton = gr.Button()\nbutton.click(_js="function(){ browserOnly(" + unresolved_value() + "); }")\n',
        'import gradio as gr\nfrom dataclasses import dataclass\n@dataclass\nclass Panel:\n    button = None\npanel = Panel()\npanel.button = gr.Button()\npanel.button.click(_js="browserOnly")\n',
        'class Caption:\n    def __init__(self):\n        self.value = ""\n    def attach(self, callback):\n        self.value += f\'<a onclick="{callback}()">go</a>\'\n        return self\nCaption().attach("browserOnly")\n',
    ],
)
def test_actual_browser_roles_survive_readonly_projections(tmp_path, source):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)
    assert "browserOnly" in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        'import gradio as gr\ndef isinstance(value, kind):\n    value.change = print\nbutton = gr.Slider()\nisinstance(button, gr.Slider)\nevent = button.change\nevent(_js="browserOnly")\n',
        'import gradio as gr\ndef dict(**values):\n    return {}\nbutton = gr.Button()\nbutton.click(**dict(_js="browserOnly"))\n',
        'class Caption:\n    def attach(self, callback):\n        return f"Example: {callback}() is only a label"\nCaption().attach("browserOnly")\n',
    ],
)
def test_browser_projection_lookalikes_keep_findings(tmp_path, source):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)
    assert "browserOnly" not in _browser_refs(tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        'import gradio as gr\ndef ordered():\n    for _, value in sorted(enumerate(["panel"])):\n        yield value\nfor value in ordered():\n    control = gr.Slider()\n    control.change(_js="browserOnly")\n',
        'import gradio as gr\ncontrols = [gr.Button()]\nfor control in controls.copy():\n    control.click(_js="browserOnly")\n',
        "import gradio as gr\ndef page():\n    return '<button onclick=\"browserOnly()\">go</button>'\ninterface = gr.Blocks()\noutput = gr.HTML()\ninterface.load(fn=page, inputs=[], outputs=[output])\n",
        "class Parent:\n    def render(self):\n        self.content = '<button onclick=\"browserOnly()\">go</button>'\nclass Child(Parent):\n    pass\nChild().render()\n",
    ],
)
def test_source_owned_browser_collections_keep_their_actual_consumers(tmp_path, source):
    _script(tmp_path)
    _write(tmp_path, "app.py", source)
    assert "browserOnly" in _browser_refs(tmp_path)
