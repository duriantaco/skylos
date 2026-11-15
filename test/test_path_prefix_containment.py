"""A prefix check proves containment only when the prefix ends at a separator.

``"/srv/files2/x".startswith("/srv/files")`` is true, so a resolved path
checked against a base without a trailing separator can still reach a
sibling directory such as ``/srv/files2``.
"""

import pytest

from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture

HEADER = """import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()
BASE = "/srv/files"
"""


def traversal_lines(tmp_path, code):
    path = write_fixture(tmp_path, "server.py", code)
    return [f["line"] for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == "SKY-D215"]


def route(check, body=None, prefix_lines=""):
    if body is None:
        body = "    target = os.path.normpath(os.path.join(BASE, name))\n"
    return (
        HEADER
        + prefix_lines
        + "\n\n@app.get('/files/{name}')\ndef download(name: str):\n"
        + body
        + f"    if not {check}:\n"
        + "        raise HTTPException(404)\n"
        + "    return FileResponse(target)\n"
    )


def sink_line(code):
    return code.splitlines().index("    return FileResponse(target)") + 1


@pytest.mark.parametrize(
    ("check", "body", "prefix_lines"),
    [
        ("target.startswith(BASE)", None, ""),
        (
            "target.startswith(os.path.realpath(BASE))",
            "    target = os.path.realpath(os.path.join(BASE, name))\n",
            "",
        ),
        (
            "target.startswith(base)",
            "    base = os.path.abspath(load_setting())\n    target = os.path.normpath(os.path.join(base, name))\n",
            "",
        ),
        (
            "str(target).startswith(str(Path(BASE).resolve()))",
            "    target = (Path(BASE) / name).resolve()\n",
            "",
        ),
        ("target.startswith((BASE + os.sep, OTHER))", None, "OTHER = '/srv/other'\n"),
        ("target.startswith(PREFIX)", None, "PREFIX = BASE + os.sep\nPREFIX = BASE\n"),
        (
            "target.startswith(PREFIX)",
            "    PREFIX = BASE\n    target = os.path.normpath(os.path.join(BASE, name))\n",
            "PREFIX = '/srv/files/'\n",
        ),
        (
            "target.startswith(prefix)",
            "    prefix = load_prefix()\n    target = os.path.normpath(os.path.join(BASE, name))\n",
            "",
        ),
        (
            "target.startswith(BASE + suffix)",
            "    suffix = load_suffix()\n    target = os.path.normpath(os.path.join(BASE, name))\n",
            "",
        ),
        ("target.startswith(os.path.join(BASE, 'public'))", None, ""),
        ("target.startswith(os.sep)", None, ""),
        ("target.startswith('/')", None, ""),
        ("target.startswith(f'{os.sep}')", None, ""),
        ("target.startswith(SEP)", None, "SEP = os.path.sep\n"),
        ("target.startswith(sep)", None, "from os import sep\n"),
        ("target.startswith(os.path.join(BASE, '/'))", None, ""),
        ("target.startswith(os.path.join('/', ''))", None, ""),
        (
            "target.startswith(os.path.join(base, ''))",
            "    base = ''\n    target = os.path.normpath(os.path.join(BASE, name))\n",
            "",
        ),
    ],
)
def test_prefix_without_a_separator_does_not_prove_containment(
    tmp_path, check, body, prefix_lines
):
    code = route(check, body, prefix_lines)

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


@pytest.mark.parametrize(
    ("check", "body", "prefix_lines"),
    [
        ("target.startswith(BASE + os.sep)", None, ""),
        ("target.startswith(BASE + os.path.sep)", None, ""),
        ("target.startswith(BASE + '/')", None, ""),
        ("target.startswith(f'{BASE}/')", None, ""),
        ("target.startswith(BASE + sep)", None, "from os import sep\n"),
        ("target.startswith(BASE + sep)", None, "from os.path import sep\n"),
        ("target.startswith(BASE + separator)", None, "from os import sep as separator\n"),
        ("target.startswith(f'{BASE}{sep}')", None, "from os import sep\n"),
        (
            "target.startswith((BASE + sep, OTHER + '/'))",
            None,
            "from os import sep\nOTHER = '/srv/other'\n",
        ),
        ("target.startswith(os.path.join(BASE, ''))", None, ""),
        (
            "target.startswith(PREFIXES)",
            None,
            "OTHER = '/srv/other'\nPREFIXES = (BASE + os.sep, OTHER + '/')\n",
        ),
        ("target.startswith('/srv/files/')", None, ""),
        (
            "target.startswith(PREFIX)",
            None,
            "PREFIX = os.path.realpath(BASE) + os.sep\n",
        ),
        ("target.startswith(PREFIX)", None, "PREFIX = '/srv/files/'\n"),
        (
            "target.startswith(prefix)",
            "    prefix = BASE + os.sep\n    target = os.path.normpath(os.path.join(BASE, name))\n",
            "",
        ),
        (
            "target.startswith((BASE + os.sep, OTHER + '/'))",
            None,
            "OTHER = '/srv/other'\n",
        ),
        (
            "str(target).startswith(str(Path(BASE).resolve()) + os.sep)",
            "    target = (Path(BASE) / name).resolve()\n",
            "",
        ),
        ("target.startswith(os.path.join(BASE, 'public/'))", None, ""),
    ],
)
def test_prefix_ending_at_a_separator_still_proves_containment(
    tmp_path, check, body, prefix_lines
):
    assert traversal_lines(tmp_path, route(check, body, prefix_lines)) == []


def test_sibling_prefix_in_a_positive_branch_is_reported(tmp_path):
    code = (
        HEADER
        + "\n\n@app.get('/files/{name}')\ndef download(name: str):\n"
        + "    target = os.path.normpath(os.path.join(BASE, name))\n"
        + "    if target.startswith(BASE):\n"
        + "        return FileResponse(target)\n"
        + "    raise HTTPException(404)\n"
    )

    line = code.splitlines().index("        return FileResponse(target)") + 1

    assert traversal_lines(tmp_path, code) == [line]


def test_sep_rebound_in_the_checking_function_does_not_prove_containment(tmp_path):
    code = """import os
from os import sep

BASE = "/srv/files"

def read(sep, name):
    if ".." in name:
        raise ValueError
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(BASE + sep):
        raise ValueError
    return open(target).read()
"""

    assert traversal_lines(tmp_path, code) == [12]


def test_separator_prefix_in_a_positive_branch_stays_quiet(tmp_path):
    code = (
        HEADER
        + "\n\n@app.get('/files/{name}')\ndef download(name: str):\n"
        + "    target = os.path.normpath(os.path.join(BASE, name))\n"
        + "    if target.startswith(BASE + os.sep):\n"
        + "        return FileResponse(target)\n"
        + "    raise HTTPException(404)\n"
    )

    assert traversal_lines(tmp_path, code) == []


def test_fake_os_module_separator_does_not_prove_containment(tmp_path):
    code = route("target.startswith(BASE + os.sep)").replace(
        'BASE = "/srv/files"\n',
        "BASE = \"/srv/files\"\n\n\nclass os:\n    sep = ''\n    path = __import__('os').path\n",
    )

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


def test_flask_open_with_sibling_prefix_check_is_reported(tmp_path):
    code = """import os
from flask import Flask, abort, request

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/read")
def read():
    path = os.path.realpath(os.path.join(BASE, request.args["f"]))
    if not path.startswith(BASE):
        abort(403)
    with open(path) as handle:
        return handle.read()
"""

    assert traversal_lines(tmp_path, code) == [13]


def test_flask_open_with_separator_prefix_check_stays_quiet(tmp_path):
    code = """import os
from flask import Flask, abort, request

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/read")
def read():
    path = os.path.realpath(os.path.join(BASE, request.args["f"]))
    if not path.startswith(BASE + os.sep):
        abort(403)
    with open(path) as handle:
        return handle.read()
"""

    assert traversal_lines(tmp_path, code) == []


def test_tuple_prefix_members_resolve_in_their_declaration_scope(tmp_path):
    # The module binds BASE to "", so PREFIXES is ("/",): a prefix of only
    # separators, which proves nothing. The function's own BASE is a
    # different binding and must not be used to expand the tuple.
    code = """import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()
BASE = ""
PREFIXES = (BASE + "/",)


@app.get("/files/{name}")
def download(name: str):
    BASE = "/srv/files"
    target = os.path.normpath(os.path.join(BASE, name))
    if not target.startswith(PREFIXES):
        raise HTTPException(404)
    return FileResponse(target)
"""

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


def test_import_alias_from_another_scope_does_not_prove_containment(tmp_path):
    # The module's S is os.extsep ("."); a separator imported as S inside an
    # unrelated function says nothing about it.
    code = """import os
from os import extsep as S
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()
BASE = "/srv/files"


def unrelated(path):
    from os import sep as S
    return path + S


@app.get("/files/{name}")
def download(name: str):
    target = os.path.normpath(os.path.join(BASE, name))
    if not target.startswith(BASE + S):
        raise HTTPException(404)
    return FileResponse(target)
"""

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


def test_self_referential_tuple_prefix_does_not_abort_the_scan(tmp_path):
    code = """import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()
BASE = "/srv/files"
PREFIXES = (PREFIXES,)


@app.get("/files/{name}")
def download(name: str):
    target = os.path.normpath(os.path.join(BASE, name))
    if not target.startswith(PREFIXES):
        raise HTTPException(404)
    return FileResponse(target)
"""

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


@pytest.mark.parametrize("named", [False, True], ids=["inline", "local-name"])
@pytest.mark.parametrize("base", ["", "/srv/files"], ids=["empty", "contained"])
def test_local_tuple_members_keep_their_function_bindings(tmp_path, named, base):
    body = (
        f"    local_base = {base!r}\n"
        "    local_prefixes = (local_base + '/',)\n"
        "    target = os.path.normpath(os.path.join(BASE, name))\n"
    )
    prefixes = "local_prefixes" if named else "(local_base + '/',)"
    code = route(f"target.startswith({prefixes})", body)

    expected = [] if base else [sink_line(code)]
    assert traversal_lines(tmp_path, code) == expected


@pytest.mark.parametrize(
    "imports",
    [
        "from os import sep as S\nfrom os import extsep as S\n",
        "if choose_separator:\n    from os import sep as S\n"
        "else:\n    from os import extsep as S\n",
    ],
    ids=["later-import", "conditional-import"],
)
def test_ambiguous_separator_imports_do_not_hide_a_sibling_path(tmp_path, imports):
    code = route("target.startswith(BASE + S)", prefix_lines=imports)

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


def test_repeated_imports_of_the_same_separator_still_prove_containment(tmp_path):
    code = route(
        "target.startswith(BASE + S)",
        prefix_lines="from os import sep as S\nfrom os import sep as S\n",
    )

    assert traversal_lines(tmp_path, code) == []


def test_function_import_cannot_borrow_a_module_separator_binding(tmp_path):
    body = (
        "    from os import extsep as S\n"
        "    target = os.path.normpath(os.path.join(BASE, name))\n"
    )
    code = route("target.startswith(BASE + S)", body, "from os import sep as S\n")

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


def test_inline_tuple_can_use_a_local_base_that_shadows_the_module(tmp_path):
    body = (
        "    BASE = '/srv/other'\n"
        "    target = os.path.normpath(os.path.join(BASE, name))\n"
    )
    code = route("target.startswith((BASE + '/',))", body)

    assert traversal_lines(tmp_path, code) == []


@pytest.mark.parametrize(
    ("module_base", "local_base"),
    [("", "/srv/files"), ("/srv/files", "")],
    ids=["vacuous-module-prefix", "contained-module-prefix"],
)
def test_scalar_prefix_alias_keeps_its_declaration_scope(
    tmp_path, module_base, local_base
):
    code = (
        "import os\nfrom fastapi import FastAPI, HTTPException\n"
        "from fastapi.responses import FileResponse\napp = FastAPI()\n"
        f"BASE = {module_base!r}\nPREFIX = BASE + '/'\n"
        "@app.get('/files/{name}')\ndef download(name: str):\n"
        f"    BASE = {local_base!r}\n"
        "    target = os.path.normpath(os.path.join('/srv/files', name))\n"
        "    if not target.startswith(PREFIX):\n        raise HTTPException(404)\n"
        "    return FileResponse(target)\n"
    )

    expected = [] if module_base else [sink_line(code)]
    assert traversal_lines(tmp_path, code) == expected


@pytest.mark.parametrize(
    ("check", "imports"),
    [
        ("target.startswith(os.path.join(BASE, '/', ''))", ""),
        (
            r"target.startswith(ntpath.join(BASE, '\\', ''))",
            "import ntpath\n",
        ),
    ],
    ids=["posix-root-reset", "windows-root-reset"],
)
def test_join_that_resets_the_base_to_a_root_is_not_containment(
    tmp_path, check, imports
):
    code = route(check, prefix_lines=imports)

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


def test_join_to_a_real_subdirectory_with_trailing_empty_part_stays_quiet(tmp_path):
    code = route("target.startswith(os.path.join(BASE, 'public', ''))")

    assert traversal_lines(tmp_path, code) == []


@pytest.mark.parametrize("scope", ["module", "local"])
@pytest.mark.parametrize("tuple_prefix", [False, True], ids=["scalar", "tuple"])
@pytest.mark.parametrize("literal", [False, True], ids=["captured-name", "literal"])
def test_prefix_capture_does_not_borrow_a_later_base_assignment(
    tmp_path, scope, tuple_prefix, literal
):
    value = "'/srv/files/'" if literal else "captured_base + '/'"
    if tuple_prefix:
        value = f"({value},)"
    bindings = (
        "captured_base = ''\n"
        f"captured_prefix = {value}\n"
        "captured_base = '/srv/files'\n"
    )
    body = "    target = os.path.normpath(os.path.join(BASE, name))\n"
    prefix_lines = bindings if scope == "module" else ""
    if scope == "local":
        body = "".join("    " + line + "\n" for line in bindings.splitlines()) + body
    code = route("target.startswith(captured_prefix)", body, prefix_lines)

    expected = [] if literal else [sink_line(code)]
    assert traversal_lines(tmp_path, code) == expected


@pytest.mark.parametrize("tuple_prefix", [False, True], ids=["scalar", "tuple"])
def test_prefix_capture_does_not_borrow_a_function_global_reassignment(
    tmp_path, tuple_prefix
):
    value = "captured_base + '/'"
    if tuple_prefix:
        value = f"({value},)"
    code = route(
        "target.startswith(captured_prefix)",
        "    global captured_base\n"
        "    captured_base = '/srv/files'\n"
        "    target = os.path.normpath(os.path.join(BASE, name))\n",
        "captured_base = ''\n" + f"captured_prefix = {value}\n",
    )

    assert traversal_lines(tmp_path, code) == [sink_line(code)]


@pytest.mark.parametrize(
    ("helper_shadow", "caller_shadow", "unrelated_shadow"),
    [
        (True, False, False),
        (True, True, False),
        (False, False, False),
        (False, True, False),
        (False, False, True),
        (False, True, True),
    ],
    ids=[
        "helper-provider-is-not-re",
        "both-scopes-shadow-re",
        "module-provider-is-re",
        "caller-shadow-does-not-change-helper",
        "unrelated-shadow-does-not-change-helper",
        "caller-and-unrelated-shadows",
    ],
)
def test_filename_helper_reads_regex_provider_in_its_own_scope(
    tmp_path, helper_shadow, caller_shadow, unrelated_shadow
):
    code = (
        "import re\nfrom pathlib import Path\nfrom fastapi import FastAPI\n"
        "from fastapi.responses import FileResponse\napp = FastAPI()\n"
        "def checked(raw: str):\n"
    )
    if helper_shadow:
        code += "    import evil as re\n"
    code += (
        "    if not re.fullmatch(r'[A-Za-z0-9_-]+', raw):\n"
        "        raise ValueError\n    return raw\n"
    )
    if unrelated_shadow:
        code += "def unrelated():\n    import evil as re\n    return re\n"
    code += "@app.get('/files/{raw}')\ndef view(raw: str):\n"
    if caller_shadow:
        code += "    import evil as re\n"
    code += "    return FileResponse(Path('/srv') / checked(raw))\n"
    line = len(code.splitlines())

    assert traversal_lines(tmp_path, code) == ([line] if helper_shadow else [])


@pytest.mark.parametrize(
    ("parameters", "bindings", "receiver", "trusted"),
    [
        ("", "    import re\n", "re", True),
        ("", "    import re as rx\n", "rx", True),
        ("", "    import evil as re\n", "re", False),
        ("", "    import evil as rx\n", "rx", False),
        ("", "    import re\n    import evil as re\n", "re", False),
        (
            "",
            "    if choose_provider:\n        import re\n"
            "    else:\n        import evil as re\n",
            "re",
            False,
        ),
        (", re=provider", "", "re", False),
        ("", "    re = provider\n", "re", False),
    ],
    ids=[
        "local-stdlib-import",
        "local-stdlib-alias",
        "fake-local-provider",
        "fake-local-alias",
        "conflicting-local-imports",
        "conditional-local-imports",
        "parameter-shadows-provider",
        "assignment-shadows-provider",
    ],
)
def test_filename_helper_requires_its_actual_local_regex_provider(
    tmp_path, parameters, bindings, receiver, trusted
):
    code = (
        "import re\nimport evil as provider\nfrom pathlib import Path\n"
        "from fastapi import FastAPI\nfrom fastapi.responses import FileResponse\n"
        "app = FastAPI()\n"
        f"def checked(raw: str{parameters}):\n"
        + bindings
        + f"    if not {receiver}.fullmatch(r'[A-Za-z0-9_-]+', raw):\n"
        "        raise ValueError\n    return raw\n"
        "@app.get('/files/{raw}')\ndef view(raw: str):\n"
        "    return FileResponse(Path('/srv') / checked(raw))\n"
    )

    expected = [] if trusted else [len(code.splitlines())]
    assert traversal_lines(tmp_path, code) == expected
