"""SKY-U006 must not report FastAPI dependency-injected parameters.

FastAPI runs ``Depends()``/``Security()`` dependencies before the handler even
when the body never reads the value (authentication, authorization, rate
limits). Suggesting the parameter's removal would remove the guard
(agent-pr-bench fa-01).
"""

import json

from skylos.analyzer import analyze


def _unused_parameters(tmp_path, files):
    for rel, source in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest tmp_path with literal filenames
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    return {finding["full_name"] for finding in result["unused_parameters"]}


DEPS = '''
from typing import Annotated
from fastapi import Depends, Security


def get_current_user():
    return 1


CurrentUser = Annotated[int, Depends(get_current_user)]
'''


def test_cross_module_annotated_dependency_alias_is_used(tmp_path):
    unused = _unused_parameters(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/deps.py": DEPS,
            "app/items.py": '''
from fastapi import APIRouter
from app.deps import CurrentUser

router = APIRouter(prefix="/items")


@router.put("/{id}")
def update_item(
    *,
    current_user: CurrentUser,
    id: int,
    unused_flag: bool = False,
) -> dict:
    return {"id": id}
''',
        },
    )
    assert "app.items.update_item.current_user" not in unused
    # Ordinary parameters are still reported.
    assert "app.items.update_item.unused_flag" in unused


def test_inline_depends_security_and_annotated_are_used(tmp_path):
    unused = _unused_parameters(
        tmp_path,
        {
            "main.py": '''
from typing import Annotated
from fastapi import FastAPI, Depends, Security

app = FastAPI()


def verify_token():
    return True


@app.delete("/a")
def delete_a(
    token=Depends(verify_token),
    ignored_flag: bool = False,
):
    return {}


@app.post("/b")
def create_b(
    scoped=Security(verify_token, scopes=["write"]),
    ignored_flag: bool = False,
):
    return {}


@app.post("/c")
def create_c(
    user: Annotated[int, Depends(verify_token)],
    ignored_flag: bool = False,
):
    return {}


def helper(really_unused, x):
    return x


helper(1, 2)
''',
        },
    )
    injected = {
        "main.delete_a.token",
        "main.create_b.scoped",
        "main.create_c.user",
    }
    assert not injected & unused
    # Plain parameters of the same handlers are still reported.
    assert {
        "main.delete_a.ignored_flag",
        "main.create_b.ignored_flag",
        "main.create_c.ignored_flag",
    } <= unused

