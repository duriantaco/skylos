"""Flask app factories, blueprint app hooks and callback signatures, plus
SQLModel/SQLAlchemy declarative fields."""

from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text, encoding="utf-8")


def _reported(result: dict) -> set[tuple[str, str]]:
    return {
        (key, item["full_name"])
        for key in (
            "unused_functions",
            "unused_variables",
            "unused_parameters",
            "unused_classes",
        )
        for item in result.get(key) or []
    }


_FLASKR = {
    "flaskr/__init__.py": (
        "from flask import Flask\n\n\n"
        "def create_app(test_config=None):\n"
        "    app = Flask(__name__)\n"
        "    from . import db\n"
        "    db.init_app(app)\n"
        "    from . import auth\n"
        "    app.register_blueprint(auth.bp)\n"
        "    return app\n"
    ),
    "flaskr/auth.py": (
        "from flask import Blueprint, g\n\n"
        'bp = Blueprint("auth", __name__, url_prefix="/auth")\n\n\n'
        "@bp.before_app_request\n"
        "def load_logged_in_user():\n"
        "    g.user = None\n\n\n"
        "def stale_helper():\n"
        "    return 1\n"
    ),
    "flaskr/db.py": (
        "from flask import g\n\n\n"
        "def close_db(e=None):\n"
        '    db = g.pop("db", None)\n'
        "    if db is not None:\n"
        "        db.close()\n\n\n"
        "def unused_with_param(value):\n"
        "    return 1\n\n\n"
        "def init_app(app):\n"
        "    app.teardown_appcontext(close_db)\n"
    ),
}


def test_flask_tutorial_factory_blueprint_hook_and_teardown_signature(tmp_path):
    _write(tmp_path, _FLASKR)

    # Confidence 50 also lists unused parameters (hidden at the default 60),
    # so the Flask callback-signature rule is checked where it matters.
    reported = _reported(json.loads(analyze(str(tmp_path), conf=50, grep_cache=False)))

    assert ("unused_functions", "flaskr.auth.load_logged_in_user") not in reported
    assert ("unused_functions", "flaskr.__init__.create_app") not in reported
    assert ("unused_functions", "flaskr.create_app") not in reported
    assert not any(name.endswith("close_db.e") for _k, name in reported)
    assert any(name.endswith("stale_helper") for _k, name in reported)
    assert any(name.endswith("unused_with_param") for _k, name in reported)
    assert ("unused_parameters", "flaskr.db.unused_with_param.value") in reported


def test_blueprint_hook_without_any_registration_stays_reported(tmp_path):
    _write(
        tmp_path,
        {
            "app/views.py": (
                "from flask import Blueprint\n\n"
                'bp = Blueprint("views", __name__)\n\n\n'
                "@bp.before_app_request\n"
                "def never_installed():\n"
                "    return None\n"
            ),
        },
    )

    reported = _reported(json.loads(analyze(str(tmp_path), grep_cache=False)))

    assert any(name.endswith("never_installed") for _k, name in reported)


def test_sqlmodel_table_and_declarative_relationship_fields(tmp_path):
    _write(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/base.py": (
                "from sqlalchemy.orm import declarative_base\n"
                "ModelBase = declarative_base()\n"
            ),
            "app/models.py": (
                "import uuid\n"
                "from sqlmodel import Field, Relationship, SQLModel\n"
                "from sqlalchemy import Column, ForeignKey, Integer\n"
                "from sqlalchemy.orm import relationship\n"
                "from app.base import ModelBase\n\n\n"
                "class ItemBase(SQLModel):\n"
                "    title: str = Field(min_length=1)\n\n\n"
                "class Item(ItemBase, table=True):\n"
                "    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)\n"
                '    owner: "User | None" = Relationship(back_populates="items")\n\n\n'
                "class User(SQLModel, table=True):\n"
                '    items: list[Item] = Relationship(back_populates="owner")\n\n\n'
                "class Post(ModelBase):\n"
                '    __tablename__ = "post"\n'
                "    id = Column(Integer, primary_key=True)\n"
                '    author_id = Column(Integer, ForeignKey("user.id"))\n'
                '    author = relationship("Author")\n\n\n'
                "def list_models():\n"
                "    return [Item, User, Post]\n\n\n"
                "def stale_query():\n"
                "    return None\n"
            ),
            "app/main.py": (
                "from app.models import list_models\n\n"
                'if __name__ == "__main__":\n'
                "    print(list_models())\n"
            ),
        },
    )

    reported = _reported(json.loads(analyze(str(tmp_path), grep_cache=False)))

    for field in ("owner", "items", "author", "author_id", "title"):
        assert not any(
            key == "unused_variables" and name.endswith(f".{field}")
            for key, name in reported
        ), field
    assert ("unused_functions", "app.models.stale_query") in reported
