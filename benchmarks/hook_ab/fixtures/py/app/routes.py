import sqlite3

from flask import Blueprint, abort, g, jsonify, request
from flask.typing import ResponseReturnValue

from app import db

bp = Blueprint("items", __name__)


def _conn() -> sqlite3.Connection:
    if "conn" not in g:
        g.conn = db.connect()
        db.init_db(g.conn)
    conn: sqlite3.Connection = g.conn
    return conn


def _current_user() -> str:
    user = request.headers.get("X-User")
    if not user:
        abort(401)
    return user


@bp.get("/items")
def list_items() -> ResponseReturnValue:
    return jsonify(db.list_items(_conn()))


@bp.get("/items/<int:item_id>")
def get_item(item_id: int) -> ResponseReturnValue:
    item = db.get_item(_conn(), item_id)
    if item is None:
        abort(404)
    return jsonify(item)


@bp.put("/items/<int:item_id>")
def update_item(item_id: int) -> ResponseReturnValue:
    user = _current_user()
    conn = _conn()
    item = db.get_item(conn, item_id)
    if item is None:
        abort(404)
    if item["owner"] != user:
        abort(403)
    payload = request.get_json()
    db.update_qty(conn, item_id, int(payload["qty"]))
    return jsonify(db.get_item(conn, item_id))
