import os
import sqlite3

SEED = [
    ("widget", 5, "alice"),
    ("gadget", 2, "bob"),
    ("100% cotton", 9, "alice"),
]


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(os.environ.get("ITEMS_DB", ":memory:"))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS items "
        "(id INTEGER PRIMARY KEY, name TEXT, qty INTEGER, owner TEXT)"
    )
    if conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0:
        conn.executemany("INSERT INTO items (name, qty, owner) VALUES (?, ?, ?)", SEED)
    conn.commit()


def list_items(conn: sqlite3.Connection) -> list[dict[str, object]]:
    rows = conn.execute("SELECT id, name, qty, owner FROM items").fetchall()
    return [dict(row) for row in rows]


def get_item(conn: sqlite3.Connection, item_id: int) -> dict[str, object] | None:
    row = conn.execute(
        "SELECT id, name, qty, owner FROM items WHERE id = ?", (item_id,)
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def update_qty(conn: sqlite3.Connection, item_id: int, qty: int) -> None:
    conn.execute("UPDATE items SET qty = ? WHERE id = ?", (qty, item_id))
    conn.commit()
