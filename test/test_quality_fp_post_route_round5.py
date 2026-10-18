"""SKY-F102 on query-named POST routes: third review round.

A query-named POST route is exempt only when its body provably changes
nothing. These cases hid a write behind a callee the rule could not
resolve: a dispatch table or a call result, ``eval``/``exec``, a writer
passed to ``map``, a local that aliases application state or a shared cache
returned by a helper, and SQL sent through a query-named method.
"""

from __future__ import annotations

import ast
import textwrap

import pytest

from skylos.rules.quality.practices import FrameworkPracticeRule


def _f102(code: str) -> list[str]:
    tree = ast.parse(textwrap.dedent(code))
    findings = FrameworkPracticeRule().visit_node(tree, {"filename": "app.py"}) or []
    return [finding["name"] for finding in findings if finding["rule_id"] == "SKY-F102"]


_FLASK = """
    from flask import Flask, jsonify, request

    app = Flask(__name__)
"""

# Expected: each route is reported once.
HIDDEN_WRITES = {
    "raw-sql-from-the-request": _FLASK
    + """
    from .db import Database

    db = Database("postgresql://app@db/app")

    @app.post("/api/query")
    def run_query():
        sql = request.get_json()["sql"]
        return jsonify(rows=db.query(sql))
    """,
    "sql-literal-that-deletes": _FLASK
    + """
    from .db import db

    @app.post("/sessions/lookup")
    def lookup():
        return jsonify(db.query("DELETE FROM sessions WHERE id = %s", (request.json["id"],)))
    """,
    "data-modifying-cte": _FLASK
    + """
    from .db import db

    @app.post("/search")
    def search():
        rows = db.query("WITH gone AS (DELETE FROM jobs RETURNING id) SELECT id FROM gone")
        return jsonify(rows)
    """,
    "sql-literal-in-a-local": _FLASK
    + """
    from .warehouse import client

    @app.post("/report/query")
    def report():
        statement = "INSERT INTO audit (q) VALUES (%s)"
        return jsonify(client.query(statement, (request.json["q"],)))
    """,
    "application-state-reached-through-the-request": """
    from fastapi import FastAPI, Request

    app = FastAPI()

    @app.post("/v1/embed")
    async def embed(body: EmbedRequest, request: Request):
        store = request.app.state.vectors
        vector = encoder.encode(body.text)
        store.add(body.doc_id, vector)
        return {"dim": len(vector)}
    """,
    "shared-cache-returned-by-a-helper": _FLASK
    + """
    from .search import run_search

    _RESULTS = {}

    def results_cache():
        return _RESULTS

    @app.post("/search")
    def search():
        q = request.get_json()["q"]
        cache = results_cache()
        cache[q] = run_search(q)
        return jsonify(cache[q])
    """,
    "shared-cache-from-an-imported-getter": _FLASK
    + """
    from .cache import lookup_results

    @app.post("/search")
    def search():
        cache = lookup_results()
        cache.update({request.json["q"]: 1})
        return jsonify(ok=True)
    """,
    "dispatch-table": _FLASK
    + """
    from . import users

    ACTIONS = {"lookup": users.lookup, "purge": users.purge}

    @app.post("/users/lookup")
    def lookup():
        body = request.get_json()
        return jsonify(ACTIONS[body.get("action", "lookup")](body["id"]))
    """,
    "callee-returned-by-a-call": _FLASK
    + """
    from .handlers import find_handler

    @app.post("/users/lookup")
    def lookup():
        return jsonify(find_handler(request.json["op"])(request.json["id"]))
    """,
    "eval-of-request-data": _FLASK
    + """
    @app.post("/evaluate")
    def evaluate():
        expr = request.get_json()["expr"]
        return jsonify(result=eval(expr))
    """,
    "exec-of-request-data": _FLASK
    + """
    @app.post("/evaluate")
    def evaluate():
        exec(request.get_json()["code"], {})
        return jsonify(ok=True)
    """,
    "imported-writer-passed-to-map": _FLASK
    + """
    from .index import find_documents
    from .store import remember

    @app.post("/search/batch")
    def batch_search():
        queries = request.get_json()["queries"]
        hits = [find_documents(q) for q in queries]
        list(map(remember, queries))
        return jsonify(hits)
    """,
    "module-writer-passed-as-an-argument": _FLASK
    + """
    from .index import find_documents

    HISTORY = []

    def _remember(query):
        HISTORY.append(query)

    @app.post("/search/batch")
    def batch_search():
        queries = request.get_json()["queries"]
        for _ in map(_remember, queries):
            pass
        return jsonify([find_documents(q) for q in queries])
    """,
}


@pytest.mark.parametrize("code", HIDDEN_WRITES.values(), ids=HIDDEN_WRITES.keys())
def test_query_named_post_with_hidden_write_is_reported(code):
    assert len(_f102(code)) == 1


# Expected: no finding.
READ_ONLY = {
    "select-literal": _FLASK
    + """
    from .db import db

    @app.post("/users/search")
    def search():
        rows = db.query("SELECT id, name FROM users WHERE name ILIKE %s", (request.json["q"],))
        return jsonify(rows)
    """,
    "select-with-a-replace-function": _FLASK
    + """
    from .db import db

    @app.post("/users/search")
    def search():
        sql = "SELECT replace(name, '-', ' ') FROM users WHERE note <> 'delete me'"
        return jsonify(db.query(sql))
    """,
    "orm-query-of-a-model": _FLASK
    + """
    from .models import User, session

    @app.post("/users/search")
    def search():
        return jsonify(session.query(User).count())
    """,
    "rag-query-engine-with-a-local-question": """
    from fastapi import FastAPI

    app = FastAPI()

    @app.post("/ask/query")
    def ask(body: AskBody) -> dict:
        question = body.question.strip()
        response = query_engine.query(question)
        return {"answer": str(response)}
    """,
    "vector-query-with-keywords": """
    from fastapi import FastAPI

    app = FastAPI()

    @app.post("/search")
    def search(body: SearchBody) -> dict:
        matches = index.query(vector=encoder.encode(body.text), top_k=5)
        return {"ids": [m.id for m in matches]}
    """,
    "results-built-and-sorted-locally": """
    from fastapi import FastAPI

    app = FastAPI()

    @app.post("/search")
    def search(body: SearchBody) -> dict:
        hits = es.search(index="docs", query={"match": {"body": body.q}})
        docs = hits["hits"]["hits"]
        docs.sort(key=lambda doc: doc["_score"], reverse=True)
        ranked = sorted(docs, key=lambda doc: doc["_id"])
        ranked.reverse()
        response = {"docs": ranked}
        response["count"] = len(ranked)
        return response
    """,
    "prediction-post-processed-in-a-local": _FLASK
    + """
    from datetime import datetime

    from .ml import model

    @app.post("/predict")
    def predict():
        features = request.get_json()["features"]
        prediction = model.predict([features])
        scores = prediction.tolist()
        stamp = datetime.now().replace(microsecond=0)
        return jsonify(scores=scores, at=stamp.isoformat())
    """,
    "builtin-passed-to-map": _FLASK
    + """
    from .index import find_documents

    @app.post("/search")
    def search():
        queries = list(map(str.strip, request.get_json()["queries"]))
        lengths = list(map(len, queries))
        return jsonify(hits=[find_documents(q) for q in queries], lengths=lengths)
    """,
    "read-only-module-helper-passed-to-map": _FLASK
    + """
    from .index import find_documents

    def _normalise(query):
        return query.strip().lower()

    @app.post("/search")
    def search():
        queries = list(map(_normalise, request.get_json()["queries"]))
        return jsonify([find_documents(q) for q in queries])
    """,
}


@pytest.mark.parametrize("code", READ_ONLY.values(), ids=READ_ONLY.keys())
def test_query_named_post_that_only_reads_is_not_reported(code):
    assert _f102(code) == []
