"""SKY-F102 on query-named POST routes: second review round.

A callee reads as a query only when its own name says so: a word of it is a
query verb (``search_documents``, ``predict_proba``, ``batch_search``) and no
word joins a second action (``fetch_and_store``) or names a write
(``mark_as_read``, ``record_query``). Value methods
(``strip``, ``get``, ``copy``) prove nothing on a long-lived object such as a
module-level client, and logging methods prove nothing unless the receiver is
a logger. Helpers past the inspection depth count as unchecked writes.
"""

from __future__ import annotations

import ast
import textwrap

import pytest

from skylos.rules.quality.practices import FrameworkPracticeRule


def _f102(code: str) -> list[tuple[str, str]]:
    tree = ast.parse(textwrap.dedent(code))
    findings = FrameworkPracticeRule().visit_node(tree, {"filename": "app.py"}) or []
    return [
        (finding["name"], finding["value"])
        for finding in findings
        if finding["rule_id"] == "SKY-F102"
    ]


_FLASK = """
    from flask import Flask, request

    app = Flask(__name__)
"""

# Expected: each route is reported once (it writes through the named call).
HIDDEN_WRITES = {
    "query-word-after-another-verb": _FLASK
    + """
    from . import notifications

    @app.post("/notifications/read")
    def read_notifications():
        notifications.mark_as_read(request.json["ids"])
        return {"ok": True}
    """,
    "query-verb-joined-to-a-write": _FLASK
    + """
    from .mongo import db

    @app.post("/profiles/search")
    def search_profiles():
        db.users.find_one_and_replace({"_id": request.json["id"]}, request.json["doc"])
        return {"ok": True}
    """,
    "search-engine-index-call": _FLASK
    + """
    from .clients import es

    @app.post("/documents/parse")
    def parse():
        es.index(index="documents", document=request.json)
        return {"ok": True}
    """,
    "get-is-not-a-query-verb": _FLASK
    + """
    from .counters import counters

    @app.post("/lookup")
    def lookup():
        return {"n": counters.get_and_increment(request.json["key"])}
    """,
    "log-method-on-a-non-logger": _FLASK
    + """
    from . import audit, index

    @app.post("/search")
    def search():
        audit.log(request.json["user"], request.json["q"])
        return {"hits": index.search(request.json["q"])}
    """,
    "imported-fetch-and-store": _FLASK
    + """
    from .ingest import fetch_and_store

    @app.post("/fetch")
    def fetch():
        return {"id": fetch_and_store(request.json["url"])}
    """,
    "query-noun-after-a-verb": _FLASK
    + """
    from . import audit, index

    @app.post("/search")
    def search():
        audit.record_query(request.json["user"], request.json["q"])
        return {"hits": index.search(request.json["q"])}
    """,
    "unknown-second-action": _FLASK
    + """
    from .ingest import fetch_and_bump

    @app.post("/fetch")
    def fetch():
        return {"id": fetch_and_bump(request.json["url"])}
    """,
    "value-method-on-module-client": _FLASK
    + """
    import boto3

    s3 = boto3.client("s3")

    @app.post("/preview")
    def preview():
        key = request.json["key"]
        s3.copy({"Bucket": "uploads", "Key": key}, "public", key)
        return {"ok": True}
    """,
    "value-method-on-injected-dependency": """
    from fastapi import Depends, FastAPI

    app = FastAPI()

    @app.post("/preview")
    def preview(key: str, cache=Depends(get_redis)) -> dict:
        cache.copy(key, "published:" + key)
        return {"ok": True}
    """,
    "write-past-helper-depth": """
    from fastapi import FastAPI

    app = FastAPI()

    def _one(x):
        return _two(x)

    def _two(x):
        return _three(x)

    def _three(x):
        return _four(x)

    def _four(x):
        session.merge(x)
        session.commit()
        return x

    @app.post("/validate")
    def validate(body: RecordBody) -> dict:
        return {"record": _one(body)}
    """,
}


@pytest.mark.parametrize("code", HIDDEN_WRITES.values(), ids=HIDDEN_WRITES.keys())
def test_query_named_post_with_hidden_write_is_reported(code):
    assert [value for _name, value in _f102(code)] == ["POST"]


# Expected: no finding (the body only reads).
READ_ONLY = {
    "flask-request-args-and-search": _FLASK
    + """
    from . import index

    @app.post("/search")
    def search():
        query = request.args.get("q", "").strip()
        return {"hits": index.search(query)}
    """,
    "uploaded-file-read": _FLASK
    + """
    from .ml import model

    @app.post("/predict")
    def predict():
        data = request.files["image"].read()
        return {"label": model.predict(data)}
    """,
    "module-logger": _FLASK
    + """
    import logging

    from . import index

    logger = logging.getLogger(__name__)

    @app.post("/search")
    def search():
        logger.info("search q=%s", request.json["q"])
        return {"hits": index.search(request.json["q"])}
    """,
    "flask-app-logger": _FLASK
    + """
    from . import index

    @app.post("/search")
    def search():
        app.logger.debug("search")
        return {"hits": index.search(request.json["q"])}
    """,
    "langchain-similarity-search": """
    from fastapi import FastAPI

    app = FastAPI()

    @app.post("/retrieve")
    def retrieve(body: QueryBody) -> dict:
        docs = vectorstore.similarity_search(body.text.strip(), k=4)
        return {"docs": ", ".join(doc.page_content for doc in docs)}
    """,
    "starlette-request-form": """
    from fastapi import FastAPI, Request

    app = FastAPI()

    @app.post("/search")
    async def search(request: Request) -> dict:
        form = await request.form()
        return {"hits": index.search(form["q"])}
    """,
    "helpers-within-depth": """
    from fastapi import FastAPI

    app = FastAPI()

    def _one(x):
        return _two(x)

    def _two(x):
        return _three(x)

    def _three(x):
        return x.strip()

    @app.post("/score")
    def score(body: ScoreBody) -> dict:
        return {"score": len(_one(body.text))}
    """,
}


@pytest.mark.parametrize("code", READ_ONLY.values(), ids=READ_ONLY.keys())
def test_query_named_post_that_only_reads_is_not_reported(code):
    assert _f102(code) == []


@pytest.mark.parametrize(
    ("name", "reads_as_query"),
    [
        ("batch_search", True),
        ("similarity_search", True),
        ("user_search", True),
        ("search_logs", True),
        ("predict_proba", True),
        ("mark_as_read", False),
        ("find_one_and_replace", False),
        ("get_and_increment", False),
        ("fetch_and_store", False),
        ("record_query", False),
        ("fetch_record", False),
        ("index_embeddings", False),
        ("count_visit", False),
        ("match_rider", False),
        ("get_user", False),
    ],
)
def test_callee_name_reads_as_query(name, reads_as_query):
    from skylos.rules.quality.practices import _name_reads_as_query

    assert _name_reads_as_query(name) is reads_as_query


ALIASED_WRITES = {
    "module-assigned-to-a-local": _FLASK
    + """
    import shutil

    @app.post("/search")
    def search():
        file_ops = shutil
        file_ops.copy("/srv/private/data.csv", "/srv/public/data.csv")
        return {"ok": True}
    """,
    "module-imported-under-an-alias-in-the-route": _FLASK
    + """
    @app.post("/search")
    def search():
        import shutil as file_ops
        file_ops.copy("/srv/private/data.csv", "/srv/public/data.csv")
        return {"ok": True}
    """,
    "global-client-reached-through-a-chain-of-locals": _FLASK
    + """
    from .store import cache

    @app.post("/search")
    def search():
        store = cache
        target = store
        target.update({"last": request.json["q"]})
        return {"ok": True}
    """,
}


@pytest.mark.parametrize("code", ALIASED_WRITES.values(), ids=ALIASED_WRITES.keys())
def test_local_alias_of_shared_state_is_still_a_write(code):
    assert [name for name, _ in _f102(code)] == ["search"]


def test_local_copy_of_request_data_is_still_read_only():
    code = _FLASK + """
    @app.post("/search")
    def search():
        query = request.json
        terms = query
        cleaned = terms.copy()
        return {"q": cleaned}
    """
    assert _f102(code) == []
