"""SKY-F102 reports routes that change state without an auth guard.

PUT, PATCH and DELETE routes change state by definition. A POST route is
treated as changing state unless its name or path reads as a query (search,
retrieve, predict, embed, ...) and its body shows no state change: no
persistence or side-effect call, no write to shared state, and no
same-module helper that does either.
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


READ_ONLY_POST = {
    "retrieval-search": """
        from fastapi import FastAPI

        app = FastAPI()
        retriever = None

        @app.post("/retrieve")
        def retrieve(request: QueryRequest) -> dict:
            if retriever is None:
                raise RuntimeError("retriever is not initialized")
            topk = request.topk or retriever.topk
            return {"result": retriever.batch_search(request.queries, topk)}
        """,
    "flask-inference": """
        from flask import Flask, jsonify, request

        app = Flask(__name__)
        model = load_model()

        @app.route("/predict", methods=["POST"])
        def predict():
            features = request.get_json()["features"]
            return jsonify(prediction=model.predict([features]).tolist())
        """,
    "local-accumulator": """
        from fastapi import APIRouter

        router = APIRouter()

        @router.post("/search")
        def run_queries(body: SearchBody) -> list:
            results = []
            for query in body.queries:
                results.append(index.search(query))
            return results
        """,
    "rebinds-request-copy": """
        from fastapi import FastAPI

        app = FastAPI()

        @app.post("/embed")
        def embed(request: EmbedRequest) -> dict:
            request.batch_size = request.batch_size or 32
            return {"vectors": encoder.encode(request.texts, request.batch_size)}
        """,
    "read-only-local-helper": """
        from fastapi import FastAPI

        app = FastAPI()

        def _score(text):
            tokens = text.split()
            return len(tokens)

        @app.post("/score")
        def score(body: ScoreBody) -> dict:
            return {"score": _score(body.text)}
        """,
    "get-and-post-form-without-writes": """
        from flask import Flask, render_template, request

        app = Flask(__name__)

        @app.route("/preview", methods=["GET", "POST"])
        def preview():
            text = request.form.get("text", "")
            return render_template("preview.html", text=text)
        """,
}


@pytest.mark.parametrize("code", READ_ONLY_POST.values(), ids=READ_ONLY_POST.keys())
def test_query_style_post_without_state_change_is_not_reported(code):
    assert _f102(code) == []


# Query-style routes whose body still changes state.
QUERY_POST_WITH_STATE_CHANGE = {
    "orm-session-commit": """
        @app.post("/search")
        def search(body: SearchBody) -> dict:
            db.session.add(SearchLog(text=body.text))
            db.session.commit()
            return {"hits": index.search(body.text)}
        """,
    "module-dict-store": """
        CACHE = {}

        @app.post("/predict")
        def predict(body: PredictBody) -> dict:
            CACHE[body.id] = model.predict(body.rows)
            return {"ok": True}
        """,
    "global-counter": """
        COUNTER = 0

        @app.post("/query")
        def query(body: QueryBody) -> dict:
            global COUNTER
            COUNTER += 1
            return {"rows": run_select(body.sql), "count": COUNTER}
        """,
    "module-list-append": """
        HISTORY = []

        @app.post("/chat")
        def chat(body: ChatBody) -> dict:
            HISTORY.append(body.text)
            return {"reply": llm.reply(HISTORY)}
        """,
    "setattr-on-module-settings": """
        @app.post("/preview")
        def preview(body: ThemeBody) -> dict:
            setattr(settings, "theme", body.theme)
            return {"ok": True}
        """,
    "subprocess": """
        import subprocess

        @app.post("/render")
        def render(body: RenderBody) -> dict:
            subprocess.run(["renderer", body.name], check=True)
            return {"ok": True}
        """,
    "file-write": """
        @app.post("/convert")
        def convert(body: ConvertBody) -> dict:
            with open(body.path, "w") as handle:
                handle.write(body.text)
            return {"ok": True}
        """,
    "outgoing-http-post": """
        import requests

        @app.post("/check")
        def check(body: CheckBody) -> dict:
            response = requests.post(body.url, json=body.payload, timeout=5)
            return {"status": response.status_code}
        """,
    "django-orm-create": """
        @app.post("/lookup")
        def lookup(body: LookupBody) -> dict:
            entry, _ = Entry.objects.get_or_create(key=body.key)
            return {"id": entry.id}
        """,
    "async-document-insert": """
        @app.post("/analyze")
        async def analyze(body: AnalyzeBody) -> dict:
            result = await collection.insert_one(body.dict())
            return {"id": str(result.inserted_id)}
        """,
    "sql-execute": """
        @app.post("/estimate")
        def estimate(body: EstimateBody) -> dict:
            cursor.execute("INSERT INTO estimates VALUES (?)", (body.value,))
            return {"ok": True}
        """,
    "session-store": """
        from flask import Flask, request

        app = Flask(__name__)

        @app.route("/preview", methods=["POST"])
        def preview():
            request.session["theme"] = request.form["theme"]
            return {"ok": True}
        """,
    "background-task": """
        @app.post("/summarize")
        def summarize(body: ReportBody, background_tasks: BackgroundTasks) -> dict:
            background_tasks.add_task(build_report, body.id)
            return {"queued": True}
        """,
    "local-helper-that-commits": """
        def _persist(record):
            session.merge(record)
            session.commit()
            return record

        @app.post("/validate")
        def validate(body: RecordBody) -> dict:
            return {"record": _persist(body)}
        """,
    "state-action-word-wins": """
        @app.post("/search/save")
        def search(body: SearchBody) -> dict:
            return service.handle(body)
        """,
}


@pytest.mark.parametrize(
    "code",
    QUERY_POST_WITH_STATE_CHANGE.values(),
    ids=QUERY_POST_WITH_STATE_CHANGE.keys(),
)
def test_query_style_post_with_state_change_is_reported(code):
    assert [value for _name, value in _f102(code)] == ["POST"]


# Without a query-style name, a POST keeps the old default: it may change
# state through calls whose names say nothing (``remote.fork(...)``).
OTHER_POST = {
    "domain-verb-delegation": """
        @app.post("/sessions/{session_id}/fork")
        async def fork(session_id: str) -> dict:
            return {"id": await remote.fork(session_id)}
        """,
    "action-in-route-name": """
        @app.post("/users")
        def create_user(body: UserBody) -> dict:
            return service.handle(body)
        """,
    "webhook-receiver": """
        @app.post("/webhooks/payments")
        async def payments(request: Request) -> dict:
            event = await request.json()
            return {"received": event["id"]}
        """,
    "get-and-post-form": """
        from flask import Flask, request

        app = Flask(__name__)

        @app.route("/profile", methods=["GET", "POST"])
        def profile():
            if request.method == "POST":
                current.name = request.form["name"]
            return {"ok": True}
        """,
}


@pytest.mark.parametrize("code", OTHER_POST.values(), ids=OTHER_POST.keys())
def test_other_post_routes_are_still_reported(code):
    assert [value for _name, value in _f102(code)] == ["POST"]


@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_put_patch_delete_need_no_state_change_evidence(method):
    findings = _f102(
        f"""
        @app.{method}("/search")
        def search(body: SearchBody) -> dict:
            return {{"echo": body.value}}
        """
    )
    assert findings == [("search", method.upper())]


def test_query_style_post_with_put_still_reported():
    findings = _f102(
        """
        @app.route("/search", methods=["POST", "PUT"])
        def search():
            return {"ok": True}
        """
    )
    assert findings == [("search", "POST,PUT")]


def test_guarded_query_style_post_with_writes_is_not_reported():
    findings = _f102(
        """
        @app.post("/search")
        def search(body: SearchBody, user=Depends(get_current_user)) -> dict:
            db.session.add(SearchLog(text=body.text))
            db.session.commit()
            return {"ok": True}
        """
    )
    assert findings == []


# Independent review: query-named POST routes that call neutral or imported
# callees which write or cause side effects. An unknown callee counts as a
# state change; only builtins, pure library calls, value methods, same-module
# helpers (checked by body) and query-named callees do not.
HIDDEN_WRITES = {
    # Unknown callees (``model(...)``, ``captioner(...)``, ``post_process``)
    # may write; these keep the main-branch behaviour.
    "inference-with-data-helpers": """
        @app.post("/classify")
        def classify(body: ClassifyBody) -> dict:
            frame = to_frame(body.rows).drop_duplicates().reset_index(drop=True)
            outputs = model(frame)
            return {"labels": post_process(outputs)}
        """,
    "opens-an-image-for-reading": """
        @app.post("/caption")
        def caption(body: CaptionBody) -> dict:
            image = Image.open("samples/cat.png")
            return {"caption": captioner(image, body.prompt)}
        """,
    "dataframe-to-sql": """
        from fastapi import FastAPI
        app = FastAPI()

        @app.post("/predict")
        def predict(frame: dict):
            data = build_frame(frame)
            data.to_sql("predictions", engine)
            return {"ok": True}
        """,
    "coupon-redeem": """
        from fastapi import FastAPI
        from shop import coupons
        app = FastAPI()

        @app.post("/coupons/check")
        def check(code: str):
            return {"valid": coupons.redeem(code)}
        """,
    "model-cache-pull": """
        from fastapi import FastAPI
        from models import model_cache
        app = FastAPI()

        @app.post("/models/download")
        def download(url: str):
            model_cache.pull(url)
            return {"ok": True}
        """,
    "lambda-invoke": """
        from fastapi import FastAPI
        app = FastAPI()

        @app.post("/analyze")
        def analyze(order_id: str):
            lambda_client.invoke(FunctionName="ProcessOrder", Payload=order_id)
            return {"queued": True}
        """,
    "http-delete-to-service": """
        import requests
        from fastapi import FastAPI
        app = FastAPI()

        @app.post("/lookup")
        def lookup(item: str):
            requests.request("DELETE", f"http://inventory/items/{item}")
            return {"ok": True}
        """,
    "background-thread": """
        from threading import Thread
        from fastapi import FastAPI
        app = FastAPI()

        @app.post("/compute")
        def compute(payload: dict):
            Thread(target=persist_all, args=(payload,)).start()
            return {"ok": True}
        """,
    "neutral-service-call": """
        from fastapi import FastAPI
        from services import service
        app = FastAPI()

        @app.post("/search")
        def search(q: str):
            return {"result": service.process(q)}
        """,
}


@pytest.mark.parametrize("code", HIDDEN_WRITES.values(), ids=HIDDEN_WRITES.keys())
def test_query_style_post_with_unknown_callee_is_reported(code):
    assert len(_f102(code)) == 1
