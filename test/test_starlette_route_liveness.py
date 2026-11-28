from textwrap import dedent

import pytest

from test.test_asgi_launch_liveness import _scan


@pytest.mark.parametrize("confidence,grep", [(0, False), (80, True)])
@pytest.mark.parametrize(
    "consumer",
    [
        "Starlette(routes=routes)",
        "Starlette(routes=[Mount('/api', routes=routes)])",
        "Starlette(routes=[Mount('/api', None, routes)])",
        "Starlette(routes=[Mount('/api', app=Router(routes=routes))])",
    ],
)
def test_starlette_class_dispatch_keeps_its_helper(
    tmp_path, confidence, grep, consumer
):
    analyzer, unused = _scan(
        tmp_path,
        {
            "main.py": dedent("""
                from starlette.applications import Starlette
                from starlette.routing import Mount, Router
                from handlers import routes
                """)
            + f"\napp = {consumer}\n",
            "handlers.py": """
                from starlette.endpoints import HTTPEndpoint, WebSocketEndpoint
                from starlette.responses import PlainTextResponse
                from starlette.routing import Route, WebSocketRoute

                def fallback_version():
                    return PlainTextResponse("1")

                def dead_neighbor():
                    return PlainTextResponse("unused")

                class Version(HTTPEndpoint):
                    async def get(self, request):
                        return fallback_version()

                async def greet(websocket):
                    await websocket.accept()

                class Feed(WebSocketEndpoint):
                    async def on_receive(self, websocket, data):
                        await websocket.send_text(str(data))

                routes = [
                    Route("/version", endpoint=Version),
                    WebSocketRoute("/greet", greet),
                    WebSocketRoute("/feed", Feed),
                ]
                """,
        },
        confidence,
        grep,
    )
    assert "handlers.fallback_version" not in unused
    assert "handlers.dead_neighbor" in unused
    for target in ("Version.get", "greet", "Feed.on_receive"):
        assert analyzer.defs[f"handlers.{target}"].heuristic_refs.get("framework_root")


@pytest.mark.parametrize("confidence,grep", [(0, False), (80, True)])
def test_unused_starlette_table_does_not_root_its_callbacks(tmp_path, confidence, grep):
    analyzer, unused = _scan(
        tmp_path,
        {
            "main.py": """
                from starlette.applications import Starlette
                from starlette.responses import PlainTextResponse
                from starlette.routing import Route as Path

                def archived_message():
                    return "Archival copy"

                async def archive(request):
                    return PlainTextResponse(archived_message())

                async def actual(request):
                    return PlainTextResponse("Current")

                unused_table = [Path("/archive", archive)]
                app = Starlette(routes=[Path("/", actual)])
                """,
        },
        confidence,
        grep,
    )
    assert "main.archive" in unused
    assert "main.archived_message" in unused
    assert "main.actual" not in unused
    assert not analyzer.defs["main.archive"].heuristic_refs.get("top_level_execution")


def test_starlette_requires_real_provider_and_preserves_another_use(tmp_path):
    analyzer, unused = _scan(
        tmp_path,
        {
            "main.py": """
                from starlette.applications import Starlette
                from starlette.routing import Route as Path

                async def preview(request):
                    return "Preview"

                unused_table = [Path("/unused", preview)]
                app = Starlette()
                callback = preview

                def Route(path, endpoint):
                    return endpoint

                async def other(request):
                    return "Other"

                app2 = Starlette(routes=[Route("/other", other)])
                """,
        },
        80,
        True,
    )
    assert "main.preview" not in unused
    assert not analyzer.defs["main.other"].heuristic_refs.get("framework_root")


@pytest.mark.parametrize(
    ("methods", "has_head", "uses_get"),
    [
        ('["HEAD", "TRACE"]', False, True),
        ('["HEAD", "TRACE"]', True, False),
        ("[]", True, True),
        ("()", False, True),
    ],
)
def test_starlette_http_dispatch_uses_the_matching_handler(
    tmp_path, methods, has_head, uses_get
):
    source = dedent("""
        from starlette.applications import Starlette
        from starlette.endpoints import HTTPEndpoint
        from starlette.routing import Route
        from starlette.responses import PlainTextResponse

        class Greeting(HTTPEndpoint):
            async def get(self, request):
                return PlainTextResponse("get")

            async def trace(self, request):
                return PlainTextResponse("trace")
        """)
    if has_head:
        source += '    async def head(self, request):\n        return PlainTextResponse("head")\n'
    source += f'app = Starlette(routes=[Route("/", Greeting, methods={methods})])\n'
    analyzer, _ = _scan(tmp_path, {"main.py": source}, 80, True)
    assert not analyzer.defs["main.Greeting.trace"].heuristic_refs.get("framework_root")
    assert (
        bool(analyzer.defs["main.Greeting.get"].heuristic_refs.get("framework_root"))
        is uses_get
    )
    if has_head:
        assert analyzer.defs["main.Greeting.head"].heuristic_refs.get("framework_root")
