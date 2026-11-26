from starlette.applications import Starlette
from starlette.responses import PlainTextResponse

app = Starlette()


async def homepage(request):
    return PlainTextResponse("home")


app.add_route("/", homepage, methods=["GET"])


async def status_page(request):
    return str(request)
