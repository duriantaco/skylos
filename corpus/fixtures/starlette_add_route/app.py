from starlette.applications import Starlette

app = Starlette()


async def homepage(request):
    return None


app.add_route("/", endpoint=homepage, methods=["GET"])
