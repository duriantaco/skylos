from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/")
async def hello(request):
    return web.Response(text="ok")


async def metadata(context):
    return web.Response(text=str(context))


def format_status(value, format_style):
    return str(value)


print(format_status(200, "compact"))
