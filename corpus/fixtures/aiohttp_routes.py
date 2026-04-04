from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/")
async def hello(request):
    return web.Response(text="ok")
