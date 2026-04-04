from sanic import Sanic

app = Sanic("demo")


async def before_start(app, loop):
    return None


app.register_listener(before_start, "before_server_start")
