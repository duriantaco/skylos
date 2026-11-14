from twisted.web import resource, server
from twisted.web.resource import Resource


class Status(resource.Resource):
    def render_GET(self, request):
        return b"ok"

    def render_page(self, request):
        return b"never dispatched"


class Action(Resource):
    def render_POST(self, request):
        return b"done"


def build():
    root = Resource()
    root.putChild(b"status", Status())
    root.putChild(b"action", Action())
    return server.Site(root)


print(build())
