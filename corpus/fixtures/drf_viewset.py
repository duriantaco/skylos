from rest_framework.response import Response
from rest_framework.viewsets import ViewSet


class UserViewSet(ViewSet):
    def list(self, request):
        return Response([])


class PreviewActions:
    def preview(self, request):
        return Response(str(request))


class ActionPreview:
    def preview(self, request):
        return Response(str(request))


ActionPreview()
