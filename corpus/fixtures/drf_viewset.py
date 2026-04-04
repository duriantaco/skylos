from rest_framework.response import Response
from rest_framework.viewsets import ViewSet


class UserViewSet(ViewSet):
    def list(self, request):
        return Response([])
