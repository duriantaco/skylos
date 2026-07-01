"""Django root URLconf error handlers are looked up by name."""

from django.http import (  # skylos: ignore[SKY-D223] corpus fixture dependency
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseNotFound,
    HttpResponseServerError,
)


def _bad_request(request, exception):
    return HttpResponseBadRequest("Bad request")


def _not_found(request, exception):
    return HttpResponseNotFound("Not found")


def _forbidden(request, exception):
    return HttpResponseForbidden("Forbidden")


def _server_error(request, exception=None):
    return HttpResponseServerError("Server error")


handler400 = _bad_request
handler404 = _not_found
handler403 = _forbidden
handler500 = _server_error

urlpatterns = []
