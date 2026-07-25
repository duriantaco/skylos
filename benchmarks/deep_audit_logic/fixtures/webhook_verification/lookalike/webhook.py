from processing.service import accept_event


def webhook(request):
    return accept_event(request.headers, request.body)
