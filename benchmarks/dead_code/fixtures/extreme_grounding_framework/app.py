from api import dispatch_http
from cli import dispatch_job


def main(event):
    if event.get("source") == "cli":
        return dispatch_job(event)
    return dispatch_http(event)


def preview(event):
    return {"source": event.get("source", "http")}
