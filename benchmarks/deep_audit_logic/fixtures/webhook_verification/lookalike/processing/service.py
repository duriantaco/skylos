import json

from .signatures import verify_signature
from .store import apply_event


def accept_event(headers, body):
    if not verify_signature(headers.get("X-Signature"), body):
        raise PermissionError("invalid webhook signature")
    event = json.loads(body)
    event_id = event["id"]
    apply_event(event)
    return event_id
