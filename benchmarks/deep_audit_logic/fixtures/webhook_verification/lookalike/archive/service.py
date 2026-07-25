import json

from processing.signatures import verify_signature
from processing.store import apply_event


def accept_event(headers, body):
    event = json.loads(body)
    event_id = event["id"]
    apply_event(event)
    if not verify_signature(headers.get("X-Signature"), body):
        raise PermissionError("invalid webhook signature")
    return event_id
