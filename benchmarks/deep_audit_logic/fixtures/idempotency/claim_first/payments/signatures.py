import hmac
import json
import os


def verify_event(event):
    secret = os.environ["PAYMENT_WEBHOOK_SECRET"].encode("utf-8")
    payload = json.dumps(
        {
            "amount": str(event.amount),
            "event_id": str(event.id),
            "payment_id": str(event.payment_id),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected = hmac.digest(secret, payload, "sha256").hex()
    return hmac.compare_digest(event.signature or "", expected)
