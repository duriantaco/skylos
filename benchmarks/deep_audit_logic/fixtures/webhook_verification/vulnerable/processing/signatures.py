import hmac
import os


def verify_signature(provided, body):
    secret = os.environ["WEBHOOK_SECRET"].encode("utf-8")
    expected = hmac.digest(secret, body, "sha256").hex()
    return hmac.compare_digest(provided or "", expected)
