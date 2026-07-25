from payments.service import process_payment_event
from payments.signatures import verify_event


def payment_webhook(event):
    if not verify_event(event):
        raise PermissionError("invalid payment webhook signature")
    return process_payment_event(event)
