from . import gateway, store


def process_payment_event(event):
    if not store.claim_once(event.id):
        return "duplicate"
    gateway.capture(event.payment_id, event.amount)
    return "captured"
