from . import gateway, store


def process_payment_event(event):
    capture = gateway.capture_once(event.id, event.payment_id, event.amount)
    store.ensure_pending(event.id)
    if store.mark_completed(event.id, capture.id):
        return "captured"
    return "duplicate"
