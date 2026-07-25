from . import gateway, store


def process_payment_event(event):
    if store.event_seen(event.id):
        return "duplicate"
    gateway.capture(event.payment_id, event.amount)
    store.mark_event_seen(event.id)
    return "captured"
