# ruff: noqa: F821 - model and provider are application-supplied fixture dependencies


def process_payment_event(event):
    if EventReceipt.objects.filter(event_id=event.id).exists():
        return "duplicate"
    provider.capture(event.payment_id, event.amount)
    EventReceipt.objects.create(event_id=event.id)
    return "captured"
