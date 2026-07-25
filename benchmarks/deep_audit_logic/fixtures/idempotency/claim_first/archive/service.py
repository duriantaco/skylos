# ruff: noqa: F821 - provider is an application-supplied fixture dependency


def process_payment_event(event):
    return provider.capture(
        event.payment_id,
        event.amount,
        idempotency_key=event.id,
    )
